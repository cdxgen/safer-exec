// Linux detection wiring: the sandbox cgroup's IO/CPU sampler and the egress
// watch that records UDP and direct TCP traffic leaving outside the egress
// proxy. Both only observe; neither denies anything.

package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/cdxgen/safer-exec/go/internal/config"
)

// Environment variables the outer engine passes to the inner --init process.
const (
	envCgroupName    = "SAFER_EXEC_CGROUP_NAME"
	envCgroupMonitor = "SAFER_EXEC_CGROUP_MONITOR"
	envNotifyFd      = "SAFER_EXEC_NOTIFY_FD"
)

// cgroupName and cgroupMonitor are adopted from the outer engine by
// adoptDetectionEnv. A unique name keeps concurrent sandboxes apart: inside a
// PID namespace every --init process is pid 1, so a pid-derived name made
// every run share "safer-exec-1".
var (
	cgroupName    string
	cgroupMonitor bool
	// notifyFd is the egress-watch socket from the outer engine, -1 without
	// one. It is close-on-exec, so the target never inherits it.
	notifyFd = -1
)

// adoptDetectionEnv reads and removes the detection variables in an inner
// process, so they never reach the target's environment.
func adoptDetectionEnv() {
	cgroupName = os.Getenv(envCgroupName)
	cgroupMonitor = os.Getenv(envCgroupMonitor) == "1"
	os.Unsetenv(envCgroupName)
	os.Unsetenv(envCgroupMonitor)
	if fd, err := strconv.Atoi(os.Getenv(envNotifyFd)); err == nil && fd >= 3 {
		unix.CloseOnExec(fd)
		notifyFd = fd
	}
	os.Unsetenv(envNotifyFd)
}

// newCgroupName returns a cgroup name unique to this engine run.
func newCgroupName() string {
	return fmt.Sprintf("safer-exec-%d-%d", os.Getpid(), time.Now().UnixNano()%1_000_000_000)
}

// ownCgroupDir returns this process's cgroup v2 directory, or "".
func ownCgroupDir() string {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "0::"); ok {
			return filepath.Join(cgroupV2Root, rest)
		}
	}
	return ""
}

// readCgroupUsage returns the cumulative CPU time (µs) and IO bytes of a
// cgroup v2 directory. io.stat is absent when the io controller is not
// enabled for the cgroup; CPU time is then sampled alone.
func readCgroupUsage(dir string) (cpuUsec, ioBytes uint64, ok bool) {
	data, err := os.ReadFile(filepath.Join(dir, "cpu.stat"))
	if err != nil {
		return 0, 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, found := strings.CutPrefix(line, "usage_usec "); found {
			cpuUsec, _ = strconv.ParseUint(strings.TrimSpace(v), 10, 64)
		}
	}
	if f, err := os.Open(filepath.Join(dir, "io.stat")); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			for _, field := range strings.Fields(sc.Text()) {
				for _, key := range []string{"rbytes=", "wbytes="} {
					if v, found := strings.CutPrefix(field, key); found {
						n, _ := strconv.ParseUint(v, 10, 64)
						ioBytes += n
					}
				}
			}
		}
		f.Close()
	}
	return cpuUsec, ioBytes, true
}

// cgroupWatch prepares the inner process's cgroup name and, for audited runs,
// samples that cgroup from the outer engine once the inner process has
// created it.
type cgroupWatch struct {
	dir     string
	sampler *contentionSampler
}

// prepareCgroupWatch adds the cgroup variables to the inner process's
// environment and returns the watch, whose start must be called after the
// inner process has started.
func prepareCgroupWatch(cfg config.ExecConfig, env []string) (*cgroupWatch, []string) {
	name := newCgroupName()
	env = append(env, envCgroupName+"="+name)
	w := &cgroupWatch{}
	if parent := ownCgroupDir(); parent != "" {
		w.dir = filepath.Join(parent, name)
	}
	if cfg.EnableAudit {
		env = append(env, envCgroupMonitor+"=1")
	}
	return w, env
}

func (w *cgroupWatch) start(cfg config.ExecConfig) {
	if !cfg.EnableAudit || w.dir == "" {
		return
	}
	w.sampler = startContentionSampler(func() (uint64, uint64, bool) {
		return readCgroupUsage(w.dir)
	})
}

// finish stops sampling, removes the cgroup if the inner process left it
// behind (it execs the target, so its own cleanup never runs) and returns
// any timing-channel findings.
func (w *cgroupWatch) finish() []config.AuditEntry {
	if w == nil {
		return nil
	}
	entries := w.sampler.finish()
	if w.dir != "" {
		os.Remove(w.dir)
	}
	return entries
}

// seccomp user-notification ABI (linux/seccomp.h).
const (
	seccompFilterFlagNewListener = 1 << 3
	seccompRetUserNotif          = 0x7fc00000
	seccompUserNotifFlagContinue = 1
	seccompIoctlNotifRecv        = 0xc0502100 // _IOWR('!', 0, struct seccomp_notif)
	seccompIoctlNotifSend        = 0xc0182101 // _IOWR('!', 1, struct seccomp_notif_resp)
	seccompIoctlNotifIDValid     = 0x40082102 // _IOW('!', 2, __u64)
	seccompNotifSize             = 80
	seccompNotifRespSize         = 24
)

// egressNotifySupported reports whether the kernel can let a notified
// syscall continue (SECCOMP_USER_NOTIF_FLAG_CONTINUE, Linux 5.5) and lets the
// engine copy the listener out of the inner process (pidfd_getfd, 5.6).
// Without the first a supervisor could only fail or emulate the call, which
// would break it.
func egressNotifySupported() bool {
	var u unix.Utsname
	if unix.Uname(&u) != nil {
		return false
	}
	return parseKernelVersion(unix.ByteSliceToString(u.Release[:])) >= 5.06
}

// egressNotifyProgram returns the filter that notifies the supervisor of
// socket(AF_INET/AF_INET6, SOCK_DGRAM), connect, sendto with a destination
// address, and sendmsg. Everything else is allowed without a notification.
func egressNotifyProgram() []unix.SockFilter {
	const (
		ld   = bpfLoadWordAbsolute
		jeq  = bpfJmpEq
		ret  = bpfJmpReturn
		and  = bpfAluAnd
		arg0 = seccompDataArg0Offset
		arg1 = seccompDataArg0Offset + 8
		arg4 = seccompDataArg0Offset + 32
	)
	allow := unix.SockFilter{Code: ret, K: seccompRetAllow}
	notify := unix.SockFilter{Code: ret, K: seccompRetUserNotif}
	return []unix.SockFilter{
		{Code: ld, K: seccompDataArchOffset},
		{Code: jeq, Jt: 1, K: seccompAuditArch},
		allow,
		{Code: ld, K: seccompDataNROffset},
		{Code: jeq, Jf: 7, K: unix.SYS_SOCKET},
		{Code: ld, K: arg0},
		{Code: jeq, Jt: 1, K: unix.AF_INET},
		{Code: jeq, Jf: 3, K: unix.AF_INET6},
		{Code: ld, K: arg1},
		{Code: and, K: 0xf},
		{Code: jeq, Jt: 9, K: unix.SOCK_DGRAM},
		allow,
		{Code: jeq, Jt: 7, K: unix.SYS_CONNECT},
		{Code: jeq, Jt: 6, K: unix.SYS_SENDMSG},
		{Code: jeq, Jf: 4, K: unix.SYS_SENDTO},
		{Code: ld, K: arg4},
		{Code: jeq, Jf: 3, K: 0},
		{Code: ld, K: arg4 + 4},
		{Code: jeq, Jf: 1, K: 0},
		allow,
		notify,
	}
}

// installEgressNotify runs in the inner process before the sandbox's own
// seccomp filter. It installs egressNotifyProgram with a listener and tells
// the outer engine the listener's descriptor number over the socket in
// SAFER_EXEC_NOTIFY_FD; the engine copies the descriptor out with
// pidfd_getfd. Passing it with SCM_RIGHTS would deadlock: the filter already
// applies to this process, so its own sendmsg would wait for a supervisor
// that has no listener yet. write and read are not watched. Any failure
// leaves the run unwatched, never blocked.
func installEgressNotify() {
	sock := notifyFd
	if sock < 0 {
		return
	}
	notifyFd = -1
	defer unix.Close(sock)
	insts := egressNotifyProgram()
	prog := unix.SockFprog{Len: uint16(len(insts)), Filter: &insts[0]}
	listener, _, errno := unix.RawSyscall(sysSeccomp, 1, seccompFilterFlagNewListener, uintptr(unsafe.Pointer(&prog)))
	if errno != 0 {
		fmt.Fprintf(os.Stderr, "safer-exec: warning: egress watch: seccomp listener: %v\n", errno)
		return
	}
	defer unix.Close(int(listener))
	if _, err := unix.Write(sock, []byte(strconv.Itoa(int(listener)))); err != nil {
		return
	}
	// Keep the listener open until the engine has its copy (or gave up).
	ack := make([]byte, 1)
	_, _ = unix.Read(sock, ack)
}

// egressWatch is the outer engine's side: it receives the listener, records
// what each notified syscall was about to do, and lets every call continue.
type egressWatch struct {
	proxyPort int
	parent    *os.File
	child     *os.File
	done      chan struct{}
	stop      chan struct{}

	mu    sync.Mutex
	notes map[string]*egressNote
}

type egressNote struct {
	proto, dest, exe string
	pid              int
	count            int
}

// maxEgressNotes caps the distinct destinations recorded.
const maxEgressNotes = 256

// prepareEgressWatch returns a watch for proxy-egress runs on kernels that
// support it, with the socket end to pass to the inner process as fd 5.
func prepareEgressWatch(cfg config.ExecConfig, proxyPort int) *egressWatch {
	if proxyPort == 0 || !cfg.EnableAudit || cfg.DisableNetwork || !egressNotifySupported() {
		return nil
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil
	}
	return &egressWatch{
		proxyPort: proxyPort,
		parent:    os.NewFile(uintptr(fds[0]), "egress-watch"),
		child:     os.NewFile(uintptr(fds[1]), "egress-watch-child"),
		done:      make(chan struct{}),
		stop:      make(chan struct{}),
		notes:     make(map[string]*egressNote),
	}
}

// notifyFdIndex is the ExtraFiles slot of the watch socket: fd 5, after the
// audit pipe (3) and the lib-load pipe (4).
const notifyFdIndex = 2

// attach passes the child end to cmd as fd 5.
func (w *egressWatch) attach(extra []*os.File, env []string) ([]*os.File, []string) {
	if w == nil {
		return extra, env
	}
	for len(extra) < notifyFdIndex {
		extra = append(extra, nil)
	}
	extra = append(extra[:notifyFdIndex], w.child)
	return extra, append(env, fmt.Sprintf("%s=%d", envNotifyFd, 3+notifyFdIndex))
}

// started closes the child end in the engine and starts serving.
func (w *egressWatch) started(rootPID int) {
	if w == nil {
		return
	}
	w.child.Close()
	go w.serve(rootPID)
}

func (w *egressWatch) serve(rootPID int) {
	defer close(w.done)
	defer w.parent.Close()
	listener := -1
	// Wait for the listener's descriptor number, giving up when the run ends
	// without one.
	for listener < 0 {
		select {
		case <-w.stop:
			return
		default:
		}
		fds := []unix.PollFd{{Fd: int32(w.parent.Fd()), Events: unix.POLLIN}}
		if n, err := unix.Poll(fds, 100); err != nil && err != unix.EINTR {
			return
		} else if n == 0 {
			continue
		}
		buf := make([]byte, 16)
		n, err := unix.Read(int(w.parent.Fd()), buf)
		if err != nil || n == 0 {
			return
		}
		remote, err := strconv.Atoi(string(buf[:n]))
		if err == nil {
			listener = copyListener(rootPID, remote)
		}
		_, _ = unix.Write(int(w.parent.Fd()), []byte{1})
		if listener < 0 {
			fmt.Fprintf(os.Stderr, "safer-exec: warning: egress watch: could not take over the seccomp listener; UDP and direct egress are not recorded\n")
			return
		}
	}
	// Closing the listener makes the notified syscalls of a process that
	// outlives the run (possible in reduced isolation, which has no PID
	// namespace) fail with ENOSYS instead of waiting for an answer forever.
	defer unix.Close(listener)
	notif := make([]byte, seccompNotifSize)
	resp := make([]byte, seccompNotifRespSize)
	for {
		select {
		case <-w.stop:
			return
		default:
		}
		fds := []unix.PollFd{{Fd: int32(listener), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, 100)
		if err != nil && err != unix.EINTR {
			return
		}
		if n == 0 {
			continue
		}
		if fds[0].Revents&(unix.POLLHUP|unix.POLLERR) != 0 && fds[0].Revents&unix.POLLIN == 0 {
			return // every watched process has exited
		}
		clear(notif)
		if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(listener), seccompIoctlNotifRecv, uintptr(unsafe.Pointer(&notif[0]))); errno != 0 {
			if errno == unix.EINTR || errno == unix.ENOENT {
				continue
			}
			return
		}
		id := binary.LittleEndian.Uint64(notif[0:])
		w.inspect(listener, id, notif)
		clear(resp)
		binary.LittleEndian.PutUint64(resp[0:], id)
		binary.LittleEndian.PutUint32(resp[20:], seccompUserNotifFlagContinue)
		unix.Syscall(unix.SYS_IOCTL, uintptr(listener), seccompIoctlNotifSend, uintptr(unsafe.Pointer(&resp[0])))
	}
}

// inspect records one notified syscall. Memory is read from the target, so
// the notification id is re-checked afterwards: if the call was abandoned
// the pid may have been reused and the bytes belong to someone else.
func (w *egressWatch) inspect(listener int, id uint64, notif []byte) {
	pid := int(binary.LittleEndian.Uint32(notif[8:]))
	nr := int(int32(binary.LittleEndian.Uint32(notif[16:])))
	arg := func(i int) uint64 { return binary.LittleEndian.Uint64(notif[32+8*i:]) }

	var fd int
	var addr, addrLen uint64
	switch nr {
	case unix.SYS_SOCKET:
		w.record(pid, "udp", "", 1)
		return
	case unix.SYS_CONNECT:
		fd, addr, addrLen = int(arg(0)), arg(1), arg(2)
	case unix.SYS_SENDTO:
		fd, addr, addrLen = int(arg(0)), arg(4), arg(5)
	case unix.SYS_SENDMSG:
		fd = int(arg(0))
		hdr := readRemote(pid, arg(1), 12)
		if len(hdr) < 12 {
			return
		}
		addr = binary.LittleEndian.Uint64(hdr[0:])
		addrLen = uint64(binary.LittleEndian.Uint32(hdr[8:]))
	default:
		return
	}
	if addr == 0 || addrLen < 8 {
		return
	}
	sa := readRemote(pid, addr, min(int(addrLen), 28))
	dest, loopback, port, ok := parseSockaddr(sa)
	if !ok {
		return
	}
	idCopy := id
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(listener), seccompIoctlNotifIDValid, uintptr(unsafe.Pointer(&idCopy))); errno != 0 {
		return
	}
	proto := socketProto(pid, fd)
	if proto != "udp" && loopback && port == w.proxyPort {
		return // the egress proxy itself
	}
	w.record(pid, proto, dest, 0)
}

// copyListener finds the inner process — rootPID itself (reduced isolation)
// or a child of it (unshare --fork) — whose descriptor fd is the seccomp
// listener, and duplicates it into this process.
func copyListener(rootPID, fd int) int {
	candidates := []int{rootPID}
	if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/children", rootPID, rootPID)); err == nil {
		for _, f := range strings.Fields(string(data)) {
			if pid, err := strconv.Atoi(f); err == nil {
				candidates = append(candidates, pid)
			}
		}
	}
	for _, pid := range candidates {
		if link, _ := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, fd)); !strings.Contains(link, "seccomp notify") {
			continue
		}
		pidfd, err := unix.PidfdOpen(pid, 0)
		if err != nil {
			return -1
		}
		dup, err := unix.PidfdGetfd(pidfd, fd, 0)
		unix.Close(pidfd)
		if err != nil {
			return -1
		}
		return dup
	}
	return -1
}

// readRemote reads n bytes at addr in pid's memory.
func readRemote(pid int, addr uint64, n int) []byte {
	if n <= 0 {
		return nil
	}
	buf := make([]byte, n)
	local := []unix.Iovec{{Base: &buf[0]}}
	local[0].SetLen(n)
	remote := []unix.RemoteIovec{{Base: uintptr(addr), Len: n}}
	got, err := unix.ProcessVMReadv(pid, local, remote, 0)
	if err != nil {
		return nil
	}
	return buf[:got]
}

// parseSockaddr decodes an AF_INET or AF_INET6 sockaddr.
func parseSockaddr(sa []byte) (dest string, loopback bool, port int, ok bool) {
	if len(sa) < 4 {
		return "", false, 0, false
	}
	family := binary.LittleEndian.Uint16(sa[0:])
	port = int(binary.BigEndian.Uint16(sa[2:]))
	var ip net.IP
	switch family {
	case unix.AF_INET:
		if len(sa) < 8 {
			return "", false, 0, false
		}
		ip = net.IP(append([]byte(nil), sa[4:8]...))
	case unix.AF_INET6:
		if len(sa) < 24 {
			return "", false, 0, false
		}
		ip = net.IP(append([]byte(nil), sa[8:24]...))
	default:
		return "", false, 0, false
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(port)), ip.IsLoopback(), port, true
}

// socketProto names the type of socket fd in pid ("udp", "tcp" or "ip"
// when it cannot be read).
func socketProto(pid, fd int) string {
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return "ip"
	}
	defer unix.Close(pidfd)
	dup, err := unix.PidfdGetfd(pidfd, fd, 0)
	if err != nil {
		return "ip"
	}
	defer unix.Close(dup)
	typ, err := unix.GetsockoptInt(dup, unix.SOL_SOCKET, unix.SO_TYPE)
	switch {
	case err != nil:
		return "ip"
	case typ == unix.SOCK_DGRAM:
		return "udp"
	case typ == unix.SOCK_STREAM:
		return "tcp"
	}
	return "ip"
}

// record counts one observation. A UDP socket's creation is kept only when
// no destination of that process is seen, so sockets used through sendmmsg
// or other unwatched calls are still reported.
func (w *egressWatch) record(pid int, proto, dest string, sockets int) {
	exe, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if exe == "" {
		exe = "pid " + strconv.Itoa(pid)
	}
	key := proto + "\x00" + dest + "\x00" + exe
	w.mu.Lock()
	defer w.mu.Unlock()
	n := w.notes[key]
	if n == nil {
		if len(w.notes) >= maxEgressNotes {
			return
		}
		n = &egressNote{proto: proto, dest: dest, exe: exe, pid: pid}
		w.notes[key] = n
	}
	n.count++
}

// finish stops the watch and returns one proxy-bypass-attempt entry per
// destination.
func (w *egressWatch) finish() []config.AuditEntry {
	if w == nil {
		return nil
	}
	close(w.stop)
	<-w.done
	w.mu.Lock()
	defer w.mu.Unlock()
	withDest := map[string]bool{}
	for _, n := range w.notes {
		if n.dest != "" {
			withDest[n.exe] = true
		}
	}
	keys := make([]string, 0, len(w.notes))
	for k := range w.notes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []config.AuditEntry
	for _, k := range keys {
		n := w.notes[k]
		var target, detail string
		switch {
		case n.dest == "":
			if withDest[n.exe] {
				continue
			}
			target = "udp socket"
			detail = fmt.Sprintf("%s (pid %d) opened %d UDP socket(s) while egress is pinned to the proxy; Landlock does not confine UDP, so DNS lookups or QUIC can carry data past the hostname allowlist", n.exe, n.pid, n.count)
		case n.proto == "udp":
			target = "udp " + n.dest
			detail = fmt.Sprintf("%s (pid %d) sent UDP to %s %d time(s), outside the egress proxy; Landlock does not confine UDP, so DNS lookups or QUIC can carry data past the hostname allowlist", n.exe, n.pid, n.dest, n.count)
		default:
			target = n.proto + " " + n.dest
			detail = fmt.Sprintf("%s (pid %d) connected to %s %d time(s) without going through the egress proxy; Landlock confines TCP by port only, so a connection on an allowed port reaches any host", n.exe, n.pid, n.dest, n.count)
		}
		out = append(out, config.AuditEntry{Type: "proxy-bypass-attempt", Target: target, Detail: detail})
	}
	return out
}

// attachDetections prepares the cgroup watch and, for audited proxy-egress
// runs, the egress watch, adding their variables and descriptor to cmd.
func attachDetections(cfg config.ExecConfig, cmd *exec.Cmd, proxy *egressProxy) (*cgroupWatch, *egressWatch) {
	cg, env := prepareCgroupWatch(cfg, cmd.Env)
	port := 0
	if proxy != nil {
		port = proxy.port
	}
	egress := prepareEgressWatch(cfg, port)
	cmd.ExtraFiles, env = egress.attach(cmd.ExtraFiles, env)
	cmd.Env = env
	return cg, egress
}

// startDetections starts both watches once the inner process runs and
// returns the function that stops them and reports their findings.
func startDetections(cfg config.ExecConfig, cmd *exec.Cmd, cg *cgroupWatch, egress *egressWatch) func() {
	egress.started(cmd.Process.Pid)
	cg.start(cfg)
	return func() {
		emitDetections(egress.finish())
		emitDetections(cg.finish())
	}
}

// abandon closes both socket ends of a watch whose process never started.
func (w *egressWatch) abandon() {
	if w != nil {
		w.child.Close()
		w.parent.Close()
	}
}
