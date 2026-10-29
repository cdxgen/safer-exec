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
	name    string
	dir     string
	sampler *contentionSampler
}

// prepareCgroupWatch adds the cgroup variables to the inner process's
// environment and returns the watch, whose start must be called after the
// inner process has started.
func prepareCgroupWatch(cfg config.ExecConfig, env []string) (*cgroupWatch, []string) {
	name := newCgroupName()
	env = append(env, envCgroupName+"="+name)
	w := &cgroupWatch{name: name}
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
	dirs := []string{}
	if w.dir != "" {
		dirs = append(dirs, w.dir)
	}
	for _, ctrl := range []string{"memory", "cpu", "pids", "blkio"} {
		dirs = append(dirs, filepath.Join("/sys/fs/cgroup", ctrl, w.name))
	}
	for _, d := range dirs {
		// A process that outlived the run (reduced isolation has no PID
		// namespace) keeps the cgroup busy; give it a moment, then leave it.
		for i := 0; i < 5; i++ {
			if err := os.Remove(d); err == nil || os.IsNotExist(err) {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
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
	// _IOR('!', 2, __u64): the original encoding, which every kernel with
	// user notification accepts; 5.9 added the corrected _IOW alias.
	seccompIoctlNotifIDValid = 0x80082102
	seccompNotifSize         = 80
	seccompNotifRespSize     = 24
)

// egressNotifySupported reports whether the kernel can let a notified
// syscall continue (SECCOMP_USER_NOTIF_FLAG_CONTINUE, Linux 5.5). Without it a
// supervisor could only fail or emulate the call, which would break it.
func egressNotifySupported() bool {
	var u unix.Utsname
	if unix.Uname(&u) != nil {
		return false
	}
	return parseKernelVersion(unix.ByteSliceToString(u.Release[:])) >= 5.05
}

// egressNotifyProgram returns the filter that notifies the supervisor of
// socket(AF_INET/AF_INET6, SOCK_DGRAM), connect, and sendto with a
// destination address. Everything else is allowed without a notification.
//
// sendmsg is deliberately not watched. The inner process hands the listener
// to the engine with sendmsg (SCM_RIGHTS) after the filter is in place, so a
// watched sendmsg would wait for a supervisor that does not have the listener
// yet. It is also the hot path of connected UDP and of IPC, where a round trip
// per call would slow workloads down. A UDP socket is still reported when it
// is created; only the destinations of unconnected sendmsg/sendmmsg go unseen.
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
		{Code: jeq, Jt: 8, K: unix.SOCK_DGRAM},
		allow,
		{Code: jeq, Jt: 6, K: unix.SYS_CONNECT},
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
// seccomp filter. It installs egressNotifyProgram with a listener and passes
// the listener to the outer engine over the socket in SAFER_EXEC_NOTIFY_FD
// with SCM_RIGHTS, which needs no permission the engine could be denied (as
// pidfd_getfd does under Docker's default profile). Once the engine holds the
// listener, this process closes its own copy. If the handoff fails the
// watched calls would fail with ENOSYS for lack of a supervisor, so that is
// reported loudly; it only happens when the engine is already gone.
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
	if err := unix.Sendmsg(sock, []byte{1}, unix.UnixRights(int(listener)), nil, 0); err != nil {
		fmt.Fprintf(os.Stderr, "safer-exec: warning: egress watch: passing the listener failed (%v); watched network calls will fail\n", err)
	}
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
	exes  map[int]string // executable per pid, read once
}

type egressNote struct {
	proto, dest, exe string
	pid              int
	count            int
}

// maxEgressNotes caps the distinct destinations recorded, and maxExeCache
// the executables remembered per pid.
const (
	maxEgressNotes = 256
	maxExeCache    = 1024
)

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
		exes:      make(map[int]string),
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
func (w *egressWatch) started() {
	if w == nil {
		return
	}
	w.child.Close()
	go w.serve()
}

// receiveListener waits for the listener from the inner process. It returns
// -1 when the run ends first or the inner process never sends one.
func (w *egressWatch) receiveListener() int {
	oob := make([]byte, unix.CmsgSpace(4))
	buf := make([]byte, 1)
	for {
		select {
		case <-w.stop:
			return -1
		default:
		}
		fds := []unix.PollFd{{Fd: int32(w.parent.Fd()), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, 100)
		if err != nil && err != unix.EINTR {
			return -1
		}
		if n <= 0 {
			continue
		}
		_, oobn, _, _, err := unix.Recvmsg(int(w.parent.Fd()), buf, oob, unix.MSG_CMSG_CLOEXEC)
		if err != nil {
			return -1
		}
		msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
		if err != nil || len(msgs) == 0 {
			return -1
		}
		fds2, err := unix.ParseUnixRights(&msgs[0])
		if err != nil || len(fds2) == 0 {
			return -1
		}
		return fds2[0]
	}
}

func (w *egressWatch) serve() {
	defer close(w.done)
	defer w.parent.Close()
	listener := w.receiveListener()
	if listener < 0 {
		return
	}
	// The listener is closed only when the run is over. Closing it earlier
	// would make every watched call of the workload fail with ENOSYS, so
	// unexpected errors are retried instead. A process that outlives the run
	// (reduced isolation has no PID namespace) gets ENOSYS afterwards rather
	// than waiting forever for an answer.
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
		if err != nil {
			if err != unix.EINTR {
				time.Sleep(10 * time.Millisecond)
			}
			continue
		}
		if n == 0 {
			continue
		}
		if fds[0].Revents&unix.POLLIN == 0 {
			if fds[0].Revents&unix.POLLHUP != 0 {
				return // every watched process has exited
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		clear(notif)
		if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(listener), seccompIoctlNotifRecv, uintptr(unsafe.Pointer(&notif[0]))); errno != 0 {
			if errno != unix.EINTR && errno != unix.ENOENT {
				time.Sleep(10 * time.Millisecond)
			}
			continue
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
		w.record(pid, "udp", "")
		return
	case unix.SYS_CONNECT:
		fd, addr, addrLen = int(arg(0)), arg(1), arg(2)
	case unix.SYS_SENDTO:
		fd, addr, addrLen = int(arg(0)), arg(4), arg(5)
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
	w.record(pid, proto, dest)
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

// socketProto names the type of socket fd in thread tid: "udp", "tcp", or
// "ip" when it cannot be told.
//
// It first duplicates the descriptor (pidfd_getfd on the thread group, so
// calls from any thread work before Linux 6.9's PIDFD_THREAD) and asks the
// socket. The duplicate is closed on a separate goroutine: if the workload
// closes its own copy meanwhile, ours is the last reference, and a socket
// with SO_LINGER set makes that close wait. At most maxDupClosers such closes
// run at once; beyond that, and where pidfd_getfd is denied (Docker's
// default profile without CAP_SYS_PTRACE), the type comes from the socket
// tables in /proc, which list a UDP socket only once it is bound.
func socketProto(tid, fd int) string {
	if typ, ok := socketTypeByDup(tid, fd); ok {
		return typ
	}
	link, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", tid, fd))
	if err != nil {
		return "ip"
	}
	inode, ok := strings.CutPrefix(link, "socket:[")
	if !ok {
		return "ip"
	}
	inode = strings.TrimSuffix(inode, "]")
	for _, t := range []struct{ table, proto string }{{"udp", "udp"}, {"udp6", "udp"}, {"tcp", "tcp"}, {"tcp6", "tcp"}} {
		if socketTableHas(fmt.Sprintf("/proc/%d/net/%s", tid, t.table), inode) {
			return t.proto
		}
	}
	return "ip"
}

// maxDupClosers bounds the goroutines closing duplicated sockets.
const maxDupClosers = 64

var dupClosers = make(chan struct{}, maxDupClosers)

func socketTypeByDup(tid, fd int) (string, bool) {
	select {
	case dupClosers <- struct{}{}:
	default:
		return "", false
	}
	release := func() { <-dupClosers }
	pidfd, err := unix.PidfdOpen(threadGroup(tid), 0)
	if err != nil {
		release()
		return "", false
	}
	dup, err := unix.PidfdGetfd(pidfd, fd, 0)
	unix.Close(pidfd)
	if err != nil {
		release()
		return "", false
	}
	typ, err := unix.GetsockoptInt(dup, unix.SOL_SOCKET, unix.SO_TYPE)
	go func() {
		unix.Close(dup)
		release()
	}()
	switch {
	case err != nil:
		return "", false
	case typ == unix.SOCK_DGRAM:
		return "udp", true
	case typ == unix.SOCK_STREAM:
		return "tcp", true
	}
	return "ip", true
}

// threadGroup returns the thread-group id of tid, or tid itself.
func threadGroup(tid int) int {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", tid))
	if err != nil {
		return tid
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "Tgid:"); ok {
			if pid, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				return pid
			}
		}
	}
	return tid
}

// socketTableHas reports whether a /proc/net socket table lists inode.
func socketTableHas(path, inode string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) > 9 && fields[9] == inode {
			return true
		}
	}
	return false
}

// exeOf returns pid's executable, read once per pid.
func (w *egressWatch) exeOf(pid int) string {
	w.mu.Lock()
	exe, ok := w.exes[pid]
	w.mu.Unlock()
	if ok {
		return exe
	}
	exe, _ = os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if exe == "" {
		exe = "pid " + strconv.Itoa(pid)
	}
	w.mu.Lock()
	if len(w.exes) < maxExeCache {
		w.exes[pid] = exe
	}
	w.mu.Unlock()
	return exe
}

// record counts one observation: a UDP socket's creation (dest "") or a
// destination.
func (w *egressWatch) record(pid int, proto, dest string) {
	exe := w.exeOf(pid)
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
// destination, and one per executable that opened UDP sockets. It waits for
// the serve loop at most a couple of seconds.
func (w *egressWatch) finish() []config.AuditEntry {
	if w == nil {
		return nil
	}
	close(w.stop)
	select {
	case <-w.done:
	case <-time.After(2 * time.Second):
	}
	w.mu.Lock()
	defer w.mu.Unlock()
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
			target = "udp socket"
			detail = fmt.Sprintf("%s (pid %d) opened %d UDP socket(s) while egress is pinned to the proxy; Landlock does not confine UDP, so DNS lookups or QUIC can carry data past the hostname allowlist", n.exe, n.pid, n.count)
		case n.proto == "udp":
			target = "udp " + n.dest
			detail = fmt.Sprintf("%s (pid %d) sent UDP to %s %d time(s), outside the egress proxy; Landlock does not confine UDP, so DNS lookups or QUIC can carry data past the hostname allowlist", n.exe, n.pid, n.dest, n.count)
		case n.proto == "tcp":
			target = "tcp " + n.dest
			detail = fmt.Sprintf("%s (pid %d) connected to %s %d time(s) without going through the egress proxy; Landlock confines TCP by port only, so a connection on an allowed port reaches any host", n.exe, n.pid, n.dest, n.count)
		default:
			target = "ip " + n.dest
			detail = fmt.Sprintf("%s (pid %d) addressed %s %d time(s) without going through the egress proxy (socket type unknown); Landlock does not confine UDP and confines TCP by port only", n.exe, n.pid, n.dest, n.count)
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
	egress.started()
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
