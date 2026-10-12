//go:build windows

package dlltrace

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// kernelProcessProvider is Microsoft-Windows-Kernel-Process.
var kernelProcessProvider = windows.GUID{Data1: 0x22fb2cd6, Data2: 0x0e7b, Data3: 0x422b, Data4: [8]byte{0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16}}

const (
	keywordProcess = 0x10 // WINEVENT_KEYWORD_PROCESS: process start and stop
	keywordImage   = 0x40 // WINEVENT_KEYWORD_IMAGE: image load and unload
	levelInfo      = 4

	eventProcessStart = 1
	eventProcessStop  = 2
	eventImageLoad    = 5

	wnodeFlagTracedGUID     = 0x00020000
	clientContextQPC        = 1
	eventTraceRealTimeMode  = 0x00000100
	processTraceRealTime    = 0x00000100
	processTraceRawTime     = 0x00001000
	processTraceEventRecord = 0x10000000
	controlStop             = 1
	controlFlush            = 3
	enableProvider          = 1
	disableProvider         = 0

	// sessionPrefix names every session this package starts. The engine's
	// PID and creation time follow it, so a session left behind by an engine
	// that was killed can be recognized and stopped.
	sessionPrefix = "safer-exec-dll-"

	maxNameChars = 1024
	// maxEvents bounds the memory a long run can use; events past it are
	// counted as lost.
	maxEvents = 1 << 20
	// stopTimeout is how long Stop waits for the consumer to drain the
	// session before it closes the consumer forcibly.
	stopTimeout = 10 * time.Second
	// readyTimeout is how long Start waits for the consumer to connect.
	readyTimeout = 10 * time.Second
)

var (
	advapi32               = windows.NewLazySystemDLL("advapi32.dll")
	tdh                    = windows.NewLazySystemDLL("tdh.dll")
	procStartTraceW        = advapi32.NewProc("StartTraceW")
	procControlTraceW      = advapi32.NewProc("ControlTraceW")
	procEnableTraceEx2     = advapi32.NewProc("EnableTraceEx2")
	procOpenTraceW         = advapi32.NewProc("OpenTraceW")
	procProcessTrace       = advapi32.NewProc("ProcessTrace")
	procCloseTrace         = advapi32.NewProc("CloseTrace")
	procQueryAllTracesW    = advapi32.NewProc("QueryAllTracesW")
	procEventRegister      = advapi32.NewProc("EventRegister")
	procEventUnregister    = advapi32.NewProc("EventUnregister")
	procEventWriteString   = advapi32.NewProc("EventWriteString")
	procTdhGetProperty     = tdh.NewProc("TdhGetProperty")
	procTdhGetPropertySize = tdh.NewProc("TdhGetPropertySize")
)

// ErrAccessDenied is returned when the user may not start an ETW session.
var ErrAccessDenied = errors.New("starting an ETW session needs administrator rights or membership in the Performance Log Users group")

// wnodeHeader is WNODE_HEADER.
type wnodeHeader struct {
	BufferSize        uint32
	ProviderID        uint32
	HistoricalContext uint64
	TimeStamp         int64
	GUID              windows.GUID
	ClientContext     uint32
	Flags             uint32
}

// eventTraceProperties is EVENT_TRACE_PROPERTIES.
type eventTraceProperties struct {
	Wnode               wnodeHeader
	BufferSize          uint32
	MinimumBuffers      uint32
	MaximumBuffers      uint32
	MaximumFileSize     uint32
	LogFileMode         uint32
	FlushTimer          uint32
	EnableFlags         uint32
	AgeLimit            int32
	NumberOfBuffers     uint32
	FreeBuffers         uint32
	EventsLost          uint32
	BuffersWritten      uint32
	LogBuffersLost      uint32
	RealTimeBuffersLost uint32
	LoggerThreadID      windows.Handle
	LogFileNameOffset   uint32
	LoggerNameOffset    uint32
}

// properties is EVENT_TRACE_PROPERTIES followed by the room StartTrace,
// ControlTrace and QueryAllTraces need for the session and log file names.
type properties struct {
	eventTraceProperties
	loggerName  [maxNameChars]uint16
	logFileName [maxNameChars]uint16
}

func newProperties() *properties {
	p := &properties{}
	p.Wnode.BufferSize = uint32(unsafe.Sizeof(*p))
	p.LoggerNameOffset = uint32(unsafe.Offsetof(p.loggerName))
	p.LogFileNameOffset = uint32(unsafe.Offsetof(p.logFileName))
	return p
}

func (p *properties) name() string {
	return windows.UTF16ToString(p.loggerName[:])
}

// eventDescriptor is EVENT_DESCRIPTOR.
type eventDescriptor struct {
	ID      uint16
	Version uint8
	Channel uint8
	Level   uint8
	Opcode  uint8
	Task    uint16
	Keyword uint64
}

// eventHeader is EVENT_HEADER.
type eventHeader struct {
	Size            uint16
	HeaderType      uint16
	Flags           uint16
	EventProperty   uint16
	ThreadID        uint32
	ProcessID       uint32
	TimeStamp       int64
	ProviderID      windows.GUID
	EventDescriptor eventDescriptor
	ProcessorTime   uint64
	ActivityID      windows.GUID
}

// eventRecord is EVENT_RECORD.
type eventRecord struct {
	EventHeader       eventHeader
	BufferContext     uint32
	ExtendedDataCount uint16
	UserDataLength    uint16
	ExtendedData      uintptr
	UserData          uintptr
	UserContext       uintptr
}

// eventTraceHeader is EVENT_TRACE_HEADER.
type eventTraceHeader struct {
	Size           uint16
	FieldTypeFlags uint16
	Version        uint32
	ThreadID       uint32
	ProcessID      uint32
	TimeStamp      int64
	GUID           windows.GUID
	ProcessorTime  uint64
}

// eventTrace is EVENT_TRACE.
type eventTrace struct {
	Header           eventTraceHeader
	InstanceID       uint32
	ParentInstanceID uint32
	ParentGUID       windows.GUID
	MofData          uintptr
	MofLength        uint32
	ClientContext    uint32
}

// traceLogfileHeader is TRACE_LOGFILE_HEADER.
type traceLogfileHeader struct {
	BufferSize         uint32
	Version            uint32
	ProviderVersion    uint32
	NumberOfProcessors uint32
	EndTime            int64
	TimerResolution    uint32
	MaximumFileSize    uint32
	LogFileMode        uint32
	BuffersWritten     uint32
	LogInstanceGUID    windows.GUID
	LoggerName         uintptr
	LogFileName        uintptr
	TimeZone           windows.Timezoneinformation
	BootTime           int64
	PerfFreq           int64
	StartTime          int64
	ReservedFlags      uint32
	BuffersLost        uint32
}

// eventTraceLogfile is EVENT_TRACE_LOGFILEW.
type eventTraceLogfile struct {
	LogFileName         *uint16
	LoggerName          *uint16
	CurrentTime         int64
	BuffersRead         uint32
	ProcessTraceMode    uint32
	CurrentEvent        eventTrace
	LogfileHeader       traceLogfileHeader
	BufferCallback      uintptr
	BufferSize          uint32
	Filled              uint32
	EventsLost          uint32
	EventRecordCallback uintptr
	IsKernelTrace       uint32
	Context             uintptr
}

// propertyDataDescriptor is PROPERTY_DATA_DESCRIPTOR.
type propertyDataDescriptor struct {
	PropertyName uint64
	ArrayIndex   uint32
	Reserved     uint32
}

// Property names, kept in package variables so the pointers TDH receives
// stay valid.
var (
	propProcessID       = windows.StringToUTF16("ProcessID")
	propParentProcessID = windows.StringToUTF16("ParentProcessID")
	propImageName       = windows.StringToUTF16("ImageName")
)

// args64 appends a 64-bit argument the way the platform's calling convention
// passes it: one register on 64-bit Windows, two stack slots on 32-bit.
func args64(args []uintptr, v uint64) []uintptr {
	if unsafe.Sizeof(uintptr(0)) == 8 {
		return append(args, uintptr(v))
	}
	return append(args, uintptr(uint32(v)), uintptr(uint32(v>>32)))
}

func etwError(r uintptr) error {
	if r == 0 {
		return nil
	}
	return windows.Errno(r)
}

// Session is a real-time ETW session recording process and image-load
// events. It records the whole system; Attribute picks out the traced tree.
type Session struct {
	name    string
	namePtr *uint16
	handle  uint64 // controller handle (StartTrace)
	trace   uint64 // consumer handle (OpenTrace)
	id      uintptr
	start   *properties
	logfile *eventTraceLogfile

	mu       sync.Mutex
	events   []Event
	interned map[string]string
	overflow uint64

	// marker is a private provider whose event, once delivered, proves the
	// consumer is attached.
	marker    windows.GUID
	ready     chan struct{}
	readyOnce sync.Once

	done     chan error
	stopping atomic.Bool
	stopOnce sync.Once
	result   Result
}

// Result is what a stopped session recorded.
type Result struct {
	Events []Event
	// Lost counts events the system dropped (buffers full) plus events past
	// the session's memory bound.
	Lost uint64
	// StoppedEarly is set when the session ended before Stop, for example
	// because another program stopped it; events after that are missing.
	StoppedEarly bool
	// Err reports a failure to stop or drain the session cleanly.
	Err error
}

var (
	sessionsMu  sync.Mutex
	sessions    = map[uintptr]*Session{}
	nextID      uintptr
	nameCounter atomic.Uint64
	callback    = sync.OnceValue(func() uintptr { return windows.NewCallback(onEvent) })
)

// Start begins recording. Sessions left behind by engines that were killed
// are stopped first, since Windows keeps a session until it is stopped or
// the machine restarts. The caller must call Stop.
func Start() (*Session, error) {
	s, err := newSession()
	if err != nil {
		return nil, err
	}
	if err := s.enable(); err != nil {
		s.abort()
		return nil, err
	}
	// A real-time session holds its buffers until a consumer connects, so
	// events logged before ProcessTrace attaches are still delivered. Stopping
	// the session before it attaches would lose them, though, so wait for it.
	if err := s.consume(); err != nil {
		s.abort()
		return nil, err
	}
	if err := s.waitReady(); err != nil {
		s.abort()
		return nil, err
	}
	return s, nil
}

// newSession starts the ETW session without a provider or a consumer.
func newSession() (*Session, error) {
	if err := advapi32.Load(); err != nil {
		return nil, err
	}
	if err := tdh.Load(); err != nil {
		return nil, err
	}
	stopStaleSessions()

	name, err := sessionName()
	if err != nil {
		return nil, err
	}
	s := &Session{
		name:     name,
		interned: make(map[string]string),
		ready:    make(chan struct{}),
		done:     make(chan error, 1),
	}
	s.namePtr, err = windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	// Set before the consumer starts, which reads it.
	if s.marker, err = windows.GenerateGUID(); err != nil {
		return nil, err
	}

	s.start = newProperties()
	s.start.Wnode.Flags = wnodeFlagTracedGUID
	s.start.Wnode.ClientContext = clientContextQPC
	s.start.LogFileMode = eventTraceRealTimeMode
	s.start.BufferSize = 64 // KB
	s.start.MinimumBuffers = 8
	s.start.MaximumBuffers = 128
	s.start.FlushTimer = 1 // second
	r, _, _ := procStartTraceW.Call(uintptr(unsafe.Pointer(&s.handle)), uintptr(unsafe.Pointer(s.namePtr)), uintptr(unsafe.Pointer(s.start)))
	if err := etwError(r); err != nil {
		return nil, startError(err)
	}

	sessionsMu.Lock()
	nextID++
	s.id = nextID
	sessions[s.id] = s
	sessionsMu.Unlock()
	return s, nil
}

// enable subscribes the session to Kernel-Process process and image events.
func (s *Session) enable() error {
	args := args64(nil, s.handle)
	args = append(args, uintptr(unsafe.Pointer(&kernelProcessProvider)), enableProvider, levelInfo)
	args = args64(args, keywordProcess|keywordImage)
	args = args64(args, 0)
	args = append(args, 0, 0)
	r, _, _ := procEnableTraceEx2.Call(args...)
	if err := etwError(r); err != nil {
		return startError(fmt.Errorf("enable Microsoft-Windows-Kernel-Process: %w", err))
	}
	return nil
}

// waitReady writes events from a private provider until the consumer
// delivers one.
func (s *Session) waitReady() error {
	var reg uint64
	r, _, _ := procEventRegister.Call(uintptr(unsafe.Pointer(&s.marker)), 0, 0, uintptr(unsafe.Pointer(&reg)))
	if err := etwError(r); err != nil {
		return fmt.Errorf("register ETW marker provider: %w", err)
	}
	defer procEventUnregister.Call(args64(nil, reg)...)
	args := args64(nil, s.handle)
	args = append(args, uintptr(unsafe.Pointer(&s.marker)), enableProvider, levelInfo)
	args = args64(args, 0)
	args = args64(args, 0)
	args = append(args, 0, 0)
	r, _, _ = procEnableTraceEx2.Call(args...)
	if err := etwError(r); err != nil {
		return fmt.Errorf("enable ETW marker provider: %w", err)
	}
	defer func() {
		args := args64(nil, s.handle)
		args = append(args, uintptr(unsafe.Pointer(&s.marker)), disableProvider, 0)
		args = args64(args, 0)
		args = args64(args, 0)
		args = append(args, 0, 0)
		_, _, _ = procEnableTraceEx2.Call(args...)
	}()

	text, _ := windows.UTF16PtrFromString("safer-exec dlltrace ready")
	deadline := time.After(readyTimeout)
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		wargs := args64(nil, reg)
		wargs = append(wargs, levelInfo)
		wargs = args64(wargs, 0)
		wargs = append(wargs, uintptr(unsafe.Pointer(text)))
		_, _, _ = procEventWriteString.Call(wargs...)
		_ = controlTrace(s.handle, nil, newProperties(), controlFlush)
		select {
		case <-s.ready:
			return nil
		case err := <-s.done:
			s.done <- err
			return fmt.Errorf("the ETW consumer ended before it connected: %v", err)
		case <-deadline:
			return errors.New("the ETW consumer did not connect")
		case <-tick.C:
		}
	}
}

func startError(err error) error {
	switch {
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		return ErrAccessDenied
	case errors.Is(err, windows.ERROR_NO_SYSTEM_RESOURCES):
		return fmt.Errorf("the system's ETW session limit is reached: %w", err)
	}
	return fmt.Errorf("start ETW session: %w", err)
}

// sessionName is unique per engine process and call.
func sessionName() (string, error) {
	created, err := processCreationTime(windows.CurrentProcess())
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s%d-%x-%d", sessionPrefix, os.Getpid(), created, nameCounter.Add(1)), nil
}

func processCreationTime(h windows.Handle) (uint64, error) {
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
		return 0, err
	}
	return uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime), nil
}

// consume opens the session as a real-time consumer and delivers its events
// on a dedicated OS thread.
func (s *Session) consume() error {
	s.logfile = &eventTraceLogfile{
		LoggerName:          s.namePtr,
		ProcessTraceMode:    processTraceRealTime | processTraceEventRecord | processTraceRawTime,
		EventRecordCallback: callback(),
		Context:             s.id,
	}
	r1, r2, err := procOpenTraceW.Call(uintptr(unsafe.Pointer(s.logfile)))
	handle := uint64(r1)
	if unsafe.Sizeof(uintptr(0)) == 4 {
		handle |= uint64(r2) << 32
	}
	if handle == ^uint64(0) || handle == 0xFFFFFFFF {
		return fmt.Errorf("open ETW session: %w", err)
	}
	s.trace = handle
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		r, _, _ := procProcessTrace.Call(uintptr(unsafe.Pointer(&s.trace)), 1, 0, 0)
		s.done <- etwError(r)
	}()
	return nil
}

// abort tears down a session that failed to start.
func (s *Session) abort() {
	s.stopping.Store(true)
	p := newProperties()
	_ = controlTrace(s.handle, nil, p, controlStop)
	if s.trace != 0 {
		select {
		case <-s.done:
		case <-time.After(stopTimeout):
			closeTrace(s.trace)
		}
		closeTrace(s.trace)
	}
	s.unregister()
}

// Stop ends the session and returns what it recorded. Events already logged
// are delivered before Stop returns. It is safe to call more than once.
func (s *Session) Stop() Result {
	s.stopOnce.Do(func() {
		select {
		case err := <-s.done:
			// The session ended before it was asked to.
			s.result.StoppedEarly = true
			s.done <- err
		default:
		}
		s.stopping.Store(true)
		p := newProperties()
		// Stopping flushes the buffers to the consumer, which then returns
		// from ProcessTrace.
		stopErr := controlTrace(s.handle, nil, p, controlStop)
		var consumeErr error
		select {
		case consumeErr = <-s.done:
		case <-time.After(stopTimeout):
			closeTrace(s.trace)
			consumeErr = errors.New("the ETW consumer did not drain the session in time")
			select {
			case <-s.done:
			case <-time.After(stopTimeout):
			}
		}
		closeTrace(s.trace)
		s.unregister()

		s.mu.Lock()
		s.result.Events = s.events
		s.result.Lost = s.overflow
		s.events = nil
		s.mu.Unlock()
		if stopErr == nil {
			s.result.Lost += uint64(p.EventsLost)
		}
		switch {
		case stopErr != nil && !s.result.StoppedEarly:
			s.result.Err = fmt.Errorf("stop ETW session: %w", stopErr)
		case consumeErr != nil && !errors.Is(consumeErr, windows.ERROR_CANCELLED):
			s.result.Err = consumeErr
		}
	})
	return s.result
}

func (s *Session) unregister() {
	sessionsMu.Lock()
	delete(sessions, s.id)
	sessionsMu.Unlock()
}

func controlTrace(handle uint64, name *uint16, p *properties, code uint32) error {
	args := args64(nil, handle)
	args = append(args, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(p)), uintptr(code))
	r, _, _ := procControlTraceW.Call(args...)
	return etwError(r)
}

func closeTrace(handle uint64) {
	_, _, _ = procCloseTrace.Call(args64(nil, handle)...)
}

// onEvent is the EventRecordCallback for every session.
func onEvent(rec *eventRecord) uintptr {
	sessionsMu.Lock()
	s := sessions[rec.UserContext]
	sessionsMu.Unlock()
	if s == nil {
		return 0
	}
	if rec.EventHeader.ProviderID != kernelProcessProvider {
		if rec.EventHeader.ProviderID == s.marker {
			s.readyOnce.Do(func() { close(s.ready) })
		}
		return 0
	}
	var e Event
	switch rec.EventHeader.EventDescriptor.ID {
	case eventProcessStart:
		e.Kind = ProcessStart
		e.ParentPID, _ = uint32Property(rec, propParentProcessID)
		e.Image = stringProperty(rec, propImageName)
	case eventProcessStop:
		e.Kind = ProcessStop
	case eventImageLoad:
		e.Kind = ImageLoad
		e.Image = stringProperty(rec, propImageName)
	default:
		return 0
	}
	pid, ok := uint32Property(rec, propProcessID)
	if !ok {
		return 0
	}
	e.PID = pid
	e.Time = rec.EventHeader.TimeStamp

	s.mu.Lock()
	if len(s.events) >= maxEvents {
		s.overflow++
	} else {
		if e.Image != "" {
			if v, ok := s.interned[e.Image]; ok {
				e.Image = v
			} else {
				s.interned[e.Image] = e.Image
			}
		}
		s.events = append(s.events, e)
	}
	s.mu.Unlock()
	return 0
}

func descriptor(name []uint16) propertyDataDescriptor {
	return propertyDataDescriptor{PropertyName: uint64(uintptr(unsafe.Pointer(&name[0]))), ArrayIndex: ^uint32(0)}
}

func uint32Property(rec *eventRecord, name []uint16) (uint32, bool) {
	d := descriptor(name)
	var v uint32
	r, _, _ := procTdhGetProperty.Call(uintptr(unsafe.Pointer(rec)), 0, 0, 1, uintptr(unsafe.Pointer(&d)), unsafe.Sizeof(v), uintptr(unsafe.Pointer(&v)))
	return v, r == 0
}

func stringProperty(rec *eventRecord, name []uint16) string {
	d := descriptor(name)
	var size uint32
	r, _, _ := procTdhGetPropertySize.Call(uintptr(unsafe.Pointer(rec)), 0, 0, 1, uintptr(unsafe.Pointer(&d)), uintptr(unsafe.Pointer(&size)))
	if r != 0 || size < 2 || size > 64*1024 {
		return ""
	}
	buf := make([]uint16, size/2)
	r, _, _ = procTdhGetProperty.Call(uintptr(unsafe.Pointer(rec)), 0, 0, 1, uintptr(unsafe.Pointer(&d)), uintptr(size), uintptr(unsafe.Pointer(&buf[0])))
	if r != 0 {
		return ""
	}
	return windows.UTF16ToString(buf)
}

// Probe reports whether this process can trace image loads: it starts a
// session, enables the provider and stops it again.
func Probe() error {
	s, err := Start()
	if err != nil {
		return err
	}
	return s.Stop().Err
}

// stopStaleSessions stops sessions this package started in engine processes
// that no longer run.
func stopStaleSessions() {
	const maxSessions = 64
	bufs := make([]*properties, maxSessions)
	ptrs := make([]uintptr, maxSessions)
	for i := range bufs {
		bufs[i] = newProperties()
		ptrs[i] = uintptr(unsafe.Pointer(bufs[i]))
	}
	var count uint32
	r, _, _ := procQueryAllTracesW.Call(uintptr(unsafe.Pointer(&ptrs[0])), maxSessions, uintptr(unsafe.Pointer(&count)))
	runtime.KeepAlive(bufs)
	if r != 0 && windows.Errno(r) != windows.ERROR_MORE_DATA {
		return
	}
	for i := 0; i < int(count) && i < maxSessions; i++ {
		name := bufs[i].name()
		if !strings.HasPrefix(name, sessionPrefix) || ownerRunning(name) {
			continue
		}
		namePtr, err := windows.UTF16PtrFromString(name)
		if err != nil {
			continue
		}
		_ = controlTrace(0, namePtr, newProperties(), controlStop)
	}
}

// ownerRunning reports whether the engine that named a session is still
// running: the same PID with the same creation time.
func ownerRunning(name string) bool {
	fields := strings.Split(strings.TrimPrefix(name, sessionPrefix), "-")
	if len(fields) != 3 {
		return true // not a name this package made; leave it alone
	}
	pid, err1 := strconv.ParseUint(fields[0], 10, 32)
	created, err2 := strconv.ParseUint(fields[1], 16, 64)
	if err1 != nil || err2 != nil {
		return true
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		// Access denied means a process we cannot inspect holds the PID;
		// assume it is the owner.
		return errors.Is(err, windows.ERROR_ACCESS_DENIED)
	}
	defer windows.CloseHandle(h)
	var code uint32
	if windows.GetExitCodeProcess(h, &code) == nil && code != 259 { // STILL_ACTIVE
		return false
	}
	actual, err := processCreationTime(h)
	return err != nil || actual == created
}

// SystemPathMapper maps this machine's kernel device paths to drive letters.
func SystemPathMapper() *PathMapper {
	drives := make(map[string]string)
	buf := make([]uint16, windows.MAX_PATH)
	for c := 'A'; c <= 'Z'; c++ {
		drive := string(c) + ":"
		name, err := windows.UTF16PtrFromString(drive)
		if err != nil {
			continue
		}
		n, err := windows.QueryDosDevice(name, &buf[0], uint32(len(buf)))
		if err != nil || n == 0 {
			continue
		}
		// The first of the NUL-separated targets is the current one.
		drives[drive] = windows.UTF16ToString(buf[:n])
	}
	root, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		root = os.Getenv("SystemRoot")
	}
	return NewPathMapper(drives, root)
}
