/* ssl_trace.c — eBPF uprobe program for HTTP URL tracing.
 *
 * Attaches to SSL_write (OpenSSL/BoringSSL), gnutls_record_send (GnuTLS),
 * and go_tls_conn_write (Go crypto/tls) to capture plaintext TLS writes
 * before encryption happens in userspace.
 *
 * Compile for amd64:
 *   clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
 *     -I /usr/include/x86_64-linux-gnu -I /usr/include \
 *     -c ssl_trace.c -o ssl_trace_linux_amd64.o
 *
 * Compile for arm64:
 *   clang -O2 -g -target bpf -D__TARGET_ARCH_arm64 \
 *     -I /usr/include/aarch64-linux-gnu -I /usr/include \
 *     -c ssl_trace.c -o ssl_trace_linux_arm64.o
 *
 * Requires: kernel >= 5.8 (BPF ring buffer + stable uprobe ABI)
 */

/* Pull in struct pt_regs and __u8/__u32 before including bpf headers. */
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_BUF_SIZE 512

/* Source identifiers embedded in each ring-buffer event. */
#define SOURCE_SSL_WRITE      0
#define SOURCE_GO_TLS_WRITE   1
#define SOURCE_GNUTLS_SEND    2

/* Each SSL write produces one event in the ring buffer. */
struct ssl_event {
    __u32 pid;
    __u32 len;    /* bytes actually captured (capped at MAX_BUF_SIZE) */
    __u8  source; /* SOURCE_* constant above */
    __u8  pad[3];
    __u8  buf[MAX_BUF_SIZE];
};

/* Ring buffer — 512 KB. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} events SEC(".maps");

/*
 * PID filter map. Key = host TGID (u32), value = 1.
 * The Go side populates this with the process tree before the probes fire
 * and refreshes it as child processes are created.
 * If the map is empty AND FLAG_TRACE_ALL is not set, no events are emitted.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 65536);
} pid_filter SEC(".maps");

/*
 * Single-entry config array (index 0 = flags byte).
 * Bit 0 (FLAG_TRACE_ALL): bypass pid_filter, capture everything.
 */
#define FLAG_TRACE_ALL 0x01

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 1);
} config_flags SEC(".maps");

/* ── Go ABI helpers ───────────────────────────────────────────────────────
 * Go 1.17+ uses a register-based calling convention that differs from the
 * C/System-V ABI on AMD64. On AMD64 Go assigns arguments in:
 *   AX(RAX), BX(RBX), CX(RCX), DI(RDI), SI(RSI), R8, R9, R10, R11
 * so for (*Conn).Write(b []byte):
 *   receiver *Conn = AX, b.Data = BX, b.Len = CX
 *
 * On ARM64 the Go ABI matches the C ABI for the first few arguments
 * (R0=receiver, R1=b.Data, R2=b.Len), so we can use PT_REGS_PARM*.
 */
#if defined(__TARGET_ARCH_x86)
/* Go AMD64 ABI: receiver=rax, b.Data=rbx, b.Len=rcx
 * rcx = PT_REGS_PARM4 in C calling convention (rcx is 4th C arg).
 * Use long names since we get the UAPI struct from linux/ptrace.h. */
#define GO_SLICE_DATA_REG(ctx) ((ctx)->rbx)
#define GO_SLICE_LEN_REG(ctx)  PT_REGS_PARM4(ctx)
#elif defined(__TARGET_ARCH_arm64)
/* ARM64 Go ABI = C ABI for first args: R0=receiver, R1=ptr, R2=len */
#define GO_SLICE_DATA_REG(ctx) PT_REGS_PARM2(ctx)
#define GO_SLICE_LEN_REG(ctx)  PT_REGS_PARM3(ctx)
#else
/* Unsupported architecture — probes will be compiled as no-ops. */
#define GO_SLICE_DATA_REG(ctx) (0UL)
#define GO_SLICE_LEN_REG(ctx)  (0UL)
#endif

/* Shared capture logic used by all three probes. */
static __always_inline int capture(void *buf_ptr, __u32 buf_len, __u8 source)
{
    if (!buf_ptr || buf_len == 0)
        return 0;

    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    __u32 key0 = 0;
    __u8 *flags = bpf_map_lookup_elem(&config_flags, &key0);
    if (!flags || !(*flags & FLAG_TRACE_ALL)) {
        __u8 *allowed = bpf_map_lookup_elem(&pid_filter, &pid);
        if (!allowed)
            return 0;
    }

    struct ssl_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    ev->pid    = pid;
    /* Store actual write length for userspace; we always read sizeof(ev->buf)
     * bytes below so the BPF verifier sees a compile-time constant size
     * instead of a runtime value — the only reliable way to pass the verifier
     * across kernel versions (5.8 through 6.x). */
    ev->len    = buf_len < MAX_BUF_SIZE ? buf_len : MAX_BUF_SIZE;
    ev->source = source;
    ev->pad[0] = ev->pad[1] = ev->pad[2] = 0;

    if (bpf_probe_read_user(ev->buf, sizeof(ev->buf), buf_ptr) < 0) {
        bpf_ringbuf_discard(ev, 0);
        return 0;
    }

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/* ── OpenSSL / BoringSSL ─────────────────────────────────────────────────
 * int SSL_write(SSL *ssl, const void *buf, int num)
 */
SEC("uprobe/SSL_write")
int probe_ssl_write(struct pt_regs *ctx)
{
    void  *buf = (void *)PT_REGS_PARM2(ctx);
    __u32  num = (__u32)(unsigned long)PT_REGS_PARM3(ctx);
    return capture(buf, num, SOURCE_SSL_WRITE);
}

/* ── GnuTLS ─────────────────────────────────────────────────────────────
 * ssize_t gnutls_record_send(session, const void *data, size_t sizeofdata)
 */
SEC("uprobe/gnutls_record_send")
int probe_gnutls_send(struct pt_regs *ctx)
{
    void  *buf = (void *)PT_REGS_PARM2(ctx);
    __u32  num = (__u32)(unsigned long)PT_REGS_PARM3(ctx);
    return capture(buf, num, SOURCE_GNUTLS_SEND);
}

/* ── Go crypto/tls (*Conn).Write ─────────────────────────────────────────
 * func (c *Conn) Write(b []byte) (int, error)
 * The symbol name "go_tls_conn_write" is a placeholder; the Go loader
 * resolves the real mangled symbol from the target binary's symbol table.
 */
SEC("uprobe/go_tls_conn_write")
int probe_go_tls_write(struct pt_regs *ctx)
{
    void  *buf_ptr = (void *)(unsigned long)GO_SLICE_DATA_REG(ctx);
    __u32  buf_len = (__u32)(unsigned long)GO_SLICE_LEN_REG(ctx);
    return capture(buf_ptr, buf_len, SOURCE_GO_TLS_WRITE);
}

char _license[] SEC("license") = "GPL";
