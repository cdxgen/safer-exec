/* ssl_trace.c — eBPF uprobe program for HTTP URL tracing.
 *
 * Attaches to SSL_write (OpenSSL/BoringSSL), gnutls_record_send (GnuTLS),
 * and go_tls_conn_write (Go crypto/tls) to capture plaintext TLS writes
 * before encryption happens in userspace.  Supports HTTP/1.x and HTTP/2
 * (binary-framed) traffic; HTTP/2 HPACK decoding is performed in userspace.
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

#define MAX_BUF_SIZE 4096

/* Source identifiers embedded in each ring-buffer event. */
#define SOURCE_SSL_WRITE      0
#define SOURCE_GO_TLS_WRITE   1
#define SOURCE_GNUTLS_SEND    2

/* Each SSL write produces one event in the ring buffer.
 * Layout (explicit padding to ensure natural alignment):
 *   offset  0: pid      u32
 *   offset  4: len      u32
 *   offset  8: source   u8
 *   offset  9: pad      u8[7]  (7 bytes to align conn_id to offset 16)
 *   offset 16: conn_id  u64
 *   offset 24: buf      u8[MAX_BUF_SIZE]
 */
struct ssl_event {
    __u32 pid;
    __u32 len;      /* bytes actually captured (capped at MAX_BUF_SIZE) */
    __u8  source;   /* SOURCE_* constant above */
    __u8  pad[7];   /* explicit padding to align conn_id to 8-byte boundary */
    __u64 conn_id;  /* SSL* / session pointer — uniquely identifies the TLS connection */
    __u8  buf[MAX_BUF_SIZE];
};

/* Ring buffer — 4 MB (larger events require more headroom). */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
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

/* Shared capture logic used by all three probes.
 * conn_id is the TLS connection pointer (SSL* / session handle) cast to u64;
 * userspace uses it to key per-connection HPACK decoder state for HTTP/2. */
static __always_inline int capture(void *buf_ptr, __u32 buf_len, __u8 source, __u64 conn_id)
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

    ev->pid     = pid;
    /* Store actual write length for userspace; we always read sizeof(ev->buf)
     * bytes below so the BPF verifier sees a compile-time constant size
     * instead of a runtime value — the only reliable way to pass the verifier
     * across kernel versions (5.8 through 6.x). */
    ev->len     = buf_len < MAX_BUF_SIZE ? buf_len : MAX_BUF_SIZE;
    ev->source  = source;
    ev->pad[0]  = ev->pad[1] = ev->pad[2] = 0;
    ev->conn_id = conn_id;

    if (bpf_probe_read_user(ev->buf, sizeof(ev->buf), buf_ptr) < 0) {
        bpf_ringbuf_discard(ev, 0);
        return 0;
    }

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/* ── OpenSSL / BoringSSL ─────────────────────────────────────────────────
 * int SSL_write(SSL *ssl, const void *buf, int num)
 * PARM1 = SSL* (used as conn_id to key per-connection HPACK state)
 */
SEC("uprobe/SSL_write")
int probe_ssl_write(struct pt_regs *ctx)
{
    __u64  conn_id = (unsigned long)PT_REGS_PARM1(ctx);
    void  *buf     = (void *)PT_REGS_PARM2(ctx);
    __u32  num     = (__u32)(unsigned long)PT_REGS_PARM3(ctx);
    return capture(buf, num, SOURCE_SSL_WRITE, conn_id);
}

/* int SSL_write_ex(SSL *s, const void *buf, size_t num, size_t *written)
 * PARM1 = SSL* (conn_id)
 * PARM2 = buf
 * PARM3 = num
 */
SEC("uprobe/SSL_write_ex")
int probe_ssl_write_ex(struct pt_regs *ctx)
{
    __u64  conn_id = (unsigned long)PT_REGS_PARM1(ctx);
    void  *buf     = (void *)PT_REGS_PARM2(ctx);
    __u32  num     = (__u32)(unsigned long)PT_REGS_PARM3(ctx);
    return capture(buf, num, SOURCE_SSL_WRITE, conn_id);
}

/* ── GnuTLS ─────────────────────────────────────────────────────────────
 * ssize_t gnutls_record_send(session, const void *data, size_t sizeofdata)
 * PARM1 = session handle (used as conn_id)
 */
SEC("uprobe/gnutls_record_send")
int probe_gnutls_send(struct pt_regs *ctx)
{
    __u64  conn_id = (unsigned long)PT_REGS_PARM1(ctx);
    void  *buf     = (void *)PT_REGS_PARM2(ctx);
    __u32  num     = (__u32)(unsigned long)PT_REGS_PARM3(ctx);
    return capture(buf, num, SOURCE_GNUTLS_SEND, conn_id);
}

/* ── Go crypto/tls (*Conn).Write ─────────────────────────────────────────
 * func (c *Conn) Write(b []byte) (int, error)
 * The symbol name "go_tls_conn_write" is a placeholder; the Go loader
 * resolves the real mangled symbol from the target binary's symbol table.
 * The receiver pointer (*Conn) serves as conn_id.
 */
SEC("uprobe/go_tls_conn_write")
int probe_go_tls_write(struct pt_regs *ctx)
{
#if defined(__TARGET_ARCH_x86)
    __u64  conn_id = (unsigned long)(ctx)->rax;  /* Go AMD64: receiver = rax */
#elif defined(__TARGET_ARCH_arm64)
    __u64  conn_id = (unsigned long)PT_REGS_PARM1(ctx);  /* ARM64: receiver = R0 */
#else
    __u64  conn_id = 0;
#endif
    void  *buf_ptr = (void *)(unsigned long)GO_SLICE_DATA_REG(ctx);
    __u32  buf_len = (__u32)(unsigned long)GO_SLICE_LEN_REG(ctx);
    return capture(buf_ptr, buf_len, SOURCE_GO_TLS_WRITE, conn_id);
}

/* Source identifiers embedded in each ring-buffer event. */
#define SOURCE_SSL_WRITE      0
#define SOURCE_GO_TLS_WRITE   1
#define SOURCE_GNUTLS_SEND    2
#define SOURCE_RAW_HANDSHAKE  3

/* ── Cipher Ring Buffer ───────────────────────────────────────────────────
 * Separate ring buffer for cipher-negotiation events. Each cipher event
 * carries the SSL* pointer (conn_id) and the cipher name string so userspace
 * can correlate cipher suites to HTTP requests on the same connection.
 */
#define MAX_CIPHER_NAME 128

struct cipher_event {
    __u32 pid;
    __u32 source;  /* SOURCE_* constant */
    __u32 pad;     /* explicit padding to 8-byte boundary */
    __u64 conn_id; /* SSL* / session pointer */
    __u32 bits;    /* secret bits from SSL_CIPHER_get_bits */
    __u8  name[MAX_CIPHER_NAME];  /* cipher name string (NUL-terminated) */
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  /* 256 KB — small events, ample headroom */
} cipher_events SEC(".maps");

/* Maps to store entry arguments for uretprobes to avoid verifier rejections on older/stripped kernels */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u64);
    __uint(max_entries, 1024);
} ssl_get_current_cipher_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u64);
    __uint(max_entries, 1024);
} ssl_cipher_get_name_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u64);
    __uint(max_entries, 1024);
} ssl_cipher_get_bits_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u64);
    __uint(max_entries, 1024);
} ssl_get_version_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u64);
    __uint(max_entries, 1024);
} libc_read_args SEC(".maps");

/* ── OpenSSL Cipher Detection ────────────────────────────────────────────
 * const SSL_CIPHER *SSL_get_current_cipher(const SSL *ssl)
 * Returns the cipher in use for the connection after handshake completes.
 * PARM1 = SSL* (conn_id)
 *
 * const char *SSL_CIPHER_get_name(const SSL_CIPHER *cipher)
 * Returns a human-readable cipher suite name.
 * We hook SSL_CIPHER_get_name and use PARM1 (cipher*) as a unique key;
 * the SSL* and cipher* are linked in userspace via a separate SSL_get_current_cipher hook.
 *
 * const char *SSL_get_version(const SSL *ssl)
 * Returns TLS protocol version string (e.g. "TLSv1.2").
 *
 * int SSL_CIPHER_get_bits(const SSL_CIPHER *cipher, int *alg_bits)
 * Returns the number of secret bits. PARM1 = cipher*.
 */
SEC("uprobe/SSL_get_current_cipher")
int probe_ssl_cipher_entry(struct pt_regs *ctx)
{
    __u64 conn_id = (unsigned long)PT_REGS_PARM1(ctx);
    __u64 tgid_tid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&ssl_get_current_cipher_args, &tgid_tid, &conn_id, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_get_current_cipher")
int probe_ssl_cipher(struct pt_regs *ctx)
{
    __u64 tgid_tid = bpf_get_current_pid_tgid();
    __u64 *conn_id_ptr = bpf_map_lookup_elem(&ssl_get_current_cipher_args, &tgid_tid);
    if (!conn_id_ptr)
        return 0;
    __u64 conn_id = *conn_id_ptr;
    bpf_map_delete_elem(&ssl_get_current_cipher_args, &tgid_tid);

    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    __u32 key0 = 0;
    __u8 *flags = bpf_map_lookup_elem(&config_flags, &key0);
    if (!flags || !(*flags & FLAG_TRACE_ALL)) {
        __u8 *allowed = bpf_map_lookup_elem(&pid_filter, &pid);
        if (!allowed)
            return 0;
    }

    struct cipher_event *ev = bpf_ringbuf_reserve(&cipher_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    __u64 cipher_ptr = (unsigned long)PT_REGS_RC(ctx);
    ev->pid     = pid;
    ev->source  = SOURCE_SSL_WRITE;
    ev->pad     = 0;
    ev->conn_id = conn_id;
    ev->bits    = (__u32)cipher_ptr;  /* store cipher* in bits field temporarily */
    __builtin_memset(ev->name, 0, MAX_CIPHER_NAME);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("uprobe/SSL_CIPHER_get_name")
int probe_ssl_cipher_name_entry(struct pt_regs *ctx)
{
    __u64 cipher_ptr = (unsigned long)PT_REGS_PARM1(ctx);
    __u64 tgid_tid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&ssl_cipher_get_name_args, &tgid_tid, &cipher_ptr, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_CIPHER_get_name")
int probe_ssl_cipher_name(struct pt_regs *ctx)
{
    __u64 tgid_tid = bpf_get_current_pid_tgid();
    __u64 *cipher_ptr_ptr = bpf_map_lookup_elem(&ssl_cipher_get_name_args, &tgid_tid);
    if (!cipher_ptr_ptr)
        return 0;
    __u64 cipher_ptr = *cipher_ptr_ptr;
    bpf_map_delete_elem(&ssl_cipher_get_name_args, &tgid_tid);

    const char *name = (const char *)PT_REGS_RC(ctx);

    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    __u32 key0 = 0;
    __u8 *flags = bpf_map_lookup_elem(&config_flags, &key0);
    if (!flags || !(*flags & FLAG_TRACE_ALL)) {
        __u8 *allowed = bpf_map_lookup_elem(&pid_filter, &pid);
        if (!allowed)
            return 0;
    }

    if (!name)
        return 0;

    struct cipher_event *ev = bpf_ringbuf_reserve(&cipher_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    ev->pid     = pid;
    ev->source  = SOURCE_SSL_WRITE;
    ev->pad     = 0;
    ev->conn_id = (__u32)cipher_ptr;  /* store cipher* as conn_id for correlation */
    ev->bits    = 0;
    long ret = bpf_probe_read_user_str(ev->name, MAX_CIPHER_NAME, name);
    if (ret < 0) {
        bpf_ringbuf_discard(ev, 0);
        return 0;
    }

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("uprobe/SSL_CIPHER_get_bits")
int probe_ssl_cipher_bits_entry(struct pt_regs *ctx)
{
    __u64 cipher_ptr = (unsigned long)PT_REGS_PARM1(ctx);
    __u64 tgid_tid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&ssl_cipher_get_bits_args, &tgid_tid, &cipher_ptr, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_CIPHER_get_bits")
int probe_ssl_cipher_bits(struct pt_regs *ctx)
{
    __u64 tgid_tid = bpf_get_current_pid_tgid();
    __u64 *cipher_ptr_ptr = bpf_map_lookup_elem(&ssl_cipher_get_bits_args, &tgid_tid);
    if (!cipher_ptr_ptr)
        return 0;
    __u64 cipher_ptr = *cipher_ptr_ptr;
    bpf_map_delete_elem(&ssl_cipher_get_bits_args, &tgid_tid);

    int bits = (int)PT_REGS_RC(ctx);

    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    __u32 key0 = 0;
    __u8 *flags = bpf_map_lookup_elem(&config_flags, &key0);
    if (!flags || !(*flags & FLAG_TRACE_ALL)) {
        __u8 *allowed = bpf_map_lookup_elem(&pid_filter, &pid);
        if (!allowed)
            return 0;
    }

    if (bits <= 0)
        return 0;

    struct cipher_event *ev = bpf_ringbuf_reserve(&cipher_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    ev->pid     = pid;
    ev->source  = SOURCE_SSL_WRITE;
    ev->pad     = 0;
    ev->conn_id = (__u32)cipher_ptr;
    ev->bits    = (__u32)bits;
    __builtin_memset(ev->name, 0, MAX_CIPHER_NAME);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("uprobe/SSL_get_version")
int probe_ssl_version_entry(struct pt_regs *ctx)
{
    __u64 conn_id = (unsigned long)PT_REGS_PARM1(ctx);
    __u64 tgid_tid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&ssl_get_version_args, &tgid_tid, &conn_id, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_get_version")
int probe_ssl_version(struct pt_regs *ctx)
{
    __u64 tgid_tid = bpf_get_current_pid_tgid();
    __u64 *conn_id_ptr = bpf_map_lookup_elem(&ssl_get_version_args, &tgid_tid);
    if (!conn_id_ptr)
        return 0;
    __u64 conn_id = *conn_id_ptr;
    bpf_map_delete_elem(&ssl_get_version_args, &tgid_tid);

    const char *ver = (const char *)PT_REGS_RC(ctx);

    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    __u32 key0 = 0;
    __u8 *flags = bpf_map_lookup_elem(&config_flags, &key0);
    if (!flags || !(*flags & FLAG_TRACE_ALL)) {
        __u8 *allowed = bpf_map_lookup_elem(&pid_filter, &pid);
        if (!allowed)
            return 0;
    }

    if (!ver)
        return 0;

    struct cipher_event *ev = bpf_ringbuf_reserve(&cipher_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    ev->pid     = pid;
    ev->source  = SOURCE_SSL_WRITE;
    ev->pad     = 0;
    ev->conn_id = conn_id;
    ev->bits    = 0;
    long ret = bpf_probe_read_user_str(ev->name, MAX_CIPHER_NAME, ver);
    if (ret < 0) {
        bpf_ringbuf_discard(ev, 0);
        return 0;
    }

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/* ── GnuTLS Cipher Detection ────────────────────────────────────────────
 * ssize_t gnutls_cipher_suite_get_name(gnutls_kx_algorithm_t kx,
 *     gnutls_cipher_algorithm_t cipher, gnutls_mac_algorithm_t mac)
 * PARM1=kx, PARM2=cipher, PARM3=mac
 * Return value = const char* (cipher suite name)
 *
 * const char *gnutls_protocol_get_name(gnutls_protocol_t version)
 * Returns protocol version string.
 */
SEC("uretprobe/gnutls_cipher_suite_get_name")
int probe_gnutls_cipher_name(struct pt_regs *ctx)
{
    /* We cannot reliably get a conn_id for GnuTLS cipher suite name,
     * but the PID is sufficient for per-process correlation. */
    const char *name = (const char *)PT_REGS_RC(ctx);

    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    __u32 key0 = 0;
    __u8 *flags = bpf_map_lookup_elem(&config_flags, &key0);
    if (!flags || !(*flags & FLAG_TRACE_ALL)) {
        __u8 *allowed = bpf_map_lookup_elem(&pid_filter, &pid);
        if (!allowed)
            return 0;
    }

    if (!name)
        return 0;

    struct cipher_event *ev = bpf_ringbuf_reserve(&cipher_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    ev->pid     = pid;
    ev->source  = SOURCE_GNUTLS_SEND;
    ev->pad     = 0;
    ev->conn_id = 0;
    ev->bits    = 0;
    long ret = bpf_probe_read_user_str(ev->name, MAX_CIPHER_NAME, name);
    if (ret < 0) {
        bpf_ringbuf_discard(ev, 0);
        return 0;
    }

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/* ── Libc socket I/O packet fallback tracing (Solution B) ──────────────── */
SEC("uprobe/libc_read")
int probe_libc_read_entry(struct pt_regs *ctx)
{
    __u64 buf = (unsigned long)PT_REGS_PARM2(ctx);
    __u64 tgid_tid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&libc_read_args, &tgid_tid, &buf, BPF_ANY);
    return 0;
}

SEC("uretprobe/libc_read")
int probe_libc_read_return(struct pt_regs *ctx)
{
    __u64 tgid_tid = bpf_get_current_pid_tgid();
    __u64 *buf_ptr = bpf_map_lookup_elem(&libc_read_args, &tgid_tid);
    if (!buf_ptr)
        return 0;
    __u64 buf = *buf_ptr;
    bpf_map_delete_elem(&libc_read_args, &tgid_tid);

    long ret_bytes = (long)PT_REGS_RC(ctx);
    if (ret_bytes <= 0)
        return 0;

    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    __u32 key0 = 0;
    __u8 *flags = bpf_map_lookup_elem(&config_flags, &key0);
    if (!flags || !(*flags & FLAG_TRACE_ALL)) {
        __u8 *allowed = bpf_map_lookup_elem(&pid_filter, &pid);
        if (!allowed)
            return 0;
    }

    /* We need at least 5 bytes for TLS record header + 4 bytes for handshake header = 9 bytes */
    if (ret_bytes < 9)
        return 0;

    __u8 header[9];
    if (bpf_probe_read_user(header, sizeof(header), (void *)buf) < 0)
        return 0;

    /* TLS Handshake Record check:
     * header[0] == 0x16 (Handshake)
     * header[1] == 0x03 (TLS version)
     * header[5] == 0x01 (ClientHello) or 0x02 (ServerHello)
     */
    if (header[0] == 0x16 && header[1] == 0x03 && (header[5] == 0x01 || header[5] == 0x02)) {
        struct cipher_event *ev = bpf_ringbuf_reserve(&cipher_events, sizeof(*ev), 0);
        if (!ev)
            return 0;

        ev->pid     = pid;
        ev->source  = SOURCE_RAW_HANDSHAKE;
        ev->pad     = 0;
        ev->conn_id = buf; // use buf address as connection identifier temporarily
        ev->bits    = (__u32)ret_bytes; // store actual read length in bits

        /* Copy the first MAX_CIPHER_NAME (128) bytes of the TLS handshake to Go */
        __u32 copy_len = ret_bytes < MAX_CIPHER_NAME ? ret_bytes : MAX_CIPHER_NAME;
        __builtin_memset(ev->name, 0, MAX_CIPHER_NAME);
        bpf_probe_read_user(ev->name, copy_len, (void *)buf);

        bpf_ringbuf_submit(ev, 0);
    }

    return 0;
}

/* ── Unified Socket-Level Tracepoints ── */
struct trace_entry {
    unsigned short type;
    unsigned char flags;
    unsigned char preempt_count;
    int pid;
};

struct trace_event_raw_sys_enter {
    struct trace_entry ent;
    long id;
    unsigned long args[6];
};

struct trace_event_raw_sys_exit {
    struct trace_entry ent;
    long id;
    long ret;
};

static __always_inline void handle_io_exit(unsigned long ret_val) {
    long ret_bytes = (long)ret_val;
    if (ret_bytes <= 0)
        return;

    __u64 tgid_tid = bpf_get_current_pid_tgid();
    __u64 *buf_ptr = bpf_map_lookup_elem(&libc_read_args, &tgid_tid);
    if (!buf_ptr)
        return;
    __u64 buf = *buf_ptr;
    bpf_map_delete_elem(&libc_read_args, &tgid_tid);

    __u32 pid = tgid_tid >> 32;
    __u32 key0 = 0;
    __u8 *flags = bpf_map_lookup_elem(&config_flags, &key0);
    if (!flags || !(*flags & FLAG_TRACE_ALL)) {
        __u8 *allowed = bpf_map_lookup_elem(&pid_filter, &pid);
        if (!allowed)
            return;
    }

    if (ret_bytes < 9)
        return;

    __u8 header[9];
    if (bpf_probe_read_user(header, sizeof(header), (void *)buf) < 0)
        return;

    if (header[0] == 0x16 && header[1] == 0x03 && (header[5] == 0x01 || header[5] == 0x02)) {
        struct cipher_event *ev = bpf_ringbuf_reserve(&cipher_events, sizeof(*ev), 0);
        if (!ev)
            return;

        ev->pid     = pid;
        ev->source  = SOURCE_RAW_HANDSHAKE;
        ev->pad     = 0;
        ev->conn_id = buf;
        ev->bits    = (__u32)ret_bytes;

        __u32 copy_len = ret_bytes < MAX_CIPHER_NAME ? ret_bytes : MAX_CIPHER_NAME;
        __builtin_memset(ev->name, 0, MAX_CIPHER_NAME);
        bpf_probe_read_user(ev->name, copy_len, (void *)buf);

        bpf_ringbuf_submit(ev, 0);
    }
}

SEC("tracepoint/syscalls/sys_enter_read")
int trace_sys_enter_read(struct trace_event_raw_sys_enter *ctx) {
    __u64 buf = ctx->args[1];
    __u64 tgid_tid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&libc_read_args, &tgid_tid, &buf, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int trace_sys_exit_read(struct trace_event_raw_sys_exit *ctx) {
    handle_io_exit(ctx->ret);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int trace_sys_enter_write(struct trace_event_raw_sys_enter *ctx) {
    __u64 buf = ctx->args[1];
    __u64 tgid_tid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&libc_read_args, &tgid_tid, &buf, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int trace_sys_exit_write(struct trace_event_raw_sys_exit *ctx) {
    handle_io_exit(ctx->ret);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_sys_enter_sendto(struct trace_event_raw_sys_enter *ctx) {
    __u64 buf = ctx->args[1];
    __u64 tgid_tid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&libc_read_args, &tgid_tid, &buf, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendto")
int trace_sys_exit_sendto(struct trace_event_raw_sys_exit *ctx) {
    handle_io_exit(ctx->ret);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int trace_sys_enter_recvfrom(struct trace_event_raw_sys_enter *ctx) {
    __u64 buf = ctx->args[1];
    __u64 tgid_tid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&libc_read_args, &tgid_tid, &buf, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int trace_sys_exit_recvfrom(struct trace_event_raw_sys_exit *ctx) {
    handle_io_exit(ctx->ret);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_sys_enter_connect(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    __u32 key0 = 0;
    __u8 *flags = bpf_map_lookup_elem(&config_flags, &key0);
    if (!flags || !(*flags & FLAG_TRACE_ALL)) {
        __u8 *allowed = bpf_map_lookup_elem(&pid_filter, &pid);
        if (!allowed)
            return 0;
    }

    void *sockaddr_ptr = (void *)ctx->args[1];
    if (!sockaddr_ptr)
        return 0;

    short family = 0;
    if (bpf_probe_read_user(&family, sizeof(family), sockaddr_ptr) < 0)
        return 0;

    struct cipher_event *ev = bpf_ringbuf_reserve(&cipher_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    ev->pid = pid;
    ev->source = SOURCE_RAW_HANDSHAKE;
    ev->pad = 0;
    ev->conn_id = ctx->args[0]; // fd
    ev->bits = 0xffff; // connect marker
    __builtin_memset(ev->name, 0, MAX_CIPHER_NAME);

    if (family == 2) { // AF_INET
        struct sockaddr_in {
            short sin_family;
            unsigned short sin_port;
            struct in_addr {
                unsigned int s_addr;
            } sin_addr;
        } sin;
        if (bpf_probe_read_user(&sin, sizeof(sin), sockaddr_ptr) < 0) {
            bpf_ringbuf_discard(ev, 0);
            return 0;
        }
        unsigned char *ip = (unsigned char *)&sin.sin_addr.s_addr;
        unsigned short port = __builtin_bswap16(sin.sin_port);
        ev->name[0] = 4;
        __builtin_memcpy(&ev->name[1], ip, 4);
        __builtin_memcpy(&ev->name[5], &port, 2);
    } else if (family == 10) { // AF_INET6
        struct sockaddr_in6 {
            unsigned short sin6_family;
            unsigned short sin6_port;
            unsigned int sin6_flowinfo;
            struct in6_addr {
                unsigned char s6_addr[16];
            } sin6_addr;
        } sin6;
        if (bpf_probe_read_user(&sin6, sizeof(sin6), sockaddr_ptr) < 0) {
            bpf_ringbuf_discard(ev, 0);
            return 0;
        }
        unsigned short port = __builtin_bswap16(sin6.sin6_port);
        ev->name[0] = 6;
        __builtin_memcpy(&ev->name[1], sin6.sin6_addr.s6_addr, 16);
        __builtin_memcpy(&ev->name[17], &port, 2);
    } else {
        bpf_ringbuf_discard(ev, 0);
        return 0;
    }

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/* ── Cryptographic Operations Auditing uprobes ── */
#define SOURCE_CRYPTO_OP 4

static __always_inline void record_crypto_op(int algo_id) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    __u32 key0 = 0;
    __u8 *flags = bpf_map_lookup_elem(&config_flags, &key0);
    if (!flags || !(*flags & FLAG_TRACE_ALL)) {
        __u8 *allowed = bpf_map_lookup_elem(&pid_filter, &pid);
        if (!allowed)
            return;
    }

    struct cipher_event *ev = bpf_ringbuf_reserve(&cipher_events, sizeof(*ev), 0);
    if (!ev)
        return;

    ev->pid = pid;
    ev->source = SOURCE_CRYPTO_OP;
    ev->pad = 0;
    ev->conn_id = 0;
    ev->bits = algo_id;
    __builtin_memset(ev->name, 0, MAX_CIPHER_NAME);

    bpf_ringbuf_submit(ev, 0);
}

SEC("uprobe/crypto_md5")
int probe_crypto_md5(struct pt_regs *ctx) {
    record_crypto_op(1);
    return 0;
}

SEC("uprobe/crypto_sha1")
int probe_crypto_sha1(struct pt_regs *ctx) {
    record_crypto_op(2);
    return 0;
}

SEC("uprobe/crypto_sha256")
int probe_crypto_sha256(struct pt_regs *ctx) {
    record_crypto_op(3);
    return 0;
}

SEC("uprobe/crypto_sha512")
int probe_crypto_sha512(struct pt_regs *ctx) {
    record_crypto_op(4);
    return 0;
}

SEC("uprobe/crypto_aes_enc")
int probe_crypto_aes_enc(struct pt_regs *ctx) {
    record_crypto_op(5);
    return 0;
}

SEC("uprobe/crypto_aes_dec")
int probe_crypto_aes_dec(struct pt_regs *ctx) {
    record_crypto_op(6);
    return 0;
}

SEC("uprobe/crypto_sha224")
int probe_crypto_sha224(struct pt_regs *ctx) {
    record_crypto_op(7);
    return 0;
}

SEC("uprobe/crypto_sha384")
int probe_crypto_sha384(struct pt_regs *ctx) {
    record_crypto_op(8);
    return 0;
}

/* ── LSM BPF Exec & File Auditing ── */
struct path {
    struct vfsmount *mnt;
    struct dentry *dentry;
};

struct file {
    struct path f_path;
};

struct linux_binprm {
    char buf[128];
    void *page;
    struct file *file;
};

SEC("lsm/bprm_check_security")
int BPF_PROG(bprm_check_security, struct linux_binprm *bprm) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    __u32 key0 = 0;
    __u8 *flags = bpf_map_lookup_elem(&config_flags, &key0);
    if (!flags || !(*flags & FLAG_TRACE_ALL)) {
        __u8 *allowed = bpf_map_lookup_elem(&pid_filter, &pid);
        if (!allowed)
            return 0;
    }

    if (!bprm || !bprm->file)
        return 0;

    char path_buf[256];
    long len = bpf_d_path(&bprm->file->f_path, path_buf, sizeof(path_buf));
    if (len < 0)
        len = 0;

    struct cipher_event *ev = bpf_ringbuf_reserve(&cipher_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    ev->pid = pid;
    ev->source = 5; // SOURCE_LSM_EXEC
    ev->pad = 0;
    ev->conn_id = 0;
    ev->bits = 0;
    __builtin_memset(ev->name, 0, MAX_CIPHER_NAME);
    __u32 copy_len = len < MAX_CIPHER_NAME ? len : MAX_CIPHER_NAME;
    if (copy_len > 0) {
        bpf_probe_read_kernel(ev->name, copy_len, path_buf);
    }

    bpf_ringbuf_submit(ev, 0);

    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(file_open, struct file *file, int mask) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    __u32 key0 = 0;
    __u8 *flags = bpf_map_lookup_elem(&config_flags, &key0);
    if (!flags || !(*flags & FLAG_TRACE_ALL)) {
        __u8 *allowed = bpf_map_lookup_elem(&pid_filter, &pid);
        if (!allowed)
            return 0;
    }

    if (!file)
        return 0;

    char path_buf[256];
    long len = bpf_d_path(&file->f_path, path_buf, sizeof(path_buf));
    if (len < 0)
        len = 0;

    struct cipher_event *ev = bpf_ringbuf_reserve(&cipher_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    ev->pid = pid;
    ev->source = 6; // SOURCE_LSM_FILE
    ev->pad = 0;
    ev->conn_id = 0;
    ev->bits = mask;
    __builtin_memset(ev->name, 0, MAX_CIPHER_NAME);
    __u32 copy_len = len < MAX_CIPHER_NAME ? len : MAX_CIPHER_NAME;
    if (copy_len > 0) {
        bpf_probe_read_kernel(ev->name, copy_len, path_buf);
    }

    bpf_ringbuf_submit(ev, 0);

    return 0;
}

char _license[] SEC("license") = "GPL";

