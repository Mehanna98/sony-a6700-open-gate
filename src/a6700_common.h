/* a6700_common.h -- Shared freestanding AArch64 READ-ONLY primitives.
 *
 * STRICT SAFETY GUARANTEE:
 *   This header contains ZERO memory-write helpers and ZERO mprotect/mmap/pwrite syscalls.
 *   Only openat(56), close(57), read(63), write(64) exist here.
 *   The only file written by callers in RO mode is /tmp/jiritsu/rampatch.result.
 */
#ifndef A6700_COMMON_H
#define A6700_COMMON_H

#include "a6700_probe_spec.h"

#define NR_openat   56
#define NR_close    57
#define NR_read     63
#define NR_write    64

#define AT_FDCWD    (-100)
#define O_RDONLY    0
#define O_WRONLY    1
#define O_CREAT     0x40
#define O_TRUNC     0x200

#define RESULT_PATH "/tmp/jiritsu/rampatch.result"
#define APPFW_PATH  "/usr/lib/appFw.so"

static inline i64 sc6(i64 n, i64 a, i64 b, i64 c, i64 d, i64 e, i64 f) {
    register i64 x8 __asm__("x8") = n;
    register i64 x0 __asm__("x0") = a;
    register i64 x1 __asm__("x1") = b;
    register i64 x2 __asm__("x2") = c;
    register i64 x3 __asm__("x3") = d;
    register i64 x4 __asm__("x4") = e;
    register i64 x5 __asm__("x5") = f;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                     : "memory", "cc");
    return x0;
}

__attribute__((noinline)) static i64 sys_open(const char *p, i64 fl, i64 mode) { return sc6(NR_openat, AT_FDCWD, (i64)p, fl, mode, 0, 0); }
__attribute__((noinline)) static i64 sys_read(i64 fd, void *b, u64 n)          { return sc6(NR_read, fd, (i64)b, (i64)n, 0, 0, 0); }
__attribute__((noinline)) static i64 sys_write(i64 fd, const void *b, u64 n)   { return sc6(NR_write, fd, (i64)b, (i64)n, 0, 0, 0); }
__attribute__((noinline)) static i64 sys_close(i64 fd)                         { return sc6(NR_close, fd, 0, 0, 0, 0, 0); }

/* ---- output buffer (max 60 KiB so single Jiritsu read returns all) ------- */
#define OUTCAP (60u * 1024u)
static char g_out[OUTCAP];
static u32  g_olen;

static void out_c(u8 c) { if (g_olen < OUTCAP - 1u) g_out[g_olen++] = (char)c; }
__attribute__((noinline)) static void out_s(const char *s) {
    if (!s) { out_c('?'); return; }
    while (*s) out_c((u8)*s++);
}
__attribute__((noinline)) static void out_u64(u64 v) {
    char b[24]; int i = 23; b[i--] = 0;
    if (!v) b[i--] = '0';
    while (v) { b[i--] = (char)('0' + (int)(v % 10u)); v /= 10u; }
    out_s(&b[i + 1]);
}
__attribute__((noinline)) static void out_hex(u64 v) {
    static const char H[] = "0123456789abcdef";
    char b[18]; int i = 17; b[i--] = 0;
    if (!v) b[i--] = '0';
    while (v) { b[i--] = H[(int)(v & 15u)]; v >>= 4; }
    out_s("0x"); out_s(&b[i + 1]);
}
__attribute__((unused)) static void out_hex_bytes(const u8 *p, u64 n) {
    static const char H[] = "0123456789abcdef";
    for (u64 i = 0; i < n; i++) {
        out_c((u8)H[p[i] >> 4]);
        out_c((u8)H[p[i] & 15u]);
    }
}
static void flush_result(void) {
    i64 fd = sys_open(RESULT_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return;
    u32 off = 0;
    while (off < g_olen) {
        i64 w = sys_write(fd, g_out + off, (u64)(g_olen - off));
        if (w <= 0) break;
        off += (u32)w;
    }
    sys_close(fd);
}

/* ---- minimal string / memory helpers (no libc) --------------------------- */
static int streq_n(const char *a, const char *b, u64 n) {
    for (u64 i = 0; i < n; i++) if (a[i] != b[i]) return 0;
    return 1;
}
static int str_ends_with(const char *s, u64 slen, const char *suf, u64 suflen) {
    if (slen < suflen) return 0;
    return streq_n(s + (slen - suflen), suf, suflen);
}

/* ---- FIPS 180-4 SHA-256 (streaming) -------------------------------------- */
struct sha256_ctx { u32 h[8]; u8 blk[64]; u64 len; u32 fill; };
static const u32 SHA_K[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};
static inline u32 ror32(u32 x, int n) { return (x >> n) | (x << (32 - n)); }
static void sha_blk(struct sha256_ctx *s, const u8 *p) {
    u32 w[64], a, b, c, d, e, f, g, h;
    for (int i = 0; i < 16; i++)
        w[i] = ((u32)p[4*i]<<24) | ((u32)p[4*i+1]<<16) | ((u32)p[4*i+2]<<8) | (u32)p[4*i+3];
    for (int i = 16; i < 64; i++)
        w[i] = w[i-16] + (ror32(w[i-15],7)^ror32(w[i-15],18)^(w[i-15]>>3))
             + w[i-7]  + (ror32(w[i-2],17)^ror32(w[i-2],19)^(w[i-2]>>10));
    a=s->h[0]; b=s->h[1]; c=s->h[2]; d=s->h[3]; e=s->h[4]; f=s->h[5]; g=s->h[6]; h=s->h[7];
    for (int i = 0; i < 64; i++) {
        u32 t1 = h + (ror32(e,6)^ror32(e,11)^ror32(e,25)) + ((e&f)^(~e&g)) + SHA_K[i] + w[i];
        u32 t2 = (ror32(a,2)^ror32(a,13)^ror32(a,22)) + ((a&b)^(a&c)^(b&c));
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    s->h[0]+=a; s->h[1]+=b; s->h[2]+=c; s->h[3]+=d;
    s->h[4]+=e; s->h[5]+=f; s->h[6]+=g; s->h[7]+=h;
}
static void sha_init(struct sha256_ctx *s) {
    static const u32 iv[8] = {
        0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
        0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u
    };
    for (int i = 0; i < 8; i++) s->h[i] = iv[i];
    s->len = 0; s->fill = 0;
}
static void sha_add(struct sha256_ctx *s, const u8 *p, u64 n) {
    s->len += n;
    while (n--) {
        s->blk[s->fill++] = *p++;
        if (s->fill == 64u) { sha_blk(s, s->blk); s->fill = 0; }
    }
}
static void sha_end(struct sha256_ctx *s, u8 dig[32]) {
    u64 bits = s->len * 8ULL;
    u8 pad = 0x80; sha_add(s, &pad, 1);
    pad = 0; while (s->fill != 56u) sha_add(s, &pad, 1);
    for (int i = 7; i >= 0; i--) { u8 b = (u8)(bits >> (8 * i)); sha_add(s, &b, 1); }
    for (int i = 0; i < 8; i++) {
        dig[4*i]   = (u8)(s->h[i] >> 24); dig[4*i+1] = (u8)(s->h[i] >> 16);
        dig[4*i+2] = (u8)(s->h[i] >> 8);  dig[4*i+3] = (u8)(s->h[i]);
    }
}

static int verify_appfw_file(u64 *out_size, char hex_out[65]) {
    static u8 fbuf[16384];
    i64 fd = sys_open(APPFW_PATH, O_RDONLY, 0);
    if (fd < 0) { *out_size = 0; hex_out[0] = 0; return 0; }
    struct sha256_ctx ctx;
    sha_init(&ctx);
    u64 total = 0;
    for (;;) {
        i64 r = sys_read(fd, fbuf, sizeof(fbuf));
        if (r < 0) { sys_close(fd); *out_size = total; hex_out[0] = 0; return 0; }
        if (r == 0) break;
        sha_add(&ctx, fbuf, (u64)r);
        total += (u64)r;
    }
    sys_close(fd);
    u8 dig[32];
    sha_end(&ctx, dig);
    static const char H[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        hex_out[2*i]   = H[dig[i] >> 4];
        hex_out[2*i+1] = H[dig[i] & 15u];
    }
    hex_out[64] = 0;
    *out_size = total;
    return (total == APPFW_EXPECT_SIZE) && streq_n(hex_out, APPFW_EXPECT_SHA256, 64);
}

/* ---- /proc/self/maps parser & bounds validator --------------------------- */
#define MAX_MAPS_BUF (256u * 1024u)
#define MAX_VMA      1024u

struct vma_rec {
    u64 start;
    u64 end;
    u64 file_off;
    u8  perms; /* bit0=R, bit1=W, bit2=X, bit3=P(private) */
};

static char           g_maps_buf[MAX_MAPS_BUF];
static struct vma_rec g_vmas[MAX_VMA];
static u32            g_vma_cnt;
static u64            g_load_base;
static int            g_load1_ok;

static u64 parse_hex(const char **p) {
    u64 v = 0;
    const char *s = *p;
    for (;;) {
        char c = *s;
        if (c >= '0' && c <= '9')      v = (v << 4) | (u64)(c - '0');
        else if (c >= 'a' && c <= 'f') v = (v << 4) | (u64)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v = (v << 4) | (u64)(c - 'A' + 10);
        else break;
        s++;
    }
    *p = s;
    return v;
}

static int parse_proc_maps(void) {
    i64 fd = sys_open("/proc/self/maps", O_RDONLY, 0);
    if (fd < 0) return 0;
    u64 got = 0;
    while (got < MAX_MAPS_BUF - 1u) {
        i64 r = sys_read(fd, g_maps_buf + got, (MAX_MAPS_BUF - 1u) - got);
        if (r <= 0) break;
        got += (u64)r;
    }
    sys_close(fd);
    g_maps_buf[got] = 0;

    g_vma_cnt = 0;
    g_load_base = 0;
    g_load1_ok = 0;

    const char *p = g_maps_buf;
    const char *end = g_maps_buf + got;
    while (p < end) {
        const char *eol = p;
        while (eol < end && *eol != '\n') eol++;

        const char *q = p;
        u64 s = parse_hex(&q);
        if (q < eol && *q == '-') q++;
        u64 e = parse_hex(&q);
        while (q < eol && *q == ' ') q++;
        u8 perms = 0;
        if (q + 4 <= eol) {
            if (q[0] == 'r') perms |= 1u;
            if (q[1] == 'w') perms |= 2u;
            if (q[2] == 'x') perms |= 4u;
            if (q[3] == 'p') perms |= 8u;
            q += 4;
        }
        while (q < eol && *q == ' ') q++;
        u64 foff = parse_hex(&q);

        /* find path token (6th column) */
        const char *path = eol;
        for (const char *t = q; t < eol; t++) {
            if (*t == '/') { path = t; break; }
        }
        u64 plen = (u64)(eol - path);

        if (g_vma_cnt < MAX_VMA && e > s) {
            g_vmas[g_vma_cnt].start = s;
            g_vmas[g_vma_cnt].end = e;
            g_vmas[g_vma_cnt].file_off = foff;
            g_vmas[g_vma_cnt].perms = perms;
            g_vma_cnt++;
        }

        /* Match /usr/lib/appFw.so (or suffix "appFw.so") */
        if (str_ends_with(path, plen, "appFw.so", 8)) {
            if (foff == 0 && (perms & 5u) == 5u && !g_load_base) {
                g_load_base = s;
            } else if (g_load_base && foff >= 0x04489000ULL && foff <= 0x0448A000ULL) {
                if ((s - g_load_base) - foff == APPFW_LOAD1_DELTA) {
                    g_load1_ok = 1;
                }
            }
        }
        p = (eol < end) ? (eol + 1) : end;
    }
    return (g_load_base != 0);
}

static int find_vma(u64 addr, u64 len, u8 *out_perms) {
    if (!addr || addr + len < addr) return 0;
    for (u32 i = 0; i < g_vma_cnt; i++) {
        if (addr >= g_vmas[i].start && (addr + len) <= g_vmas[i].end) {
            if (out_perms) *out_perms = g_vmas[i].perms;
            return 1;
        }
    }
    return 0;
}

static int is_readable(u64 addr, u64 len) {
    u8 perms = 0;
    return find_vma(addr, len, &perms) && ((perms & 1u) != 0);
}

/* Safe byte-wise unaligned reads (with /proc/self/maps validation) */
static int safe_read_bytes(u64 addr, u8 *dst, u64 len) {
    if (!is_readable(addr, len)) return 0;
    const volatile u8 *src = (const volatile u8 *)addr;
    for (u64 i = 0; i < len; i++) dst[i] = src[i];
    return 1;
}
static int safe_read_u32(u64 addr, u32 *out) {
    u8 b[4];
    if (!safe_read_bytes(addr, b, 4)) return 0;
    *out = (u32)b[0] | ((u32)b[1] << 8) | ((u32)b[2] << 16) | ((u32)b[3] << 24);
    return 1;
}
static int safe_read_u64(u64 addr, u64 *out) {
    u8 b[8];
    if (!safe_read_bytes(addr, b, 8)) return 0;
    u64 v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | (u64)b[i];
    *out = v;
    return 1;
}

/* ---- Read-only GNU libstdc++ std::unordered_map<u32, ...> lookup ---------
 * Verified against a6700 v2.00 disassembly:
 *   0x2fad8b8 (0x138bd888), 0x2fad7bc (outer 0x138bd930), 0x2fad714 (inner 0x138bd930).
 *   [map + 0x00] = buckets ptr (each slot points to BEFORE-node)
 *   [map + 0x08] = bucket_count
 *   [node + 0x00] = next ptr
 *   [node + 0x08] = u32 key
 *   [node + 0x0c] = u8 value (for bool maps) OR [node + 0x10] = inner map
 * Returns runtime address of matching node, or 0 if not found / invalid ptr.
 */
static u64 umap_find_node(u64 map_addr, u32 key) {
    u64 buckets = 0, bcnt = 0;
    if (!safe_read_u64(map_addr + 0x00ULL, &buckets)) return 0;
    if (!safe_read_u64(map_addr + 0x08ULL, &bcnt))    return 0;
    if (!buckets || bcnt == 0 || bcnt > 1000000ULL)   return 0;

    u64 bidx = (u64)key % bcnt;
    u64 prev = 0;
    if (!safe_read_u64(buckets + bidx * 8ULL, &prev) || !prev) return 0;

    u64 cur = 0;
    if (!safe_read_u64(prev, &cur)) return 0;

    for (u32 steps = 0; cur && steps < 64u; steps++) {
        u32 nkey = 0;
        if (!safe_read_u32(cur + 0x08ULL, &nkey)) return 0;
        if (nkey == key) return cur;
        u64 nxt = 0;
        if (!safe_read_u64(cur, &nxt) || !nxt) break;
        u32 next_key = 0;
        if (!safe_read_u32(nxt + 0x08ULL, &next_key)) break;
        if (((u64)next_key % bcnt) != bidx) break;
        cur = nxt;
    }
    return 0;
}

#endif /* A6700_COMMON_H */
