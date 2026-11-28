/* a6700_sd_bypass_ram.c -- Zero-flash volatile AP-RAM SD Card Speed-Limit Bypass (ON / OFF).
 *
 * Target: Sony ILCE-6700 (a6700) FW v2.00 ONLY (stock libmpr.so SHA-256 verified).
 * Site  : RateCheck::GetMediaTransferRateInh @ libmpr.so + 0x0E3F0C (20 bytes = 5 ARM64 insns).
 *         Compile with -DSD_BYPASS_OFF=0 (enable bypass) or -DSD_BYPASS_OFF=1 (restore stock).
 *
 * SAFETY GUARANTEES:
 *   - 100% ZERO FLASH WRITES, ZERO /dev/mem, ZERO CP access.
 *   - Exact 5-syscall surface: openat(56), close(57), read(63), write(64), mprotect(226).
 *   - 10-second battery pull returns the camera 100% to factory stock.
 *   - PASS 0 verifies on-disk /libmpr.so exact size & SHA-256.
 *   - PASS 1 verifies 8-byte pre-guard (0x0E3F04) + 8-byte post-guard (0x0E3F20) + exact 20-byte
 *     preimage (strictly STOCK or BYPASS) BEFORE writing 1 byte.
 *   - PASS 2 writes 5 aligned 32-bit instructions via private COW mprotect (keeping PROT_EXEC!)
 *     + full AArch64 D-cache clean (dc cvau) + I-cache invalidate (ic ivau) + dsb ish + isb.
 *   - PASS 3 verifies all 20 written bytes and both 8-byte guards end-to-end.
 */
#include "a6700_sd_bypass_spec.h"

#ifndef SD_BYPASS_OFF
#define SD_BYPASS_OFF 0
#endif

#define NR_openat   56
#define NR_close    57
#define NR_read     63
#define NR_write    64
#define NR_mprotect 226

#define AT_FDCWD    (-100)
#define O_RDONLY    0
#define O_WRONLY    1
#define O_CREAT     0x40
#define O_TRUNC     0x200

#define PROT_READ   1
#define PROT_WRITE  2
#define PROT_EXEC   4

#define RESULT_PATH "/tmp/jiritsu/rampatch.result"

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
__attribute__((noinline)) static i64 sys_mprotect(u64 addr, u64 len, i64 prot) { return sc6(NR_mprotect, (i64)addr, (i64)len, prot, 0, 0, 0); }

#define OUTCAP 4096U
static char g_out[OUTCAP];
static u32  g_olen;

static void out_c(u8 c) { if (g_olen < OUTCAP - 1U) g_out[g_olen++] = (char)c; }
__attribute__((noinline)) static void out_s(const char *s) {
    if (!s) { out_c('?'); return; }
    while (*s) out_c((u8)*s++);
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

static u64 slen(const char *s) { u64 n = 0; while (s[n]) n++; return n; }
static int mem_eq(const u8 *a, const u8 *b, u64 n) {
    for (u64 i = 0; i < n; i++) if (a[i] != b[i]) return 0;
    return 1;
}
static int ends_with(const char *s, u64 n, const char *suf) {
    u64 m = slen(suf);
    if (n < m) return 0;
    return mem_eq((const u8 *)s + (n - m), (const u8 *)suf, m);
}
static u32 rd_u32(const u8 *p) {
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

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
__attribute__((noinline)) static void sha_blk(struct sha256_ctx *s, const u8 *p) {
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

#define MAPS_CAP (256u * 1024u)
static char g_maps[MAPS_CAP];
static u64  g_maps_len;
static u8   g_iobuf[8192];

static u64 read_text_file(const char *path, char *dst, u64 cap) {
    i64 fd = sys_open(path, O_RDONLY, 0);
    if (fd < 0) { dst[0] = 0; return 0; }
    u64 got = 0;
    while (got + 1u < cap) {
        i64 r = sys_read(fd, dst + got, (cap - 1u) - got);
        if (r <= 0) break;
        got += (u64)r;
    }
    sys_close(fd);
    dst[got] = 0;
    return got;
}
static u64 parse_hex(const char **p) {
    u64 v = 0; const char *s = *p;
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
static u64 find_libmpr_slice(u64 file_off, u64 len, u8 *out_perms, char *path_out, u64 path_cap) {
    const char *p = g_maps;
    const char *end = g_maps + g_maps_len;
    u64 found = 0;
    while (p < end) {
        const char *line = p;
        while (p < end && *p != '\n') p++;
        u64 n = (u64)(p - line);
        if (p < end) p++;
        if (!ends_with(line, n, "/libmpr.so")) continue;
        const char *q = line;
        u64 lo = parse_hex(&q); if (q >= line + n || *q != '-') continue; q++;
        u64 hi = parse_hex(&q); if (q >= line + n || *q != ' ') continue; q++;
        u8 perms = 0;
        if (q + 4 <= line + n) {
            if (q[0] == 'r') perms |= 1u;
            if (q[1] == 'w') perms |= 2u;
            if (q[2] == 'x') perms |= 4u;
            q += 4;
        }
        while (q < line + n && *q == ' ') q++;
        u64 foff = parse_hex(&q);
        if (path_out && !path_out[0]) {
            const char *s = line + n;
            while (s > line && s[-1] != ' ') s--;
            u64 k = 0;
            for (; s < line + n && k + 1u < path_cap; s++) path_out[k++] = *s;
            path_out[k] = 0;
        }
        if (!found && ((perms & 5u) == 5u) &&
            file_off >= foff && (file_off + len) <= foff + (hi - lo)) {
            found = lo + (file_off - foff);
            if (out_perms) *out_perms = perms;
        }
    }
    return found;
}
static int hash_disk_file(const char *path, u64 *out_sz, u8 dig[32]) {
    i64 fd = sys_open(path, O_RDONLY, 0);
    if (fd < 0) { *out_sz = 0; return 0; }
    struct sha256_ctx ctx;
    sha_init(&ctx);
    u64 total = 0;
    for (;;) {
        i64 r = sys_read(fd, g_iobuf, sizeof(g_iobuf));
        if (r < 0) { sys_close(fd); *out_sz = total; return 0; }
        if (r == 0) break;
        sha_add(&ctx, g_iobuf, (u64)r);
        total += (u64)r;
    }
    sys_close(fd);
    sha_end(&ctx, dig);
    *out_sz = total;
    return 1;
}
static void flush_icache_range(u64 start, u64 len) {
    u64 end = start + len;
    for (u64 p = start & ~63ULL; p < end; p += 64ULL) {
        __asm__ volatile("dc cvau, %0" :: "r"(p) : "memory");
    }
    __asm__ volatile("dsb ish" ::: "memory");
    for (u64 p = start & ~63ULL; p < end; p += 64ULL) {
        __asm__ volatile("ic ivau, %0" :: "r"(p) : "memory");
    }
    __asm__ volatile("dsb ish\nisb" ::: "memory");
}

__attribute__((visibility("default"))) void _init(void) {
    g_olen = 0;
#if SD_BYPASS_OFF
    out_s("A6700_SD_BYPASS_OFF_RAM_V1\n");
    const u8 *want = SD_STOCK_20;
    const u8 *other = SD_PATCH_20;
#else
    out_s("A6700_SD_BYPASS_RAM_V1\n");
    const u8 *want = SD_PATCH_20;
    const u8 *other = SD_STOCK_20;
#endif

    /* PASS 0: Locate & verify stock on-disk /libmpr.so SHA-256 */
    g_maps_len = read_text_file("/proc/self/maps", g_maps, sizeof(g_maps));
    char path[200]; path[0] = 0;
    u8 perms = 0;
    u64 va_pre = find_libmpr_slice(SD_PRE_GUARD_OFF, 36ULL, &perms, path, sizeof(path));
    u64 fsz = 0; u8 dig[32];
    if (!va_pre || !path[0] || !hash_disk_file(path, &fsz, dig) ||
        fsz != SD_LIBMPR_SIZE || !mem_eq(dig, SD_LIBMPR_SHA256, 32U)) {
        out_s("RESULT=ABORT_IDENTITY reason=libmpr_sha_mismatch writes=0\n");
        flush_result();
        return;
    }
    u64 va_site = va_pre + 8ULL;
    u64 va_post = va_site + SD_SITE_LEN;
    out_s("PASS0_IDENTITY=OK\n");

    /* PASS 1: Dry preimage & surrounding 16-byte code guard verification (0 writes!) */
    if (!mem_eq((const u8 *)va_pre, SD_PRE_GUARD, 8U) ||
        !mem_eq((const u8 *)va_post, SD_POST_GUARD, 8U)) {
        out_s("RESULT=ABORT_MISMATCH reason=code_guard_mismatch writes=0\n");
        flush_result();
        return;
    }
    if (mem_eq((const u8 *)va_site, want, SD_SITE_LEN)) {
#if SD_BYPASS_OFF
        out_s("RESULT=ALREADY_STOCK writes=0\n");
#else
        out_s("RESULT=ALREADY_APPLIED writes=0\n");
#endif
        flush_result();
        return;
    }
    if (!mem_eq((const u8 *)va_site, other, SD_SITE_LEN)) {
        out_s("RESULT=ABORT_MISMATCH reason=site_bytes_unknown writes=0\n");
        flush_result();
        return;
    }
    out_s("PASS1_PREIMAGE=OK\n");

    /* PASS 2: Private COW mprotect (preserving PROT_EXEC!) + aligned u32 stores + I-cache flush */
    u64 pg_start = va_site & ~4095ULL;
    u64 pg_end   = (va_site + SD_SITE_LEN + 4095ULL) & ~4095ULL;
    u64 pg_len   = pg_end - pg_start;
    i64 orig_prot = ((perms & 1u) ? PROT_READ : 0)
                  | ((perms & 2u) ? PROT_WRITE : 0)
                  | ((perms & 4u) ? PROT_EXEC : 0);
    int need_mprot = !(perms & 2u);
    if (need_mprot) {
        if (sys_mprotect(pg_start, pg_len, orig_prot | PROT_WRITE) != 0) {
            out_s("RESULT=ABORT_MPROTECT writes=0\n");
            flush_result();
            return;
        }
    }
    volatile u32 *dst32 = (volatile u32 *)va_site;
    for (u32 i = 0; i < 5U; i++) {
        __atomic_store_n(&dst32[i], rd_u32(want + i * 4U), __ATOMIC_RELEASE);
    }
    flush_icache_range(va_site, SD_SITE_LEN);
    if (need_mprot) (void)sys_mprotect(pg_start, pg_len, orig_prot);

    /* PASS 3: End-to-end readback verification */
    if (!mem_eq((const u8 *)va_site, want, SD_SITE_LEN) ||
        !mem_eq((const u8 *)va_pre, SD_PRE_GUARD, 8U) ||
        !mem_eq((const u8 *)va_post, SD_POST_GUARD, 8U)) {
        out_s("RESULT=ABORT_VERIFY_FAIL\n");
        flush_result();
        return;
    }

    out_s("PASS3_READBACK=OK bytes=20\n");
#if SD_BYPASS_OFF
    out_s("RESULT=SD_BYPASS_OFF_OK mode=stock_sd_check\n");
#else
    out_s("RESULT=APPLY_OK feature=sd_speed_bypass_v1\n");
#endif
    flush_result();
}
