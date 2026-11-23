/* a6700_og_probe_ro.c -- 100% READ-ONLY Open Gate CP-RAM + /dev/mem probe for Sony a6700 (v2.00).
 *
 * STRICT ZERO-WRITE SAFETY DESIGN (ArcaneLantern s3read.c + a6700_probe_ro.c discipline):
 *   1. Freestanding AArch64 ELF (DT_INIT = _init, DT_NEEDED = 0, 0 libc deps, < 65,536 B).
 *   2. ZERO mprotect(226), ZERO pwrite64(68), ZERO PROT_WRITE in mmap(222).
 *      The ONLY mmap wrapper in this file hardcodes PROT_READ (1) | MAP_SHARED (1).
 *   3. /dev/mem is opened strictly O_RDONLY (or O_RDONLY | O_SYNC); never O_RDWR / O_WRONLY.
 *   4. Coprocessor reads use libsencore.so sen_dma_transfer(0U, cp_page, cp_phys, 4096U) ONLY:
 *      - Direction is the compile-time constant 0U (CP -> AP read-only, disassembly-verified
 *        at a6700 libsencore.so +0x13db0: csel x20, x25, x2, eq).
 *      - Hard-locked to stock libsencore.so SHA-256 + 8-byte function prologues before calling.
 *      - Every CP page is range-checked to [OG_CP_LO, OG_CP_HI) and 4 KB aligned.
 *   5. av-cam.bin /dev/mem read is hard-gated on /proc/cmdline containing OG_AVCAM_RESERVE.
 *   6. The ONLY file created is /tmp/jiritsu/rampatch.result (deleted same-session by runner).
 *      ZERO flash paths (/dev/nflash, /cp/cpapp, /setting/BACKUP).
 */
#include "a6700_og_probe_spec.h"

/* ---- AArch64 Linux syscalls (READ-ONLY set ONLY) ------------------------- */
#define NR_openat   56
#define NR_close    57
#define NR_read     63
#define NR_write    64
#define NR_munmap   215
#define NR_mmap     222

#define AT_FDCWD      (-100)
#define O_RDONLY      0
#define O_RDONLY_SYNC 0x101000 /* O_RDONLY | O_SYNC */
#define O_WRONLY      1
#define O_CREAT       0x40
#define O_TRUNC       0x200

#define PROT_READ     1
#define MAP_SHARED    1

#define CP_PAGE       4096U
#define RAM_LO        0x400000000ULL
#define RAM_HI        0x500000000ULL
#define RESULT_PATH   "/tmp/jiritsu/rampatch.result"

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
__attribute__((noinline)) static i64 sys_munmap(void *p, u64 len)              { return sc6(NR_munmap, (i64)p, (i64)len, 0, 0, 0, 0); }

/* SINGLE mmap site in the entire binary: strictly PROT_READ (1) | MAP_SHARED (1). */
__attribute__((noinline))
static i64 sys_mmap_ro(i64 fd, u64 len, u64 off) {
    i64 r = sc6(NR_mmap, 0, (i64)len, PROT_READ, MAP_SHARED, fd, (i64)off);
    return (r < 0 && r > -4096) ? -1 : r;
}

/* ---- Single-shot Jiritsu output buffer (max 60 KiB < 65,536 B limit) ----- */
#define OUTCAP (60u * 1024u)
static char g_out[OUTCAP];
static u32  g_olen;

static void out_c(u8 c) { if (g_olen < OUTCAP - 1u) g_out[g_olen++] = (char)c; }
__attribute__((noinline)) static void out_s(const char *s) {
    if (!s) { out_c('?'); return; }
    while (*s) out_c((u8)*s++);
}
__attribute__((noinline)) static void out_buf(const char *s, u64 n) {
    for (u64 i = 0; i < n; i++) out_c((u8)s[i]);
}
__attribute__((noinline)) static void out_u64(u64 v) {
    char b[24]; int i = 23; b[i--] = 0;
    if (!v) b[i--] = '0';
    while (v) { b[i--] = (char)('0' + (int)(v % 10u)); v /= 10u; }
    out_s(&b[i + 1]);
}
__attribute__((noinline)) static void out_i64(i64 v) {
    if (v < 0) { out_c('-'); out_u64((u64)(-v)); }
    else out_u64((u64)v);
}
__attribute__((noinline)) static void out_hex(u64 v) {
    static const char H[] = "0123456789abcdef";
    char b[18]; int i = 17; b[i--] = 0;
    if (!v) b[i--] = '0';
    while (v) { b[i--] = H[(int)(v & 15u)]; v >>= 4; }
    out_s("0x"); out_s(&b[i + 1]);
}
__attribute__((noinline)) static void out_hex_bytes(const u8 *p, u64 n) {
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

/* ---- Freestanding byte/string helpers ------------------------------------ */
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
static u16 rd_u16(const u8 *p) { return (u16)((u16)p[0] | ((u16)p[1] << 8)); }
static u32 rd_u32(const u8 *p) {
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

/* ---- FIPS 180-4 SHA-256 -------------------------------------------------- */
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
static void sha_buf(const u8 *p, u64 n, u8 dig[32]) {
    struct sha256_ctx ctx;
    sha_init(&ctx);
    sha_add(&ctx, p, n);
    sha_end(&ctx, dig);
}

/* ---- /proc readers & /proc/self/maps lookup ------------------------------ */
#define MAPS_CAP (256u * 1024u)
static char g_maps[MAPS_CAP];
static u64  g_maps_len;
static char g_cmdline[2048];
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

static void dump_proc_trimmed(const char *path, u64 cap) {
    static char tmp[4096];
    if (cap > sizeof(tmp)) cap = sizeof(tmp);
    u64 n = read_text_file(path, tmp, cap);
    out_s("== file "); out_s(path); out_s(" len="); out_u64(n); out_s("\n");
    out_buf(tmp, n);
    if (n == 0 || tmp[n - 1] != '\n') out_s("\n");
}

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

static int cmdline_has(const char *needle) {
    u64 m = slen(needle);
    for (u64 i = 0; g_cmdline[i]; i++) {
        if (mem_eq((const u8 *)(g_cmdline + i), (const u8 *)needle, m)) return 1;
    }
    return 0;
}

/* Return process VA where [file_off, file_off + len) of `suffix` is mapped with `req_perms`
 * (bit0=R, bit2=X). Optionally copies the full path of the first matching VMA into path_out. */
static u64 find_mapped_slice(const char *suffix, u64 file_off, u64 len, u8 req_perms,
                             char *path_out, u64 path_cap) {
    const char *p = g_maps;
    const char *end = g_maps + g_maps_len;
    u64 found = 0;
    while (p < end) {
        const char *line = p;
        while (p < end && *p != '\n') p++;
        u64 n = (u64)(p - line);
        if (p < end) p++;

        if (!ends_with(line, n, suffix)) continue;
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
        if (!found && ((perms & req_perms) == req_perms) &&
            file_off >= foff && (file_off + len) <= foff + (hi - lo)) {
            found = lo + (file_off - foff);
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

/* ---- Coprocessor read-only DMA engine via verified libsencore.so --------- */
typedef u64 (*fn_dmm_alloc_t)(u32 size, u32 *handle);
typedef u64 (*fn_dmm_free_t)(u32 handle);
typedef u32 (*fn_sen_dma_t)(u32 dir, u64 src, u64 dst, u32 size);

static fn_dmm_alloc_t g_dmm_alloc;
static fn_dmm_free_t  g_dmm_free;
static fn_sen_dma_t   g_sen_dma;
static const u8      *g_cp_buf;
static u64            g_cp_phys;
static u32            g_cp_cached_page = 0xFFFFFFFFU;
static int            g_cp_ok;

__attribute__((noinline))
static int cp_read_page(u32 page) {
    if (!g_cp_ok) return 0;
    if ((page & 0xFFFU) != 0U || page < OG_CP_LO || page >= OG_CP_HI) {
        out_s("!! cp_read_page out_of_range="); out_hex(page); out_s("\n");
        return 0;
    }
    if (page == g_cp_cached_page) return 1;
    /* HARDCODED dir = 0U (CP -> AP READ-ONLY, proven at libsencore.so +0x13db0). */
    u32 rc = g_sen_dma(0U, (u64)page, g_cp_phys, CP_PAGE);
    if (rc != 0U) {
        out_s("!! sen_dma_transfer failed rc="); out_u64(rc);
        out_s(" page="); out_hex(page); out_s("\n");
        g_cp_ok = 0;
        g_cp_cached_page = 0xFFFFFFFFU;
        return 0;
    }
    g_cp_cached_page = page;
    return 1;
}

static int cp_read_bytes(u32 addr, u8 *dst, u32 len) {
    while (len > 0U) {
        u32 page = addr & ~0xFFFU;
        u32 off  = addr & 0xFFFU;
        u32 take = CP_PAGE - off;
        if (take > len) take = len;
        if (!cp_read_page(page)) return 0;
        for (u32 i = 0; i < take; i++) dst[i] = g_cp_buf[off + i];
        addr += take;
        dst  += take;
        len  -= take;
    }
    return 1;
}

/* ---- Counters & buffers -------------------------------------------------- */
static u32 g_checked;
static u32 g_mismatches;
static u8  g_big[3072];
static u8  g_scan_win[CP_PAGE + 64U];

/* 100% READ-ONLY CP RAM scan for live DmmCfg.bin Group 0x08a (key 0x57f).
 * Uses ONLY cp_read_page(page) -> single dir=0U sen_dma_transfer call site. */
static void scan_cp_for_dmmcfg(void) {
    static const struct { u32 lo; u32 hi; } ranges[3] = {
        { 0x02000000U, 0x02800000U }, /* highest probability: adjacent to CSDrvParam @ 0x025dabcc */
        { 0x01220000U, 0x02000000U }, /* lower CP .bss / heap (matches A7 IV @ 0x01f7090c) */
        { 0x02800000U, 0x03400000U }, /* upper CP heap up to tmon_addr (0x03400000) */
    };
    u32 pages_scanned = 0;
    u32 hit_va = 0;

    out_s("== cp dmmcfg 0x57f locator (read-only)\n");
    for (u32 r = 0; r < 3u && !hit_va && g_cp_ok; r++) {
        int have_prev = 0;
        for (u32 page = ranges[r].lo; page < ranges[r].hi && g_cp_ok; page += CP_PAGE) {
            if (!cp_read_page(page)) break;
            pages_scanned++;
            for (u32 i = 0; i < CP_PAGE; i++) g_scan_win[64U + i] = g_cp_buf[i];

            u32 start_off = have_prev ? 0U : 64U;
            u32 end_off   = CP_PAGE + 64U - 40U;
            for (u32 o = start_off; o <= end_off; o += 4U) {
                if (g_scan_win[o] == 0x7fU && g_scan_win[o + 1U] == 0x05U &&
                    g_scan_win[o + 2U] == 0x00U && g_scan_win[o + 3U] == 0x00U &&
                    g_scan_win[o + 4U] == 0x00U && g_scan_win[o + 5U] == 0x12U &&
                    g_scan_win[o + 6U] == 0x34U && g_scan_win[o + 7U] == 0x01U) {
                    if (mem_eq(g_scan_win + o, DMM_SIG_8A, 40U)) {
                        hit_va = (page - 64U) + o;
                        break;
                    }
                }
            }
            if (hit_va) break;
            for (u32 i = 0; i < 64U; i++) g_scan_win[i] = g_scan_win[CP_PAGE + i];
            have_prev = 1;
        }
    }

    if (!hit_va) {
        out_s("OBS_DMMCFG_57F_8A status=NOT_FOUND pages_scanned=");
        out_u64(pages_scanned); out_s("\n");
        return;
    }

    u32 base = hit_va;
    out_s("OBS_DMMCFG_57F_8A va="); out_hex(hit_va);
    out_s(" pages_scanned="); out_u64(pages_scanned); out_s("\n");

    /* Live CP RAM packs DmmCfg 20-byte records contiguously (0x50-B group headers stripped at boot):
     *   +0x000: Grp 0x8a (3x 0x57f + 0xffffffff)
     *   +0x050: Grp 0x8b (0x124 = 0x3b00000)
     *   +0x078: Grp 0x8c (0x0ec = 0x1d80000)
     *   +0x0b4: Grp 0x8d (0x0eb = 0x0ec0000)
     *   +0x118: Grp 0x8e (0x57f, 2x 0x634, 2x 0x635, 0x2da)
     *   +0x26c: Grp 0x92 (0x2da = 0x13c6800) */
    u8 buf60[60], b8b[8], b8c[8], b8d[8], b8e[120], b92[8];
    int ok_8a = cp_read_bytes(base,          buf60, 60U);
    int ok_8b = cp_read_bytes(base + 0x050U, b8b,    8U);
    int ok_8c = cp_read_bytes(base + 0x078U, b8c,    8U);
    int ok_8d = cp_read_bytes(base + 0x0B4U, b8d,    8U);
    int ok_8e = cp_read_bytes(base + 0x118U, b8e,  120U);
    int ok_92 = cp_read_bytes(base + 0x26CU, b92,    8U);

    u32 sz_8e = ok_8e ? rd_u32(b8e + 4U) : 0U;
    int ver = ok_8a && ok_8b && ok_8c && ok_8d && ok_8e && ok_92 &&
              rd_u32(b8b) == 0x124U && rd_u32(b8b + 4U) == 0x03B00000U &&
              rd_u32(b8c) == 0x0ECU && rd_u32(b8c + 4U) == 0x01D80000U &&
              rd_u32(b8d) == 0x0EBU && rd_u32(b8d + 4U) == 0x00EC0000U &&
              rd_u32(b8e) == 0x57fU && (sz_8e == 0x01341200U || sz_8e == 0x017A3400U || sz_8e == 0x017BAC00U) &&
              rd_u32(b8e + 20U) == 0x634U && rd_u32(b8e + 24U) == 0x0032A000U &&
              rd_u32(b8e + 60U) == 0x635U && rd_u32(b8e + 64U) == 0x00CA8000U &&
              rd_u32(b8e + 100U) == 0x2DAU && rd_u32(b8e + 104U) == 0x013C6800U &&
              rd_u32(b92) == 0x2DAU && rd_u32(b92 + 4U) == 0x013C6800U;

    out_s("OBS_DMMCFG_VERIFIED="); out_u64((u64)ver);
    out_s(" va_8a="); out_hex(base);
    out_s(" va_8e="); out_hex(base + 0x118U); out_s("\n");
    if (ok_8a) {
        out_s("OBS_DMMCFG_8A_HEX hex="); out_hex_bytes(buf60, 60U); out_s("\n");
    }
    if (ok_8e) {
        out_s("OBS_DMMCFG_8E_HEX hex="); out_hex_bytes(b8e, 40U); out_s("\n");
    }
}

/* 100% READ-ONLY CP RAM preimage check for Zero-Code-Patch True FX2 FL2 & FL3 (IN/SH).
 * Uses ONLY cp_read_bytes() -> single dir=0U sen_dma_transfer call site. */
static void probe_fl23_ro(void) {
    static const u8 pmap_stock[8] = {0x08,0x0e,0x0a,0x0c,0x09,0x0f,0x0b,0x0d};
    static const u8 pmap_patch[8] = {0x08,0x0e,0x16,0x18,0x09,0x0f,0x17,0x19};
    static const u32 desc39_stock[7] = {
        0x00de665cU, 0x00de665cU, 0x00de665cU, 0x00de665cU, 0x00de665cU, 0x00de665cU, 0x00de689cU
    };
    out_s("== cp fl23 zero-code-patch preimage check (read-only)\n");

    int cave_zero = 0, desc39_ok = 0, u01_pm = 0, u01_sl = 0, u0d_pm = 0, u0d_sl = 0;

    /* 1. 0x0010B000 gamma cave (3,456 B) in two chunks (<= 3072 B g_big) */
    if (cp_read_bytes(0x0010B000U, g_big, 2048U)) {
        int z = 1;
        for (u32 i = 0; i < 2048U; i++) if (g_big[i] != 0U) { z = 0; break; }
        if (z && cp_read_bytes(0x0010B800U, g_big, 1408U)) {
            for (u32 i = 0; i < 1408U; i++) if (g_big[i] != 0U) { z = 0; break; }
            cave_zero = z;
        }
    }
    /* 2. desc[39] (IN Still @ 0x010D8AB8, 28 B) */
    {
        u8 d[28];
        if (cp_read_bytes(0x010D8AB8U, d, 28U)) {
            int ok = 1;
            for (u32 i = 0; i < 7U; i++) if (rd_u32(d + i * 4U) != desc39_stock[i]) ok = 0;
            desc39_ok = ok;
            if (!ok) { out_s("OBS_FL23_DESC39 hex="); out_hex_bytes(d, 28U); out_s("\n"); }
        }
    }
    /* 3. Chroma 0x02A40001 pmap (0x016F22BD, 8 B) & unused slots 22..25 (0x016F2864, 256 B) */
    {
        u8 pm[8];
        if (cp_read_bytes(0x016F22BDU, pm, 8U)) {
            if (mem_eq(pm, pmap_stock, 8U)) u01_pm = 1;
            else if (mem_eq(pm, pmap_patch, 8U)) u01_pm = 2;
            else { out_s("OBS_FL23_U01_PMAP hex="); out_hex_bytes(pm, 8U); out_s("\n"); }
        }
        if (cp_read_bytes(0x016F2864U, g_big, 256U)) {
            int z = 1;
            for (u32 i = 0; i < 256U; i++) if (g_big[i] != 0U) { z = 0; break; }
            u01_sl = z;
        }
    }
    /* 4. Matrix 0x02A4000D pmap (0x016F3753, 8 B) & unused slots 22..25 (0x016F7974, 3072 B) */
    {
        u8 pm[8];
        if (cp_read_bytes(0x016F3753U, pm, 8U)) {
            if (mem_eq(pm, pmap_stock, 8U)) u0d_pm = 1;
            else if (mem_eq(pm, pmap_patch, 8U)) u0d_pm = 2;
            else { out_s("OBS_FL23_U0D_PMAP hex="); out_hex_bytes(pm, 8U); out_s("\n"); }
        }
        if (cp_read_bytes(0x016F7974U, g_big, 3072U)) {
            int z = 1;
            for (u32 i = 0; i < 3072U; i++) if (g_big[i] != 0U) { z = 0; break; }
            u0d_sl = z;
        }
    }
    int ready = (cave_zero && desc39_ok && u01_pm == 1 && u01_sl && u0d_pm == 1 && u0d_sl);
    out_s("OBS_FL23 cave_zero="); out_u64((u64)cave_zero);
    out_s(" desc39_ok="); out_u64((u64)desc39_ok);
    out_s(" u01_pmap="); out_u64((u64)u01_pm);
    out_s(" u01_slots_zero="); out_u64((u64)u01_sl);
    out_s(" u0d_pmap="); out_u64((u64)u0d_pm);
    out_s(" u0d_slots_zero="); out_u64((u64)u0d_sl);
    out_s(" fl23_ready="); out_u64((u64)ready); out_s("\n");
}

/* 100% READ-ONLY CP RAM live DMM divide state & CP kprint ring-buffer snapshot.
 * Uses ONLY cp_read_bytes() -> single dir=0U sen_dma_transfer call site. */
static void probe_cp_dmm_and_klog_ro(void) {
    u8 ptrs[20];
    if (cp_read_bytes(0x019D7BCCU, ptrs, 20U)) {
        u32 ext_hash = rd_u32(ptrs + 0x00U);
        u32 div_cnt  = rd_u32(ptrs + 0x10U);
        u16 d8a = 0, d8e = 0;
        u32 h6fa = 0, h74d = 0, h57f = 0;
        u8 b4[4];
        if (div_cnt >= OG_CP_LO && (div_cnt + 0x90U * 2U) <= OG_CP_HI) {
            if (cp_read_bytes(div_cnt + 0x8aU * 2U, b4, 2U)) d8a = rd_u16(b4);
            if (cp_read_bytes(div_cnt + 0x8eU * 2U, b4, 2U)) d8e = rd_u16(b4);
        }
        if (ext_hash >= OG_CP_LO && (ext_hash + 0x750U * 8U) <= OG_CP_HI) {
            if (cp_read_bytes(ext_hash + 0x6faU * 8U, b4, 4U)) h6fa = rd_u32(b4);
            if (cp_read_bytes(ext_hash + 0x74dU * 8U, b4, 4U)) h74d = rd_u32(b4);
            if (cp_read_bytes(ext_hash + 0x57fU * 8U, b4, 4U)) h57f = rd_u32(b4);
        }
        out_s("OBS_DMM_LIVE ext_hash="); out_hex(ext_hash);
        out_s(" div_8a="); out_u64(d8a);
        out_s(" div_8e="); out_u64(d8e);
        out_s(" h_6fa="); out_hex(h6fa);
        out_s(" h_74d="); out_hex(h74d);
        out_s(" h_57f="); out_hex(h57f); out_s("\n");
    }
    u8 kp[8];
    if (cp_read_bytes(0x019DBC38U, kp, 8U)) {
        u32 kbase = rd_u32(kp + 0U);
        u32 ksize = rd_u32(kp + 4U);
        u8 khdr[16];
        if (kbase >= OG_CP_LO && ksize > 32U && (kbase + ksize) <= OG_CP_HI &&
            cp_read_bytes(kbase, khdr, 16U) && rd_u32(khdr) == 0x4B4C4F47U) {
            u32 wpos = rd_u32(khdr + 4U);
            u32 wrap = rd_u32(khdr + 8U);
            out_s("OBS_CP_KLOG base="); out_hex(kbase);
            out_s(" wpos="); out_u64(wpos);
            out_s(" wrap="); out_u64(wrap); out_s("\n");
            u32 max_data = ksize - 16U;
            u32 dump_len = (wpos <= max_data) ? wpos : max_data;
            u32 start_off = 0U;
            if (dump_len > 16384U) {
                start_off = dump_len - 16384U;
                dump_len  = 16384U;
            }
            out_s("== cp kprint text len="); out_u64(dump_len); out_s("\n");
            while (dump_len > 0U && g_cp_ok) {
                u32 chunk = (dump_len > 2048U) ? 2048U : dump_len;
                if (!cp_read_bytes(kbase + 16U + start_off, g_big, chunk)) break;
                for (u32 i = 0; i < chunk; i++) {
                    u8 c = g_big[i];
                    if (c == '\n' || c == '\r' || c == '\t' || (c >= 0x20U && c <= 0x7EU)) out_c(c);
                    else if (c != 0U) out_c('.');
                }
                start_off += chunk;
                dump_len  -= chunk;
            }
            out_s("\n== end cp kprint\n");
        }
    }
}

/* 100% READ-ONLY dump of /log crash/escape files if present after a warm restart. */
static void dump_crash_logs_ro(void) {
    static const char *const log_paths[7] = {
        "/log/escape_done",
        "/log/ulogio_klog.txt",
        "/log/ulogio_tlog.txt",
        "/log/escapelog.bin",
        "/log/cp/escapelog.bin",
        "/log/cp/ulogio_klog.bin",
        "/log/errlog.bin",
    };
    out_s("== ap /log crash probe (read-only)\n");
    for (u32 k = 0; k < 7U; k++) {
        i64 fd = sys_open(log_paths[k], O_RDONLY, 0);
        if (fd < 0) continue;
        i64 r = sys_read(fd, g_big, 2048U);
        sys_close(fd);
        out_s("LOG_FILE "); out_s(log_paths[k]); out_s(" read="); out_i64(r); out_s("\n");
        if (r > 0) {
            for (i64 i = 0; i < r; i++) {
                u8 c = g_big[i];
                if (c == '\n' || c == '\r' || c == '\t' || (c >= 0x20U && c <= 0x7EU)) out_c(c);
                else if (c != 0U) out_c('.');
            }
            out_s("\n");
        }
    }
}

static int verify_files_and_bind_sencore(void) {
    out_s("== identity: process libraries\n");
    int sencore_verified = 0;
    for (u32 i = 0; i < OG_ID_FILE_COUNT; i++) {
        const struct og_id_file *f = &OG_ID_FILES[i];
        char path[200];
        path[0] = 0;
        u64 base = find_mapped_slice(f->suffix, 0, 4096, 5u /* r-x */, path, sizeof(path));
        g_checked++;
        out_s("LIB "); out_s(f->suffix);
        if (!path[0] || !base) {
            out_s(" status=NOT_MAPPED\n");
            g_mismatches++;
            continue;
        }
        u64 fsz = 0;
        u8 dig[32];
        int ok = hash_disk_file(path, &fsz, dig) &&
                 (fsz == f->size) &&
                 mem_eq(dig, f->sha256, 32);
        out_s(" base="); out_hex(base);
        out_s(" size="); out_u64(fsz);
        out_s(" sha256="); out_hex_bytes(dig, 32);
        out_s(ok ? " status=OK\n" : " status=MISMATCH\n");
        if (!ok) {
            g_mismatches++;
            continue;
        }
        if (i == 0U) { /* /libsencore.so: verify all 3 PT_LOAD[0] function prologues before binding */
            u64 a_alloc = find_mapped_slice(f->suffix, SENCORE_DMM_ALLOC_OFF, 8, 5u, 0, 0);
            u64 a_free  = find_mapped_slice(f->suffix, SENCORE_DMM_FREE_OFF,  8, 5u, 0, 0);
            u64 a_dma   = find_mapped_slice(f->suffix, SENCORE_DMA_XFER_OFF,  8, 5u, 0, 0);
            int p_ok = (a_alloc != 0 && a_free != 0 && a_dma != 0) &&
                       mem_eq((const u8 *)a_alloc, SENCORE_PROL_ALLOC, 8) &&
                       mem_eq((const u8 *)a_free,  SENCORE_PROL_FREE,  8) &&
                       mem_eq((const u8 *)a_dma,   SENCORE_PROL_DMA,   8);
            out_s("SENCORE_BIND alloc="); out_hex(a_alloc);
            out_s(" free="); out_hex(a_free);
            out_s(" dma="); out_hex(a_dma);
            out_s(p_ok ? " status=OK\n" : " status=PROLOGUE_MISMATCH\n");
            if (p_ok) {
                g_dmm_alloc = (fn_dmm_alloc_t)a_alloc;
                g_dmm_free  = (fn_dmm_free_t)a_free;
                g_sen_dma   = (fn_sen_dma_t)a_dma;
                sencore_verified = 1;
            } else {
                g_mismatches++;
            }
        }
    }
    return sencore_verified;
}

static void probe_coprocessor(int sencore_ready) {
    out_s("== coprocessor read-only probe\n");
    if (!sencore_ready) {
        out_s("!! CP_SKIP reason=libsencore_not_verified\n");
        g_mismatches++;
        return;
    }

    u32 handle = 0;
    g_cp_phys = g_dmm_alloc(CP_PAGE, &handle);
    out_s("CP_DMM_BUF phys="); out_hex(g_cp_phys); out_s(" handle="); out_u64(handle); out_s("\n");
    if (!g_cp_phys || (g_cp_phys & 0x3FULL) != 0ULL || g_cp_phys < RAM_LO || (g_cp_phys + CP_PAGE) > RAM_HI) {
        out_s("!! CP_SKIP reason=bad_dmm_phys\n");
        if (handle) g_dmm_free(handle);
        g_mismatches++;
        return;
    }

    i64 fd = sys_open("/dev/mem", O_RDONLY_SYNC, 0);
    if (fd < 0) {
        out_s("!! CP_SKIP reason=devmem_open_err rc="); out_i64(fd); out_s("\n");
        g_dmm_free(handle);
        g_mismatches++;
        return;
    }

    u64 lead = g_cp_phys & 0xFFFULL;
    u64 maplen = (lead + CP_PAGE + 0xFFFULL) & ~0xFFFULL;
    i64 mapped = sys_mmap_ro(fd, maplen, g_cp_phys - lead);
    if (mapped == -1) {
        out_s("!! CP_SKIP reason=devmem_mmap_ro_failed\n");
        sys_close(fd);
        g_dmm_free(handle);
        g_mismatches++;
        return;
    }

    g_cp_buf = (const u8 *)mapped + lead;
    g_cp_cached_page = 0xFFFFFFFFU;
    g_cp_ok = 1;

    /* 1. Verify 4 cpapp-b.bin 4 KB code/table identity pages */
    out_s("== cp identity pages\n");
    for (u32 i = 0; i < OG_ID_PAGE_COUNT && g_cp_ok; i++) {
        const struct og_id_page *pg = &OG_ID_PAGES[i];
        g_checked++;
        out_s("CP_PAGE "); out_s(pg->name); out_s(" va="); out_hex(pg->cp_va);
        if (!cp_read_page(pg->cp_va)) {
            out_s(" status=READ_ERR\n");
            g_mismatches++;
            break;
        }
        u8 dig[32];
        sha_buf(g_cp_buf, CP_PAGE, dig);
        int ok = mem_eq(dig, pg->sha256, 32);
        out_s(" sha256="); out_hex_bytes(dig, 32);
        out_s(ok ? " status=OK\n" : " status=MISMATCH\n");
        if (!ok) g_mismatches++;
    }

    /* 2. Verify all 30 small sensor/table cells (8 IMX684 S0 + 11 NTSC 0x08c0 + 11 PAL 0x0880) */
    out_s("== cp ogsq cells (30)\n");
    for (u32 i = 0; i < OG_CP_CELL_COUNT && g_cp_ok; i++) {
        const struct og_cp_cell *c = &OG_CP_CELLS[i];
        u8 got[4];
        g_checked++;
        out_s("CP_CELL "); out_s(c->name); out_s(" va="); out_hex(c->cp_va);
        if (!cp_read_bytes(c->cp_va, got, c->len)) {
            out_s(" status=READ_ERR\n");
            g_mismatches++;
            break;
        }
        int is_st = mem_eq(got, c->stock, c->len);
        int is_tg = mem_eq(got, c->target, c->len);
        out_s(" got="); out_hex_bytes(got, c->len);
        if (is_st)      out_s(" state=STOCK\n");
        else if (is_tg) out_s(" state=TARGET\n");
        else          { out_s(" state=OTHER\n"); g_mismatches++; }
    }

    /* 3. Verify both full 3000-byte Left & Right ISP records by full SHA-256 + key fields */
    out_s("== cp 3000B ISP records (2)\n");
    static const u16 diag_offs[11] = {
        0x006, 0x00a, 0x00e, 0x012, 0x016, 0x194, 0x19c, 0x1a4, 0x784, 0x78c, 0x95e
    };
    for (u32 i = 0; i < OG_CP_REC_COUNT && g_cp_ok; i++) {
        const struct og_cp_rec3000 *r = &OG_CP_RECS[i];
        g_checked++;
        out_s("CP_REC "); out_s(r->name); out_s(" va="); out_hex(r->cp_va);
        if (!cp_read_bytes(r->cp_va, g_big, 3000U)) {
            out_s(" status=READ_ERR\n");
            g_mismatches++;
            break;
        }
        u8 dig[32];
        sha_buf(g_big, 3000U, dig);
        int is_st = mem_eq(dig, r->stock_sha, 32);
        int is_tg = mem_eq(dig, r->target_sha, 32);
        out_s(" sha256="); out_hex_bytes(dig, 32);
        if (is_st)      out_s(" state=STOCK\n");
        else if (is_tg) out_s(" state=TARGET\n");
        else          { out_s(" state=OTHER\n"); g_mismatches++; }
        out_s("  FIELDS");
        for (u32 k = 0; k < 11u; k++) {
            out_s(" +"); out_hex(diag_offs[k]); out_c('=');
            out_u64(rd_u16(g_big + diag_offs[k]));
        }
        out_s("\n");
    }

    /* 4. Verify Step 5 lcdfill_v2 rear-LCD VDF fit + AF/tracking rect tables */
    out_s("== cp step5 lcdfill rects (3)\n");
    for (u32 i = 0; i < OG_STEP5_RECT_COUNT && g_cp_ok; i++) {
        const struct og_cp_rect *rt = &OG_STEP5_RECTS[i];
        u8 got[32];
        g_checked++;
        out_s("CP_RECT "); out_s(rt->name); out_s(" va="); out_hex(rt->cp_va);
        if (!cp_read_bytes(rt->cp_va, got, 32U)) {
            out_s(" status=READ_ERR\n");
            g_mismatches++;
            break;
        }
        int ok = mem_eq(got, rt->stock, 32U);
        out_s(ok ? " state=STOCK\n" : " state=OTHER\n");
        if (!ok) {
            out_s("  hex="); out_hex_bytes(got, 32U); out_s("\n");
            g_mismatches++;
        }
    }

    /* 5. Runtime CP RAM diagnostic snapshots (SOFT/OBS: reported in full for Phase-4 confirmation) */
    out_s("== cp runtime snapshots (soft/obs)\n");
    if (g_cp_ok && cp_read_bytes(CP_DRVPARAM_8C0, g_big, CP_DRVPARAM_LEN)) {
        out_s("OBS_DRVPARAM_8C0 va="); out_hex(CP_DRVPARAM_8C0);
        out_s(" ratio_4_7="); out_hex_bytes(g_big + 4, 4);
        out_s(" hex="); out_hex_bytes(g_big, CP_DRVPARAM_LEN); out_s("\n");
    } else {
        out_s("!! OBS_DRVPARAM_8C0 READ_ERR\n");
    }
    if (g_cp_ok && cp_read_bytes(CP_DRVPARAM_880, g_big, CP_DRVPARAM_LEN)) {
        out_s("OBS_DRVPARAM_880 va="); out_hex(CP_DRVPARAM_880);
        out_s(" ratio_4_7="); out_hex_bytes(g_big + 4, 4);
        out_s(" hex="); out_hex_bytes(g_big, CP_DRVPARAM_LEN); out_s("\n");
    } else {
        out_s("!! OBS_DRVPARAM_880 READ_ERR\n");
    }
    {
        static const struct { const char *tag; u32 va; } alt_drvs[3] = {
            { "OBS_DRVPARAM_820", CP_DRVPARAM_820 },
            { "OBS_DRVPARAM_890", CP_DRVPARAM_890 },
            { "OBS_DRVPARAM_8D0", CP_DRVPARAM_8D0 },
        };
        for (u32 k = 0; k < 3u && g_cp_ok; k++) {
            u8 hdr[48];
            if (cp_read_bytes(alt_drvs[k].va, hdr, 48U)) {
                out_s(alt_drvs[k].tag); out_s(" va="); out_hex(alt_drvs[k].va);
                out_s(" ratio_4_7="); out_hex_bytes(hdr + 4, 4);
                out_s(" hdr48="); out_hex_bytes(hdr, 48U); out_s("\n");
            }
        }
    }
    if (g_cp_ok && cp_read_bytes(CP_SIZETBL_BASE, g_big, CP_SIZETBL_LEN)) {
        u32 def_units = rd_u32(g_big + (CP_SPLIT_DEF_ADDR - CP_SIZETBL_BASE));
        u16 out_w     = rd_u16(g_big + (CP_OUTSZ_CLASS3   - CP_SIZETBL_BASE));
        u16 out_h     = rd_u16(g_big + (CP_OUTSZ_CLASS3   - CP_SIZETBL_BASE) + 2U);
        u32 dmm_id    = rd_u32(g_big + (CP_DMMID_CLASS3   - CP_SIZETBL_BASE));
        u8  ovr_units = g_big[CP_SPLIT_OVR_ADDR - CP_SIZETBL_BASE];
        out_s("OBS_SIZETBL base=0x199ec8c class3_w="); out_u64(out_w);
        out_s(" class3_h="); out_u64(out_h);
        out_s(" dmm_id="); out_hex(dmm_id);
        out_s(" split_def="); out_u64(def_units);
        out_s(" split_ovr="); out_u64(ovr_units); out_s("\n");
        out_s("OBS_SIZETBL_RAW128 va=0x199ec8c hex=");
        out_hex_bytes(g_big + (0x0199EC8CU - CP_SIZETBL_BASE), 128U); out_s("\n");
    } else {
        out_s("!! OBS_SIZETBL READ_ERR\n");
    }
    if (g_cp_ok && cp_read_bytes(CP_SHADOW_ADDR, g_big, CP_SHADOW_LEN)) {
        out_s("OBS_IMX684_SHADOW va="); out_hex(CP_SHADOW_ADDR);
        out_s(" r2_7b80="); out_hex(g_big[0x10]);
        out_s(" r34_7b84="); out_hex(g_big[0x14]); out_c('/'); out_hex(g_big[0x18]);
        out_s(" r56_7b8c="); out_hex(g_big[0x1c]); out_c('/'); out_hex(g_big[0x20]);
        out_s(" r78_7ba4="); out_hex(g_big[0x34]); out_c('/'); out_hex(g_big[0x3c]);
        out_s(" r10_7bd0="); out_hex(g_big[0x60]); out_s("\n");
        out_s("OBS_IMX684_SHADOW_HEX hex=");
        out_hex_bytes(g_big, CP_SHADOW_LEN); out_s("\n");
    } else {
        out_s("!! OBS_IMX684_SHADOW READ_ERR\n");
    }

    /* 6. Read-only CP RAM scan for live DmmCfg.bin Group 0x08a / 0x08e (key 0x57f) */
    if (g_cp_ok) {
        scan_cp_for_dmmcfg();
    }

    /* 7. Read-only CP RAM preimage check for Zero-Code-Patch True FX2 FL2 & FL3 (IN/SH) + live DMM/KLOG */
    if (g_cp_ok) {
        probe_fl23_ro();
        probe_cp_dmm_and_klog_ro();
    }

    sys_munmap((void *)mapped, maplen);
    sys_close(fd);
    g_dmm_free(handle);
}

static void probe_main_processor(void) {
    /* 1. Step 3 libmpr.so g_videoParamComb (4 L1-comb sites in process memory) */
    out_s("== mp libmpr.so sites (4)\n");
    for (u32 i = 0; i < OG_LIBMPR_SITE_COUNT; i++) {
        const struct og_mp_site *s = &OG_LIBMPR_SITES[i];
        u64 va = find_mapped_slice("/libmpr.so", s->file_off, s->len, 1u /* r */, 0, 0);
        g_checked++;
        out_s("LM_SITE "); out_s(s->name); out_s(" off="); out_hex(s->file_off);
        if (!va) {
            out_s(" status=NOT_MAPPED\n");
            g_mismatches++;
            continue;
        }
        const u8 *p = (const u8 *)va;
        int is_st = mem_eq(p, s->stock, s->len);
        int is_tg = mem_eq(p, s->target, s->len);
        out_s(" got="); out_hex_bytes(p, s->len);
        if (is_st)      out_s(" state=STOCK\n");
        else if (is_tg) out_s(" state=TARGET\n");
        else          { out_s(" state=OTHER\n"); g_mismatches++; }
    }

    /* 2. Step 3 av-cam.bin via /dev/mem (STRICT O_RDONLY + PROT_READ, cmdline-gated) */
    out_s("== mp av-cam.bin via /dev/mem (ro)\n");
    if (!cmdline_has(OG_AVCAM_RESERVE)) {
        out_s("!! AVCAM_SKIP reason=cmdline_missing_" OG_AVCAM_RESERVE "\n");
        g_mismatches++;
        return;
    }
    i64 fd = sys_open("/dev/mem", O_RDONLY, 0);
    if (fd < 0) {
        out_s("!! AVCAM_SKIP reason=devmem_open_err rc="); out_i64(fd); out_s("\n");
        g_mismatches++;
        return;
    }
    i64 mapped = sys_mmap_ro(fd, OG_AVCAM_MAP_HI, OG_AVCAM_PHYS);
    if (mapped == -1) {
        out_s("!! AVCAM_SKIP reason=devmem_mmap_ro_failed\n");
        sys_close(fd);
        g_mismatches++;
        return;
    }
    const u8 *av = (const u8 *)mapped;
    for (u32 i = 0; i < OG_AVCAM_GUARD_COUNT; i++) {
        const struct og_av_guard *g = &OG_AVCAM_GUARDS[i];
        u8 dig[32];
        g_checked++;
        sha_buf(av + g->file_off, g->len, dig);
        int ok = mem_eq(dig, g->sha256, 32);
        out_s("AV_GUARD "); out_s(g->name); out_s(" off="); out_hex(g->file_off);
        out_s(" len="); out_u64(g->len);
        out_s(ok ? " status=OK\n" : " status=MISMATCH\n");
        if (!ok) g_mismatches++;
    }
    for (u32 i = 0; i < OG_AVCAM_SITE_COUNT; i++) {
        const struct og_mp_site *s = &OG_AVCAM_SITES[i];
        const u8 *p = av + s->file_off;
        int is_st = mem_eq(p, s->stock, s->len);
        int is_tg = mem_eq(p, s->target, s->len);
        g_checked++;
        out_s("AV_SITE "); out_s(s->name); out_s(" off="); out_hex(s->file_off);
        out_s(" got="); out_hex_bytes(p, s->len);
        if (is_st)      out_s(" state=STOCK\n");
        else if (is_tg) out_s(" state=TARGET\n");
        else          { out_s(" state=OTHER\n"); g_mismatches++; }
    }
    sys_munmap((void *)mapped, OG_AVCAM_MAP_HI);
    sys_close(fd);
}

__attribute__((visibility("default"))) void _init(void) {
    g_olen = 0;
    g_checked = 0;
    g_mismatches = 0;

    out_s("A6700_OG_PROBE_V1 " OG_PROBE_LABEL "\n");
    out_s("MODE=READ_ONLY_ZERO_WRITE\n");

    dump_proc_trimmed("/proc/version", 512U);
    u64 cmd_n = read_text_file("/proc/cmdline", g_cmdline, sizeof(g_cmdline));
    out_s("== file /proc/cmdline len="); out_u64(cmd_n); out_s("\n");
    out_buf(g_cmdline, cmd_n);
    if (cmd_n == 0 || g_cmdline[cmd_n - 1] != '\n') out_s("\n");
    dump_proc_trimmed("/proc/iomem", 4096U);

    g_maps_len = read_text_file("/proc/self/maps", g_maps, sizeof(g_maps));
    out_s("MAPS_BYTES="); out_u64(g_maps_len); out_s("\n");

    int sencore_ready = verify_files_and_bind_sencore();
    probe_coprocessor(sencore_ready);
    probe_main_processor();
    dump_crash_logs_ro();

    out_s("SUMMARY checked="); out_u64(g_checked);
    out_s(" mismatches="); out_u64(g_mismatches);
    out_s(" STATUS="); out_s(g_mismatches == 0U ? "READY" : "MISMATCH");
    out_s("\n");
    flush_result();
}
