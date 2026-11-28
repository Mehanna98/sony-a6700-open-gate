/* a6700_og_ram.c -- All-or-nothing compare-and-swap + automatic-rollback RAM-only Open Gate v6.2.1 patcher.
 *
 * Target: Sony ILCE-6700 (a6700) FW v2.00 ONLY (stock SHA-256 locked, auto PAL/NTSC detection).
 * Scope : Complete Universal 4K 3:2 Open Gate v6.2.1 (3840x2560 @ NTSC 23.98p + PAL 25p + PAL 50p):
 *   - Step 4 (CP RAM, applied FIRST): Dynamic 7-anchor-verified DmmCfg.bin key 0x57f raw write buffer
 *                    (20,189,696 -> 23,943,680 B = 3980x6016 = 0x016D5A00 across all 4 size words in Grp 0x8a+0x8e;
 *                    matches dmmwb_a6700_v1.json; 3 * 23,943,680 = 71,831,040 B <= 74,448,896 B [+2.50 MiB spare]).
 *   - Step 1 (CP RAM):
 *       * Col-1 (ogsq_a6700_v1: PAL-50Hz-safe 5952x3876 from row 214, readout=1968 < 2000 line periods,
 *         v_ratio=165/191 = 0xa5/0xbf): ALL 51 sensor/table cells (6 IMX684 Col-1 regs + 9x5 modes
 *         0x820/0x880/0x890/0x8c0/0x8d0) + L/R 3000-B ISP records (0x0d3885c, 0x0d39414)
 *         + ALL 5 Col-1 CSDrvParam records (auto-detected PAL or NTSC sparse diffs).
 *       * PAL 50p (ogsq50_a6700_v1, mode 0x0830, 5612x3732 from row 214, readout=1897 < 2000 lines,
 *         v_ratio=137/162 = 0x89/0xa2): 16 CP cells + L/R 3000-B ISP records (0x0d39fcc, 0x0d3ab84)
 *         + CSDrvParam[0x0830] @ 0x025db01c (applied on PAL cameras; cleanly skipped on NTSC).
 *   - Step 5 (CP RAM): 3 lcdfill_v2 rear-LCD 3:2 preview fill + AF/tracking rect sites (20 B)
 *   - Step 2 (CP RAM): Movie size table Class 3 @ 0x0199ecc4 (3840x2160 -> 3840x2560, guarded)
 *   - Step 3 (AP RAM): Exact 8 verified libmpr.so sites (5 comb + 2 MP4 track heights 0x1ec1b8/0x1ec2e8 +
 *                      CompareResolution 0x15e4e4) + 475 M19 av-cam.bin sites (dc civac + pread64 kview)
 *   - Step 6 (AP RAM): 17-byte In-Camera 3:2 Playback Fix (avdec8k + pbaspect + pbformat + pbmpr):
 *                      3 VIPT-aligned av-cam.bin code pages (whole-page masked SHA-256 in mapped + kernel views,
 *                      dc cvau + ic ivau across all cores, code written FIRST) + decode row 0 @ 0xc00350 LAST.
 *
 * STRICT SAFETY GUARANTEES:
 *   1. ZERO flash writes (/dev/nflash, /cp/cpapp, /setting/BACKUP). 100% volatile RAM / CP-RAM.
 *   2. Exact 8-syscall surface: openat(56), close(57), read(63), write(64), pread64(67), munmap(215), mmap(222), mprotect(226).
 *   3. PASS 0 locks /proc/cmdline, CTR_EL0 PIPT/VIPT check, on-disk SHA-256 of libsencore/libmpr/libJiritsu,
 *      libsencore prologues, 3 cpapp-b.bin code pages, 3 av-cam .rodata guards, and 3 whole-page PB code guards (mapped+kview).
 *   4. PASS 1 dry-checks EVERY SINGLE preimage site BEFORE writing 1 byte. Auto-rollback restores STOCK on error.
 *   5. PASS 3 re-reads every single site end-to-end (incl. pread64 kernel view on av-cam.bin) and only reports APPLY_OK on 100% match.
 */
#include "a6700_og_patch_spec.h"

/* ---- AArch64 Linux syscalls ---------------------------------------------- */
#define NR_openat   56
#define NR_close    57
#define NR_read     63
#define NR_write    64
#define NR_pread64  67
#define NR_munmap   215
#define NR_mmap     222
#define NR_mprotect 226

#define AT_FDCWD      (-100)
#define O_RDONLY      0
#define O_WRONLY      1
#define O_RDWR        2
#define O_RDWR_SYNC   0x101002
#define O_CREAT       0x40
#define O_TRUNC       0x200

#define PROT_NONE     0
#define PROT_READ     1
#define PROT_WRITE    2
#define PROT_EXEC     4
#define MAP_SHARED    1
#define MAP_FIXED     0x10
#define MAP_ANON_PRIV 0x22 /* MAP_PRIVATE | MAP_ANONYMOUS */

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

__attribute__((noinline)) static i64 sys_open(const char *p, i64 fl, i64 mode)       { return sc6(NR_openat, AT_FDCWD, (i64)p, fl, mode, 0, 0); }
__attribute__((noinline)) static i64 sys_read(i64 fd, void *b, u64 n)                { return sc6(NR_read, fd, (i64)b, (i64)n, 0, 0, 0); }
__attribute__((noinline)) static i64 sys_write(i64 fd, const void *b, u64 n)         { return sc6(NR_write, fd, (i64)b, (i64)n, 0, 0, 0); }
__attribute__((noinline)) static i64 sys_pread64(i64 fd, void *b, u64 n, u64 off)    { return sc6(NR_pread64, fd, (i64)b, (i64)n, (i64)off, 0, 0); }
__attribute__((noinline)) static i64 sys_close(i64 fd)                               { return sc6(NR_close, fd, 0, 0, 0, 0, 0); }
__attribute__((noinline)) static i64 sys_munmap(void *p, u64 len)                    { return sc6(NR_munmap, (i64)p, (i64)len, 0, 0, 0, 0); }
__attribute__((noinline)) static i64 sys_mprotect(u64 addr, u64 len, i64 prot)       { return sc6(NR_mprotect, (i64)addr, (i64)len, prot, 0, 0, 0); }
__attribute__((noinline)) static i64 sys_mmap_rw(i64 fd, u64 len, u64 off) {
    i64 r = sc6(NR_mmap, 0, (i64)len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (i64)off);
    return (r < 0 && r > -4096) ? -1 : r;
}
__attribute__((noinline)) static i64 sys_mmap_anon_none(u64 len) {
    i64 r = sc6(NR_mmap, 0, (i64)len, PROT_NONE, MAP_ANON_PRIV, -1, 0);
    return (r < 0 && r > -4096) ? -1 : r;
}
__attribute__((noinline)) static i64 sys_mmap_fixed_rw(i64 fd, u64 va, u64 len, u64 off) {
    i64 r = sc6(NR_mmap, (i64)va, (i64)len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, (i64)off);
    return (r < 0 && r > -4096) ? -1 : r;
}

static void mem_barrier_sy(void) { __asm__ volatile("dsb sy" ::: "memory"); }
static u64 read_ctr_el0(void) {
    u64 v;
    __asm__ volatile("mrs %0, ctr_el0" : "=r"(v));
    return v;
}

/* ---- Output buffer (max 60 KiB) ------------------------------------------ */
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

/* ---- Helpers & FIPS 180-4 SHA-256 ---------------------------------------- */
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
static int av_kview_eq(i64 av_fd, u64 file_off, const u8 *exp, u32 len) {
    u8 tmp[16];
    if (len > 16U) return 0;
    if (sys_pread64(av_fd, tmp, len, OG_AVCAM_PHYS + file_off) != (i64)len) return 0;
    return mem_eq(tmp, exp, len);
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
static void sha_buf(const u8 *p, u64 n, u8 dig[32]) {
    struct sha256_ctx ctx;
    sha_init(&ctx); sha_add(&ctx, p, n); sha_end(&ctx, dig);
}

/* ---- /proc/self/maps & /proc/cmdline ------------------------------------- */
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
static int cmdline_has(const char *needle) {
    u64 m = slen(needle);
    for (u64 i = 0; g_cmdline[i]; i++) {
        if (mem_eq((const u8 *)(g_cmdline + i), (const u8 *)needle, m)) return 1;
    }
    return 0;
}
static u64 find_mapped_slice(const char *suffix, u64 file_off, u64 len, u8 req_perms,
                             u8 *out_perms, char *path_out, u64 path_cap) {
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
/* Clean & invalidate to Point of Coherency (PoC) so kernel linear map & video HW see new av-cam.bin bytes immediately */
static void clean_dcache_range(u64 start, u64 len) {
    u64 end = start + len;
    for (u64 p = start & ~63ULL; p < end; p += 64ULL) {
        __asm__ volatile("dc civac, %0" :: "r"(p) : "memory");
    }
    __asm__ volatile("dsb sy" ::: "memory");
}

/* ---- Private Copy-on-Write writer for libmpr.so -------------------------- */
static int cow_write_libmpr(u64 file_off, const u8 *src, u64 len) {
    u8 perms = 0;
    u64 va = find_mapped_slice("/libmpr.so", file_off, len, 1u, &perms, 0, 0);
    if (!va) return 0;
    int need_mprot = !(perms & 2u);
    int is_code = (perms & 4u) != 0u;
    u64 pg_start = va & ~4095ULL;
    u64 pg_end   = (va + len + 4095ULL) & ~4095ULL;
    u64 pg_len   = pg_end - pg_start;
    i64 orig_prot = ((perms & 1u) ? PROT_READ : 0)
                  | ((perms & 2u) ? PROT_WRITE : 0)
                  | ((perms & 4u) ? PROT_EXEC : 0);
    if (need_mprot) {
        if (sys_mprotect(pg_start, pg_len, orig_prot | PROT_WRITE) != 0) return 0;
    }
    if (is_code && ((va & 3ULL) == 0ULL) && ((len & 3ULL) == 0ULL)) {
        volatile u32 *dst32 = (volatile u32 *)va;
        for (u64 i = 0; i < len; i += 4ULL) {
            u32 w = rd_u32(src + i);
            __atomic_store_n(&dst32[i >> 2], w, __ATOMIC_RELEASE);
        }
        flush_icache_range(va, len);
    } else {
        volatile u8 *dst = (volatile u8 *)va;
        for (u64 i = 0; i < len; i++) dst[i] = src[i];
        __asm__ volatile("dsb ish" ::: "memory");
    }
    if (need_mprot) (void)sys_mprotect(pg_start, pg_len, orig_prot);
    return mem_eq((const u8 *)va, src, len);
}

/* ---- 64-byte-aligned CP DMA read-modify-write engine --------------------- */
typedef u64 (*fn_dmm_alloc_t)(u32 size, u32 *handle);
typedef u64 (*fn_dmm_free_t)(u32 handle);
typedef u32 (*fn_sen_dma_t)(u32 dir, u64 src, u64 dst, u32 size);

static fn_dmm_alloc_t g_dmm_alloc;
static fn_dmm_free_t  g_dmm_free;
static fn_sen_dma_t   g_sen_dma;
static u8            *g_cp_buf;
static u64            g_cp_phys;

__attribute__((noinline))
static u8 *cp_dma_read_span(u32 cp_va, u32 len, u32 *out_aligned_va, u32 *out_dma_len) {
    if (cp_va < OG_CP_LO || (cp_va + len) > OG_CP_HI) return 0;
    u32 al_start = cp_va & ~0x3FU;
    u32 al_end   = (cp_va + len + 0x3FU) & ~0x3FU;
    u32 dma_len  = al_end - al_start;
    if (dma_len == 0U || dma_len > CP_PAGE) return 0;
    for (u32 i = 0; i < dma_len; i++) g_cp_buf[i] = 0xEEU;
    mem_barrier_sy();
    if (g_sen_dma(0U, (u64)al_start, g_cp_phys, dma_len) != 0U) return 0;
    mem_barrier_sy();
    if (out_aligned_va) *out_aligned_va = al_start;
    if (out_dma_len)    *out_dma_len = dma_len;
    return g_cp_buf + (cp_va - al_start);
}

__attribute__((noinline))
static int cp_dma_write_contig(u32 cp_va, const u8 *src, u32 len) {
    u32 al_start = 0, dma_len = 0;
    u8 *p = cp_dma_read_span(cp_va, len, &al_start, &dma_len);
    if (!p) return 0;
    for (u32 i = 0; i < len; i++) p[i] = src[i];
    mem_barrier_sy();
    if (g_sen_dma(1U, g_cp_phys, (u64)al_start, dma_len) != 0U) return 0;
    u8 *rb = cp_dma_read_span(cp_va, len, 0, 0);
    return (rb != 0) && mem_eq(rb, src, len);
}

__attribute__((noinline))
static int cp_dma_write_sparse(u32 cp_va, u32 span_len, const u16 *offs, const u8 *src, u32 count) {
    u32 al_start = 0, dma_len = 0;
    u8 *p = cp_dma_read_span(cp_va, span_len, &al_start, &dma_len);
    if (!p) return 0;
    for (u32 i = 0; i < count; i++) p[offs[i]] = src[i];
    mem_barrier_sy();
    if (g_sen_dma(1U, g_cp_phys, (u64)al_start, dma_len) != 0U) return 0;
    u8 *rb = cp_dma_read_span(cp_va, span_len, 0, 0);
    if (!rb) return 0;
    for (u32 i = 0; i < count; i++) if (rb[offs[i]] != src[i]) return 0;
    return 1;
}

static int cp_check_sparse(const u8 *rec, const u16 *offs, const u8 *exp, u32 count) {
    for (u32 i = 0; i < count; i++) if (rec[offs[i]] != exp[i]) return 0;
    return 1;
}

/* ---- Step 4: Dynamic 7-anchor-verified DmmCfg key 0x57f (3980x6016 = 0x016D5A00) ---- */
#define OG_DMM_SITE_COUNT 4U
struct og_dmm_site { const char *name; u32 off; u8 stock[4]; u8 target[4]; };
static const struct og_dmm_site OG_DMM_SITES[OG_DMM_SITE_COUNT] = {
    { "dmm_8a_sz0", 0x00000004U, {0x00,0x12,0x34,0x01}, {0x00,0x5a,0x6d,0x01} },
    { "dmm_8a_sz1", 0x00000018U, {0x00,0x12,0x34,0x01}, {0x00,0x5a,0x6d,0x01} },
    { "dmm_8a_sz2", 0x0000002CU, {0x00,0x12,0x34,0x01}, {0x00,0x5a,0x6d,0x01} },
    { "dmm_8e_sz0", 0x0000011CU, {0x00,0x12,0x34,0x01}, {0x00,0x5a,0x6d,0x01} },
};
static const u8 DMM_SIG_8A_TGT[40] = {
    0x7f,0x05,0x00,0x00, 0x00,0x5a,0x6d,0x01, 0x0f,0x01,0x00,0x00, 0x00,0x00,0x00,0x00, 0x07,0x00,0x00,0x00,
    0x7f,0x05,0x00,0x00, 0x00,0x5a,0x6d,0x01, 0x0f,0x01,0x00,0x00, 0x00,0x00,0x00,0x00, 0x07,0x00,0x00,0x00
};

static u8  g_scan_win[CP_PAGE + 64U];
static u32 g_dmm_base;

static int verify_dmmcfg_anchors(u32 base) {
    if (base < OG_CP_LO || (base + 0x280U) > OG_CP_HI) return 0;
    u8 *p = cp_dma_read_span(base, 0x280U, 0, 0);
    if (!p) return 0;
    if (!mem_eq(p, DMM_SIG_8A, 40U) && !mem_eq(p, DMM_SIG_8A_TGT, 40U)) return 0;
    if (rd_u32(p + 0x050U) != 0x124U || rd_u32(p + 0x054U) != 0x03B00000U) return 0;
    if (rd_u32(p + 0x078U) != 0x0ECU || rd_u32(p + 0x07CU) != 0x01D80000U) return 0;
    if (rd_u32(p + 0x0B4U) != 0x0EBU || rd_u32(p + 0x0B8U) != 0x00EC0000U) return 0;
    if (rd_u32(p + 0x118U) != 0x57fU) return 0;
    u32 sz_8e = rd_u32(p + 0x11CU);
    if (sz_8e != 0x01341200U && sz_8e != 0x016D5A00U) return 0;
    if (rd_u32(p + 0x12CU) != 0x634U || rd_u32(p + 0x130U) != 0x0032A000U) return 0;
    if (rd_u32(p + 0x154U) != 0x635U || rd_u32(p + 0x158U) != 0x00CA8000U) return 0;
    if (rd_u32(p + 0x17CU) != 0x2DAU || rd_u32(p + 0x180U) != 0x013C6800U) return 0;
    if (rd_u32(p + 0x26CU) != 0x2DAU || rd_u32(p + 0x270U) != 0x013C6800U) return 0;
    return 1;
}

static u32 locate_dmmcfg_base(void) {
    static const struct { u32 lo; u32 hi; } ranges[3] = {
        { 0x02000000U, 0x02800000U },
        { 0x01220000U, 0x02000000U },
        { 0x02800000U, 0x03400000U },
    };
    for (u32 r = 0; r < 3U; r++) {
        int have_prev = 0;
        for (u32 page = ranges[r].lo; page < ranges[r].hi; page += CP_PAGE) {
            u8 *pg = cp_dma_read_span(page, CP_PAGE, 0, 0);
            if (!pg) break;
            for (u32 i = 0; i < CP_PAGE; i++) g_scan_win[64U + i] = pg[i];
            u32 start_off = have_prev ? 0U : 64U;
            u32 end_off   = CP_PAGE + 64U - 40U;
            for (u32 o = start_off; o <= end_off; o += 4U) {
                if (g_scan_win[o] == 0x7fU && g_scan_win[o + 1U] == 0x05U &&
                    g_scan_win[o + 2U] == 0x00U && g_scan_win[o + 3U] == 0x00U &&
                    g_scan_win[o + 7U] == 0x01U) {
                    if (mem_eq(g_scan_win + o, DMM_SIG_8A, 40U) ||
                        mem_eq(g_scan_win + o, DMM_SIG_8A_TGT, 40U)) {
                        u32 hit_va = (page - 64U) + o;
                        if (verify_dmmcfg_anchors(hit_va)) return hit_va;
                    }
                }
            }
            for (u32 i = 0; i < 64U; i++) g_scan_win[i] = g_scan_win[CP_PAGE + i];
            have_prev = 1;
        }
    }
    return 0U;
}

/* ---- Step 6 VIPT-aligned av-cam.bin Playback Code Page helpers ----------- */
struct pb_map {
    i64 res_raw;
    u8 *page_va;
};
static struct pb_map g_pb_code[OG_PB_CODE_PAGE_COUNT];
static i64 g_pb_data_raw = -1;
static u8 *g_pb_data_va;
static u8  g_pb_tmp[4096];

static void pb_sync_all_code_icache(void) {
    for (u32 i = 0; i < OG_PB_CODE_SITE_COUNT; i++) {
        const struct og_pb_code_site *s = &OG_PB_CODE_SITES[i];
        u8 *p = g_pb_code[s->page_idx].page_va + (s->file_off - OG_PB_CODE_PAGES[s->page_idx].page_off);
        __asm__ volatile("dc cvau, %0" :: "r"(p) : "memory");
    }
    __asm__ volatile("dsb ish" ::: "memory");
    for (u32 i = 0; i < OG_PB_CODE_SITE_COUNT; i++) {
        const struct og_pb_code_site *s = &OG_PB_CODE_SITES[i];
        u8 *p = g_pb_code[s->page_idx].page_va + (s->file_off - OG_PB_CODE_PAGES[s->page_idx].page_off);
        __asm__ volatile("ic ivau, %0" :: "r"(p) : "memory");
    }
    __asm__ volatile("dsb ish\nisb" ::: "memory");
}

static int pb_verify_masked_page(u32 p, const u8 *src_4k) {
    for (u32 k = 0; k < 4096U; k++) g_pb_tmp[k] = src_4k[k];
    for (u32 s = 0; s < OG_PB_CODE_SITE_COUNT; s++) {
        if (OG_PB_CODE_SITES[s].page_idx != p) continue;
        u32 lo = OG_PB_CODE_SITES[s].file_off - OG_PB_CODE_PAGES[p].page_off;
        g_pb_tmp[lo] = 0; g_pb_tmp[lo + 1U] = 0; g_pb_tmp[lo + 2U] = 0; g_pb_tmp[lo + 3U] = 0;
    }
    u8 dig[32];
    sha_buf(g_pb_tmp, 4096ULL, dig);
    return mem_eq(dig, OG_PB_CODE_PAGES[p].masked_sha256, 32U);
}

static int pb_map_all(i64 av_mem_fd) {
    for (u32 i = 0; i < OG_PB_CODE_PAGE_COUNT; i++) {
        g_pb_code[i].res_raw = -1;
        g_pb_code[i].page_va = 0;
    }
    g_pb_data_raw = -1;
    g_pb_data_va = 0;

    for (u32 i = 0; i < OG_PB_CODE_PAGE_COUNT; i++) {
        u64 page_off = OG_PB_CODE_PAGES[i].page_off;
        i64 res = sys_mmap_anon_none(OG_AVCAM_VIPT_ALIGN + 4096ULL);
        if (res == -1) return 0;
        g_pb_code[i].res_raw = res;
        u64 want = (OG_AVCAM_KVA_BASE + page_off) & (OG_AVCAM_VIPT_ALIGN - 1ULL);
        u64 va = (u64)res + ((want - (u64)res) & (OG_AVCAM_VIPT_ALIGN - 1ULL));
        i64 c = sys_mmap_fixed_rw(av_mem_fd, va, 4096ULL, OG_AVCAM_PHYS + page_off);
        if (c == -1 || (u64)c != va) return 0;
        if (((u64)c ^ (OG_AVCAM_KVA_BASE + page_off)) & (OG_AVCAM_VIPT_ALIGN - 1ULL)) return 0;
        g_pb_code[i].page_va = (u8 *)c;
    }
    g_pb_data_raw = sys_mmap_rw(av_mem_fd, 4096ULL, OG_AVCAM_PHYS + OG_PB_DATA_PAGE_OFF);
    if (g_pb_data_raw == -1) return 0;
    g_pb_data_va = (u8 *)g_pb_data_raw;
    return 1;
}

static void pb_unmap_all(void) {
    if (g_pb_data_raw != -1) {
        sys_munmap((void *)g_pb_data_raw, 4096ULL);
        g_pb_data_raw = -1;
        g_pb_data_va = 0;
    }
    for (u32 i = 0; i < OG_PB_CODE_PAGE_COUNT; i++) {
        if (g_pb_code[i].res_raw != -1) {
            sys_munmap((void *)g_pb_code[i].res_raw, OG_AVCAM_VIPT_ALIGN + 4096ULL);
            g_pb_code[i].res_raw = -1;
            g_pb_code[i].page_va = 0;
        }
    }
}

/* ---- Touched-site tracking for automatic rollback ------------------------ */
static u8 g_touched_dmm[OG_DMM_SITE_COUNT];
static u8 g_touched_cells[OG_CP_CELL_COUNT];
static u8 g_touched_cells50[OG_CP50_CELL_COUNT];
static u8 g_touched_lcdfill[OG_LCDFILL_CELL_COUNT];
static u8 g_touched_isp[OG_ISP_REC_COUNT];
static u8 g_touched_col1_drv[OG_COL1_DRV_COUNT];
static u8 g_touched_drv_830;
static u8 g_touched_sizetbl;
static u8 g_touched_lm[OG_LIBMPR_SITE_COUNT];
static u8 g_touched_av_blob[OG_AVCAM_BLOB_COUNT];
static u8 g_touched_av_h[OG_AVCAM_HPATCH_COUNT];
static u8 g_touched_pb_code[OG_PB_CODE_SITE_COUNT];
static u8 g_touched_pb_data;

static const u8 OG_H2160_BYTES[4] = { 0x70, 0x08, 0x00, 0x00 };
static const u8 OG_H2560_BYTES[4] = { 0x00, 0x0a, 0x00, 0x00 };

static void rollback_all(u8 *av_map, int is_pal) {
    out_s("== ROLLBACK: restoring STOCK to all touched sites\n");
    u32 rb_fail = 0;

    /* Reverse Step 6 Playback: DATA FIRST, then CODE + I-cache invalidate! */
    if (g_touched_pb_data && g_pb_data_va) {
        volatile u32 *dst = (volatile u32 *)(g_pb_data_va + (OG_PB_DATA_SITE_OFF - OG_PB_DATA_PAGE_OFF));
        __atomic_store_n(dst, rd_u32(OG_PB_DATA_OLD), __ATOMIC_RELEASE);
        clean_dcache_range((u64)dst, 4ULL);
        if (!mem_eq((const u8 *)dst, OG_PB_DATA_OLD, 4U)) rb_fail++;
    }
    int pb_code_touched = 0;
    for (u32 i = 0; i < OG_PB_CODE_SITE_COUNT; i++) {
        if (!g_touched_pb_code[i]) continue;
        const struct og_pb_code_site *s = &OG_PB_CODE_SITES[i];
        u8 *pg = g_pb_code[s->page_idx].page_va;
        if (!pg) { rb_fail++; continue; }
        volatile u32 *dst = (volatile u32 *)(pg + (s->file_off - OG_PB_CODE_PAGES[s->page_idx].page_off));
        __atomic_store_n(dst, rd_u32(s->stock), __ATOMIC_RELEASE);
        pb_code_touched = 1;
        if (!mem_eq((const u8 *)dst, s->stock, 4U)) rb_fail++;
    }
    if (pb_code_touched) pb_sync_all_code_icache();

    for (u32 i = 0; i < OG_AVCAM_HPATCH_COUNT; i++) {
        if (!g_touched_av_h[i] || !av_map) continue;
        u32 pk = OG_AVCAM_HPACKED[i];
        u32 off = pk & 0x7FFFFFFFU;
        u8 len = (pk & 0x80000000U) ? 4U : 2U;
        u8 *dst = av_map + off;
        for (u8 k = 0; k < len; k++) dst[k] = OG_H2160_BYTES[k];
        clean_dcache_range((u64)dst, len);
        if (!mem_eq(dst, OG_H2160_BYTES, len)) rb_fail++;
    }
    for (u32 i = 0; i < OG_AVCAM_BLOB_COUNT; i++) {
        if (!g_touched_av_blob[i] || !av_map) continue;
        const struct og_av_patch *p = &OG_AVCAM_BLOBS[i];
        u8 *dst = av_map + p->file_off;
        for (u8 k = 0; k < p->len; k++) dst[k] = p->stock[k];
        clean_dcache_range((u64)dst, p->len);
        if (!mem_eq(dst, p->stock, p->len)) rb_fail++;
    }
    for (u32 i = 0; i < OG_LIBMPR_SITE_COUNT; i++) {
        if (!g_touched_lm[i]) continue;
        const struct og_mp_site *s = &OG_LIBMPR_SITES[i];
        if (!cow_write_libmpr(s->file_off, s->stock, s->len)) rb_fail++;
    }
    if (g_touched_sizetbl && !cp_dma_write_contig(OG_SIZETBL_SITE_VA, OG_SIZETBL_OLD, 4U)) rb_fail++;
    if (g_touched_drv_830 && !cp_dma_write_sparse(CP_DRVPARAM_830, CP_DRVPARAM_LEN, OG_DRV_830_OFFS, OG_DRV_830_OLD, OG_DRV_830_COUNT)) rb_fail++;
    for (u32 i = 0; i < OG_COL1_DRV_COUNT; i++) {
        if (!g_touched_col1_drv[i]) continue;
        const struct og_col1_drv *d = &OG_COL1_DRVS[i];
        const u8 *old_b = is_pal ? d->pal_old : d->ntsc_old;
        if (!cp_dma_write_sparse(d->cp_va, CP_DRVPARAM_LEN, OG_DRV_COL1_OFFS, old_b, OG_DRV_COL1_DIFFS)) rb_fail++;
    }
    for (u32 i = 0; i < OG_ISP_REC_COUNT; i++) {
        if (!g_touched_isp[i]) continue;
        const struct og_isp_rec *r = &OG_ISP_RECS[i];
        if (!cp_dma_write_sparse(r->cp_va, 3000U, r->offs, r->stock, r->count)) rb_fail++;
    }
    for (u32 i = 0; i < OG_LCDFILL_CELL_COUNT; i++) {
        if (!g_touched_lcdfill[i]) continue;
        const struct og_cp_cell8 *c = &OG_LCDFILL_CELLS[i];
        if (!cp_dma_write_contig(c->cp_va, c->stock, c->len)) rb_fail++;
    }
    for (u32 i = 0; i < OG_CP50_CELL_COUNT; i++) {
        if (!g_touched_cells50[i]) continue;
        const struct og_cp_cell *c = &OG_CP50_CELLS[i];
        if (!cp_dma_write_contig(c->cp_va, c->stock, c->len)) rb_fail++;
    }
    for (u32 i = 0; i < OG_CP_CELL_COUNT; i++) {
        if (!g_touched_cells[i]) continue;
        const struct og_cp_cell *c = &OG_CP_CELLS[i];
        if (!cp_dma_write_contig(c->cp_va, c->stock, c->len)) rb_fail++;
    }
    for (u32 i = 0; i < OG_DMM_SITE_COUNT; i++) {
        if (!g_touched_dmm[i] || !g_dmm_base) continue;
        const struct og_dmm_site *d = &OG_DMM_SITES[i];
        if (!cp_dma_write_contig(g_dmm_base + d->off, d->stock, 4U)) rb_fail++;
    }
    out_s("ROLLBACK_FAILURES="); out_u64(rb_fail); out_s("\n");
}

__attribute__((visibility("default"))) void _init(void) {
    g_olen = 0;
    out_s("A6700_OG_RAM_V6_2_1 " OG_RAM_LABEL "\n");

    /* ==== PASS 0: Kernel cmdline, CTR_EL0 PIPT/VIPT, library SHA-256 & guards === */
    u64 ctr = read_ctr_el0();
    u32 l1ip = (u32)(ctr >> 14) & 3U;
    out_s("CTR_EL0="); out_hex(ctr); out_s(" L1Ip="); out_u64(l1ip); out_s("\n");
    if (l1ip < 2U) {
        out_s("RESULT=ABORT_IDENTITY reason=icache_not_vipt_pipt writes=0\n");
        flush_result();
        return;
    }

    read_text_file("/proc/cmdline", g_cmdline, sizeof(g_cmdline));
    g_maps_len = read_text_file("/proc/self/maps", g_maps, sizeof(g_maps));
    if (!cmdline_has(OG_AVCAM_RESERVE)) {
        out_s("RESULT=ABORT_IDENTITY reason=cmdline_missing_" OG_AVCAM_RESERVE " writes=0\n");
        flush_result();
        return;
    }

    int sencore_ok = 0;
    for (u32 i = 0; i < OG_ID_FILE_COUNT; i++) {
        const struct og_id_file *f = &OG_ID_FILES[i];
        char path[200]; path[0] = 0;
        u64 base = find_mapped_slice(f->suffix, 0, 4096, 5u, 0, path, sizeof(path));
        u64 fsz = 0; u8 dig[32];
        if (!path[0] || !base || !hash_disk_file(path, &fsz, dig) ||
            fsz != f->size || !mem_eq(dig, f->sha256, 32)) {
            out_s("RESULT=ABORT_IDENTITY reason=lib_sha_mismatch lib=");
            out_s(f->suffix); out_s(" writes=0\n");
            flush_result();
            return;
        }
        if (i == 0U) {
            u64 a_alloc = find_mapped_slice(f->suffix, SENCORE_DMM_ALLOC_OFF, 8, 5u, 0, 0, 0);
            u64 a_free  = find_mapped_slice(f->suffix, SENCORE_DMM_FREE_OFF,  8, 5u, 0, 0, 0);
            u64 a_dma   = find_mapped_slice(f->suffix, SENCORE_DMA_XFER_OFF,  8, 5u, 0, 0, 0);
            if (a_alloc && a_free && a_dma &&
                mem_eq((const u8 *)a_alloc, SENCORE_PROL_ALLOC, 8) &&
                mem_eq((const u8 *)a_free,  SENCORE_PROL_FREE,  8) &&
                mem_eq((const u8 *)a_dma,   SENCORE_PROL_DMA,   8)) {
                g_dmm_alloc = (fn_dmm_alloc_t)a_alloc;
                g_dmm_free  = (fn_dmm_free_t)a_free;
                g_sen_dma   = (fn_sen_dma_t)a_dma;
                sencore_ok = 1;
            }
        }
    }
    if (!sencore_ok) {
        out_s("RESULT=ABORT_IDENTITY reason=sencore_prologue_mismatch writes=0\n");
        flush_result();
        return;
    }

    u32 dmm_handle = 0;
    g_cp_phys = g_dmm_alloc(CP_PAGE, &dmm_handle);
    if (!g_cp_phys || (g_cp_phys & 0x3FULL) != 0ULL || g_cp_phys < RAM_LO || (g_cp_phys + CP_PAGE) > RAM_HI) {
        if (dmm_handle) g_dmm_free(dmm_handle);
        out_s("RESULT=ABORT_IDENTITY reason=dmm_alloc_failed writes=0\n");
        flush_result();
        return;
    }

    i64 cp_mem_fd = sys_open("/dev/mem", O_RDWR_SYNC, 0);
    if (cp_mem_fd < 0) {
        g_dmm_free(dmm_handle);
        out_s("RESULT=ABORT_IDENTITY reason=cp_devmem_open_failed writes=0\n");
        flush_result();
        return;
    }

    u64 cp_lead = g_cp_phys & 0xFFFULL;
    u64 cp_maplen = (cp_lead + CP_PAGE + 0xFFFULL) & ~0xFFFULL;
    i64 cp_map = sys_mmap_rw(cp_mem_fd, cp_maplen, g_cp_phys - cp_lead);
    if (cp_map == -1) {
        sys_close(cp_mem_fd);
        g_dmm_free(dmm_handle);
        out_s("RESULT=ABORT_IDENTITY reason=dmm_mmap_failed writes=0\n");
        flush_result();
        return;
    }
    g_cp_buf = (u8 *)cp_map + cp_lead;

    i64 av_mem_fd = sys_open("/dev/mem", O_RDWR, 0);
    if (av_mem_fd < 0) {
        sys_munmap((void *)cp_map, cp_maplen);
        sys_close(cp_mem_fd);
        g_dmm_free(dmm_handle);
        out_s("RESULT=ABORT_IDENTITY reason=av_devmem_open_failed writes=0\n");
        flush_result();
        return;
    }

    i64 av_map_raw = sys_mmap_rw(av_mem_fd, OG_AVCAM_PATCH_MAP_HI, OG_AVCAM_PHYS);
    if (av_map_raw == -1) {
        sys_close(av_mem_fd);
        sys_munmap((void *)cp_map, cp_maplen);
        sys_close(cp_mem_fd);
        g_dmm_free(dmm_handle);
        out_s("RESULT=ABORT_IDENTITY reason=avcam_mmap_failed writes=0\n");
        flush_result();
        return;
    }
    u8 *av_map = (u8 *)av_map_raw;

    if (!pb_map_all(av_mem_fd)) {
        out_s("RESULT=ABORT_IDENTITY reason=pb_vipt_mmap_failed writes=0\n");
        goto cleanup;
    }

    /* Verify 3 pure-code cpapp-b.bin 4 KB pages & 3 av-cam.bin static .rodata guards */
    for (u32 i = 0; i < 3U; i++) {
        const struct og_id_page *pg = &OG_ID_PAGES[i];
        u8 *p = cp_dma_read_span(pg->cp_va, CP_PAGE, 0, 0);
        u8 dig[32];
        if (!p || (sha_buf(p, CP_PAGE, dig), !mem_eq(dig, pg->sha256, 32))) {
            out_s("RESULT=ABORT_IDENTITY reason=cp_page_mismatch page=");
            out_s(pg->name); out_s(" writes=0\n");
            goto cleanup;
        }
    }
    for (u32 i = 0; i < OG_AVCAM_GUARD_COUNT; i++) {
        const struct og_av_guard *g = &OG_AVCAM_GUARDS[i];
        u8 dig[32];
        sha_buf(av_map + g->file_off, g->len, dig);
        if (!mem_eq(dig, g->sha256, 32)) {
            out_s("RESULT=ABORT_IDENTITY reason=avcam_guard_mismatch guard=");
            out_s(g->name); out_s(" writes=0\n");
            goto cleanup;
        }
    }
    /* Verify ALL 3 playback code pages in BOTH mapped view AND kernel pread64 view + 56-byte PB data guard */
    for (u32 p = 0; p < OG_PB_CODE_PAGE_COUNT; p++) {
        if (!pb_verify_masked_page(p, g_pb_code[p].page_va)) {
            out_s("RESULT=ABORT_IDENTITY reason=pb_codepage_sha_mismatch page=");
            out_s(OG_PB_CODE_PAGES[p].name); out_s(" writes=0\n");
            goto cleanup;
        }
        u64 phys = OG_AVCAM_PHYS + OG_PB_CODE_PAGES[p].page_off;
        if (sys_pread64(av_mem_fd, g_iobuf, 4096ULL, phys) != 4096 ||
            !pb_verify_masked_page(p, g_iobuf)) {
            out_s("RESULT=ABORT_IDENTITY reason=pb_codepage_kview_mismatch page=");
            out_s(OG_PB_CODE_PAGES[p].name); out_s(" writes=0\n");
            goto cleanup;
        }
    }
    if (!mem_eq(g_pb_data_va + (OG_PB_DATA_GUARD_OFF - OG_PB_DATA_PAGE_OFF), OG_PB_DATA_GUARD, OG_PB_DATA_GUARD_LEN)) {
        out_s("RESULT=ABORT_IDENTITY reason=pb_data_guard_mismatch writes=0\n");
        goto cleanup;
    }
    pb_sync_all_code_icache();
    out_s("PASS0_IDENTITY=OK\n");

    /* ==== Auto-detect PAL (50 Hz) vs NTSC (60 Hz) from CSDrvParam[0x0820] +0x2c ==== */
    int is_pal = -1;
    {
        u8 *p820 = cp_dma_read_span(CP_DRVPARAM_820, CP_DRVPARAM_LEN, 0, 0);
        if (p820) {
            u32 vtot = rd_u32(p820 + 0x2CU);
            if (vtot == OG_VTOT_820_PAL)       is_pal = 1;
            else if (vtot == OG_VTOT_820_NTSC) is_pal = 0;
        }
    }
    if (is_pal < 0) {
        out_s("RESULT=ABORT_MISMATCH reason=unknown_video_system writes=0\n");
        goto cleanup;
    }
    out_s(is_pal ? "SYSTEM=PAL_50HZ\n" : "SYSTEM=NTSC_60HZ\n");

    /* ==== PASS 1: 100% Dry Preimage Check Across All Sites (0 writes!) ======= */
    u32 pre_errs = 0;
    u32 to_apply = 0;

    g_dmm_base = locate_dmmcfg_base();
    if (!g_dmm_base) {
        out_s("PRE_FAIL dmmcfg_not_found\n");
        pre_errs++;
    } else {
        out_s("DMMCFG_BASE="); out_hex(g_dmm_base); out_s("\n");
        int dmm_is_stock = 0;
        for (u32 i = 0; i < OG_DMM_SITE_COUNT; i++) {
            const struct og_dmm_site *d = &OG_DMM_SITES[i];
            u8 *p = cp_dma_read_span(g_dmm_base + d->off, 4U, 0, 0);
            if (!p) { pre_errs++; continue; }
            if (mem_eq(p, d->stock, 4U)) { to_apply++; dmm_is_stock = 1; }
            else if (!mem_eq(p, d->target, 4U)) {
                out_s("PRE_FAIL dmm="); out_s(d->name); out_s(" va="); out_hex(g_dmm_base + d->off); out_s("\n");
                pre_errs++;
            }
        }
        if (dmm_is_stock) {
            u8 *p_eh = cp_dma_read_span(0x019D7BCCU, 4U, 0, 0);
            if (p_eh) {
                u32 ext_hash = rd_u32(p_eh);
                if (ext_hash >= OG_CP_LO && (ext_hash + 0x57fU * 8U + 8U) <= OG_CP_HI) {
                    u8 *p_h57f = cp_dma_read_span(ext_hash + 0x57fU * 8U, 4U, 0, 0);
                    if (p_h57f && rd_u32(p_h57f) != 0U) {
                        out_s("PRE_FAIL dmm_57f_already_divided (cold-boot on STILLS required)\n");
                        pre_errs++;
                    }
                }
            }
        }
    }

    for (u32 i = 0; i < OG_CP_CELL_COUNT; i++) {
        const struct og_cp_cell *c = &OG_CP_CELLS[i];
        u8 *p = cp_dma_read_span(c->cp_va, c->len, 0, 0);
        if (!p) { pre_errs++; continue; }
        if (mem_eq(p, c->stock, c->len)) to_apply++;
        else if (!mem_eq(p, c->target, c->len)) {
            out_s("PRE_FAIL cell="); out_s(c->name); out_s(" va="); out_hex(c->cp_va); out_s("\n");
            pre_errs++;
        }
    }
    if (is_pal) {
        for (u32 i = 0; i < OG_CP50_CELL_COUNT; i++) {
            const struct og_cp_cell *c = &OG_CP50_CELLS[i];
            u8 *p = cp_dma_read_span(c->cp_va, c->len, 0, 0);
            if (!p) { pre_errs++; continue; }
            if (mem_eq(p, c->stock, c->len)) to_apply++;
            else if (!mem_eq(p, c->target, c->len)) {
                out_s("PRE_FAIL cell50="); out_s(c->name); out_s(" va="); out_hex(c->cp_va); out_s("\n");
                pre_errs++;
            }
        }
    }
    for (u32 i = 0; i < OG_LCDFILL_CELL_COUNT; i++) {
        const struct og_cp_cell8 *c = &OG_LCDFILL_CELLS[i];
        u8 *p = cp_dma_read_span(c->cp_va, c->len, 0, 0);
        if (!p) { pre_errs++; continue; }
        if (mem_eq(p, c->stock, c->len)) to_apply++;
        else if (!mem_eq(p, c->target, c->len)) {
            out_s("PRE_FAIL lcdfill="); out_s(c->name); out_s(" va="); out_hex(c->cp_va); out_s("\n");
            pre_errs++;
        }
    }
    for (u32 i = 0; i < OG_ISP_REC_COUNT; i++) {
        const struct og_isp_rec *r = &OG_ISP_RECS[i];
        if (r->pal_only && !is_pal) continue;
        u8 *p = cp_dma_read_span(r->cp_va, 3000U, 0, 0);
        u8 dig[32];
        if (!p) { pre_errs++; continue; }
        sha_buf(p, 3000ULL, dig);
        if (mem_eq(dig, r->stock_sha, 32U)) to_apply++;
        else if (!mem_eq(dig, r->target_sha, 32U)) {
            out_s("PRE_FAIL isp_rec="); out_s(r->name); out_s("\n");
            pre_errs++;
        }
    }
    for (u32 i = 0; i < OG_COL1_DRV_COUNT; i++) {
        const struct og_col1_drv *d = &OG_COL1_DRVS[i];
        u8 *p = cp_dma_read_span(d->cp_va, CP_DRVPARAM_LEN, 0, 0);
        u32 want_vtot = is_pal ? d->pal_vtot : d->ntsc_vtot;
        const u8 *old_b = is_pal ? d->pal_old : d->ntsc_old;
        const u8 *new_b = is_pal ? d->pal_new : d->ntsc_new;
        if (!p || rd_u32(p + 0x2CU) != want_vtot) {
            out_s("PRE_FAIL csdrvparam_vtot="); out_s(d->name); out_s("\n"); pre_errs++;
        } else if (cp_check_sparse(p, OG_DRV_COL1_OFFS, old_b, OG_DRV_COL1_DIFFS)) {
            to_apply++;
        } else if (!cp_check_sparse(p, OG_DRV_COL1_OFFS, new_b, OG_DRV_COL1_DIFFS)) {
            out_s("PRE_FAIL csdrvparam="); out_s(d->name); out_s("\n"); pre_errs++;
        }
    }
    if (is_pal) {
        u8 *p5 = cp_dma_read_span(CP_DRVPARAM_830, CP_DRVPARAM_LEN, 0, 0);
        if (!p5 || rd_u32(p5 + 0x2CU) != OG_VTOT_830_PAL) {
            out_s("PRE_FAIL csdrvparam_0x830_vtot\n"); pre_errs++;
        } else if (cp_check_sparse(p5, OG_DRV_830_OFFS, OG_DRV_830_OLD, OG_DRV_830_COUNT)) {
            to_apply++;
        } else if (!cp_check_sparse(p5, OG_DRV_830_OFFS, OG_DRV_830_NEW, OG_DRV_830_COUNT)) {
            out_s("PRE_FAIL csdrvparam_0x830\n"); pre_errs++;
        }
    }
    {
        u8 *pS = cp_dma_read_span(OG_SIZETBL_GUARD0_VA, 16U, 0, 0);
        if (!pS || !mem_eq(pS, OG_SIZETBL_GUARD0, 8U) || !mem_eq(pS + 12U, OG_SIZETBL_GUARD1, 4U)) {
            out_s("PRE_FAIL sizetbl_guards_uninitialized (cold-boot on STILLS required)\n");
            pre_errs++;
        } else if (mem_eq(pS + 8U, OG_SIZETBL_OLD, 4U)) {
            to_apply++;
        } else if (!mem_eq(pS + 8U, OG_SIZETBL_NEW, 4U)) {
            out_s("PRE_FAIL sizetbl_0x0199ecc4\n"); pre_errs++;
        }
    }
    for (u32 i = 0; i < OG_LIBMPR_SITE_COUNT; i++) {
        const struct og_mp_site *s = &OG_LIBMPR_SITES[i];
        u64 va = find_mapped_slice("/libmpr.so", s->file_off, s->len, 1u, 0, 0, 0);
        if (!va) { pre_errs++; continue; }
        if (mem_eq((const u8 *)va, s->stock, s->len)) to_apply++;
        else if (!mem_eq((const u8 *)va, s->target, s->len)) {
            out_s("PRE_FAIL libmpr="); out_s(s->name); out_s("\n"); pre_errs++;
        }
    }
    for (u32 i = 0; i < OG_AVCAM_BLOB_COUNT; i++) {
        const struct og_av_patch *p = &OG_AVCAM_BLOBS[i];
        const u8 *cur = av_map + p->file_off;
        if (mem_eq(cur, p->stock, p->len)) to_apply++;
        else if (!mem_eq(cur, p->target, p->len)) {
            out_s("PRE_FAIL avcam_blob_off="); out_hex(p->file_off); out_s("\n"); pre_errs++;
        }
    }
    for (u32 i = 0; i < OG_AVCAM_HPATCH_COUNT; i++) {
        u32 pk = OG_AVCAM_HPACKED[i];
        u32 off = pk & 0x7FFFFFFFU;
        u8 len = (pk & 0x80000000U) ? 4U : 2U;
        const u8 *cur = av_map + off;
        if (mem_eq(cur, OG_H2160_BYTES, len)) to_apply++;
        else if (!mem_eq(cur, OG_H2560_BYTES, len)) {
            out_s("PRE_FAIL avcam_h_off="); out_hex(off); out_s("\n"); pre_errs++;
        }
    }
    for (u32 i = 0; i < OG_PB_CODE_SITE_COUNT; i++) {
        const struct og_pb_code_site *s = &OG_PB_CODE_SITES[i];
        const u8 *cur = g_pb_code[s->page_idx].page_va + (s->file_off - OG_PB_CODE_PAGES[s->page_idx].page_off);
        if (mem_eq(cur, s->stock, 4U)) to_apply++;
        else if (!mem_eq(cur, s->target, 4U)) {
            out_s("PRE_FAIL pb_code_off="); out_hex(s->file_off); out_s("\n"); pre_errs++;
        }
    }
    {
        const u8 *cur = g_pb_data_va + (OG_PB_DATA_SITE_OFF - OG_PB_DATA_PAGE_OFF);
        if (mem_eq(cur, OG_PB_DATA_OLD, 4U)) to_apply++;
        else if (!mem_eq(cur, OG_PB_DATA_NEW, 4U)) {
            out_s("PRE_FAIL pb_data_0xc00350\n"); pre_errs++;
        }
    }

    u32 total_sites = OG_DMM_SITE_COUNT + OG_CP_CELL_COUNT
                    + (is_pal ? OG_CP50_CELL_COUNT : 0U)
                    + OG_LCDFILL_CELL_COUNT
                    + (is_pal ? OG_ISP_REC_COUNT : 2U)
                    + OG_COL1_DRV_COUNT + (is_pal ? 1U : 0U) + 1U /* sizetbl */
                    + OG_LIBMPR_SITE_COUNT + OG_AVCAM_BLOB_COUNT + OG_AVCAM_HPATCH_COUNT
                    + OG_PB_CODE_SITE_COUNT + 1U /* pb_data */;

    if (pre_errs != 0U) {
        out_s("RESULT=ABORT_MISMATCH pre_errors="); out_u64(pre_errs); out_s(" writes=0\n");
        goto cleanup;
    }
    if (to_apply == 0U) {
        out_s("RESULT=NOTHING_TO_DO sites="); out_u64(total_sites); out_s(" writes=0\n");
        goto cleanup;
    }
    out_s("PASS1_PREIMAGE=OK sites_to_write="); out_u64(to_apply); out_s("\n");

    /* ==== PASS 2: Atomic Apply + Immediate Readback + Auto-Rollback ========= */
    for (u32 i = 0; i < OG_DMM_SITE_COUNT; i++) g_touched_dmm[i] = 0;
    for (u32 i = 0; i < OG_CP_CELL_COUNT; i++) g_touched_cells[i] = 0;
    for (u32 i = 0; i < OG_CP50_CELL_COUNT; i++) g_touched_cells50[i] = 0;
    for (u32 i = 0; i < OG_LCDFILL_CELL_COUNT; i++) g_touched_lcdfill[i] = 0;
    for (u32 i = 0; i < OG_ISP_REC_COUNT; i++) g_touched_isp[i] = 0;
    for (u32 i = 0; i < OG_COL1_DRV_COUNT; i++) g_touched_col1_drv[i] = 0;
    g_touched_drv_830 = 0;
    g_touched_sizetbl = 0;
    for (u32 i = 0; i < OG_LIBMPR_SITE_COUNT; i++) g_touched_lm[i] = 0;
    for (u32 i = 0; i < OG_AVCAM_BLOB_COUNT; i++) g_touched_av_blob[i] = 0;
    for (u32 i = 0; i < OG_AVCAM_HPATCH_COUNT; i++) g_touched_av_h[i] = 0;
    for (u32 i = 0; i < OG_PB_CODE_SITE_COUNT; i++) g_touched_pb_code[i] = 0;
    g_touched_pb_data = 0;

    int apply_err = 0;

    /* 2.0 Step 4 DmmCfg 0x57f = 0x016D5A00 FIRST */
    for (u32 i = 0; i < OG_DMM_SITE_COUNT && !apply_err; i++) {
        const struct og_dmm_site *d = &OG_DMM_SITES[i];
        u8 *p = cp_dma_read_span(g_dmm_base + d->off, 4U, 0, 0);
        if (p && mem_eq(p, d->target, 4U)) continue;
        g_touched_dmm[i] = 1;
        if (!cp_dma_write_contig(g_dmm_base + d->off, d->target, 4U)) apply_err = 1;
    }
    /* 2.1 Step 1 Col-1 (ALL 5 modes) + PAL 50p CP sensor/table cells */
    for (u32 i = 0; i < OG_CP_CELL_COUNT && !apply_err; i++) {
        const struct og_cp_cell *c = &OG_CP_CELLS[i];
        u8 *p = cp_dma_read_span(c->cp_va, c->len, 0, 0);
        if (p && mem_eq(p, c->target, c->len)) continue;
        g_touched_cells[i] = 1;
        if (!cp_dma_write_contig(c->cp_va, c->target, c->len)) apply_err = 1;
    }
    if (is_pal) {
        for (u32 i = 0; i < OG_CP50_CELL_COUNT && !apply_err; i++) {
            const struct og_cp_cell *c = &OG_CP50_CELLS[i];
            u8 *p = cp_dma_read_span(c->cp_va, c->len, 0, 0);
            if (p && mem_eq(p, c->target, c->len)) continue;
            g_touched_cells50[i] = 1;
            if (!cp_dma_write_contig(c->cp_va, c->target, c->len)) apply_err = 1;
        }
    }
    /* 2.2 Step 5 LCD 3:2 Fill */
    for (u32 i = 0; i < OG_LCDFILL_CELL_COUNT && !apply_err; i++) {
        const struct og_cp_cell8 *c = &OG_LCDFILL_CELLS[i];
        u8 *p = cp_dma_read_span(c->cp_va, c->len, 0, 0);
        if (p && mem_eq(p, c->target, c->len)) continue;
        g_touched_lcdfill[i] = 1;
        if (!cp_dma_write_contig(c->cp_va, c->target, c->len)) apply_err = 1;
    }
    /* 2.3 ISP records (Col-1 L/R + PAL 50p L/R) */
    for (u32 i = 0; i < OG_ISP_REC_COUNT && !apply_err; i++) {
        const struct og_isp_rec *r = &OG_ISP_RECS[i];
        if (r->pal_only && !is_pal) continue;
        u8 *p = cp_dma_read_span(r->cp_va, 3000U, 0, 0);
        u8 dig[32];
        if (p && (sha_buf(p, 3000ULL, dig), mem_eq(dig, r->target_sha, 32U))) continue;
        g_touched_isp[i] = 1;
        if (!cp_dma_write_sparse(r->cp_va, 3000U, r->offs, r->target, r->count)) apply_err = 1;
    }
    /* 2.4 ALL 5 Col-1 CSDrvParams + PAL 50p 0x0830 CSDrvParam */
    for (u32 i = 0; i < OG_COL1_DRV_COUNT && !apply_err; i++) {
        const struct og_col1_drv *d = &OG_COL1_DRVS[i];
        const u8 *new_b = is_pal ? d->pal_new : d->ntsc_new;
        u8 *p = cp_dma_read_span(d->cp_va, CP_DRVPARAM_LEN, 0, 0);
        if (!p || !cp_check_sparse(p, OG_DRV_COL1_OFFS, new_b, OG_DRV_COL1_DIFFS)) {
            g_touched_col1_drv[i] = 1;
            if (!cp_dma_write_sparse(d->cp_va, CP_DRVPARAM_LEN, OG_DRV_COL1_OFFS, new_b, OG_DRV_COL1_DIFFS)) apply_err = 1;
        }
    }
    if (is_pal && !apply_err) {
        u8 *p5 = cp_dma_read_span(CP_DRVPARAM_830, CP_DRVPARAM_LEN, 0, 0);
        if (!p5 || !cp_check_sparse(p5, OG_DRV_830_OFFS, OG_DRV_830_NEW, OG_DRV_830_COUNT)) {
            g_touched_drv_830 = 1;
            if (!cp_dma_write_sparse(CP_DRVPARAM_830, CP_DRVPARAM_LEN, OG_DRV_830_OFFS, OG_DRV_830_NEW, OG_DRV_830_COUNT)) apply_err = 1;
        }
    }
    /* 2.5 Step 2 CP Movie Size Table */
    if (!apply_err) {
        u8 *pS = cp_dma_read_span(OG_SIZETBL_SITE_VA, 4U, 0, 0);
        if (!pS || !mem_eq(pS, OG_SIZETBL_NEW, 4U)) {
            g_touched_sizetbl = 1;
            if (!cp_dma_write_contig(OG_SIZETBL_SITE_VA, OG_SIZETBL_NEW, 4U)) apply_err = 1;
        }
    }
    /* 2.6 Step 3 libmpr.so (exact 8 verified M19 sites) */
    for (u32 i = 0; i < OG_LIBMPR_SITE_COUNT && !apply_err; i++) {
        const struct og_mp_site *s = &OG_LIBMPR_SITES[i];
        u64 va = find_mapped_slice("/libmpr.so", s->file_off, s->len, 1u, 0, 0, 0);
        if (va && mem_eq((const u8 *)va, s->target, s->len)) continue;
        g_touched_lm[i] = 1;
        if (!cow_write_libmpr(s->file_off, s->target, s->len)) apply_err = 1;
    }
    /* 2.7 Step 3 M19 av-cam.bin tables (127 blobs + 348 heights; dc civac + kview!) */
    for (u32 i = 0; i < OG_AVCAM_BLOB_COUNT && !apply_err; i++) {
        const struct og_av_patch *p = &OG_AVCAM_BLOBS[i];
        u8 *dst = av_map + p->file_off;
        if (mem_eq(dst, p->target, p->len)) continue;
        g_touched_av_blob[i] = 1;
        for (u8 k = 0; k < p->len; k++) dst[k] = p->target[k];
        clean_dcache_range((u64)dst, p->len);
        if (!mem_eq(dst, p->target, p->len)) apply_err = 1;
    }
    for (u32 i = 0; i < OG_AVCAM_HPATCH_COUNT && !apply_err; i++) {
        u32 pk = OG_AVCAM_HPACKED[i];
        u32 off = pk & 0x7FFFFFFFU;
        u8 len = (pk & 0x80000000U) ? 4U : 2U;
        u8 *dst = av_map + off;
        if (mem_eq(dst, OG_H2560_BYTES, len)) continue;
        g_touched_av_h[i] = 1;
        for (u8 k = 0; k < len; k++) dst[k] = OG_H2560_BYTES[k];
        clean_dcache_range((u64)dst, len);
        if (!mem_eq(dst, OG_H2560_BYTES, len)) apply_err = 1;
    }
    /* 2.8 Step 6 In-Camera 3:2 Playback Fix: CODE FIRST + VIPT I-cache flush -> DATA LAST! */
    if (!apply_err) {
        int wrote_pb_code = 0;
        for (u32 i = 0; i < OG_PB_CODE_SITE_COUNT && !apply_err; i++) {
            const struct og_pb_code_site *s = &OG_PB_CODE_SITES[i];
            u8 *p = g_pb_code[s->page_idx].page_va + (s->file_off - OG_PB_CODE_PAGES[s->page_idx].page_off);
            if (mem_eq(p, s->target, 4U)) continue;
            g_touched_pb_code[i] = 1;
            __atomic_store_n((volatile u32 *)p, rd_u32(s->target), __ATOMIC_RELEASE);
            wrote_pb_code = 1;
            if (!mem_eq(p, s->target, 4U)) apply_err = 1;
        }
        if (wrote_pb_code) pb_sync_all_code_icache();
    }
    if (!apply_err) {
        u8 *p = g_pb_data_va + (OG_PB_DATA_SITE_OFF - OG_PB_DATA_PAGE_OFF);
        if (!mem_eq(p, OG_PB_DATA_NEW, 4U)) {
            g_touched_pb_data = 1;
            __atomic_store_n((volatile u32 *)p, rd_u32(OG_PB_DATA_NEW), __ATOMIC_RELEASE);
            clean_dcache_range((u64)p, 4ULL);
            if (!mem_eq(p, OG_PB_DATA_NEW, 4U)) apply_err = 1;
        }
    }

    if (apply_err) {
        rollback_all(av_map, is_pal);
        out_s("RESULT=ABORT_ROLLED_BACK\n");
        goto cleanup;
    }

    /* ==== PASS 3: Full End-to-End Readback Verification (incl. pread64 kview!) ==== */
    u32 rb_errs = 0;
    for (u32 i = 0; i < OG_DMM_SITE_COUNT; i++) {
        const struct og_dmm_site *d = &OG_DMM_SITES[i];
        u8 *p = cp_dma_read_span(g_dmm_base + d->off, 4U, 0, 0);
        if (!p || !mem_eq(p, d->target, 4U)) rb_errs++;
    }
    for (u32 i = 0; i < OG_CP_CELL_COUNT; i++) {
        const struct og_cp_cell *c = &OG_CP_CELLS[i];
        u8 *p = cp_dma_read_span(c->cp_va, c->len, 0, 0);
        if (!p || !mem_eq(p, c->target, c->len)) rb_errs++;
    }
    if (is_pal) {
        for (u32 i = 0; i < OG_CP50_CELL_COUNT; i++) {
            const struct og_cp_cell *c = &OG_CP50_CELLS[i];
            u8 *p = cp_dma_read_span(c->cp_va, c->len, 0, 0);
            if (!p || !mem_eq(p, c->target, c->len)) rb_errs++;
        }
    }
    for (u32 i = 0; i < OG_LCDFILL_CELL_COUNT; i++) {
        const struct og_cp_cell8 *c = &OG_LCDFILL_CELLS[i];
        u8 *p = cp_dma_read_span(c->cp_va, c->len, 0, 0);
        if (!p || !mem_eq(p, c->target, c->len)) rb_errs++;
    }
    for (u32 i = 0; i < OG_ISP_REC_COUNT; i++) {
        const struct og_isp_rec *r = &OG_ISP_RECS[i];
        if (r->pal_only && !is_pal) continue;
        u8 *p = cp_dma_read_span(r->cp_va, 3000U, 0, 0);
        u8 dig[32];
        if (!p || (sha_buf(p, 3000ULL, dig), !mem_eq(dig, r->target_sha, 32U))) rb_errs++;
    }
    for (u32 i = 0; i < OG_COL1_DRV_COUNT; i++) {
        const struct og_col1_drv *d = &OG_COL1_DRVS[i];
        const u8 *new_b = is_pal ? d->pal_new : d->ntsc_new;
        u8 *p = cp_dma_read_span(d->cp_va, CP_DRVPARAM_LEN, 0, 0);
        if (!p || !cp_check_sparse(p, OG_DRV_COL1_OFFS, new_b, OG_DRV_COL1_DIFFS)) rb_errs++;
    }
    if (is_pal) {
        u8 *p5 = cp_dma_read_span(CP_DRVPARAM_830, CP_DRVPARAM_LEN, 0, 0);
        if (!p5 || !cp_check_sparse(p5, OG_DRV_830_OFFS, OG_DRV_830_NEW, OG_DRV_830_COUNT)) rb_errs++;
    }
    {
        u8 *pS = cp_dma_read_span(OG_SIZETBL_SITE_VA, 4U, 0, 0);
        if (!pS || !mem_eq(pS, OG_SIZETBL_NEW, 4U)) rb_errs++;
    }
    for (u32 i = 0; i < OG_LIBMPR_SITE_COUNT; i++) {
        const struct og_mp_site *s = &OG_LIBMPR_SITES[i];
        u64 va = find_mapped_slice("/libmpr.so", s->file_off, s->len, 1u, 0, 0, 0);
        if (!va || !mem_eq((const u8 *)va, s->target, s->len)) rb_errs++;
    }
    for (u32 i = 0; i < OG_AVCAM_BLOB_COUNT; i++) {
        const struct og_av_patch *p = &OG_AVCAM_BLOBS[i];
        if (!mem_eq(av_map + p->file_off, p->target, p->len) ||
            !av_kview_eq(av_mem_fd, p->file_off, p->target, p->len)) rb_errs++;
    }
    for (u32 i = 0; i < OG_AVCAM_HPATCH_COUNT; i++) {
        u32 pk = OG_AVCAM_HPACKED[i];
        u32 off = pk & 0x7FFFFFFFU;
        u8 len = (pk & 0x80000000U) ? 4U : 2U;
        if (!mem_eq(av_map + off, OG_H2560_BYTES, len) ||
            !av_kview_eq(av_mem_fd, off, OG_H2560_BYTES, len)) rb_errs++;
    }
    for (u32 i = 0; i < OG_PB_CODE_SITE_COUNT; i++) {
        const struct og_pb_code_site *s = &OG_PB_CODE_SITES[i];
        const u8 *cur = g_pb_code[s->page_idx].page_va + (s->file_off - OG_PB_CODE_PAGES[s->page_idx].page_off);
        if (!mem_eq(cur, s->target, 4U) ||
            !av_kview_eq(av_mem_fd, s->file_off, s->target, 4U)) rb_errs++;
    }
    if (!mem_eq(g_pb_data_va + (OG_PB_DATA_SITE_OFF - OG_PB_DATA_PAGE_OFF), OG_PB_DATA_NEW, 4U) ||
        !av_kview_eq(av_mem_fd, OG_PB_DATA_SITE_OFF, OG_PB_DATA_NEW, 4U)) rb_errs++;

    if (rb_errs != 0U) {
        rollback_all(av_map, is_pal);
        out_s("RESULT=ABORT_VERIFY_FAIL rb_errors="); out_u64(rb_errs); out_s("\n");
        goto cleanup;
    }

    out_s("PASS3_READBACK=OK kview=OK sites="); out_u64(total_sites); out_s("\n");
    out_s("RESULT=APPLY_OK design=v6_2_1_ogsq5m_50p_m19_pb32_lcdfill raster=3840x2560\n");

cleanup:
    pb_unmap_all();
    sys_munmap((void *)av_map_raw, OG_AVCAM_PATCH_MAP_HI);
    sys_close(av_mem_fd);
    sys_munmap((void *)cp_map, cp_maplen);
    sys_close(cp_mem_fd);
    g_dmm_free(dmm_handle);
    flush_result();
}
