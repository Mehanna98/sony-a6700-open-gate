/* a6700_og_ram.c -- All-or-nothing compare-and-swap + automatic-rollback RAM-only Open Gate v4 patcher.
 *
 * Target: Sony ILCE-6700 (a6700) FW v2.00 ONLY (stock SHA-256 locked).
 * Scope : Complete Universal 4K 3:2 Open Gate v4 (3840x2560 @ PAL 25p [0x0880] + NTSC 23.98p [0x08c0]):
 *   - Step 4 (CP RAM, applied FIRST): Dynamic 7-anchor-verified DmmCfg.bin key 0x57f raw write buffer
 *                    (20,189,696 -> 24,785,920 B = 4120x6016 across all 4 size words in Grp 0x8a + 0x8e;
 *                    3 * 24,785,920 = 74,357,760 B <= 74,448,896 B [71.00 MiB 0x6fa, +89 KiB spare], preserving
 *                    ALL 7 of 7 key-0x57f buffers required by cpapp-b.bin @ 0x4aea66; requires cold boot on STILLS!)
 *   - Step 1 (CP RAM): 25 sensor/table cells (7 IMX684 col-1 [r2=0x05 stock] + 9 NTSC 0x08c0 + 9 PAL 0x0880,
 *                    H_act=4112, v_off=8, S3=2086 < PAL 50Hz VMAX 2115, S10=84, S9=49, S8=73)
 *                    + 2 full 3000-B Left (0x0d3885c) & Right (0x0d39414) ISP records (shared 0x0880/0x08c0)
 *                    + 30 sparse bytes of stored CSDrvParam[0x08c0] @ 0x025db46c (+0x6/+0x7 = 27/32)
 *                    + 30 sparse bytes of stored CSDrvParam[0x0880] @ 0x025db18c (+0x6/+0x7 = 27/32)
 *   - Step 2 (CP RAM): Movie size table Class 3 @ 0x0199ecc4 (3840x2160 -> 3840x2560, guarded)
 *   - Step 3 (AP RAM): 4 libmpr.so g_videoParamComb sites (private COW RAM via mprotect)
 *                    + 101 av-cam.bin sites @ AVCAM_PHYS 0x401000000 (cmdline + 3 .rodata guards locked)
 *   - Step 5 (CP RAM): 3 lcdfill_v2 rear-LCD 3:2 preview fill + AF/tracking rect sites (20 B)
 *
 * STRICT SAFETY GUARANTEES:
 *   1. ZERO flash writes (/dev/nflash, /cp/cpapp, /setting/BACKUP, or any disk library).
 *      100% volatile RAM / CP-RAM -- a 10s battery pull reverts 100% to factory stock.
 *   2. PASS 0 verifies /proc/cmdline (@0x401000000), on-disk SHA-256 of /libsencore.so, /libmpr.so,
 *      /libJiritsu.so, all 3 libsencore.so 8-byte function prologues, 3 cpapp-b.bin 4 KB code pages,
 *      and 3 static .rodata SHA-256 guards in av-cam.bin.
 *   3. PASS 1 dynamically locates & 7-anchor-verifies DmmCfg.bin in CP RAM, checks that key 0x57f has not
 *      already been divided at stock size, and verifies EVERY SINGLE preimage site (142 sites + 5 guards)
 *      is STOCK (or TARGET) BEFORE writing 1 byte.
 *   4. PASS 2 applies Step 4 DmmCfg FIRST, then Steps 1/5/2/3 via 64B-aligned CP DMA RMW + readback,
 *      private COW on libmpr.so, and dsb sy on av-cam.bin. Auto-rollback restores STOCK on any failure.
 *   5. PASS 3 re-reads all 142 sites end-to-end and only reports RESULT=APPLY_OK on 100% match.
 */
#include "a6700_og_patch_spec.h"

/* ---- AArch64 Linux syscalls ---------------------------------------------- */
#define NR_openat   56
#define NR_close    57
#define NR_read     63
#define NR_write    64
#define NR_munmap   215
#define NR_mmap     222
#define NR_mprotect 226

#define AT_FDCWD      (-100)
#define O_RDONLY      0
#define O_WRONLY      1
#define O_RDWR        2
#define O_RDWR_SYNC   0x101002 /* O_RDWR | O_SYNC (for CP DMA bounce buffer ONLY) */
#define O_CREAT       0x40
#define O_TRUNC       0x200

#define PROT_READ     1
#define PROT_WRITE    2
#define PROT_EXEC     4
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
__attribute__((noinline)) static i64 sys_mprotect(u64 addr, u64 len, i64 prot) { return sc6(NR_mprotect, (i64)addr, (i64)len, prot, 0, 0, 0); }
__attribute__((noinline)) static i64 sys_mmap_rw(i64 fd, u64 len, u64 off) {
    i64 r = sc6(NR_mmap, 0, (i64)len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (i64)off);
    return (r < 0 && r > -4096) ? -1 : r;
}

static void mem_barrier_sy(void) {
    __asm__ volatile("dsb sy" ::: "memory");
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

/* ---- Private Copy-on-Write writer for libmpr.so (.rodata in PT_LOAD[0]) -- */
static int cow_write_libmpr(u64 file_off, const u8 *src, u64 len) {
    u8 perms = 0;
    u64 va = find_mapped_slice("/libmpr.so", file_off, len, 1u, &perms, 0, 0);
    if (!va) return 0;
    int need_mprot = !(perms & 2u);
    u64 pg_start = va & ~4095ULL;
    u64 pg_end   = (va + len + 4095ULL) & ~4095ULL;
    u64 pg_len   = pg_end - pg_start;
    i64 orig_prot = ((perms & 1u) ? PROT_READ : 0)
                  | ((perms & 2u) ? PROT_WRITE : 0)
                  | ((perms & 4u) ? PROT_EXEC : 0);
    if (need_mprot) {
        if (sys_mprotect(pg_start, pg_len, orig_prot | PROT_WRITE) != 0) return 0;
    }
    volatile u8 *dst = (volatile u8 *)va;
    for (u64 i = 0; i < len; i++) dst[i] = src[i];
    __asm__ volatile("dsb ish" ::: "memory");
    if (need_mprot) {
        (void)sys_mprotect(pg_start, pg_len, orig_prot);
    }
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

/* Poison bounce buffer with 0xEE, DMA-read 64B-aligned span covering [cp_va, cp_va+len),
 * and return pointer to cp_va inside g_cp_buf (or 0 on failure). */
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

/* 64B-aligned read-modify-write + immediate poisoned readback verification (contiguous). */
__attribute__((noinline))
static int cp_dma_write_contig(u32 cp_va, const u8 *src, u32 len) {
    u32 al_start = 0, dma_len = 0;
    u8 *p = cp_dma_read_span(cp_va, len, &al_start, &dma_len);
    if (!p) return 0;
    for (u32 i = 0; i < len; i++) p[i] = src[i];
    mem_barrier_sy();
    if (g_sen_dma(1U, g_cp_phys, (u64)al_start, dma_len) != 0U) return 0;
    /* Immediate poisoned readback check */
    u8 *rb = cp_dma_read_span(cp_va, len, 0, 0);
    return (rb != 0) && mem_eq(rb, src, len);
}

/* 64B-aligned read-modify-write + immediate poisoned readback verification (sparse bytes). */
__attribute__((noinline))
static int cp_dma_write_sparse(u32 cp_va, u32 span_len, const u16 *offs, const u8 *src, u32 count) {
    u32 al_start = 0, dma_len = 0;
    u8 *p = cp_dma_read_span(cp_va, span_len, &al_start, &dma_len);
    if (!p) return 0;
    for (u32 i = 0; i < count; i++) p[offs[i]] = src[i];
    mem_barrier_sy();
    if (g_sen_dma(1U, g_cp_phys, (u64)al_start, dma_len) != 0U) return 0;
    /* Immediate poisoned readback check */
    u8 *rb = cp_dma_read_span(cp_va, span_len, 0, 0);
    if (!rb) return 0;
    for (u32 i = 0; i < count; i++) {
        if (rb[offs[i]] != src[i]) return 0;
    }
    return 1;
}

static int cp_check_sparse(const u8 *rec, const u16 *offs, const u8 *exp, u32 count) {
    for (u32 i = 0; i < count; i++) {
        if (rec[offs[i]] != exp[i]) return 0;
    }
    return 1;
}

static u32 rd_u32(const u8 *p) {
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

/* ---- Step 4: Dynamic 7-anchor-verified DmmCfg key 0x57f raw write buffer ----
 * Live CP RAM (proven via 20261123_125207_og_probe_ro.txt @ 0x2580cd4) strips the 0x50-B
 * DmmCfg.bin group headers at boot and packs all 20-byte records contiguously:
 *   +0x000: Group 0x8a (parent 0x6fa = 71 MiB): 3x key 0x57f @ +0x000, +0x014, +0x028
 *   +0x050: Group 0x8b (0x124 = 0x3b00000), +0x078: Grp 0x8c (0xec), +0x0b4: Grp 0x8d (0xeb)
 *   +0x118: Group 0x8e (parent 0x74d = 78 MiB): 1x key 0x57f @ +0x118, + 0x634/0x635/0x2da
 *   +0x26c: Group 0x92 (0x2da = 0x13c6800)
 *   Stock unit size    : 3356 * 6016 = 20,189,696 (0x01341200)
 *   Open Gate v6 size  : 3976 * 6016 = 23,919,616 (0x016CFC00)
 *   3 * 23,919,616 = 71,758,848 B <= 74,448,896 B (71.00 MiB 0x6fa, +2.57 MiB spare!), keeping
 *   ALL 7 of 7 key-0x57f buffers available for cpapp-b.bin @ 0x4aea66 (which pre-allocates 6 upfront)! */
#define OG_DMM_SITE_COUNT 4U
struct og_dmm_site {
    const char *name;
    u32         off;
    u8          stock[4];
    u8          target[4];
};
static const struct og_dmm_site OG_DMM_SITES[OG_DMM_SITE_COUNT] = {
    { "dmm_8a_sz0", 0x00000004U, {0x00,0x12,0x34,0x01}, {0x00,0xfc,0x6c,0x01} },
    { "dmm_8a_sz1", 0x00000018U, {0x00,0x12,0x34,0x01}, {0x00,0xfc,0x6c,0x01} },
    { "dmm_8a_sz2", 0x0000002CU, {0x00,0x12,0x34,0x01}, {0x00,0xfc,0x6c,0x01} },
    { "dmm_8e_sz0", 0x0000011CU, {0x00,0x12,0x34,0x01}, {0x00,0xfc,0x6c,0x01} },
};
static const u8 DMM_SIG_8A_TGT[40] = {
    0x7f,0x05,0x00,0x00, 0x00,0xfc,0x6c,0x01, 0x0f,0x01,0x00,0x00, 0x00,0x00,0x00,0x00, 0x07,0x00,0x00,0x00,
    0x7f,0x05,0x00,0x00, 0x00,0xfc,0x6c,0x01, 0x0f,0x01,0x00,0x00, 0x00,0x00,0x00,0x00, 0x07,0x00,0x00,0x00
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
    if (sz_8e != 0x01341200U && sz_8e != 0x016CFC00U) return 0;
    if (rd_u32(p + 0x12CU) != 0x634U || rd_u32(p + 0x130U) != 0x0032A000U) return 0;
    if (rd_u32(p + 0x154U) != 0x635U || rd_u32(p + 0x158U) != 0x00CA8000U) return 0;
    if (rd_u32(p + 0x17CU) != 0x2DAU || rd_u32(p + 0x180U) != 0x013C6800U) return 0;
    if (rd_u32(p + 0x26CU) != 0x2DAU || rd_u32(p + 0x270U) != 0x013C6800U) return 0;
    return 1;
}

static u32 locate_dmmcfg_base(void) {
    static const struct { u32 lo; u32 hi; } ranges[3] = {
        { 0x02000000U, 0x02800000U }, /* adjacent to CSDrvParam @ 0x025dabcc */
        { 0x01220000U, 0x02000000U }, /* lower CP .bss / heap */
        { 0x02800000U, 0x03400000U }, /* upper CP heap up to 0x03400000 */
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

/* ---- Touched-site tracking for automatic rollback ------------------------ */
static u8 g_touched_dmm[OG_DMM_SITE_COUNT];
static u8 g_touched_cells[OG_CP_CELL_COUNT];
static u8 g_touched_lcdfill[OG_LCDFILL_CELL_COUNT];
static u8 g_touched_rec_L;
static u8 g_touched_rec_R;
static u8 g_touched_drv_8c0;
static u8 g_touched_drv_880;
static u8 g_touched_sizetbl;
static u8 g_touched_lm[OG_LIBMPR_SITE_COUNT];
static u8 g_touched_av[OG_AVCAM_PATCH_COUNT];

static void rollback_all(u8 *av_map) {
    out_s("== ROLLBACK: restoring STOCK to all touched sites\n");
    u32 rb_fail = 0;
    for (u32 i = 0; i < OG_AVCAM_PATCH_COUNT; i++) {
        if (!g_touched_av[i] || !av_map) continue;
        const struct og_av_patch *p = &OG_AVCAM_PATCHES[i];
        u8 *dst = av_map + p->file_off;
        for (u8 k = 0; k < p->len; k++) dst[k] = p->stock[k];
        mem_barrier_sy();
        if (!mem_eq(dst, p->stock, p->len)) rb_fail++;
    }
    for (u32 i = 0; i < OG_LIBMPR_SITE_COUNT; i++) {
        if (!g_touched_lm[i]) continue;
        const struct og_mp_site *s = &OG_LIBMPR_SITES[i];
        if (!cow_write_libmpr(s->file_off, s->stock, s->len)) rb_fail++;
    }
    if (g_touched_sizetbl) {
        if (!cp_dma_write_contig(OG_SIZETBL_SITE_VA, OG_SIZETBL_OLD, 4U)) rb_fail++;
    }
    if (g_touched_drv_880) {
        if (!cp_dma_write_sparse(CP_DRVPARAM_880, CP_DRVPARAM_LEN, OG_DRV_880_OFFS,
                                 OG_DRV_880_OLD, OG_DRV_880_COUNT)) rb_fail++;
    }
    if (g_touched_drv_8c0) {
        if (!cp_dma_write_sparse(CP_DRVPARAM_8C0, CP_DRVPARAM_LEN, OG_DRV_8C0_OFFS,
                                 OG_DRV_8C0_OLD, OG_DRV_8C0_COUNT)) rb_fail++;
    }
    if (g_touched_rec_R) {
        if (!cp_dma_write_contig(0x0D39414U, OG_REC_R_OLD, 3000U)) rb_fail++;
    }
    if (g_touched_rec_L) {
        if (!cp_dma_write_contig(0x0D3885CU, OG_REC_L_OLD, 3000U)) rb_fail++;
    }
    for (u32 i = 0; i < OG_LCDFILL_CELL_COUNT; i++) {
        if (!g_touched_lcdfill[i]) continue;
        const struct og_cp_cell8 *c = &OG_LCDFILL_CELLS[i];
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
    out_s("A6700_OG_RAM_V6 a6700_og_ram_v6_3968_pal50safe_all7dmm_lcdfill\n");

    /* ==== PASS 0: Kernel cmdline, library SHA-256 & CP code-page identity === */
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

    /* Allocate 64B-aligned 4 KB DMM bounce buffer and open /dev/mem */
    u32 dmm_handle = 0;
    g_cp_phys = g_dmm_alloc(CP_PAGE, &dmm_handle);
    if (!g_cp_phys || (g_cp_phys & 0x3FULL) != 0ULL || g_cp_phys < RAM_LO || (g_cp_phys + CP_PAGE) > RAM_HI) {
        if (dmm_handle) g_dmm_free(dmm_handle);
        out_s("RESULT=ABORT_IDENTITY reason=dmm_alloc_failed writes=0\n");
        flush_result();
        return;
    }

    /* CP DMA bounce buffer uses O_RDWR|O_SYNC (uncached); av-cam.bin uses O_RDWR (cacheable, matches kernel) */
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

    /* Verify 3 pure-code cpapp-b.bin 4 KB pages (index 0..2; index 3 @ 0xdc7000 holds S2/PAL_S2!) & 3 av-cam.bin guards */
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
    out_s("PASS0_IDENTITY=OK\n");

    /* ==== PASS 1: 100% Dry Preimage Check Across All 142 Sites (0 writes!) == */
    u32 pre_errs = 0;
    u32 to_apply = 0;

    /* 1.0 Dynamic 7-anchor Step 4 DmmCfg.bin key 0x57f locator, preimage & not-already-divided check */
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

    /* 1a. 30 small CP sensor/table cells (8 IMX684 + 11 NTSC 0x08c0 + 11 PAL 0x0880) */
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

    /* 1a2. 3 Step 5 Rear-LCD 3:2 Fill (lcdfill_v2) CP cells */
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

    /* 1b. Left & Right 3000-B ISP records (shared 0x0880 PAL + 0x08c0 NTSC) */
    {
        u8 *pL = cp_dma_read_span(0x0D3885CU, 3000U, 0, 0);
        if (!pL) pre_errs++;
        else if (mem_eq(pL, OG_REC_L_OLD, 3000U)) to_apply++;
        else if (!mem_eq(pL, OG_REC_L_NEW, 3000U)) { out_s("PRE_FAIL rec3000_L\n"); pre_errs++; }

        u8 *pR = cp_dma_read_span(0x0D39414U, 3000U, 0, 0);
        if (!pR) pre_errs++;
        else if (mem_eq(pR, OG_REC_R_OLD, 3000U)) to_apply++;
        else if (!mem_eq(pR, OG_REC_R_NEW, 3000U)) { out_s("PRE_FAIL rec3000_R\n"); pre_errs++; }
    }

    /* 1c. Stored CSDrvParam[0x08c0] @ 0x025db46c & CSDrvParam[0x0880] @ 0x025db18c (32+32 sparse B) */
    {
        u8 *pD = cp_dma_read_span(CP_DRVPARAM_8C0, CP_DRVPARAM_LEN, 0, 0);
        if (!pD) pre_errs++;
        else if (cp_check_sparse(pD, OG_DRV_8C0_OFFS, OG_DRV_8C0_OLD, OG_DRV_8C0_COUNT)) to_apply++;
        else if (!cp_check_sparse(pD, OG_DRV_8C0_OFFS, OG_DRV_8C0_NEW, OG_DRV_8C0_COUNT)) {
            out_s("PRE_FAIL csdrvparam_0x8c0\n");
            pre_errs++;
        }

        u8 *pP = cp_dma_read_span(CP_DRVPARAM_880, CP_DRVPARAM_LEN, 0, 0);
        if (!pP) pre_errs++;
        else if (cp_check_sparse(pP, OG_DRV_880_OFFS, OG_DRV_880_OLD, OG_DRV_880_COUNT)) to_apply++;
        else if (!cp_check_sparse(pP, OG_DRV_880_OFFS, OG_DRV_880_NEW, OG_DRV_880_COUNT)) {
            out_s("PRE_FAIL csdrvparam_0x880\n");
            pre_errs++;
        }
    }

    /* 1d. Step 2 CP .bss movie size table @ 0x0199ecc4 + adjacent guards */
    {
        u8 *pS = cp_dma_read_span(OG_SIZETBL_GUARD0_VA, 16U, 0, 0);
        if (!pS || !mem_eq(pS, OG_SIZETBL_GUARD0, 8U) || !mem_eq(pS + 12U, OG_SIZETBL_GUARD1, 4U)) {
            out_s("PRE_FAIL sizetbl_guards_uninitialized (cold-boot on STILLS required)\n");
            pre_errs++;
        } else if (mem_eq(pS + 8U, OG_SIZETBL_OLD, 4U)) {
            to_apply++;
        } else if (!mem_eq(pS + 8U, OG_SIZETBL_NEW, 4U)) {
            out_s("PRE_FAIL sizetbl_0x0199ecc4\n");
            pre_errs++;
        }
    }

    /* 1e. Step 3: 4 libmpr.so sites + 101 av-cam.bin sites */
    for (u32 i = 0; i < OG_LIBMPR_SITE_COUNT; i++) {
        const struct og_mp_site *s = &OG_LIBMPR_SITES[i];
        u64 va = find_mapped_slice("/libmpr.so", s->file_off, s->len, 1u, 0, 0, 0);
        if (!va) { pre_errs++; continue; }
        if (mem_eq((const u8 *)va, s->stock, s->len)) to_apply++;
        else if (!mem_eq((const u8 *)va, s->target, s->len)) {
            out_s("PRE_FAIL libmpr="); out_s(s->name); out_s("\n");
            pre_errs++;
        }
    }
    for (u32 i = 0; i < OG_AVCAM_PATCH_COUNT; i++) {
        const struct og_av_patch *p = &OG_AVCAM_PATCHES[i];
        const u8 *cur = av_map + p->file_off;
        if (mem_eq(cur, p->stock, p->len)) to_apply++;
        else if (!mem_eq(cur, p->target, p->len)) {
            out_s("PRE_FAIL avcam_off="); out_hex(p->file_off); out_s("\n");
            pre_errs++;
        }
    }

    if (pre_errs != 0U) {
        out_s("RESULT=ABORT_MISMATCH pre_errors="); out_u64(pre_errs); out_s(" writes=0\n");
        goto cleanup;
    }
    if (to_apply == 0U) {
        out_s("RESULT=NOTHING_TO_DO sites=142 writes=0\n");
        goto cleanup;
    }
    out_s("PASS1_PREIMAGE=OK sites_to_write="); out_u64(to_apply); out_s("\n");

    /* ==== PASS 2: Atomic Apply + Immediate Readback + Auto-Rollback ========= */
    for (u32 i = 0; i < OG_DMM_SITE_COUNT; i++) g_touched_dmm[i] = 0;
    for (u32 i = 0; i < OG_CP_CELL_COUNT; i++) g_touched_cells[i] = 0;
    for (u32 i = 0; i < OG_LCDFILL_CELL_COUNT; i++) g_touched_lcdfill[i] = 0;
    g_touched_rec_L = 0; g_touched_rec_R = 0;
    g_touched_drv_8c0 = 0; g_touched_drv_880 = 0;
    g_touched_sizetbl = 0;
    for (u32 i = 0; i < OG_LIBMPR_SITE_COUNT; i++) g_touched_lm[i] = 0;
    for (u32 i = 0; i < OG_AVCAM_PATCH_COUNT; i++) g_touched_av[i] = 0;

    int apply_err = 0;

    /* 2.0 Step 4 DmmCfg 0x57f applied FIRST (before Step 1, matching ArcaneLantern open_gate_apply.py) */
    for (u32 i = 0; i < OG_DMM_SITE_COUNT && !apply_err; i++) {
        const struct og_dmm_site *d = &OG_DMM_SITES[i];
        u8 *p = cp_dma_read_span(g_dmm_base + d->off, 4U, 0, 0);
        if (p && mem_eq(p, d->target, 4U)) continue;
        g_touched_dmm[i] = 1;
        if (!cp_dma_write_contig(g_dmm_base + d->off, d->target, 4U)) apply_err = 1;
    }

    for (u32 i = 0; i < OG_CP_CELL_COUNT && !apply_err; i++) {
        const struct og_cp_cell *c = &OG_CP_CELLS[i];
        u8 *p = cp_dma_read_span(c->cp_va, c->len, 0, 0);
        if (p && mem_eq(p, c->target, c->len)) continue;
        g_touched_cells[i] = 1;
        if (!cp_dma_write_contig(c->cp_va, c->target, c->len)) apply_err = 1;
    }
    for (u32 i = 0; i < OG_LCDFILL_CELL_COUNT && !apply_err; i++) {
        const struct og_cp_cell8 *c = &OG_LCDFILL_CELLS[i];
        u8 *p = cp_dma_read_span(c->cp_va, c->len, 0, 0);
        if (p && mem_eq(p, c->target, c->len)) continue;
        g_touched_lcdfill[i] = 1;
        if (!cp_dma_write_contig(c->cp_va, c->target, c->len)) apply_err = 1;
    }
    if (!apply_err) {
        u8 *pL = cp_dma_read_span(0x0D3885CU, 3000U, 0, 0);
        if (!pL || !mem_eq(pL, OG_REC_L_NEW, 3000U)) {
            g_touched_rec_L = 1;
            if (!cp_dma_write_contig(0x0D3885CU, OG_REC_L_NEW, 3000U)) apply_err = 1;
        }
    }
    if (!apply_err) {
        u8 *pR = cp_dma_read_span(0x0D39414U, 3000U, 0, 0);
        if (!pR || !mem_eq(pR, OG_REC_R_NEW, 3000U)) {
            g_touched_rec_R = 1;
            if (!cp_dma_write_contig(0x0D39414U, OG_REC_R_NEW, 3000U)) apply_err = 1;
        }
    }
    if (!apply_err) {
        u8 *pD = cp_dma_read_span(CP_DRVPARAM_8C0, CP_DRVPARAM_LEN, 0, 0);
        if (!pD || !cp_check_sparse(pD, OG_DRV_8C0_OFFS, OG_DRV_8C0_NEW, OG_DRV_8C0_COUNT)) {
            g_touched_drv_8c0 = 1;
            if (!cp_dma_write_sparse(CP_DRVPARAM_8C0, CP_DRVPARAM_LEN, OG_DRV_8C0_OFFS,
                                     OG_DRV_8C0_NEW, OG_DRV_8C0_COUNT)) apply_err = 1;
        }
    }
    if (!apply_err) {
        u8 *pP = cp_dma_read_span(CP_DRVPARAM_880, CP_DRVPARAM_LEN, 0, 0);
        if (!pP || !cp_check_sparse(pP, OG_DRV_880_OFFS, OG_DRV_880_NEW, OG_DRV_880_COUNT)) {
            g_touched_drv_880 = 1;
            if (!cp_dma_write_sparse(CP_DRVPARAM_880, CP_DRVPARAM_LEN, OG_DRV_880_OFFS,
                                     OG_DRV_880_NEW, OG_DRV_880_COUNT)) apply_err = 1;
        }
    }
    if (!apply_err) {
        u8 *pS = cp_dma_read_span(OG_SIZETBL_SITE_VA, 4U, 0, 0);
        if (!pS || !mem_eq(pS, OG_SIZETBL_NEW, 4U)) {
            g_touched_sizetbl = 1;
            if (!cp_dma_write_contig(OG_SIZETBL_SITE_VA, OG_SIZETBL_NEW, 4U)) apply_err = 1;
        }
    }
    for (u32 i = 0; i < OG_LIBMPR_SITE_COUNT && !apply_err; i++) {
        const struct og_mp_site *s = &OG_LIBMPR_SITES[i];
        u64 va = find_mapped_slice("/libmpr.so", s->file_off, s->len, 1u, 0, 0, 0);
        if (va && mem_eq((const u8 *)va, s->target, s->len)) continue;
        g_touched_lm[i] = 1;
        if (!cow_write_libmpr(s->file_off, s->target, s->len)) apply_err = 1;
    }
    for (u32 i = 0; i < OG_AVCAM_PATCH_COUNT && !apply_err; i++) {
        const struct og_av_patch *p = &OG_AVCAM_PATCHES[i];
        u8 *dst = av_map + p->file_off;
        if (mem_eq(dst, p->target, p->len)) continue;
        g_touched_av[i] = 1;
        for (u8 k = 0; k < p->len; k++) dst[k] = p->target[k];
        mem_barrier_sy();
        if (!mem_eq(dst, p->target, p->len)) apply_err = 1;
    }

    if (apply_err) {
        rollback_all(av_map);
        out_s("RESULT=ABORT_ROLLED_BACK\n");
        goto cleanup;
    }

    /* ==== PASS 3: Full End-to-End Readback Verification (All 147 Sites) ===== */
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
    for (u32 i = 0; i < OG_LCDFILL_CELL_COUNT; i++) {
        const struct og_cp_cell8 *c = &OG_LCDFILL_CELLS[i];
        u8 *p = cp_dma_read_span(c->cp_va, c->len, 0, 0);
        if (!p || !mem_eq(p, c->target, c->len)) rb_errs++;
    }
    {
        u8 *pL = cp_dma_read_span(0x0D3885CU, 3000U, 0, 0);
        if (!pL || !mem_eq(pL, OG_REC_L_NEW, 3000U)) rb_errs++;
        u8 *pR = cp_dma_read_span(0x0D39414U, 3000U, 0, 0);
        if (!pR || !mem_eq(pR, OG_REC_R_NEW, 3000U)) rb_errs++;
        u8 *pD = cp_dma_read_span(CP_DRVPARAM_8C0, CP_DRVPARAM_LEN, 0, 0);
        if (!pD || !cp_check_sparse(pD, OG_DRV_8C0_OFFS, OG_DRV_8C0_NEW, OG_DRV_8C0_COUNT)) rb_errs++;
        u8 *pP = cp_dma_read_span(CP_DRVPARAM_880, CP_DRVPARAM_LEN, 0, 0);
        if (!pP || !cp_check_sparse(pP, OG_DRV_880_OFFS, OG_DRV_880_NEW, OG_DRV_880_COUNT)) rb_errs++;
        u8 *pS = cp_dma_read_span(OG_SIZETBL_SITE_VA, 4U, 0, 0);
        if (!pS || !mem_eq(pS, OG_SIZETBL_NEW, 4U)) rb_errs++;
    }
    for (u32 i = 0; i < OG_LIBMPR_SITE_COUNT; i++) {
        const struct og_mp_site *s = &OG_LIBMPR_SITES[i];
        u64 va = find_mapped_slice("/libmpr.so", s->file_off, s->len, 1u, 0, 0, 0);
        if (!va || !mem_eq((const u8 *)va, s->target, s->len)) rb_errs++;
    }
    for (u32 i = 0; i < OG_AVCAM_PATCH_COUNT; i++) {
        const struct og_av_patch *p = &OG_AVCAM_PATCHES[i];
        if (!mem_eq(av_map + p->file_off, p->target, p->len)) rb_errs++;
    }

    if (rb_errs != 0U) {
        rollback_all(av_map);
        out_s("RESULT=ABORT_VERIFY_FAIL rb_errors="); out_u64(rb_errs); out_s("\n");
        goto cleanup;
    }

    out_s("PASS3_READBACK=OK sites=142\n");
    out_s("RESULT=APPLY_OK design=dmmwb3976_all7+ogsq_v6_3968_pal50safe+outsz2560+ogfile2560+lcdfill_v2 raster=3840x2560\n");

cleanup:
    sys_munmap((void *)av_map_raw, OG_AVCAM_PATCH_MAP_HI);
    sys_close(av_mem_fd);
    sys_munmap((void *)cp_map, cp_maplen);
    sys_close(cp_mem_fd);
    g_dmm_free(dmm_handle);
    flush_result();
}
