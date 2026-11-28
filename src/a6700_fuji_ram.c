/* a6700_fuji_ram.c -- Zero-flash, zero-code-patch, 100% volatile CP-data-only
 * True Hardware 8-Sim Fujifilm Film Simulation Pack for Sony ILCE-6700 (a6700) FW v2.00.
 *
 * ARCHITECTURE (Zero AP code patched, ZERO CP executable instructions patched -> 0 I-cache hazard!):
 *   ST  (params  0/21, mode[0] {0,10}->{ 2,12}, slot 22) -> Provia          (Still + Movie)
 *   PT  (params  6/27, mode[3] {1,11}->{23,30}, slot 23) -> Astia           (Still + Movie)
 *   VV  (params  1/22, mode[1] {8,18}->{ 9,19}, slot 24) -> Velvia          (Still + Movie)
 *   VV2 (params 42/46, desc    38/42,           slot 25) -> Classic Neg.    (Still + Movie)
 *   FL  (params 41/45, desc    37/41,           slot 26) -> Classic Chrome  (Still + Movie)
 *   IN  (params 43/47, desc    39/43,           slot 27) -> Pro Neg. Hi     (Still + Movie)
 *   SH  (params 44/48, desc    40/44,           slot 28) -> Eterna          (Still + Movie)
 *   BW  (monochrome,   mode[5] {4,14}->{20,21}, Gamma)   -> Acros           (Still + Movie)
 *   NT (Neutral) & SE (Sepia) remain 100% untouched Sony factory stock!
 *
 * SAFETY GUARANTEES:
 *   - 100% ZERO flash writes (/dev/nflash, /cp/cpapp, /setting/BACKUP untouched).
 *   - ZERO mprotect / ZERO pwrite64 / ZERO CP code writes.
 *   - 10-second battery pull returns the camera 100% to factory stock.
 *   - PASS 0 verifies libsencore.so / libJiritsu.so SHA-256, 3 prologues, and 3 pure-code CP pages.
 *   - PASS 1 dry-verifies ALL CP-RAM preimage regions (Stock, FX2 FL2/3, Legacy 4-Sim, or 8-Sim).
 *   - PASS 2 parks pointers to Stock FIRST, writes backing caves/aux-descs/slots, flips descs/modes/pmaps LAST.
 *   - PASS 3 re-reads all regions end-to-end and only reports RESULT=APPLY_OK on 100% match.
 */
#include "a6700_fuji_spec.h"
#include "a6700_fl23_spec.h"

#define NR_openat   56
#define NR_close    57
#define NR_read     63
#define NR_write    64
#define NR_munmap   215
#define NR_mmap     222

#define AT_FDCWD      (-100)
#define O_RDONLY      0
#define O_WRONLY      1
#define O_RDWR_SYNC   0x101002
#define O_CREAT       0x40
#define O_TRUNC       0x200

#define PROT_READ     1
#define PROT_WRITE    2
#define MAP_SHARED    1

#define CP_PAGE       4096U
#define CP_CHUNK      2048U
#define RAM_LO        0x400000000ULL
#define RAM_HI        0x500000000ULL
#define RESULT_PATH   "/tmp/jiritsu/rampatch.result"

static const u8 LEGACY_FUJI4_U01_PMAP14[FUJI_PMAP_SPARSE_COUNT] = {
    0x00,0x02,0x06, 0x01,0x03,0x07, 0x16,0x17,0x18,0x19, 0x16,0x17,0x18,0x19
};
static const u8 LEGACY_FUJI4_U0D_PMAP14[FUJI_PMAP_SPARSE_COUNT] = {
    0x00,0x02,0x06, 0x01,0x03,0x07, 0x16,0x18,0x1a,0x1c, 0x17,0x19,0x1b,0x1d
};

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
__attribute__((noinline)) static i64 sys_mmap_rw(i64 fd, u64 len, u64 off) {
    i64 r = sc6(NR_mmap, 0, (i64)len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (i64)off);
    return (r < 0 && r > -4096) ? -1 : r;
}

static void mem_barrier_sy(void) { __asm__ volatile("dsb sy" ::: "memory"); }

/* ---- Output buffer ------------------------------------------------------- */
#define OUTCAP (16u * 1024u)
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
__attribute__((noinline)) static void out_hex_bytes(const u8 *p, u64 n) {
    static const char H[] = "0123456789abcdef";
    for (u64 i = 0; i < n; i++) { out_c((u8)H[p[i] >> 4]); out_c((u8)H[p[i] & 15]); }
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
static int mem_is_zero(const u8 *a, u64 n) {
    for (u64 i = 0; i < n; i++) if (a[i] != 0U) return 0;
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
    struct sha256_ctx c; sha_init(&c); sha_add(&c, p, n); sha_end(&c, dig);
}

/* ---- /proc/self/maps + disk file hashing --------------------------------- */
static char g_maps[131072];
static u64  g_maps_len;
static u8   g_iobuf[4096];
static u8   g_zeros[CP_CHUNK];

static u64 read_text_file(const char *path, char *buf, u64 cap) {
    i64 fd = sys_open(path, O_RDONLY, 0);
    if (fd < 0) return 0;
    u64 tot = 0;
    while (tot + 1u < cap) {
        i64 r = sys_read(fd, buf + tot, cap - 1u - tot);
        if (r <= 0) break;
        tot += (u64)r;
    }
    sys_close(fd);
    buf[tot] = 0;
    return tot;
}

static u64 parse_hex_str(const char *s, u64 *adv) {
    u64 v = 0, i = 0;
    for (;;) {
        char c = s[i];
        u64 d;
        if (c >= '0' && c <= '9') d = (u64)(c - '0');
        else if (c >= 'a' && c <= 'f') d = (u64)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') d = (u64)(c - 'A' + 10);
        else break;
        v = (v << 4) | d;
        i++;
    }
    *adv = i;
    return v;
}

static u64 find_mapped_slice(const char *suffix, u64 file_off, u64 len, u8 req_perms,
                             char *out_path, u64 out_cap) {
    u64 pos = 0, found = 0;
    while (pos < g_maps_len) {
        u64 ls = pos;
        while (pos < g_maps_len && g_maps[pos] != '\n') pos++;
        u64 le = pos;
        if (pos < g_maps_len && g_maps[pos] == '\n') pos++;
        u64 p = ls, a = 0;
        u64 s_va = parse_hex_str(g_maps + p, &a); if (!a) continue; p += a;
        if (p >= le || g_maps[p] != '-') continue; p++;
        u64 e_va = parse_hex_str(g_maps + p, &a); if (!a) continue; p += a;
        while (p < le && g_maps[p] == ' ') p++;
        if (p + 4u > le) continue;
        u8 perms = ((g_maps[p] == 'r') ? 1u : 0u) | ((g_maps[p+1] == 'w') ? 2u : 0u)
                 | ((g_maps[p+2] == 'x') ? 4u : 0u);
        p += 4u;
        while (p < le && g_maps[p] == ' ') p++;
        u64 m_off = parse_hex_str(g_maps + p, &a); if (!a) continue; p += a;
        for (int fld = 0; fld < 2; fld++) {
            while (p < le && g_maps[p] == ' ') p++;
            while (p < le && g_maps[p] != ' ') p++;
        }
        while (p < le && g_maps[p] == ' ') p++;
        if (p >= le) continue;
        const char *mpath = g_maps + p;
        u64 plen = le - p;
        if (!ends_with(mpath, plen, suffix)) continue;
        if (out_path && out_path[0] == 0 && plen < out_cap) {
            for (u64 i = 0; i < plen; i++) out_path[i] = mpath[i];
            out_path[plen] = 0;
        }
        if ((perms & req_perms) != req_perms) continue;
        u64 m_sz = e_va - s_va;
        if (file_off >= m_off && (file_off - m_off + len) <= m_sz) {
            found = s_va + (file_off - m_off);
            break;
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

static int pmap14_eq(const u8 *span49, const u8 exp[FUJI_PMAP_SPARSE_COUNT]) {
    for (u32 i = 0; i < FUJI_PMAP_SPARSE_COUNT; i++) {
        if (span49[FUJI_PMAP_OFFS[i]] != exp[i]) return 0;
    }
    return 1;
}

__attribute__((noinline))
static int cp_dma_write_pmap14(u32 base_va, const u8 src[FUJI_PMAP_SPARSE_COUNT]) {
    u32 al_start = 0, dma_len = 0;
    u8 *p = cp_dma_read_span(base_va, FUJI_PMAP_SPAN_LEN, &al_start, &dma_len);
    if (!p) return 0;
    for (u32 i = 0; i < FUJI_PMAP_SPARSE_COUNT; i++) p[FUJI_PMAP_OFFS[i]] = src[i];
    mem_barrier_sy();
    if (g_sen_dma(1U, g_cp_phys, (u64)al_start, dma_len) != 0U) return 0;
    u8 *rb = cp_dma_read_span(base_va, FUJI_PMAP_SPAN_LEN, 0, 0);
    return (rb != 0) && pmap14_eq(rb, src);
}

static int cp_dma_eq_pmap14(u32 base_va, const u8 exp[FUJI_PMAP_SPARSE_COUNT]) {
    u8 *p = cp_dma_read_span(base_va, FUJI_PMAP_SPAN_LEN, 0, 0);
    return (p != 0) && pmap14_eq(p, exp);
}

static int cp_dma_check_chunked(u32 cp_va, const u8 *exp_or_null_zero, u32 total_len) {
    u32 off = 0;
    while (off < total_len) {
        u32 n = total_len - off;
        if (n > CP_CHUNK) n = CP_CHUNK;
        u8 *p = cp_dma_read_span(cp_va + off, n, 0, 0);
        if (!p) return -1;
        if (exp_or_null_zero) {
            if (!mem_eq(p, exp_or_null_zero + off, n)) return 0;
        } else {
            if (!mem_is_zero(p, n)) return 0;
        }
        off += n;
    }
    return 1;
}

static int cp_dma_write_chunked(u32 cp_va, const u8 *src_or_null_zero, u32 total_len) {
    u32 off = 0;
    while (off < total_len) {
        u32 n = total_len - off;
        if (n > CP_CHUNK) n = CP_CHUNK;
        const u8 *src = src_or_null_zero ? (src_or_null_zero + off) : g_zeros;
        if (!cp_dma_write_contig(cp_va + off, src, n)) return 0;
        off += n;
    }
    return 1;
}

/* Safe park-to-Stock & clean rollback helper */
static int park_stock_and_rollback(int zero_caves) {
    u32 fail = 0;
    for (u32 i = 0; i < FUJI_MODE_COUNT; i++) {
        if (!cp_dma_write_contig(FUJI_MODES[i].cp_va, FUJI_MODES[i].stock, 8U)) fail++;
    }
    for (u32 i = 0; i < FUJI_DESC_COUNT; i++) {
        if (!cp_dma_write_contig(FUJI_DESCS[i].cp_va, FUJI_DESCS[i].stock, 28U)) fail++;
    }
    if (!cp_dma_write_pmap14(FUJI_U01_PMAP_BASE_VA, FUJI_PMAP14_STOCK)) fail++;
    if (!cp_dma_write_pmap14(FUJI_U0D_PMAP_BASE_VA, FUJI_PMAP14_STOCK)) fail++;
    for (u32 i = 0; i < FUJI_AUX_DESC_COUNT; i++) {
        if (!cp_dma_write_contig(FUJI_AUX_DESCS[i].cp_va, g_zeros, 28U)) fail++;
    }
    if (zero_caves) {
        if (!cp_dma_write_chunked(FUJI_U01_SLOTS_VA, 0, FUJI_U01_SCRUB_LEN)) fail++;
        for (u32 sl = 0; sl < FUJI_U0D_SCRUB_SLOTS; sl++) {
            if (!cp_dma_write_chunked(FUJI_U0D_SLOTS_VA + sl * FUJI_U0D_SLOT_STRIDE, 0, FUJI_U0D_SLOT_STRIDE)) fail++;
        }
        if (!cp_dma_write_chunked(FUJI_GAMMA_CAVE_VA, 0, FUJI_GAMMA_CAVE_LEN)) fail++;
    }
    return (fail == 0U);
}

static void rollback_all(void) {
    out_s("== ROLLBACK: restoring prior state to all touched CP Fuji sites\n");
    int ok = park_stock_and_rollback(1);
    out_s("ROLLBACK_FAILURES="); out_u64(ok ? 0U : 1U); out_s("\n");
}

__attribute__((visibility("default"))) void _init(void) {
    g_olen = 0;
    out_s("A6700_FUJI_RAM_V1 " FUJI_RAM_LABEL "\n");

    /* ==== PASS 0: Library SHA-256 + libsencore bind + CP page guards ====== */
    g_maps_len = read_text_file("/proc/self/maps", g_maps, sizeof(g_maps));

    int sencore_ok = 0;
    for (u32 i = 0; i < OG_ID_FILE_COUNT; i++) {
        const struct og_id_file *f = &OG_ID_FILES[i];
        char path[200]; path[0] = 0;
        u64 base = find_mapped_slice(f->suffix, 0, 4096, 5u, path, sizeof(path));
        u64 fsz = 0; u8 dig[32];
        if (!path[0] || !base || !hash_disk_file(path, &fsz, dig) ||
            fsz != f->size || !mem_eq(dig, f->sha256, 32)) {
            out_s("RESULT=ABORT_IDENTITY reason=lib_sha_mismatch lib=");
            out_s(f->suffix); out_s(" writes=0\n");
            flush_result();
            return;
        }
        if (i == 0U) {
            u64 a_alloc = find_mapped_slice(f->suffix, SENCORE_DMM_ALLOC_OFF, 8, 5u, 0, 0);
            u64 a_free  = find_mapped_slice(f->suffix, SENCORE_DMM_FREE_OFF,  8, 5u, 0, 0);
            u64 a_dma   = find_mapped_slice(f->suffix, SENCORE_DMA_XFER_OFF,  8, 5u, 0, 0);
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
        out_s("RESULT=ABORT_IDENTITY reason=sencore_bind_failed writes=0\n");
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
        out_s("RESULT=ABORT_IDENTITY reason=devmem_open_failed writes=0\n");
        flush_result();
        return;
    }

    u64 cp_lead = g_cp_phys & 0xFFFULL;
    u64 cp_maplen = (cp_lead + CP_PAGE + 0xFFFULL) & ~0xFFFULL;
    i64 cp_map = sys_mmap_rw(cp_mem_fd, cp_maplen, g_cp_phys - cp_lead);
    if (cp_map == -1) {
        sys_close(cp_mem_fd);
        g_dmm_free(dmm_handle);
        out_s("RESULT=ABORT_IDENTITY reason=devmem_mmap_failed writes=0\n");
        flush_result();
        return;
    }
    g_cp_buf = (u8 *)cp_map + cp_lead;

    /* Verify 3 pure-code cpapp-b.bin 4 KB pages (index 0..2; index 3 @ 0xdc7000 is patched by Open Gate!) */
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
    out_s("PASS0_IDENTITY=OK\n");

    /* ==== PASS 1: Dry Preimage Check across all Fuji 8-Sim CP Data Regions == */
    u32 pre_errs = 0, to_apply = 0;

    /* 1a. Gamma cave 0x0010BD80 (13,824 B: stock zeros, legacy 4-sim + zeros, or already 8-sim target) */
    {
        int is_z = cp_dma_check_chunked(FUJI_GAMMA_CAVE_VA, 0, FUJI_GAMMA_CAVE_LEN);
        int is_t = (is_z == 1) ? 0 : cp_dma_check_chunked(FUJI_GAMMA_CAVE_VA, FUJI_GAMMA_CURVES, FUJI_GAMMA_CAVE_LEN);
        int is_z_tail = (is_z == 1 || is_t == 1) ? 0 : cp_dma_check_chunked(FUJI_GAMMA_CAVE_VA + 6912U, 0, FUJI_GAMMA_CAVE_LEN - 6912U);
        if (is_z < 0 || is_t < 0 || is_z_tail < 0) { out_s("PRE_FAIL gamma_cave_read\n"); pre_errs++; }
        else if (is_z == 1 || is_z_tail == 1) to_apply++;
        else if (is_t != 1) { out_s("PRE_FAIL gamma_cave_mismatch\n"); pre_errs++; }
    }

    /* 1b. 8 Aux descriptors (must be all-zero OR already 8-sim target) */
    for (u32 i = 0; i < FUJI_AUX_DESC_COUNT; i++) {
        const struct fuji_aux_desc *d = &FUJI_AUX_DESCS[i];
        u8 *p = cp_dma_read_span(d->cp_va, 28U, 0, 0);
        if (!p) { out_s("PRE_FAIL aux_read "); out_s(d->name); out_s("\n"); pre_errs++; }
        else if (mem_is_zero(p, 28U)) to_apply++;
        else if (!mem_eq(p, d->target, 28U)) {
            out_s("PRE_FAIL "); out_s(d->name); out_s(" got="); out_hex_bytes(p, 28U); out_s("\n");
            pre_errs++;
        }
    }

    /* 1c. 4 Mode-table entries @ 0x00DE08CC (stock OR already 8-sim target) */
    for (u32 i = 0; i < FUJI_MODE_COUNT; i++) {
        const struct fuji_mode_patch *m = &FUJI_MODES[i];
        u8 *p = cp_dma_read_span(m->cp_va, 8U, 0, 0);
        if (!p) { out_s("PRE_FAIL mode_read "); out_s(m->name); out_s("\n"); pre_errs++; }
        else if (mem_eq(p, m->stock, 8U)) to_apply++;
        else if (!mem_eq(p, m->target, 8U)) {
            out_s("PRE_FAIL "); out_s(m->name); out_s(" got="); out_hex_bytes(p, 8U); out_s("\n");
            pre_errs++;
        }
    }

    /* 1d. 8 Direct descriptors desc[37..44] (stock, FX2 alt, legacy 4-sim in cave, or 8-sim target) */
    for (u32 i = 0; i < FUJI_DESC_COUNT; i++) {
        const struct fuji_desc_patch *d = &FUJI_DESCS[i];
        u8 *p = cp_dma_read_span(d->cp_va, 28U, 0, 0);
        if (!p) { out_s("PRE_FAIL desc_read "); out_s(d->name); out_s("\n"); pre_errs++; }
        else if (mem_eq(p, d->target, 28U)) {
            /* already 8-sim target */
        } else if (mem_eq(p, d->stock, 28U) || mem_eq(p, d->alt_fl23, 28U) ||
                   (p[2] == 0x10U && p[3] == 0x00U)) {
            to_apply++;
        } else {
            out_s("PRE_FAIL "); out_s(d->name); out_s(" got="); out_hex_bytes(p, 28U); out_s("\n");
            pre_errs++;
        }
    }

    /* 1e. Sparse 14-byte Chroma & Matrix pmaps (checked separately: single DMA bounce buf!) */
    int legacy4 = 0;
    {
        u8 *m1 = cp_dma_read_span(FUJI_U01_PMAP_BASE_VA, FUJI_PMAP_SPAN_LEN, 0, 0);
        if (!m1) { out_s("PRE_FAIL u01_pmap_read\n"); pre_errs++; }
        else if (pmap14_eq(m1, FUJI_PMAP14_NEW)) { /* already 8-sim */ }
        else if (pmap14_eq(m1, LEGACY_FUJI4_U01_PMAP14)) { legacy4 = 1; to_apply++; }
        else if (pmap14_eq(m1, FUJI_PMAP14_STOCK) || pmap14_eq(m1, FUJI_PMAP14_FL23)) { to_apply++; }
        else { out_s("PRE_FAIL u01_pmap\n"); pre_errs++; }

        u8 *m2 = cp_dma_read_span(FUJI_U0D_PMAP_BASE_VA, FUJI_PMAP_SPAN_LEN, 0, 0);
        if (!m2) { out_s("PRE_FAIL u0d_pmap_read\n"); pre_errs++; }
        else if (pmap14_eq(m2, FUJI_PMAP14_NEW)) { /* already 8-sim */ }
        else if (pmap14_eq(m2, LEGACY_FUJI4_U0D_PMAP14)) { legacy4 = 1; to_apply++; }
        else if (pmap14_eq(m2, FUJI_PMAP14_STOCK) || pmap14_eq(m2, FUJI_PMAP14_FL23)) { to_apply++; }
        else { out_s("PRE_FAIL u0d_pmap\n"); pre_errs++; }
    }

    /* 1f. Chroma slots 22..28 & Matrix slots 22..28 */
    {
        u8 *sl = cp_dma_read_span(FUJI_U01_SLOTS_VA, FUJI_U01_SLOTS_LEN, 0, 0);
        if (!sl) { out_s("PRE_FAIL u01_slots_read\n"); pre_errs++; }
        else if (mem_eq(sl, FUJI_U01_SLOTS_NEW, FUJI_U01_SLOTS_LEN)) { /* already 8-sim */ }
        else if (mem_is_zero(sl, FUJI_U01_SLOTS_LEN) ||
                 (mem_eq(sl, FL23_U01_SLOTS_NEW, FL23_U01_SLOTS_LEN) && mem_is_zero(sl + 256U, FUJI_U01_SLOTS_LEN - 256U)) ||
                 (legacy4 && mem_is_zero(sl + 256U, FUJI_U01_SLOTS_LEN - 256U))) {
            to_apply++;
        } else {
            out_s("PRE_FAIL u01_slots head="); out_hex_bytes(sl, 16); out_s("\n");
            pre_errs++;
        }

        u32 slot_need = 0;
        for (u32 s = 0; s < FUJI_U0D_SLOT_COUNT; s++) {
            u32 sva = FUJI_U0D_SLOTS_VA + s * FUJI_U0D_SLOT_STRIDE;
            u8 *ps = cp_dma_read_span(sva, FUJI_U0D_SLOT_STRIDE, 0, 0);
            if (!ps) { out_s("PRE_FAIL u0d_slot_read\n"); pre_errs++; break; }
            int is_fuji = mem_eq(ps, FUJI_U0D_ACTIVE_NEW + s * FUJI_U0D_ACTIVE_LEN, FUJI_U0D_ACTIVE_LEN) &&
                          mem_is_zero(ps + FUJI_U0D_ACTIVE_LEN, FUJI_U0D_SLOT_STRIDE - FUJI_U0D_ACTIVE_LEN);
            int is_zero = mem_is_zero(ps, FUJI_U0D_SLOT_STRIDE);
            int is_fl23 = (s < 4U) && mem_eq(ps, FL23_U0D_SLOTS_NEW + s * FUJI_U0D_SLOT_STRIDE, FUJI_U0D_SLOT_STRIDE);
            int is_leg4 = legacy4 && mem_is_zero(ps + FUJI_U0D_ACTIVE_LEN, FUJI_U0D_SLOT_STRIDE - FUJI_U0D_ACTIVE_LEN);
            if (is_fuji) continue;
            if (is_zero || is_fl23 || is_leg4) slot_need = 1;
            else {
                out_s("PRE_FAIL u0d_slot="); out_u64(22u + s); out_s(" head="); out_hex_bytes(ps, 12); out_s("\n");
                pre_errs++;
                break;
            }
        }
        if (slot_need) to_apply++;
    }

    if (pre_errs != 0U) {
        out_s("RESULT=ABORT_MISMATCH pre_errors="); out_u64(pre_errs); out_s(" writes=0\n");
        goto cleanup;
    }
    if (to_apply == 0U) {
        out_s("RESULT=NOTHING_TO_DO regions=25 writes=0\n");
        goto cleanup;
    }
    out_s("PASS1_PREIMAGE=OK regions_to_write="); out_u64(to_apply); out_s("\n");

    /* ==== PASS 2: Safe Ordering Apply (Park Stock -> Data Caves -> Pointers LAST) === */
    if (!park_stock_and_rollback(0)) {
        rollback_all();
        out_s("RESULT=ABORT_ROLLED_BACK\n");
        goto cleanup;
    }

    int apply_err = 0;
    if (!cp_dma_write_chunked(FUJI_GAMMA_CAVE_VA, FUJI_GAMMA_CURVES, FUJI_GAMMA_CAVE_LEN)) apply_err = 1;
    for (u32 i = 0; i < FUJI_AUX_DESC_COUNT && !apply_err; i++) {
        if (!cp_dma_write_contig(FUJI_AUX_DESCS[i].cp_va, FUJI_AUX_DESCS[i].target, 28U)) apply_err = 1;
    }
    if (!apply_err && (!cp_dma_write_contig(FUJI_U01_SLOTS_VA, FUJI_U01_SLOTS_NEW, FUJI_U01_SLOTS_LEN) ||
                       !cp_dma_write_contig(FUJI_U01_SLOTS_VA + FUJI_U01_SLOTS_LEN, g_zeros, FUJI_U01_SCRUB_LEN - FUJI_U01_SLOTS_LEN))) {
        apply_err = 1;
    }
    for (u32 s = 0; s < FUJI_U0D_SLOT_COUNT && !apply_err; s++) {
        u32 sva = FUJI_U0D_SLOTS_VA + s * FUJI_U0D_SLOT_STRIDE;
        const u8 *act = FUJI_U0D_ACTIVE_NEW + s * FUJI_U0D_ACTIVE_LEN;
        if (!cp_dma_write_contig(sva, act, FUJI_U0D_ACTIVE_LEN) ||
            !cp_dma_write_contig(sva + FUJI_U0D_ACTIVE_LEN, g_zeros, FUJI_U0D_SLOT_STRIDE - FUJI_U0D_ACTIVE_LEN)) {
            apply_err = 1;
        }
    }
    for (u32 s = FUJI_U0D_SLOT_COUNT; s < FUJI_U0D_SCRUB_SLOTS && !apply_err; s++) {
        if (!cp_dma_write_chunked(FUJI_U0D_SLOTS_VA + s * FUJI_U0D_SLOT_STRIDE, 0, FUJI_U0D_SLOT_STRIDE)) apply_err = 1;
    }

    /* Flip direct descriptors, mode-table redirects, & sparse pmaps LAST */
    for (u32 i = 0; i < FUJI_DESC_COUNT && !apply_err; i++) {
        if (!cp_dma_write_contig(FUJI_DESCS[i].cp_va, FUJI_DESCS[i].target, 28U)) apply_err = 1;
    }
    for (u32 i = 0; i < FUJI_MODE_COUNT && !apply_err; i++) {
        if (!cp_dma_write_contig(FUJI_MODES[i].cp_va, FUJI_MODES[i].target, 8U)) apply_err = 1;
    }
    if (!apply_err && (!cp_dma_write_pmap14(FUJI_U01_PMAP_BASE_VA, FUJI_PMAP14_NEW) ||
                       !cp_dma_write_pmap14(FUJI_U0D_PMAP_BASE_VA, FUJI_PMAP14_NEW))) {
        apply_err = 1;
    }

    if (apply_err) {
        rollback_all();
        out_s("RESULT=ABORT_ROLLED_BACK\n");
        goto cleanup;
    }

    /* ==== PASS 3: End-to-End Readback Verification ======================== */
    u32 rb_errs = 0;
    if (cp_dma_check_chunked(FUJI_GAMMA_CAVE_VA, FUJI_GAMMA_CURVES, FUJI_GAMMA_CAVE_LEN) != 1) rb_errs++;
    for (u32 i = 0; i < FUJI_AUX_DESC_COUNT; i++) {
        u8 *p = cp_dma_read_span(FUJI_AUX_DESCS[i].cp_va, 28U, 0, 0);
        if (!p || !mem_eq(p, FUJI_AUX_DESCS[i].target, 28U)) rb_errs++;
    }
    for (u32 i = 0; i < FUJI_DESC_COUNT; i++) {
        u8 *p = cp_dma_read_span(FUJI_DESCS[i].cp_va, 28U, 0, 0);
        if (!p || !mem_eq(p, FUJI_DESCS[i].target, 28U)) rb_errs++;
    }
    for (u32 i = 0; i < FUJI_MODE_COUNT; i++) {
        u8 *p = cp_dma_read_span(FUJI_MODES[i].cp_va, 8U, 0, 0);
        if (!p || !mem_eq(p, FUJI_MODES[i].target, 8U)) rb_errs++;
    }
    {
        u8 *p1 = cp_dma_read_span(FUJI_U01_SLOTS_VA, FUJI_U01_SLOTS_LEN, 0, 0);
        if (!p1 || !mem_eq(p1, FUJI_U01_SLOTS_NEW, FUJI_U01_SLOTS_LEN)) rb_errs++;
        if (!cp_dma_eq_pmap14(FUJI_U01_PMAP_BASE_VA, FUJI_PMAP14_NEW)) rb_errs++;
        if (!cp_dma_eq_pmap14(FUJI_U0D_PMAP_BASE_VA, FUJI_PMAP14_NEW)) rb_errs++;
        for (u32 s = 0; s < FUJI_U0D_SLOT_COUNT; s++) {
            u32 sva = FUJI_U0D_SLOTS_VA + s * FUJI_U0D_SLOT_STRIDE;
            u8 *ps = cp_dma_read_span(sva, FUJI_U0D_SLOT_STRIDE, 0, 0);
            if (!ps ||
                !mem_eq(ps, FUJI_U0D_ACTIVE_NEW + s * FUJI_U0D_ACTIVE_LEN, FUJI_U0D_ACTIVE_LEN) ||
                !mem_is_zero(ps + FUJI_U0D_ACTIVE_LEN, FUJI_U0D_SLOT_STRIDE - FUJI_U0D_ACTIVE_LEN)) {
                rb_errs++;
            }
        }
    }

    if (rb_errs != 0U) {
        rollback_all();
        out_s("RESULT=ABORT_VERIFY_FAIL rb_errors="); out_u64(rb_errs); out_s("\n");
        goto cleanup;
    }

    out_s("PASS3_READBACK=OK regions=25\n");
    out_s("RESULT=APPLY_OK mode=cp_data_only ST=Provia PT=Astia VV=Velvia VV2=ClassicNeg FL=ClassicChrome IN=ProNegHi SH=Eterna BW=Acros\n");

cleanup:
    sys_munmap((void *)cp_map, cp_maplen);
    sys_close(cp_mem_fd);
    g_dmm_free(dmm_handle);
    flush_result();
}
