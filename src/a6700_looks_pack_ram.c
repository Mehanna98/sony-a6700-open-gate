/* a6700_looks_pack_ram.c -- 100% Zero-Flash RAM-Only Resident Creative Look Pack Switcher.
 *
 * Target: Sony ILCE-6700 (a6700) FW v2.00 ONLY (stock SHA-256 + 3 CP code pages verified).
 *
 * ZERO-FLASH, ZERO-MPROTECT, ZERO-CP-CODE-PATCH ARCHITECTURE:
 *   1. Stage 1 (/tmp/jiritsu/libJit.so):
 *        - Checks if already resident via dlsym(NULL, "a6700_apply_look_pack") -> ALREADY_INSTALLED.
 *        - Verifies libJiritsu.so SHA-256, copies self to volatile RAM tmpfs
 *          /tmp_wbshd/a6700_looks_pack.so, loads with dlopen(..., RTLD_NOW | RTLD_GLOBAL),
 *          and IMMEDIATELY unlinks /tmp_wbshd/a6700_looks_pack.so.
 *        - If Stage 2 failed identity checks (ready != 1), calls dlclose cleanly.
 *   2. Stage 2 (permanently pinned in volatile RAM until battery pull):
 *        - Locks libsencore.so & libJiritsu.so SHA-256 + 3 prologues + 3 pure-code CP 4KB pages.
 *        - Exports two C functions resolved via dlsym by a6700_og_menu_ram.so:
 *            int a6700_get_look_pack(void);    // 0=Stock, 1=FX2 FL2/FL3, 2=Fujifilm 8-Sim, -1=err, -2=not_ready
 *            int a6700_apply_look_pack(int m); // safely transitions CP data tables (gamma+chroma+matrix)
 *        - Auto-detects & heals post-warm-sleep partial CP resets (where WBI retained pmap/slots
 *          while volatile cpapp-b.bin gamma curves/descriptors reset to stock) AND seamlessly
 *          auto-upgrades any prior 4-Sim WBI pmap to the full 8-Sim Fujifilm pack.
 *   3. Safe switch ordering on EVERY transition (Stock <-> FX2 <-> Fujifilm 8-Sim):
 *        - First restores mode[0,1,3,5], desc[37..44], & sparse 14-byte pmaps to Stock, then zeroes
 *          aux descriptors desc[2,9,12,19,20,21,23,30] so CP NEVER sees a NULL or half-written table.
 *        - Writes target payload caves, aux descriptors, and slots 22..28 (scrubbing slot 29).
 *        - Flips target descriptors, mode-table redirects, & sparse pmaps LAST, then readback-verifies.
 *   4. Cold boot (10-second battery pull) wipes all RAM -> 100% untouched factory stock.
 */
#include "a6700_fl23_spec.h"
#include "a6700_fuji_spec.h"

/* ---- Exact 7-syscall surface (ZERO mprotect, ZERO pwrite64, ZERO flash) -- */
#define NR_unlinkat 35
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
#define STAGE_RAM_SO  "/tmp_wbshd/a6700_looks_pack.so"
#define RTLD_NOW_GLOB 0x102 /* RTLD_NOW (2) | RTLD_GLOBAL (0x100) so og_menu resolves via dlsym(NULL, ...) */

#define LIBJIT_PLT_DLSYM   0x60E0ULL
#define LIBJIT_PLT_DLOPEN  0x63F0ULL
#define LIBJIT_PLT_DLCLOSE 0x64B0ULL

/* Legacy 4-Sim WBI pmap patterns (for seamless upgrade without requiring a battery pull) */
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
__attribute__((noinline)) static i64 sys_unlink(const char *p)                 { return sc6(NR_unlinkat, AT_FDCWD, (i64)p, 0, 0, 0, 0); }
__attribute__((noinline)) static i64 sys_munmap(void *p, u64 len)              { return sc6(NR_munmap, (i64)p, (i64)len, 0, 0, 0, 0); }
__attribute__((noinline)) static i64 sys_mmap_rw(i64 fd, u64 len, u64 off) {
    i64 r = sc6(NR_mmap, 0, (i64)len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (i64)off);
    return (r < 0 && r > -4096) ? -1 : r;
}

static void mem_barrier_sy(void) { __asm__ volatile("dsb sy" ::: "memory"); }
static inline u64 read_cur_pc(void) { u64 pc; __asm__ volatile("adr %0, ." : "=r"(pc)); return pc; }

/* ---- Minimal helpers & output log ---------------------------------------- */
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
static int has_substr(const char *s, const char *needle) {
    u64 n = slen(s), m = slen(needle);
    if (m == 0 || n < m) return 0;
    for (u64 i = 0; i + m <= n; i++) {
        if (mem_eq((const u8 *)(s + i), (const u8 *)needle, m)) return 1;
    }
    return 0;
}

#define OUTCAP 4096U
static char g_out[OUTCAP];
static u32  g_olen;
static void out_c(u8 c) { if (g_olen < OUTCAP - 1u) g_out[g_olen++] = (char)c; }
__attribute__((noinline)) static void out_s(const char *s) { if (s) while (*s) out_c((u8)*s++); }
__attribute__((noinline)) static void out_u64(u64 v) {
    char b[24]; int i = 23; b[i--] = 0;
    if (!v) b[i--] = '0';
    while (v) { b[i--] = (char)('0' + (int)(v % 10u)); v /= 10u; }
    out_s(&b[i + 1]);
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
        w[i] = ((u32)p[4*i]<<24) | ((u32)p[4*i+1]<<16) | ((u32)p[4*i+2]<<8) | ((u32)p[4*i+3]);
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
    struct sha256_ctx ctx; sha_init(&ctx); sha_add(&ctx, p, n); sha_end(&ctx, dig);
}

/* ---- /proc/self/maps parser ---------------------------------------------- */
#define MAPS_CAP (256u * 1024u)
static char g_maps[MAPS_CAP];
static u64  g_maps_len;
static u8   g_iobuf[4096];
static u8   g_zeros[CP_CHUNK];

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
    *p = s; return v;
}
static u64 find_mapped_slice(const char *suffix, u64 file_off, u64 len, u8 req_perms,
                             char *path_out, u64 path_cap) {
    const char *p = g_maps, *end = g_maps + g_maps_len;
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
static int find_addr_path(u64 addr, char *path_out, u64 path_cap) {
    const char *p = g_maps, *end = g_maps + g_maps_len;
    while (p < end) {
        const char *line = p;
        while (p < end && *p != '\n') p++;
        u64 n = (u64)(p - line);
        if (p < end) p++;
        const char *q = line;
        u64 lo = parse_hex(&q); if (q >= line + n || *q != '-') continue; q++;
        u64 hi = parse_hex(&q); if (q >= line + n || *q != ' ') continue; q++;
        if (addr < lo || addr >= hi) continue;
        const char *s = q;
        while (s < line + n && *s != '/') s++;
        u64 k = 0;
        if (s < line + n && *s == '/') {
            for (; s < line + n && k + 1u < path_cap; s++) path_out[k++] = *s;
        }
        path_out[k] = 0;
        return 1;
    }
    return 0;
}
static int hash_disk_file(const char *path, u64 *out_sz, u8 dig[32]) {
    i64 fd = sys_open(path, O_RDONLY, 0);
    if (fd < 0) { *out_sz = 0; return 0; }
    struct sha256_ctx ctx; sha_init(&ctx);
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

/* ---- Runtime bindings & CP DMA engine ------------------------------------ */
typedef u64   (*fn_dmm_alloc_t)(u32 size, u32 *handle);
typedef u64   (*fn_dmm_free_t)(u32 handle);
typedef u32   (*fn_sen_dma_t)(u32 dir, u64 src, u64 dst, u32 size);
typedef void *(*fn_dlopen_t)(const char *path, int flags);
typedef void *(*fn_dlsym_t)(void *handle, const char *sym);
typedef int   (*fn_dlclose_t)(void *handle);
typedef int   (*fn_get_pack_t)(void);

static fn_dmm_alloc_t g_dmm_alloc;
static fn_dmm_free_t  g_dmm_free;
static fn_sen_dma_t   g_sen_dma;
static volatile int   g_ready;
static volatile int   g_cp_lock;

static u8 *g_cp_buf;
static u64 g_cp_phys;

static void cp_lock(void)   { while (__atomic_exchange_n(&g_cp_lock, 1, __ATOMIC_ACQUIRE) != 0) {} }
static void cp_unlock(void) { __atomic_store_n(&g_cp_lock, 0, __ATOMIC_RELEASE); }

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

static int cp_dma_write_chunked(u32 cp_va, const u8 *src, u32 total_len) {
    u32 off = 0;
    while (off < total_len) {
        u32 n = total_len - off;
        if (n > CP_CHUNK) n = CP_CHUNK;
        if (!cp_dma_write_contig(cp_va + off, src ? (src + off) : g_zeros, n)) return 0;
        off += n;
    }
    return 1;
}

static int cp_dma_check_chunked(u32 cp_va, const u8 *exp, u32 total_len) {
    u32 off = 0;
    while (off < total_len) {
        u32 n = total_len - off;
        if (n > CP_CHUNK) n = CP_CHUNK;
        u8 *p = cp_dma_read_span(cp_va + off, n, 0, 0);
        if (!p) return 0;
        if (exp ? !mem_eq(p, exp + off, n) : !mem_is_zero(p, n)) return 0;
        off += n;
    }
    return 1;
}

struct cp_session {
    u32 handle;
    i64 fd;
    i64 map_raw;
    u64 map_len;
};

static int cp_session_open(struct cp_session *s) {
    s->handle = 0; s->fd = -1; s->map_raw = -1; s->map_len = 0;
    g_cp_phys = g_dmm_alloc(CP_PAGE, &s->handle);
    if (!g_cp_phys || (g_cp_phys & 0x3FULL) || g_cp_phys < RAM_LO || (g_cp_phys + CP_PAGE) > RAM_HI) {
        if (s->handle) g_dmm_free(s->handle);
        s->handle = 0;
        return 0;
    }
    s->fd = sys_open("/dev/mem", O_RDWR_SYNC, 0);
    if (s->fd < 0) { g_dmm_free(s->handle); s->handle = 0; return 0; }
    u64 lead = g_cp_phys & 0xFFFULL;
    s->map_len = (lead + CP_PAGE + 0xFFFULL) & ~0xFFFULL;
    s->map_raw = sys_mmap_rw(s->fd, s->map_len, g_cp_phys - lead);
    if (s->map_raw == -1) {
        sys_close(s->fd); g_dmm_free(s->handle);
        s->fd = -1; s->handle = 0;
        return 0;
    }
    g_cp_buf = (u8 *)s->map_raw + lead;
    return 1;
}

static void cp_session_close(struct cp_session *s) {
    if (s->map_raw != -1) sys_munmap((void *)s->map_raw, s->map_len);
    if (s->fd >= 0) sys_close(s->fd);
    if (s->handle) g_dmm_free(s->handle);
    g_cp_buf = 0;
}

static int verify_cp_code_guards(void) {
    for (u32 i = 0; i < 3U; i++) {
        u8 *p = cp_dma_read_span(OG_ID_PAGES[i].cp_va, CP_PAGE, 0, 0);
        u8 dig[32];
        if (!p || (sha_buf(p, CP_PAGE, dig), !mem_eq(dig, OG_ID_PAGES[i].sha256, 32U))) return 0;
    }
    return 1;
}

/* ---- Core Look Pack Prober & Live Switcher (0=Stock, 1=FX2, 2=Fuji 8-Sim) - */
static int apply_look_pack_impl(int mode);

static int set_stock_pointers_and_pmaps(void) {
    /* 1. Restore mode[0,1,3,5] @ 0x00DE08CC to Stock FIRST so CP stops referencing aux descs */
    for (u32 i = 0; i < FUJI_MODE_COUNT; i++) {
        if (!cp_dma_write_contig(FUJI_MODES[i].cp_va, FUJI_MODES[i].stock, 8U)) return 0;
    }
    /* 2. Restore direct descriptors desc[37..44] to Stock */
    for (u32 i = 0; i < FUJI_DESC_COUNT; i++) {
        if (!cp_dma_write_contig(FUJI_DESCS[i].cp_va, FUJI_DESCS[i].stock, 28U)) return 0;
    }
    /* 3. Restore sparse 14-byte Chroma & Matrix pmaps to Stock */
    if (!cp_dma_write_pmap14(FUJI_U01_PMAP_BASE_VA, FUJI_PMAP14_STOCK)) return 0;
    if (!cp_dma_write_pmap14(FUJI_U0D_PMAP_BASE_VA, FUJI_PMAP14_STOCK)) return 0;
    /* 4. Zero all 8 unused aux descriptors now that NO mode references them */
    for (u32 i = 0; i < FUJI_AUX_DESC_COUNT; i++) {
        if (!cp_dma_write_contig(FUJI_AUX_DESCS[i].cp_va, g_zeros, 28U)) return 0;
    }
    return 1;
}

static int get_look_pack_impl(void) {
    if (!__atomic_load_n(&g_ready, __ATOMIC_ACQUIRE)) return -2;
    int res = -1;
    int need_heal = -1;
    cp_lock();
    struct cp_session s;
    if (cp_session_open(&s)) {
        int pm_mode = -1;
        u8 *pm = cp_dma_read_span(FUJI_U01_PMAP_BASE_VA, FUJI_PMAP_SPAN_LEN, 0, 0);
        if (pm) {
            if (pmap14_eq(pm, FUJI_PMAP14_NEW))               pm_mode = 2;
            else if (pmap14_eq(pm, LEGACY_FUJI4_U01_PMAP14))  pm_mode = 3; /* legacy 4-Sim -> upgrade to 8-Sim! */
            else if (pmap14_eq(pm, FUJI_PMAP14_FL23))         pm_mode = 1;
            else if (pmap14_eq(pm, FUJI_PMAP14_STOCK))        pm_mode = 0;
        }
        /* Separate DMA read (single bounce buffer!): verify desc[39] & mode[0] match volatile CP state */
        if (pm_mode == 0) {
            u8 *d39 = cp_dma_read_span(FUJI_DESCS[2].cp_va, 28U, 0, 0);
            if (d39 && mem_eq(d39, FUJI_DESCS[2].stock, 28U)) res = 0;
            else need_heal = 0;
        } else if (pm_mode == 1) {
            u8 *d39 = cp_dma_read_span(FL23_DESCS[0].cp_va, 28U, 0, 0);
            if (d39 && mem_eq(d39, FL23_DESCS[0].target, 28U)) res = 1;
            else need_heal = 1;
        } else if (pm_mode == 2) {
            u8 *d39 = cp_dma_read_span(FUJI_DESCS[2].cp_va, 28U, 0, 0);
            int d_ok = (d39 != 0) && mem_eq(d39, FUJI_DESCS[2].target, 28U);
            u8 *m0  = d_ok ? cp_dma_read_span(FUJI_MODES[0].cp_va, 8U, 0, 0) : 0;
            if (d_ok && m0 && mem_eq(m0, FUJI_MODES[0].target, 8U)) res = 2;
            else need_heal = 2;
        } else if (pm_mode == 3) {
            need_heal = 2;
        }
        cp_session_close(&s);
    }
    cp_unlock();

    /* Auto-heal warm-sleep partial CP reset or legacy 4-Sim WBI pmap in <15ms */
    if (need_heal >= 0) {
        if (apply_look_pack_impl(need_heal)) return need_heal;
        if (need_heal != 0 && apply_look_pack_impl(0)) return 0;
    }
    return res;
}

static int apply_look_pack_impl(int mode) {
    if (!__atomic_load_n(&g_ready, __ATOMIC_ACQUIRE)) return 0;
    if (mode < 0 || mode > 2) return 0;
    cp_lock();
    struct cp_session s;
    int ok = 0;
    if (!cp_session_open(&s)) { cp_unlock(); return 0; }
    if (!verify_cp_code_guards()) goto out;

    /* Verify live sparse pmaps are each one of our known states (checked separately: single DMA bounce buf!) */
    {
        u8 *m1 = cp_dma_read_span(FUJI_U01_PMAP_BASE_VA, FUJI_PMAP_SPAN_LEN, 0, 0);
        if (!m1) goto out;
        int m1_ok = pmap14_eq(m1, FUJI_PMAP14_STOCK) || pmap14_eq(m1, FUJI_PMAP14_FL23) ||
                    pmap14_eq(m1, FUJI_PMAP14_NEW)   || pmap14_eq(m1, LEGACY_FUJI4_U01_PMAP14);
        if (!m1_ok) goto out;

        u8 *m2 = cp_dma_read_span(FUJI_U0D_PMAP_BASE_VA, FUJI_PMAP_SPAN_LEN, 0, 0);
        if (!m2) goto out;
        int m2_ok = pmap14_eq(m2, FUJI_PMAP14_STOCK) || pmap14_eq(m2, FUJI_PMAP14_FL23) ||
                    pmap14_eq(m2, FUJI_PMAP14_NEW)   || pmap14_eq(m2, LEGACY_FUJI4_U0D_PMAP14);
        if (!m2_ok) goto out;
    }

    /* Step 1: Always park mode-table, descriptors, & sparse pmaps on Stock BEFORE rewriting slots 22..29! */
    if (!set_stock_pointers_and_pmaps()) goto out;

    if (mode == 0) {
        /* 0 = 100% Factory Stock: scrub all 8 slots (22..29) & both gamma caves */
        if (!cp_dma_write_chunked(FUJI_U01_SLOTS_VA, 0, FUJI_U01_SCRUB_LEN)) goto out;
        for (u32 sl = 0; sl < FUJI_U0D_SCRUB_SLOTS; sl++) {
            if (!cp_dma_write_chunked(FUJI_U0D_SLOTS_VA + sl * FUJI_U0D_SLOT_STRIDE, 0, FUJI_U0D_SLOT_STRIDE)) goto out;
        }
        if (!cp_dma_write_chunked(ALL_LOOKS_GAMMA_VA, 0, ALL_LOOKS_GAMMA_LEN)) goto out;

        /* Verify Stock readback */
        for (u32 i = 0; i < FUJI_MODE_COUNT; i++) {
            u8 *p = cp_dma_read_span(FUJI_MODES[i].cp_va, 8U, 0, 0);
            if (!p || !mem_eq(p, FUJI_MODES[i].stock, 8U)) goto out;
        }
        for (u32 i = 0; i < FUJI_DESC_COUNT; i++) {
            u8 *p = cp_dma_read_span(FUJI_DESCS[i].cp_va, 28U, 0, 0);
            if (!p || !mem_eq(p, FUJI_DESCS[i].stock, 28U)) goto out;
        }
        for (u32 i = 0; i < FUJI_AUX_DESC_COUNT; i++) {
            u8 *p = cp_dma_read_span(FUJI_AUX_DESCS[i].cp_va, 28U, 0, 0);
            if (!p || !mem_is_zero(p, 28U)) goto out;
        }
        if (!cp_dma_eq_pmap14(FUJI_U01_PMAP_BASE_VA, FUJI_PMAP14_STOCK) ||
            !cp_dma_eq_pmap14(FUJI_U0D_PMAP_BASE_VA, FUJI_PMAP14_STOCK)) goto out;
        if (!cp_dma_check_chunked(ALL_LOOKS_GAMMA_VA, 0, ALL_LOOKS_GAMMA_LEN)) goto out;
        ok = 1;
    } else if (mode == 1) {
        /* 1 = Sony FX2 FL2 (IN) & FL3 (SH) */
        if (!cp_dma_write_chunked(FL23_GAMMA_CAVE_VA, FL23_GAMMA_CURVES, FL23_GAMMA_CAVE_LEN)) goto out;
        if (!cp_dma_write_chunked(FUJI_GAMMA_CAVE_VA, 0, FUJI_GAMMA_CAVE_LEN)) goto out;
        if (!cp_dma_write_contig(FL23_U01_SLOTS_VA, FL23_U01_SLOTS_NEW, FL23_U01_SLOTS_LEN)) goto out;
        if (!cp_dma_write_contig(FL23_U01_SLOTS_VA + FL23_U01_SLOTS_LEN, g_zeros, FUJI_U01_SCRUB_LEN - FL23_U01_SLOTS_LEN)) goto out;
        if (!cp_dma_write_chunked(FL23_U0D_SLOTS_VA, FL23_U0D_SLOTS_NEW, FL23_U0D_SLOTS_LEN)) goto out;
        for (u32 sl = 4U; sl < FUJI_U0D_SCRUB_SLOTS; sl++) {
            if (!cp_dma_write_chunked(FUJI_U0D_SLOTS_VA + sl * FUJI_U0D_SLOT_STRIDE, 0, FUJI_U0D_SLOT_STRIDE)) goto out;
        }
        /* Flip pointers & sparse pmaps LAST */
        for (u32 i = 0; i < FL23_DESC_COUNT; i++) {
            if (!cp_dma_write_contig(FL23_DESCS[i].cp_va, FL23_DESCS[i].target, 28U)) {
                (void)set_stock_pointers_and_pmaps();
                goto out;
            }
        }
        if (!cp_dma_write_pmap14(FUJI_U01_PMAP_BASE_VA, FUJI_PMAP14_FL23) ||
            !cp_dma_write_pmap14(FUJI_U0D_PMAP_BASE_VA, FUJI_PMAP14_FL23)) {
            (void)set_stock_pointers_and_pmaps();
            goto out;
        }
        /* Verify FX2 readback (checked separately: single DMA bounce buf!) */
        if (!cp_dma_eq_pmap14(FUJI_U01_PMAP_BASE_VA, FUJI_PMAP14_FL23) ||
            !cp_dma_eq_pmap14(FUJI_U0D_PMAP_BASE_VA, FUJI_PMAP14_FL23)) {
            (void)set_stock_pointers_and_pmaps();
            goto out;
        }
        ok = 1;
    } else {
        /* 2 = Fujifilm 8-Sim (ST=Provia, PT=Astia, VV=Velvia, VV2=C.Neg, FL=C.Chrome, IN=ProNegHi, SH=Eterna, BW=Acros) */
        if (!cp_dma_write_chunked(FL23_GAMMA_CAVE_VA, 0, FL23_GAMMA_CAVE_LEN)) goto out;
        if (!cp_dma_write_chunked(FUJI_GAMMA_CAVE_VA, FUJI_GAMMA_CURVES, FUJI_GAMMA_CAVE_LEN)) goto out;
        /* Write 8 unused aux descriptors WHILE 0x00DE08CC still points to Stock! */
        for (u32 i = 0; i < FUJI_AUX_DESC_COUNT; i++) {
            if (!cp_dma_write_contig(FUJI_AUX_DESCS[i].cp_va, FUJI_AUX_DESCS[i].target, 28U)) goto out;
        }
        /* Write Chroma slots 22..28 + zero scrub slot 29 */
        if (!cp_dma_write_contig(FUJI_U01_SLOTS_VA, FUJI_U01_SLOTS_NEW, FUJI_U01_SLOTS_LEN)) goto out;
        if (!cp_dma_write_contig(FUJI_U01_SLOTS_VA + FUJI_U01_SLOTS_LEN, g_zeros, FUJI_U01_SCRUB_LEN - FUJI_U01_SLOTS_LEN)) goto out;
        /* Write Matrix slots 22..28 + zero scrub slot 29 */
        for (u32 sl = 0; sl < FUJI_U0D_SLOT_COUNT; sl++) {
            u32 sva = FUJI_U0D_SLOTS_VA + sl * FUJI_U0D_SLOT_STRIDE;
            const u8 *act = FUJI_U0D_ACTIVE_NEW + sl * FUJI_U0D_ACTIVE_LEN;
            if (!cp_dma_write_contig(sva, act, FUJI_U0D_ACTIVE_LEN) ||
                !cp_dma_write_contig(sva + FUJI_U0D_ACTIVE_LEN, g_zeros, FUJI_U0D_SLOT_STRIDE - FUJI_U0D_ACTIVE_LEN)) {
                goto out;
            }
        }
        for (u32 sl = FUJI_U0D_SLOT_COUNT; sl < FUJI_U0D_SCRUB_SLOTS; sl++) {
            if (!cp_dma_write_chunked(FUJI_U0D_SLOTS_VA + sl * FUJI_U0D_SLOT_STRIDE, 0, FUJI_U0D_SLOT_STRIDE)) goto out;
        }
        /* Flip direct descriptors, mode-table redirects, & sparse pmaps LAST */
        for (u32 i = 0; i < FUJI_DESC_COUNT; i++) {
            if (!cp_dma_write_contig(FUJI_DESCS[i].cp_va, FUJI_DESCS[i].target, 28U)) {
                (void)set_stock_pointers_and_pmaps();
                goto out;
            }
        }
        for (u32 i = 0; i < FUJI_MODE_COUNT; i++) {
            if (!cp_dma_write_contig(FUJI_MODES[i].cp_va, FUJI_MODES[i].target, 8U)) {
                (void)set_stock_pointers_and_pmaps();
                goto out;
            }
        }
        if (!cp_dma_write_pmap14(FUJI_U01_PMAP_BASE_VA, FUJI_PMAP14_NEW) ||
            !cp_dma_write_pmap14(FUJI_U0D_PMAP_BASE_VA, FUJI_PMAP14_NEW)) {
            (void)set_stock_pointers_and_pmaps();
            goto out;
        }
        /* Verify Fujifilm 8-Sim readback (checked separately: single DMA bounce buf!) */
        if (!cp_dma_eq_pmap14(FUJI_U01_PMAP_BASE_VA, FUJI_PMAP14_NEW) ||
            !cp_dma_eq_pmap14(FUJI_U0D_PMAP_BASE_VA, FUJI_PMAP14_NEW)) {
            (void)set_stock_pointers_and_pmaps();
            goto out;
        }
        for (u32 i = 0; i < FUJI_MODE_COUNT; i++) {
            u8 *pm = cp_dma_read_span(FUJI_MODES[i].cp_va, 8U, 0, 0);
            if (!pm || !mem_eq(pm, FUJI_MODES[i].target, 8U)) {
                (void)set_stock_pointers_and_pmaps();
                goto out;
            }
        }
        ok = 1;
    }

out:
    cp_session_close(&s);
    cp_unlock();
    return ok;
}

/* Exported symbols (NEVER referenced internally -> 0 R_AARCH64_GLOB_DAT!) */
__attribute__((visibility("default"))) int a6700_get_look_pack(void) {
    return get_look_pack_impl();
}
__attribute__((visibility("default"))) int a6700_apply_look_pack(int mode) {
    return apply_look_pack_impl(mode);
}

/* ---- Stage 1: Relocate self to volatile RAM /tmp_wbshd & pin globally ---- */
static int stage_self_to_ram_and_pin(const char *self_path, u64 libjit_base) {
    fn_dlopen_t  fn_dlopen  = (fn_dlopen_t)(libjit_base + LIBJIT_PLT_DLOPEN);
    fn_dlsym_t   fn_dlsym   = (fn_dlsym_t)(libjit_base + LIBJIT_PLT_DLSYM);
    fn_dlclose_t fn_dlclose = (fn_dlclose_t)(libjit_base + LIBJIT_PLT_DLCLOSE);
    i64 in_fd = sys_open(self_path, O_RDONLY, 0);
    if (in_fd < 0) return 0;
    i64 out_fd = sys_open(STAGE_RAM_SO, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (out_fd < 0) { sys_close(in_fd); return 0; }
    int copy_ok = 1;
    for (;;) {
        i64 r = sys_read(in_fd, g_iobuf, sizeof(g_iobuf));
        if (r < 0) { copy_ok = 0; break; }
        if (r == 0) break;
        i64 off = 0;
        while (off < r) {
            i64 w = sys_write(out_fd, g_iobuf + off, (u64)(r - off));
            if (w <= 0) { copy_ok = 0; break; }
            off += w;
        }
        if (!copy_ok) break;
    }
    sys_close(out_fd);
    sys_close(in_fd);
    if (!copy_ok) { (void)sys_unlink(STAGE_RAM_SO); return 0; }
    void *h = fn_dlopen(STAGE_RAM_SO, RTLD_NOW_GLOB);
    (void)sys_unlink(STAGE_RAM_SO);
    if (!h) return 0;
    fn_get_pack_t gp = (fn_get_pack_t)fn_dlsym(h, "a6700_get_look_pack");
    if (!gp || gp() == -2) (void)fn_dlclose(h);
    return 1;
}

__attribute__((visibility("default"))) void _init(void) {
    g_olen = 0;
    g_maps_len = read_text_file("/proc/self/maps", g_maps, sizeof(g_maps));

    char self_path[200]; self_path[0] = 0;
    (void)find_addr_path(read_cur_pc(), self_path, sizeof(self_path));

    u64 libjit_base = find_mapped_slice("/libJiritsu.so", 0, 4096, 5u, 0, 0);
    if (!libjit_base) {
        out_s("A6700_LOOKS_PACK_RAM_V1\nRESULT=ABORT_MAPS_MISSING\n");
        flush_result();
        return;
    }

    /* Stage 1: Transient /tmp/jiritsu/libJit.so -> relocate & pin in /tmp_wbshd */
    if (ends_with(self_path, slen(self_path), "/libJit.so")) {
        char jpath[200]; jpath[0] = 0;
        u64 jsz = 0; u8 jdig[32];
        (void)find_mapped_slice(OG_ID_FILES[2].suffix, 0, 4096, 5u, jpath, sizeof(jpath));
        if (!jpath[0] || !hash_disk_file(jpath, &jsz, jdig) ||
            jsz != OG_ID_FILES[2].size || !mem_eq(jdig, OG_ID_FILES[2].sha256, 32U)) {
            out_s("A6700_LOOKS_PACK_RAM_V1\nRESULT=ABORT_IDENTITY reason=libjit_sha_mismatch\n");
            flush_result();
            return;
        }
        fn_dlsym_t fn_dlsym = (fn_dlsym_t)(libjit_base + LIBJIT_PLT_DLSYM);
        void *existing = fn_dlsym((void *)0, "a6700_apply_look_pack");
        if (existing != 0) {
            char epath[200]; epath[0] = 0;
            if (find_addr_path((u64)existing, epath, sizeof(epath)) &&
                has_substr(epath, "a6700_looks_pack.so")) {
                out_s("A6700_LOOKS_PACK_RAM_V1\nRESULT=ALREADY_INSTALLED feature=looks_pack_ram_v2_8sim\n");
                flush_result();
                return;
            }
        }
        if (!stage_self_to_ram_and_pin(self_path, libjit_base)) {
            out_s("A6700_LOOKS_PACK_RAM_V1\nRESULT=ABORT_RAM_STAGE_FAIL\n");
            flush_result();
        }
        return;
    }

    /* Stage 2: Pinned in volatile RAM! Lock libsencore + 3 CP pure-code pages */
    out_s("A6700_LOOKS_PACK_RAM_V1 " FUJI_RAM_LABEL " self="); out_s(self_path); out_s("\n");
    int sencore_ok = 0;
    for (u32 i = 0; i < OG_ID_FILE_COUNT; i++) {
        const struct og_id_file *f = &OG_ID_FILES[i];
        char path[200]; path[0] = 0;
        u64 base = find_mapped_slice(f->suffix, 0, 4096, 5u, path, sizeof(path));
        u64 fsz = 0; u8 dig[32];
        if (!path[0] || !base || !hash_disk_file(path, &fsz, dig) ||
            fsz != f->size || !mem_eq(dig, f->sha256, 32U)) {
            out_s("RESULT=ABORT_IDENTITY reason=lib_sha_mismatch lib="); out_s(f->suffix); out_s("\n");
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
        out_s("RESULT=ABORT_IDENTITY reason=sencore_prologue\n");
        flush_result();
        return;
    }

    struct cp_session s;
    if (!cp_session_open(&s)) {
        out_s("RESULT=ABORT_CP_SESSION\n");
        flush_result();
        return;
    }
    int guards_ok = verify_cp_code_guards();
    cp_session_close(&s);
    if (!guards_ok) {
        out_s("RESULT=ABORT_IDENTITY reason=cp_page_mismatch\n");
        flush_result();
        return;
    }

    __atomic_store_n(&g_ready, 1, __ATOMIC_RELEASE);
    int cur = get_look_pack_impl();
    out_s("CURRENT_PACK="); out_u64((u64)(cur >= 0 ? cur : 9)); out_s(" (0=Stock 1=FX2 2=Fuji8Sim)\n");
    out_s("RESULT=APPLY_OK feature=looks_pack_ram_v2 packs=Stock,FX2_FL23,Fuji8Sim_XMP\n");
    flush_result();
}
