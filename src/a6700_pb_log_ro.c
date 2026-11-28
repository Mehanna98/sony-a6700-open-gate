/* a6700_pb_log_ro.c -- 100% READ-ONLY Main-Processor Playback + CP kprint Log Dumper for Sony a6700 (v2.00).
 *
 * STRICT ZERO-WRITE SAFETY DESIGN:
 *   1. Freestanding AArch64 ELF (DT_INIT = _init, DT_NEEDED = 0, 0 libc deps, < 65,536 B).
 *   2. Exact 6-syscall READ-ONLY surface: openat(56), close(57), read(63), write(64), munmap(215), mmap(222).
 *      ZERO mprotect(226), ZERO pwrite64(68), ZERO PROT_WRITE in mmap(222).
 *   3. /dev/mem opened strictly O_RDONLY (or O_RDONLY | O_SYNC); mmap strictly PROT_READ (1) | MAP_SHARED (1).
 *   4. Reads Sony's reserved AP log ring buffer at physical 0x405000000 (verified via /proc/cmdline
 *      memrsv=0x01000000@0x405000000):
 *        - Decoder area   : +0x232000..+0x290000 (DECHANDLER / IMLDECSTAT / playback create_ch & errors)
 *        - Media area     : +0x1ce000..+0x232000 (MPR / playback / error lines)
 *        - Application    : +0x000000..+0x0f0000 (PB_ / Play / error lines)
 *      Plus CP kprint ring buffer (0x000E0000) via read-only sen_dma_transfer(dir=0).
 *   5. Output written ONLY to /tmp/jiritsu/rampatch.result (deleted same-session by runner).
 */
#include "a6700_og_probe_spec.h"

#define NR_openat   56
#define NR_close    57
#define NR_read     63
#define NR_write    64
#define NR_munmap   215
#define NR_mmap     222

#define AT_FDCWD      (-100)
#define O_RDONLY      0
#define O_RDONLY_SYNC 0x101000
#define O_WRONLY      1
#define O_CREAT       0x40
#define O_TRUNC       0x200

#define PROT_READ     1
#define MAP_SHARED    1

#define CP_PAGE       4096U
#define RAM_LO        0x400000000ULL
#define RAM_HI        0x500000000ULL
#define LOGB_PHYS     0x405000000ULL
#define LOGB_RESERVE  "memrsv=0x01000000@0x405000000"
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
__attribute__((noinline)) static i64 sys_mmap_ro(i64 fd, u64 len, u64 off) {
    i64 r = sc6(NR_mmap, 0, (i64)len, PROT_READ, MAP_SHARED, fd, (i64)off);
    return (r < 0 && r > -4096) ? -1 : r;
}

/* Single-shot Jiritsu result buffer (60 KiB < 65,536 B channel limit) */
#define OUTCAP (60u * 1024u)
static char g_out[OUTCAP];
static u32  g_olen;

static void out_c(u8 c) { if (g_olen < OUTCAP - 1u) g_out[g_olen++] = (char)c; }
__attribute__((noinline)) static void out_s(const char *s) {
    if (!s) return;
    while (*s) out_c((u8)*s++);
}
__attribute__((noinline)) static void out_buf(const u8 *s, u64 n) {
    for (u64 i = 0; i < n; i++) out_c(s[i]);
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

static u64 slen(const char *s) { u64 n = 0; while (s[n]) n++; return n; }
static int mem_eq(const u8 *a, const u8 *b, u64 n) {
    for (u64 i = 0; i < n; i++) if (a[i] != b[i]) return 0;
    return 1;
}
static int has_sub(const u8 *s, u64 len, const char *pat) {
    u64 pl = slen(pat);
    if (!pl || pl > len) return 0;
    for (u64 i = 0; i + pl <= len; i++) {
        if (mem_eq(s + i, (const u8 *)pat, pl)) return 1;
    }
    return 0;
}
static int ends_with(const char *s, u64 n, const char *suf) {
    u64 m = slen(suf);
    if (n < m) return 0;
    return mem_eq((const u8 *)s + (n - m), (const u8 *)suf, m);
}
static u32 rd_u32(const u8 *p) {
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

/* ---- Minimal SHA-256 (for locking libsencore.so before CP kprint RO DMA) ---- */
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
    s->h[0]+=a; s->h[1]+=b; s->h[2]+=c; s->h[3]+=d; s->h[4]+=e; s->h[5]+=f; s->h[6]+=g; s->h[7]+=h;
}
static void sha_init(struct sha256_ctx *s) {
    s->h[0]=0x6a09e667u; s->h[1]=0xbb67ae85u; s->h[2]=0x3c6ef372u; s->h[3]=0xa54ff53au;
    s->h[4]=0x510e527fu; s->h[5]=0x9b05688cu; s->h[6]=0x1f83d9abu; s->h[7]=0x5be0cd19u;
    s->len = 0; s->fill = 0;
}
static void sha_upd(struct sha256_ctx *s, const u8 *p, u64 n) {
    s->len += n;
    while (n) {
        u64 k = 64u - s->fill;
        if (k > n) k = n;
        for (u64 i = 0; i < k; i++) s->blk[s->fill + i] = p[i];
        s->fill += (u32)k; p += k; n -= k;
        if (s->fill == 64u) { sha_blk(s, s->blk); s->fill = 0; }
    }
}
static void sha_fin(struct sha256_ctx *s, u8 out[32]) {
    u64 bits = s->len * 8ULL;
    u8 z = 0x80; sha_upd(s, &z, 1); z = 0;
    while (s->fill != 56u) sha_upd(s, &z, 1);
    u8 lb[8];
    for (int i = 0; i < 8; i++) lb[i] = (u8)(bits >> (56 - 8*i));
    sha_upd(s, lb, 8);
    for (int i = 0; i < 8; i++) {
        out[4*i+0]=(u8)(s->h[i]>>24); out[4*i+1]=(u8)(s->h[i]>>16);
        out[4*i+2]=(u8)(s->h[i]>>8);  out[4*i+3]=(u8)(s->h[i]);
    }
}

static char g_cmdline[2048];
static char g_maps[128 * 1024];
static u64  g_maps_len;
static u8   g_iobuf[4096];

static u64 read_text_file(const char *path, char *buf, u64 cap) {
    i64 fd = sys_open(path, O_RDONLY, 0);
    if (fd < 0) return 0;
    u64 tot = 0;
    while (tot + 1 < cap) {
        i64 n = sys_read(fd, buf + tot, cap - 1 - tot);
        if (n <= 0) break;
        tot += (u64)n;
    }
    sys_close(fd);
    buf[tot] = 0;
    return tot;
}

static int parse_hex(const char *s, u64 *i, u64 n, u64 *out) {
    u64 v = 0; int got = 0;
    while (*i < n) {
        char c = s[*i]; u64 d;
        if (c >= '0' && c <= '9') d = (u64)(c - '0');
        else if (c >= 'a' && c <= 'f') d = (u64)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') d = (u64)(c - 'A' + 10);
        else break;
        v = (v << 4) | d; (*i)++; got = 1;
    }
    *out = v; return got;
}

static u64 find_mapped_slice(const char *suffix, u64 file_off, u64 len, u32 need_perm,
                             char *path_out, u64 path_cap) {
    u64 i = 0, n = g_maps_len;
    while (i < n) {
        u64 ls = i;
        while (i < n && g_maps[i] != '\n') i++;
        u64 le = i; if (i < n) i++;
        u64 p = ls, va0 = 0, va1 = 0, off = 0;
        if (!parse_hex(g_maps, &p, le, &va0)) continue;
        if (p >= le || g_maps[p++] != '-') continue;
        if (!parse_hex(g_maps, &p, le, &va1)) continue;
        if (p >= le || g_maps[p++] != ' ') continue;
        if (p + 4 > le) continue;
        u32 pm = (g_maps[p]=='r'?1u:0u) | (g_maps[p+1]=='w'?2u:0u) | (g_maps[p+2]=='x'?4u:0u);
        p += 4;
        if ((pm & need_perm) != need_perm) continue;
        if (p >= le || g_maps[p++] != ' ') continue;
        if (!parse_hex(g_maps, &p, le, &off)) continue;
        int sp = 0;
        while (p < le && sp < 3) {
            while (p < le && g_maps[p] == ' ') p++;
            if (sp < 2) { while (p < le && g_maps[p] != ' ') p++; }
            sp++;
        }
        if (p >= le || g_maps[p] != '/') continue;
        u64 plen = le - p;
        if (!ends_with(g_maps + p, plen, suffix)) continue;
        u64 seg_len = va1 - va0;
        if (file_off >= off && file_off + len <= off + seg_len) {
            if (path_out && path_cap > 0) {
                u64 k = plen < path_cap - 1 ? plen : path_cap - 1;
                for (u64 j = 0; j < k; j++) path_out[j] = g_maps[p + j];
                path_out[k] = 0;
            }
            return va0 + (file_off - off);
        }
    }
    return 0;
}

static int hash_disk_file(const char *path, u64 *size_out, u8 digest[32]) {
    i64 fd = sys_open(path, O_RDONLY, 0);
    if (fd < 0) return 0;
    struct sha256_ctx ctx; sha_init(&ctx);
    u64 tot = 0;
    for (;;) {
        i64 n = sys_read(fd, g_iobuf, sizeof(g_iobuf));
        if (n < 0) { sys_close(fd); return 0; }
        if (n == 0) break;
        sha_upd(&ctx, g_iobuf, (u64)n);
        tot += (u64)n;
    }
    sys_close(fd);
    sha_fin(&ctx, digest);
    *size_out = tot;
    return 1;
}

/* ---- Main-processor RAM log ring dump (0x405000000, strictly PROT_READ) ---- */
static int log_wanted(const u8 *s, u64 len, int filtered) {
    static const char *const repeats[] = {
        "IMOLA CH[", "FmcTx TopFldBufWidth", "[ENCHANDLER]",
        "[IMLENCSTAT]", "[ENCSTATE_I]", "Enc CreateCh Done"
    };
    static const char *const names[] = {
        "ERR", "Err", "err", "FAIL", "fail", "NG", "unsupported", "aspect",
        "2560", "0x498", "0x47c", "0x47e", "Cannot", "Movie", "DEC_", "Dec",
        "PB_", "Play", "MPR", "level", "Level", "UseCore", "IMLDEC", "DECHANDLER", "VLD"
    };
    if (!filtered) {
        for (u32 k = 0; k < (u32)(sizeof(repeats) / sizeof(repeats[0])); k++) {
            if (has_sub(s, len, repeats[k])) return 0;
        }
        return 1;
    }
    for (u32 k = 0; k < (u32)(sizeof(names) / sizeof(names[0])); k++) {
        if (has_sub(s, len, names[k])) return 1;
    }
    return 0;
}

static void dump_log_area(i64 fd, const char *title, u64 from, u64 to,
                          int filtered, u32 max_lines, u32 budget) {
    const u64 WIN = 256ULL * 1024ULL;
    u32 start_olen = g_olen;
    u32 count = 0;
    out_s("-- "); out_s(title); out_s(" "); out_hex(from); out_s(".."); out_hex(to); out_s("\n");
    for (u64 off = from; off < to && count < max_lines && (g_olen - start_olen) < budget; off += WIN) {
        u64 len = (to - off) < WIN ? (to - off) : WIN;
        i64 m = sys_mmap_ro(fd, len, LOGB_PHYS + off);
        if (m == -1) {
            out_s("!! mmap_ro failed @ "); out_hex(LOGB_PHYS + off); out_s("\n");
            break;
        }
        const u8 *p = (const u8 *)m;
        for (u64 i = 0; i < len && count < max_lines && (g_olen - start_olen) < budget; ) {
            while (i < len && !(p[i] >= 32u && p[i] < 127u)) i++;
            u64 s = i;
            while (i < len && p[i] >= 32u && p[i] < 127u) i++;
            u64 rlen = i - s;
            if (rlen < 10u || !log_wanted(p + s, rlen, filtered)) continue;
            out_s("  [+"); out_hex(off + s); out_s("] ");
            out_buf(p + s, rlen > 180u ? 180u : rlen);
            out_s("\n");
            count++;
        }
        sys_munmap((void *)m, len);
    }
    out_s("   lines="); out_u64(count); out_s("\n");
}

/* ---- Read-only CP kprint dump (0x000E0000 via sen_dma_transfer dir=0 ONLY) --- */
typedef u64 (*fn_dmm_alloc_t)(u32 size, u32 *handle_out);
typedef int (*fn_dmm_free_t)(u32 handle);
typedef u32 (*fn_sen_dma_t)(u32 dir, u64 cp_addr, u64 ap_phys, u32 size);

__attribute__((noinline))
static int cp_dma_ro_page(fn_sen_dma_t fn_dma, u32 cp_page, u64 ap_phys) {
    if (fn_dma(0U, (u64)cp_page, ap_phys, CP_PAGE) != 0U) return 0;
    __asm__ volatile("dsb sy" ::: "memory");
    return 1;
}

static void dump_cp_kprint_ro(void) {
    const struct og_id_file *f = &OG_ID_FILES[0]; /* /libsencore.so */
    char path[200]; path[0] = 0;
    u64 base = find_mapped_slice(f->suffix, 0, 4096, 5u, path, sizeof(path));
    u64 fsz = 0; u8 dig[32];
    if (!path[0] || !base || !hash_disk_file(path, &fsz, dig) ||
        fsz != f->size || !mem_eq(dig, f->sha256, 32)) {
        out_s("== cp kprint: SKIP (libsencore hash mismatch)\n");
        return;
    }
    u64 a_alloc = find_mapped_slice(f->suffix, SENCORE_DMM_ALLOC_OFF, 8, 5u, 0, 0);
    u64 a_free  = find_mapped_slice(f->suffix, SENCORE_DMM_FREE_OFF,  8, 5u, 0, 0);
    u64 a_dma   = find_mapped_slice(f->suffix, SENCORE_DMA_XFER_OFF,  8, 5u, 0, 0);
    if (!a_alloc || !a_free || !a_dma ||
        !mem_eq((const u8 *)a_alloc, SENCORE_PROL_ALLOC, 8) ||
        !mem_eq((const u8 *)a_free,  SENCORE_PROL_FREE,  8) ||
        !mem_eq((const u8 *)a_dma,   SENCORE_PROL_DMA,   8)) {
        out_s("== cp kprint: SKIP (libsencore prologue mismatch)\n");
        return;
    }
    fn_dmm_alloc_t fn_alloc = (fn_dmm_alloc_t)a_alloc;
    fn_dmm_free_t  fn_free  = (fn_dmm_free_t)a_free;
    fn_sen_dma_t   fn_dma   = (fn_sen_dma_t)a_dma;

    u32 handle = 0;
    u64 phys = fn_alloc(CP_PAGE, &handle);
    if (!phys || (phys & 0x3FULL) || phys < RAM_LO || (phys + CP_PAGE) > RAM_HI) {
        if (handle) fn_free(handle);
        out_s("== cp kprint: SKIP (dmm_alloc failed)\n");
        return;
    }
    i64 fd = sys_open("/dev/mem", O_RDONLY_SYNC, 0);
    if (fd < 0) {
        fn_free(handle);
        out_s("== cp kprint: SKIP (devmem open failed)\n");
        return;
    }
    u64 lead = phys & 0xFFFULL;
    u64 maplen = (lead + CP_PAGE + 0xFFFULL) & ~0xFFFULL;
    i64 mapped = sys_mmap_ro(fd, maplen, phys - lead);
    if (mapped == -1) {
        sys_close(fd);
        fn_free(handle);
        out_s("== cp kprint: SKIP (mmap_ro failed)\n");
        return;
    }
    const u8 *buf = (const u8 *)mapped + lead;

    /* Read kprint header @ 0x019D7F70 (page 0x019D7000, +0xF70) */
    if (cp_dma_ro_page(fn_dma, 0x019D7000U, phys)) {
        u32 base_va = rd_u32(buf + 0xF70U);
        u32 wpos    = rd_u32(buf + 0xF74U);
        u32 wrap    = rd_u32(buf + 0xF78U);
        out_s("== cp kprint base="); out_hex(base_va);
        out_s(" wpos="); out_u64(wpos);
        out_s(" wrap="); out_u64(wrap); out_s("\n");
        if (base_va >= 0x00080000U && base_va <= 0x03800000U && (base_va & 0xFFFU) == 0U && wpos > 0U && wpos <= 0x100000U) {
            u32 last_pg = (wpos - 1U) & ~0xFFFU;
            u32 start_pg = (last_pg >= CP_PAGE) ? (last_pg - CP_PAGE) : 0U;
            for (u32 pg = start_pg; pg <= last_pg && g_olen < OUTCAP - 128u; pg += CP_PAGE) {
                if (!cp_dma_ro_page(fn_dma, base_va + pg, phys)) break;
                u32 lim = (pg == last_pg) ? (wpos - pg) : CP_PAGE;
                if (lim > CP_PAGE) lim = CP_PAGE;
                for (u32 i = 0; i < lim && g_olen < OUTCAP - 128u; i++) {
                    u8 c = buf[i];
                    if ((c >= 32u && c < 127u) || c == '\n' || c == '\t') out_c(c);
                }
            }
            out_s("\n");
        }
    }

    sys_munmap((void *)mapped, maplen);
    sys_close(fd);
    fn_free(handle);
}

__attribute__((visibility("default"))) void _init(void) {
    g_olen = 0;
    out_s("A6700_PB_LOG_RO_V1 mode=READ_ONLY_ZERO_WRITE\n");

    u64 cmd_n = read_text_file("/proc/cmdline", g_cmdline, sizeof(g_cmdline));
    g_maps_len = read_text_file("/proc/self/maps", g_maps, sizeof(g_maps));

    if (!has_sub((const u8 *)g_cmdline, cmd_n, LOGB_RESERVE)) {
        out_s("RESULT=ABORT_CMDLINE missing=" LOGB_RESERVE "\n");
        flush_result();
        return;
    }

    i64 fd = sys_open("/dev/mem", O_RDONLY, 0);
    if (fd < 0) {
        out_s("RESULT=ERR_DEVMEM_OPEN\n");
        flush_result();
        return;
    }

    out_s("== main-processor log (playback, read-only @ 0x405000000)\n");
    dump_log_area(fd, "decoder area",     0x232000ULL, 0x290000ULL, 0, 420u, 32768u);
    dump_log_area(fd, "media area (err)", 0x1ce000ULL, 0x232000ULL, 1, 160u, 12288u);
    dump_log_area(fd, "app area (err)",   0x000000ULL, 0x0f0000ULL, 1,  80u,  6144u);
    out_s("== end main-processor log\n");
    sys_close(fd);

    dump_cp_kprint_ro();
    out_s("RESULT=PB_LOG_OK\n");
    flush_result();
}
