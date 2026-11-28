/* a6700_og_menu_ram.c -- 100% Zero-Flash RAM-Only Native Sony Menu Toggle for Open Gate v6.2.1 + SD Bypass.
 *
 * Target: Sony ILCE-6700 (a6700) FW v2.00 ONLY (stock SHA-256 + appFw.so GOT verified).
 *
 * ZERO-FLASH RESIDENT ARCHITECTURE:
 *   1. Stage 1 (loaded as /tmp/jiritsu/libJit.so):
 *        - Checks appFw.so GOT (refuses double-install -> ALREADY_INSTALLED).
 *        - Copies itself to volatile RAM tmpfs /tmp_wbshd/a6700_og_menu.so (0 flash writes!),
 *          calls dlopen(..., RTLD_NOW) via libJiritsu.so's verified PLT stub (+0x63F0),
 *          then IMMEDIATELY unlinks /tmp_wbshd/a6700_og_menu.so (and dlclose on abort).
 *        - Returns cleanly so libJiritsu.so dlclose()s /tmp/jiritsu/libJit.so and the host runner
 *          deletes the /tmp/jiritsu scratch files — leaving 0 files on flash and keeping Jiritsu 100% usable.
 *   2. Stage 2 (permanently pinned in volatile RAM until battery pull):
 *        - Runs PASS 0 identity lock (CTR_EL0 VIPT/PIPT, /proc/cmdline, SHA-256 of libsencore/libmpr/libJiritsu,
 *          3 cpapp-b.bin code pages, 3 av-cam.bin guards, 3 whole-page PB code guards mapped+kview, 56B PB guard).
 *        - Auto-detects PAL (50 Hz) vs NTSC (60 Hz) from CSDrvParam[0x0820] + 0x2c.
 *        - Pre-expands DmmCfg 0x57f (0x01341200 -> 0x016D5A00 = 3980x6016) while in Stills mode so
 *          toggling Open Gate ON <-> OFF works unlimited times from Movie mode without ever rebooting.
 *        - Installs native Sony menu "Open Gate" in Setup -> Operation Customize (Group 0x535, Slot 12),
 *          adapted from verified Pilot-main a6700 v2.00 appFw.so GOT hooks:
 *            * Row 0: "4K Open Gate (3:2)"  [ON / OFF]  (atomic 572 PAL / 553 NTSC toggle + seq 0xCA/0x32F reload)
 *            * Row 1: "SD Speed Bypass"     [ON / OFF]  (atomic 20B libmpr.so toggle)
 *          Plus live Movie File Format badge ("XAVC S 4K OG" / "XAVC HS 4K OG" / "XAVC S-I 4K OG") when ON.
 *   3. Cold boot (10-second battery pull) wipes all RAM -> 100% untouched factory stock.
 */
#include "a6700_og_patch_spec.h"
#include "a6700_sd_bypass_spec.h"
#include "a6700_cine_ei_compact.h"

/* ---- Exact 9-syscall surface (ZERO pwrite64, ZERO flash writes) ---------- */
#define NR_unlinkat 35
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
#define MAP_ANON_PRIV 0x22

#define CP_PAGE       4096U
#define RAM_LO        0x400000000ULL
#define RAM_HI        0x500000000ULL
#define RESULT_PATH   "/tmp/jiritsu/rampatch.result"
#define STAGE_RAM_SO  "/tmp_wbshd/a6700_og_menu.so"
#define RTLD_NOW_LOC  2 /* RTLD_NOW (2) | RTLD_LOCAL (0); pinned by never calling dlclose on success */

/* ---- Verified stock ILCE-6700 v2.00 PLT, GOT & function offsets ---------- */
/* Use libJiritsu.so verified .plt stubs (100% safe with lazy PLT binding!) */
#define LIBJIT_PLT_DLSYM          0x60E0ULL
#define LIBJIT_PLT_DLOPEN         0x63F0ULL
#define LIBJIT_PLT_DLCLOSE        0x64B0ULL

#define APPFW_GOT_MENU_TABLE      0x4EA8A68ULL
#define APPFW_MENU_TABLE_OFF      0x44B8AB0ULL
#define APPFW_MENU_TABLE_SIZE     0xF908ULL
#define APPFW_CUSTOM_GROUP_OFF    0xDE68ULL
#define APPFW_CUSTOM_SLOT12_OFF   0xDF98ULL
#define APPFW_CUSTOM_STOCK_COUNT  12U
#define APPFW_COLOR_GROUP_OFF     0x6890ULL
#define APPFW_COLOR_SLOT7_OFF     0x6948ULL
#define APPFW_COLOR_STOCK_COUNT   7U
#define APPFW_MAP_PID_SUPPORT_VA  0x138BD888ULL

#define APPFW_STOCK_DESC_293_OFF  0x4BF0090ULL
#define APPFW_STOCK_ITEM_DESC_OFF 0x4BF8828ULL
#define APPFW_DESC_SIZE           0x60ULL
#define APPFW_ITEM_ENTRY_SIZE     0x10ULL
#define APPFW_ITEM_DESC_SIZE      0xB0ULL
#define APPFW_VISIBILITY_OK_OFF   0x2351858ULL
#define APPFW_GOT_NONSETTING_TREE 0x4EA32E0ULL
#define APPFW_NONSETTING_TREE_OFF 0x8394BE0ULL
#define APPFW_TREE_INSERT_OFF     0x236C014ULL

#define APPFW_GOT_PAGE_TABLE      0x4E48818ULL
#define APPFW_PAGE_TABLE_OFF      0x44CA518ULL
#define APPFW_PAGE_ENTRY_SIZE     0x58ULL
#define APPFW_PAGE_STOCK_COUNT    0x42CU

#define APPFW_GOT_LAYOUT_293      0x4E77818ULL
#define APPFW_LAYOUT_293_OFF      0x508C270ULL

#define APPFW_VIEW_FACTORY_293_OFF 0x25CB2ECULL
#define APPFW_CTRL_FACTORY_293_OFF 0x252DD08ULL
#define APPFW_293_ON_ENTER_OFF     0x29EB2ECULL
#define APPFW_293_GET_FOCUSED_OFF  0x29EAAC4ULL
#define APPFW_293_GENERIC_OPEN_OFF 0x29EAB8CULL
#define APPFW_293_CURSOR_OBJ_OFF   0x11B38ULL
#define APPFW_CURSOR_FOCUS_ITEM_OFF 0x2185CE0ULL

#define APPFW_GOT_BTN_CONFIRM     0x4ED84A0ULL
#define APPFW_BTN_CONFIRM_OFF     0x29EB830ULL
#define APPFW_GOT_BTN_BACK        0x4E666F8ULL
#define APPFW_BTN_BACK_OFF        0x29EBB1CULL
#define APPFW_GOT_BTN_BACK2       0x4EDE688ULL
#define APPFW_BTN_BACK2_OFF       0x29EC030ULL
#define APPFW_GOT_SET_STRING_RID  0x4F1FE98ULL
#define APPFW_GOT_ISNAV_TABLE     0x4E5B430ULL

#define APPFW_GET_CUR_GROUP_OFF   0x2F731D8ULL
#define APPFW_GET_SEL_ROW_OFF     0x2F73228ULL
#define APPFW_GET_CUR_ITEM_OFF    0x2F73278ULL

#define APPFW_STOCK_OPT_DESC_OFF  0x4BE5F58ULL
#define APPFW_STOCK_OPT_ROW_OFF   0x4BB14F8ULL
#define APPFW_OPT_DESC_SIZE       0xB0ULL
#define APPFW_OPT_ROW_SIZE        0xA0ULL
#define APPFW_ACCESSOR_VTABLE_OFF 0x4B4DBD0ULL
#define APPFW_ACCESSOR_HDR_QWS    2U
#define APPFW_ACCESSOR_SLOTS      313U
#define APPFW_GOT_2A7_CONFIRM     0x4F19520ULL
#define APPFW_2A7_CONFIRM_OFF     0x29ED258ULL
#define APPFW_2A7_GET_FOCUSED_OFF 0x29ECE68ULL
#define APPFW_2A7_CLOSE_OFF       0x29ED1D0ULL

/* Native 0x260 Processing Dialog (verified on stock ILCE-6700 v2.00 appFw.so) */
#define OG_BUSY_SCREEN_ID         0x260U
#define OG_BUSY_MSG_RID           0x0200606CU
#define APPFW_CTRL_FACTORY_260_OFF 0x250E390ULL
#define APPFW_260_HANDLE_OFF      0x11B20ULL
#define APPFW_260_MGR_OFF         0x11B28ULL

/* appFw live video pipeline reload (seq 0xCA + seq 0x32F) */
#define APPFW_GET_SEQ_MGR_OFF       0x328B434ULL
#define APPFW_SEQ_SET_MOVIE_FMT_OFF 0x33164ACULL
#define APPFW_SEQ_DISP_UPDATE_OFF   0x33CDE20ULL
#define APPFW_SEQ_IS_RUNNING_OFF    0x32C7694ULL
#define APPFW_SEQ_ID_MOVIE_FMT      0xCAU
#define APPFW_SEQ_ID_DISP_UPDATE    0x32FU

/* Sony native Movie File Format RIDs */
#define RID_XAVC_HS_4K 0x0200856FU
#define RID_XAVC_S_4K  0x0200851EU
#define RID_XAVC_SI_4K 0x020086B8U

/* Virtual menu IDs & RIDs (identical namespace to verified Pilot Menu UI) */
#define OG_GROUP_ID            0x535U
#define OG_OPT_GROUP_ID        0x536U
#define LOOK_GROUP_ID          0x537U
#define LOOK_OPT_GROUP_ID      0x538U

#define OG_ITEM_ID_BASE        0x1F00U
#define LOOK_ITEM_ID_BASE      0x1F10U
#define OG_OPT_CHOICE_BASE     0x2000U
#define OG_LIST_VAL_KEY_BASE   0x2020U
#define LOOK_OPT_CHOICE_BASE   0x2040U
#define LOOK_LIST_VAL_KEY_BASE 0x2060U

#define OG_LIST_SCREEN_ID      0x293U
#define OG_OPT_SCREEN_ID       0x2A7U
#define OG_GENERIC_SKIP        0x42BU

#define OG_RID_MENU_LABEL      0x02FFFF00U
#define OG_RID_OPT_TITLE       0x02FFFF04U
#define LOOK_RID_MENU_LABEL    0x02FFFF08U
#define LOOK_RID_OPT_TITLE     0x02FFFF0CU
#define OG_RID_ITEM_BASE       0x02FFFF20U
#define LOOK_RID_ITEM_BASE     0x02FFFF30U
#define OG_RID_OPT_CHOICE      0x02FFFF60U
#define LOOK_RID_OPT_CHOICE    0x02FFFF70U
#define OG_RID_VAL_BASE        0x02FFFF80U
#define LOOK_RID_VAL_BASE      0x02FFFF90U
#define OG_RID_HELP_BASE       0x02FFFFA0U
#define LOOK_RID_HELP_BASE     0x02FFFFB0U
#define LOOK_RID_OPT_HELP      0x02FFFFC0U
#define OG_RID_EMPTY           0x02FFFFFEU

#define OG_ROW_COUNT           4U
#define LOOK_ROW_COUNT         6U
#define LOOK_PACK_COUNT        3U
#define OG_VTABLE_SLOTS        32U

/* ---- Syscall wrappers ---------------------------------------------------- */
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
__attribute__((noinline)) static i64 sys_open(const char *p, i64 fl, i64 mode)    { return sc6(NR_openat, AT_FDCWD, (i64)p, fl, mode, 0, 0); }
__attribute__((noinline)) static i64 sys_read(i64 fd, void *b, u64 n)             { return sc6(NR_read, fd, (i64)b, (i64)n, 0, 0, 0); }
__attribute__((noinline)) static i64 sys_write(i64 fd, const void *b, u64 n)      { return sc6(NR_write, fd, (i64)b, (i64)n, 0, 0, 0); }
__attribute__((noinline)) static i64 sys_pread64(i64 fd, void *b, u64 n, u64 off) { return sc6(NR_pread64, fd, (i64)b, (i64)n, (i64)off, 0, 0); }
__attribute__((noinline)) static i64 sys_close(i64 fd)                            { return sc6(NR_close, fd, 0, 0, 0, 0, 0); }
__attribute__((noinline)) static i64 sys_unlink(const char *p)                    { return sc6(NR_unlinkat, AT_FDCWD, (i64)p, 0, 0, 0, 0); }
__attribute__((noinline)) static i64 sys_munmap(void *p, u64 len)                 { return sc6(NR_munmap, (i64)p, (i64)len, 0, 0, 0, 0); }
__attribute__((noinline)) static i64 sys_mprotect(u64 addr, u64 len, i64 prot)    { return sc6(NR_mprotect, (i64)addr, (i64)len, prot, 0, 0, 0); }
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
static u64 read_ctr_el0(void) { u64 v; __asm__ volatile("mrs %0, ctr_el0" : "=r"(v)); return v; }
static inline u64 read_cur_pc(void) { u64 pc; __asm__ volatile("adr %0, ." : "=r"(pc)); return pc; }

/* ---- Minimal freestanding helpers ---------------------------------------- */
static u64 slen(const char *s) { u64 n = 0; while (s[n]) n++; return n; }
static int mem_eq(const u8 *a, const u8 *b, u64 n) {
    for (u64 i = 0; i < n; i++) if (a[i] != b[i]) return 0;
    return 1;
}
static void mem_cpy(void *dst, const void *src, u64 n) {
    u8 *d = (u8 *)dst; const u8 *s = (const u8 *)src;
    for (u64 i = 0; i < n; i++) d[i] = s[i];
}
static int ends_with(const char *s, u64 n, const char *suf) {
    u64 m = slen(suf);
    if (n < m) return 0;
    return mem_eq((const u8 *)s + (n - m), (const u8 *)suf, m);
}
static u32 rd_u32(const u8 *p) {
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}
static void flush_icache_range(u64 start, u64 len) {
    u64 end = start + len;
    for (u64 p = start & ~63ULL; p < end; p += 64ULL) __asm__ volatile("dc cvau, %0" :: "r"(p) : "memory");
    __asm__ volatile("dsb ish" ::: "memory");
    for (u64 p = start & ~63ULL; p < end; p += 64ULL) __asm__ volatile("ic ivau, %0" :: "r"(p) : "memory");
    __asm__ volatile("dsb ish\nisb" ::: "memory");
}
static void clean_dcache_range(u64 start, u64 len) {
    u64 end = start + len;
    for (u64 p = start & ~63ULL; p < end; p += 64ULL) __asm__ volatile("dc civac, %0" :: "r"(p) : "memory");
    __asm__ volatile("dsb sy" ::: "memory");
}

/* ---- Result logger (used during _init only) ------------------------------ */
#define OUTCAP 8192U
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

/* ---- /proc/self/maps & /proc/cmdline ------------------------------------- */
#define MAPS_CAP (256u * 1024u)
static char g_maps[MAPS_CAP];
static u64  g_maps_len;
static char g_cmdline[2048];
static u8   g_iobuf[4096];

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
static int cmdline_has(const char *needle) {
    u64 m = slen(needle);
    for (u64 i = 0; g_cmdline[i]; i++)
        if (mem_eq((const u8 *)(g_cmdline + i), (const u8 *)needle, m)) return 1;
    return 0;
}
static u64 find_mapped_slice(const char *suffix, u64 file_off, u64 len, u8 req_perms,
                             u8 *out_perms, char *path_out, u64 path_cap) {
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
            if (out_perms) *out_perms = perms;
        }
    }
    return found;
}
static int find_addr_info(u64 addr, u8 *out_perms, char *path_out, u64 path_cap) {
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
        u8 perms = 0;
        if (q + 4 <= line + n) {
            if (q[0] == 'r') perms |= 1u;
            if (q[1] == 'w') perms |= 2u;
            if (q[2] == 'x') perms |= 4u;
        }
        if (out_perms) *out_perms = perms;
        if (path_out && path_cap > 0) {
            const char *s = line + n;
            while (s > line && s[-1] != ' ') s--;
            u64 k = 0;
            if (s < line + n && *s == '/') {
                for (; s < line + n && k + 1u < path_cap; s++) path_out[k++] = *s;
            }
            path_out[k] = 0;
        }
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

/* ---- Global runtime bindings (valid for the lifetime of appFw process) --- */
typedef u64  (*fn_dmm_alloc_t)(u32 size, u32 *handle);
typedef u64  (*fn_dmm_free_t)(u32 handle);
typedef u32  (*fn_sen_dma_t)(u32 dir, u64 src, u64 dst, u32 size);
typedef void *(*fn_dlopen_t)(const char *path, int flags);
typedef void *(*fn_dlsym_t)(void *handle, const char *sym);
typedef int   (*fn_dlclose_t)(void *handle);
typedef int   (*fn_pthread_create_t)(u64 *tid, const void *attr, void *(*start)(void *), void *arg);
typedef int   (*fn_pthread_detach_t)(u64 tid);
typedef int   (*fn_usleep_t)(u32 usec);
typedef int   (*fn_get_look_pack_t)(void);
typedef int   (*fn_apply_look_pack_t)(int mode);

static fn_dmm_alloc_t       g_dmm_alloc;
static fn_dmm_free_t        g_dmm_free;
static fn_sen_dma_t         g_sen_dma;
static fn_pthread_create_t  g_pthread_create;
static fn_pthread_detach_t  g_pthread_detach;
static fn_usleep_t          g_usleep;
static fn_get_look_pack_t   g_get_look_pack;
static fn_apply_look_pack_t g_apply_look_pack;

static u64 g_appfw_base;
static u64 g_libmpr_base;
static u64 g_libjit_base;
static int g_is_pal = -1;
static u32 g_dmm_base;

/* Transient CP/av-cam session state (only live while a patch/probe runs) */
static u8 *g_cp_buf;
static u64 g_cp_phys;
static u8  g_scan_win[CP_PAGE + 64U];

struct pb_map { i64 res_raw; u8 *page_va; };
static struct pb_map g_pb_code[OG_PB_CODE_PAGE_COUNT];
static i64 g_pb_data_raw = -1;
static u8 *g_pb_data_va;
static u8  g_pb_tmp[4096];

/* ---- Safe COW writers (libmpr.so & appFw.so GOT) ------------------------- */
static int cow_write_va(u64 va, const u8 *src, u64 len, int is_code, int restore_ro) {
    u64 pg_start = va & ~4095ULL;
    u64 pg_end   = (va + len + 4095ULL) & ~4095ULL;
    u64 pg_len   = pg_end - pg_start;
    i64 rw_prot  = PROT_READ | PROT_WRITE | (is_code ? PROT_EXEC : 0);
    if (sys_mprotect(pg_start, pg_len, rw_prot) != 0) return 0;
    if (is_code && ((va & 3ULL) == 0ULL) && ((len & 3ULL) == 0ULL)) {
        volatile u32 *dst32 = (volatile u32 *)va;
        for (u64 i = 0; i < len; i += 4ULL)
            __atomic_store_n(&dst32[i >> 2], rd_u32(src + i), __ATOMIC_RELEASE);
        flush_icache_range(va, len);
    } else if (len == 8ULL && ((va & 7ULL) == 0ULL)) {
        u64 val = (u64)rd_u32(src) | ((u64)rd_u32(src + 4) << 32);
        __atomic_store_n((volatile u64 *)va, val, __ATOMIC_RELEASE);
        __asm__ volatile("dsb ish" ::: "memory");
    } else {
        volatile u8 *dst = (volatile u8 *)va;
        for (u64 i = 0; i < len; i++) dst[i] = src[i];
        __asm__ volatile("dsb ish" ::: "memory");
    }
    if (restore_ro)
        (void)sys_mprotect(pg_start, pg_len, PROT_READ | (is_code ? PROT_EXEC : 0));
    return mem_eq((const u8 *)va, src, len);
}

static int cow_write_libmpr(u64 file_off, const u8 *src, u64 len) {
    /* libmpr.so ELF segments are contiguous relative to g_libmpr_base for text/rodata;
     * use cached /proc/self/maps lookup for exact VA & original perms. */
    u8 perms = 0;
    u64 va = find_mapped_slice("/libmpr.so", file_off, len, 1u, &perms, 0, 0);
    if (!va) return 0;
    return cow_write_va(va, src, len, (perms & 4u) != 0u, !(perms & 2u));
}

static int patch_got_ptr(u64 got_va, u64 expected, u64 replacement) {
    u64 cur = __atomic_load_n((volatile u64 *)got_va, __ATOMIC_ACQUIRE);
    if (cur != expected) return 0;
    u8 perms = 3u;
    (void)find_addr_info(got_va, &perms, 0, 0);
    u8 rep[8];
    for (int i = 0; i < 8; i++) rep[i] = (u8)(replacement >> (8 * i));
    return cow_write_va(got_va, rep, 8ULL, 0, !(perms & 2u));
}

/* ---- CP DMA helpers ------------------------------------------------------ */
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
static int av_kview_eq(i64 av_fd, u64 file_off, const u8 *exp, u32 len) {
    u8 tmp[16];
    if (len > 16U) return 0;
    if (sys_pread64(av_fd, tmp, len, OG_AVCAM_PHYS + file_off) != (i64)len) return 0;
    return mem_eq(tmp, exp, len);
}

/* ---- DmmCfg 0x57f locator & pre-expander (3980x6016 = 0x016D5A00) -------- */
#define OG_DMM_SITE_COUNT 4U
struct og_dmm_site { u32 off; u8 stock[4]; u8 target[4]; };
static const struct og_dmm_site OG_DMM_SITES[OG_DMM_SITE_COUNT] = {
    { 0x00000004U, {0x00,0x12,0x34,0x01}, {0x00,0x5a,0x6d,0x01} },
    { 0x00000018U, {0x00,0x12,0x34,0x01}, {0x00,0x5a,0x6d,0x01} },
    { 0x0000002CU, {0x00,0x12,0x34,0x01}, {0x00,0x5a,0x6d,0x01} },
    { 0x0000011CU, {0x00,0x12,0x34,0x01}, {0x00,0x5a,0x6d,0x01} },
};
static const u8 DMM_SIG_8A_TGT[40] = {
    0x7f,0x05,0x00,0x00, 0x00,0x5a,0x6d,0x01, 0x0f,0x01,0x00,0x00, 0x00,0x00,0x00,0x00, 0x07,0x00,0x00,0x00,
    0x7f,0x05,0x00,0x00, 0x00,0x5a,0x6d,0x01, 0x0f,0x01,0x00,0x00, 0x00,0x00,0x00,0x00, 0x07,0x00,0x00,0x00
};

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
    if (g_dmm_base && verify_dmmcfg_anchors(g_dmm_base)) return g_dmm_base;
    static const struct { u32 lo; u32 hi; } ranges[3] = {
        { 0x02000000U, 0x02800000U }, { 0x01220000U, 0x02000000U }, { 0x02800000U, 0x03400000U },
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
                    g_scan_win[o + 7U] == 0x01U &&
                    (mem_eq(g_scan_win + o, DMM_SIG_8A, 40U) || mem_eq(g_scan_win + o, DMM_SIG_8A_TGT, 40U))) {
                    u32 hit_va = (page - 64U) + o;
                    if (verify_dmmcfg_anchors(hit_va)) { g_dmm_base = hit_va; return hit_va; }
                }
            }
            for (u32 i = 0; i < 64U; i++) g_scan_win[i] = g_scan_win[CP_PAGE + i];
            have_prev = 1;
        }
    }
    return 0U;
}
static int ensure_dmm57f_expanded(void) {
    u32 base = locate_dmmcfg_base();
    if (!base) return 0;
    int need_write = 0;
    for (u32 i = 0; i < OG_DMM_SITE_COUNT; i++) {
        u8 *p = cp_dma_read_span(base + OG_DMM_SITES[i].off, 4U, 0, 0);
        if (!p) return 0;
        if (mem_eq(p, OG_DMM_SITES[i].stock, 4U)) need_write = 1;
        else if (!mem_eq(p, OG_DMM_SITES[i].target, 4U)) return 0;
    }
    if (!need_write) return 1;
    u8 *p_eh = cp_dma_read_span(0x019D7BCCU, 4U, 0, 0);
    if (p_eh) {
        u32 ext_hash = rd_u32(p_eh);
        if (ext_hash >= OG_CP_LO && (ext_hash + 0x57fU * 8U + 8U) <= OG_CP_HI) {
            u8 *p_h57f = cp_dma_read_span(ext_hash + 0x57fU * 8U, 4U, 0, 0);
            if (p_h57f && rd_u32(p_h57f) != 0U) return 0; /* already divided! */
        }
    }
    for (u32 i = 0; i < OG_DMM_SITE_COUNT; i++) {
        if (!cp_dma_write_contig(base + OG_DMM_SITES[i].off, OG_DMM_SITES[i].target, 4U)) return 0;
    }
    return 1;
}

/* ---- VIPT Playback Code Page helpers ------------------------------------- */
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
    mem_cpy(g_pb_tmp, src_4k, 4096ULL);
    for (u32 s = 0; s < OG_PB_CODE_SITE_COUNT; s++) {
        if (OG_PB_CODE_SITES[s].page_idx != p) continue;
        u32 lo = OG_PB_CODE_SITES[s].file_off - OG_PB_CODE_PAGES[p].page_off;
        g_pb_tmp[lo] = 0; g_pb_tmp[lo+1U] = 0; g_pb_tmp[lo+2U] = 0; g_pb_tmp[lo+3U] = 0;
    }
    u8 dig[32]; sha_buf(g_pb_tmp, 4096ULL, dig);
    return mem_eq(dig, OG_PB_CODE_PAGES[p].masked_sha256, 32U);
}
static int pb_map_all(i64 av_mem_fd) {
    for (u32 i = 0; i < OG_PB_CODE_PAGE_COUNT; i++) { g_pb_code[i].res_raw = -1; g_pb_code[i].page_va = 0; }
    g_pb_data_raw = -1; g_pb_data_va = 0;
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
    if (g_pb_data_raw != -1) { sys_munmap((void *)g_pb_data_raw, 4096ULL); g_pb_data_raw = -1; g_pb_data_va = 0; }
    for (u32 i = 0; i < OG_PB_CODE_PAGE_COUNT; i++) {
        if (g_pb_code[i].res_raw != -1) {
            sys_munmap((void *)g_pb_code[i].res_raw, OG_AVCAM_VIPT_ALIGN + 4096ULL);
            g_pb_code[i].res_raw = -1; g_pb_code[i].page_va = 0;
        }
    }
}

/* ---- Unified Atomic Open Gate v6.2.1 Toggle Engine (ON <-> OFF) ---------- */
static const u8 OG_H2160_BYTES[4] = { 0x70, 0x08, 0x00, 0x00 };
static const u8 OG_H2560_BYTES[4] = { 0x00, 0x0a, 0x00, 0x00 };

static int og_run_toggle_atomic(int enable) {
    int ok = 0;
    u32 dmm_handle = 0;
    g_cp_phys = g_dmm_alloc(CP_PAGE, &dmm_handle);
    if (!g_cp_phys || (g_cp_phys & 0x3FULL) || g_cp_phys < RAM_LO || (g_cp_phys + CP_PAGE) > RAM_HI) {
        if (dmm_handle) g_dmm_free(dmm_handle);
        return 0;
    }
    i64 cp_fd = sys_open("/dev/mem", O_RDWR_SYNC, 0);
    if (cp_fd < 0) { g_dmm_free(dmm_handle); return 0; }
    u64 cp_lead = g_cp_phys & 0xFFFULL;
    u64 cp_maplen = (cp_lead + CP_PAGE + 0xFFFULL) & ~0xFFFULL;
    i64 cp_map = sys_mmap_rw(cp_fd, cp_maplen, g_cp_phys - cp_lead);
    if (cp_map == -1) { sys_close(cp_fd); g_dmm_free(dmm_handle); return 0; }
    g_cp_buf = (u8 *)cp_map + cp_lead;

    i64 av_fd = sys_open("/dev/mem", O_RDWR, 0);
    if (av_fd < 0) {
        sys_munmap((void *)cp_map, cp_maplen); sys_close(cp_fd); g_dmm_free(dmm_handle); return 0;
    }
    i64 av_map_raw = sys_mmap_rw(av_fd, OG_AVCAM_PATCH_MAP_HI, OG_AVCAM_PHYS);
    if (av_map_raw == -1) {
        sys_close(av_fd); sys_munmap((void *)cp_map, cp_maplen); sys_close(cp_fd); g_dmm_free(dmm_handle); return 0;
    }
    u8 *av_map = (u8 *)av_map_raw;
    if (!pb_map_all(av_fd)) goto out_unmap;

    /* Guard check: 3 PB code pages (mapped + kview) + 56B PB data guard + 3 CP code pages */
    for (u32 i = 0; i < 3U; i++) {
        u8 *p = cp_dma_read_span(OG_ID_PAGES[i].cp_va, CP_PAGE, 0, 0);
        u8 dig[32];
        if (!p || (sha_buf(p, CP_PAGE, dig), !mem_eq(dig, OG_ID_PAGES[i].sha256, 32U))) goto out_unmap;
    }
    for (u32 p = 0; p < OG_PB_CODE_PAGE_COUNT; p++) {
        if (!pb_verify_masked_page(p, g_pb_code[p].page_va)) goto out_unmap;
        if (sys_pread64(av_fd, g_iobuf, 4096ULL, OG_AVCAM_PHYS + OG_PB_CODE_PAGES[p].page_off) != 4096 ||
            !pb_verify_masked_page(p, g_iobuf)) goto out_unmap;
    }
    if (!mem_eq(g_pb_data_va + (OG_PB_DATA_GUARD_OFF - OG_PB_DATA_PAGE_OFF), OG_PB_DATA_GUARD, OG_PB_DATA_GUARD_LEN))
        goto out_unmap;

    /* Ensure DmmCfg 0x57f = 0x016D5A00 when enabling (handles warm-sleep CP reset too!) */
    if (enable && !ensure_dmm57f_expanded()) goto out_unmap;

    int is_pal = g_is_pal;
    if (is_pal < 0) goto out_unmap;

    /* PASS 1: Dry-verify every site is strictly STOCK or TARGET before writing 1 byte */
    for (u32 i = 0; i < OG_CP_CELL_COUNT; i++) {
        const struct og_cp_cell *c = &OG_CP_CELLS[i];
        u8 *p = cp_dma_read_span(c->cp_va, c->len, 0, 0);
        if (!p || (!mem_eq(p, c->stock, c->len) && !mem_eq(p, c->target, c->len))) goto out_unmap;
    }
    if (is_pal) {
        for (u32 i = 0; i < OG_CP50_CELL_COUNT; i++) {
            const struct og_cp_cell *c = &OG_CP50_CELLS[i];
            u8 *p = cp_dma_read_span(c->cp_va, c->len, 0, 0);
            if (!p || (!mem_eq(p, c->stock, c->len) && !mem_eq(p, c->target, c->len))) goto out_unmap;
        }
    }
    for (u32 i = 0; i < OG_LCDFILL_CELL_COUNT; i++) {
        const struct og_cp_cell8 *c = &OG_LCDFILL_CELLS[i];
        u8 *p = cp_dma_read_span(c->cp_va, c->len, 0, 0);
        if (!p || (!mem_eq(p, c->stock, c->len) && !mem_eq(p, c->target, c->len))) goto out_unmap;
    }
    for (u32 i = 0; i < OG_ISP_REC_COUNT; i++) {
        const struct og_isp_rec *r = &OG_ISP_RECS[i];
        if (r->pal_only && !is_pal) continue;
        u8 *p = cp_dma_read_span(r->cp_va, 3000U, 0, 0);
        u8 dig[32];
        if (!p || (sha_buf(p, 3000ULL, dig), !mem_eq(dig, r->stock_sha, 32U) && !mem_eq(dig, r->target_sha, 32U))) goto out_unmap;
    }
    for (u32 i = 0; i < OG_COL1_DRV_COUNT; i++) {
        const struct og_col1_drv *d = &OG_COL1_DRVS[i];
        u8 *p = cp_dma_read_span(d->cp_va, CP_DRVPARAM_LEN, 0, 0);
        const u8 *old_b = is_pal ? d->pal_old : d->ntsc_old;
        const u8 *new_b = is_pal ? d->pal_new : d->ntsc_new;
        if (!p || rd_u32(p + 0x2CU) != (is_pal ? d->pal_vtot : d->ntsc_vtot)) goto out_unmap;
        if (!cp_check_sparse(p, OG_DRV_COL1_OFFS, old_b, OG_DRV_COL1_DIFFS) &&
            !cp_check_sparse(p, OG_DRV_COL1_OFFS, new_b, OG_DRV_COL1_DIFFS)) goto out_unmap;
    }
    if (is_pal) {
        u8 *p5 = cp_dma_read_span(CP_DRVPARAM_830, CP_DRVPARAM_LEN, 0, 0);
        if (!p5 || rd_u32(p5 + 0x2CU) != OG_VTOT_830_PAL) goto out_unmap;
        if (!cp_check_sparse(p5, OG_DRV_830_OFFS, OG_DRV_830_OLD, OG_DRV_830_COUNT) &&
            !cp_check_sparse(p5, OG_DRV_830_OFFS, OG_DRV_830_NEW, OG_DRV_830_COUNT)) goto out_unmap;
    }
    {
        u8 *pS = cp_dma_read_span(OG_SIZETBL_GUARD0_VA, 16U, 0, 0);
        if (!pS || !mem_eq(pS, OG_SIZETBL_GUARD0, 8U) || !mem_eq(pS + 12U, OG_SIZETBL_GUARD1, 4U)) goto out_unmap;
        if (!mem_eq(pS + 8U, OG_SIZETBL_OLD, 4U) && !mem_eq(pS + 8U, OG_SIZETBL_NEW, 4U)) goto out_unmap;
    }
    for (u32 i = 0; i < OG_LIBMPR_SITE_COUNT; i++) {
        const struct og_mp_site *s = &OG_LIBMPR_SITES[i];
        u64 va = find_mapped_slice("/libmpr.so", s->file_off, s->len, 1u, 0, 0, 0);
        if (!va || (!mem_eq((const u8 *)va, s->stock, s->len) && !mem_eq((const u8 *)va, s->target, s->len))) goto out_unmap;
    }
    for (u32 i = 0; i < OG_AVCAM_BLOB_COUNT; i++) {
        const struct og_av_patch *p = &OG_AVCAM_BLOBS[i];
        const u8 *cur = av_map + p->file_off;
        if (!mem_eq(cur, p->stock, p->len) && !mem_eq(cur, p->target, p->len)) goto out_unmap;
    }
    for (u32 i = 0; i < OG_AVCAM_HPATCH_COUNT; i++) {
        u32 pk = OG_AVCAM_HPACKED[i]; u32 off = pk & 0x7FFFFFFFU; u8 len = (pk & 0x80000000U) ? 4U : 2U;
        const u8 *cur = av_map + off;
        if (!mem_eq(cur, OG_H2160_BYTES, len) && !mem_eq(cur, OG_H2560_BYTES, len)) goto out_unmap;
    }
    for (u32 i = 0; i < OG_PB_CODE_SITE_COUNT; i++) {
        const struct og_pb_code_site *s = &OG_PB_CODE_SITES[i];
        const u8 *cur = g_pb_code[s->page_idx].page_va + (s->file_off - OG_PB_CODE_PAGES[s->page_idx].page_off);
        if (!mem_eq(cur, s->stock, 4U) && !mem_eq(cur, s->target, 4U)) goto out_unmap;
    }
    {
        const u8 *cur = g_pb_data_va + (OG_PB_DATA_SITE_OFF - OG_PB_DATA_PAGE_OFF);
        if (!mem_eq(cur, OG_PB_DATA_OLD, 4U) && !mem_eq(cur, OG_PB_DATA_NEW, 4U)) goto out_unmap;
    }

    /* PASS 2: Write in safe hardware order!
     *   When disabling (enable==0): PB data FIRST -> PB code -> M19/libmpr -> CP tables
     *   When enabling  (enable==1): CP tables -> libmpr/M19 -> PB code FIRST -> PB data LAST */
    if (!enable) {
        u8 *pd = g_pb_data_va + (OG_PB_DATA_SITE_OFF - OG_PB_DATA_PAGE_OFF);
        if (!mem_eq(pd, OG_PB_DATA_OLD, 4U)) {
            __atomic_store_n((volatile u32 *)pd, rd_u32(OG_PB_DATA_OLD), __ATOMIC_RELEASE);
            clean_dcache_range((u64)pd, 4ULL);
        }
        int touched_c = 0;
        for (u32 i = 0; i < OG_PB_CODE_SITE_COUNT; i++) {
            const struct og_pb_code_site *s = &OG_PB_CODE_SITES[i];
            u8 *p = g_pb_code[s->page_idx].page_va + (s->file_off - OG_PB_CODE_PAGES[s->page_idx].page_off);
            if (!mem_eq(p, s->stock, 4U)) {
                __atomic_store_n((volatile u32 *)p, rd_u32(s->stock), __ATOMIC_RELEASE);
                touched_c = 1;
            }
        }
        if (touched_c) pb_sync_all_code_icache();
    }

    /* CP tables (Col-1 cells, PAL 50p cells, LCD fill, ISP recs, CSDrvParams, SizeTbl) */
    for (u32 i = 0; i < OG_CP_CELL_COUNT; i++) {
        const struct og_cp_cell *c = &OG_CP_CELLS[i];
        const u8 *want = enable ? c->target : c->stock;
        u8 *p = cp_dma_read_span(c->cp_va, c->len, 0, 0);
        if (!p || !mem_eq(p, want, c->len)) { if (!cp_dma_write_contig(c->cp_va, want, c->len)) goto out_unmap; }
    }
    if (is_pal) {
        for (u32 i = 0; i < OG_CP50_CELL_COUNT; i++) {
            const struct og_cp_cell *c = &OG_CP50_CELLS[i];
            const u8 *want = enable ? c->target : c->stock;
            u8 *p = cp_dma_read_span(c->cp_va, c->len, 0, 0);
            if (!p || !mem_eq(p, want, c->len)) { if (!cp_dma_write_contig(c->cp_va, want, c->len)) goto out_unmap; }
        }
    }
    for (u32 i = 0; i < OG_LCDFILL_CELL_COUNT; i++) {
        const struct og_cp_cell8 *c = &OG_LCDFILL_CELLS[i];
        const u8 *want = enable ? c->target : c->stock;
        u8 *p = cp_dma_read_span(c->cp_va, c->len, 0, 0);
        if (!p || !mem_eq(p, want, c->len)) { if (!cp_dma_write_contig(c->cp_va, want, c->len)) goto out_unmap; }
    }
    for (u32 i = 0; i < OG_ISP_REC_COUNT; i++) {
        const struct og_isp_rec *r = &OG_ISP_RECS[i];
        if (r->pal_only && !is_pal) continue;
        const u8 *want_sha = enable ? r->target_sha : r->stock_sha;
        const u8 *want_val = enable ? r->target : r->stock;
        u8 *p = cp_dma_read_span(r->cp_va, 3000U, 0, 0);
        u8 dig[32];
        if (!p || (sha_buf(p, 3000ULL, dig), !mem_eq(dig, want_sha, 32U))) {
            if (!cp_dma_write_sparse(r->cp_va, 3000U, r->offs, want_val, r->count)) goto out_unmap;
        }
    }
    for (u32 i = 0; i < OG_COL1_DRV_COUNT; i++) {
        const struct og_col1_drv *d = &OG_COL1_DRVS[i];
        const u8 *want = enable ? (is_pal ? d->pal_new : d->ntsc_new) : (is_pal ? d->pal_old : d->ntsc_old);
        u8 *p = cp_dma_read_span(d->cp_va, CP_DRVPARAM_LEN, 0, 0);
        if (!p || !cp_check_sparse(p, OG_DRV_COL1_OFFS, want, OG_DRV_COL1_DIFFS)) {
            if (!cp_dma_write_sparse(d->cp_va, CP_DRVPARAM_LEN, OG_DRV_COL1_OFFS, want, OG_DRV_COL1_DIFFS)) goto out_unmap;
        }
    }
    if (is_pal) {
        const u8 *want = enable ? OG_DRV_830_NEW : OG_DRV_830_OLD;
        u8 *p5 = cp_dma_read_span(CP_DRVPARAM_830, CP_DRVPARAM_LEN, 0, 0);
        if (!p5 || !cp_check_sparse(p5, OG_DRV_830_OFFS, want, OG_DRV_830_COUNT)) {
            if (!cp_dma_write_sparse(CP_DRVPARAM_830, CP_DRVPARAM_LEN, OG_DRV_830_OFFS, want, OG_DRV_830_COUNT)) goto out_unmap;
        }
    }
    {
        const u8 *want = enable ? OG_SIZETBL_NEW : OG_SIZETBL_OLD;
        u8 *pS = cp_dma_read_span(OG_SIZETBL_SITE_VA, 4U, 0, 0);
        if (!pS || !mem_eq(pS, want, 4U)) {
            if (!cp_dma_write_contig(OG_SIZETBL_SITE_VA, want, 4U)) goto out_unmap;
        }
    }

    /* libmpr.so (exact 8 verified sites) + av-cam.bin (475 M19 sites) */
    for (u32 i = 0; i < OG_LIBMPR_SITE_COUNT; i++) {
        const struct og_mp_site *s = &OG_LIBMPR_SITES[i];
        const u8 *want = enable ? s->target : s->stock;
        u64 va = find_mapped_slice("/libmpr.so", s->file_off, s->len, 1u, 0, 0, 0);
        if (!va || !mem_eq((const u8 *)va, want, s->len)) {
            if (!cow_write_libmpr(s->file_off, want, s->len)) goto out_unmap;
        }
    }
    for (u32 i = 0; i < OG_AVCAM_BLOB_COUNT; i++) {
        const struct og_av_patch *p = &OG_AVCAM_BLOBS[i];
        const u8 *want = enable ? p->target : p->stock;
        u8 *dst = av_map + p->file_off;
        if (!mem_eq(dst, want, p->len)) {
            for (u8 k = 0; k < p->len; k++) dst[k] = want[k];
            clean_dcache_range((u64)dst, p->len);
        }
    }
    for (u32 i = 0; i < OG_AVCAM_HPATCH_COUNT; i++) {
        u32 pk = OG_AVCAM_HPACKED[i]; u32 off = pk & 0x7FFFFFFFU; u8 len = (pk & 0x80000000U) ? 4U : 2U;
        const u8 *want = enable ? OG_H2560_BYTES : OG_H2160_BYTES;
        u8 *dst = av_map + off;
        if (!mem_eq(dst, want, len)) {
            for (u8 k = 0; k < len; k++) dst[k] = want[k];
            clean_dcache_range((u64)dst, len);
        }
    }

    if (enable) {
        int touched_c = 0;
        for (u32 i = 0; i < OG_PB_CODE_SITE_COUNT; i++) {
            const struct og_pb_code_site *s = &OG_PB_CODE_SITES[i];
            u8 *p = g_pb_code[s->page_idx].page_va + (s->file_off - OG_PB_CODE_PAGES[s->page_idx].page_off);
            if (!mem_eq(p, s->target, 4U)) {
                __atomic_store_n((volatile u32 *)p, rd_u32(s->target), __ATOMIC_RELEASE);
                touched_c = 1;
            }
        }
        if (touched_c) pb_sync_all_code_icache();
        u8 *pd = g_pb_data_va + (OG_PB_DATA_SITE_OFF - OG_PB_DATA_PAGE_OFF);
        if (!mem_eq(pd, OG_PB_DATA_NEW, 4U)) {
            __atomic_store_n((volatile u32 *)pd, rd_u32(OG_PB_DATA_NEW), __ATOMIC_RELEASE);
            clean_dcache_range((u64)pd, 4ULL);
        }
    }

    /* PASS 3: Verify key sites end-to-end incl. pread64 kernel view! */
    for (u32 i = 0; i < OG_PB_CODE_SITE_COUNT; i++) {
        const struct og_pb_code_site *s = &OG_PB_CODE_SITES[i];
        const u8 *want = enable ? s->target : s->stock;
        const u8 *cur = g_pb_code[s->page_idx].page_va + (s->file_off - OG_PB_CODE_PAGES[s->page_idx].page_off);
        if (!mem_eq(cur, want, 4U) || !av_kview_eq(av_fd, s->file_off, want, 4U)) goto out_unmap;
    }
    {
        const u8 *want = enable ? OG_PB_DATA_NEW : OG_PB_DATA_OLD;
        if (!mem_eq(g_pb_data_va + (OG_PB_DATA_SITE_OFF - OG_PB_DATA_PAGE_OFF), want, 4U) ||
            !av_kview_eq(av_fd, OG_PB_DATA_SITE_OFF, want, 4U)) goto out_unmap;
    }
    for (u32 i = 0; i < OG_AVCAM_BLOB_COUNT; i++) {
        const struct og_av_patch *p = &OG_AVCAM_BLOBS[i];
        const u8 *want = enable ? p->target : p->stock;
        if (!av_kview_eq(av_fd, p->file_off, want, p->len)) goto out_unmap;
    }
    {
        const u8 *want = enable ? OG_SIZETBL_NEW : OG_SIZETBL_OLD;
        u8 *pS = cp_dma_read_span(OG_SIZETBL_SITE_VA, 4U, 0, 0);
        if (!pS || !mem_eq(pS, want, 4U)) goto out_unmap;
    }
    ok = 1;

out_unmap:
    pb_unmap_all();
    sys_munmap((void *)av_map_raw, OG_AVCAM_PATCH_MAP_HI);
    sys_close(av_fd);
    sys_munmap((void *)cp_map, cp_maplen);
    sys_close(cp_fd);
    g_dmm_free(dmm_handle);
    g_cp_buf = 0;
    return ok;
}

/* ---- Reversible Power-Off Shutter Curtain (FEAT_SHUTTER = 1, AP-RAM only) - */
#define SHUTTER_BYTE_COUNT 9U
#define SHUTTER_PID_COUNT  2U
#define SHUTTER_EXCL_COUNT 6U

static const u64 SHUTTER_BYTE_VAS[SHUTTER_BYTE_COUNT] = {
    0x03f17334ULL, 0x03f1773cULL, 0x04beeb90ULL, 0x04c2d8f2ULL, 0x04c2ff9aULL,
    0x04c3003aULL, 0x04c362baULL, 0x04c3d95aULL, 0x04c3d9faULL,
};
static const u32 SHUTTER_PIDS[SHUTTER_PID_COUNT] = { 0x04bbU, 0x06b2U };
struct shutter_excl { u64 ctr_va; u64 flag_va; u64 slot_va; };
static const struct shutter_excl SHUTTER_EXCLS[SHUTTER_EXCL_COUNT] = {
    { 0x08cf8434ULL, 0x08d37374ULL, 0x048f2f68ULL },
    { 0x08d08c54ULL, 0x08d37375ULL, 0x048f2f78ULL },
    { 0x08d08c58ULL, 0x08d37376ULL, 0x048f2f80ULL },
    { 0x08cf893cULL, 0x08d39590ULL, 0x048c9e90ULL },
    { 0x08d0ba50ULL, 0x08d39591ULL, 0x048c9ea0ULL },
    { 0x08d0ba54ULL, 0x08d39592ULL, 0x048c9ea8ULL },
};
static u64 g_shutter_pid_flag[SHUTTER_PID_COUNT];

static int addr_readable(u64 va) {
    u8 p = 0;
    return va && find_addr_info(va, &p, 0, 0) && ((p & 1u) != 0u);
}
static u64 umap_find_node(u64 map_addr, u32 key) {
    if (!addr_readable(map_addr) || !addr_readable(map_addr + 8ULL)) return 0ULL;
    u64 buckets = *(const volatile u64 *)(map_addr + 0x00ULL);
    u64 bcnt    = *(const volatile u64 *)(map_addr + 0x08ULL);
    if (!buckets || bcnt == 0ULL || bcnt > 1000000ULL) return 0ULL;
    u64 bidx = (u64)key % bcnt;
    if (!addr_readable(buckets + bidx * 8ULL)) return 0ULL;
    u64 prev = *(const volatile u64 *)(buckets + bidx * 8ULL);
    if (!prev || !addr_readable(prev)) return 0ULL;
    u64 cur = *(const volatile u64 *)prev;
    for (u32 steps = 0; cur && steps < 64U; steps++) {
        if (!addr_readable(cur + 0x0CULL)) return 0ULL;
        u32 nkey = *(const volatile u32 *)(cur + 0x08ULL);
        if (nkey == key) return cur;
        u64 nxt = *(const volatile u64 *)cur;
        if (!nxt || !addr_readable(nxt + 0x08ULL)) break;
        u32 next_key = *(const volatile u32 *)(nxt + 0x08ULL);
        if (((u64)next_key % bcnt) != bidx) break;
        cur = nxt;
    }
    return 0ULL;
}
static void shutter_cache_pid_addrs(void) {
    for (u32 i = 0; i < SHUTTER_PID_COUNT; i++) {
        u64 node = umap_find_node(g_appfw_base + APPFW_MAP_PID_SUPPORT_VA, SHUTTER_PIDS[i]);
        g_shutter_pid_flag[i] = node ? (node + 0x0CULL) : 0ULL;
    }
}
static int shutter_probe_live_on(void) {
    if (!g_appfw_base) return 0;
    return (*(const volatile u8 *)(g_appfw_base + SHUTTER_BYTE_VAS[0]) == 1U) ? 1 : 0;
}
static int cow_write_appfw_byte(u64 va, u8 val) {
    u8 perms = 0;
    if (!find_addr_info(va, &perms, 0, 0) || !(perms & 1u)) return 0;
    if (perms & 2u) {
        *(volatile u8 *)va = val;
        __asm__ volatile("dsb ish" ::: "memory");
        return *(const volatile u8 *)va == val;
    }
    return cow_write_va(va, &val, 1ULL, (perms & 4u) != 0u, 1);
}
static int shutter_run_toggle_atomic(int enable) {
    u8 want = enable ? 1U : 0U;
    u8 alt  = enable ? 0U : 1U;
    if (!g_appfw_base || !g_shutter_pid_flag[0] || !g_shutter_pid_flag[1]) return 0;

    /* PASS 1: Dry verify all 9 bytes, 2 PIDs, and 6 exclusion pairs */
    int already = 1;
    for (u32 i = 0; i < SHUTTER_BYTE_COUNT; i++) {
        u8 cur = *(const volatile u8 *)(g_appfw_base + SHUTTER_BYTE_VAS[i]);
        if (cur != want) {
            already = 0;
            if (cur != alt) return 0;
        }
    }
    for (u32 i = 0; i < SHUTTER_PID_COUNT; i++) {
        u8 cur = *(const volatile u8 *)g_shutter_pid_flag[i];
        if (cur != want) {
            already = 0;
            if (cur != alt) return 0;
        }
    }
    if (already) return 1;

    u32 ctr_pre[SHUTTER_EXCL_COUNT];
    for (u32 i = 0; i < SHUTTER_EXCL_COUNT; i++) {
        u64 slot_val = *(const volatile u64 *)(g_appfw_base + SHUTTER_EXCLS[i].slot_va);
        if (slot_val != (g_appfw_base + SHUTTER_EXCLS[i].flag_va)) return 0;
        u32 c = *(const volatile u32 *)(g_appfw_base + SHUTTER_EXCLS[i].ctr_va);
        if (enable && c == 0U) return 0;
        if (!enable && c == 0xFFFFFFFFU) return 0;
        ctr_pre[i] = c;
    }

    /* PASS 2: Apply bytes, PIDs, and safe dec/inc-by-1 on exclusion pairs */
    for (u32 i = 0; i < SHUTTER_BYTE_COUNT; i++) {
        if (!cow_write_appfw_byte(g_appfw_base + SHUTTER_BYTE_VAS[i], want)) return 0;
    }
    for (u32 i = 0; i < SHUTTER_PID_COUNT; i++) {
        *(volatile u8 *)g_shutter_pid_flag[i] = want;
        __asm__ volatile("dsb ish" ::: "memory");
    }
    for (u32 i = 0; i < SHUTTER_EXCL_COUNT; i++) {
        u32 new_c = enable ? (ctr_pre[i] - 1U) : (ctr_pre[i] + 1U);
        u8  new_f = (new_c == 0U) ? 0U : 1U;
        *(volatile u32 *)(g_appfw_base + SHUTTER_EXCLS[i].ctr_va) = new_c;
        *(volatile u8  *)(g_appfw_base + SHUTTER_EXCLS[i].flag_va) = new_f;
    }
    __asm__ volatile("dsb ish" ::: "memory");

    /* PASS 3: Verify */
    for (u32 i = 0; i < SHUTTER_BYTE_COUNT; i++) {
        if (*(const volatile u8 *)(g_appfw_base + SHUTTER_BYTE_VAS[i]) != want) return 0;
    }
    for (u32 i = 0; i < SHUTTER_PID_COUNT; i++) {
        if (*(const volatile u8 *)g_shutter_pid_flag[i] != want) return 0;
    }
    return 1;
}

/* ---- Reversible Cine EI v2.2 Toggle (AP-RAM only, safe dec/inc-by-1) ----- */
static u64 g_cine_l1_flag[5];
static u64 g_cine_l2_flag[2];
static u64 g_cine_def_slot[6];

static void cine_cache_pid_addrs(void) {
    for (u32 i = 0; i < 5U; i++) {
        u64 n = umap_find_node(g_appfw_base + APPFW_MAP_PID_SUPPORT_VA, CINE_L1_PIDS[i]);
        g_cine_l1_flag[i] = n ? (n + 0x0CULL) : 0ULL;
    }
    u64 l2_out = umap_find_node(g_appfw_base + CINE_MAP_VAL_SUPPORT_VA, CINE_L2_PID);
    for (u32 i = 0; i < 2U; i++) {
        u64 n = l2_out ? umap_find_node(l2_out + 0x10ULL, CINE_L2_VALS[i]) : 0ULL;
        g_cine_l2_flag[i] = n ? (n + 0x0CULL) : 0ULL;
    }
    static const u32 dm_pids[6] = { 0x0506U, 0x0507U, 0x0508U, 0x0509U, 0x050AU, 0x1575U };
    for (u32 i = 0; i < 6U; i++) {
        u64 n = umap_find_node(g_appfw_base + CINE_MAP_DEFAULTS_VA, dm_pids[i]);
        g_cine_def_slot[i] = n ? (n + 0x0CULL) : 0ULL;
    }
}
static int cine_probe_live_on(void) {
    if (!g_appfw_base) return 0;
    return (*(const volatile u8 *)(g_appfw_base + (u64)CINE_B01_VAS[0]) == 1U) ? 1 : 0;
}
static int cow_write_appfw_span(u64 va, const u8 *src, u64 len, int is_code) {
    u8 perms = 0;
    if (!find_addr_info(va, &perms, 0, 0) || !(perms & 1u)) return 0;
    if (!is_code && (perms & 2u)) {
        volatile u8 *dst = (volatile u8 *)va;
        for (u64 i = 0; i < len; i++) dst[i] = src[i];
        __asm__ volatile("dsb ish" ::: "memory");
        return mem_eq((const u8 *)va, src, len);
    }
    return cow_write_va(va, src, len, is_code || ((perms & 4u) != 0u), !(perms & 2u));
}
static int cine_run_toggle_atomic(int enable) {
    if (!g_appfw_base) return 0;
    for (u32 i = 0; i < 5U; i++) if (!g_cine_l1_flag[i]) return 0;
    for (u32 i = 0; i < 2U; i++) if (!g_cine_l2_flag[i]) return 0;

    u8 want_b = enable ? 1U : 0U;
    u8 alt_b  = enable ? 0U : 1U;
    u32 want_s3 = enable ? CINE_STEP3_TARGET_VAL : CINE_STEP3_STOCK_VAL;
    u32 alt_s3  = enable ? CINE_STEP3_STOCK_VAL  : CINE_STEP3_TARGET_VAL;

    /* PASS 1: Dry verify every site is strictly target or alt before writing 1 byte */
    int already = 1;
    for (u32 i = 0; i < CINE_B01_COUNT; i++) {
        u8 cur = *(const volatile u8 *)(g_appfw_base + (u64)CINE_B01_VAS[i]);
        if (cur != want_b) { already = 0; if (cur != alt_b) return 0; }
    }
    for (u32 i = 0; i < CINE_B1_OTHER_COUNT; i++) {
        u8 w = enable ? CINE_B1_OTHER[i].after : CINE_B1_OTHER[i].before;
        u8 a = enable ? CINE_B1_OTHER[i].before : CINE_B1_OTHER[i].after;
        u8 cur = *(const volatile u8 *)(g_appfw_base + (u64)CINE_B1_OTHER[i].va);
        if (cur != w) { already = 0; if (cur != a) return 0; }
    }
    for (u32 i = 0; i < CINE_C4_COUNT; i++) {
        const u8 *w = enable ? CINE_C4[i].after : CINE_C4[i].before;
        const u8 *a = enable ? CINE_C4[i].before : CINE_C4[i].after;
        const u8 *cur = (const u8 *)(g_appfw_base + (u64)CINE_C4[i].va);
        if (!mem_eq(cur, w, 4U)) { already = 0; if (!mem_eq(cur, a, 4U)) return 0; }
    }
    {
        const u8 *w = enable ? CINE_C20_AFTER : CINE_C20_BEFORE;
        const u8 *a = enable ? CINE_C20_BEFORE : CINE_C20_AFTER;
        const u8 *cur = (const u8 *)(g_appfw_base + (u64)CINE_C20_VA);
        if (!mem_eq(cur, w, 20U)) { already = 0; if (!mem_eq(cur, a, 20U)) return 0; }
    }
    {
        u32 s3a = *(const volatile u32 *)(g_appfw_base + CINE_STEP3_HIGH_A_VA);
        u32 s3b = *(const volatile u32 *)(g_appfw_base + CINE_STEP3_HIGH_B_VA);
        if (s3a != want_s3) { already = 0; if (s3a != alt_s3) return 0; }
        if (s3b != want_s3) { already = 0; if (s3b != alt_s3) return 0; }
    }
    for (u32 i = 0; i < 5U; i++) {
        u8 v = *(const volatile u8 *)g_cine_l1_flag[i];
        if (v != want_b) { already = 0; if (v != alt_b) return 0; }
    }
    for (u32 i = 0; i < 2U; i++) {
        u8 v = *(const volatile u8 *)g_cine_l2_flag[i];
        if (v != want_b) { already = 0; if (v != alt_b) return 0; }
    }
    if (already) return 1;

    u32 ctr_pre[CINE_EXCL_COUNT];
    for (u32 i = 0; i < CINE_EXCL_COUNT; i++) {
        u64 slot_val = *(const volatile u64 *)(g_appfw_base + (u64)CINE_EXCL[i].slot_va);
        if (slot_val != (g_appfw_base + (u64)CINE_EXCL[i].flag_va)) return 0;
        u32 c = *(const volatile u32 *)(g_appfw_base + (u64)CINE_EXCL[i].ctr_va);
        if (enable && c == 0U) return 0;
        if (!enable && c == 0xFFFFFFFFU) return 0;
        ctr_pre[i] = c;
    }

    /* PASS 2: Apply 81 patches + 7 live flags + 58 dec/inc + Step 3 + defaults/clamps */
    for (u32 i = 0; i < CINE_B01_COUNT; i++) {
        if (!cow_write_appfw_byte(g_appfw_base + (u64)CINE_B01_VAS[i], want_b)) return 0;
    }
    for (u32 i = 0; i < CINE_B1_OTHER_COUNT; i++) {
        u8 w = enable ? CINE_B1_OTHER[i].after : CINE_B1_OTHER[i].before;
        if (!cow_write_appfw_byte(g_appfw_base + (u64)CINE_B1_OTHER[i].va, w)) return 0;
    }
    for (u32 i = 0; i < CINE_C4_COUNT; i++) {
        const u8 *w = enable ? CINE_C4[i].after : CINE_C4[i].before;
        if (!cow_write_appfw_span(g_appfw_base + (u64)CINE_C4[i].va, w, 4ULL, 1)) return 0;
    }
    if (!cow_write_appfw_span(g_appfw_base + (u64)CINE_C20_VA, enable ? CINE_C20_AFTER : CINE_C20_BEFORE, 20ULL, 1)) return 0;

    for (u32 i = 0; i < 5U; i++) *(volatile u8 *)g_cine_l1_flag[i] = want_b;
    for (u32 i = 0; i < 2U; i++) *(volatile u8 *)g_cine_l2_flag[i] = want_b;
    for (u32 i = 0; i < CINE_EXCL_COUNT; i++) {
        u32 new_c = enable ? (ctr_pre[i] - 1U) : (ctr_pre[i] + 1U);
        u8  new_f = (new_c == 0U) ? 0U : 1U;
        *(volatile u32 *)(g_appfw_base + (u64)CINE_EXCL[i].ctr_va) = new_c;
        *(volatile u8  *)(g_appfw_base + (u64)CINE_EXCL[i].flag_va) = new_f;
    }
    *(volatile u32 *)(g_appfw_base + CINE_STEP3_HIGH_A_VA) = want_s3;
    *(volatile u32 *)(g_appfw_base + CINE_STEP3_HIGH_B_VA) = want_s3;
    if (addr_readable(g_appfw_base + CINE_STEP3_HIGH_C_VA))
        *(volatile u32 *)(g_appfw_base + CINE_STEP3_HIGH_C_VA) = want_s3;

    static const u32 dm_on[6]  = { 0U, 10U, 7U, 7U, 12U, 19U };
    static const u32 dm_off[6] = { 2U, 13U, 25U, 13U, 25U, 26U };
    for (u32 i = 0; i < 6U; i++) {
        if (g_cine_def_slot[i]) *(volatile u32 *)g_cine_def_slot[i] = enable ? dm_on[i] : dm_off[i];
    }

    if (enable) {
        static const struct { u64 off; u32 lo; u32 hi; u32 defv; } dobj[5] = {
            { 0x14A04ULL, 0U, 1U, 0U }, { 0x14A14ULL, 8U, 12U, 10U },
            { 0x14A3CULL, 1U, 18U, 7U }, { 0x14A64ULL, 1U, 13U, 7U }, { 0x14A8CULL, 6U, 18U, 12U },
        };
        if (addr_readable(g_appfw_base + CINE_DEF_OBJ_PTR_VA)) {
            u64 ptr = *(const volatile u64 *)(g_appfw_base + CINE_DEF_OBJ_PTR_VA);
            if (ptr && addr_readable(ptr + 0x14A04ULL) && addr_readable(ptr + 0x14A8CULL)) {
                int fresh = (*(const volatile u32 *)(ptr + 0x14A04ULL) == 2U);
                for (u32 i = 0; i < 5U; i++) {
                    u32 v = *(const volatile u32 *)(ptr + dobj[i].off);
                    if (v < dobj[i].lo || v > dobj[i].hi || (fresh && i == 3U && v == 13U))
                        *(volatile u32 *)(ptr + dobj[i].off) = dobj[i].defv;
                }
            }
        }
        static const u64 extra_bases[3] = { 0x1391BAE4ULL, 0x1391F018ULL, 0x13937CE0ULL };
        for (u32 idx = 0; idx < 16U; idx++) {
            u64 base = (idx < 13U) ? (g_appfw_base + 0x138C0948ULL + (u64)idx * 0x1D44ULL + 0x590ULL)
                                   : (g_appfw_base + extra_bases[idx - 13U]);
            if (!addr_readable(base) || !addr_readable(base + 16ULL)) continue;
            int fresh = (*(const volatile u32 *)base == 2U);
            for (u32 j = 0; j < 5U; j++) {
                u32 v = *(const volatile u32 *)(base + (u64)j * 4ULL);
                if (v < dobj[j].lo || v > dobj[j].hi || (fresh && j == 3U && v == 13U))
                    *(volatile u32 *)(base + (u64)j * 4ULL) = dobj[j].defv;
            }
        }
        static const struct { u64 va; u32 lo; u32 hi; u32 defv; } ei_recs[8] = {
            { 0x08D37994ULL, 0U, 1U, 0U },   { 0x08D379A4ULL, 8U, 12U, 10U },
            { 0x08D379CCULL, 1U, 18U, 7U },  { 0x08D379F4ULL, 1U, 13U, 7U },
            { 0x08D37A1CULL, 6U, 18U, 12U }, { 0x08D91754ULL, 0U, 12U, 6U },
            { 0x08D91770ULL, 0U, 12U, 6U },  { 0x08D9178CULL, 0U, 12U, 6U },
        };
        int fresh = (*(const volatile u32 *)(g_appfw_base + 0x08D37994ULL) == 2U);
        for (u32 i = 0; i < 8U; i++) {
            u32 va_a = *(const volatile u32 *)(g_appfw_base + ei_recs[i].va);
            u32 va_b = *(const volatile u32 *)(g_appfw_base + ei_recs[i].va + 4ULL);
            if (va_a < ei_recs[i].lo || va_a > ei_recs[i].hi || (fresh && i == 3U && va_a == 13U))
                *(volatile u32 *)(g_appfw_base + ei_recs[i].va) = ei_recs[i].defv;
            if (va_b < ei_recs[i].lo || va_b > ei_recs[i].hi || (fresh && i == 3U && va_b == 13U))
                *(volatile u32 *)(g_appfw_base + ei_recs[i].va + 4ULL) = ei_recs[i].defv;
        }
    }
    __asm__ volatile("dsb ish" ::: "memory");

    /* PASS 3: Verify key state */
    if (*(const volatile u8 *)(g_appfw_base + (u64)CINE_B01_VAS[0]) != want_b) return 0;
    if (*(const volatile u32 *)(g_appfw_base + CINE_STEP3_HIGH_A_VA) != want_s3) return 0;
    return 1;
}

/* ---- Atomic 20-byte SD Speed-Limit Bypass toggle (libmpr.so) ------------- */
static int sd_probe_live_on(void) {
    u64 va = find_mapped_slice("/libmpr.so", SD_SITE_OFF, SD_SITE_LEN, 1u, 0, 0, 0);
    if (!va) return 0;
    return mem_eq((const u8 *)va, SD_PATCH_20, SD_SITE_LEN) ? 1 : 0;
}
static int sd_run_toggle_atomic(int enable) {
    u64 g0 = find_mapped_slice("/libmpr.so", SD_PRE_GUARD_OFF,  8U, 1u, 0, 0, 0);
    u64 g1 = find_mapped_slice("/libmpr.so", SD_POST_GUARD_OFF, 8U, 1u, 0, 0, 0);
    u64 va = find_mapped_slice("/libmpr.so", SD_SITE_OFF, SD_SITE_LEN, 1u, 0, 0, 0);
    if (!g0 || !g1 || !va) return 0;
    if (!mem_eq((const u8 *)g0, SD_PRE_GUARD, 8U) || !mem_eq((const u8 *)g1, SD_POST_GUARD, 8U)) return 0;
    const u8 *want = enable ? SD_PATCH_20 : SD_STOCK_20;
    const u8 *alt  = enable ? SD_STOCK_20 : SD_PATCH_20;
    if (mem_eq((const u8 *)va, want, SD_SITE_LEN)) return 1;
    if (!mem_eq((const u8 *)va, alt, SD_SITE_LEN)) return 0;
    return cow_write_libmpr(SD_SITE_OFF, want, SD_SITE_LEN);
}

/* Fast 1-page live CP state check (called when entering menu -> detects warm-sleep CP reset!) */
static int og_probe_live_on(void) {
    u32 dmm_handle = 0;
    g_cp_phys = g_dmm_alloc(CP_PAGE, &dmm_handle);
    if (!g_cp_phys || (g_cp_phys & 0x3FULL) || g_cp_phys < RAM_LO || (g_cp_phys + CP_PAGE) > RAM_HI) {
        if (dmm_handle) g_dmm_free(dmm_handle);
        return -1;
    }
    i64 cp_fd = sys_open("/dev/mem", O_RDWR_SYNC, 0);
    if (cp_fd < 0) { g_dmm_free(dmm_handle); return -1; }
    u64 cp_lead = g_cp_phys & 0xFFFULL;
    u64 cp_maplen = (cp_lead + CP_PAGE + 0xFFFULL) & ~0xFFFULL;
    i64 cp_map = sys_mmap_rw(cp_fd, cp_maplen, g_cp_phys - cp_lead);
    if (cp_map == -1) { sys_close(cp_fd); g_dmm_free(dmm_handle); return -1; }
    g_cp_buf = (u8 *)cp_map + cp_lead;
    u8 *pS = cp_dma_read_span(OG_SIZETBL_SITE_VA, 4U, 0, 0);
    int res = (pS && mem_eq(pS, OG_SIZETBL_NEW, 4U)) ? 1 : 0;
    sys_munmap((void *)cp_map, cp_maplen);
    sys_close(cp_fd);
    g_dmm_free(dmm_handle);
    g_cp_buf = 0;
    return res;
}

/* ---- Sony Native Live Video Pipeline Reload (seq 0xCA + seq 0x32F) ------- */
static void reload_movie_pipeline(void) {
    if (!g_appfw_base || !g_usleep) return;
    typedef void *(*get_seq_mgr_fn)(void);
    typedef void  (*start_seq_fn)(void *mgr, u32 seq_id, void *arg);
    typedef void  (*start_disp_fn)(void *mgr, u32 seq_id, void *arg, u32 flag);
    typedef int   (*is_running_fn)(void *mgr, u32 seq_id);
    get_seq_mgr_fn get_mgr = (get_seq_mgr_fn)(g_appfw_base + APPFW_GET_SEQ_MGR_OFF);
    start_seq_fn   start_s = (start_seq_fn)(g_appfw_base + APPFW_SEQ_SET_MOVIE_FMT_OFF);
    start_disp_fn  start_d = (start_disp_fn)(g_appfw_base + APPFW_SEQ_DISP_UPDATE_OFF);
    is_running_fn  is_run  = (is_running_fn)(g_appfw_base + APPFW_SEQ_IS_RUNNING_OFF);
    void *mgr = get_mgr();
    if (!mgr) return;
    start_s(mgr, APPFW_SEQ_ID_MOVIE_FMT, 0);
    g_usleep(50000U);
    for (u32 w = 0; w < 50U && is_run(mgr, APPFW_SEQ_ID_MOVIE_FMT); w++) g_usleep(50000U);
    start_d(mgr, APPFW_SEQ_ID_DISP_UPDATE, 0, 1U);
    g_usleep(50000U);
    for (u32 w = 0; w < 30U && is_run(mgr, APPFW_SEQ_ID_DISP_UPDATE); w++) g_usleep(50000U);
}

/* =========================================================================
 *  Native Sony Menu UI Integration (Setup -> Operation Customize -> Open Gate)
 * ========================================================================= */
typedef void  (*tree_insert_fn)(void *tree_this, const void *start, const void *end);
typedef void *(*ctrl_factory_fn)(void *buf, void *a1, void *a2, void *a3, u32 a4);
typedef void *(*view_factory_fn)(void *buf, void *a1, void *a2, u32 pool_idx, u32 sid);
typedef void  (*view_update_fn)(void *view, u32 flag);
typedef void  (*text_set_rid_fn)(void *sprite, u32 rid);
typedef void  (*text_set_cstr_fn)(void *sprite, const char *str);
typedef u32   (*ctrl_event_fn)(void *ctrl, void *ev);
typedef void  (*generic_open_fn)(void *ctrl, void *a, void *b, void *c);
typedef void *(*accessor_ptr_fn)(void *self, u32 key);
typedef u32   (*accessor_u32_fn)(void *self, u32 key);
typedef void  (*ctrl_2a7_close_fn)(void *ctrl);
typedef void  (*ctrl_enter_fn)(void *ctrl, const u32 *source);
typedef void  (*cursor_focus_fn)(void *cursor, u32 item);
typedef u32  *(*get_id_ptr_fn)(void);

struct menu_row_entry { u64 group_id; u64 setting_desc; u64 non_setting_desc; };
struct tree_reg_entry { u64 group_id; u64 desc_ptr; };

/* Large cloned tables live in .bss (0 bytes on disk / in the .so file!) */
static u8  g_menu_table[APPFW_MENU_TABLE_SIZE] __attribute__((aligned(16)));
static u8  g_page_table[APPFW_PAGE_STOCK_COUNT * APPFW_PAGE_ENTRY_SIZE] __attribute__((aligned(16)));
static u64 g_accessor_vt[APPFW_ACCESSOR_HDR_QWS + APPFW_ACCESSOR_SLOTS] __attribute__((aligned(16)));
static u64 g_ctrl_vt_293[OG_VTABLE_SLOTS] __attribute__((aligned(16)));

static u8  g_stock_ns_desc[APPFW_DESC_SIZE] __attribute__((aligned(16)));
static u8  g_stock_item_desc[APPFW_ITEM_DESC_SIZE] __attribute__((aligned(16)));
static u8  g_stock_opt_desc[APPFW_OPT_DESC_SIZE] __attribute__((aligned(16)));
static u8  g_stock_opt_row[APPFW_OPT_ROW_SIZE] __attribute__((aligned(16)));

static u8  g_parent_desc[APPFW_DESC_SIZE + OG_ROW_COUNT * APPFW_ITEM_ENTRY_SIZE] __attribute__((aligned(16)));
static u8  g_item_descs[OG_ROW_COUNT][APPFW_ITEM_DESC_SIZE] __attribute__((aligned(16)));
static u8  g_item_ns_descs[OG_ROW_COUNT][APPFW_DESC_SIZE] __attribute__((aligned(16)));
static u8  g_list_val_descs[OG_ROW_COUNT][APPFW_OPT_DESC_SIZE] __attribute__((aligned(16)));
static u8  g_list_val_rows[OG_ROW_COUNT][APPFW_OPT_ROW_SIZE] __attribute__((aligned(16)));
static u8  g_opt_setting_desc[APPFW_OPT_DESC_SIZE] __attribute__((aligned(16)));
static u8  g_opt_rows[2][APPFW_OPT_ROW_SIZE] __attribute__((aligned(16)));

/* Dedicated Creative Looks menu (Exposure/Color -> Color/Tone -> Creative Looks, Slot 7) */
static u8  g_look_parent_desc[APPFW_DESC_SIZE + LOOK_ROW_COUNT * APPFW_ITEM_ENTRY_SIZE] __attribute__((aligned(16)));
static u8  g_look_item_descs[LOOK_ROW_COUNT][APPFW_ITEM_DESC_SIZE] __attribute__((aligned(16)));
static u8  g_look_item_ns_descs[LOOK_ROW_COUNT][APPFW_DESC_SIZE] __attribute__((aligned(16)));
static u8  g_look_val_descs[LOOK_ROW_COUNT][APPFW_OPT_DESC_SIZE] __attribute__((aligned(16)));
static u8  g_look_val_rows[LOOK_ROW_COUNT][APPFW_OPT_ROW_SIZE] __attribute__((aligned(16)));
static u8  g_look_opt_desc[APPFW_OPT_DESC_SIZE] __attribute__((aligned(16)));
static u8  g_look_opt_rows[LOOK_PACK_COUNT][APPFW_OPT_ROW_SIZE] __attribute__((aligned(16)));

static struct tree_reg_entry g_tree_parent __attribute__((aligned(16)));
static struct tree_reg_entry g_tree_items[OG_ROW_COUNT] __attribute__((aligned(16)));
static struct tree_reg_entry g_tree_look_parent __attribute__((aligned(16)));
static struct tree_reg_entry g_tree_look_items[LOOK_ROW_COUNT] __attribute__((aligned(16)));

/* Saved originals */
static ctrl_factory_fn   g_orig_ctrl_260;
static ctrl_factory_fn   g_orig_ctrl_292;
static ctrl_factory_fn   g_orig_ctrl_293;
static view_factory_fn   g_orig_view_293;
static ctrl_enter_fn     g_orig_enter_293;
static ctrl_event_fn     g_orig_btn_confirm;
static ctrl_event_fn     g_orig_btn_back;
static ctrl_event_fn     g_orig_btn_back2;
static ctrl_event_fn     g_orig_2a7_confirm;
static text_set_rid_fn   g_orig_set_rid;
static text_set_cstr_fn  g_orig_set_cstr;
static accessor_ptr_fn   g_orig_acc_grp_desc;
static accessor_ptr_fn   g_orig_acc_row_desc;
static accessor_u32_fn   g_orig_acc_row_vis;
static accessor_u32_fn   g_orig_acc_get_val;
static accessor_u32_fn   g_orig_acc_item_grp;
static accessor_ptr_fn   g_orig_acc_row_struct;
static accessor_ptr_fn   g_orig_acc_grp_struct;

/* Live UI, 0x260 busy dialog & toggle state */
static volatile int  g_og_on;
static volatile int  g_sd_on;
static volatile int  g_shutter_on;
static volatile int  g_cine_on;
static volatile int  g_look_pack; /* 0=Stock, 1=FX2 FL2/3, 2=Fujifilm 4-Sim, -1=unavailable */
static volatile int  g_busy;
static volatile int  g_busy_spin;
static int           g_busy_pending;
static int           g_busy_active;
static int           g_busy_open;
static u32           g_busy_ret_item = OG_ITEM_ID_BASE;
static void         *g_active_260_ctrl;
static void         *g_active_260_mgr;
static const char   *g_busy_text = "Processing...";
static int           g_in_our_293;
static int           g_our_2a7_kind; /* 0=none, 1=OG ON/OFF, 2=Look Pack 3-way */
static u32           g_og_2a7_row;
static u32           g_og_2a7_cur_choice;
static u32           g_ret_item;
static int           g_ret_pending;
static const char   *g_row_val_str[OG_ROW_COUNT];
static const char   *g_look_val_str[LOOK_ROW_COUNT];

static void busy_lock(void)   { while (__atomic_exchange_n(&g_busy_spin, 1, __ATOMIC_ACQUIRE) != 0) {} }
static void busy_unlock(void) { __atomic_store_n(&g_busy_spin, 0, __ATOMIC_RELEASE); }

static void busy_reset_state(void) {
    busy_lock();
    g_busy_pending = 0; g_busy_active = 0; g_busy_open = 0;
    g_active_260_ctrl = 0; g_active_260_mgr = 0;
    busy_unlock();
}

static void og_260_close_ctrl(void *ctrl, void *expected_mgr) {
    if (!ctrl) return;
    void *mgr = *(void **)((u8 *)ctrl + APPFW_260_MGR_OFF);
    void *handle = (u8 *)ctrl + APPFW_260_HANDLE_OFF;
    if (!mgr || (expected_mgr && mgr != expected_mgr)) return;
    u64 *vt = *(u64 **)mgr;
    if (!vt || !vt[4]) return;
    typedef void (*mgr_close_fn)(void *mgr_obj, void *handle_ptr);
    ((mgr_close_fn)vt[4])(mgr, handle);
}

static void *og_ctrl_260_hook(void *buf, void *a1, void *a2, void *a3, u32 a4) {
    void *ctrl = g_orig_ctrl_260(buf, a1, a2, a3, a4);
    if (!ctrl) return 0;
    busy_lock();
    if (g_busy_active) {
        g_active_260_ctrl = ctrl;
        g_active_260_mgr = a1;
        g_busy_open = 1;
    }
    busy_unlock();
    return ctrl;
}

static void og_busy_on_293_enter(void *ctrl_293, u32 source_id) {
    if (source_id == OG_BUSY_SCREEN_ID) {
        busy_lock();
        g_busy_open = 0;
        g_active_260_ctrl = 0;
        g_active_260_mgr = 0;
        if (!g_busy_pending) g_busy_active = 0;
        busy_unlock();
    }
    if (!ctrl_293 || !g_appfw_base) return;
    int should_open = 0;
    busy_lock();
    if (g_busy_pending && !g_busy_open) {
        g_busy_active = 1;
        should_open = 1;
    }
    busy_unlock();
    if (!should_open) return;

    g_ret_item = g_busy_ret_item;
    g_ret_pending = 1;
    u32 a[4] = { OG_BUSY_SCREEN_ID, 0U, 0U, 0U };
    u32 b[4] = { OG_GENERIC_SKIP,   0U, 0U, 0U };
    u32 c[4] = { OG_GENERIC_SKIP,   0U, 0U, 0U };
    ((generic_open_fn)(g_appfw_base + APPFW_293_GENERIC_OPEN_OFF))(ctrl_293, a, b, c);

    void *close_now = 0, *close_mgr = 0;
    busy_lock();
    if (!g_busy_pending && g_busy_open && g_active_260_ctrl) {
        close_now = g_active_260_ctrl;
        close_mgr = g_active_260_mgr;
        g_active_260_ctrl = 0; g_active_260_mgr = 0;
        g_busy_open = 0; g_busy_active = 0;
    }
    busy_unlock();
    if (close_now) og_260_close_ctrl(close_now, close_mgr);
}

static void og_busy_hide(void) {
    void *ctrl = 0, *mgr = 0;
    busy_lock();
    g_busy_pending = 0;
    if (g_busy_open && g_active_260_ctrl) {
        ctrl = g_active_260_ctrl;
        mgr = g_active_260_mgr;
        g_active_260_ctrl = 0; g_active_260_mgr = 0;
        g_busy_open = 0; g_busy_active = 0;
    } else if (!g_busy_open) {
        g_busy_active = 0;
    }
    busy_unlock();
    if (ctrl) og_260_close_ctrl(ctrl, mgr);
}

static const char *const kRowLabels[OG_ROW_COUNT] = {
    "4K Open Gate (3:2)",
    "SD Speed Bypass",
    "Power-Off Shutter",
    "Cine EI / Quick",
};
static const char *const kRowHelp[OG_ROW_COUNT] = {
    "Enables 3840x2560 (3:2) 4K 24p/25p/50p Open Gate + 3:2 playback fix.",
    "Bypasses SD card speed-class lock for 120p and All-Intra on V60/V30 cards.",
    "Unlocks Setup > Setup Option > Anti-dust Function > Shutter When Pwr OFF.",
    "Unlocks Shooting > Image Quality/Rec > Log Shooting Setting (Cine EI / Quick + Base ISO).",
};
static const char *const kOnOffChoices[2] = { "ON", "OFF" };

static const char *const kLookRowLabels[LOOK_ROW_COUNT] = {
    "Creative Look Pack",
    "Fuji Slide (ST/PT)",
    "Fuji Vivid (VV/VV2)",
    "Fuji Film (FL/IN)",
    "Fuji Cine/BW (SH/BW)",
    "FX2 / Stock Slots",
};
static const char *const kLookRowHelp[LOOK_ROW_COUNT] = {
    "Switch live between Sony Stock, FX2 FL2/FL3, and Fujifilm 8-Sim packs (RAM-only).",
    "Fujifilm Pack: ST = Provia (standard slide), PT = Astia (soft portrait slide).",
    "Fujifilm Pack: VV = Velvia (vivid slide), VV2 = Classic Neg. (street film).",
    "Fujifilm Pack: FL = Classic Chrome, IN = Pro Neg. Hi (portrait film).",
    "Fujifilm Pack: SH = Eterna (cinema negative), BW = Acros (fine-art monochrome).",
    "FX2 Pack: IN = FL2, SH = FL3. NT (Neutral) and SE (Sepia) always stay 100% Sony stock.",
};
static const char *const kLookPackChoices[LOOK_PACK_COUNT] = {
    "Stock",
    "FX2 (FL2 / FL3)",
    "Fujifilm 8-Sim",
};
static const char *const kLookPackHelp[LOOK_PACK_COUNT] = {
    "Restores all 10 Creative Looks and menu names to 100% Sony factory stock.",
    "Replaces IN with Sony FX2 FL2 and SH with Sony FX2 FL3 (with live FL2/FL3 menu names).",
    "ST=Provia PT=Astia VV=Velvia VV2=C.Neg FL=C.Chrome IN=ProNegHi SH=Eterna BW=Acros (NT/SE stock).",
};
static const char *const kLookPackShort[LOOK_PACK_COUNT] = {
    "Stock",
    "FX2 FL2/3",
    "Fuji 8-Sim",
};

static u32 *menu_id_ptr(u64 off) {
    return ((get_id_ptr_fn)(g_appfw_base + off))();
}
static int cur_our_group(void) {
    u32 *g = menu_id_ptr(APPFW_GET_CUR_GROUP_OFF);
    if (!g) return 0;
    if (*g == OG_GROUP_ID)   return 1;
    if (*g == LOOK_GROUP_ID) return 2;
    return 0;
}
static void update_row_val_strings(void) {
    g_row_val_str[0] = g_busy ? "Busy..." : (g_og_on ? "ON" : "OFF");
    g_row_val_str[1] = g_sd_on ? "ON" : "OFF";
    g_row_val_str[2] = g_shutter_on ? "ON" : "OFF";
    g_row_val_str[3] = g_cine_on ? "ON" : "OFF";
    int lp = __atomic_load_n(&g_look_pack, __ATOMIC_ACQUIRE);
    if (!g_apply_look_pack || lp < 0 || lp >= (int)LOOK_PACK_COUNT) {
        g_look_val_str[0] = g_busy ? "Busy..." : "N/A";
    } else {
        g_look_val_str[0] = g_busy ? "Busy..." : kLookPackShort[lp];
    }
    g_look_val_str[1] = "ST:Provia  PT:Astia";
    g_look_val_str[2] = "VV:Velvia  VV2:C.Neg";
    g_look_val_str[3] = "FL:C.Chr  IN:ProNegH";
    g_look_val_str[4] = "SH:Eterna  BW:Acros";
    g_look_val_str[5] = "FX2:IN/SH  Stk:NT/SE";
}

/* Detached worker: runs Open Gate toggle or Creative Look Pack switch, then closes 0x260 */
struct toggle_req { u32 kind; int value; }; /* kind: 0=OG ON/OFF, 1=Look Pack 0..2 */
static struct toggle_req g_req;

static void *og_toggle_worker(void *arg) {
    const struct toggle_req *r = (const struct toggle_req *)arg;
    if (r->kind == 0U) {
        int ok = og_run_toggle_atomic(r->value);
        if (ok) {
            __atomic_store_n(&g_og_on, r->value, __ATOMIC_RELEASE);
            reload_movie_pipeline();
        }
        g_row_val_str[0] = ok ? (r->value ? "ON" : "OFF") : "ERR";
    } else if (r->kind == 1U && g_apply_look_pack) {
        int ok = g_apply_look_pack(r->value);
        if (ok) {
            __atomic_store_n(&g_look_pack, r->value, __ATOMIC_RELEASE);
            g_look_val_str[0] = kLookPackShort[r->value];
        } else {
            g_look_val_str[0] = "ERR";
        }
    }
    if (g_usleep) g_usleep(120000U); /* allow 0x260 open to settle before closing cleanly */
    og_busy_hide();
    __atomic_store_n(&g_busy, 0, __ATOMIC_RELEASE);
    return 0;
}

static void dispatch_og_toggle(u32 row, int enable) {
    if (row == 1U) {
        int ok = sd_run_toggle_atomic(enable);
        if (ok) __atomic_store_n(&g_sd_on, enable, __ATOMIC_RELEASE);
        g_row_val_str[1] = ok ? (enable ? "ON" : "OFF") : "ERR";
        return;
    }
    if (row == 2U) {
        int ok = shutter_run_toggle_atomic(enable);
        if (ok) __atomic_store_n(&g_shutter_on, enable, __ATOMIC_RELEASE);
        g_row_val_str[2] = ok ? (enable ? "ON" : "OFF") : "ERR";
        return;
    }
    if (row == 3U) {
        int ok = cine_run_toggle_atomic(enable);
        if (ok) __atomic_store_n(&g_cine_on, enable, __ATOMIC_RELEASE);
        g_row_val_str[3] = ok ? (enable ? "ON" : "OFF") : "ERR";
        return;
    }
    if (__atomic_exchange_n(&g_busy, 1, __ATOMIC_ACQ_REL) != 0) return;
    g_req.kind = 0U;
    g_req.value = enable;
    g_row_val_str[0] = enable ? "ON..." : "OFF...";
    busy_lock();
    g_busy_text = enable ? "Enabling Open Gate..." : "Restoring 16:9...";
    g_busy_ret_item = OG_ITEM_ID_BASE;
    g_busy_pending = 1;
    g_busy_active = 1;
    busy_unlock();
    if (g_pthread_create) {
        u64 tid = 0;
        if (g_pthread_create(&tid, 0, og_toggle_worker, &g_req) == 0) {
            if (g_pthread_detach) g_pthread_detach(tid);
            return;
        }
    }
    (void)og_toggle_worker(&g_req);
}

static void dispatch_look_pack(int pack) {
    if (!g_apply_look_pack || pack < 0 || pack >= (int)LOOK_PACK_COUNT) return;
    if (__atomic_exchange_n(&g_busy, 1, __ATOMIC_ACQ_REL) != 0) return;
    g_req.kind = 1U;
    g_req.value = pack;
    g_look_val_str[0] = "Busy...";
    busy_lock();
    g_busy_text = "Applying Look Pack...";
    g_busy_ret_item = LOOK_ITEM_ID_BASE;
    g_busy_pending = 1;
    g_busy_active = 1;
    busy_unlock();
    if (g_pthread_create) {
        u64 tid = 0;
        if (g_pthread_create(&tid, 0, og_toggle_worker, &g_req) == 0) {
            if (g_pthread_detach) g_pthread_detach(tid);
            return;
        }
    }
    (void)og_toggle_worker(&g_req);
}

/* ---- Accessor vtable hooks (for right-aligned values + 0x2A7 pickers) ---- */
static int is_og_val_group(u32 gid) {
    return g_in_our_293 && cur_our_group() == 1 &&
           gid >= OG_ITEM_ID_BASE && gid < OG_ITEM_ID_BASE + OG_ROW_COUNT;
}
static int is_look_val_group(u32 gid) {
    return g_in_our_293 && cur_our_group() == 2 &&
           gid >= LOOK_ITEM_ID_BASE && gid < LOOK_ITEM_ID_BASE + LOOK_ROW_COUNT;
}
static void *acc_grp_desc_hook(void *self, u32 gid) {
    if (gid == OG_OPT_GROUP_ID)   return g_opt_setting_desc;
    if (gid == LOOK_OPT_GROUP_ID) return g_look_opt_desc;
    if (is_og_val_group(gid))     return g_list_val_descs[gid - OG_ITEM_ID_BASE];
    if (is_look_val_group(gid))   return g_look_val_descs[gid - LOOK_ITEM_ID_BASE];
    return g_orig_acc_grp_desc(self, gid);
}
static void *acc_row_desc_hook(void *self, u32 key) {
    if (key >= OG_OPT_CHOICE_BASE && key < OG_OPT_CHOICE_BASE + 2U)
        return g_opt_rows[key - OG_OPT_CHOICE_BASE];
    if (key >= OG_LIST_VAL_KEY_BASE && key < OG_LIST_VAL_KEY_BASE + OG_ROW_COUNT)
        return g_list_val_rows[key - OG_LIST_VAL_KEY_BASE];
    if (key >= LOOK_OPT_CHOICE_BASE && key < LOOK_OPT_CHOICE_BASE + LOOK_PACK_COUNT)
        return g_look_opt_rows[key - LOOK_OPT_CHOICE_BASE];
    if (key >= LOOK_LIST_VAL_KEY_BASE && key < LOOK_LIST_VAL_KEY_BASE + LOOK_ROW_COUNT)
        return g_look_val_rows[key - LOOK_LIST_VAL_KEY_BASE];
    return g_orig_acc_row_desc(self, key);
}
static u32 acc_row_vis_hook(void *self, u32 key) {
    if (key >= OG_OPT_CHOICE_BASE && key < OG_OPT_CHOICE_BASE + 2U) return 1U;
    if (key >= OG_LIST_VAL_KEY_BASE && key < OG_LIST_VAL_KEY_BASE + OG_ROW_COUNT) return 1U;
    if (key >= LOOK_OPT_CHOICE_BASE && key < LOOK_OPT_CHOICE_BASE + LOOK_PACK_COUNT) return 1U;
    if (key >= LOOK_LIST_VAL_KEY_BASE && key < LOOK_LIST_VAL_KEY_BASE + LOOK_ROW_COUNT) return 1U;
    return g_orig_acc_row_vis(self, key);
}
static u32 acc_get_val_hook(void *self, u32 gid) {
    if (gid == OG_OPT_GROUP_ID || gid == LOOK_OPT_GROUP_ID) return g_og_2a7_cur_choice;
    if (is_og_val_group(gid) || is_look_val_group(gid))     return 0U;
    return g_orig_acc_get_val(self, gid);
}
static u32 acc_item_grp_hook(void *self, u32 key) {
    if (key >= OG_OPT_CHOICE_BASE && key < OG_OPT_CHOICE_BASE + 2U) return OG_OPT_GROUP_ID;
    if (key >= OG_LIST_VAL_KEY_BASE && key < OG_LIST_VAL_KEY_BASE + OG_ROW_COUNT)
        return OG_ITEM_ID_BASE + (key - OG_LIST_VAL_KEY_BASE);
    if (key >= LOOK_OPT_CHOICE_BASE && key < LOOK_OPT_CHOICE_BASE + LOOK_PACK_COUNT) return LOOK_OPT_GROUP_ID;
    if (key >= LOOK_LIST_VAL_KEY_BASE && key < LOOK_LIST_VAL_KEY_BASE + LOOK_ROW_COUNT)
        return LOOK_ITEM_ID_BASE + (key - LOOK_LIST_VAL_KEY_BASE);
    return g_orig_acc_item_grp(self, key);
}
static void *acc_row_struct_hook(void *self, u32 key) {
    if (key >= OG_OPT_CHOICE_BASE && key < OG_OPT_CHOICE_BASE + 2U)
        return g_opt_rows[key - OG_OPT_CHOICE_BASE];
    if (key >= OG_LIST_VAL_KEY_BASE && key < OG_LIST_VAL_KEY_BASE + OG_ROW_COUNT)
        return g_list_val_rows[key - OG_LIST_VAL_KEY_BASE];
    if (key >= LOOK_OPT_CHOICE_BASE && key < LOOK_OPT_CHOICE_BASE + LOOK_PACK_COUNT)
        return g_look_opt_rows[key - LOOK_OPT_CHOICE_BASE];
    if (key >= LOOK_LIST_VAL_KEY_BASE && key < LOOK_LIST_VAL_KEY_BASE + LOOK_ROW_COUNT)
        return g_look_val_rows[key - LOOK_LIST_VAL_KEY_BASE];
    return g_orig_acc_row_struct(self, key);
}
static void *acc_grp_struct_hook(void *self, u32 gid) {
    if (gid == OG_OPT_GROUP_ID || gid == LOOK_OPT_GROUP_ID ||
        is_og_val_group(gid) || is_look_val_group(gid)) return 0;
    return g_orig_acc_grp_struct(self, gid);
}

/* ---- Dynamic Creative Look RID override (0=Stock, 1=FX2, 2=Fuji 8-Sim) --- *
 * Disassembly-verified across all 11,917 UXC records & gid=0x0197 (0x4B697A8):
 *   Set 1: Menu option row short labels (+0x04) & help descriptions (+0x0C)
 *   Set 2: Fn / HUD / Screen 0xC0 short badge RIDs (2-3 chars max -> 0 clipping)
 *   Set 3: Screen 0xC0 full header titles (e.g. "CC (Classic Chrome)")
 *   NT (Neutral) & SE (Sepia) are intentionally untouched in every mode!      */
static const char *lookup_creative_look_str(int lp, u32 rid) {
    switch (rid) {
        /* ST -> Provia (Fuji only) */
        case 0x021C658EU:
        case 0x021C6FE8U:
        case 0x021C71EBU: return (lp == 2) ? "Provia" : 0;
        case 0x021C61CEU: return (lp == 2) ? "Fujifilm Provia (Standard): Clean slide film with natural contrast and cyan sky tint." : 0;

        /* PT -> Astia (Fuji only) */
        case 0x021C6654U:
        case 0x021C6F8BU:
        case 0x021C718EU: return (lp == 2) ? "Astia" : 0;
        case 0x0204E581U: return (lp == 2) ? "Fujifilm Astia (Soft): Portrait slide film with smooth skin tones and open shadows." : 0;

        /* VV -> Velvia (Fuji only) */
        case 0x021C687BU:
        case 0x021C6F80U:
        case 0x021C71BCU: return (lp == 2) ? "Velvia" : 0;
        case 0x021C6190U: return (lp == 2) ? "Fujifilm Velvia (Vivid): High-saturation landscape slide film with rich greens and blues." : 0;

        /* VV2 -> Classic Neg. (Fuji only) */
        case 0x021C689AU:
        case 0x021C6F4DU:
        case 0x021C70DDU: return (lp == 2) ? "Classic Neg." : 0;
        case 0x021C6617U: return (lp == 2) ? "Fujifilm Classic Neg.: Superia street film with cyan-green shadows and warm midtones." : 0;

        /* FL -> Classic Chrome (Fuji only) */
        case 0x021C6CC9U:
        case 0x021C6FDAU:
        case 0x021C725DU: return (lp == 2) ? "Classic Chrome" : 0;
        case 0x021C6CA9U: return (lp == 2) ? "Fujifilm Classic Chrome: Documentary film with muted colors and rolled-off highlights." : 0;

        /* IN -> FX2 FL2 (lp==1) | Fujifilm Pro Neg. Hi (lp==2) */
        case 0x021C6857U:
        case 0x021C7092U: return (lp == 1) ? "FL2" : "Pro Neg. Hi";
        case 0x021C7129U: return (lp == 1) ? "FL2 (Film 2)" : "Pro Neg. Hi";
        case 0x021C626CU: return (lp == 1)
            ? "Sony FX2 FL2 (Film 2): Nostalgic cinema film look with soft contrast and calm colors."
            : "Fujifilm Pro Neg. Hi: Portrait negative film with crisp midtones and natural skin color.";

        /* SH -> FX2 FL3 (lp==1) | Fujifilm Eterna (lp==2) */
        case 0x021C6961U:
        case 0x021C6F11U: return (lp == 1) ? "FL3" : "Eterna";
        case 0x021C70FBU: return (lp == 1) ? "FL3 (Film 3)" : "Eterna";
        case 0x021C6287U: return (lp == 1)
            ? "Sony FX2 FL3 (Film 3): Clean cinema film look with gentle contrast and glossy tones."
            : "Fujifilm Eterna: Wide-latitude cinema negative with soft shadows and gentle highlights.";

        /* BW -> Acros (Fuji only) */
        case 0x021C65F8U:
        case 0x021C6F63U:
        case 0x021C71A2U: return (lp == 2) ? "Acros" : 0;
        case 0x0204E587U: return (lp == 2) ? "Fujifilm Acros: Fine-art monochrome film with smooth highlight gradation and deep blacks." : 0;

        default: return 0;
    }
}

/* ---- TextSprite::setString(uint32_t rid) hook ---------------------------- */
static void og_set_string_rid_hook(void *sprite, u32 rid) {
    if (g_orig_set_cstr) {
        if (rid == OG_BUSY_MSG_RID) {
            const char *btxt = 0;
            busy_lock();
            if (g_busy_active) btxt = g_busy_text;
            busy_unlock();
            if (btxt) { g_orig_set_cstr(sprite, btxt); return; }
        }
        if (rid >= OG_RID_MENU_LABEL) {
            if (rid == OG_RID_MENU_LABEL)   { g_orig_set_cstr(sprite, "Wildcard"); return; }
            if (rid == LOOK_RID_MENU_LABEL) { g_orig_set_cstr(sprite, "Creative Looks"); return; }
            if (rid == OG_RID_OPT_TITLE)    { g_orig_set_cstr(sprite, kRowLabels[g_og_2a7_row < OG_ROW_COUNT ? g_og_2a7_row : 0U]); return; }
            if (rid == LOOK_RID_OPT_TITLE)  { g_orig_set_cstr(sprite, "Creative Look Pack"); return; }
            if (rid == OG_RID_EMPTY)        { g_orig_set_cstr(sprite, ""); return; }
            if (rid >= OG_RID_ITEM_BASE && rid < OG_RID_ITEM_BASE + OG_ROW_COUNT) {
                g_orig_set_cstr(sprite, kRowLabels[rid - OG_RID_ITEM_BASE]); return;
            }
            if (rid >= LOOK_RID_ITEM_BASE && rid < LOOK_RID_ITEM_BASE + LOOK_ROW_COUNT) {
                g_orig_set_cstr(sprite, kLookRowLabels[rid - LOOK_RID_ITEM_BASE]); return;
            }
            if (rid >= OG_RID_VAL_BASE && rid < OG_RID_VAL_BASE + OG_ROW_COUNT) {
                u32 r = rid - OG_RID_VAL_BASE;
                g_orig_set_cstr(sprite, g_row_val_str[r] ? g_row_val_str[r] : ""); return;
            }
            if (rid >= LOOK_RID_VAL_BASE && rid < LOOK_RID_VAL_BASE + LOOK_ROW_COUNT) {
                u32 r = rid - LOOK_RID_VAL_BASE;
                g_orig_set_cstr(sprite, g_look_val_str[r] ? g_look_val_str[r] : ""); return;
            }
            if (rid >= OG_RID_OPT_CHOICE && rid < OG_RID_OPT_CHOICE + 2U) {
                g_orig_set_cstr(sprite, kOnOffChoices[rid - OG_RID_OPT_CHOICE]); return;
            }
            if (rid >= LOOK_RID_OPT_CHOICE && rid < LOOK_RID_OPT_CHOICE + LOOK_PACK_COUNT) {
                g_orig_set_cstr(sprite, kLookPackChoices[rid - LOOK_RID_OPT_CHOICE]); return;
            }
            if (rid >= OG_RID_HELP_BASE && rid < OG_RID_HELP_BASE + OG_ROW_COUNT) {
                g_orig_set_cstr(sprite, kRowHelp[rid - OG_RID_HELP_BASE]); return;
            }
            if (rid >= LOOK_RID_HELP_BASE && rid < LOOK_RID_HELP_BASE + LOOK_ROW_COUNT) {
                g_orig_set_cstr(sprite, kLookRowHelp[rid - LOOK_RID_HELP_BASE]); return;
            }
            if (rid >= LOOK_RID_OPT_HELP && rid < LOOK_RID_OPT_HELP + LOOK_PACK_COUNT) {
                g_orig_set_cstr(sprite, kLookPackHelp[rid - LOOK_RID_OPT_HELP]); return;
            }
        }
        int lp = __atomic_load_n(&g_look_pack, __ATOMIC_ACQUIRE);
        if ((lp == 1 || lp == 2) &&
            ((rid >= 0x021C6190U && rid <= 0x021C725DU) ||
             rid == 0x0204E581U || rid == 0x0204E587U)) {
            const char *ls = lookup_creative_look_str(lp, rid);
            if (ls) { g_orig_set_cstr(sprite, ls); return; }
        }
        if (__atomic_load_n(&g_og_on, __ATOMIC_ACQUIRE)) {
            if (rid == RID_XAVC_HS_4K) { g_orig_set_cstr(sprite, "XAVC HS 4K OG");  return; }
            if (rid == RID_XAVC_S_4K)  { g_orig_set_cstr(sprite, "XAVC S 4K OG");   return; }
            if (rid == RID_XAVC_SI_4K) { g_orig_set_cstr(sprite, "XAVC S-I 4K OG"); return; }
        }
    }
    if (g_orig_set_rid) g_orig_set_rid(sprite, rid);
}

/* ---- 0x292 / 0x293 / 0x2A7 lifecycle & button hooks ---------------------- */
static void *og_ctrl_292_hook(void *buf, void *a1, void *a2, void *a3, u32 a4) {
    g_ret_pending = 0;
    g_our_2a7_kind = 0;
    busy_reset_state();
    return g_orig_ctrl_292(buf, a1, a2, a3, a4);
}
static void og_enter_293_hook(void *ctrl, const u32 *source) {
    if (!cur_our_group()) { g_orig_enter_293(ctrl, source); return; }
    u32 source_id = source ? *source : OG_GENERIC_SKIP;
    int restore = g_ret_pending;
    if (restore) {
        u32 *row_p = menu_id_ptr(APPFW_GET_SEL_ROW_OFF);
        if (row_p) *row_p = g_ret_item;
    }
    g_orig_enter_293(ctrl, source);
    if (restore) {
        void *cursor = (u8 *)ctrl + APPFW_293_CURSOR_OBJ_OFF;
        ((cursor_focus_fn)(g_appfw_base + APPFW_CURSOR_FOCUS_ITEM_OFF))(cursor, g_ret_item);
        g_ret_pending = 0;
    }
    og_busy_on_293_enter(ctrl, source_id);
}
static void *og_ctrl_293_hook(void *buf, void *a1, void *a2, void *a3, u32 a4) {
    int grp = cur_our_group();
    if (grp) {
        g_in_our_293 = 1;
        g_our_2a7_kind = 0;
        if (!__atomic_load_n(&g_busy, __ATOMIC_ACQUIRE)) {
            if (!g_apply_look_pack && g_libjit_base) {
                fn_dlsym_t fn_dlsym = (fn_dlsym_t)(g_libjit_base + LIBJIT_PLT_DLSYM);
                g_get_look_pack   = (fn_get_look_pack_t)fn_dlsym((void *)0, "a6700_get_look_pack");
                g_apply_look_pack = (fn_apply_look_pack_t)fn_dlsym((void *)0, "a6700_apply_look_pack");
            }
            if (g_get_look_pack) {
                int lp = g_get_look_pack();
                if (lp >= 0 && lp < (int)LOOK_PACK_COUNT)
                    __atomic_store_n(&g_look_pack, lp, __ATOMIC_RELEASE);
            }
            if (grp == 1) {
                int live_og = og_probe_live_on();
                if (live_og >= 0) __atomic_store_n(&g_og_on, live_og, __ATOMIC_RELEASE);
                __atomic_store_n(&g_sd_on, sd_probe_live_on(), __ATOMIC_RELEASE);
                __atomic_store_n(&g_shutter_on, shutter_probe_live_on(), __ATOMIC_RELEASE);
                __atomic_store_n(&g_cine_on, cine_probe_live_on(), __ATOMIC_RELEASE);
            }
        }
        update_row_val_strings();
        u32 base = (grp == 1) ? OG_ITEM_ID_BASE : LOOK_ITEM_ID_BASE;
        u32 cnt  = (grp == 1) ? OG_ROW_COUNT    : LOOK_ROW_COUNT;
        u32 *row_p  = menu_id_ptr(APPFW_GET_SEL_ROW_OFF);
        u32 *item_p = menu_id_ptr(APPFW_GET_CUR_ITEM_OFF);
        u32 r = row_p ? *row_p : 0U;
        if (r < base || r >= base + cnt) {
            if (row_p)  *row_p  = base;
            if (item_p) *item_p = base;
        }
    }
    void *ret = g_orig_ctrl_293(buf, a1, a2, a3, a4);
    if (ret && cur_our_group()) {
        u64 *vt = *(u64 **)ret;
        if (vt && vt[2] == g_appfw_base + APPFW_293_ON_ENTER_OFF) {
            if (!g_orig_enter_293) {
                mem_cpy(g_ctrl_vt_293, vt, sizeof(g_ctrl_vt_293));
                g_orig_enter_293 = (ctrl_enter_fn)vt[2];
                g_ctrl_vt_293[2] = (u64)og_enter_293_hook;
            }
            *(u64 **)ret = g_ctrl_vt_293;
        }
    }
    return ret;
}
static void *og_view_293_hook(void *buf, void *a1, void *a2, u32 pool_idx, u32 sid) {
    int grp = cur_our_group();
    if (!grp) return g_orig_view_293(buf, a1, a2, pool_idx, sid);
    g_in_our_293 = 1;
    g_our_2a7_kind = 0;
    u32 base = (grp == 1) ? OG_ITEM_ID_BASE : LOOK_ITEM_ID_BASE;
    u32 cnt  = (grp == 1) ? OG_ROW_COUNT    : LOOK_ROW_COUNT;
    u32 *row_p  = menu_id_ptr(APPFW_GET_SEL_ROW_OFF);
    u32 *item_p = menu_id_ptr(APPFW_GET_CUR_ITEM_OFF);
    u32 iid = item_p ? *item_p : 0U;
    u32 rid = row_p  ? *row_p  : 0U;
    int i_ok = (iid >= base && iid < base + cnt);
    int r_ok = (rid >= base && rid < base + cnt);
    u32 sync = i_ok ? iid : (r_ok ? rid : base);
    if (row_p)  *row_p  = sync;
    if (item_p) *item_p = sync;
    return g_orig_view_293(buf, a1, a2, pool_idx, OG_LIST_SCREEN_ID);
}
static u32 og_btn_confirm_hook(void *ctrl, void *ev) {
    int grp = cur_our_group();
    if (g_in_our_293 && grp && ctrl) {
        if (__atomic_load_n(&g_busy, __ATOMIC_ACQUIRE)) return 1U;
        const u32 *foc = ((get_id_ptr_fn)(g_appfw_base + APPFW_293_GET_FOCUSED_OFF))();
        u32 id = foc ? *foc : 0U;
        if (grp == 1 && id >= OG_ITEM_ID_BASE && id < OG_ITEM_ID_BASE + OG_ROW_COUNT) {
            u32 row = id - OG_ITEM_ID_BASE;
            g_og_2a7_row = row;
            int is_on = (row == 0U) ? g_og_on : ((row == 1U) ? g_sd_on : ((row == 2U) ? g_shutter_on : g_cine_on));
            g_og_2a7_cur_choice = is_on ? 0U : 1U;
            g_our_2a7_kind = 1;
            g_ret_item = id;
            g_ret_pending = 1;
            u32 *row_p  = menu_id_ptr(APPFW_GET_SEL_ROW_OFF);
            u32 *item_p = menu_id_ptr(APPFW_GET_CUR_ITEM_OFF);
            if (row_p)  *row_p  = id;
            if (item_p) *item_p = OG_OPT_GROUP_ID;
            u32 a[4] = { OG_OPT_SCREEN_ID, 0U, 0U, 0U };
            u32 b[4] = { OG_GENERIC_SKIP,  0U, 0U, 0U };
            u32 c[4] = { OG_GENERIC_SKIP,  0U, 0U, 0U };
            ((generic_open_fn)(g_appfw_base + APPFW_293_GENERIC_OPEN_OFF))(ctrl, a, b, c);
            return 1U;
        }
        if (grp == 2 && id >= LOOK_ITEM_ID_BASE && id < LOOK_ITEM_ID_BASE + LOOK_ROW_COUNT) {
            if (id != LOOK_ITEM_ID_BASE || !g_apply_look_pack) return 1U;
            int cur_lp = __atomic_load_n(&g_look_pack, __ATOMIC_ACQUIRE);
            g_og_2a7_cur_choice = (cur_lp >= 0 && cur_lp < (int)LOOK_PACK_COUNT) ? (u32)cur_lp : 0U;
            g_our_2a7_kind = 2;
            g_ret_item = LOOK_ITEM_ID_BASE;
            g_ret_pending = 1;
            u32 *row_p  = menu_id_ptr(APPFW_GET_SEL_ROW_OFF);
            u32 *item_p = menu_id_ptr(APPFW_GET_CUR_ITEM_OFF);
            if (row_p)  *row_p  = LOOK_ITEM_ID_BASE;
            if (item_p) *item_p = LOOK_OPT_GROUP_ID;
            u32 a[4] = { OG_OPT_SCREEN_ID, 0U, 0U, 0U };
            u32 b[4] = { OG_GENERIC_SKIP,  0U, 0U, 0U };
            u32 c[4] = { OG_GENERIC_SKIP,  0U, 0U, 0U };
            ((generic_open_fn)(g_appfw_base + APPFW_293_GENERIC_OPEN_OFF))(ctrl, a, b, c);
            return 1U;
        }
    }
    return g_orig_btn_confirm ? g_orig_btn_confirm(ctrl, ev) : 1U;
}
static u32 og_2a7_confirm_hook(void *ctrl, void *ev) {
    if (g_our_2a7_kind && ctrl) {
        const u32 *cur = menu_id_ptr(APPFW_GET_CUR_ITEM_OFF);
        if (g_our_2a7_kind == 1 && cur && *cur == OG_OPT_GROUP_ID) {
            const u32 *foc = ((get_id_ptr_fn)(g_appfw_base + APPFW_2A7_GET_FOCUSED_OFF))();
            u32 key = foc ? *foc : 0U;
            if (key >= OG_OPT_CHOICE_BASE && key < OG_OPT_CHOICE_BASE + 2U) {
                int want_on = (key == OG_OPT_CHOICE_BASE) ? 1 : 0;
                int cur_on  = (g_og_2a7_row == 0U) ? g_og_on
                            : ((g_og_2a7_row == 1U) ? g_sd_on
                            : ((g_og_2a7_row == 2U) ? g_shutter_on : g_cine_on));
                if (want_on != cur_on) dispatch_og_toggle(g_og_2a7_row, want_on);
            }
            g_our_2a7_kind = 0;
            u32 *item_p = menu_id_ptr(APPFW_GET_CUR_ITEM_OFF);
            if (item_p) *item_p = OG_ITEM_ID_BASE + g_og_2a7_row;
            ((ctrl_2a7_close_fn)(g_appfw_base + APPFW_2A7_CLOSE_OFF))(ctrl);
            return 1U;
        }
        if (g_our_2a7_kind == 2 && cur && *cur == LOOK_OPT_GROUP_ID) {
            const u32 *foc = ((get_id_ptr_fn)(g_appfw_base + APPFW_2A7_GET_FOCUSED_OFF))();
            u32 key = foc ? *foc : 0U;
            if (key >= LOOK_OPT_CHOICE_BASE && key < LOOK_OPT_CHOICE_BASE + LOOK_PACK_COUNT) {
                int want_pack = (int)(key - LOOK_OPT_CHOICE_BASE);
                dispatch_look_pack(want_pack);
            }
            g_our_2a7_kind = 0;
            u32 *item_p = menu_id_ptr(APPFW_GET_CUR_ITEM_OFF);
            if (item_p) *item_p = LOOK_ITEM_ID_BASE;
            ((ctrl_2a7_close_fn)(g_appfw_base + APPFW_2A7_CLOSE_OFF))(ctrl);
            return 1U;
        }
    }
    return g_orig_2a7_confirm ? g_orig_2a7_confirm(ctrl, ev) : 1U;
}
static u32 og_btn_back_common(void *ctrl, void *ev, ctrl_event_fn orig) {
    u32 r = orig ? orig(ctrl, ev) : 1U;
    if (g_in_our_293 && !cur_our_group()) {
        g_in_our_293 = 0; g_our_2a7_kind = 0; g_ret_pending = 0;
    }
    return r;
}
static u32 og_btn_back_hook(void *ctrl, void *ev)  { return og_btn_back_common(ctrl, ev, g_orig_btn_back); }
static u32 og_btn_back2_hook(void *ctrl, void *ev) { return og_btn_back_common(ctrl, ev, g_orig_btn_back2); }

/* ---- Menu descriptor & GOT installation (100% RAM-only) ------------------ */
static void normalize_child_desc(u8 *desc) {
    *(u64 *)(desc + 0x28ULL) = 0ULL;
    for (u32 k = 0; k < 9U; k++) *(u16 *)(desc + 0x3AULL + k * 2ULL) = 1U;
}

static int install_og_menu_ui(void) {
    u64 got_menu  = *(volatile u64 *)(g_appfw_base + APPFW_GOT_MENU_TABLE);
    u64 got_page  = *(volatile u64 *)(g_appfw_base + APPFW_GOT_PAGE_TABLE);
    u64 got_tree  = *(volatile u64 *)(g_appfw_base + APPFW_GOT_NONSETTING_TREE);
    u64 got_l293  = *(volatile u64 *)(g_appfw_base + APPFW_GOT_LAYOUT_293);
    u64 got_acc   = *(volatile u64 *)(g_appfw_base + APPFW_GOT_ISNAV_TABLE);
    u64 got_rid   = *(volatile u64 *)(g_appfw_base + APPFW_GOT_SET_STRING_RID);
    u64 got_conf  = *(volatile u64 *)(g_appfw_base + APPFW_GOT_BTN_CONFIRM);
    u64 got_back  = *(volatile u64 *)(g_appfw_base + APPFW_GOT_BTN_BACK);
    u64 got_back2 = *(volatile u64 *)(g_appfw_base + APPFW_GOT_BTN_BACK2);
    u64 got_2a7c  = *(volatile u64 *)(g_appfw_base + APPFW_GOT_2A7_CONFIRM);

    if (got_menu  != g_appfw_base + APPFW_MENU_TABLE_OFF ||
        got_page  != g_appfw_base + APPFW_PAGE_TABLE_OFF ||
        got_tree  != g_appfw_base + APPFW_NONSETTING_TREE_OFF ||
        got_l293  != g_appfw_base + APPFW_LAYOUT_293_OFF ||
        got_acc   != g_appfw_base + APPFW_ACCESSOR_VTABLE_OFF ||
        got_conf  != g_appfw_base + APPFW_BTN_CONFIRM_OFF ||
        got_back  != g_appfw_base + APPFW_BTN_BACK_OFF ||
        got_back2 != g_appfw_base + APPFW_BTN_BACK2_OFF ||
        got_2a7c  != g_appfw_base + APPFW_2A7_CONFIRM_OFF) {
        out_s("RESULT=ABORT_MISMATCH reason=appfw_got_unexpected\n");
        return 0;
    }

    /* Clone stock templates */
    mem_cpy(g_stock_ns_desc,   (const void *)(g_appfw_base + APPFW_STOCK_DESC_293_OFF),  APPFW_DESC_SIZE);
    mem_cpy(g_stock_item_desc, (const void *)(g_appfw_base + APPFW_STOCK_ITEM_DESC_OFF), APPFW_ITEM_DESC_SIZE);
    mem_cpy(g_stock_opt_desc,  (const void *)(g_appfw_base + APPFW_STOCK_OPT_DESC_OFF),  APPFW_OPT_DESC_SIZE);
    mem_cpy(g_stock_opt_row,   (const void *)(g_appfw_base + APPFW_STOCK_OPT_ROW_OFF),   APPFW_OPT_ROW_SIZE);
    mem_cpy(g_menu_table,      (const void *)got_menu, APPFW_MENU_TABLE_SIZE);
    mem_cpy(g_page_table,      (const void *)got_page, sizeof(g_page_table));
    mem_cpy(g_accessor_vt,     (const void *)got_acc,  sizeof(g_accessor_vt));

    /* Verify Setup -> Operation Customize (row_count==12, slot12 empty)
     * AND Exposure/Color -> Color/Tone (row_count==7, slot7 empty) */
    u32 *row_cnt = (u32 *)(g_menu_table + APPFW_CUSTOM_GROUP_OFF + 8ULL);
    struct menu_row_entry *slot12 = (struct menu_row_entry *)(g_menu_table + APPFW_CUSTOM_SLOT12_OFF);
    if (*row_cnt != APPFW_CUSTOM_STOCK_COUNT ||
        slot12->group_id != 0ULL || slot12->setting_desc != 0ULL || slot12->non_setting_desc != 0ULL) {
        out_s("RESULT=ABORT_MISMATCH reason=custom_group_slot12_occupied\n");
        return 0;
    }
    u32 *color_cnt = (u32 *)(g_menu_table + APPFW_COLOR_GROUP_OFF + 8ULL);
    struct menu_row_entry *slot7 = (struct menu_row_entry *)(g_menu_table + APPFW_COLOR_SLOT7_OFF);
    if (*color_cnt != APPFW_COLOR_STOCK_COUNT ||
        slot7->group_id != 0ULL || slot7->setting_desc != 0ULL || slot7->non_setting_desc != 0ULL) {
        out_s("RESULT=ABORT_MISMATCH reason=color_group_slot7_occupied\n");
        return 0;
    }

    /* Resolve TextSprite::setString + pthread/usleep + looks_pack symbols via libJiritsu PLT */
    fn_dlsym_t fn_dlsym = (fn_dlsym_t)(g_libjit_base + LIBJIT_PLT_DLSYM);
    g_orig_set_rid    = (text_set_rid_fn)fn_dlsym((void *)0, "_ZN2ux6gfxeng10TextSprite9setStringEj");
    g_orig_set_cstr   = (text_set_cstr_fn)fn_dlsym((void *)0, "_ZN2ux6gfxeng10TextSprite9setStringEPKc");
    g_pthread_create  = (fn_pthread_create_t)fn_dlsym((void *)0, "pthread_create");
    g_pthread_detach  = (fn_pthread_detach_t)fn_dlsym((void *)0, "pthread_detach");
    g_usleep          = (fn_usleep_t)fn_dlsym((void *)0, "usleep");
    g_get_look_pack   = (fn_get_look_pack_t)fn_dlsym((void *)0, "a6700_get_look_pack");
    g_apply_look_pack = (fn_apply_look_pack_t)fn_dlsym((void *)0, "a6700_apply_look_pack");
    if (!g_orig_set_rid || !g_orig_set_cstr) { out_s("RESULT=ABORT_TEXTSPRITE_SYM\n"); return 0; }
    g_look_pack = g_get_look_pack ? g_get_look_pack() : -1;

    /* Build Menu 1 parent descriptor ("Open Gate" -> screen 0x293, 3 rows) */
    mem_cpy(g_parent_desc, g_stock_ns_desc, APPFW_DESC_SIZE);
    *(u32 *)(g_parent_desc + 0x00ULL) = OG_RID_MENU_LABEL;
    *(u32 *)(g_parent_desc + 0x0CULL) = OG_LIST_SCREEN_ID;
    *(u64 *)(g_parent_desc + 0x20ULL) = g_appfw_base + APPFW_VISIBILITY_OK_OFF;
    *(u32 *)(g_parent_desc + 0x50ULL) = OG_ROW_COUNT;

    /* Build 4 toggle rows + right-aligned ON/OFF value descriptors + native Help RIDs */
    update_row_val_strings();
    for (u32 i = 0; i < OG_ROW_COUNT; i++) {
        mem_cpy(g_list_val_descs[i], g_stock_opt_desc, APPFW_OPT_DESC_SIZE);
        *(u32 *)(g_list_val_descs[i] + 0x00ULL) = OG_RID_ITEM_BASE + i;
        *(u32 *)(g_list_val_descs[i] + 0x0CULL) = OG_RID_HELP_BASE + i;
        *(u32 *)(g_list_val_descs[i] + 0x20ULL) = OG_OPT_SCREEN_ID;
        *(u32 *)(g_list_val_descs[i] + 0x40ULL) = 1U;
        *(u64 *)(g_list_val_descs[i] + 0x48ULL) = (u64)g_list_val_rows[i];
        *(u64 *)(g_list_val_descs[i] + 0x60ULL) = g_appfw_base + APPFW_VISIBILITY_OK_OFF;
        *(u64 *)(g_list_val_descs[i] + 0x68ULL) = g_appfw_base + APPFW_VISIBILITY_OK_OFF;
        *(u64 *)(g_list_val_descs[i] + 0x70ULL) = 0ULL;
        *(u64 *)(g_list_val_descs[i] + 0x78ULL) = 0ULL;
        *(u64 *)(g_list_val_descs[i] + 0x98ULL) = 0ULL;
        *(u64 *)(g_list_val_descs[i] + 0xA0ULL) = 0ULL;

        mem_cpy(g_list_val_rows[i], g_stock_opt_row, APPFW_OPT_ROW_SIZE);
        *(u32 *)(g_list_val_rows[i] + 0x00ULL) = OG_LIST_VAL_KEY_BASE + i;
        *(u32 *)(g_list_val_rows[i] + 0x04ULL) = OG_RID_VAL_BASE + i;
        *(u32 *)(g_list_val_rows[i] + 0x0CULL) = OG_RID_HELP_BASE + i;
        *(u32 *)(g_list_val_rows[i] + 0x48ULL) = 0U;
        *(u64 *)(g_list_val_rows[i] + 0x60ULL) = 0ULL;
        *(u64 *)(g_list_val_rows[i] + 0x80ULL) = g_appfw_base + APPFW_VISIBILITY_OK_OFF;
        *(u32 *)(g_list_val_rows[i] + 0x94ULL) = 0U;
        *(u64 *)(g_list_val_rows[i] + 0x98ULL) = 0ULL;

        mem_cpy(g_item_descs[i], g_stock_item_desc, APPFW_ITEM_DESC_SIZE);
        *(u32 *)(g_item_descs[i] + 0x00ULL) = OG_RID_ITEM_BASE + i;
        *(u32 *)(g_item_descs[i] + 0x0CULL) = OG_RID_HELP_BASE + i;
        *(u32 *)(g_item_descs[i] + 0x20ULL) = OG_OPT_SCREEN_ID;
        *(u32 *)(g_item_descs[i] + 0x40ULL) = 1U;
        *(u64 *)(g_item_descs[i] + 0x48ULL) = (u64)g_list_val_rows[i];
        *(u64 *)(g_item_descs[i] + 0x58ULL) = g_appfw_base + APPFW_VISIBILITY_OK_OFF;
        *(u64 *)(g_item_descs[i] + 0x68ULL) = g_appfw_base + APPFW_VISIBILITY_OK_OFF;

        mem_cpy(g_item_ns_descs[i], g_stock_ns_desc, APPFW_DESC_SIZE);
        *(u32 *)(g_item_ns_descs[i] + 0x00ULL) = OG_RID_ITEM_BASE + i;
        *(u32 *)(g_item_ns_descs[i] + 0x0CULL) = OG_OPT_SCREEN_ID;
        *(u64 *)(g_item_ns_descs[i] + 0x20ULL) = g_appfw_base + APPFW_VISIBILITY_OK_OFF;
        *(u32 *)(g_item_ns_descs[i] + 0x50ULL) = 0U;
        normalize_child_desc(g_item_ns_descs[i]);

        u8 *slot = g_parent_desc + APPFW_DESC_SIZE + i * APPFW_ITEM_ENTRY_SIZE;
        *(u32 *)(slot + 0x00ULL) = OG_ITEM_ID_BASE + i;
        *(u32 *)(slot + 0x04ULL) = 0U;
        *(u64 *)(slot + 0x08ULL) = (u64)g_item_descs[i];
    }

    /* Build Menu 2 parent descriptor ("Creative Looks" -> screen 0x293, 5 rows incl. notes) */
    mem_cpy(g_look_parent_desc, g_stock_ns_desc, APPFW_DESC_SIZE);
    *(u32 *)(g_look_parent_desc + 0x00ULL) = LOOK_RID_MENU_LABEL;
    *(u32 *)(g_look_parent_desc + 0x0CULL) = OG_LIST_SCREEN_ID;
    *(u64 *)(g_look_parent_desc + 0x20ULL) = g_appfw_base + APPFW_VISIBILITY_OK_OFF;
    *(u32 *)(g_look_parent_desc + 0x50ULL) = LOOK_ROW_COUNT;

    for (u32 i = 0; i < LOOK_ROW_COUNT; i++) {
        mem_cpy(g_look_val_descs[i], g_stock_opt_desc, APPFW_OPT_DESC_SIZE);
        *(u32 *)(g_look_val_descs[i] + 0x00ULL) = LOOK_RID_ITEM_BASE + i;
        *(u32 *)(g_look_val_descs[i] + 0x0CULL) = LOOK_RID_HELP_BASE + i;
        *(u32 *)(g_look_val_descs[i] + 0x20ULL) = OG_OPT_SCREEN_ID;
        *(u32 *)(g_look_val_descs[i] + 0x40ULL) = 1U;
        *(u64 *)(g_look_val_descs[i] + 0x48ULL) = (u64)g_look_val_rows[i];
        *(u64 *)(g_look_val_descs[i] + 0x60ULL) = g_appfw_base + APPFW_VISIBILITY_OK_OFF;
        *(u64 *)(g_look_val_descs[i] + 0x68ULL) = g_appfw_base + APPFW_VISIBILITY_OK_OFF;
        *(u64 *)(g_look_val_descs[i] + 0x70ULL) = 0ULL;
        *(u64 *)(g_look_val_descs[i] + 0x78ULL) = 0ULL;
        *(u64 *)(g_look_val_descs[i] + 0x98ULL) = 0ULL;
        *(u64 *)(g_look_val_descs[i] + 0xA0ULL) = 0ULL;

        mem_cpy(g_look_val_rows[i], g_stock_opt_row, APPFW_OPT_ROW_SIZE);
        *(u32 *)(g_look_val_rows[i] + 0x00ULL) = LOOK_LIST_VAL_KEY_BASE + i;
        *(u32 *)(g_look_val_rows[i] + 0x04ULL) = LOOK_RID_VAL_BASE + i;
        *(u32 *)(g_look_val_rows[i] + 0x0CULL) = LOOK_RID_HELP_BASE + i;
        *(u32 *)(g_look_val_rows[i] + 0x48ULL) = 0U;
        *(u64 *)(g_look_val_rows[i] + 0x60ULL) = 0ULL;
        *(u64 *)(g_look_val_rows[i] + 0x80ULL) = g_appfw_base + APPFW_VISIBILITY_OK_OFF;
        *(u32 *)(g_look_val_rows[i] + 0x94ULL) = 0U;
        *(u64 *)(g_look_val_rows[i] + 0x98ULL) = 0ULL;

        mem_cpy(g_look_item_descs[i], g_stock_item_desc, APPFW_ITEM_DESC_SIZE);
        *(u32 *)(g_look_item_descs[i] + 0x00ULL) = LOOK_RID_ITEM_BASE + i;
        *(u32 *)(g_look_item_descs[i] + 0x0CULL) = LOOK_RID_HELP_BASE + i;
        *(u32 *)(g_look_item_descs[i] + 0x20ULL) = OG_OPT_SCREEN_ID;
        *(u32 *)(g_look_item_descs[i] + 0x40ULL) = 1U;
        *(u64 *)(g_look_item_descs[i] + 0x48ULL) = (u64)g_look_val_rows[i];
        *(u64 *)(g_look_item_descs[i] + 0x58ULL) = g_appfw_base + APPFW_VISIBILITY_OK_OFF;
        *(u64 *)(g_look_item_descs[i] + 0x68ULL) = g_appfw_base + APPFW_VISIBILITY_OK_OFF;

        mem_cpy(g_look_item_ns_descs[i], g_stock_ns_desc, APPFW_DESC_SIZE);
        *(u32 *)(g_look_item_ns_descs[i] + 0x00ULL) = LOOK_RID_ITEM_BASE + i;
        *(u32 *)(g_look_item_ns_descs[i] + 0x0CULL) = OG_OPT_SCREEN_ID;
        *(u64 *)(g_look_item_ns_descs[i] + 0x20ULL) = g_appfw_base + APPFW_VISIBILITY_OK_OFF;
        *(u32 *)(g_look_item_ns_descs[i] + 0x50ULL) = 0U;
        normalize_child_desc(g_look_item_ns_descs[i]);

        u8 *slot = g_look_parent_desc + APPFW_DESC_SIZE + i * APPFW_ITEM_ENTRY_SIZE;
        *(u32 *)(slot + 0x00ULL) = LOOK_ITEM_ID_BASE + i;
        *(u32 *)(slot + 0x04ULL) = 0U;
        *(u64 *)(slot + 0x08ULL) = (u64)g_look_item_descs[i];
    }

    /* Build 0x2A7 On/Off picker descriptor (2 choices: ON, OFF) */
    mem_cpy(g_opt_setting_desc, g_stock_opt_desc, APPFW_OPT_DESC_SIZE);
    *(u32 *)(g_opt_setting_desc + 0x00ULL) = OG_RID_OPT_TITLE;
    *(u32 *)(g_opt_setting_desc + 0x0CULL) = OG_RID_EMPTY;
    *(u32 *)(g_opt_setting_desc + 0x20ULL) = OG_OPT_SCREEN_ID;
    *(u32 *)(g_opt_setting_desc + 0x40ULL) = 2U;
    *(u64 *)(g_opt_setting_desc + 0x48ULL) = (u64)g_opt_rows;
    *(u64 *)(g_opt_setting_desc + 0x60ULL) = g_appfw_base + APPFW_VISIBILITY_OK_OFF;
    *(u64 *)(g_opt_setting_desc + 0x68ULL) = g_appfw_base + APPFW_VISIBILITY_OK_OFF;
    *(u64 *)(g_opt_setting_desc + 0x70ULL) = 0ULL;
    *(u64 *)(g_opt_setting_desc + 0x78ULL) = 0ULL;
    *(u64 *)(g_opt_setting_desc + 0x98ULL) = 0ULL;
    *(u64 *)(g_opt_setting_desc + 0xA0ULL) = 0ULL;
    for (u32 c = 0; c < 2U; c++) {
        mem_cpy(g_opt_rows[c], g_stock_opt_row, APPFW_OPT_ROW_SIZE);
        *(u32 *)(g_opt_rows[c] + 0x00ULL) = OG_OPT_CHOICE_BASE + c;
        *(u32 *)(g_opt_rows[c] + 0x04ULL) = OG_RID_OPT_CHOICE + c;
        *(u32 *)(g_opt_rows[c] + 0x0CULL) = OG_RID_EMPTY;
        *(u32 *)(g_opt_rows[c] + 0x48ULL) = c;
        *(u64 *)(g_opt_rows[c] + 0x60ULL) = 0ULL;
        *(u64 *)(g_opt_rows[c] + 0x80ULL) = g_appfw_base + APPFW_VISIBILITY_OK_OFF;
        *(u32 *)(g_opt_rows[c] + 0x94ULL) = 0U;
        *(u64 *)(g_opt_rows[c] + 0x98ULL) = 0ULL;
    }

    /* Build 0x2A7 Creative Look Pack picker (3 choices: Stock / FX2 / Fujifilm 4-Sim) */
    mem_cpy(g_look_opt_desc, g_stock_opt_desc, APPFW_OPT_DESC_SIZE);
    *(u32 *)(g_look_opt_desc + 0x00ULL) = LOOK_RID_OPT_TITLE;
    *(u32 *)(g_look_opt_desc + 0x0CULL) = OG_RID_EMPTY;
    *(u32 *)(g_look_opt_desc + 0x20ULL) = OG_OPT_SCREEN_ID;
    *(u32 *)(g_look_opt_desc + 0x40ULL) = LOOK_PACK_COUNT;
    *(u64 *)(g_look_opt_desc + 0x48ULL) = (u64)g_look_opt_rows;
    *(u64 *)(g_look_opt_desc + 0x60ULL) = g_appfw_base + APPFW_VISIBILITY_OK_OFF;
    *(u64 *)(g_look_opt_desc + 0x68ULL) = g_appfw_base + APPFW_VISIBILITY_OK_OFF;
    *(u64 *)(g_look_opt_desc + 0x70ULL) = 0ULL;
    *(u64 *)(g_look_opt_desc + 0x78ULL) = 0ULL;
    *(u64 *)(g_look_opt_desc + 0x98ULL) = 0ULL;
    *(u64 *)(g_look_opt_desc + 0xA0ULL) = 0ULL;
    for (u32 c = 0; c < LOOK_PACK_COUNT; c++) {
        mem_cpy(g_look_opt_rows[c], g_stock_opt_row, APPFW_OPT_ROW_SIZE);
        *(u32 *)(g_look_opt_rows[c] + 0x00ULL) = LOOK_OPT_CHOICE_BASE + c;
        *(u32 *)(g_look_opt_rows[c] + 0x04ULL) = LOOK_RID_OPT_CHOICE + c;
        *(u32 *)(g_look_opt_rows[c] + 0x0CULL) = LOOK_RID_OPT_HELP + c;
        *(u32 *)(g_look_opt_rows[c] + 0x48ULL) = c;
        *(u64 *)(g_look_opt_rows[c] + 0x60ULL) = 0ULL;
        *(u64 *)(g_look_opt_rows[c] + 0x80ULL) = g_appfw_base + APPFW_VISIBILITY_OK_OFF;
        *(u32 *)(g_look_opt_rows[c] + 0x94ULL) = 0U;
        *(u64 *)(g_look_opt_rows[c] + 0x98ULL) = 0ULL;
    }

    /* Wire accessor vtable hooks */
    u64 *vt = g_accessor_vt + APPFW_ACCESSOR_HDR_QWS;
    g_orig_acc_grp_desc   = (accessor_ptr_fn)vt[2];   vt[2]   = (u64)acc_grp_desc_hook;
    g_orig_acc_row_desc   = (accessor_ptr_fn)vt[4];   vt[4]   = (u64)acc_row_desc_hook;
    g_orig_acc_row_vis    = (accessor_u32_fn)vt[50];  vt[50]  = (u64)acc_row_vis_hook;
    g_orig_acc_get_val    = (accessor_u32_fn)vt[82];  vt[82]  = (u64)acc_get_val_hook;
    g_orig_acc_item_grp   = (accessor_u32_fn)vt[94];  vt[94]  = (u64)acc_item_grp_hook;
    g_orig_acc_row_struct = (accessor_ptr_fn)vt[203]; vt[203] = (u64)acc_row_struct_hook;
    g_orig_acc_grp_struct = (accessor_ptr_fn)vt[206]; vt[206] = (u64)acc_grp_struct_hook;

    /* Wire page table hooks (0x260 busy + 0x292 reset + 0x293 list) */
    u8 *e260 = g_page_table + (u64)OG_BUSY_SCREEN_ID * APPFW_PAGE_ENTRY_SIZE;
    if (*(u64 *)(e260 + 8ULL) == g_appfw_base + APPFW_CTRL_FACTORY_260_OFF) {
        g_orig_ctrl_260 = (ctrl_factory_fn)(*(u64 *)(e260 + 8ULL));
        *(u64 *)(e260 + 8ULL) = (u64)og_ctrl_260_hook;
    }
    u8 *e292 = g_page_table + 0x292ULL * APPFW_PAGE_ENTRY_SIZE;
    if (*(u64 *)(e292 + 8ULL)) {
        g_orig_ctrl_292 = (ctrl_factory_fn)(*(u64 *)(e292 + 8ULL));
        *(u64 *)(e292 + 8ULL) = (u64)og_ctrl_292_hook;
    }
    u8 *e293 = g_page_table + (u64)OG_LIST_SCREEN_ID * APPFW_PAGE_ENTRY_SIZE;
    g_orig_view_293 = (view_factory_fn)(g_appfw_base + APPFW_VIEW_FACTORY_293_OFF);
    g_orig_ctrl_293 = (ctrl_factory_fn)(g_appfw_base + APPFW_CTRL_FACTORY_293_OFF);
    *(u64 *)(e293 + 0ULL) = (u64)og_view_293_hook;
    *(u64 *)(e293 + 8ULL) = (u64)og_ctrl_293_hook;

    /* Populate Slot 12 in Setup -> Operation Customize AND Slot 7 in Exposure/Color -> Color/Tone */
    slot12->group_id = OG_GROUP_ID;
    slot12->setting_desc = 0ULL;
    slot12->non_setting_desc = (u64)g_parent_desc;
    *row_cnt = APPFW_CUSTOM_STOCK_COUNT + 1U;

    slot7->group_id = LOOK_GROUP_ID;
    slot7->setting_desc = 0ULL;
    slot7->non_setting_desc = (u64)g_look_parent_desc;
    *color_cnt = APPFW_COLOR_STOCK_COUNT + 1U;

    /* Save button handlers & install GOT hooks in safe dependency order */
    g_orig_btn_confirm = (ctrl_event_fn)got_conf;
    g_orig_btn_back    = (ctrl_event_fn)got_back;
    g_orig_btn_back2   = (ctrl_event_fn)got_back2;
    g_orig_2a7_confirm = (ctrl_event_fn)got_2a7c;

    if (!patch_got_ptr(g_appfw_base + APPFW_GOT_SET_STRING_RID, got_rid,   (u64)og_set_string_rid_hook) ||
        !patch_got_ptr(g_appfw_base + APPFW_GOT_ISNAV_TABLE,    got_acc,   (u64)g_accessor_vt) ||
        !patch_got_ptr(g_appfw_base + APPFW_GOT_2A7_CONFIRM,    got_2a7c,  (u64)og_2a7_confirm_hook) ||
        !patch_got_ptr(g_appfw_base + APPFW_GOT_BTN_CONFIRM,    got_conf,  (u64)og_btn_confirm_hook) ||
        !patch_got_ptr(g_appfw_base + APPFW_GOT_BTN_BACK,       got_back,  (u64)og_btn_back_hook) ||
        !patch_got_ptr(g_appfw_base + APPFW_GOT_BTN_BACK2,      got_back2, (u64)og_btn_back2_hook)) {
        out_s("RESULT=ABORT_GOT_PATCH_FAIL\n");
        return 0;
    }

    /* Register groups 0x535 (+3 items) & 0x537 (+2 items) in appFw's non-setting runtime tree */
    tree_insert_fn tree_ins = (tree_insert_fn)(g_appfw_base + APPFW_TREE_INSERT_OFF);
    g_tree_parent.group_id = OG_GROUP_ID;
    g_tree_parent.desc_ptr = (u64)g_parent_desc;
    tree_ins((void *)got_tree, &g_tree_parent, &g_tree_parent + 1);
    for (u32 i = 0; i < OG_ROW_COUNT; i++) {
        g_tree_items[i].group_id = OG_ITEM_ID_BASE + i;
        g_tree_items[i].desc_ptr = (u64)g_item_ns_descs[i];
        tree_ins((void *)got_tree, &g_tree_items[i], &g_tree_items[i] + 1);
    }
    g_tree_look_parent.group_id = LOOK_GROUP_ID;
    g_tree_look_parent.desc_ptr = (u64)g_look_parent_desc;
    tree_ins((void *)got_tree, &g_tree_look_parent, &g_tree_look_parent + 1);
    for (u32 i = 0; i < LOOK_ROW_COUNT; i++) {
        g_tree_look_items[i].group_id = LOOK_ITEM_ID_BASE + i;
        g_tree_look_items[i].desc_ptr = (u64)g_look_item_ns_descs[i];
        tree_ins((void *)got_tree, &g_tree_look_items[i], &g_tree_look_items[i] + 1);
    }

    /* Publish cloned page table GOT, then cloned menu table GOT LAST! */
    if (!patch_got_ptr(g_appfw_base + APPFW_GOT_PAGE_TABLE, got_page, (u64)g_page_table) ||
        !patch_got_ptr(g_appfw_base + APPFW_GOT_MENU_TABLE, got_menu, (u64)g_menu_table)) {
        out_s("RESULT=ABORT_TABLE_PUBLISH_FAIL\n");
        return 0;
    }
    return 1;
}

/* ---- Stage 1: Copy self to volatile RAM /tmp_wbshd & pin via dlopen ------ */
static int stage_self_to_ram_and_pin(const char *self_path, u64 libjit_base, u64 appfw_base) {
    fn_dlopen_t  fn_dlopen  = (fn_dlopen_t)(libjit_base + LIBJIT_PLT_DLOPEN);
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
    void *h = fn_dlopen(STAGE_RAM_SO, RTLD_NOW_LOC);
    (void)sys_unlink(STAGE_RAM_SO); /* always unlink volatile RAM file immediately! */
    if (!h) return 0;
    /* If Stage 2 aborted without installing the menu GOT, unload cleanly so retries work! */
    if (*(volatile u64 *)(appfw_base + APPFW_GOT_MENU_TABLE) == appfw_base + APPFW_MENU_TABLE_OFF)
        (void)fn_dlclose(h);
    return 1;
}

__attribute__((visibility("default"))) void _init(void) {
    g_olen = 0;
    g_maps_len = read_text_file("/proc/self/maps", g_maps, sizeof(g_maps));
    read_text_file("/proc/cmdline", g_cmdline, sizeof(g_cmdline));

    char self_path[200]; self_path[0] = 0;
    (void)find_addr_info(read_cur_pc(), 0, self_path, sizeof(self_path));

    g_appfw_base  = find_mapped_slice("/appFw.so",     0, 4096, 5u, 0, 0, 0);
    g_libmpr_base = find_mapped_slice("/libmpr.so",    0, 4096, 5u, 0, 0, 0);
    g_libjit_base = find_mapped_slice("/libJiritsu.so",0, 4096, 5u, 0, 0, 0);
    if (!g_appfw_base || !g_libmpr_base || !g_libjit_base) {
        out_s("A6700_OG_MENU_RAM_V1\nRESULT=ABORT_MAPS_MISSING\n");
        flush_result();
        return;
    }

    /* Stage 1: Transient Jiritsu trigger (/tmp/jiritsu/libJit.so) -> relocate to volatile RAM */
    if (ends_with(self_path, slen(self_path), "/libJit.so")) {
        u64 cur_menu = *(volatile u64 *)(g_appfw_base + APPFW_GOT_MENU_TABLE);
        if (cur_menu != g_appfw_base + APPFW_MENU_TABLE_OFF) {
            out_s("A6700_OG_MENU_RAM_V1\nRESULT=ALREADY_INSTALLED menu=Setup/OperationCustomize/OpenGate\n");
            flush_result();
            return;
        }
        /* Verify libJiritsu.so SHA-256 before trusting LIBJIT_GOT_DLOPEN */
        char jpath[200]; jpath[0] = 0;
        u64 jsz = 0; u8 jdig[32];
        (void)find_mapped_slice(OG_ID_FILES[2].suffix, 0, 4096, 5u, 0, jpath, sizeof(jpath));
        if (!jpath[0] || !hash_disk_file(jpath, &jsz, jdig) ||
            jsz != OG_ID_FILES[2].size || !mem_eq(jdig, OG_ID_FILES[2].sha256, 32U)) {
            out_s("A6700_OG_MENU_RAM_V1\nRESULT=ABORT_IDENTITY reason=libjit_sha_mismatch\n");
            flush_result();
            return;
        }
        if (!stage_self_to_ram_and_pin(self_path, g_libjit_base, g_appfw_base)) {
            out_s("A6700_OG_MENU_RAM_V1\nRESULT=ABORT_RAM_STAGE_FAIL\n");
            flush_result();
        }
        return;
    }

    /* Stage 2: Running permanently pinned inside volatile RAM! */
    out_s("A6700_OG_MENU_RAM_V1 a6700_og_menu_v6_2_1 self="); out_s(self_path); out_s("\n");
    u64 ctr = read_ctr_el0();
    u32 l1ip = (u32)(ctr >> 14) & 3U;
    out_s("CTR_EL0="); out_hex(ctr); out_s(" L1Ip="); out_u64(l1ip); out_s("\n");
    if (l1ip < 2U || !cmdline_has(OG_AVCAM_RESERVE)) {
        out_s("RESULT=ABORT_IDENTITY reason=ctr_or_cmdline\n");
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
            fsz != f->size || !mem_eq(dig, f->sha256, 32U)) {
            out_s("RESULT=ABORT_IDENTITY reason=lib_sha_mismatch lib="); out_s(f->suffix); out_s("\n");
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
        out_s("RESULT=ABORT_IDENTITY reason=sencore_prologue\n");
        flush_result();
        return;
    }

    /* Probe PAL/NTSC + pre-expand DmmCfg 0x57f (3980x6016) + detect live ON/OFF state */
    u32 dmm_handle = 0;
    g_cp_phys = g_dmm_alloc(CP_PAGE, &dmm_handle);
    if (!g_cp_phys || (g_cp_phys & 0x3FULL) || g_cp_phys < RAM_LO || (g_cp_phys + CP_PAGE) > RAM_HI) {
        if (dmm_handle) g_dmm_free(dmm_handle);
        out_s("RESULT=ABORT_DMM_ALLOC\n");
        flush_result();
        return;
    }
    i64 cp_fd = sys_open("/dev/mem", O_RDWR_SYNC, 0);
    u64 cp_lead = g_cp_phys & 0xFFFULL;
    u64 cp_maplen = (cp_lead + CP_PAGE + 0xFFFULL) & ~0xFFFULL;
    i64 cp_map = (cp_fd >= 0) ? sys_mmap_rw(cp_fd, cp_maplen, g_cp_phys - cp_lead) : -1;
    if (cp_map == -1) {
        if (cp_fd >= 0) sys_close(cp_fd);
        g_dmm_free(dmm_handle);
        out_s("RESULT=ABORT_CP_MMAP\n");
        flush_result();
        return;
    }
    g_cp_buf = (u8 *)cp_map + cp_lead;

    int id_ok = 1;
    for (u32 i = 0; i < 3U; i++) {
        u8 *p = cp_dma_read_span(OG_ID_PAGES[i].cp_va, CP_PAGE, 0, 0);
        u8 dig[32];
        if (!p || (sha_buf(p, CP_PAGE, dig), !mem_eq(dig, OG_ID_PAGES[i].sha256, 32U))) id_ok = 0;
    }
    u8 *p820 = cp_dma_read_span(CP_DRVPARAM_820, CP_DRVPARAM_LEN, 0, 0);
    if (p820) {
        u32 vtot = rd_u32(p820 + 0x2CU);
        if (vtot == OG_VTOT_820_PAL)       g_is_pal = 1;
        else if (vtot == OG_VTOT_820_NTSC) g_is_pal = 0;
    }
    int dmm_ok = (id_ok && g_is_pal >= 0) ? ensure_dmm57f_expanded() : 0;
    u8 *pS = cp_dma_read_span(OG_SIZETBL_SITE_VA, 4U, 0, 0);
    g_og_on = (pS && mem_eq(pS, OG_SIZETBL_NEW, 4U)) ? 1 : 0;
    g_sd_on = sd_probe_live_on();
    shutter_cache_pid_addrs();
    g_shutter_on = shutter_probe_live_on();
    cine_cache_pid_addrs();
    g_cine_on = cine_probe_live_on();

    sys_munmap((void *)cp_map, cp_maplen);
    sys_close(cp_fd);
    g_dmm_free(dmm_handle);
    g_cp_buf = 0;

    if (!id_ok || g_is_pal < 0) {
        out_s("RESULT=ABORT_IDENTITY reason=cp_page_or_system\n");
        flush_result();
        return;
    }
    out_s(g_is_pal ? "SYSTEM=PAL_50HZ\n" : "SYSTEM=NTSC_60HZ\n");
    if (!dmm_ok) {
        out_s("RESULT=ABORT_MISMATCH reason=dmm_57f_already_divided (cold-boot on STILLS required)\n");
        flush_result();
        return;
    }
    out_s("DMMCFG_BASE="); out_hex(g_dmm_base); out_s(" dmm57f=0x016d5a00\n");

    if (!install_og_menu_ui()) {
        flush_result();
        return;
    }
    out_s("MENU_INSTALLED=1 path1=Setup/OperationCustomize/Wildcard path2=ExposureColor/ColorTone/CreativeLooks og=");
    out_s(g_og_on ? "ON" : "OFF");
    out_s(" sd_bypass="); out_s(g_sd_on ? "ON" : "OFF");
    out_s(" shutter="); out_s(g_shutter_on ? "ON" : "OFF");
    out_s(" cine_ei="); out_s(g_cine_on ? "ON" : "OFF");
    out_s(" looks_pack="); out_u64((u64)(g_look_pack >= 0 ? g_look_pack : 9)); out_s("\n");
    out_s("RESULT=APPLY_OK feature=og_menu_ram_v2\n");
    flush_result();
}
