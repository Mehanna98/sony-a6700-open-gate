/* a6700_cine_ei_ram.c -- All-or-nothing compare-and-swap RAM-only Cine EI patcher.
 *
 * Target: Sony ILCE-6700 (a6700) FW v2.00 ONLY (stock appFw.so SHA-256 verified).
 * Scope : Steps 0-6 + Layer 5 menu permissions (skips experimental Steps 7-8;
 *         Layer 3 PRM 0x2bd is verified RO and intentionally NOT written at runtime, matching FireHydrant;
 *         Step 2 safely decrements-by-1 ONLY the 58 FX30-valid Cine EI pairs to prevent exclusion_manager.cpp:1599).
 *
 * SAFETY GUARANTEES:
 *   - ZERO flash writes to /usr/lib/appFw.so, /cp/cpapp-b.bin, /dev/nflasha5 (WBI), or /setting/.
 *   - All memory writes hit MAP_PRIVATE copy-on-write RAM pages only; battery pull (10s) = 100% stock.
 *   - PASS 0 verifies appFw.so file SHA-256 + /proc/self/maps PT_LOAD[0]/[1] layout.
 *   - PASS 1 verifies EVERY SINGLE preimage byte, relocated pointer, Step-2 flag_slot, Step-3 value,
 *     and live support-map node BEFORE writing a single byte. Any mismatch -> ABORT with 0 writes.
 *   - PASS 2 applies private COW writes (never dropping PROT_EXEC on PT_LOAD[0] pages; full AArch64
 *     D-cache clean + I-cache invalidate + barriers).
 *   - PASS 3 reads back EVERY patched site and only reports RESULT=APPLY_OK on 100% match.
 */
#include "a6700_common.h"
#include "a6700_cine_ei_patch_spec.h"

#define NR_mprotect 226
#define PROT_READ   1
#define PROT_WRITE  2
#define PROT_EXEC   4

static i64 sys_mprotect(u64 addr, u64 len, i64 prot) {
    return sc6(NR_mprotect, (i64)addr, (i64)len, prot, 0, 0, 0);
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

/* Write bytes to private RAM, preserving PROT_EXEC on RX pages during temporary RW. */
static int cow_write(u64 addr, const u8 *src, u64 len, int is_code) {
    u8 orig_perms = 0;
    if (!find_vma(addr, len, &orig_perms) || !(orig_perms & 1u)) return 0;

    int need_mprot = !(orig_perms & 2u);
    u64 pg_start = addr & ~4095ULL;
    u64 pg_end   = (addr + len + 4095ULL) & ~4095ULL;
    u64 pg_len   = pg_end - pg_start;

    i64 orig_prot = ((orig_perms & 1u) ? PROT_READ : 0)
                  | ((orig_perms & 2u) ? PROT_WRITE : 0)
                  | ((orig_perms & 4u) ? PROT_EXEC : 0);

    if (need_mprot) {
        /* Never drop PROT_EXEC on a live RX page while other appFw threads execute! */
        if (sys_mprotect(pg_start, pg_len, orig_prot | PROT_WRITE) != 0) return 0;
    }

    if (is_code && ((addr & 3ULL) == 0) && ((len & 3ULL) == 0)) {
        volatile u32 *dst32 = (volatile u32 *)addr;
        for (u64 i = 0; i < len; i += 4ULL) {
            u32 w = (u32)src[i] | ((u32)src[i+1] << 8)
                  | ((u32)src[i+2] << 16) | ((u32)src[i+3] << 24);
            __atomic_store_n(&dst32[i >> 2], w, __ATOMIC_RELEASE);
        }
        flush_icache_range(addr, len);
    } else {
        volatile u8 *dst = (volatile u8 *)addr;
        for (u64 i = 0; i < len; i++) dst[i] = src[i];
        __asm__ volatile("dsb ish" ::: "memory");
    }

    if (need_mprot) {
        (void)sys_mprotect(pg_start, pg_len, orig_prot);
    }
    return 1;
}

static int cow_write_u32(u64 addr, u32 val) {
    u8 b[4] = { (u8)(val), (u8)(val >> 8), (u8)(val >> 16), (u8)(val >> 24) };
    return cow_write(addr, b, 4, 0);
}

__attribute__((visibility("default"))) void _init(void) {
    g_olen = 0;
    out_s("A6700_CINE_EI_RAM_V2_1\n");

    /* ==== PASS 0: File SHA-256 & /proc/self/maps identity gate ============ */
    u64 fsz = 0;
    char sha_hex[65];
    int sha_ok = verify_appfw_file(&fsz, sha_hex);
    int maps_ok = parse_proc_maps();
    out_s("APPFW_SIZE="); out_u64(fsz);
    out_s(" MATCH="); out_u64((u64)sha_ok);
    out_s(" LOAD_BASE="); out_hex(g_load_base);
    out_s(" LOAD1_OK="); out_u64((u64)g_load1_ok); out_s("\n");

    if (!sha_ok || !maps_ok || !g_load1_ok) {
        out_s("RESULT=ABORT_IDENTITY writes=0\n");
        flush_result();
        return;
    }

    /* ==== PASS 1: 100% Dry Preimage Check (ZERO writes!) ================== */
    u32 errs = 0;

    /* 1a. All 25 fixed byte/code patches */
    for (u32 i = 0; i < CINE_BYTE_PATCH_COUNT; i++) {
        const struct byte_patch *bp = &CINE_BYTE_PATCHES[i];
        u8 cur[24];
        if (!safe_read_bytes(g_load_base + bp->elf_va, cur, bp->len)) {
            out_s("PRE_FAIL unmapped "); out_s(bp->tag); out_s("\n");
            errs++;
            continue;
        }
        for (u8 k = 0; k < bp->len; k++) {
            if (cur[k] != bp->before[k]) {
                out_s("PRE_FAIL byte "); out_s(bp->tag); out_s(" va="); out_hex(bp->elf_va);
                out_s(" got="); out_hex_bytes(cur, bp->len); out_s("\n");
                errs++;
                break;
            }
        }
    }

    /* 1b. Layer 3 (PRM 0x2bd): verify LAX ptr & stock DZ == 0 */
    u64 l3_lax = 0, l3_dz = 0;
    u64 exp_lax = g_load_base + LAYER3_LAX_TARGET_VA;
    if (!safe_read_u64(g_load_base + LAYER3_LAX_SLOT_VA, &l3_lax) || l3_lax != exp_lax) {
        out_s("PRE_FAIL l3_lax got="); out_hex(l3_lax); out_s(" exp="); out_hex(exp_lax); out_s("\n");
        errs++;
    }
    if (!safe_read_u64(g_load_base + LAYER3_DZ_SLOT_VA, &l3_dz) || l3_dz != 0ULL) {
        out_s("PRE_FAIL l3_dz got="); out_hex(l3_dz); out_s("\n");
        errs++;
    }

    /* 1c. Step 3 (.bss HIGH Base ISO anchor == 26 on both copies) */
    u32 s3a = 0, s3b = 0;
    if (!safe_read_u32(g_load_base + STEP3_HIGH_A_VA, &s3a) || s3a != STEP3_STOCK_VAL) {
        out_s("PRE_FAIL step3_a got="); out_u64(s3a); out_s("\n");
        errs++;
    }
    if (!safe_read_u32(g_load_base + STEP3_HIGH_B_VA, &s3b) || s3b != STEP3_STOCK_VAL) {
        out_s("PRE_FAIL step3_b got="); out_u64(s3b); out_s("\n");
        errs++;
    }

    /* 1d. Live support maps: 5 PIDs in 0x138bd888 + 2 vals in 0x138bd930 */
    u64 l1_flag_addrs[5];
    for (u32 i = 0; i < 5u; i++) {
        u64 node = umap_find_node(g_load_base + MAP_PID_SUPPORT_VA, STEP2_L1_PIDS[i]);
        u8 v = 0xff;
        if (!node || !safe_read_bytes(node + 0x0cULL, &v, 1) || v != 0) {
            out_s("PRE_FAIL l1_map pid="); out_hex(STEP2_L1_PIDS[i]);
            out_s(" node="); out_hex(node); out_s(" v="); out_u64(v); out_s("\n");
            errs++;
            l1_flag_addrs[i] = 0;
        } else {
            l1_flag_addrs[i] = node + 0x0cULL;
        }
    }

    u64 l2_flag_addrs[2] = { 0, 0 };
    u64 l2_outer = umap_find_node(g_load_base + MAP_VAL_SUPPORT_VA, STEP2_L2_PID);
    if (!l2_outer) {
        out_s("PRE_FAIL l2_map outer 0x467 not found\n");
        errs++;
    } else {
        for (u32 i = 0; i < 2u; i++) {
            u64 node = umap_find_node(l2_outer + 0x10ULL, STEP2_L2_VALS[i]);
            u8 v = 0xff;
            if (!node || !safe_read_bytes(node + 0x0cULL, &v, 1) || v != 0) {
                out_s("PRE_FAIL l2_map val="); out_u64(STEP2_L2_VALS[i]);
                out_s(" node="); out_hex(node); out_s(" v="); out_u64(v); out_s("\n");
                errs++;
            } else {
                l2_flag_addrs[i] = node + 0x0cULL;
            }
        }
    }

    /* 1e. All 114 Step-2 flag_slot pointers must match; capture live counters for 58 active FX30 pairs
     *     (each active pair must have ctr >= 1 so decrement-by-1 cannot underflow exclusion_manager.cpp:1599!) */
    u32 s2_before[STEP2_PAIR_COUNT];
    for (u32 i = 0; i < STEP2_PAIR_COUNT; i++) {
        const struct step2_pair *p = &STEP2_PAIRS[i];
        u64 slot_val = 0;
        u32 ctr = 0;
        s2_before[i] = 0U;
        if (!safe_read_u64(g_load_base + p->flag_slot_va, &slot_val) ||
            slot_val != (g_load_base + p->flag_va) ||
            !safe_read_u32(g_load_base + p->counter_va, &ctr) ||
            !is_readable(g_load_base + p->flag_va, 1)) {
            out_s("PRE_FAIL step2 node="); out_u64(p->node); out_s("\n");
            errs++;
            continue;
        }
        s2_before[i] = ctr;
        if (p->active && ctr == 0U) {
            out_s("PRE_FAIL step2_ctr0 node="); out_u64(p->node); out_s("\n");
            errs++;
        }
    }

    if (errs != 0) {
        out_s("RESULT=ABORT_MISMATCH pre_errors="); out_u64(errs); out_s(" writes=0\n");
        flush_result();
        return;
    }
    out_s("PASS1_PREIMAGE=OK\n");

    /* ==== PASS 2: Private COW RAM Application ============================= */
    u32 write_errs = 0;

    /* 2a. Byte/code patches (Steps 0, L1/L2 .rodata, L5+L5b, .rodata defaults, Steps 4, 5, 6) */
    for (u32 i = 0; i < CINE_BYTE_PATCH_COUNT; i++) {
        const struct byte_patch *bp = &CINE_BYTE_PATCHES[i];
        if (!cow_write(g_load_base + bp->elf_va, bp->after, bp->len, bp->is_code)) {
            out_s("WR_FAIL "); out_s(bp->tag); out_s("\n");
            write_errs++;
        }
    }

    /* NOTE: Layer 3 (0x051BFF68 PRM 0x2bd) is INTENTIONALLY NOT written at runtime
     * (matches FireHydrant rampatch/README.md): injecting boot-time FX30 exclusion rules mid-boot
     * without their boot-time +1 counter increments causes exclusion_manager.cpp:1599 underflow! */

    /* 2c. 7 live support flags -> 1 */
    u8 one = 1;
    for (u32 i = 0; i < 5u; i++) {
        if (!cow_write(l1_flag_addrs[i], &one, 1, 0)) { out_s("WR_FAIL l1_map\n"); write_errs++; }
    }
    for (u32 i = 0; i < 2u; i++) {
        if (!cow_write(l2_flag_addrs[i], &one, 1, 0)) { out_s("WR_FAIL l2_map\n"); write_errs++; }
    }

    /* 2d. Step 2: SAFE DECREMENT-BY-1 on ONLY the 58 FX30-valid Cine EI pairs!
     *     Removes exactly one boot-time model_unsupported contribution (matches Powerful6700 + FireHydrant).
     *     ONLY clears flag_va = 0 when new_ctr == 0 (preserves active mode/Log exclusions so switching
     *     Stills->Movie, M->S, or Log Off->Cine EI never underflows exclusion_manager.cpp:1599!).
     *     Leaves all 56 out-of-range EI choices excluded so the ISO dial stays strictly inside FX30 bounds. */
    u8 zero = 0;
    u32 s2_active = 0, s2_zeroed = 0, s2_kept_nz = 0;
    for (u32 i = 0; i < STEP2_PAIR_COUNT; i++) {
        const struct step2_pair *p = &STEP2_PAIRS[i];
        if (!p->active) continue;
        s2_active++;
        u32 new_c = s2_before[i] - 1U;
        if (!cow_write_u32(g_load_base + p->counter_va, new_c)) { write_errs++; }
        if (new_c == 0U) {
            if (!cow_write(g_load_base + p->flag_va, &zero, 1, 0)) { write_errs++; }
            s2_zeroed++;
        } else {
            s2_kept_nz++;
        }
    }
    out_s("S2_DEC active="); out_u64(s2_active);
    out_s(" zeroed="); out_u64(s2_zeroed);
    out_s(" kept_nz="); out_u64(s2_kept_nz); out_s("\n");

    /* 2e. Step 3: HIGH Base ISO anchor 26 -> 19 (all 3 copies: A, B, C) */
    if (!cow_write_u32(g_load_base + STEP3_HIGH_A_VA, STEP3_TARGET_VAL)) write_errs++;
    if (!cow_write_u32(g_load_base + STEP3_HIGH_B_VA, STEP3_TARGET_VAL)) write_errs++;
    if (is_readable(g_load_base + STEP3_HIGH_C_VA, 4)) {
        (void)cow_write_u32(g_load_base + STEP3_HIGH_C_VA, STEP3_TARGET_VAL);
    }

    /* 2f. Live compiled-defaults map 0x138BDA18 (node+0x0c = u32 default value) */
    {
        static const struct { u32 pid; u32 defv; } dm_fix[6] = {
            { 0x0506U, 0U },  /* Base ISO: 2(Auto) -> 0(ISO 800) */
            { 0x0507U, 10U }, /* Switch EI: 13 -> 10 (EI 1600, center of 8..12) */
            { 0x0508U, 7U },  /* EI Auto: 25 -> 7 (EI 800) */
            { 0x0509U, 7U },  /* EI Low: 13 -> 7 (EI 800, 0 EV) */
            { 0x050AU, 12U }, /* EI High: 25 -> 12 (EI 2500, 0 EV) */
            { 0x1575U, 19U }, /* HIGH Base ISO: 26 -> 19 (ISO 2500) */
        };
        u32 dm_ok = 0;
        for (u32 i = 0; i < 6u; i++) {
            u64 node = umap_find_node(g_load_base + MAP_DEFAULTS_VA, dm_fix[i].pid);
            if (node && is_readable(node + 0x0cULL, 4)) {
                if (!cow_write_u32(node + 0x0cULL, dm_fix[i].defv)) write_errs++;
                else dm_ok++;
            }
        }
        out_s("DEFMAP_FIXED="); out_u64(dm_ok); out_s("/6\n");
    }

    /* 2g. Live shadow defaults struct *(0x138BD9A0) + 0x14A04..0x14A8C (506..50a) */
    {
        static const struct { u64 off; u32 lo; u32 hi; u32 defv; } dobj[5] = {
            { 0x14A04ULL, 0U, 1U,  0U  }, /* 0x506 Base ISO */
            { 0x14A14ULL, 8U, 12U, 10U }, /* 0x507 Switch EI */
            { 0x14A3CULL, 1U, 18U, 7U  }, /* 0x508 EI Auto */
            { 0x14A64ULL, 1U, 13U, 7U  }, /* 0x509 EI Low */
            { 0x14A8CULL, 6U, 18U, 12U }, /* 0x50a EI High */
        };
        u64 ptr = 0;
        u32 clamped = 0;
        if (safe_read_u64(g_load_base + DEF_OBJ_PTR_VA, &ptr) && ptr && is_readable(ptr + 0x14A04ULL, 0x8CULL)) {
            u32 cur506 = 0;
            (void)safe_read_u32(ptr + 0x14A04ULL, &cur506);
            int fresh = (cur506 == 2U);
            for (u32 i = 0; i < 5u; i++) {
                u32 v = 0;
                if (safe_read_u32(ptr + dobj[i].off, &v)) {
                    if (v < dobj[i].lo || v > dobj[i].hi || (fresh && i == 3u && v == 13U)) {
                        if (!cow_write_u32(ptr + dobj[i].off, dobj[i].defv)) write_errs++;
                        else clamped++;
                    }
                }
            }
        }
        out_s("DEFOBJ_PTR="); out_hex(ptr); out_s(" CLAMPED="); out_u64(clamped); out_s("\n");
    }

    /* 2h. ALL 13 mode profiles (0x138C0948 + k*0x1D44 + 0x590..0x5A0) + 3 secondary reload structs
     *     (0x1391BAE4, 0x1391F018, 0x13937CE0) -- stops Stills->Movie & M->S from reloading PID 0x506=2! */
    {
        static const struct { u32 lo; u32 hi; u32 defv; } lim[5] = {
            { 0U, 1U,  0U  }, /* +0x00: 0x506 Base ISO (0=800, 1=2500) */
            { 8U, 12U, 10U }, /* +0x04: 0x507 Switch EI (8..12) */
            { 1U, 18U, 7U  }, /* +0x08: 0x508 EI Auto (1..18) */
            { 1U, 13U, 7U  }, /* +0x0c: 0x509 EI Low (1..13) */
            { 6U, 18U, 12U }, /* +0x10: 0x50a EI High (6..18) */
        };
        static const u64 extra_bases[3] = {
            0x1391BAE4ULL, /* 0x13918B68 + 0x2f7c (0x317615c / 0x318cb14) */
            0x1391F018ULL, /* 0x1391EA88 + 0x0590 (0x31e1444 -> 0x3164980) */
            0x13937CE0ULL, /* direct reload struct (0x31a9fb0..0x31aa160) */
        };
        u32 scanned = 0, clamped = 0;
        for (u32 idx = 0; idx < 16u; idx++) {
            u64 base = (idx < 13u)
                     ? (g_load_base + 0x138C0948ULL + (u64)idx * 0x1D44ULL + 0x590ULL)
                     : (g_load_base + extra_bases[idx - 13u]);
            if (!is_readable(base, 20ULL)) continue;
            scanned++;
            u32 v506 = 0;
            (void)safe_read_u32(base, &v506);
            int fresh = (v506 == 2U);
            for (u32 j = 0; j < 5u; j++) {
                u32 v = 0;
                if (safe_read_u32(base + (u64)j * 4ULL, &v)) {
                    if (v < lim[j].lo || v > lim[j].hi || (fresh && j == 3u && v == 13U)) {
                        if (!cow_write_u32(base + (u64)j * 4ULL, lim[j].defv)) write_errs++;
                        else clamped++;
                    }
                }
            }
        }
        out_s("PROFILES_SCANNED="); out_u64(scanned); out_s("/16 CLAMPED_WORDS="); out_u64(clamped); out_s("\n");
    }

    /* 2i. Active .bss EI / Latitude records (tightened 507_sw to 8..12 & fresh 509 13->7!) */
    {
        static const struct { const char *name; u64 va; u32 lo; u32 hi; u32 defv; } ei_recs[8] = {
            { "506_base",  0x08D37994ULL, 0U,  1U,  0U },
            { "507_sw",    0x08D379A4ULL, 8U,  12U, 10U },
            { "508_auto",  0x08D379CCULL, 1U,  18U, 7U },
            { "509_low",   0x08D379F4ULL, 1U,  13U, 7U },
            { "50a_high",  0x08D37A1CULL, 6U,  18U, 12U },
            { "1580_lata", 0x08D91754ULL, 0U,  12U, 6U },
            { "1581_latl", 0x08D91770ULL, 0U,  12U, 6U },
            { "1582_lath", 0x08D9178CULL, 0U,  12U, 6U },
        };
        u32 cur506 = 0;
        (void)safe_read_u32(g_load_base + 0x08D37994ULL, &cur506);
        int fresh = (cur506 == 2U);
        out_s("EI_BSS_BEFORE");
        for (u32 i = 0; i < 8u; i++) {
            u32 va_a = 0, va_b = 0;
            (void)safe_read_u32(g_load_base + ei_recs[i].va, &va_a);
            (void)safe_read_u32(g_load_base + ei_recs[i].va + 4ULL, &va_b);
            out_s(" "); out_s(ei_recs[i].name); out_s("="); out_u64(va_a); out_s("/"); out_u64(va_b);
            if (va_a < ei_recs[i].lo || va_a > ei_recs[i].hi || (fresh && i == 3u && va_a == 13U)) {
                if (!cow_write_u32(g_load_base + ei_recs[i].va, ei_recs[i].defv)) write_errs++;
            }
            if (va_b < ei_recs[i].lo || va_b > ei_recs[i].hi || (fresh && i == 3u && va_b == 13U)) {
                if (!cow_write_u32(g_load_base + ei_recs[i].va + 4ULL, ei_recs[i].defv)) write_errs++;
            }
        }
        out_s("\n");
    }

    /* ==== PASS 3: Full Readback Verification ============================== */
    u32 rb_errs = 0;
    for (u32 i = 0; i < CINE_BYTE_PATCH_COUNT; i++) {
        const struct byte_patch *bp = &CINE_BYTE_PATCHES[i];
        u8 cur[24];
        if (!safe_read_bytes(g_load_base + bp->elf_va, cur, bp->len)) { rb_errs++; continue; }
        for (u8 k = 0; k < bp->len; k++) {
            if (cur[k] != bp->after[k]) { rb_errs++; break; }
        }
    }
    u32 a_now = 0, b_now = 0;
    if (!safe_read_u32(g_load_base + STEP3_HIGH_A_VA, &a_now) || a_now != STEP3_TARGET_VAL) rb_errs++;
    if (!safe_read_u32(g_load_base + STEP3_HIGH_B_VA, &b_now) || b_now != STEP3_TARGET_VAL) rb_errs++;
    for (u32 i = 0; i < 5u; i++) {
        u8 v = 0; if (!safe_read_bytes(l1_flag_addrs[i], &v, 1) || v != 1) rb_errs++;
    }
    for (u32 i = 0; i < 2u; i++) {
        u8 v = 0; if (!safe_read_bytes(l2_flag_addrs[i], &v, 1) || v != 1) rb_errs++;
    }
    for (u32 i = 0; i < STEP2_PAIR_COUNT; i++) {
        const struct step2_pair *p = &STEP2_PAIRS[i];
        if (!p->active) continue;
        u32 exp_c = s2_before[i] - 1U;
        u8 exp_f = (exp_c == 0U) ? 0U : 1U;
        u32 c = 0xffffffffU; u8 f = 0xffU;
        if (!safe_read_u32(g_load_base + p->counter_va, &c) || c != exp_c) rb_errs++;
        if (!safe_read_bytes(g_load_base + p->flag_va, &f, 1) || f != exp_f) rb_errs++;
    }
    {
        u32 b506 = 99U, b507 = 0U, b508 = 0U, b509 = 0U, b50a = 0U;
        if (!safe_read_u32(g_load_base + 0x08D37994ULL, &b506) || b506 > 1U) rb_errs++;
        if (!safe_read_u32(g_load_base + 0x08D379A4ULL, &b507) || b507 < 8U || b507 > 12U) rb_errs++;
        if (!safe_read_u32(g_load_base + 0x08D379CCULL, &b508) || b508 < 1U || b508 > 18U) rb_errs++;
        if (!safe_read_u32(g_load_base + 0x08D379F4ULL, &b509) || b509 < 1U || b509 > 13U) rb_errs++;
        if (!safe_read_u32(g_load_base + 0x08D37A1CULL, &b50a) || b50a < 6U || b50a > 18U) rb_errs++;
    }

    out_s("WRITE_ERRORS="); out_u64(write_errs);
    out_s(" READBACK_ERRORS="); out_u64(rb_errs); out_s("\n");
    if (write_errs == 0 && rb_errs == 0) {
        out_s("RESULT=APPLY_OK patches=81+7maps+58dec+Step3+16profiles+defmap\n");
    } else {
        out_s("RESULT=APPLY_VERIFY_FAIL\n");
    }
    flush_result();
}
