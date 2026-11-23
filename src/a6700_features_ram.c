/* a6700_features_ram.c -- Zero-flash volatile AP-RAM unlock for Powerful6700 Pro Pack:
 *   - Power-Off Shutter Curtain + Silent-Mode Link (FEAT_SHUTTER  = 1)
 *   - Flexible Exposure                            (FEAT_EXPOSURE = 2)
 *   - Native FTP Transfer + Playback FTP Action    (FEAT_FTP      = 4)
 *
 * Target: Sony ILCE-6700 (a6700) FW v2.00 ONLY (stock appFw.so SHA-256 verified).
 *
 * SAFETY GUARANTEES:
 *   - 100% ZERO FLASH WRITES: never touches /usr/lib/appFw.so, /cp/cpapp-b.bin, WBI, or /setting/.
 *   - ZERO CP writes, ZERO executable code patches (only .rodata + PT_LOAD[1] menu + .bss).
 *   - 10-second battery pull returns the camera 100% to factory stock.
 *   - PASS 0 verifies /usr/lib/appFw.so SHA-256 + /proc/self/maps PT_LOAD[0]/[1].
 *   - PASS 1 verifies EVERY selected byte preimage, live 0x138BD888 PID entry == 0,
 *     flag_slot pointer, and live exclusion counter >= 1 BEFORE writing a single byte.
 *   - PASS 2 applies private COW writes (preserving PROT_EXEC on RX pages) and SAFE
 *     DECREMENT-BY-1 on exclusion counters (clearing flag_va ONLY when counter reaches 0 —
 *     preventing exclusion_manager.cpp:1599 underflow crashes!).
 *   - PASS 3 verifies every single written byte, PID flag, counter, and exclusion flag.
 */
#include "a6700_common.h"
#include "a6700_features_spec.h"

#ifndef FEAT_MASK
#define FEAT_MASK FEAT_ALL
#endif

#define NR_mprotect 226
#define PROT_READ   1
#define PROT_WRITE  2
#define PROT_EXEC   4

static i64 sys_mprotect(u64 addr, u64 len, i64 prot) {
    return sc6(NR_mprotect, (i64)addr, (i64)len, prot, 0, 0, 0);
}

static int cow_write(u64 addr, const u8 *src, u64 len) {
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
        if (sys_mprotect(pg_start, pg_len, orig_prot | PROT_WRITE) != 0) return 0;
    }

    volatile u8 *dst = (volatile u8 *)addr;
    for (u64 i = 0; i < len; i++) dst[i] = src[i];
    __asm__ volatile("dsb ish" ::: "memory");

    if (need_mprot) {
        (void)sys_mprotect(pg_start, pg_len, orig_prot);
    }
    return 1;
}

static int cow_write_u32(u64 addr, u32 val) {
    u8 b[4] = { (u8)(val), (u8)(val >> 8), (u8)(val >> 16), (u8)(val >> 24) };
    return cow_write(addr, b, 4);
}

__attribute__((visibility("default"))) void _init(void) {
    g_olen = 0;
    out_s("A6700_FEATURES_RAM_V1 mask="); out_u64(FEAT_MASK); out_s("\n");

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
    u32 sel_bytes = 0, sel_pids = 0, sel_pairs = 0;

    /* 1a. .rodata model-support bytes + PT_LOAD[1] menu permission bytes */
    for (u32 i = 0; i < FEAT_BYTE_PATCH_COUNT; i++) {
        const struct feat_byte_patch *bp = &FEAT_BYTE_PATCHES[i];
        if (!(bp->feat & FEAT_MASK)) continue;
        sel_bytes++;
        u8 cur = 0xffU;
        if (!safe_read_bytes(g_load_base + bp->elf_va, &cur, 1)) {
            out_s("PRE_FAIL unmapped va="); out_hex(bp->elf_va); out_s("\n");
            errs++;
        } else if (cur != bp->before) {
            out_s("PRE_FAIL byte va="); out_hex(bp->elf_va);
            out_s(" got="); out_hex(cur); out_s(" exp="); out_hex(bp->before); out_s("\n");
            errs++;
        }
    }

    /* 1b. Live 0x138BD888 PID support map entries (all must exist & be 0) */
    u64 pid_flag_addrs[FEAT_PID_COUNT];
    for (u32 i = 0; i < FEAT_PID_COUNT; i++) {
        pid_flag_addrs[i] = 0ULL;
        const struct feat_pid_entry *pe = &FEAT_PIDS[i];
        if (!(pe->feat & FEAT_MASK)) continue;
        sel_pids++;
        u64 node = umap_find_node(g_load_base + MAP_PID_SUPPORT_VA, pe->pid);
        u8 v = 0xffU;
        if (!node || !safe_read_bytes(node + 0x0cULL, &v, 1) || v != 0U) {
            out_s("PRE_FAIL pid_map pid="); out_hex(pe->pid);
            out_s(" node="); out_hex(node); out_s(" v="); out_u64(v); out_s("\n");
            errs++;
        } else {
            pid_flag_addrs[i] = node + 0x0cULL;
        }
    }

    /* 1c. Live .bss exclusion pairs: verify flag_slot & ctr >= 1 */
    u32 ctr_before[FEAT_EXCL_COUNT];
    for (u32 i = 0; i < FEAT_EXCL_COUNT; i++) {
        ctr_before[i] = 0U;
        const struct feat_excl_pair *ep = &FEAT_EXCL_PAIRS[i];
        if (!(ep->feat & FEAT_MASK)) continue;
        sel_pairs++;
        u64 slot_val = 0ULL;
        u32 ctr = 0U;
        if (!safe_read_u64(g_load_base + ep->flag_slot_va, &slot_val) ||
            slot_val != (g_load_base + ep->flag_va) ||
            !safe_read_u32(g_load_base + ep->counter_va, &ctr) ||
            !is_readable(g_load_base + ep->flag_va, 1)) {
            out_s("PRE_FAIL excl node="); out_u64(ep->node); out_s("\n");
            errs++;
            continue;
        }
        ctr_before[i] = ctr;
        if (ctr == 0U) {
            out_s("PRE_FAIL excl_ctr0 node="); out_u64(ep->node); out_s("\n");
            errs++;
        }
    }

    if (errs != 0U) {
        out_s("RESULT=ABORT_MISMATCH pre_errors="); out_u64(errs); out_s(" writes=0\n");
        flush_result();
        return;
    }
    out_s("PASS1_PREIMAGE=OK bytes="); out_u64(sel_bytes);
    out_s(" pids="); out_u64(sel_pids);
    out_s(" pairs="); out_u64(sel_pairs); out_s("\n");

    /* ==== PASS 2: Private COW RAM Application ============================= */
    u32 write_errs = 0U;

    /* 2a. .rodata + PT_LOAD[1] menu permission bytes */
    for (u32 i = 0; i < FEAT_BYTE_PATCH_COUNT; i++) {
        const struct feat_byte_patch *bp = &FEAT_BYTE_PATCHES[i];
        if (!(bp->feat & FEAT_MASK)) continue;
        if (!cow_write(g_load_base + bp->elf_va, &bp->after, 1)) {
            out_s("WR_FAIL va="); out_hex(bp->elf_va); out_s("\n");
            write_errs++;
        }
    }

    /* 2b. Live 0x138BD888 PID support entries -> 1 */
    u8 one = 1U;
    for (u32 i = 0; i < FEAT_PID_COUNT; i++) {
        if (!pid_flag_addrs[i]) continue;
        if (!cow_write(pid_flag_addrs[i], &one, 1)) {
            out_s("WR_FAIL pid="); out_hex(FEAT_PIDS[i].pid); out_s("\n");
            write_errs++;
        }
    }

    /* 2c. Live .bss exclusion pairs: SAFE DECREMENT-BY-1 (clear flag ONLY if new_ctr == 0) */
    u8 zero = 0U;
    u32 zeroed = 0U, kept_nz = 0U;
    for (u32 i = 0; i < FEAT_EXCL_COUNT; i++) {
        const struct feat_excl_pair *ep = &FEAT_EXCL_PAIRS[i];
        if (!(ep->feat & FEAT_MASK)) continue;
        u32 new_c = ctr_before[i] - 1U;
        if (!cow_write_u32(g_load_base + ep->counter_va, new_c)) write_errs++;
        if (new_c == 0U) {
            if (!cow_write(g_load_base + ep->flag_va, &zero, 1)) write_errs++;
            zeroed++;
        } else {
            kept_nz++;
        }
    }
    out_s("EXCL_DEC pairs="); out_u64(sel_pairs);
    out_s(" zeroed="); out_u64(zeroed);
    out_s(" kept_nz="); out_u64(kept_nz); out_s("\n");

    /* ==== PASS 3: Full End-to-End Readback Verification =================== */
    u32 rb_errs = 0U;
    for (u32 i = 0; i < FEAT_BYTE_PATCH_COUNT; i++) {
        const struct feat_byte_patch *bp = &FEAT_BYTE_PATCHES[i];
        if (!(bp->feat & FEAT_MASK)) continue;
        u8 cur = 0xffU;
        if (!safe_read_bytes(g_load_base + bp->elf_va, &cur, 1) || cur != bp->after) rb_errs++;
    }
    for (u32 i = 0; i < FEAT_PID_COUNT; i++) {
        if (!pid_flag_addrs[i]) continue;
        u8 v = 0U;
        if (!safe_read_bytes(pid_flag_addrs[i], &v, 1) || v != 1U) rb_errs++;
    }
    for (u32 i = 0; i < FEAT_EXCL_COUNT; i++) {
        const struct feat_excl_pair *ep = &FEAT_EXCL_PAIRS[i];
        if (!(ep->feat & FEAT_MASK)) continue;
        u32 exp_c = ctr_before[i] - 1U;
        u8 exp_f = (exp_c == 0U) ? 0U : 1U;
        u32 c = 0xffffffffU; u8 f = 0xffU;
        if (!safe_read_u32(g_load_base + ep->counter_va, &c) || c != exp_c) rb_errs++;
        if (!safe_read_bytes(g_load_base + ep->flag_va, &f, 1) || f != exp_f) rb_errs++;
    }

    out_s("WRITE_ERRORS="); out_u64(write_errs);
    out_s(" READBACK_ERRORS="); out_u64(rb_errs); out_s("\n");
    if (write_errs == 0U && rb_errs == 0U) {
        out_s("RESULT=APPLY_OK mask="); out_u64(FEAT_MASK);
        out_s(" bytes="); out_u64(sel_bytes);
        out_s(" pids="); out_u64(sel_pids);
        out_s(" pairs="); out_u64(sel_pairs);
        out_s(" zeroed="); out_u64(zeroed);
        out_s(" kept_nz="); out_u64(kept_nz); out_s("\n");
    } else {
        out_s("RESULT=APPLY_VERIFY_FAIL\n");
    }
    flush_result();
}
