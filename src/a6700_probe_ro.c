/* a6700_probe_ro.c -- 100% READ-ONLY live memory probe for Sony a6700 (v2.00).
 *
 * SAFETY DESIGN (ArcaneLantern s3read.c + FireHydrant jiritsu_module.c discipline):
 *   - Contains ZERO write/mprotect/mmap/pwrite syscalls for camera memory or firmware.
 *   - Literally cannot modify appFw.so memory or any flash partition.
 *   - Only output is plain-text report /tmp/jiritsu/rampatch.result (deleted same-session).
 *
 * Build: via native/build.py (freestanding AArch64 ELF shared object, DT_INIT = _init).
 */
#include "a6700_common.h"
#include "a6700_features_spec.h"

static void dump_map_l1(void) {
    static const u32 pids[12] = {
        0x467U, 0x506U, 0x507U, 0x508U, 0x509U, 0x50AU,
        0x4BBU, 0x6B2U, 0x497U, 0x50CU, 0x5A5U, 0x86BU
    };
    u64 maddr = g_load_base + MAP_PID_SUPPORT_VA;
    u64 bptr = 0, bcnt = 0;
    safe_read_u64(maddr, &bptr);
    safe_read_u64(maddr + 8, &bcnt);
    out_s("MAP_138BD888 buckets="); out_hex(bptr); out_s(" count="); out_u64(bcnt); out_s("\n");
    for (u32 i = 0; i < 12u; i++) {
        u64 node = umap_find_node(maddr, pids[i]);
        out_s("  L1 pid="); out_hex(pids[i]);
        if (node) {
            u8 v = 0xff;
            safe_read_bytes(node + 0x0cULL, &v, 1);
            out_s(" node="); out_hex(node); out_s(" supported="); out_u64(v);
        } else {
            out_s(" node=NOT_FOUND");
        }
        out_s("\n");
    }
}

static void dump_map_l2(void) {
    u64 maddr = g_load_base + MAP_VAL_SUPPORT_VA;
    u64 bptr = 0, bcnt = 0;
    safe_read_u64(maddr, &bptr);
    safe_read_u64(maddr + 8, &bcnt);
    out_s("MAP_138BD930 buckets="); out_hex(bptr); out_s(" count="); out_u64(bcnt); out_s("\n");
    u64 outer = umap_find_node(maddr, 0x467U);
    if (!outer) {
        out_s("  L2 pid=0x467 outer=NOT_FOUND\n");
        return;
    }
    u64 inner_map = outer + 0x10ULL;
    out_s("  L2 pid=0x467 outer="); out_hex(outer); out_s(" inner_map="); out_hex(inner_map); out_s("\n");
    for (u32 val = 0; val < 4u; val++) {
        u64 n = umap_find_node(inner_map, val);
        out_s("    val="); out_u64(val);
        if (n) {
            u8 v = 0xff;
            safe_read_bytes(n + 0x0cULL, &v, 1);
            out_s(" node="); out_hex(n); out_s(" supported="); out_u64(v);
        } else {
            out_s(" node=NOT_FOUND");
        }
        out_s("\n");
    }
}

__attribute__((visibility("default"))) void _init(void) {
    g_olen = 0;
    out_s("A6700_PROBE_V1\n");
    out_s("MODE=READ_ONLY_ZERO_WRITE\n");

    /* 1. Verify /usr/lib/appFw.so file identity */
    u64 fsz = 0;
    char sha_hex[65];
    int sha_ok = verify_appfw_file(&fsz, sha_hex);
    out_s("APPFW_SIZE="); out_u64(fsz);
    out_s(" APPFW_SHA256="); out_s(sha_hex);
    out_s(" MATCH="); out_u64((u64)sha_ok); out_s("\n");

    /* 2. Parse /proc/self/maps and verify PT_LOAD[0] + PT_LOAD[1] delta */
    int maps_ok = parse_proc_maps();
    out_s("LOAD_BASE="); out_hex(g_load_base);
    out_s(" LOAD1_OK="); out_u64((u64)g_load1_ok);
    out_s(" VMA_COUNT="); out_u64(g_vma_cnt); out_s("\n");

    if (!sha_ok || !maps_ok || !g_load1_ok) {
        out_s("SUMMARY checked=0 mismatches=1 STATUS=MISMATCH reason=identity_or_maps\n");
        flush_result();
        return;
    }

    /* 3. Verify all unified PROBE_SITES[] (Cine EI + Claude AP lanes) */
    u32 checked = 0, mismatches = 0;
    for (u32 i = 0; i < PROBE_SITE_COUNT; i++) {
        const struct probe_site *st = &PROBE_SITES[i];
        u64 raddr = g_load_base + st->elf_va;
        out_s("SITE "); out_s(st->tag);
        out_s(" va="); out_hex(st->elf_va);
        out_s(" kind="); out_u64(st->kind);

        if (st->kind == CHK_BYTES) {
            u8 got[16];
            checked++;
            if (!safe_read_bytes(raddr, got, st->len)) {
                mismatches++;
                out_s(" got=UNMAPPED status=MISMATCH\n");
            } else {
                int eq = 1;
                for (u8 k = 0; k < st->len; k++) if (got[k] != st->expected[k]) eq = 0;
                out_s(" got="); out_hex_bytes(got, st->len);
                if (eq) out_s(" status=OK\n");
                else { mismatches++; out_s(" status=MISMATCH\n"); }
            }
        } else if (st->kind == CHK_U32_EQ) {
            u32 v = 0;
            checked++;
            if (!safe_read_u32(raddr, &v)) {
                mismatches++;
                out_s(" got=UNMAPPED status=MISMATCH\n");
            } else {
                out_s(" got="); out_u64(v);
                if ((u64)v == st->expected_u64) out_s(" status=OK\n");
                else { mismatches++; out_s(" status=MISMATCH\n"); }
            }
        } else if (st->kind == CHK_PTR_REL) {
            u64 v = 0;
            u64 exp = st->expected_u64 ? (g_load_base + st->expected_u64) : 0ULL;
            checked++;
            if (!safe_read_u64(raddr, &v)) {
                mismatches++;
                out_s(" got=UNMAPPED status=MISMATCH\n");
            } else {
                out_s(" got="); out_hex(v);
                if (v == exp) out_s(" status=OK\n");
                else { mismatches++; out_s(" status=MISMATCH\n"); }
            }
        } else { /* CHK_OBSERVE */
            u8 got[16];
            if (!safe_read_bytes(raddr, got, st->len)) {
                out_s(" got=UNMAPPED status=OBS\n");
            } else {
                out_s(" got="); out_hex_bytes(got, st->len); out_s(" status=OBS\n");
            }
        }
    }

    /* 4. Dump live support hash maps (0x138bd888 & 0x138bd930) */
    dump_map_l1();
    dump_map_l2();

    /* 5. Verify all 114 Step-2 flag_slot pointers & summarize live counters/flags */
    u32 s2_slot_ok = 0, s2_ctr_nz = 0, s2_flg_nz = 0;
    u32 act_c1 = 0, act_c2 = 0, act_c3p = 0;
    for (u32 i = 0; i < STEP2_PAIR_COUNT; i++) {
        const struct step2_pair *p = &STEP2_PAIRS[i];
        u64 slot_val = 0;
        u32 ctr = 0;
        u8 flg = 0;
        checked++;
        if (safe_read_u64(g_load_base + p->flag_slot_va, &slot_val) &&
            slot_val == (g_load_base + p->flag_va)) {
            s2_slot_ok++;
        } else {
            mismatches++;
        }
        if (safe_read_u32(g_load_base + p->counter_va, &ctr) && ctr != 0) s2_ctr_nz++;
        if (safe_read_bytes(g_load_base + p->flag_va, &flg, 1) && flg != 0) s2_flg_nz++;
        if (p->active) {
            if (ctr == 1U) act_c1++;
            else if (ctr == 2U) act_c2++;
            else if (ctr >= 3U) act_c3p++;
        }

        /* Log the 3 FireHydrant anchor nodes individually */
        if (p->node == 9713U || p->node == 9714U || p->node == 699U) {
            out_s("STEP2_ANCHOR node="); out_u64(p->node);
            out_s(" ctr="); out_u64(ctr);
            out_s(" flg="); out_u64(flg);
            out_s(" slot_ok="); out_u64((u64)(slot_val == g_load_base + p->flag_va));
            out_s("\n");
        }
    }
    out_s("STEP2_SUMMARY total="); out_u64(STEP2_PAIR_COUNT);
    out_s(" slot_ok="); out_u64(s2_slot_ok);
    out_s(" ctr_nonzero="); out_u64(s2_ctr_nz);
    out_s(" flg_nonzero="); out_u64(s2_flg_nz);
    out_s(" act_c1="); out_u64(act_c1);
    out_s(" act_c2="); out_u64(act_c2);
    out_s(" act_c3p="); out_u64(act_c3p); out_s("\n");

    /* 6. Read-only preimage & live exclusion audit for Powerful6700 Pro Pack (shutter/exposure/ftp) */
    {
        static const struct { const char *name; u8 bit; } feats[3] = {
            { "shutter",  FEAT_SHUTTER  },
            { "exposure", FEAT_EXPOSURE },
            { "ftp",      FEAT_FTP      },
        };
        for (u32 f = 0; f < 3u; f++) {
            u8 bit = feats[f].bit;
            u32 b_tot = 0, b_ok = 0, p_tot = 0, p_ok = 0, e_tot = 0, e_slot = 0;
            u32 c0 = 0, c1 = 0, c2 = 0, c3p = 0;
            for (u32 i = 0; i < FEAT_BYTE_PATCH_COUNT; i++) {
                const struct feat_byte_patch *bp = &FEAT_BYTE_PATCHES[i];
                if (!(bp->feat & bit)) continue;
                b_tot++; checked++;
                u8 cur = 0xffU;
                if (safe_read_bytes(g_load_base + bp->elf_va, &cur, 1) && cur == bp->before) b_ok++;
                else mismatches++;
            }
            for (u32 i = 0; i < FEAT_PID_COUNT; i++) {
                const struct feat_pid_entry *pe = &FEAT_PIDS[i];
                if (!(pe->feat & bit)) continue;
                p_tot++; checked++;
                u64 node = umap_find_node(g_load_base + MAP_PID_SUPPORT_VA, pe->pid);
                u8 v = 0xffU;
                if (node && safe_read_bytes(node + 0x0cULL, &v, 1) && v == 0U) p_ok++;
                else mismatches++;
            }
            for (u32 i = 0; i < FEAT_EXCL_COUNT; i++) {
                const struct feat_excl_pair *ep = &FEAT_EXCL_PAIRS[i];
                if (!(ep->feat & bit)) continue;
                e_tot++; checked++;
                u64 slot_val = 0ULL; u32 ctr = 0U;
                if (safe_read_u64(g_load_base + ep->flag_slot_va, &slot_val) &&
                    slot_val == (g_load_base + ep->flag_va) &&
                    safe_read_u32(g_load_base + ep->counter_va, &ctr)) {
                    e_slot++;
                    if (ctr == 0U) c0++;
                    else if (ctr == 1U) c1++;
                    else if (ctr == 2U) c2++;
                    else c3p++;
                } else {
                    mismatches++;
                }
            }
            out_s("PROPACK feat="); out_s(feats[f].name);
            out_s(" bytes="); out_u64(b_ok); out_c('/'); out_u64(b_tot);
            out_s(" pids="); out_u64(p_ok); out_c('/'); out_u64(p_tot);
            out_s(" slots="); out_u64(e_slot); out_c('/'); out_u64(e_tot);
            out_s(" c0="); out_u64(c0); out_s(" c1="); out_u64(c1);
            out_s(" c2="); out_u64(c2); out_s(" c3p="); out_u64(c3p); out_s("\n");
        }
    }

    out_s("SUMMARY checked="); out_u64(checked);
    out_s(" mismatches="); out_u64(mismatches);
    out_s(" STATUS="); out_s(mismatches == 0 ? "READY" : "MISMATCH"); out_s("\n");
    flush_result();
}
