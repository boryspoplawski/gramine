/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include <stdalign.h>

#include "api.h"
#include "cpu.h"
#include "enclave_ocalls.h"
#include "pal_error.h"
#include "pal_linux_error.h"
#include "pal_sgx.h"
#include "sgx_arch.h"

static int enclu(uint32_t eax, uint64_t rbx, uint64_t rcx) {
    __asm__ volatile (
        "enclu"
        : "+a"(eax)
        : "b"(rbx), "c"(rcx)
        : "memory", "cc"
    );
    return (int)eax;
}

static int sgx_eaccept(uint64_t addr, uint64_t flags) {
    alignas(64) sgx_arch_sec_info_t secinfo = {
        .flags = flags,
    };
    return enclu(EACCEPT, (uint64_t)&secinfo, addr);
}

static void sgx_emodpe(uint64_t addr, uint64_t prot) {
    alignas(64) sgx_arch_sec_info_t secinfo = {
        .flags = prot,
    };
    enclu(EMODPE, (uint64_t)&secinfo, addr);
    /* `EMODPE` does not return errors, it can only fault. */
}

int sgx_edmm_add_pages(uint64_t addr, size_t count, uint64_t prot) {
    int ret;
    if (count > 1) {
        /* Fault the pages from untrusted userspace. For more details, see "edmm_tricks.nasm". */
        ret = ocall_edmm_fault_pages(addr, count);
        if (ret < 0) {
            return unix_to_pal_error(ret);
        }
    }

    if (prot & SGX_SECINFO_FLAGS_W) {
        /* HW limitation. */
        prot |= SGX_SECINFO_FLAGS_R;
    }

    for (size_t i = 0; i < count; i++) {
        /* SGX2 HW requires initial page permissions to be RW. */
        ret = sgx_eaccept(addr + i * PAGE_SIZE, (SGX_PAGE_TYPE_REG << SGX_SECINFO_FLAGS_TYPE_SHIFT)
                                                | SGX_SECINFO_FLAGS_R | SGX_SECINFO_FLAGS_W
                                                | SGX_SECINFO_FLAGS_PENDING);
        if (ret < 0) {
            log_error("%s: failed to accept page at addres %#lx: %d", __func__,
                      addr + i * PAGE_SIZE, ret);
            // ret error? what about restoring allocated pages?
            die_or_inf_loop();
        }
    }

    if (prot & ~(SGX_SECINFO_FLAGS_R | SGX_SECINFO_FLAGS_W)) {
        for (size_t i = 0; i < count; i++) {
            sgx_emodpe(addr + i * PAGE_SIZE, prot);
        }
    }

    if (~prot & (SGX_SECINFO_FLAGS_R | SGX_SECINFO_FLAGS_W)) {
        ret = ocall_edmm_restrict_pages_perm(addr, count, prot);
        if (ret < 0) {
            log_error("%s: failed to restrict pages permissions at %#lx-%#lx", __func__, addr,
                      addr + count * PAGE_SIZE);
            // ret error? what about restoring allocated pages?
            die_or_inf_loop();
        }
    }

    return 0;
}

int sgx_edmm_remove_pages(uint64_t addr, size_t count) {
    // FIXME: we cannot use malloc here, but this could be big?
    uint64_t bitmap_missing_pages[UDIV_ROUND_UP(count, 64)];

    int ret = ocall_edmm_modify_pages_type(addr, count, SGX_PAGE_TYPE_TRIM, bitmap_missing_pages);
    if (ret < 0) {
        return unix_to_pal_error(ret);
    }

    for (size_t i = 0; i < count; i++) {
        if (bitmap_missing_pages[i / 64] & (1ul << i % 64)) {
            continue;
        }
        ret = sgx_eaccept(addr + i * PAGE_SIZE, (SGX_PAGE_TYPE_TRIM << SGX_SECINFO_FLAGS_TYPE_SHIFT)
                                                | SGX_SECINFO_FLAGS_MODIFIED);
        if (ret < 0) {
            log_error("%s: failed to accept page removal at addres %#lx: %d", __func__,
                      addr + i * PAGE_SIZE, ret);
            // ret error? what about trimmed pages?
            die_or_inf_loop();
        }
    }

    ret = ocall_edmm_remove_pages(addr, count, bitmap_missing_pages);
    if (ret < 0) {
        log_error("%s: failed to remove pages at %#lx-%#lx", __func__, addr,
                  addr + count * PAGE_SIZE);
        // ret error? what about trimmed pages?
        die_or_inf_loop();
    }

    return 0;
}

int sgx_edmm_set_page_permissions(uint64_t addr, size_t count, uint64_t prot) {
    if (prot & SGX_SECINFO_FLAGS_W) {
        /* HW limitation. */
        prot |= SGX_SECINFO_FLAGS_R;
    }

    for (size_t i = 0; i < count; i++) {
        sgx_emodpe(addr + i * PAGE_SIZE, prot);
    }

    int ret = ocall_edmm_restrict_pages_perm(addr, count, prot);
    if (ret < 0) {
        log_error("%s: failed to restrict pages permissions at %#lx-%#lx", __func__, addr,
                  addr + count * PAGE_SIZE);
        // ret error? what about already processed pages?
        die_or_inf_loop();
    }

    return 0;
}
