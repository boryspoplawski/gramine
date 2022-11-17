; SPDX-License-Identifier: LGPL-3.0-or-later
; Copyright (C) 2022 Intel Corporation
;                    Borys Popławski <borysp@invisiblethingslab.com>

global edmm_fault_enclave_page
global edmm_fault_enclave_page_ret
section .text

; If a page is faulted, which belongs to the enclave, but was not yet allocated, the SGX2 in-kernel
; driver EAUGs it, assuming it's enclave doing EACCEPT on it (once the page is added - via EAUG
; - kernel goes back to the enclave, which re-does the EACCEPT, this time succeeding.
; The in-kernel driver does not care whether the fault originated from within the enclave or from
; normal userspace, so we abuse this fact and fault from normal userspace, to avoid expensive
; kernel-enclave round trip for faulted each page.
; Until they add a way to properly EAUG multiple pages, we use this hack.

; void edmm_fault_enclave_page(uint64_t addr)
edmm_fault_enclave_page:
    mov rax, [rdi]
    mov eax, 1337
    ret
edmm_fault_enclave_page_ret:
    mov eax, 0
    ret
