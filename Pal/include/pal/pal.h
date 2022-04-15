/* SPDX-License-Identifier: LGPL-3.0-or-later */

#ifndef PAL_H
#define PAL_H

#include "pal_api_types.h"

#ifdef IN_PAL

typedef struct {
    PAL_IDX type;
} PAL_HDR;

#include "pal_host.h"

#define HANDLE_HDR(handle) (&((handle)->hdr))
#define PAL_GET_TYPE(h) (HANDLE_HDR(h)->type)
#define UNKNOWN_HANDLE(handle) (PAL_GET_TYPE(handle) >= PAL_HANDLE_TYPE_BOUND)

static inline void init_handle_hdr(PAL_HANDLE handle, int pal_type) {
    HANDLE_HDR(handle)->type = pal_type;
}

#else /* IN_PAL */

typedef struct _pal_handle_undefined_type* PAL_HANDLE;

#endif /* IN_PAL */

#include "pal-arch.h"
#include "pal_topology.h"

#include "pal_api.h"

#endif /* PAL_H */
