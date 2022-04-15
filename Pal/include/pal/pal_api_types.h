/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*!
 * \file pal_api_types.h
 * \brief This file contains definitions of types in PAL API.
 */

#ifndef PAL_API_TYPES_H
#define PAL_API_TYPES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* TODO: we should `#include "toml.h"` here. However, this is currently inconvenient to do in Meson,
 * because `toml.h` is a generated (patched) file, and all targets built using `pal.h` would need to
 * declare a dependency on it. */
typedef struct toml_table_t toml_table_t;

typedef uint64_t    PAL_NUM; /*!< a number */
typedef uint32_t    PAL_IDX; /*!< an index */

/* maximum length of pipe/FIFO name (should be less than Linux sockaddr_un.sun_path = 108) */
#define PIPE_NAME_MAX 96

/* maximum length of URIs */
#define URI_MAX 4096

enum {
    PAL_TYPE_FILE,
    PAL_TYPE_PIPE,
    PAL_TYPE_PIPESRV,
    PAL_TYPE_PIPECLI,
    PAL_TYPE_DEV,
    PAL_TYPE_DIR,
    PAL_TYPE_TCP,
    PAL_TYPE_TCPSRV,
    PAL_TYPE_UDP,
    PAL_TYPE_UDPSRV,
    PAL_TYPE_PROCESS,
    PAL_TYPE_THREAD,
    PAL_TYPE_EVENT,
    PAL_TYPE_EVENTFD,
    PAL_HANDLE_TYPE_BOUND,
};

#define PAL_IDX_POISON         ((PAL_IDX)-1) /* PAL identifier poison value */

/* Part of PAL state which is shared between all PALs and accessible (read-only) by the binary
 * started by PAL (usually our LibOS). */
struct pal_public_state {
    const char* host_type;

    /*
     * Handles and executables
     */

    toml_table_t* manifest_root; /*!< program manifest */
    PAL_HANDLE parent_process;   /*!< handle of parent process */
    PAL_HANDLE first_thread;     /*!< handle of first thread */
    int log_level;               /*!< what log messages to enable */

    /*
     * Memory layout
     */
    bool disable_aslr;        /*!< disable ASLR (may be necessary for restricted environments) */
    void* user_address_start; /*!< User address range start */
    void* user_address_end;   /*!< User address range end */

    struct {
        uintptr_t start;
        uintptr_t end;
        const char* comment;
    }* preloaded_ranges; /*!< array of memory ranges which are preoccupied */
    size_t preloaded_ranges_cnt;

    /*
     * Host information
     */

    /*!
     * \brief Host allocation alignment.
     *
     * This currently is (and most likely will always be) indistinguishable from the page size,
     * looking from the LibOS perspective. The two values can be different on the PAL level though,
     * see e.g. SYSTEM_INFO::dwAllocationGranularity on Windows.
     */
    PAL_NUM alloc_align;

    size_t mem_total;

    struct pal_cpu_info cpu_info;

    bool enable_sysfs_topology;
    struct pal_topo_info topo_info; /* received from untrusted host, but sanitized */
};

/*! memory allocation flags */
typedef uint32_t pal_alloc_flags_t; /* bitfield */
#define PAL_ALLOC_RESERVE  0x1 /*!< Only reserve the memory */
#define PAL_ALLOC_INTERNAL 0x2 /*!< Allocate for PAL (valid only if #IN_PAL) */
#define PAL_ALLOC_MASK     0x3

/*! memory protection flags */
typedef uint32_t pal_prot_flags_t; /* bitfield */
#define PAL_PROT_READ      0x1
#define PAL_PROT_WRITE     0x2
#define PAL_PROT_EXEC      0x4
#define PAL_PROT_WRITECOPY 0x8
#define PAL_PROT_MASK      0xF

/*! Stream Access Flags */
enum pal_access {
    PAL_ACCESS_RDONLY,
    PAL_ACCESS_WRONLY,
    PAL_ACCESS_RDWR,
    PAL_ACCESS_BOUND,
};

/*! stream sharing flags */
// FIXME: These flags currently must correspond 1-1 to Linux flags, which is totally unportable.
//        They should be redesigned when we'll be rewriting the filesystem layer.
typedef uint32_t pal_share_flags_t; /* bitfield */
#define PAL_SHARE_GLOBAL_X    01
#define PAL_SHARE_GLOBAL_W    02
#define PAL_SHARE_GLOBAL_R    04
#define PAL_SHARE_GROUP_X    010
#define PAL_SHARE_GROUP_W    020
#define PAL_SHARE_GROUP_R    040
#define PAL_SHARE_OWNER_X   0100
#define PAL_SHARE_OWNER_W   0200
#define PAL_SHARE_OWNER_R   0400
#define PAL_SHARE_STICKY   01000
#define PAL_SHARE_SET_GID  02000
#define PAL_SHARE_SET_UID  04000
#define PAL_SHARE_MASK     07777

/*! stream create mode */
enum pal_create_mode {
    PAL_CREATE_NEVER,     /*!< Fail if file does not exist */
    PAL_CREATE_TRY,       /*!< Create file if file does not exist */
    PAL_CREATE_ALWAYS,    /*!< Create file and fail if file already exists */
    PAL_CREATE_IGNORED,   /*!< Magic value for calls to handle types which ignore creation mode */
};

/*! stream misc flags */
typedef uint32_t pal_stream_options_t; /* bitfield */
#define PAL_OPTION_CLOEXEC         1
#define PAL_OPTION_EFD_SEMAPHORE   2 /*!< specific to `eventfd` syscall */
#define PAL_OPTION_NONBLOCK        4
#define PAL_OPTION_DUALSTACK       8 /*!< Create dual-stack socket (opposite of IPV6_V6ONLY) */
#define PAL_OPTION_MASK          0xF

enum pal_delete_mode {
    PAL_DELETE_ALL,  /*!< delete the whole resource / shut down both directions */
    PAL_DELETE_READ,  /*!< shut down the read side only */
    PAL_DELETE_WRITE, /*!< shut down the write side only */
};

/* stream attribute structure */
typedef struct _PAL_STREAM_ATTR {
    PAL_IDX handle_type;
    bool nonblocking;
    pal_share_flags_t share_flags;
    PAL_NUM pending_size;
    union {
        struct {
            PAL_NUM linger;
            PAL_NUM receivebuf, sendbuf;
            uint64_t receivetimeout_us, sendtimeout_us;
            bool tcp_cork;
            bool tcp_keepalive;
            bool tcp_nodelay;
        } socket;
    };
} PAL_STREAM_ATTR;

/* These values are used as indices in an array of PAL_EVENT_NUM_BOUND elements, be careful when
 * changing them. */
enum pal_event {
    /*! pseudo event, used in some APIs to denote a lack of event */
    PAL_EVENT_NO_EVENT,
    /*! arithmetic error (div-by-zero, floating point exception, etc.) */
    PAL_EVENT_ARITHMETIC_ERROR,
    /*! segmentation fault, protection fault, bus fault */
    PAL_EVENT_MEMFAULT,
    /*! illegal instructions */
    PAL_EVENT_ILLEGAL,
    /*! terminated by external program (see "sys.enable_sigterm_injection" manifest option) */
    PAL_EVENT_QUIT,
    /*! interrupted (usually internally to handle aync event) */
    PAL_EVENT_INTERRUPTED,

    PAL_EVENT_NUM_BOUND,
};

/*!
 * \brief Type of exception handlers (upcalls).
 *
 * \param is_in_pal  `true` if the exception happened inside PAL.
 * \param addr       Address of the exception (meaningful only for sync exceptions).
 * \param context    CPU context at the moment of exception.
 */
typedef void (*pal_event_handler_t)(bool is_in_pal, PAL_NUM addr, PAL_CONTEXT* context);

/*! block until the handle's event is triggered */
#define NO_TIMEOUT ((PAL_NUM)-1)

typedef uint32_t pal_wait_flags_t; /* bitfield */
#define PAL_WAIT_READ   1
#define PAL_WAIT_WRITE  2
#define PAL_WAIT_ERROR  4 /*!< ignored in events */

enum pal_segment_reg {
    PAL_SEGMENT_FS,
    PAL_SEGMENT_GS,
};

#endif /* PAL_API_TYPES_H */
