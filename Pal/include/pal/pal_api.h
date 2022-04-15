/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*!
 * \file pal_api.h
 * \brief This file contains definitions of PAL API functions.
 */

#ifndef PAL_API_H
#define PAL_API_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdnoreturn.h>

const struct pal_public_state* DkGetPalPublicState(void);

/*!
 * \brief Allocate virtual memory for the library OS and zero it out.
 *
 * \param[in,out] addr_ptr    `*addr_ptr` should contain requested address or NULL. On success,
 *                            it will be set to the allocated address.
 * \param         size        Must be a positive number, aligned at the allocation alignment.
 * \param         alloc_type  A combination of any of the `PAL_ALLOC_*` flags.
 * \param         prot        A combination of the `PAL_PROT_*` flags.
 *
 * `*addr_ptr` can be any valid address aligned at the allocation alignment or `NULL`, in which case
 * a suitable address will be picked automatically. Any memory previously allocated at the same
 * address will be discarded (only if `*addr_ptr` was provided). Overwriting any part of PAL memory
 * is forbidden. On successful return `*addr_ptr` will contain the allocated address (which can
 * differ only in the `NULL` case).
 *
 */
int DkVirtualMemoryAlloc(void** addr_ptr, PAL_NUM size, pal_alloc_flags_t alloc_type,
                         pal_prot_flags_t prot);

/*!
 * \brief Deallocate a previously allocated memory mapping.
 *
 * \param addr  The address.
 * \param size  The size.
 *
 * Both `addr` and `size` must be non-zero and aligned at the allocation alignment.
 */
int DkVirtualMemoryFree(void* addr, PAL_NUM size);

/*!
 * \brief Modify the permissions of a previously allocated memory mapping.
 *
 * \param addr  The address.
 * \param size  The size.
 * \param prot  See #DkVirtualMemoryAlloc.
 *
 * Both `addr` and `size` must be non-zero and aligned at the allocation alignment.
 */
int DkVirtualMemoryProtect(void* addr, PAL_NUM size, pal_prot_flags_t prot);

/*!
 * \brief Create a new process.
 *
 * \param      args    An array of strings -- the arguments to be passed to the new process.
 * \param[out] handle  On success contains the process handle.
 *
 * Loads and executes the same binary as currently executed one (`loader.entrypoint`), and passes
 * the new arguments.
 *
 * TODO: `args` is only used by PAL regression tests, and should be removed at some point.
 */
int DkProcessCreate(const char** args, PAL_HANDLE* handle);

/*!
 * \brief Terminate all threads in the process immediately.
 *
 * \param exit_code  The exit value returned to the host.
 */
noreturn void DkProcessExit(PAL_NUM exit_code);

/*!
 * \brief Open/create a stream resource specified by `uri`.
 *
 * \param uri          The URI of the stream to be opened/created.
 * \param access       See #pal_access.
 * \param share_flags  A combination of the `PAL_SHARE_*` flags.
 * \param create       See #pal_create_mode.
 * \param options      A combination of the `PAL_OPTION_*` flags.
 * \param handle[out]  If the resource is successfully opened or created, a PAL handle is returned
 *                     in `*handle` for further access such as reading or writing.
 *
 * \returns 0 on success, negative error code on failure.
 *
 * Supported URI types:
 * * `%file:...`, `dir:...`: Files or directories on the host file system. If #PAL_CREATE_TRY or
 *   #PAL_CREATE_ALWAYS is given in `create` flags, the file/directory will be created.
 * * `dev:...`: Open a device as a stream. For example, `dev:tty` represents the standard I/O.
 * * `pipe.srv:<name>`, `pipe:<name>`, `pipe:`: Open a byte stream that can be used for RPC between
 *   processes. The server side of a pipe can accept any number of connections. If `pipe:` is given
 *   as the URI (i.e., without a name), it will open an anonymous bidirectional pipe.
 * * `tcp.srv:<ADDR>:<PORT>`, `tcp:<ADDR>:<PORT>`: Open a TCP socket to listen or connect to
 *   a remote TCP socket.
 * * `udp.srv:<ADDR>:<PORT>`, `udp:<ADDR>:<PORT>`: Open a UDP socket to listen or connect to
 *   a remote UDP socket.
 */
int DkStreamOpen(const char* uri, enum pal_access access, pal_share_flags_t share_flags,
                 enum pal_create_mode create, pal_stream_options_t options, PAL_HANDLE* handle);

/*!
 * \brief Block until a new connection is accepted and return the PAL handle for the connection.
 *
 * \param      handle   Handle to accept a new connection on.
 * \param[out] client   On success holds handle for the new connection.
 * \param      options  Flags to set on \p client handle.
 *
 * This API is only available for handles that are opened with `pipe.srv:...`, `tcp.srv:...`, and
 * `udp.srv:...`.
 */
int DkStreamWaitForClient(PAL_HANDLE handle, PAL_HANDLE* client, pal_stream_options_t options);

/*!
 * \brief Read data from an open stream.
 *
 * \param         handle  Handle to the stream.
 * \param         offset  Offset to read at. If \p handle is a file, \p offset must be specified at
 *                        each call.
 * \param[in,out] count   Contains size of \p buffer. On success, will be set to the number of bytes
 *                        read.
 * \param         buffer  Pointer to the buffer to read into.
 * \param[out]    source  If \p handle is a UDP socket, \p size is not zero and \p source is not
 *                        NULL, the remote socket address is returned in it.
 * \param         size    Size of the \p source buffer.
 *
 * \returns 0 on success, negative error code on failure.
 *
 * If \p handle is a directory, DkStreamRead fills the buffer with the null-terminated names of the
 * directory entries.
 */
int DkStreamRead(PAL_HANDLE handle, PAL_NUM offset, PAL_NUM* count, void* buffer, char* source,
                 PAL_NUM size);

/*!
 * \brief Write data to an open stream.
 *
 * \param         handle  Handle to the stream.
 * \param         offset  Offset to write to. If \p handle is a file, \p offset must be specified at
 *                        each call.
 * \param[in,out] count   Contains size of \p buffer. On success, will be set to the number of bytes
 *                        written.
 * \param         buffer  Pointer to the buffer to write from.
 * \param         dest    If the handle is a UDP socket, specifies the remote socket address.
 *
 * \returns 0 on success, negative error code on failure.
 */
int DkStreamWrite(PAL_HANDLE handle, PAL_NUM offset, PAL_NUM* count, void* buffer,
                  const char* dest);

/*!
 * \brief Delete files or directories on the host or shut down the connection of TCP/UDP sockets.
 *
 * \param access  Which side to shut down (see #pal_delete_mode values).
 */
int DkStreamDelete(PAL_HANDLE handle, enum pal_delete_mode delete_mode);

/*!
 * \brief Map a file to a virtual memory address in the current process.
 *
 * \param         handle    Handle to the stream to be mapped.
 * \param[in,out] addr_ptr  See #DkVirtualMemoryAlloc.
 * \param         prot      See #DkVirtualMemoryAlloc.
 * \param         offset    Offset in the stream to be mapped. Must be properly aligned.
 * \param         size      Size of the requested mapping. Must be non-zero and properly aligned.
 *
 * \returns 0 on success, negative error code on failure.
 */
int DkStreamMap(PAL_HANDLE handle, void** addr_ptr, pal_prot_flags_t prot, PAL_NUM offset,
                PAL_NUM size);

/*!
 * \brief Unmap virtual memory that is backed by a file stream.
 *
 * `addr` and `size` must be aligned at the allocation alignment.
 *
 * \returns 0 on success, negative error code on failure.
 */
int DkStreamUnmap(void* addr, PAL_NUM size);

/*!
 * \brief Set the length of the file referenced by handle to `length`.
 *
 * \returns 0 on success, negative error code on failure.
 */
int DkStreamSetLength(PAL_HANDLE handle, PAL_NUM length);

/*!
 * \brief Flush the buffer of a file stream.
 *
 * \returns 0 on success, negative error code on failure.
 */
int DkStreamFlush(PAL_HANDLE handle);

/*!
 * \brief Send a PAL handle to a process.
 *
 * \param target_process  The handle to the target process where \p cargo will be sent.
 * \param cargo           The handle to send.
 *
 * \returns 0 on success, negative error code on failure.
 */
int DkSendHandle(PAL_HANDLE target_process, PAL_HANDLE cargo);

/*!
 * \brief Receive a handle from another process.
 *
 * \param      source_process  The handle to the source process from which \p cargo will be
 *                             received.
 * \param[out] out_cargo       The received handle.
 *
 * \returns 0 on success, negative error code on failure.
 */
int DkReceiveHandle(PAL_HANDLE source_process, PAL_HANDLE* out_cargo);

/*!
 * \brief Query the attributes of a named stream.
 *
 * This API only applies for URIs such as `%file:...`, `dir:...`, and `dev:...`.
 */
int DkStreamAttributesQuery(const char* uri, PAL_STREAM_ATTR* attr);

/*!
 * \brief Query the attributes of an open stream.
 *
 * This API applies to any stream handle.
 */
int DkStreamAttributesQueryByHandle(PAL_HANDLE handle, PAL_STREAM_ATTR* attr);

/*!
 * \brief Set the attributes of an open stream.
 */
int DkStreamAttributesSetByHandle(PAL_HANDLE handle, PAL_STREAM_ATTR* attr);

/*!
 * \brief Query the name of an open stream. On success `buffer` contains a null-terminated string.
 */
int DkStreamGetName(PAL_HANDLE handle, char* buffer, PAL_NUM size);

/*!
 * \brief This API changes the name of an open stream.
 */
int DkStreamChangeName(PAL_HANDLE handle, const char* uri);

/*!
 * \brief Create a thread in the current process.
 *
 * \param      addr    Address of an entry point of execution for the new thread.
 * \param      param   Pointer argument that is passed to the new thread.
 * \param[out] handle  On success contains the thread handle.
 */
int DkThreadCreate(int (*callback)(void*), void* param, PAL_HANDLE* handle);

/*!
 * \brief Yield the current thread such that the host scheduler can reschedule it.
 */
void DkThreadYieldExecution(void);

/*!
 * \brief Terminate the current thread.
 *
 * \param clear_child_tid  Pointer to memory that is erased on thread exit to notify LibOS (which in
 *                         turn notifies the parent thread if any); if `clear_child_tid` is NULL,
 *                         then PAL doesn't do the clearing.
 */
noreturn void DkThreadExit(int* clear_child_tid);

/*!
 * \brief Resume a thread.
 */
int DkThreadResume(PAL_HANDLE thread);

/*!
 * \brief Set the CPU affinity of a thread.
 *
 * \param thread        PAL thread for which to set the CPU affinity.
 * \param cpumask_size  Size in bytes of the bitmask pointed by \a cpu_mask.
 * \param cpu_mask      Pointer to the new CPU mask.
 *
 * \returns 0 on success, negative error code on failure.
 *
 * All bit positions exceeding the count of host CPUs are ignored. Returns an error if no CPUs were
 * selected.
 */
int DkThreadSetCpuAffinity(PAL_HANDLE thread, PAL_NUM cpumask_size, unsigned long* cpu_mask);

/*!
 * \brief Get the CPU affinity of a thread.
 *
 * \param thread        PAL thread for which to get the CPU affinity.
 * \param cpumask_size  Size in bytes of the bitmask pointed by \a cpu_mask.
 * \param cpu_mask      Pointer to hold the current CPU mask.
 *
 * \returns 0 on success, negative error code on failure.
 *
 * This function assumes that \a cpumask_size is valid and greater than 0. Also, \a cpumask_size
 * must be able to fit all the processors in the host and must be aligned by sizeof(long). For
 * example, if the host supports 4 CPUs, \a cpumask_size should be 8 bytes.
 */
int DkThreadGetCpuAffinity(PAL_HANDLE thread, PAL_NUM cpumask_size, unsigned long* cpu_mask);

/*!
 * \brief Set the handler for the specific exception event.
 *
 * \param event  One of #pal_event values.
 */
void DkSetExceptionHandler(pal_event_handler_t handler, enum pal_event event);

/*!
 * \brief Create an event handle.
 *
 * \param[out] handle         On success `*handle` contains pointer to the event handle.
 * \param      init_signaled  Initial state of the event (`true` - set, `false` - not set).
 * \param      auto_clear     `true` if a successful wait for the event should also reset (consume)
 *                            it.
 *
 * Creates a handle to an event that resembles WinAPI synchronization events. A thread can set
 * (signal) the event using #DkEventSet, clear (unset) it using #DkEventClear or wait until
 * the event becomes set (signaled) using #DkEventWait.
 */
int DkEventCreate(PAL_HANDLE* handle, bool init_signaled, bool auto_clear);

/*!
 * \brief Set (signal) an event.
 *
 * If the event is already set, does nothing.
 *
 * This function has release semantics and synchronizes with #DkEventWait.
 */
void DkEventSet(PAL_HANDLE handle);

/*!
 * \brief Clear (unset) an event.
 *
 * If the event is not set, does nothing.
 */
void DkEventClear(PAL_HANDLE handle);

/*!
 * \brief Wait for an event handle.
 *
 * \param         handle      Handle to wait on, must be of "event" type.
 * \param[in,out] timeout_us  Timeout for the wait.
 *
 * \returns 0 if the event was triggered, negative error code otherwise (#PAL_ERROR_TRYAGAIN in case
 *          of timeout triggering)
 *
 * \p timeout_us points to a value that specifies the maximal time (in microseconds) that this
 * function should sleep if this event is not signaled in the meantime. Specifying `NULL` blocks
 * indefinitely. Note that in any case this function can return earlier, e.g. if a signal has
 * arrived, but this will be indicated by the returned error code.
 * After returning (both successful and not), \p timeout_us will contain the remaining time (time
 * that need to pass before we hit original \p timeout_us).
 *
 * This function has acquire semantics and synchronizes with #DkEventSet.
 */
int DkEventWait(PAL_HANDLE handle, uint64_t* timeout_us);

/*!
 * \brief Poll - wait for an event to happen on at least one handle.
 *
 * \param         count         The number of items in \p handle_array.
 * \param         handle_array  Array of handles to poll.
 * \param         events        Requested events for each handle.
 * \param[out]    ret_events    Events that were detected on each handle.
 * \param[in,out] timeout_us    Timeout for the wait (`NULL` to block indefinitely).
 *
 * \returns 0 if there was an event on at least one handle, negative error code otherwise.
 *
 * \p timeout_us contains remaining timeout both on successful and failed calls.
 */
int DkStreamsWaitEvents(size_t count, PAL_HANDLE* handle_array, pal_wait_flags_t* events,
                        pal_wait_flags_t* ret_events, uint64_t* timeout_us);

/*!
 * \brief Close (deallocate) a PAL handle.
 */
void DkObjectClose(PAL_HANDLE object_handle);

/*!
 * \brief Output a message to the debug stream.
 *
 * \param     buffer  Message to write.
 * \param[in] size    \p buffer size.
 *
 * \returns 0 on success, negative error code on failure.
 */
int DkDebugLog(const void* buffer, PAL_NUM size);

/*!
 * \brief Get the current time.
 *
 * \param[out] time  On success holds the current time in microseconds.
 */
int DkSystemTimeQuery(PAL_NUM* time);

/*!
 * \brief Cryptographically secure RNG.
 *
 * \param[out] buffer  Output buffer.
 * \param[in]  size    \p buffer size.
 *
 * \returns 0 on success, negative on failure.
 */
int DkRandomBitsRead(void* buffer, PAL_NUM size);

/*!
 * \brief Get segment register base.
 *
 * \param reg   The register base to get (#pal_segment_reg).
 * \param addr  The address where result will be stored.
 *
 * \returns 0 on success, negative error value on failure.
 */
int DkSegmentBaseGet(enum pal_segment_reg reg, uintptr_t* addr);

/*!
 * \brief Set segment register.
 *
 * \param reg   The register base to be set (#pal_segment_reg).
 * \param addr  The address to be set.
 *
 * \returns 0 on success, negative error value on failure.
 */
int DkSegmentBaseSet(enum pal_segment_reg reg, uintptr_t addr);

/*!
 * \brief Return the amount of currently available memory for LibOS/application usage.
 */
PAL_NUM DkMemoryAvailableQuota(void);

/*!
 * \brief Obtain the attestation report (local) with `user_report_data` embedded into it.
 *
 * \param[in]     user_report_data       Report data with arbitrary contents (typically uniquely
 *                                       identifies this Gramine instance). Must be a 64B buffer
 *                                       in case of SGX PAL.
 * \param[in,out] user_report_data_size  Caller specifies size of `user_report_data`; on return,
 *                                       contains PAL-enforced size of `user_report_data` (64B in
 *                                       case of SGX PAL).
 * \param[in,out] target_info            Target info of target enclave for attestation. If it
 *                                       contains all zeros, it is populated with this enclave's
 *                                       target info. Must be a 512B buffer in case of SGX PAL.
 * \param[in,out] target_info_size       Caller specifies size of `target_info`; on return,
 *                                       contains PAL-enforced size of `target_info` (512B in case
 *                                       of SGX PAL).
 * \param[out]    report                 Attestation report with `user_report_data` embedded,
 *                                       targeted for an enclave with provided `target_info`. Must
 *                                       be a 432B buffer in case of SGX PAL.
 * \param[in,out] report_size            Caller specifies size of `report`; on return, contains
 *                                       PAL-enforced size of `report` (432B in case of SGX PAL).
 *
 * Currently works only for Linux-SGX PAL, where `user_report_data` is a blob of exactly 64B,
 * `target_info` is an SGX target_info struct of exactly 512B, and `report` is an SGX report
 * obtained via the EREPORT instruction (exactly 432B). If `target_info` contains all zeros,
 * then this function additionally returns this enclave's target info in `target_info`. Useful
 * for local attestation.
 *
 * The caller may specify `*user_report_data_size`, `*target_info_size`, and `*report_size` as 0
 * and other fields as NULL to get PAL-enforced sizes of these three structs.
 */
int DkAttestationReport(const void* user_report_data, PAL_NUM* user_report_data_size,
                        void* target_info, PAL_NUM* target_info_size, void* report,
                        PAL_NUM* report_size);

/*!
 * \brief Obtain the attestation quote with `user_report_data` embedded into it.
 *
 * \param[in]     user_report_data       Report data with arbitrary contents (typically uniquely
 *                                       identifies this Gramine instance). Must be a 64B buffer
 *                                       in case of SGX PAL.
 * \param[in]     user_report_data_size  Size in bytes of `user_report_data`. Must be exactly 64B
 *                                       in case of SGX PAL.
 * \param[out]    quote                  Attestation quote with `user_report_data` embedded.
 * \param[in,out] quote_size             Caller specifies maximum size allocated for `quote`; on
 *                                       return, contains actual size of obtained quote.
 *
 * Currently works only for Linux-SGX PAL, where `user_report_data` is a blob of exactly 64B
 * and `quote` is an SGX quote obtained from Quoting Enclave via AESM service.
 */
int DkAttestationQuote(const void* user_report_data, PAL_NUM user_report_data_size, void* quote,
                       PAL_NUM* quote_size);

/*!
 * \brief Set wrap key (master key) for protected files.
 *
 * \param[in] pf_key_hex  Wrap key for protected files. Must be a 32-char null-terminated hex string
 *                        in case of SGX PAL (AES-GCM encryption key).
 *
 * Currently works only for Linux-SGX PAL. This function is supposed to be called during
 * remote attestation and secret provisioning, before the user application starts.
 */
int DkSetProtectedFilesKey(const char* pf_key_hex);

#if defined(__i386__) || defined(__x86_64__)
/*!
 * \brief Return CPUID information, based on the leaf/subleaf.
 *
 * \param[out] values  The array of the results.
 */
int DkCpuIdRetrieve(uint32_t leaf, uint32_t subleaf, uint32_t values[CPUID_WORD_NUM]);
#endif

void DkDebugMapAdd(const char* uri, void* start_addr);
void DkDebugMapRemove(void* start_addr);

/* Describe the code under given address (see `describe_location()` in `callbacks.h`). Without
 * DEBUG, falls back to raw value ("0x1234"). */
void DkDebugDescribeLocation(uintptr_t addr, char* buf, size_t buf_size);

#endif /* PAL_API_H */
