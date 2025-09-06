// SPDX-License-Identifier: GPL-2.0
/*
 * This program traces system calls for a specific PID on ARM64.
 *
 * This version uses a union of structs to capture detailed, structured
 * argument data for specific syscalls. The userspace program can then
 * parse the data based on the syscall number.
 */

 #include "vmlinux.h"
 #include <bpf/bpf_helpers.h>
 #include <bpf/bpf_tracing.h>
 
 #define DATA_LEN 256
 
 // Syscall numbers for ARM64 (aarch64)
 #define __NR_write 64
 #define __NR_execve 221
 #define __NR_openat 56
 // Note: __NR_open is deprecated on arm64 in favor of openat.
 
 // --- Define structs for specific syscall arguments ---
 
 // For openat()
 struct path_args_t {
     char pathname[DATA_LEN];
 };
 
 // For write()
 struct write_args_t {
     u32 len;
     char buf[DATA_LEN];
 };
 
 // For execve()
 struct execve_args_t {
     char filename[DATA_LEN];
 };
 
 
 // The main event struct now contains a union of the above structs.
 struct syscall_event {
     u64 ts;         // Timestamp
     u32 pid;        // Process ID
     u64 syscall_nr; // Syscall number
     u64 args[6];    // Raw register arguments
 
     // Union to hold structured data for specific syscalls.
     // The active member is determined by syscall_nr.
     union {
         struct path_args_t path_args;
         struct write_args_t write_args;
         struct execve_args_t execve_args;
     } data;
 };
 
 
 // Ring buffer map for sending data to userspace
 struct {
     __uint(type, BPF_MAP_TYPE_RINGBUF);
     __uint(max_entries, 256 * 1024); // 256 KB
 } rb SEC(".maps");
 
 // Target PID to trace.
 volatile const pid_t target_pid = 0;
 
 SEC("tp/raw_syscalls/sys_enter")
 int handle_sys_enter(struct trace_event_raw_sys_enter *ctx) {
     u64 id = bpf_get_current_pid_tgid();
     u32 pid = id >> 32;
 
     if (pid != target_pid) {
         return 0;
     }
 
     struct syscall_event *e;
     e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
     if (!e) {
         return 0;
     }
 
     // Populate basic event info
     e->ts = bpf_ktime_get_ns();
     e->pid = pid;
     e->syscall_nr = (u64)ctx->id;
     bpf_probe_read_kernel(&e->args, sizeof(e->args), &ctx->args);
 
 
     if (e->syscall_nr != __NR_openat && e->syscall_nr != __NR_execve && e->syscall_nr != __NR_write) {
        bpf_ringbuf_discard(e, 0);
        return 0;
     }
     // Switch on the syscall number to populate the correct union member.
     const void *ptr;
     switch (e->syscall_nr) {
     case __NR_openat:
        bpf_printk("Tracking %d and %d", pid, e->syscall_nr);
         ptr = (const void *)e->args[1];
         bpf_probe_read_user_str(&e->data.path_args.pathname, DATA_LEN, ptr);
         break;
 
     case __NR_execve:
        bpf_printk("Tracking %d and %d", pid, e->syscall_nr);
         ptr = (const void *)e->args[0];
         bpf_probe_read_user_str(&e->data.execve_args.filename, DATA_LEN, ptr);
         break;
 
     case __NR_write: {
        bpf_printk("Tracking %d and %d", pid, e->syscall_nr);
         ptr = (const void *)e->args[1];
         u64 count = e->args[2];
         u32 read_size = (count < DATA_LEN) ? count : DATA_LEN;
         e->data.write_args.len = read_size;
         bpf_probe_read_user(&e->data.write_args.buf, read_size, ptr);
         break;
     }
     }
 
     bpf_ringbuf_submit(e, 0);
     return 0;
 }
 
 char LICENSE[] SEC("license") = "GPL";
 
 
