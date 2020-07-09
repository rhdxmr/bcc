#!/usr/bin/python
#
# strlen_snoop  Trace strlen() library function for a given PID.
#               For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: strlensnoop PID
#
# Try running this on a separate bash shell.
#
# Written as a basic example of BCC and uprobes.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from __future__ import print_function
from bcc import BPF
from bcc.libbcc import lib, bcc_symbol, bcc_symbol_option
from os import getpid
import sys
import ctypes as ct

if len(sys.argv) < 2:
    print("USAGE: strlensnoop PID")
    exit()
pid = sys.argv[1]

NAME = b"c"
SYMBOL = b"strlen"
STT_GNU_IFUNC = 1 << 10

# load BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
int printarg(struct pt_regs *ctx) {
    if (!PT_REGS_PARM1(ctx))
        return 0;

    u32 pid = bpf_get_current_pid_tgid();
    if (pid != PID)
        return 0;

    char str[80] = {};
    bpf_probe_read_user(&str, sizeof(str), (void *)PT_REGS_PARM1(ctx));
    bpf_trace_printk("%s\\n", &str);

    return 0;
};
"""

bpf_text_impl_func_addr = """
#include <uapi/linux/ptrace.h>
BPF_PERF_OUTPUT(output);
void get_impl_function_addr(struct pt_regs *ctx) {
    u64 addr = PT_REGS_RC(ctx);
    output.perf_submit(ctx, &addr, sizeof(addr));
}
"""


def is_symbol_indirect_function(module, symname):
    sym = bcc_symbol()
    sym_op = bcc_symbol_option()
    sym_op.use_debug_file = 1
    sym_op.check_debug_file_crc = 1
    sym_op.lazy_symbolize = 1
    sym_op.use_symbol_type = STT_GNU_IFUNC
    if lib.bcc_resolve_symname(
            module,
            symname,
            0x0,
            0,
            ct.byref(sym_op),
            ct.byref(sym),
    ) < 0:
        return False, None
    else:
        return True, sym


def print_data(cpu, data, size):
    ev = ct.cast(data, ct.POINTER(ct.c_uint64)).contents

    print('cpu:', cpu, f'ev: {ev.value:#0x}', 'size:', size)


ifunc, symbol = is_symbol_indirect_function(NAME, SYMBOL)
if ifunc:
    b = BPF(text=bpf_text_impl_func_addr)
    b.attach_uretprobe(name=NAME,
                       sym=SYMBOL,
                       fn_name=b"get_impl_function_addr")
    b["output"].open_perf_buffer(print_data)
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()
else:
    exit()

# bpf_text = bpf_text.replace('PID', pid)
# b = BPF(text=bpf_text)
# b.attach_uprobe(name=NAME, addr=12, fn_name="printarg")

# # header
# print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "STRLEN"))

# # format output
# me = getpid()
# while 1:
#     try:
#         (task, pid, cpu, flags, ts, msg) = b.trace_fields()
#     except ValueError:
#         continue
#     if pid == me or msg == "":
#         continue
#     print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
