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
import ctypes as ct

NAME = b"c"
SYMBOL = b"strlen"
STT_GNU_IFUNC = 1 << 10

# load BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
int printarg(struct pt_regs *ctx) {
    if (!PT_REGS_PARM1(ctx))
        return 0;

    char str[80] = {};
    bpf_probe_read_user(&str, sizeof(str), (void *)PT_REGS_PARM1(ctx));
    bpf_trace_printk("%s\\n", &str);

    return 0;
};
"""

bpf_text_impl_func_addr = """
#include <uapi/linux/ptrace.h>
struct ifunc_addr_t {
    u64 addr;
    u32 pid;
};


BPF_PERF_OUTPUT(output);
void get_impl_function_addr(struct pt_regs *ctx) {
    struct ifunc_addr_t addr;
    __builtin_memset(&addr, 0, sizeof(addr));
    addr.addr = PT_REGS_RC(ctx);
    addr.pid = bpf_get_current_pid_tgid();
    output.perf_submit(ctx, &addr, sizeof(addr));
}


BPF_PERF_OUTPUT(resolve_func_addr);
int get_resolve_func_addr(struct pt_regs *ctx) {
    u64 rip = PT_REGS_IP(ctx);
    resolve_func_addr.perf_submit(ctx, &rip, sizeof(rip));
    return 0;
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


def print_impl_func_addr(cpu, data, size):
    class IfuncAddr(ct.Structure):
        _fields_ = [
            ('addr', ct.c_uint64),
            ('pid', ct.c_uint32),
        ]
    ev = ct.cast(data, ct.POINTER(IfuncAddr)).contents

    print(f'impl func addr: {ev.addr:#x}')
    global impl_addr
    impl_addr = ev.addr


def print_resolve_func_addr(cpu, data, size):
    global difference
    addr = ct.cast(data, ct.POINTER(ct.c_uint64)).contents.value
    print(f'resolve_func_addr: {addr:#x}')
    difference = addr - symbol_offset


ifunc, symbol = is_symbol_indirect_function(NAME, SYMBOL)
if not ifunc:
    print('NOT IFUNC')
    exit()

difference = 0
impl_addr = 0
module_path = ct.cast(symbol.module, ct.c_char_p).value
symbol_offset = symbol.offset
print('module: ', module_path.decode(), f'{symbol_offset:x}')
b = BPF(text=bpf_text_impl_func_addr)
b.attach_uprobe(name=NAME, sym=SYMBOL, fn_name=b"get_resolve_func_addr")
b['resolve_func_addr'].open_perf_buffer(print_resolve_func_addr)
b.attach_uretprobe(name=NAME,
                   sym=SYMBOL,
                   fn_name=b"get_impl_function_addr")
b["output"].open_perf_buffer(print_impl_func_addr)
while True:
    try:
        if difference and impl_addr:
            b.detach_uprobe(name=NAME, sym=SYMBOL)
            b.detach_uretprobe(name=NAME, sym=SYMBOL)
            break
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

b.cleanup()

print(f'difference: {difference:#x}')
print(f'impl_addr: {impl_addr:#x}')
impl_offset = impl_addr - difference
print(f'impl_offset: {impl_offset:#x}')


b2 = BPF(text=bpf_text)
b2.attach_uprobe(name=module_path, addr=impl_offset, fn_name=b'printarg')
# header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "STRLEN"))

# format output
me = getpid()
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b2.trace_fields()
    except ValueError:
        continue
    if pid == me or msg == "":
        continue
    print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
