#!/usr/bin/env python3
"""Decompile a DEX class using androguard.

Usage: asc_decompile.py <dex_path> <class_descriptor>

Outputs Java source to stdout.
"""

import sys
import os
import struct
import zlib

def fix_dex_checksum(data: bytes) -> bytes:
    """Recalculate and fix the Adler32 checksum at offset 8."""
    if len(data) < 12:
        return data
    adler = zlib.adler32(data[12:]) & 0xffffffff
    return data[:8] + struct.pack('<I', adler) + data[12:]

def main():
    if len(sys.argv) < 3:
        print("Usage: asc_decompile.py <dex_path> <class_descriptor>", file=sys.stderr)
        sys.exit(1)

    dex_path = sys.argv[1]
    class_descriptor = sys.argv[2]

    if not os.path.exists(dex_path):
        print(f"/* Error: DEX file not found: {dex_path} */")
        sys.exit(1)

    with open(dex_path, 'rb') as f:
        raw = f.read()
    raw = fix_dex_checksum(raw)

    from androguard.core.dex import DEX
    from androguard.core.analysis.analysis import Analysis
    from androguard.decompiler.decompile import DvClass, DvMethod

    vm = DEX(raw)
    vmx = Analysis(vm)

    class_def = vm.get_class(class_descriptor)
    if class_def is None:
        print(f"/* Error: Class {class_descriptor} not found */")
        sys.exit(1)

    # Create DvClass
    dv = DvClass(class_def, vmx)

    # Create DvMethod for each method in the class and decompile
    raw_methods = class_def.get_methods()
    decompiled_methods = []
    for method in raw_methods:
        method_analysis = vmx.get_method(method)
        if method_analysis is None:
            continue
        dv_method = DvMethod(method_analysis)
        if dv_method.method.get_code() is not None:
            dv_method.process()
        decompiled_methods.append(dv_method)

    # Replace raw methods with DvMethod instances
    dv.methods = decompiled_methods

    source = dv.get_source()
    print(source)

if __name__ == "__main__":
    main()