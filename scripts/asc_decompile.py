"""
Helper script for rust_ASC getclass.
Usage: py asc_decompile.py <dex_file> <dalvik_class>
Reads a rebuilt DEX file and decompiles the target class using androguard DAD.
"""
import sys
import os

# Add ASC source to path
_script_dir = os.path.dirname(os.path.abspath(__file__))
_asc_src = os.path.join(_script_dir, '..', '..', '..', 'Tools', 'ASC', 'src')
if os.path.isdir(_asc_src):
    sys.path.insert(0, _asc_src)
else:
    # Try env var or relative from cwd
    asc_dir = os.environ.get('ASC_SRC')
    if asc_dir:
        sys.path.insert(0, asc_dir)

from asc_core.utils.decompiler import decompile_dex_bytes

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: py asc_decompile.py <dex_file> <dalvik_class>", file=sys.stderr)
        sys.exit(1)

    dex_path = sys.argv[1]
    dalvik_class = sys.argv[2]

    with open(dex_path, 'rb') as f:
        dex_bytes = bytearray(f.read())

    source = decompile_dex_bytes(dex_bytes, dalvik_class)
    print(source, end='')