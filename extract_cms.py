#!/usr/bin/env python3
"""
extract_cms.py - Extract CMS (PKCS#7) blobs from PDF signature dictionaries.

Parses the PDF to find all /ByteRange + /Contents pairs, extracts the raw
CMS DER blobs, and writes them to individual files. Also prints summary
information about each signature.

Usage:
    python3 extract_cms.py <pdf_file> [output_dir]

Output:
    <output_dir>/sig0_cms.der
    <output_dir>/sig1_cms.der
    ...
"""

import os
import re
import sys
import hashlib


def extract_cms_blobs(pdf_path: str, output_dir: str) -> list[dict]:
    """Extract CMS blobs from all PDF signatures.

    Returns a list of dicts with keys:
        index, byte_range, cms_size, cms_sha256, output_path, sub_filter
    """
    with open(pdf_path, "rb") as f:
        data = f.read()

    pdf_size = len(data)
    results = []

    # Find all ByteRange arrays: /ByteRange [off1 len1 off2 len2]
    byte_range_pattern = rb"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]"
    matches = list(re.finditer(byte_range_pattern, data))

    if not matches:
        print("No signatures found in PDF.", file=sys.stderr)
        return results

    print(f"PDF: {pdf_path}")
    print(f"PDF size: {pdf_size} bytes")
    print(f"Signatures found: {len(matches)}")
    print()

    for i, m in enumerate(matches):
        off1 = int(m.group(1))
        len1 = int(m.group(2))
        off2 = int(m.group(3))
        len2 = int(m.group(4))

        covers_eof = (off2 + len2) == pdf_size

        # Extract the hex-encoded Contents between the two byte ranges
        # The Contents value is a hex string enclosed in < ... >
        hex_start = off1 + len1 + 1  # skip the '<'
        hex_end = off2 - 1  # before the '>'
        hex_data = data[hex_start:hex_end]

        # Clean up: remove whitespace and trailing zero-padding
        hex_str = hex_data.replace(b" ", b"").replace(b"\n", b"").replace(b"\r", b"")
        hex_str = hex_str.rstrip(b"0")
        if len(hex_str) % 2:
            hex_str += b"0"

        cms_bytes = bytes.fromhex(hex_str.decode("ascii"))
        cms_sha256 = hashlib.sha256(cms_bytes).hexdigest()

        # Try to find SubFilter near the ByteRange
        # Search backwards and forwards from the ByteRange match
        context_start = max(0, m.start() - 500)
        context_end = min(len(data), m.end() + 200)
        context = data[context_start:context_end]

        sub_filter = "unknown"
        sf_match = re.search(rb"/SubFilter\s*/([A-Za-z0-9._]+)", context)
        if sf_match:
            sub_filter = sf_match.group(1).decode("ascii")

        # Write CMS blob
        out_path = os.path.join(output_dir, f"sig{i}_cms.der")
        with open(out_path, "wb") as f:
            f.write(cms_bytes)

        result = {
            "index": i,
            "byte_range": [off1, len1, off2, len2],
            "covers_eof": covers_eof,
            "cms_size": len(cms_bytes),
            "cms_sha256": cms_sha256,
            "output_path": out_path,
            "sub_filter": sub_filter,
        }
        results.append(result)

        print(f"--- Signature {i} ---")
        print(f"  SubFilter:    {sub_filter}")
        print(f"  ByteRange:    [{off1}, {len1}, {off2}, {len2}]")
        print(f"  Covers EOF:   {covers_eof}")
        print(f"  CMS size:     {len(cms_bytes)} bytes")
        print(f"  CMS SHA-256:  {cms_sha256}")
        print(f"  Written to:   {out_path}")
        print()

    return results


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <pdf_file> [output_dir]", file=sys.stderr)
        sys.exit(1)

    pdf_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "."

    if not os.path.isfile(pdf_path):
        print(f"Error: {pdf_path} not found", file=sys.stderr)
        sys.exit(1)

    os.makedirs(output_dir, exist_ok=True)
    results = extract_cms_blobs(pdf_path, output_dir)

    if results:
        print(f"Extracted {len(results)} CMS blob(s) to {output_dir}/")


if __name__ == "__main__":
    main()
