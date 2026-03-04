#!/usr/bin/env python3
"""
extract_svt.py - Extract and decode SVT (Signature Validation Token) JWTs
                 embedded in PDF document timestamps.

An SVT is a signed JWT embedded as a TSTInfo extension (OID 1.2.752.201.5.2)
inside an RFC 3161 document timestamp. This script finds and decodes them.

Usage:
    python3 extract_svt.py <pdf_file>
    python3 extract_svt.py <cms_der_file> --der

Output:
    Decoded SVT header, payload, and analysis of sig_val_claims.
"""

import base64
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone

# Sweden Connect SVT extension OID: 1.2.752.201.5.2
# BER/DER encoding: 2a 85 70 81 49 05 02
SVT_OID_BYTES = bytes([0x2A, 0x85, 0x70, 0x81, 0x49, 0x05, 0x02])
SVT_OID_STR = "1.2.752.201.5.2"

# JWT base64url alphabet
JWT_CHARS = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.=")


def b64url_decode(s: str) -> bytes:
    """Decode base64url with padding correction."""
    s = s.rstrip("=")
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def find_svt_in_cms(cms_data: bytes) -> str | None:
    """Search CMS DER data for the SVT OID and extract the JWT string."""
    pos = cms_data.find(SVT_OID_BYTES)
    if pos < 0:
        return None

    # The JWT (eyJ...) follows somewhere after the OID.
    # Scan forward for the JWT marker.
    jwt_marker = b"eyJ"
    jwt_start = cms_data.find(jwt_marker, pos)
    if jwt_start < 0:
        return None

    # Collect JWT characters until we hit a non-JWT byte
    jwt_bytes = bytearray()
    for i in range(jwt_start, len(cms_data)):
        if cms_data[i] in JWT_CHARS:
            jwt_bytes.append(cms_data[i])
        else:
            break

    jwt_str = jwt_bytes.decode("ascii")

    # Validate: must have exactly 3 parts (header.payload.signature)
    parts = jwt_str.split(".")
    if len(parts) != 3:
        return None

    return jwt_str


def extract_cms_from_pdf(pdf_data: bytes) -> list[bytes]:
    """Extract all CMS blobs from PDF signature dictionaries."""
    blobs = []
    byte_range_pattern = rb"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]"
    for m in re.finditer(byte_range_pattern, pdf_data):
        off1 = int(m.group(1))
        len1 = int(m.group(2))
        off2 = int(m.group(3))

        hex_start = off1 + len1 + 1
        hex_end = off2 - 1
        hex_data = pdf_data[hex_start:hex_end]
        hex_str = hex_data.replace(b" ", b"").replace(b"\n", b"").replace(b"\r", b"")
        hex_str = hex_str.rstrip(b"0")
        if len(hex_str) % 2:
            hex_str += b"0"

        blobs.append(bytes.fromhex(hex_str.decode("ascii")))
    return blobs


def decode_svt(jwt_str: str) -> dict:
    """Decode an SVT JWT and return structured data."""
    parts = jwt_str.split(".")
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    sig_b64 = parts[2]

    return {
        "header": header,
        "payload": payload,
        "signature_b64url": sig_b64,
        "jwt_length": len(jwt_str),
    }


def format_timestamp(unix_ts: int) -> str:
    """Format a Unix timestamp as ISO 8601."""
    dt = datetime.fromtimestamp(unix_ts, tz=timezone.utc)
    return dt.isoformat()


def analyze_svt(svt: dict) -> None:
    """Print detailed analysis of a decoded SVT."""
    header = svt["header"]
    payload = svt["payload"]

    print("=" * 72)
    print("SVT (Signature Validation Token) Analysis")
    print("=" * 72)
    print()

    # Header
    print("JWT Header:")
    print(f"  Algorithm:    {header.get('alg', 'N/A')}")
    print(f"  Type:         {header.get('typ', 'N/A')}")
    if "x5c" in header:
        print(f"  x5c certs:    {len(header['x5c'])} certificate(s)")
        # Decode first cert to show subject
        try:
            cert_der = base64.b64decode(header["x5c"][0])
            cert_sha256 = hashlib.sha256(cert_der).hexdigest()
            print(f"  Signer cert SHA-256: {cert_sha256}")
        except Exception:
            pass
    print()

    # Payload metadata
    print("JWT Payload:")
    print(f"  Issuer (iss): {payload.get('iss', 'N/A')}")
    iat = payload.get("iat")
    if iat:
        print(f"  Issued at:    {format_timestamp(iat)} (Unix: {iat})")
    print(f"  JWT ID (jti): {payload.get('jti', 'N/A')}")
    print()

    # sig_val_claims
    claims = payload.get("sig_val_claims", {})
    print("Signature Validation Claims:")
    print(f"  Version:      {claims.get('ver', 'N/A')}")
    print(f"  Profile:      {claims.get('profile', 'N/A')}")
    print(f"  Hash algo:    {claims.get('hash_algo', 'N/A')}")
    print()

    sigs = claims.get("sig", [])
    for i, sig in enumerate(sigs):
        print(f"  --- Covered Signature {i} ---")

        sig_ref = sig.get("sig_ref", {})
        print(f"    sig_ref.id:       {sig_ref.get('id', 'N/A')}")
        print(f"    sig_ref.sig_hash: {sig_ref.get('sig_hash', 'N/A')}")
        print(f"    sig_ref.sb_hash:  {sig_ref.get('sb_hash', 'N/A')}")

        for j, dr in enumerate(sig.get("sig_data_ref", [])):
            print(f"    sig_data_ref[{j}].ref:  {dr.get('ref', 'N/A')}")
            print(f"    sig_data_ref[{j}].hash: {dr.get('hash', 'N/A')}")

        cert_ref = sig.get("signer_cert_ref", {})
        print(f"    cert_ref.type:    {cert_ref.get('type', 'N/A')}")
        refs = cert_ref.get("ref", [])
        for k, r in enumerate(refs):
            print(f"    cert_ref.ref[{k}]:  {r}")

        time_vals = sig.get("time_val", [])
        if time_vals:
            for tv in time_vals:
                print(f"    time_val: {json.dumps(tv)}")
        else:
            print("    time_val:         (none)")

        sig_vals = sig.get("sig_val", [])
        for sv in sig_vals:
            print(f"    sig_val.policy:   {sv.get('pol', 'N/A')}")
            print(f"    sig_val.result:   {sv.get('res', 'N/A')}")
            print(f"    sig_val.message:  {sv.get('msg', 'N/A')}")

        print()

    # Summary
    print("=" * 72)
    print("SUMMARY")
    print("=" * 72)
    all_passed = all(
        sv.get("res") == "PASSED" for sig in sigs for sv in sig.get("sig_val", [])
    )
    if all_passed:
        print("  The SVT asserts ALL covered signatures PASSED validation.")
        print("  Any system trusting this SVT will skip direct crypto verification")
        print("  of the original signature(s).")
    else:
        print("  WARNING: Not all signatures have PASSED status in the SVT.")
    print()


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <pdf_or_der_file> [--der]", file=sys.stderr)
        sys.exit(1)

    input_path = sys.argv[1]
    is_der = "--der" in sys.argv

    if not os.path.isfile(input_path):
        print(f"Error: {input_path} not found", file=sys.stderr)
        sys.exit(1)

    with open(input_path, "rb") as f:
        data = f.read()

    if is_der:
        # Direct CMS DER input
        cms_blobs = [data]
        print(f"Analyzing CMS DER: {input_path} ({len(data)} bytes)")
    else:
        # PDF input - extract all CMS blobs
        cms_blobs = extract_cms_from_pdf(data)
        print(f"PDF: {input_path} ({len(data)} bytes)")
        print(f"Found {len(cms_blobs)} signature(s)")

    print()
    svt_found = False

    for i, cms in enumerate(cms_blobs):
        jwt_str = find_svt_in_cms(cms)
        if jwt_str:
            svt_found = True
            print(f"SVT found in signature {i} (CMS blob: {len(cms)} bytes)")
            print()
            svt = decode_svt(jwt_str)
            analyze_svt(svt)

            # Also dump raw JSON for further processing
            json_path = os.path.join(
                os.path.dirname(input_path) or ".",
                f"sig{i}_svt.json",
            )
            with open(json_path, "w") as jf:
                json.dump(
                    {"header": svt["header"], "payload": svt["payload"]},
                    jf,
                    indent=2,
                )
            print(f"Raw SVT JSON written to: {json_path}")

    if not svt_found:
        print("No SVT (Signature Validation Token) found in any signature.")
        print(f"(Searched for OID {SVT_OID_STR} in {len(cms_blobs)} CMS blob(s))")


if __name__ == "__main__":
    main()
