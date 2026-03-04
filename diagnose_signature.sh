#!/usr/bin/env bash
#
# diagnose_signature.sh -- Extract and diagnose signatures in a signed PDF
# using only standard tools (openssl, python3, xxd).
#
# This script proves step by step whether each cryptographic operation
# in a PDF signature is valid or invalid, using only openssl as the
# verification oracle (independent of any Rust or Java implementation).
#
# Usage:
#     ./diagnose_signature.sh <path/to/signed.pdf>

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -z "${1:-}" ]; then
    echo "Usage: $0 <path/to/signed.pdf>" >&2
    exit 1
fi
PDF="$1"

if [ ! -f "$PDF" ]; then
    echo "ERROR: PDF not found: $PDF" >&2
    exit 1
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

echo "========================================================================"
echo " PDF Signature Diagnostic Report"
echo "========================================================================"
echo
echo "PDF file:          $PDF"
echo "PDF size:          $(wc -c < "$PDF") bytes"
echo "Working directory: $WORK"
echo "Date:              $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo

# ── Step 1: Extract CMS blobs and byte-range data ─────────────────────────

echo "========================================================================"
echo " Step 1: Extract CMS blobs from all signatures"
echo "========================================================================"
echo

python3 - "$PDF" "$WORK" <<'PYEOF'
import sys, re, hashlib

pdf_path, work = sys.argv[1], sys.argv[2]
data = open(pdf_path, "rb").read()
pdf_size = len(data)

# Find all ByteRange arrays
br_pattern = rb'/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]'
matches = list(re.finditer(br_pattern, data))
print(f"Signatures found: {len(matches)}")
print()

for i, m in enumerate(matches):
    off1, len1, off2, len2 = int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4))
    covers_eof = (off2 + len2) == pdf_size

    # Find SubFilter near this ByteRange
    ctx_start = max(0, m.start() - 500)
    ctx_end = min(pdf_size, m.end() + 200)
    ctx = data[ctx_start:ctx_end]
    sf_match = re.search(rb'/SubFilter\s*/([A-Za-z0-9._]+)', ctx)
    sub_filter = sf_match.group(1).decode() if sf_match else "unknown"

    print(f"--- Sig {i} ---")
    print(f"  SubFilter:   {sub_filter}")
    print(f"  ByteRange:   [{off1}, {len1}, {off2}, {len2}]")
    print(f"  Covers EOF:  {covers_eof}")
    if not covers_eof:
        gap = pdf_size - (off2 + len2)
        print(f"               ({gap} bytes appended after this signature)")

    # Extract signed byte ranges
    signed_bytes = data[off1:off1+len1] + data[off2:off2+len2]
    open(f"{work}/sig{i}_signed_data.bin", "wb").write(signed_bytes)

    # Extract CMS hex blob
    hex_start = off1 + len1 + 1
    hex_end = off2 - 1
    hex_data = data[hex_start:hex_end]
    hex_str = hex_data.replace(b" ", b"").replace(b"\n", b"").replace(b"\r", b"")
    hex_str = hex_str.rstrip(b"0")
    if len(hex_str) % 2:
        hex_str += b"0"
    cms_bytes = bytes.fromhex(hex_str.decode("ascii"))
    cms_sha256 = hashlib.sha256(cms_bytes).hexdigest()

    open(f"{work}/sig{i}_cms.der", "wb").write(cms_bytes)
    print(f"  CMS size:    {len(cms_bytes)} bytes")
    print(f"  CMS SHA-256: {cms_sha256}")
    print(f"  Signed data: {len(signed_bytes)} bytes")
    print()
PYEOF

# ── Step 2: Inspect CMS structures ────────────────────────────────────────

echo "========================================================================"
echo " Step 2: CMS structure overview (Sig 0)"
echo "========================================================================"
echo
openssl cms -inform DER -in "$WORK/sig0_cms.der" -cmsout -print -noout 2>&1 | head -60
echo "  ..."
echo

# ── Step 3: Extract signer certificate ─────────────────────────────────────

echo "========================================================================"
echo " Step 3: Extract signer certificate"
echo "========================================================================"
echo

# Extract all certs from the CMS
openssl cms -inform DER -in "$WORK/sig0_cms.der" \
    -print_certs -out "$WORK/all_certs.pem" 2>/dev/null || \
    openssl pkcs7 -inform DER -in "$WORK/sig0_cms.der" \
        -print_certs -out "$WORK/all_certs.pem" 2>/dev/null

# Split into individual certs
csplit -z -s -f "$WORK/cert_" -b "%02d.pem" \
    "$WORK/all_certs.pem" '/-----BEGIN CERTIFICATE-----/' '{*}' 2>/dev/null
for f in "$WORK"/cert_*.pem; do
    if [ ! -s "$f" ] || ! grep -q "BEGIN CERTIFICATE" "$f"; then
        rm -f "$f"
    fi
done

# Identify the signer by matching issuer/serial from CMS SignerInfo
# Also detect the digest algorithm used
python3 - "$WORK" <<'PYEOF_SID'
import sys, re, subprocess

work = sys.argv[1]

out = subprocess.check_output(
    ["openssl", "cms", "-inform", "DER", "-in", f"{work}/sig0_cms.der",
     "-cmsout", "-print", "-noout"], stderr=subprocess.STDOUT).decode(errors="replace")

# The serialNumber line from openssl CMS dump is decimal
serial_match = re.search(r'issuerAndSerialNumber.*?serialNumber:\s*(\d+)', out, re.DOTALL)
if serial_match:
    serial_dec = serial_match.group(1).strip()
    print(f"SignerInfo serial (dec): {serial_dec}")
    open(f"{work}/signer_serial.txt", "w").write(serial_dec)
else:
    print("WARNING: Could not extract signer serial from CMS")
    open(f"{work}/signer_serial.txt", "w").write("")

# Detect digest algorithm from digestAlgorithms field
digest_alg = "sha256"  # default fallback
alg_match = re.search(r'digestAlgorithms:.*?algorithm:\s*(\S+)', out, re.DOTALL)
if alg_match:
    alg_name = alg_match.group(1).lower()
    if "sha512" in alg_name:
        digest_alg = "sha512"
    elif "sha384" in alg_name:
        digest_alg = "sha384"
    elif "sha256" in alg_name:
        digest_alg = "sha256"
    elif "sha1" in alg_name:
        digest_alg = "sha1"
    print(f"Digest algorithm: {alg_name} -> {digest_alg}")
open(f"{work}/digest_alg.txt", "w").write(digest_alg)
PYEOF_SID

SIGNER_SERIAL=$(cat "$WORK/signer_serial.txt")
DIGEST_ALG=$(cat "$WORK/digest_alg.txt")

SIGNER_CERT=""
for f in "$WORK"/cert_*.pem; do
    subject=$(openssl x509 -in "$f" -noout -subject 2>/dev/null || true)
    issuer=$(openssl x509 -in "$f" -noout -issuer 2>/dev/null || true)
    serial_hex=$(openssl x509 -in "$f" -noout -serial 2>/dev/null | sed 's/serial=//' || true)
    # Convert cert's hex serial to decimal for comparison with CMS decimal serial
    serial_dec=$(python3 -c "print(int('$serial_hex', 16))" 2>/dev/null || echo "")
    if [ -n "$SIGNER_SERIAL" ] && [ "$serial_dec" = "$SIGNER_SERIAL" ]; then
        SIGNER_CERT="$f"
        echo "Signer certificate found (matched by serial number):"
        echo "  $subject"
        echo "  $issuer"
        echo "  Serial: $serial_hex (dec: $serial_dec)"
        openssl x509 -in "$f" -noout -text 2>/dev/null | \
            grep -E "Public-Key:|Signature Algorithm:" | head -4
        break
    fi
done

# Fallback: if serial matching failed, use the first non-CA (end-entity) cert
if [ -z "$SIGNER_CERT" ]; then
    echo "Serial matching did not find signer; trying end-entity heuristic..."
    for f in "$WORK"/cert_*.pem; do
        is_ca=$(openssl x509 -in "$f" -noout -text 2>/dev/null | grep -c "CA:TRUE" || true)
        if [ "$is_ca" = "0" ]; then
            SIGNER_CERT="$f"
            subject=$(openssl x509 -in "$f" -noout -subject 2>/dev/null || true)
            issuer=$(openssl x509 -in "$f" -noout -issuer 2>/dev/null || true)
            echo "Signer certificate (end-entity heuristic):"
            echo "  $subject"
            echo "  $issuer"
            openssl x509 -in "$f" -noout -text 2>/dev/null | \
                grep -E "Public-Key:|Signature Algorithm:" | head -4
            break
        fi
    done
fi

if [ -z "$SIGNER_CERT" ]; then
    echo "WARNING: Could not identify signer certificate" >&2
    echo "Listing all certificates in the CMS:"
    for f in "$WORK"/cert_*.pem; do
        openssl x509 -in "$f" -noout -subject -issuer 2>/dev/null
        echo
    done
    exit 1
fi

# Extract the public key
openssl x509 -in "$SIGNER_CERT" -noout -pubkey > "$WORK/signer_pubkey.pem"
echo
echo "Public key:"
openssl pkey -pubin -in "$WORK/signer_pubkey.pem" -text -noout 2>/dev/null | head -3
echo

# ── Step 4: Verify messageDigest against PDF content ───────────────────────

echo "========================================================================"
echo " Step 4: Verify messageDigest matches PDF content (Sig 0)"
echo "========================================================================"
echo

COMPUTED_HASH=$(openssl dgst -"$DIGEST_ALG" -hex "$WORK/sig0_signed_data.bin" 2>/dev/null | awk '{print $NF}')
echo "Digest algorithm:                $(echo "$DIGEST_ALG" | tr '[:lower:]' '[:upper:]')"
echo "Hash of signed byte ranges:      $COMPUTED_HASH"

MSG_DIGEST=$(openssl cms -inform DER -in "$WORK/sig0_cms.der" -cmsout -print -noout 2>&1 | \
    grep -A 10 "messageDigest" | grep -A 5 "OCTET STRING" | \
    grep "^ " | sed 's/.*- //; s/  .*//; s/ //g; s/-//g' | tr -d '\n')
echo "messageDigest from CMS:        $MSG_DIGEST"

if [ "$COMPUTED_HASH" = "$MSG_DIGEST" ]; then
    echo
    echo "RESULT: MATCH -- The PDF content hash is correct."
    echo "  The signer hashed the correct byte ranges."
else
    echo
    echo "RESULT: MISMATCH -- The content hash does not match!"
fi
echo

# ── Step 5: RSA crypto verification ───────────────────────────────────────

echo "========================================================================"
echo " Step 5: RSA cryptographic signature verification (Sig 0)"
echo "========================================================================"
echo

# 5a: Full CMS verification
echo "--- 5a: openssl cms -verify (full CMS verification) ---"
echo

# Build a CA bundle from trust/ directory (DER and PEM certs)
TRUST_DIR="$SCRIPT_DIR/trust"
CA_BUNDLE="$WORK/ca_bundle.pem"
: > "$CA_BUNDLE"
if [ -d "$TRUST_DIR" ]; then
    for tf in "$TRUST_DIR"/*.crt "$TRUST_DIR"/*.cer "$TRUST_DIR"/*.pem; do
        [ -f "$tf" ] || continue
        # Try PEM first, fall back to DER conversion
        if grep -q "BEGIN CERTIFICATE" "$tf" 2>/dev/null; then
            cat "$tf" >> "$CA_BUNDLE"
        else
            openssl x509 -inform DER -in "$tf" -outform PEM >> "$CA_BUNDLE" 2>/dev/null || true
        fi
        # Ensure newline separator between certs
        echo "" >> "$CA_BUNDLE"
    done
    echo "Trust store: $TRUST_DIR ($(grep -c 'BEGIN CERTIFICATE' "$CA_BUNDLE") certs loaded)"
else
    echo "Trust store: not found at $TRUST_DIR"
fi
echo

# Also include intermediate certs from the CMS itself
openssl cms -verify \
    -inform DER -in "$WORK/sig0_cms.der" \
    -certfile "$WORK/all_certs.pem" \
    -CAfile "$CA_BUNDLE" \
    -content "$WORK/sig0_signed_data.bin" \
    -purpose any \
    -no_check_time \
    -out /dev/null 2>&1 || true
echo

# 5b: Manual extraction and verification of signed attributes
echo "--- 5b: Manual RSA signature check over signed attributes ---"
echo

python3 - "$WORK" <<'PYEOF2'
import sys

work = sys.argv[1]
cms = open(f"{work}/sig0_cms.der", "rb").read()

def read_tl(data, pos):
    tag = data[pos]
    pos2 = pos + 1
    if data[pos2] < 0x80:
        length = data[pos2]
        content_start = pos2 + 1
    elif data[pos2] == 0x81:
        length = data[pos2 + 1]
        content_start = pos2 + 2
    elif data[pos2] == 0x82:
        length = (data[pos2 + 1] << 8) | data[pos2 + 2]
        content_start = pos2 + 3
    elif data[pos2] == 0x83:
        length = (data[pos2 + 1] << 16) | (data[pos2 + 2] << 8) | data[pos2 + 3]
        content_start = pos2 + 4
    else:
        raise ValueError(f"Unsupported length encoding at {pos}: 0x{data[pos2]:02x}")
    total_len = (content_start - pos) + length
    return tag, content_start, length, total_len

def skip_tlv(data, pos):
    _, _, _, total = read_tl(data, pos)
    return pos + total

# Navigate: ContentInfo -> [0] EXPLICIT -> SignedData
pos = 0
tag, cs, cl, tl = read_tl(cms, pos)
assert tag == 0x30

inner = cs
tag, cs2, cl2, tl2 = read_tl(cms, inner)  # contentType OID
inner += tl2
tag, cs2, cl2, tl2 = read_tl(cms, inner)  # [0] EXPLICIT
assert tag == 0xA0

# SignedData
sd_pos = cs2
tag, sd_cs, sd_cl, sd_tl = read_tl(cms, sd_pos)
assert tag == 0x30

pos = sd_cs
pos = skip_tlv(cms, pos)  # version
pos = skip_tlv(cms, pos)  # digestAlgorithms
pos = skip_tlv(cms, pos)  # encapContentInfo
while cms[pos] in (0xA0, 0xA1):
    pos = skip_tlv(cms, pos)

# signerInfos SET OF
tag, si_set_cs, _, _ = read_tl(cms, pos)
assert tag == 0x31

# SignerInfo SEQUENCE
tag, si_cs, _, _ = read_tl(cms, si_set_cs)
assert tag == 0x30

pos = si_cs
pos = skip_tlv(cms, pos)  # version
pos = skip_tlv(cms, pos)  # sid
pos = skip_tlv(cms, pos)  # digestAlgorithm

# signedAttrs [0] IMPLICIT
tag, sa_cs, sa_cl, sa_tl = read_tl(cms, pos)
assert tag == 0xA0

signed_attrs_raw = cms[pos:pos + sa_tl]
signed_attrs_for_verify = bytearray(signed_attrs_raw)
signed_attrs_for_verify[0] = 0x31  # RFC 5652 section 5.4
open(f"{work}/sig0_signed_attrs.der", "wb").write(bytes(signed_attrs_for_verify))
print(f"Signed attributes: {len(signed_attrs_for_verify)} bytes (tag 0xA0 -> 0x31)")

pos += sa_tl

# signatureAlgorithm
tag, _, _, alg_tl = read_tl(cms, pos)
alg_bytes = cms[pos:pos + alg_tl]
pos += alg_tl

# signature OCTET STRING
tag, sig_cs, sig_cl, sig_tl = read_tl(cms, pos)
assert tag == 0x04
rsa_sig = cms[sig_cs:sig_cs + sig_cl]
open(f"{work}/sig0_rsa_signature.bin", "wb").write(rsa_sig)
print(f"RSA signature:     {len(rsa_sig)} bytes ({len(rsa_sig)*8}-bit)")

# Decode signatureAlgorithm OID
tag2, oid_outer_cs, _, _ = read_tl(alg_bytes, 0)
tag3, oid_cs, oid_cl, _ = read_tl(alg_bytes, oid_outer_cs)
oid_bytes = alg_bytes[oid_cs:oid_cs + oid_cl]
vals = [str(oid_bytes[0] // 40), str(oid_bytes[0] % 40)]
val = 0
for b in oid_bytes[1:]:
    val = (val << 7) | (b & 0x7F)
    if not (b & 0x80):
        vals.append(str(val))
        val = 0
oid_str = ".".join(vals)
names = {
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption (PKCS#1 v1.5)",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
}
name = names.get(oid_str, "(unknown)")
print(f"Signature algorithm: {oid_str} = {name}")
PYEOF2

echo
echo "Verifying RSA signature over signed attributes with openssl ($DIGEST_ALG):"
echo
openssl dgst -"$DIGEST_ALG" \
    -verify "$WORK/signer_pubkey.pem" \
    -signature "$WORK/sig0_rsa_signature.bin" \
    "$WORK/sig0_signed_attrs.der" 2>&1 || true
echo

# ── Step 6: Summary ───────────────────────────────────────────────────────

echo "========================================================================"
echo " Step 6: Summary"
echo "========================================================================"
echo

# Determine messageDigest result
if [ "$COMPUTED_HASH" = "$MSG_DIGEST" ]; then
    DIGEST_RESULT="CORRECT ($(echo "$DIGEST_ALG" | tr '[:lower:]' '[:upper:]') matches)"
else
    DIGEST_RESULT="MISMATCH"
fi

# Determine RSA verification result
RSA_RESULT=$(openssl dgst -"$DIGEST_ALG" \
    -verify "$WORK/signer_pubkey.pem" \
    -signature "$WORK/sig0_rsa_signature.bin" \
    "$WORK/sig0_signed_attrs.der" 2>&1 || true)

SIGNER_SUBJECT=$(openssl x509 -in "$SIGNER_CERT" -noout -subject 2>/dev/null | sed 's/^subject=//')

echo "Signer: $SIGNER_SUBJECT"
echo
echo "Sig 0 (adbe.pkcs7.detached):"
echo "  - PDF content hash (messageDigest):  $DIGEST_RESULT"

if echo "$RSA_RESULT" | grep -qi "verified ok"; then
    echo "  - Signature over signed attrs:       VALID"
else
    echo "  - Signature over signed attrs:       INVALID"
    echo
    echo "Possible causes for the invalid signature:"
    echo "  1. Wrong private key was used during signing"
    echo "  2. CMS blob was corrupted or truncated after signing"
    echo "  3. Bug in the signing software produced an invalid signature"
fi
echo

echo "========================================================================"
echo " Intermediate files"
echo "========================================================================"
ls -la "$WORK"/
echo
echo "Done."
