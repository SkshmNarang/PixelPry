#!/usr/bin/env python3
"""
PixelPry.py - Heuristic Image Steganography Analysis & Extraction Tool

Performs format identification via magic bytes, spatial-domain LSB extraction
for uncompressed/lossless formats (PNG, BMP), transform-domain DCT coefficient
analysis for JPEG images, and Steghide payload extraction.

Supports both plain text and binary payloads (WAV, ZIP, PNG, JSON, PEM, etc.)
with Windows console safety and byte-for-byte reference verification.
"""

import sys
import os
import string
import json
import zipfile
import wave
from PIL import Image
import numpy as np

# SciPy is required for DCT calculations on JPEG images
try:
    from scipy.fftpack import dct
except ImportError:
    dct = None


def identify_format(file_path):
    """
    STEP 1 — Identify the image format.
    Reads magic bytes from the start of the file to determine whether
    the image is PNG, JPEG, or BMP. Falls back to Pillow if unrecognized.

    Args:
        file_path (str): Path to image file.

    Returns:
        str: Format name ('PNG', 'JPEG', 'BMP', or other recognized Pillow format),
             or None if the file cannot be recognized.
    """
    try:
        with open(file_path, "rb") as f:
            header = f.read(16)
    except Exception as e:
        print(f"[-] Error opening file: {e}")
        return None

    # Check known magic byte signatures
    # PNG signature: \x89PNG\r\n\x1a\n (8 bytes)
    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG"

    # JPEG signature: starts with \xff\xd8\xff (SOI + marker prefix)
    if header.startswith(b"\xff\xd8\xff"):
        return "JPEG"

    # BMP signature: starts with ASCII "BM"
    if header.startswith(b"BM"):
        return "BMP"

    # Fallback: Attempt detection with Pillow
    try:
        with Image.open(file_path) as img:
            return img.format
    except Exception:
        return None


def analyze_payload(raw_bytes):
    """
    Intelligently inspects raw payload bytes to determine exact format:
    Text (JSON, XML, CSV, Python, PEM, ASCII) or Binary (WAV, ZIP, PNG, ELF, etc.).

    Args:
        raw_bytes (bytes): Extracted raw payload bytes.

    Returns:
        dict: {
            "type": str,
            "ext": str,
            "preview": str,
            "is_text": bool,
            "metadata": str
        }
    """
    if not raw_bytes:
        return {
            "type": "Empty",
            "ext": ".bin",
            "preview": "Empty payload (0 bytes)",
            "is_text": False,
            "metadata": ""
        }

    length = len(raw_bytes)

    # 1. ZIP Archive (magic: PK\x03\x04)
    if raw_bytes.startswith(b"PK\x03\x04"):
        try:
            import io
            with zipfile.ZipFile(io.BytesIO(raw_bytes)) as zf:
                file_list = zf.namelist()
                preview = f"[ZIP Archive] Contains {len(file_list)} file(s): " + ", ".join(file_list[:5])
                return {
                    "type": "ZIP Archive",
                    "ext": ".zip",
                    "preview": preview,
                    "is_text": False,
                    "metadata": f"Files: {file_list}"
                }
        except Exception:
            return {
                "type": "ZIP Archive",
                "ext": ".zip",
                "preview": f"[ZIP Archive Header] Size: {length} bytes",
                "is_text": False,
                "metadata": ""
            }

    # 2. WAV Audio (magic: RIFF....WAVE)
    if raw_bytes.startswith(b"RIFF") and len(raw_bytes) >= 12 and raw_bytes[8:12] == b"WAVE":
        try:
            import io
            with wave.open(io.BytesIO(raw_bytes), "rb") as wf:
                ch = wf.getnchannels()
                rate = wf.getframerate()
                frames = wf.getnframes()
                duration = frames / float(rate) if rate > 0 else 0
                preview = f"[WAV Audio] {ch}-channel, {rate} Hz, {wf.getsampwidth()*8}-bit PCM (duration: {duration:.2f}s)"
                return {
                    "type": "WAV Audio",
                    "ext": ".wav",
                    "preview": preview,
                    "is_text": False,
                    "metadata": f"{ch}ch, {rate}Hz, {length} bytes"
                }
        except Exception:
            return {
                "type": "WAV Audio",
                "ext": ".wav",
                "preview": f"[WAV Audio Stream] Size: {length} bytes",
                "is_text": False,
                "metadata": ""
            }

    # 3. PNG Image (magic: \x89PNG\r\n\x1a\n)
    if raw_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        try:
            import io
            with Image.open(io.BytesIO(raw_bytes)) as im:
                preview = f"[PNG Image] Resolution: {im.size[0]}x{im.size[1]} pixels, Mode: {im.mode}"
                return {
                    "type": "PNG Image",
                    "ext": ".png",
                    "preview": preview,
                    "is_text": False,
                    "metadata": f"{im.size}, {im.mode}"
                }
        except Exception:
            return {
                "type": "PNG Image",
                "ext": ".png",
                "preview": f"[PNG Image Stream] Size: {length} bytes",
                "is_text": False,
                "metadata": ""
            }

    # 4. ELF Executable / Shellcode (magic: \x7fELF)
    if raw_bytes.startswith(b"\x7fELF"):
        preview = f"[ELF Binary / Shellcode] Size: {length} bytes | Hex: {raw_bytes[:32].hex()}..."
        return {
            "type": "ELF Binary/Shellcode",
            "ext": ".bin",
            "preview": preview,
            "is_text": False,
            "metadata": "ELF Header"
        }

    # 5. Check if valid UTF-8 / ASCII text
    try:
        decoded = raw_bytes.decode("utf-8")
        printable_count = sum(1 for c in decoded if c in string.printable)
        ratio = printable_count / len(decoded) if decoded else 0
        if ratio >= 0.80:
            stripped = decoded.strip()

            # Sub-type: JSON Data
            if (stripped.startswith("{") and stripped.endswith("}")) or (stripped.startswith("[") and stripped.endswith("]")):
                try:
                    parsed = json.loads(stripped)
                    preview = json.dumps(parsed, indent=2)[:300]
                    return {
                        "type": "JSON Data",
                        "ext": ".json",
                        "preview": preview,
                        "is_text": True,
                        "metadata": "Valid JSON"
                    }
                except Exception:
                    pass

            # Sub-type: PEM Key / Certificate
            if "-----BEGIN " in stripped:
                preview = stripped[:300]
                return {
                    "type": "Cryptographic Key (PEM)",
                    "ext": ".pem",
                    "preview": preview,
                    "is_text": True,
                    "metadata": "PEM Key"
                }

            # Sub-type: XML Document
            if stripped.startswith("<?xml") or (stripped.startswith("<") and stripped.endswith(">")):
                preview = stripped[:300]
                return {
                    "type": "XML Document",
                    "ext": ".xml",
                    "preview": preview,
                    "is_text": True,
                    "metadata": "XML Document"
                }

            # Sub-type: Python Script
            if (stripped.startswith("#!/") and "python" in stripped) or ("import " in stripped and "def " in stripped):
                preview = stripped[:300]
                return {
                    "type": "Python Script",
                    "ext": ".py",
                    "preview": preview,
                    "is_text": True,
                    "metadata": "Python Source Code"
                }

            # Sub-type: CSV Spreadsheet
            lines = [l for l in stripped.splitlines() if l.strip()]
            if len(lines) >= 2 and all("," in l for l in lines[:5]):
                preview = stripped[:300]
                return {
                    "type": "CSV Spreadsheet",
                    "ext": ".csv",
                    "preview": preview,
                    "is_text": True,
                    "metadata": f"{len(lines)} rows"
                }

            # Sub-type: General Plain Text
            preview = stripped[:300]
            return {
                "type": "Plain Text",
                "ext": ".txt",
                "preview": preview,
                "is_text": True,
                "metadata": f"{len(stripped)} chars"
            }
    except UnicodeDecodeError:
        pass

    # 6. Fallback: Raw Binary Stream
    preview = f"[Binary Payload] Size: {length} bytes | Hex: {raw_bytes[:32].hex()}..."
    return {
        "type": "Raw Binary",
        "ext": ".bin",
        "preview": preview,
        "is_text": False,
        "metadata": f"{length} bytes"
    }


def _find_printable_runs(byte_data, min_length=24):
    """
    Helper function to inspect byte data for printable ASCII strings.
    Requires minimum length and letter frequency to filter out false-positive
    noise runs from encrypted/random data.

    Args:
        byte_data (bytes): Extracted byte buffer.
        min_length (int): Minimum continuous printable characters to qualify.

    Returns:
        tuple (bool, str): (is_plausible, preview_text)
    """
    printable_set = set(bytes(string.printable, "ascii"))
    current = []
    runs = []

    for b in byte_data[:100000]:  # Limit scan range to avoid excessive overhead
        if b == 0:
            if len(current) >= min_length:
                text = bytes(current).decode("ascii", errors="replace")
                runs.append(text)
            current = []
            continue

        if b in printable_set:
            current.append(b)
        else:
            if len(current) >= min_length:
                text = bytes(current).decode("ascii", errors="replace")
                runs.append(text)
            current = []

    if len(current) >= min_length:
        runs.append(bytes(current).decode("ascii", errors="replace"))

    # Strict letter frequency filter to eliminate ciphertext/compression noise
    valid_runs = []
    for r in runs:
        letters = sum(1 for c in r if c.isalpha())
        if letters / len(r) >= 0.50:
            valid_runs.append(r)

    if valid_runs:
        combined = "\n".join(valid_runs[:5])
        safe_preview = "".join(c if (32 <= ord(c) <= 126 or c in "\n\r\t") else "." for c in combined)
        preview = safe_preview[:300] + ("..." if len(safe_preview) > 300 else "")
        return True, preview

    return False, ""


def extract_lsb(image_path):
    """
    STEP 2 — Attempt LSB (Least Significant Bit) extraction.
    Applies to spatial-domain formats (PNG, BMP) where pixels are stored directly.

    Evaluates:
      a) Big-endian 32-bit length header convention (supports text & binary formats).
      b) Direct byte stream with NUL-terminators or printable ASCII runs.

    Args:
        image_path (str): Path to image file.

    Returns:
        dict: Analysis results with status, convention details, preview, and raw bytes.
    """
    result = {
        "applicable": True,
        "payload_found": False,
        "convention": "Spatial LSB (Bitstream sequential extraction)",
        "preview": "",
        "raw_bytes": None,
        "payload_info": None
    }

    try:
        with Image.open(image_path) as img:
            mode = "RGBA" if img.mode in ("RGBA", "LA", "PA") else "RGB"
            img_converted = img.convert(mode)
            pixels = np.array(img_converted, dtype=np.uint8)

        # Flatten channel values into a 1D array
        channels = pixels.flatten()

        # Extract the least significant bit from each channel value
        bits = channels & 1

        # Pack the bitstream into bytes (8 bits per byte)
        raw_bytes = np.packbits(bits).tobytes()

        # -------------------------------------------------------------
        # Convention (a): Big-endian 32-bit length header
        # -------------------------------------------------------------
        if len(raw_bytes) >= 4:
            header_len = int.from_bytes(raw_bytes[:4], byteorder="big")
            remaining_bytes = len(raw_bytes) - 4

            if 1 <= header_len <= min(remaining_bytes, 10000000):
                payload = raw_bytes[4 : 4 + header_len]
                info = analyze_payload(payload)

                result["payload_found"] = True
                result["raw_bytes"] = payload
                result["payload_info"] = info
                result["convention"] = f"32-bit big-endian length header ({header_len} bytes, {info['type']})"
                result["preview"] = info["preview"]
                return result

        # -------------------------------------------------------------
        # Convention (b): Raw byte stream scan for printable text runs / NUL terminator
        # -------------------------------------------------------------
        found, preview = _find_printable_runs(raw_bytes, min_length=24)
        if found:
            result["payload_found"] = True
            result["convention"] = "Direct bitstream sequential bytes (ASCII run / NUL-delimited)"
            result["preview"] = preview
            return result

        # If neither convention found coherent payload
        result["payload_found"] = False
        result["preview"] = "No coherent printable ASCII run or valid length header detected."
        return result

    except Exception as e:
        result["preview"] = f"Extraction failed with error: {e}"
        result["payload_found"] = False
        return result


def extract_dct(image_path):
    """
    STEP 3 — Attempt DCT (Discrete Cosine Transform) extraction.
    Applies to JPEG images where frequency-domain coefficients represent 8x8 blocks.

    Reconstructs 8x8 2D-DCT blocks from decoded grayscale pixels, samples
    mid-frequency AC coefficients (skipping DC and zero-valued coefficients),
    and packs coefficient LSBs into a bitstream.

    Args:
        image_path (str): Path to JPEG image file.

    Returns:
        dict: Analysis results with status, convention details, and preview.
    """
    result = {
        "applicable": True,
        "payload_found": False,
        "convention": "2D-DCT mid-frequency AC coefficient LSBs (jsteg approximation)",
        "preview": ""
    }

    if dct is None:
        result["preview"] = "SciPy library is not installed (required for DCT analysis)."
        result["payload_found"] = False
        return result

    try:
        with Image.open(image_path) as img:
            gray = img.convert("L")
            img_arr = np.array(gray, dtype=np.float32)

        height, width = img_arr.shape
        h_blocks = height // 8
        w_blocks = width // 8

        if h_blocks == 0 or w_blocks == 0:
            result["preview"] = "Image too small for 8x8 DCT block analysis."
            return result

        mid_freq_indices = [
            (0, 1), (1, 0), (2, 0), (1, 1), (0, 2),
            (0, 3), (1, 2), (2, 1), (3, 0), (4, 0),
            (3, 1), (2, 2), (1, 3), (0, 4), (1, 4),
            (2, 3), (3, 2), (4, 1), (5, 0), (4, 2)
        ]

        extracted_bits = []

        for r in range(h_blocks):
            for c in range(w_blocks):
                block = img_arr[r * 8 : (r + 1) * 8, c * 8 : (c + 1) * 8]
                dct_block = dct(dct(block, axis=0, norm="ortho"), axis=1, norm="ortho")

                for row_idx, col_idx in mid_freq_indices:
                    coeff = dct_block[row_idx, col_idx]
                    quantized_val = int(np.round(coeff))

                    if quantized_val == 0:
                        continue
                    extracted_bits.append(quantized_val & 1)

        if not extracted_bits:
            result["preview"] = "No non-zero mid-frequency AC coefficients found."
            return result

        bit_arr = np.array(extracted_bits, dtype=np.uint8)
        raw_bytes = np.packbits(bit_arr).tobytes()

        # Check for printable text runs / NUL-terminators using strict filter
        found, preview = _find_printable_runs(raw_bytes, min_length=24)
        if found:
            result["payload_found"] = True
            result["preview"] = preview
        else:
            result["payload_found"] = False
            result["preview"] = "No coherent printable ASCII run detected in sampled DCT coefficients."

        return result

    except Exception as e:
        result["preview"] = f"DCT extraction failed with error: {e}"
        result["payload_found"] = False
        return result


def extract_steghide(image_path, passphrase=""):
    """
    Attempt Steghide payload extraction.
    Applies to JPEG and BMP files where Steghide graph-theoretic matching
    and Rijndael/zlib compression are used.
    """
    import subprocess
    import tempfile

    result = {
        "applicable": True,
        "payload_found": False,
        "convention": "Steghide (Rijndael-128 CBC + zlib + graph matching)",
        "preview": "",
        "raw_bytes": None,
        "payload_info": None
    }

    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp:
        tmp_name = tmp.name

    try:
        cmd = ["steghide", "extract", "-sf", image_path, "-p", passphrase, "-xf", tmp_name, "-f"]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode == 0 and os.path.exists(tmp_name) and os.path.getsize(tmp_name) > 0:
            with open(tmp_name, "rb") as f:
                raw_bytes = f.read()

            info = analyze_payload(raw_bytes)
            result["payload_found"] = True
            result["raw_bytes"] = raw_bytes
            result["payload_info"] = info
            result["convention"] = f"Steghide (Rijndael-128, {len(raw_bytes)} bytes, {info['type']})"
            result["preview"] = info["preview"]
        else:
            result["preview"] = "No Steghide payload detected or incorrect passphrase."
    except FileNotFoundError:
        result["applicable"] = False
        result["preview"] = "Steghide binary not found on PATH."
    except Exception as e:
        result["preview"] = f"Steghide extraction failed: {e}"
    finally:
        if os.path.exists(tmp_name):
            try:
                os.remove(tmp_name)
            except OSError:
                pass

    return result


def print_report(image_path, format_name, lsb_result, dct_result, steghide_result=None, verify_file=None, output_dir=None):
    """
    STEP 4 — Report results.
    Prints a formatted summary displaying format detection, applicability,
    payload status, text preview, and forensic caveats.
    """
    separator = "=" * 70
    sub_sep = "-" * 70

    print("\n" + separator)
    print(" STEGANOGRAPHY ANALYSIS REPORT")
    print(separator)
    print(f" Target File     : {image_path}")
    print(f" Detected Format : {format_name}")
    print(separator)

    # 1. Spatial Domain (LSB) Report
    print("\n[Method 1: Spatial Domain LSB Extraction]")
    print(sub_sep)
    print(f" Applicable       : {'Yes (Spatial/Lossless image)' if lsb_result['applicable'] else 'No (Skipped for lossy format)'}")
    print(f" Convention Used  : {lsb_result['convention']}")
    print(f" Payload Found    : {'[+] LIKELY' if lsb_result['payload_found'] else '[-] None detected'}")
    if lsb_result["preview"]:
        # Safe printing to avoid Windows cp1252 charmap encoding crash
        safe_preview = "".join(c if (32 <= ord(c) <= 126 or c in "\n\r\t") else "." for c in lsb_result["preview"])
        print(f" Preview / Details:\n{safe_preview}")

    # 2. Transform Domain (DCT) Report
    print("\n[Method 2: Transform Domain DCT Extraction]")
    print(sub_sep)
    print(f" Applicable       : {'Yes (JPEG compressed format)' if dct_result['applicable'] else 'No (Skipped for spatial format)'}")
    print(f" Convention Used  : {dct_result['convention']}")
    print(f" Payload Found    : {'[+] LIKELY' if dct_result['payload_found'] else '[-] None detected'}")
    if dct_result["preview"]:
        safe_preview = "".join(c if (32 <= ord(c) <= 126 or c in "\n\r\t") else "." for c in dct_result["preview"])
        print(f" Preview / Details:\n{safe_preview}")

    # 3. Steghide Method Report (if applicable)
    if steghide_result:
        print("\n[Method 3: Steghide Extraction (Encrypted & Compressed Payloads)]")
        print(sub_sep)
        print(f" Applicable       : {'Yes (JPEG / BMP supported)' if steghide_result['applicable'] else 'No'}")
        print(f" Convention Used  : {steghide_result['convention']}")
        print(f" Payload Found    : {'[+] LIKELY' if steghide_result['payload_found'] else '[-] None detected'}")
        if steghide_result["preview"]:
            safe_preview = "".join(c if (32 <= ord(c) <= 126 or c in "\n\r\t") else "." for c in steghide_result["preview"])
            print(f" Preview / Details:\n{safe_preview}")

    # Determine extracted payload bytes if any found
    extracted_payload_bytes = None
    payload_info = None
    if steghide_result and steghide_result.get("raw_bytes"):
        extracted_payload_bytes = steghide_result["raw_bytes"]
        payload_info = steghide_result.get("payload_info")
    elif lsb_result and lsb_result.get("raw_bytes"):
        extracted_payload_bytes = lsb_result["raw_bytes"]
        payload_info = lsb_result.get("payload_info")

    # Optional file export
    if extracted_payload_bytes and output_dir:
        os.makedirs(output_dir, exist_ok=True)
        base = os.path.splitext(os.path.basename(image_path))[0]
        ext = payload_info["ext"] if payload_info else ".bin"
        save_path = os.path.join(output_dir, f"{base}_extracted{ext}")
        with open(save_path, "wb") as f:
            f.write(extracted_payload_bytes)
        print(f"\n[+] Extracted payload saved to: {save_path}")

    # 4. Verification Check
    if verify_file and os.path.isfile(verify_file):
        print("\n" + sub_sep)
        print(f" VERIFICATION AGAINST: {verify_file}")
        print(sub_sep)
        with open(verify_file, "rb") as vf:
            expected_bytes = vf.read()

        if extracted_payload_bytes == expected_bytes:
            print(" [+] VERIFICATION STATUS: EXACT MATCH (100% byte identical)")
            print(f"     Payload Size: {len(extracted_payload_bytes)} bytes | Detected Type: {payload_info['type'] if payload_info else 'Unknown'}")
        elif extracted_payload_bytes and expected_bytes in extracted_payload_bytes:
            print(" [+] VERIFICATION STATUS: SUBSTRING MATCH")
        else:
            print(" [-] VERIFICATION STATUS: MISMATCH")

    # 5. Caveats & Heuristic Disclaimer
    print("\n" + separator)
    print(" CAVEATS & FORENSIC NOTES")
    print(separator)
    print(" * Heuristic Results Only: A 'None detected' verdict does not prove the")
    print("   image is devoid of steganographic data. Encrypted payloads, non-sequential")
    print("   pixel orderings, custom PRNG steganography, or alternate channels cannot")
    print("   be identified by simple sequential ASCII scans.")
    print(" * Verification Required: A 'LIKELY' payload should always be manually")
    print("   verified, as uncompressed high-entropy visual noise or compressed artifacts")
    print("   can occasionally mimic printable character distributions.")
    print(" * DCT Approximation: DCT analysis reconstructs coefficients from decoded")
    print("   pixels rather than reading the original quantized bitstream tables,")
    print("   serving as an approximation for standard frequency-domain modifications.")
    print(separator + "\n")


def main():
    """
    Main entry point for command-line execution.
    """
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print("PixelPry - Heuristic Image Steganography Analysis & Extraction Tool")
        print(f"Usage: python {os.path.basename(sys.argv[0])} <image_file_path> [--verify <reference_file>] [--save <output_dir>]")
        sys.exit(0 if len(sys.argv) >= 2 and sys.argv[1] in ("-h", "--help") else 1)

    image_path = sys.argv[1]

    # Parse optional CLI flags
    verify_file = None
    output_dir = None

    args = sys.argv[2:]
    idx = 0
    while idx < len(args):
        if args[idx] == "--verify" and idx + 1 < len(args):
            verify_file = args[idx + 1]
            idx += 2
        elif args[idx] == "--save" and idx + 1 < len(args):
            output_dir = args[idx + 1]
            idx += 2
        else:
            idx += 1

    # Verify target file existence
    if not os.path.isfile(image_path):
        print(f"[-] Error: File not found: '{image_path}'")
        sys.exit(1)

    # STEP 1: Identify image format via magic bytes
    format_name = identify_format(image_path)
    if not format_name:
        print(f"[-] Error: Unrecognized or corrupted image file: '{image_path}'")
        sys.exit(1)

    # Initialize results
    lsb_result = {
        "applicable": False,
        "payload_found": False,
        "convention": "N/A",
        "preview": "Not applicable to this image format."
    }
    dct_result = {
        "applicable": False,
        "payload_found": False,
        "convention": "N/A",
        "preview": "Not applicable to this image format."
    }
    steghide_result = None

    # STEP 2: Spatial LSB extraction (applies to PNG, BMP, and spatial formats)
    if format_name in ("PNG", "BMP"):
        lsb_result = extract_lsb(image_path)

    # STEP 3: Transform DCT extraction (applies to JPEG format)
    if format_name in ("JPEG", "JPG"):
        dct_result = extract_dct(image_path)

    # STEP 3b: Steghide extraction (for JPEG & BMP)
    if format_name in ("JPEG", "JPG", "BMP"):
        steghide_result = extract_steghide(image_path, passphrase="")

    # STEP 4: Print the structured report
    print_report(image_path, format_name, lsb_result, dct_result, steghide_result, verify_file, output_dir)


if __name__ == "__main__":
    main()
