#!/usr/bin/env python3
"""
PixelPry.py - Multi-Format Steganography Forensic Analysis & Payload Extraction Suite

Performs deep forensic inspection of digital images to detect, carve, and extract
ALL types of hidden data, including:
  1. Binary File Payloads (ZIP, PNG, JPEG, BMP, GIF, WAV, MP3, PDF, ELF, EXE, GZIP, 7z, SQLite, etc.)
  2. Multi-Channel Spatial LSB (RGB, RGBA, BGR, Red-only, Green-only, Blue-only, Alpha-only)
  3. Visual Bit-Plane Steganography (1-bit / 2-bit visual watermarks & hidden images)
  4. Appended File Overlay Data (Data concatenated after PNG IEND, JPEG EOI, BMP EOF)
  5. Palette & Color-as-Text Steganography (Indexed RGB translations)
  6. Container Metadata & Chunk Anomalies (PNG custom/corrupt chunks, IHDR CRC tampering, EXIF)
  7. Transform-Domain DCT Analysis (JPEG 8x8 frequency coefficient AC LSBs)
  8. Steghide Integration (Encrypted Rijndael-128 / zlib extraction for JPEG/BMP)
"""

import sys
import os
import string
import struct
import json
import zipfile
import wave
import zlib
from collections import Counter
from PIL import Image
import numpy as np

# SciPy is required for DCT calculations on JPEG images
try:
    from scipy.fftpack import dct
except ImportError:
    dct = None


# =====================================================================
# STEP 1: FORMAT IDENTIFICATION & CONTAINER PARSING
# =====================================================================

def identify_format(file_path):
    """
    Reads raw magic bytes to identify true file format.
    """
    try:
        with open(file_path, "rb") as f:
            header = f.read(16)
    except Exception as e:
        print(f"[-] Error opening file: {e}")
        return None

    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG"
    if header.startswith(b"\xff\xd8\xff"):
        return "JPEG"
    if header.startswith(b"BM"):
        return "BMP"
    if header.startswith(b"GIF87a") or header.startswith(b"GIF89a"):
        return "GIF"
    if header.startswith(b"RIFF") and len(header) >= 12 and header[8:12] == b"WEBP":
        return "WEBP"

    try:
        with Image.open(file_path) as img:
            return img.format
    except Exception:
        return None


# =====================================================================
# STEP 2: PAYLOAD TYPE IDENTIFICATION & FILE CARVING
# =====================================================================

def get_container_size(raw_bytes, file_type):
    """
    Calculates exact byte length of embedded container files from headers.
    """
    try:
        # PNG Image
        if file_type == "PNG" and raw_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
            idx = 8
            while idx + 8 <= len(raw_bytes):
                length = struct.unpack(">I", raw_bytes[idx:idx+4])[0]
                ctype = raw_bytes[idx+4:idx+8]
                idx += 12 + length
                if ctype == b"IEND":
                    return min(idx, len(raw_bytes))
            return len(raw_bytes)

        # WAV / RIFF Audio
        if file_type == "WAV" and raw_bytes.startswith(b"RIFF") and len(raw_bytes) >= 8:
            riff_len = struct.unpack("<I", raw_bytes[4:8])[0] + 8
            return min(riff_len, len(raw_bytes))

        # BMP Image
        if file_type == "BMP" and raw_bytes.startswith(b"BM") and len(raw_bytes) >= 6:
            bmp_len = struct.unpack("<I", raw_bytes[2:6])[0]
            return min(bmp_len, len(raw_bytes))

        # ZIP Archive (Look for End of Central Directory record b'PK\x05\x06')
        if file_type == "ZIP" and raw_bytes.startswith(b"PK\x03\x04"):
            eocd_pos = raw_bytes.rfind(b"PK\x05\x06")
            if eocd_pos != -1 and eocd_pos + 22 <= len(raw_bytes):
                comment_len = struct.unpack("<H", raw_bytes[eocd_pos+20:eocd_pos+22])[0]
                return min(eocd_pos + 22 + comment_len, len(raw_bytes))

        # PDF Document (Look for %%EOF)
        if file_type == "PDF" and raw_bytes.startswith(b"%PDF"):
            eof_pos = raw_bytes.rfind(b"%%EOF")
            if eof_pos != -1:
                return min(eof_pos + 5, len(raw_bytes))

        # JPEG Image (Look for \xff\xd9)
        if file_type == "JPEG" and raw_bytes.startswith(b"\xff\xd8"):
            eoi_pos = raw_bytes.rfind(b"\xff\xd9")
            if eoi_pos != -1:
                return min(eoi_pos + 2, len(raw_bytes))

    except Exception:
        pass
    return len(raw_bytes)


def analyze_payload(raw_bytes):
    """
    Identifies exact format of raw bytes:
    Binary (ZIP, WAV, PNG, JPEG, BMP, GIF, PDF, ELF, EXE, GZIP, 7z, SQLite, etc.)
    or Text (JSON, XML, CSV, Python, PEM, ASCII, CTF Flags).
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

    # 1. ZIP Archive (PK\x03\x04)
    if raw_bytes.startswith(b"PK\x03\x04"):
        actual_len = get_container_size(raw_bytes, "ZIP")
        try:
            import io
            with zipfile.ZipFile(io.BytesIO(raw_bytes[:actual_len])) as zf:
                file_list = zf.namelist()
                preview = f"[ZIP Archive] Size: {actual_len} bytes | Files ({len(file_list)}): " + ", ".join(file_list[:5])
                return {
                    "type": "ZIP Archive",
                    "ext": ".zip",
                    "preview": preview,
                    "is_text": False,
                    "metadata": f"Contains {len(file_list)} file(s)",
                    "exact_length": actual_len
                }
        except Exception:
            return {
                "type": "ZIP Archive",
                "ext": ".zip",
                "preview": f"[ZIP Archive] Size: {actual_len} bytes",
                "is_text": False,
                "metadata": "ZIP container",
                "exact_length": actual_len
            }

    # 2. WAV Audio (RIFF....WAVE)
    if raw_bytes.startswith(b"RIFF") and len(raw_bytes) >= 12 and raw_bytes[8:12] == b"WAVE":
        actual_len = get_container_size(raw_bytes, "WAV")
        try:
            import io
            with wave.open(io.BytesIO(raw_bytes[:actual_len]), "rb") as wf:
                ch = wf.getnchannels()
                rate = wf.getframerate()
                duration = wf.getnframes() / float(rate) if rate > 0 else 0
                preview = f"[WAV Audio] Size: {actual_len} bytes | {ch}-channel, {rate} Hz (duration: {duration:.2f}s)"
                return {
                    "type": "WAV Audio",
                    "ext": ".wav",
                    "preview": preview,
                    "is_text": False,
                    "metadata": f"{ch}ch, {rate}Hz, {duration:.2f}s",
                    "exact_length": actual_len
                }
        except Exception:
            return {
                "type": "WAV Audio",
                "ext": ".wav",
                "preview": f"[WAV Audio Stream] Size: {actual_len} bytes",
                "is_text": False,
                "metadata": "PCM Audio",
                "exact_length": actual_len
            }

    # 3. PNG Image (\x89PNG\r\n\x1a\n)
    if raw_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        actual_len = get_container_size(raw_bytes, "PNG")
        try:
            import io
            with Image.open(io.BytesIO(raw_bytes[:actual_len])) as im:
                preview = f"[PNG Image] Size: {actual_len} bytes | Resolution: {im.size[0]}x{im.size[1]}, Mode: {im.mode}"
                return {
                    "type": "PNG Image",
                    "ext": ".png",
                    "preview": preview,
                    "is_text": False,
                    "metadata": f"{im.size}, {im.mode}",
                    "exact_length": actual_len
                }
        except Exception:
            return {
                "type": "PNG Image",
                "ext": ".png",
                "preview": f"[PNG Image Stream] Size: {actual_len} bytes",
                "is_text": False,
                "metadata": "PNG image",
                "exact_length": actual_len
            }

    # 4. JPEG Image (\xff\xd8\xff)
    if raw_bytes.startswith(b"\xff\xd8\xff"):
        actual_len = get_container_size(raw_bytes, "JPEG")
        preview = f"[JPEG Image] Size: {actual_len} bytes"
        return {
            "type": "JPEG Image",
            "ext": ".jpg",
            "preview": preview,
            "is_text": False,
            "metadata": "JPEG container",
            "exact_length": actual_len
        }

    # 5. BMP Image (BM)
    if raw_bytes.startswith(b"BM") and len(raw_bytes) >= 14:
        actual_len = get_container_size(raw_bytes, "BMP")
        preview = f"[BMP Image] Size: {actual_len} bytes"
        return {
            "type": "BMP Image",
            "ext": ".bmp",
            "preview": preview,
            "is_text": False,
            "metadata": "BMP bitmap",
            "exact_length": actual_len
        }

    # 6. GIF Image (GIF87a / GIF89a)
    if raw_bytes.startswith(b"GIF87a") or raw_bytes.startswith(b"GIF89a"):
        preview = f"[GIF Image] Size: {length} bytes"
        return {
            "type": "GIF Image",
            "ext": ".gif",
            "preview": preview,
            "is_text": False,
            "metadata": "GIF animation/image"
        }

    # 7. PDF Document (%PDF)
    if raw_bytes.startswith(b"%PDF"):
        actual_len = get_container_size(raw_bytes, "PDF")
        preview = f"[PDF Document] Size: {actual_len} bytes"
        return {
            "type": "PDF Document",
            "ext": ".pdf",
            "preview": preview,
            "is_text": False,
            "metadata": "Portable Document Format",
            "exact_length": actual_len
        }

    # 8. 7-Zip Archive (7z\xbc\xaf\x27\x1c)
    if raw_bytes.startswith(b"7z\xbc\xaf\x27\x1c"):
        preview = f"[7-Zip Archive] Size: {length} bytes"
        return {
            "type": "7-Zip Archive",
            "ext": ".7z",
            "preview": preview,
            "is_text": False,
            "metadata": "7z Archive"
        }

    # 9. GZIP Compressed Data (\x1f\x8b)
    if raw_bytes.startswith(b"\x1f\x8b"):
        try:
            decomp = zlib.decompress(raw_bytes, 16 + zlib.MAX_WBITS)
            decomp_info = analyze_payload(decomp)
            preview = f"[GZIP Compressed Stream] Unpacks to {len(decomp)} bytes of {decomp_info['type']}"
            return {
                "type": "GZIP Archive",
                "ext": ".gz",
                "preview": preview,
                "is_text": False,
                "metadata": f"Unpacks to {decomp_info['type']}",
                "decompressed": decomp
            }
        except Exception:
            return {
                "type": "GZIP Stream",
                "ext": ".gz",
                "preview": f"[GZIP Compressed Stream] Size: {length} bytes",
                "is_text": False,
                "metadata": "GZIP"
            }

    # 10. RAR Archive (Rar!\x1a\x07)
    if raw_bytes.startswith(b"Rar!\x1a\x07"):
        return {
            "type": "RAR Archive",
            "ext": ".rar",
            "preview": f"[RAR Archive] Size: {length} bytes",
            "is_text": False,
            "metadata": "RAR Archive"
        }

    # 11. Linux ELF Binary (\x7fELF)
    if raw_bytes.startswith(b"\x7fELF"):
        return {
            "type": "ELF Executable/Library",
            "ext": ".elf",
            "preview": f"[Linux ELF Binary] Size: {length} bytes",
            "is_text": False,
            "metadata": "ELF binary"
        }

    # 12. Windows PE Executable / DLL (MZ)
    if raw_bytes.startswith(b"MZ"):
        return {
            "type": "Windows Executable (PE)",
            "ext": ".exe",
            "preview": f"[Windows PE Executable] Size: {length} bytes",
            "is_text": False,
            "metadata": "PE / MZ executable"
        }

    # 13. SQLite Database (SQLite format 3)
    if raw_bytes.startswith(b"SQLite format 3\x00"):
        return {
            "type": "SQLite Database",
            "ext": ".db",
            "preview": f"[SQLite 3 Database] Size: {length} bytes",
            "is_text": False,
            "metadata": "SQLite DB"
        }

    # 14. Audio Streams: MP3 / FLAC / OGG
    if raw_bytes.startswith(b"ID3") or raw_bytes.startswith(b"\xff\xfb") or raw_bytes.startswith(b"\xff\xf3"):
        return {
            "type": "MP3 Audio",
            "ext": ".mp3",
            "preview": f"[MP3 Audio Stream] Size: {length} bytes",
            "is_text": False,
            "metadata": "MPEG Audio"
        }
    if raw_bytes.startswith(b"fLaC"):
        return {
            "type": "FLAC Audio",
            "ext": ".flac",
            "preview": f"[FLAC Lossless Audio] Size: {length} bytes",
            "is_text": False,
            "metadata": "FLAC Audio"
        }
    if raw_bytes.startswith(b"OggS"):
        return {
            "type": "OGG Container",
            "ext": ".ogg",
            "preview": f"[OGG Stream] Size: {length} bytes",
            "is_text": False,
            "metadata": "OGG"
        }

    # 15. Check for Decodable Text & Structured Formats
    try:
        decoded = raw_bytes.decode("utf-8", errors="ignore")
        printable_count = sum(1 for c in decoded if c in string.printable)
        ratio = printable_count / len(decoded) if decoded else 0
        if ratio >= 0.85:
            stripped = decoded.strip()

            # CTF Flag Pattern
            for prefix in ("flag{", "BYTE{", "CTF{", "picoCTF{", "HTB{"):
                if prefix.lower() in stripped.lower():
                    start_idx = stripped.lower().find(prefix.lower())
                    end_idx = stripped.find("}", start_idx)
                    flag_val = stripped[start_idx : end_idx + 1] if end_idx != -1 else stripped[start_idx : start_idx + 60]
                    return {
                        "type": "CTF Flag",
                        "ext": ".txt",
                        "preview": f"[+] RECOVERED FLAG: {flag_val}",
                        "is_text": True,
                        "metadata": f"CTF Flag ({flag_val})"
                    }

            # JSON Data
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

            # PEM Key / Certificate
            if "-----BEGIN " in stripped:
                return {
                    "type": "Cryptographic Key (PEM)",
                    "ext": ".pem",
                    "preview": stripped[:300],
                    "is_text": True,
                    "metadata": "PEM Key"
                }

            # XML / HTML Document
            if stripped.startswith("<?xml") or (stripped.startswith("<") and stripped.endswith(">")):
                return {
                    "type": "XML Document",
                    "ext": ".xml",
                    "preview": stripped[:300],
                    "is_text": True,
                    "metadata": "XML"
                }

            # Python Script
            if (stripped.startswith("#!/") and "python" in stripped) or ("import " in stripped and "def " in stripped):
                return {
                    "type": "Python Script",
                    "ext": ".py",
                    "preview": stripped[:300],
                    "is_text": True,
                    "metadata": "Python Source Code"
                }

            # Shell Script
            if stripped.startswith("#!/bin/") or stripped.startswith("@echo off"):
                return {
                    "type": "Shell Script",
                    "ext": ".sh" if stripped.startswith("#!") else ".bat",
                    "preview": stripped[:300],
                    "is_text": True,
                    "metadata": "Shell Script"
                }

            # CSV Spreadsheet
            lines = [l for l in stripped.splitlines() if l.strip()]
            if len(lines) >= 2 and all("," in l for l in lines[:5]):
                return {
                    "type": "CSV Spreadsheet",
                    "ext": ".csv",
                    "preview": stripped[:300],
                    "is_text": True,
                    "metadata": f"{len(lines)} rows"
                }

            # Plain Text (Must pass entropy filter to avoid uniform noise like 'wwwwww')
            distinct_chars = len(set(stripped))
            if distinct_chars >= 6:
                counts = Counter(stripped)
                most_common_ratio = counts.most_common(1)[0][1] / len(stripped)
                if most_common_ratio <= 0.40:
                    return {
                        "type": "Plain Text",
                        "ext": ".txt",
                        "preview": stripped[:300],
                        "is_text": True,
                        "metadata": f"{len(stripped)} chars"
                    }

    except Exception:
        pass

    # 16. Fallback: Raw Binary Stream
    return {
        "type": "Raw Binary",
        "ext": ".bin",
        "preview": f"[Raw Binary Payload] Size: {length} bytes | Hex: {raw_bytes[:32].hex()}...",
        "is_text": False,
        "metadata": f"{length} bytes"
    }


def find_magic_in_stream(raw_bytes, max_scan=512):
    """
    Scans the beginning of a raw bitstream for known file magic bytes.
    """
    signatures = [
        (b"PK\x03\x04", "ZIP Archive", ".zip", "ZIP"),
        (b"\x89PNG\r\n\x1a\n", "PNG Image", ".png", "PNG"),
        (b"\xff\xd8\xff", "JPEG Image", ".jpg", "JPEG"),
        (b"BM", "BMP Image", ".bmp", "BMP"),
        (b"GIF87a", "GIF Image", ".gif", "GIF"),
        (b"GIF89a", "GIF Image", ".gif", "GIF"),
        (b"RIFF", "RIFF Container (WAV/AVI)", ".wav", "WAV"),
        (b"%PDF", "PDF Document", ".pdf", "PDF"),
        (b"\x1f\x8b", "GZIP Archive", ".gz", "GZIP"),
        (b"7z\xbc\xaf\x27\x1c", "7-Zip Archive", ".7z", "7Z"),
        (b"Rar!\x1a\x07", "RAR Archive", ".rar", "RAR"),
        (b"\x7fELF", "ELF Binary", ".bin", "ELF"),
        (b"MZ", "Windows PE Binary", ".exe", "EXE"),
        (b"SQLite format 3\x00", "SQLite Database", ".db", "SQLITE"),
        (b"-----BEGIN ", "Cryptographic Key (PEM)", ".pem", "PEM"),
    ]

    scan_len = min(len(raw_bytes), max_scan)
    for offset in range(scan_len):
        slice_data = raw_bytes[offset:]
        for sig, name, ext, ftype in signatures:
            if slice_data.startswith(sig):
                if sig == b"RIFF" and len(slice_data) >= 12 and slice_data[8:12] != b"WAVE" and slice_data[8:12] != b"AVI ":
                    continue
                actual_len = get_container_size(slice_data, ftype)
                carved = slice_data[:actual_len]
                info = analyze_payload(carved)
                return {
                    "found": True,
                    "offset": offset,
                    "info": info,
                    "carved_bytes": carved,
                    "description": f"Carved {info['type']} at offset {offset} ({len(carved)} bytes)"
                }

    return {"found": False}


def find_text_runs(byte_data, min_length=20):
    """
    Scans byte data for coherent printable text, filtering out uniform noise.
    """
    printable_set = set(bytes(string.printable, "ascii"))
    current = []
    runs = []

    for b in byte_data[:100000]:
        if b == 0:
            if len(current) >= min_length:
                runs.append(bytes(current))
            current = []
            continue

        if b in printable_set:
            current.append(b)
        else:
            if len(current) >= min_length:
                runs.append(bytes(current))
            current = []

    if len(current) >= min_length:
        runs.append(bytes(current))

    valid_runs = []
    for raw_run in runs:
        try:
            text = raw_run.decode("ascii", errors="replace")
            # Shannon / Diversity filter
            distinct = len(set(text))
            if distinct >= 5:
                counts = Counter(text)
                most_common_ratio = counts.most_common(1)[0][1] / len(text)
                if most_common_ratio <= 0.40:
                    letters = sum(1 for c in text if c.isalpha())
                    if letters / len(text) >= 0.40:
                        # Require spaces or flag/code structure to eliminate unspaced noise
                        is_flag = any(prefix in text.lower() for prefix in ("flag{", "byte{", "ctf{", "http", "-----begin", "import ", "def "))
                        is_struct = text.strip().startswith(("{", "[", "<", "<?xml"))
                        has_spaces = (" " in text) if len(text) >= 20 else True
                        has_words = len(text.split(" ")) >= 3 if len(text) >= 30 else True
                        if is_flag or is_struct or (has_spaces and has_words):
                            valid_runs.append(text)
        except Exception:
            continue

    if valid_runs:
        combined = "\n".join(valid_runs[:5])
        safe_preview = "".join(c if (32 <= ord(c) <= 126 or c in "\n\r\t") else "." for c in combined)
        preview = safe_preview[:300] + ("..." if len(safe_preview) > 300 else "")
        return True, preview, "\n".join(valid_runs).encode("utf-8")

    return False, "", None


# =====================================================================
# STEP 3: CONTAINER ANOMALIES, OVERLAYS & METADATA
# =====================================================================

def detect_overlay_data(file_path, format_name):
    """
    Detects data appended after the formal End-of-File marker.
    """
    result = {
        "found": False,
        "offset": 0,
        "overlay_bytes": None,
        "info": None,
        "preview": ""
    }

    try:
        file_size = os.path.getsize(file_path)
        with open(file_path, "rb") as f:
            data = f.read()

        iend_offset = None

        if format_name == "PNG":
            # Search for IEND chunk (49 45 4E 44 + 4 bytes CRC = 8 bytes total)
            iend_idx = data.find(b"IEND")
            if iend_idx != -1:
                iend_end = iend_idx + 4 + 4  # Chunk name + CRC
                if file_size > iend_end:
                    iend_offset = iend_end

        elif format_name == "JPEG":
            # Search for last EOI marker \xff\xd9
            eoi_idx = data.rfind(b"\xff\xd9")
            if eoi_idx != -1 and (eoi_idx + 2) < file_size:
                # Disregard trailing 0x00 or 0xff padding
                trailing = data[eoi_idx + 2 :]
                if any(b not in (0x00, 0xFF) for b in trailing):
                    iend_offset = eoi_idx + 2

        elif format_name == "BMP":
            if len(data) >= 6:
                bmp_size = struct.unpack("<I", data[2:6])[0]
                if file_size > bmp_size:
                    iend_offset = bmp_size

        if iend_offset is not None and iend_offset < file_size:
            overlay = data[iend_offset:]
            info = analyze_payload(overlay)
            result["found"] = True
            result["offset"] = iend_offset
            result["overlay_bytes"] = overlay
            result["info"] = info
            result["preview"] = f"Appended overlay detected at offset {iend_offset} ({len(overlay)} bytes, {info['type']}):\n{info['preview']}"

    except Exception as e:
        result["preview"] = f"Overlay check error: {e}"

    return result


def inspect_png_chunks(file_path):
    """
    Inspects PNG chunk sequence for CRC tampering, injected bytes, or hidden custom chunks.
    """
    result = {
        "anomalies": [],
        "text_chunks": {},
        "custom_chunks": []
    }

    try:
        with open(file_path, "rb") as f:
            header = f.read(8)
            if header != b"\x89PNG\r\n\x1a\n":
                return result

            file_bytes = header + f.read()

        idx = 8
        standard_chunks = {
            b"IHDR", b"PLTE", b"IDAT", b"IEND", b"cHRM", b"gAMA", b"iCCP",
            b"sBIT", b"sRGB", b"bKGD", b"hIST", b"tRNS", b"pHYs", b"sPLT", b"tIME"
        }

        while idx + 8 <= len(file_bytes):
            length = struct.unpack(">I", file_bytes[idx:idx+4])[0]
            ctype = file_bytes[idx+4:idx+8]
            ctype_name = "".join(chr(b) if 32 <= b <= 126 else f"\\x{b:02x}" for b in ctype)

            if idx + 12 + length > len(file_bytes):
                result["anomalies"].append(f"Corrupt chunk length {length} for '{ctype_name}' at byte {idx}")
                break

            cdata = file_bytes[idx+8:idx+8+length]
            expected_crc = struct.unpack(">I", file_bytes[idx+8+length:idx+12+length])[0]
            calc_crc = zlib.crc32(file_bytes[idx+4:idx+8+length]) & 0xFFFFFFFF

            if expected_crc != calc_crc:
                result["anomalies"].append(
                    f"CRC MISMATCH on chunk '{ctype_name}' at offset {idx} "
                    f"(Recorded: 0x{expected_crc:08x}, Calc: 0x{calc_crc:08x})"
                )

            # Metadata text chunks
            if ctype == b"tEXt":
                parts = cdata.split(b"\x00", 1)
                if len(parts) == 2:
                    k, v = parts[0].decode("latin1", "replace"), parts[1].decode("latin1", "replace")
                    result["text_chunks"][k] = v

            elif ctype == b"zTXt":
                parts = cdata.split(b"\x00", 2)
                if len(parts) >= 2:
                    k = parts[0].decode("latin1", "replace")
                    try:
                        v = zlib.decompress(parts[-1]).decode("latin1", "replace")
                        result["text_chunks"][k] = v
                    except Exception:
                        pass

            elif ctype not in standard_chunks:
                name = ctype.decode("latin1", "replace")
                result["custom_chunks"].append((name, len(cdata), cdata))

            idx += 12 + length
            if ctype == b"IEND":
                break

    except Exception as e:
        result["anomalies"].append(f"Chunk parsing error: {e}")

    return result


def inspect_palette_and_colors(image_path):
    """
    Checks for Palette / Color-as-Text steganography (e.g. Wikipedia Stego Flag).
    """
    result = {
        "found": False,
        "word": "",
        "preview": ""
    }

    try:
        with Image.open(image_path) as img:
            if img.mode == "P" and img.getpalette():
                pal = img.getpalette()
                # Extract non-zero RGB triplets
                non_zero = [b for b in pal if b != 0]
                text = "".join(chr(b) for b in non_zero if 32 <= b <= 126)
                if len(text) >= 4 and any(c.isalpha() for c in text):
                    result["found"] = True
                    result["word"] = text
                    result["preview"] = f"Palette Color-as-Text Steganography detected: '{text}'"
                    return result

            # TrueColor image with very few unique colors
            converted = img.convert("RGB")
            colors = converted.getcolors(maxcolors=256)
            if colors and len(colors) <= 32:
                rgb_bytes = []
                for _, rgb in colors:
                    rgb_bytes.extend(rgb)
                text = "".join(chr(b) for b in rgb_bytes if 32 <= b <= 126)
                if len(text) >= 4 and any(c.isalpha() for c in text):
                    result["found"] = True
                    result["word"] = text
                    result["preview"] = f"Unique Color Hex-Translation Steganography detected: '{text}'"
                    return result

    except Exception:
        pass

    return result


# =====================================================================
# STEP 4: VISUAL BITPLANE STEGANOGRAPHY (IMAGE IN IMAGE)
# =====================================================================

def inspect_visual_bitplanes(image_path):
    """
    Detects visual watermarks and hidden 1-bit / 2-bit images embedded in bitplanes.
    (e.g., hidden cat photograph in Steganography_original.png).
    """
    result = {
        "found": False,
        "type": "",
        "recovered_image": None,
        "preview": ""
    }

    try:
        with Image.open(image_path) as img:
            arr = np.array(img.convert("RGB"), dtype=np.uint8)

        h, w, _ = arr.shape
        if h < 20 or w < 20:
            return result

        # 1. Test 2-Bit Visual LSB: (pixel & 0x03) * 85
        vis_2bit = (arr & 0x03) * 85
        diff_h = np.abs(vis_2bit[:, 1:, :] - vis_2bit[:, :-1, :]).mean()
        diff_v = np.abs(vis_2bit[1:, :, :] - vis_2bit[:-1, :, :]).mean()
        std_val = vis_2bit.std()

        # Random noise has difference ~95; visual images have smooth edges (diff < 65)
        if diff_h < 65 and diff_v < 65 and std_val > 15:
            result["found"] = True
            result["type"] = "2-Bit Visual Color Image"
            result["recovered_image"] = Image.fromarray(vis_2bit)
            result["preview"] = (
                f"[+] 2-Bit Visual Image Detected! High spatial correlation (diff_h: {diff_h:.1f}, "
                f"diff_v: {diff_v:.1f}). Visual payload spans {w}x{h} pixels."
            )
            return result

        # 2. Test 1-Bit Visual LSB: (pixel & 0x01) * 255
        vis_1bit = (arr & 0x01) * 255
        diff_1h = np.abs(vis_1bit[:, 1:, :] - vis_1bit[:, :-1, :]).mean()
        diff_1v = np.abs(vis_1bit[1:, :, :] - vis_1bit[:-1, :, :]).mean()
        std_1 = vis_1bit.std()

        if diff_1h < 80 and diff_1v < 80 and std_1 > 20:
            result["found"] = True
            result["type"] = "1-Bit Visual Watermark Image"
            result["recovered_image"] = Image.fromarray(vis_1bit)
            result["preview"] = (
                f"[+] 1-Bit Visual Watermark Detected! Spatial structure (diff_h: {diff_1h:.1f}, "
                f"diff_v: {diff_1v:.1f}). Visual payload spans {w}x{h} pixels."
            )
            return result

    except Exception:
        pass

    return result


# =====================================================================
# STEP 5: DEEP MULTI-CHANNEL SPATIAL LSB EXTRACTION
# =====================================================================

def extract_lsb(image_path):
    """
    Extracts LSB across multiple candidate channels and formats:
      - RGB Sequential, RGBA Sequential, BGR Sequential
      - Red channel only, Green channel only, Blue channel only, Alpha channel only
      - Length-prefixed headers (big-endian / little-endian)
      - Direct file carving from bitstreams (ZIP, PNG, WAV, PDF, EXE, ELF, etc.)
      - Filtered text & flag recovery
    """
    result = {
        "applicable": True,
        "payload_found": False,
        "convention": "Spatial LSB",
        "preview": "",
        "raw_bytes": None,
        "payload_info": None
    }

    try:
        with Image.open(image_path) as img:
            has_alpha = img.mode in ("RGBA", "LA", "PA")
            img_conv = img.convert("RGBA" if has_alpha else "RGB")
            arr = np.array(img_conv, dtype=np.uint8)

        # Build Candidate Extraction Pipelines
        pipelines = []
        # Pipeline 1: RGB Sequential
        pipelines.append(("RGB Sequential 1-bit LSB", np.packbits(arr[:, :, :3].flatten() & 1).tobytes()))
        # Pipeline 2: BGR Sequential (OpenCV / BMP order)
        pipelines.append(("BGR Sequential 1-bit LSB", np.packbits(arr[:, :, :3][:, :, ::-1].flatten() & 1).tobytes()))
        # Pipeline 3: Red Channel Only
        pipelines.append(("Red Channel 1-bit LSB", np.packbits(arr[:, :, 0].flatten() & 1).tobytes()))
        # Pipeline 4: Green Channel Only
        pipelines.append(("Green Channel 1-bit LSB", np.packbits(arr[:, :, 1].flatten() & 1).tobytes()))
        # Pipeline 5: Blue Channel Only
        pipelines.append(("Blue Channel 1-bit LSB", np.packbits(arr[:, :, 2].flatten() & 1).tobytes()))

        if has_alpha:
            # Pipeline 6: RGBA Sequential
            pipelines.append(("RGBA Sequential 1-bit LSB", np.packbits(arr.flatten() & 1).tobytes()))
            # Pipeline 7: Alpha Channel Only
            pipelines.append(("Alpha Channel 1-bit LSB", np.packbits(arr[:, :, 3].flatten() & 1).tobytes()))

        # Evaluate Each Extraction Pipeline
        for pipe_name, raw_bytes in pipelines:
            if len(raw_bytes) < 8:
                continue

            # Check 1: 32-bit Big-Endian Length Prefix
            be_len = int.from_bytes(raw_bytes[:4], byteorder="big")
            if 1 <= be_len <= min(len(raw_bytes) - 4, 25000000):
                candidate = raw_bytes[4 : 4 + be_len]
                info = analyze_payload(candidate)
                if info["type"] not in ("Empty", "Raw Binary"):
                    result["payload_found"] = True
                    result["raw_bytes"] = candidate
                    result["payload_info"] = info
                    result["convention"] = f"{pipe_name} -> 32-bit big-endian length header ({be_len} bytes, {info['type']})"
                    result["preview"] = info["preview"]
                    return result

            # Check 2: 32-bit Little-Endian Length Prefix
            le_len = int.from_bytes(raw_bytes[:4], byteorder="little")
            if 1 <= le_len <= min(len(raw_bytes) - 4, 25000000):
                candidate = raw_bytes[4 : 4 + le_len]
                info = analyze_payload(candidate)
                if info["type"] not in ("Empty", "Raw Binary"):
                    result["payload_found"] = True
                    result["raw_bytes"] = candidate
                    result["payload_info"] = info
                    result["convention"] = f"{pipe_name} -> 32-bit little-endian length header ({le_len} bytes, {info['type']})"
                    result["preview"] = info["preview"]
                    return result

            # Check 3: Direct File Magic Byte Carving (Offsets 0 - 64)
            carved = find_magic_in_stream(raw_bytes, max_scan=64)
            if carved["found"]:
                info = carved["info"]
                result["payload_found"] = True
                result["raw_bytes"] = carved["carved_bytes"]
                result["payload_info"] = info
                result["convention"] = f"{pipe_name} -> Direct magic byte carving ({info['type']})"
                result["preview"] = info["preview"]
                return result

            # Check 4: Coherent Filtered Text / Flag Recovery
            has_text, text_preview, text_bytes = find_text_runs(raw_bytes, min_length=20)
            if has_text:
                result["payload_found"] = True
                result["raw_bytes"] = text_bytes
                result["convention"] = f"{pipe_name} -> Direct bitstream ASCII text run"
                result["preview"] = text_preview
                result["payload_info"] = analyze_payload(text_bytes)
                return result

        result["payload_found"] = False
        result["preview"] = "No coherent file header, printable ASCII run, or valid length prefix detected."
        return result

    except Exception as e:
        result["preview"] = f"Spatial LSB extraction failed: {e}"
        result["payload_found"] = False
        return result


# =====================================================================
# STEP 6: TRANSFORM-DOMAIN 2D-DCT EXTRACTION (JPEG)
# =====================================================================

def extract_dct(image_path):
    """
    Extracts LSBs from 2D-DCT AC frequency coefficients for JPEG images.
    """
    result = {
        "applicable": True,
        "payload_found": False,
        "convention": "2D-DCT mid-frequency AC coefficient LSBs (jsteg convention)",
        "preview": "",
        "raw_bytes": None,
        "payload_info": None
    }

    if dct is None:
        result["preview"] = "SciPy is not installed (required for DCT frequency analysis)."
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

        # Check for length prefix
        if len(raw_bytes) >= 4:
            be_len = int.from_bytes(raw_bytes[:4], byteorder="big")
            if 1 <= be_len <= min(len(raw_bytes) - 4, 1000000):
                candidate = raw_bytes[4 : 4 + be_len]
                info = analyze_payload(candidate)
                result["payload_found"] = True
                result["raw_bytes"] = candidate
                result["payload_info"] = info
                result["convention"] = f"2D-DCT -> 32-bit length header ({be_len} bytes, {info['type']})"
                result["preview"] = info["preview"]
                return result

        # Check for magic bytes
        carved = find_magic_in_stream(raw_bytes, max_scan=64)
        if carved["found"]:
            info = carved["info"]
            result["payload_found"] = True
            result["raw_bytes"] = carved["carved_bytes"]
            result["payload_info"] = info
            result["convention"] = f"2D-DCT -> Direct magic byte carving ({info['type']})"
            result["preview"] = info["preview"]
            return result

        # Check for coherent text
        has_text, text_preview, text_bytes = find_text_runs(raw_bytes, min_length=20)
        if has_text:
            result["payload_found"] = True
            result["raw_bytes"] = text_bytes
            result["preview"] = text_preview
            result["payload_info"] = analyze_payload(text_bytes)
            return result

        result["payload_found"] = False
        result["preview"] = "No coherent printable ASCII run or valid file header in DCT coefficients."
        return result

    except Exception as e:
        result["preview"] = f"DCT extraction failed with error: {e}"
        result["payload_found"] = False
        return result


# =====================================================================
# STEP 7: STEGHIDE INTEGRATION
# =====================================================================

def extract_steghide(image_path, passphrases=("", "password", "admin", "123456", "stego")):
    """
    Attempts Steghide extraction across common default passphrases.
    """
    import subprocess
    import tempfile

    result = {
        "applicable": True,
        "payload_found": False,
        "convention": "Steghide (Rijndael-128 CBC + zlib)",
        "preview": "",
        "raw_bytes": None,
        "payload_info": None
    }

    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp:
        tmp_name = tmp.name

    try:
        for p in passphrases:
            cmd = ["steghide", "extract", "-sf", image_path, "-p", p, "-xf", tmp_name, "-f"]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            if proc.returncode == 0 and os.path.exists(tmp_name) and os.path.getsize(tmp_name) > 0:
                with open(tmp_name, "rb") as f:
                    raw_bytes = f.read()

                info = analyze_payload(raw_bytes)
                result["payload_found"] = True
                result["raw_bytes"] = raw_bytes
                result["payload_info"] = info
                result["convention"] = f"Steghide (Passphrase: '{p}', {len(raw_bytes)} bytes, {info['type']})"
                result["preview"] = info["preview"]
                return result

        result["preview"] = "No Steghide payload detected with standard passphrases."
    except FileNotFoundError:
        result["applicable"] = False
        result["preview"] = "Steghide binary not found on PATH (optional for JPEG/BMP)."
    except Exception as e:
        result["preview"] = f"Steghide extraction failed: {e}"
    finally:
        if os.path.exists(tmp_name):
            try:
                os.remove(tmp_name)
            except OSError:
                pass

    return result


# =====================================================================
# STEP 8: REPORTING & FILE EXPORT
# =====================================================================

def print_report(
    image_path,
    format_name,
    lsb_result,
    dct_result,
    steghide_result=None,
    overlay_result=None,
    chunk_result=None,
    palette_result=None,
    visual_result=None,
    verify_file=None,
    output_dir=None
):
    """
    Prints structured forensic analysis report and exports any discovered payloads.
    """
    sep = "=" * 70
    sub_sep = "-" * 70

    def safe_str(val):
        s = str(val)
        return "".join(c if (32 <= ord(c) <= 126 or c in "\n\r\t") else f"\\x{ord(c):02x}" for c in s)

    print("\n" + sep)
    print(" PIXELPRY FORENSIC STEGANOGRAPHY ANALYSIS REPORT")
    print(sep)
    print(f" Target File     : {safe_str(image_path)}")
    print(f" Detected Format : {safe_str(format_name)}")
    try:
        print(f" File Size       : {os.path.getsize(image_path):,} bytes")
    except Exception:
        pass
    print(sep)

    # 1. Container Integrity & Overlay
    print("\n[Method 1: Container Structure, Chunks & File Overlay]")
    print(sub_sep)
    if overlay_result and overlay_result["found"]:
        print(" Overlay Data     : [+] LIKELY (Appended data detected past image EOF)")
        print(f" Details          : {safe_str(overlay_result['preview'])}")
    else:
        print(" Overlay Data     : [-] None detected (Clean image EOF)")

    if chunk_result:
        if chunk_result["anomalies"]:
            print(" Chunk Anomalies  : [!] CORRUPTION / TAMPERING DETECTED")
            for anom in chunk_result["anomalies"]:
                print(f"   * {safe_str(anom)}")
        if chunk_result["text_chunks"]:
            print(" Metadata Chunks  : [+] Embedded Text Metadata Found:")
            for k, v in chunk_result["text_chunks"].items():
                print(f"   [{safe_str(k)}]: {safe_str(v[:100])}")
        if chunk_result["custom_chunks"]:
            print(" Non-Standard Chunks: [+] Custom Chunk Types Found:")
            for cname, csz, _ in chunk_result["custom_chunks"]:
                print(f"   * '{safe_str(cname)}' chunk ({csz} bytes)")

    # 2. Visual Bit-Plane Steganography
    print("\n[Method 2: Visual Bit-Plane & Watermark Analysis]")
    print(sub_sep)
    if visual_result and visual_result["found"]:
        print(f" Visual Payload   : [+] LIKELY ({visual_result['type']})")
        print(f" Details          : {visual_result['preview']}")
    else:
        print(" Visual Payload   : [-] None detected (Standard visual noise distribution)")

    # 3. Palette & Color-as-Text Steganography
    print("\n[Method 3: Palette & Color-as-Text Analysis]")
    print(sub_sep)
    if palette_result and palette_result["found"]:
        print(" Color Stego      : [+] LIKELY (Palette / Color-as-Text Translation)")
        print(f" Details          : {palette_result['preview']}")
    else:
        print(" Color Stego      : [-] None detected")

    # 4. Multi-Channel Spatial Domain LSB
    print("\n[Method 4: Multi-Channel Spatial Domain LSB Extraction]")
    print(sub_sep)
    print(f" Applicable       : {'Yes (Spatial/Lossless image)' if lsb_result['applicable'] else 'No (Skipped for lossy format)'}")
    print(f" Convention Used  : {lsb_result['convention']}")
    print(f" Payload Found    : {'[+] LIKELY' if lsb_result['payload_found'] else '[-] None detected'}")
    if lsb_result["preview"]:
        safe_preview = "".join(c if (32 <= ord(c) <= 126 or c in "\n\r\t") else "." for c in lsb_result["preview"])
        print(f" Preview / Details:\n{safe_preview}")

    # 5. Transform Domain DCT (JPEG)
    print("\n[Method 5: Transform Domain DCT Extraction]")
    print(sub_sep)
    print(f" Applicable       : {'Yes (JPEG compressed format)' if dct_result['applicable'] else 'No (Skipped for spatial format)'}")
    print(f" Convention Used  : {dct_result['convention']}")
    print(f" Payload Found    : {'[+] LIKELY' if dct_result['payload_found'] else '[-] None detected'}")
    if dct_result["preview"]:
        safe_preview = "".join(c if (32 <= ord(c) <= 126 or c in "\n\r\t") else "." for c in dct_result["preview"])
        print(f" Preview / Details:\n{safe_preview}")

    # 6. Steghide Method
    if steghide_result:
        print("\n[Method 6: Steghide Extraction (Encrypted/Compressed Payloads)]")
        print(sub_sep)
        print(f" Applicable       : {'Yes (JPEG / BMP supported)' if steghide_result['applicable'] else 'No'}")
        print(f" Convention Used  : {steghide_result['convention']}")
        print(f" Payload Found    : {'[+] LIKELY' if steghide_result['payload_found'] else '[-] None detected'}")
        if steghide_result["preview"]:
            safe_preview = "".join(c if (32 <= ord(c) <= 126 or c in "\n\r\t") else "." for c in steghide_result["preview"])
            print(f" Preview / Details:\n{safe_preview}")

    # Collect all payloads for export or verification
    all_payloads = []
    if lsb_result and lsb_result.get("raw_bytes"):
        all_payloads.append((lsb_result["raw_bytes"], lsb_result.get("payload_info"), "lsb_payload"))
    if overlay_result and overlay_result.get("overlay_bytes"):
        all_payloads.append((overlay_result["overlay_bytes"], overlay_result.get("info"), "overlay_payload"))
    if steghide_result and steghide_result.get("raw_bytes"):
        all_payloads.append((steghide_result["raw_bytes"], steghide_result.get("payload_info"), "steghide_payload"))
    if dct_result and dct_result.get("raw_bytes"):
        all_payloads.append((dct_result["raw_bytes"], dct_result.get("payload_info"), "dct_payload"))

    # Reference Verification
    if verify_file:
        print("\n" + sub_sep)
        print(f" VERIFICATION AGAINST: {verify_file}")
        print(sub_sep)
        if not os.path.isfile(verify_file):
            print(f"[-] Reference file not found: '{verify_file}'")
        else:
            try:
                with open(verify_file, "rb") as rf:
                    ref_bytes = rf.read()

                matched = False
                for p_bytes, _, _ in all_payloads:
                    if p_bytes == ref_bytes or ref_bytes in p_bytes:
                        matched = True
                        break

                if matched:
                    print("[+] VERIFICATION STATUS: MATCH (Byte-for-byte verified!)")
                else:
                    print("[-] VERIFICATION STATUS: MISMATCH")
            except Exception as e:
                print(f"[-] Verification error: {e}")

    # File Export (--save <output_dir>)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        base = os.path.splitext(os.path.basename(image_path))[0]
        saved_count = 0

        # Save Visual Bitplane Image
        if visual_result and visual_result.get("recovered_image"):
            vis_path = os.path.join(output_dir, f"{base}_visual_extracted.png")
            visual_result["recovered_image"].save(vis_path)
            print(f"[+] Saved visual extracted image to: {vis_path}")
            saved_count += 1

        # Save Binary/Text Payloads
        for p_bytes, p_info, suffix in all_payloads:
            ext = p_info["ext"] if p_info else ".bin"
            out_file = os.path.join(output_dir, f"{base}_{suffix}{ext}")
            try:
                with open(out_file, "wb") as f:
                    f.write(p_bytes)
                print(f"[+] Saved extracted payload to: {out_file} ({len(p_bytes):,} bytes, {p_info['type'] if p_info else 'Binary'})")
                saved_count += 1
            except Exception as e:
                print(f"[-] Failed to save {out_file}: {e}")

        if saved_count == 0:
            print(f"[*] No extracted payloads were available to save in: {output_dir}")

    # Forensic Notes
    print("\n" + sep)
    print(" CAVEATS & FORENSIC NOTES")
    print(sep)
    print(" * Heuristic Multi-Domain Analysis: PixelPry tests 6 distinct vector classes")
    print("   (Container Overlay, Chunk Anomalies, Visual Bitplanes, Palette Translations,")
    print("   Multi-Channel LSBs, and Transform DCT AC coefficients).")
    print(" * True-Format Carving: Discovered payloads are mapped to their true format")
    print("   via magic bytes (PNG, ZIP, WAV, PDF, ELF, PEM, JSON, etc.) rather than generic text.")
    print(" * Entropy-Filtered: Single-character repetitions (e.g. solid color noise) are")
    print("   filtered out using Shannon diversity metrics.")
    print(sep + "\n")


# =====================================================================
# STEP 9: CLI & INTERACTIVE SHELL LAUNCHER
# =====================================================================

def is_launched_from_explorer():
    """
    Detects if launched from Windows Explorer (double-clicked or dragged).
    """
    if os.name != "nt":
        return False
    try:
        import ctypes
        arr = (ctypes.c_uint * 16)()
        count = ctypes.windll.kernel32.GetConsoleProcessList(arr, 16)
        return count <= 2
    except Exception:
        return False


def main():
    interactive_mode = False
    from_explorer = is_launched_from_explorer()

    try:
        if len(sys.argv) >= 2 and sys.argv[1] in ("-h", "--help"):
            print("PixelPry - Multi-Format Steganography Forensic Analysis & Payload Extraction Suite")
            print(f"Usage: {os.path.basename(sys.argv[0])} <image_file_path> [--verify <reference_file>] [--save <output_dir>]")
            if from_explorer:
                input("\nPress Enter to exit...")
            sys.exit(0)

        verify_file = None
        output_dir = None
        image_path = None

        if len(sys.argv) >= 2:
            image_path = sys.argv[1].strip('"').strip("'")
            args = sys.argv[2:]
            idx = 0
            while idx < len(args):
                if args[idx] == "--verify" and idx + 1 < len(args):
                    verify_file = args[idx + 1].strip('"').strip("'")
                    idx += 2
                elif args[idx] == "--save" and idx + 1 < len(args):
                    output_dir = args[idx + 1].strip('"').strip("'")
                    idx += 2
                else:
                    idx += 1
        else:
            interactive_mode = True
            print("=" * 70)
            print("        PixelPry - Digital Image Steganography & Forensics")
            print("=" * 70)
            print("\nUsage tips:")
            print(" - Drag and drop an image file directly into this window, or")
            print(" - Type or paste the path to an image file.\n")

            user_input = input("Enter image file path: ").strip().strip('"').strip("'")
            if not user_input:
                print("[-] No file provided. Exiting.")
                input("\nPress Enter to exit...")
                sys.exit(0)
            image_path = user_input

            save_prompt = input("Save extracted payloads to directory? (Leave blank to skip, or enter folder): ").strip().strip('"').strip("'")
            if save_prompt:
                output_dir = save_prompt

        if not os.path.isfile(image_path):
            print(f"[-] Error: File not found: '{image_path}'")
            if interactive_mode or from_explorer:
                input("\nPress Enter to exit...")
            sys.exit(1)

        format_name = identify_format(image_path)
        if not format_name:
            print(f"[-] Error: Unrecognized image file: '{image_path}'")
            if interactive_mode or from_explorer:
                input("\nPress Enter to exit...")
            sys.exit(1)

        # 1. Overlay detection
        overlay_result = detect_overlay_data(image_path, format_name)

        # 2. Chunk inspection (for PNG)
        chunk_result = inspect_png_chunks(image_path) if format_name == "PNG" else None

        # 3. Palette & Color-as-Text inspection
        palette_result = inspect_palette_and_colors(image_path)

        # 4. Visual Bit-Plane analysis
        visual_result = inspect_visual_bitplanes(image_path)

        # 5. Spatial LSB (PNG, BMP, GIF, WebP)
        lsb_result = {
            "applicable": False,
            "payload_found": False,
            "convention": "N/A",
            "preview": "Not applicable to this image format."
        }
        if format_name in ("PNG", "BMP", "GIF", "WEBP"):
            lsb_result = extract_lsb(image_path)

        # 6. Transform DCT (JPEG)
        dct_result = {
            "applicable": False,
            "payload_found": False,
            "convention": "N/A",
            "preview": "Not applicable to this image format."
        }
        if format_name in ("JPEG", "JPG"):
            dct_result = extract_dct(image_path)

        # 7. Steghide (JPEG / BMP)
        steghide_result = None
        if format_name in ("JPEG", "JPG", "BMP"):
            steghide_result = extract_steghide(image_path)

        # 8. Report & Export
        print_report(
            image_path,
            format_name,
            lsb_result,
            dct_result,
            steghide_result=steghide_result,
            overlay_result=overlay_result,
            chunk_result=chunk_result,
            palette_result=palette_result,
            visual_result=visual_result,
            verify_file=verify_file,
            output_dir=output_dir
        )

    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user.")
    except Exception as e:
        import traceback
        print(f"\n[-] Unexpected Error: {e}")
        traceback.print_exc()
    finally:
        if interactive_mode or from_explorer:
            try:
                input("\nScan completed. Press Enter to exit...")
            except (EOFError, KeyboardInterrupt):
                pass


if __name__ == "__main__":
    main()
