# Steganography Analysis, Extraction & Forensic Recovery Suite

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Cybersecurity: Steganography](https://img.shields.io/badge/Domain-Cybersecurity%20%7C%20Stego-orange.svg)]()

A modular digital image steganography forensic analysis, extraction, and file repair framework. Designed for security researchers, CTF competitors, and forensic analysts to automatically identify image formats via magic bytes, analyze spatial-domain LSB bitstreams, calculate transform-domain 2D-DCT AC frequency coefficients, integrate Steghide Rijndael-128 extraction, and repair corrupted image chunk structures.

---

## Table of Contents
- [Key Features](#key-features)
- [Repository Structure](#repository-structure)
- [Installation & Requirements](#installation--requirements)
- [Usage Guide](#usage-guide)
- [BYTE MAIT Task 02: Challenge Writeup](#byte-mait-task-02-challenge-writeup)
- [Verification & Reference Suite (`wiki/`)](#verification--reference-suite-wiki)
- [Forensic Methodology](#forensic-methodology)
- [License](#license)

---

## Key Features

1. **Format Identification via Magic Bytes (Header Signatures)**
   - Identifies raw file headers directly from byte signatures rather than trusting spoofed extensions:
     - PNG: `\x89PNG\r\n\x1a\n`
     - JPEG: `\xff\xd8\xff`
     - BMP: `BM`
   - Graceful fallback to Pillow container inspection for edge formats.

2. **Spatial-Domain LSB Extraction (Lossless PNG / BMP)**
   - Extracts bitstream sequences from flattened RGB/RGBA channel arrays.
   - Evaluates big-endian 32-bit length prefixes to recover exact-length payloads (supporting images, audio, zip archives, PEM certificates, scripts, JSON, and text).
   - Evaluates sequential ASCII bitstreams with letter-frequency heuristics to eliminate compression noise and identify human-readable messages.

3. **Transform-Domain 2D-DCT Frequency Analysis (JPEG)**
   - Converts JPEG luminance to $8 \times 8$ blocks.
   - Computes 2D Discrete Cosine Transform (`scipy.fftpack.dct`) coefficients.
   - Samples mid-frequency AC coefficient LSBs (mirroring the *jsteg* embedding convention).

4. **Steghide Extraction Integration**
   - Automatically attempts payload decryption and decompression on JPEG and BMP images using Steghide (Rijndael-128 in CBC mode with zlib decompression).

5. **Advanced Binary Chunk Repair & Reconstruction**
   - Reconstructs corrupted PNG headers, solves IHDR CRC checksums to recover tampered dimensions (width/height), strips injected corrupting bytes, and realigns IDAT deflate streams.

---

## Repository Structure

```text
├── prototype1/
│   └── stego_extract.py       # Core forensic analysis & extraction tool
├── wiki/                      # Complete forensic wiki & true-format payloads
│   ├── README.md              # Master verification registry
│   ├── challenge_flag.png     # Isolated high-res image of the recovered flag banner
│   ├── challenge_flag.txt     # Official flag text (BYTE{g0t_1t_1n_plA1n_s1ght})
│   ├── challenge_recovered.png# Fully repaired 724x850 challenge image
│   ├── Steganography_original_extracted_cat.png # Extracted 2-bit visual LSB cat
│   ├── Wikipedia_Steganography_Flag_extracted_secret.txt # Decoded RGB flag text
│   ├── Steganography_extracted_*_plane.png # Isolated color bit-planes
│   ├── Spectrogram_The_Presence_extracted_hand.png # Audio spectrogram secret
│   ├── Printer_Steganography_extracted_dots.png # Machine Identification Codes
│   └── *.md / *.txt           # Detailed plain-English analysis guides
├── testing phase/             # Authentic reference steganography images
├── challenge.png              # Original corrupted CTF challenge image
├── challenge_recovered.png    # Repaired image with hidden flag banner visible
├── .gitignore
└── README.md
```

---

## Installation & Requirements

### Prerequisites
- Python 3.10+
- Optional: `steghide` (for transform-domain encrypted payload extraction)

### Python Dependencies
```bash
pip install pillow numpy scipy
```

---

## Usage Guide

### 1. Basic Analysis
Run the primary script on any target image:
```bash
python prototype1/stego_extract.py path/to/image.png
```

### 2. Verify Against a Reference Payload
```bash
python prototype1/stego_extract.py path/to/image.png --verify secret.txt
```

### 3. Automatically Extract & Save Discovered Payloads
```bash
python prototype1/stego_extract.py path/to/image.png --save output_directory/
```

---

## BYTE MAIT Task 02: Challenge Writeup

### Challenge Overview
- **Track:** Cybersecurity Recruitment — Task 02: Steganography
- **File:** `challenge.png` (415,143 bytes)
- **Problem Statement:** *"The challenge is a PNG file that has been corrupted. Find the flag in the format BYTE{...}."*
- **Flag Recovered:** `BYTE{g0t_1t_1n_plA1n_s1ght}`

### Forensic Diagnosis & Solution
1. **Initial Execution Failure:**
   Running `prototype1/stego_extract.py` reported `cannot identify image file 'challenge.png'` because standard PNG decoders (libpng/Pillow) rejected the corrupted structure.
2. **Anomaly 1 — IHDR Dimension Tampering (Height Truncation):**
   - The file recorded an IHDR CRC of `0xcad1ced6`, but the dimensions were set to $724 \times 800$ (which produces CRC `0x8c3b621c`).
   - Brute-forcing the dimension space matching CRC `0xcad1ced6` revealed the true height is **$850$ pixels**. The author cropped 50 rows to hide the flag banner outside the canvas.
3. **Anomaly 2 — Injected Corrupting Bytes:**
   - Exactly 12 extraneous bytes (`6c 0b f0 45 4a 5d 83 1e 0c ff 95 34`) were injected at byte offset `196677` between IDAT chunks 3 and 4, misaligning all remaining chunk headers.
4. **Reconstruction:**
   - Stripping the 12 corrupting bytes realigned chunks 4, 5, 6, 7, and 8 to valid CRCs.
   - Expanding the canvas to 850 rows and unfiltering the bottom scanlines exposed the black footer banner:
     $$\mathbf{flag\{g0t\_1t\_1n\_plA1n\_s1ght\}} \longrightarrow \mathbf{BYTE\{g0t\_1t\_1n\_plA1n\_s1ght\}}$$

---

## Verification & Reference Suite (`wiki/`)

The repository includes a comprehensive verification suite demonstrating various steganography techniques across 8 distinct categories:

| Target Image | Steganography Method | Extracted Payload | True Format |
| :--- | :--- | :--- | :--- |
| `Steganography_original.png` | 2-bit Spatial Visual LSB | Hidden cat photograph | `.png` |
| `Wikipedia_Steganography_Flag.png` | 24-bit RGB Color-as-Text | `"Wikipedia"` | `.txt` |
| `Steganography.png` | Color Channel Separation | Red/Green/Blue bit-planes | `.png` |
| `Spectrogram_-_Nine_Inch_Nails.png` | Audio Frequency Spectrogram | "The Presence" ghostly hand | `.png` |
| `Printer_Steganography.jpg` | Machine Identification Code | Yellow laser tracking dot grid | `.png` |
| `ChangeinLSB.jpg` | Human Perception Analysis | Lossless LSB comparison | `.png` |

---

## Forensic Methodology & Caveats

- **Heuristic Boundaries:** A verdict of `None detected` does not prove an image is clean. Non-sequential pixel orderings, custom PRNG seeds, encryption without headers, and exotic color space manipulation require targeted domain tests.
- **Verification Requirement:** Plausible payloads flagged as `LIKELY` must be cross-verified, as high-frequency textures or compression patterns can occasionally mimic ASCII character distributions.
- **Reconstruction Approximation:** JPEG DCT analysis reconstructs coefficients from decoded spatial pixels when raw quantized stream tables are not directly exposed.

---

## License
MIT License. Created for educational and cybersecurity research purposes.
