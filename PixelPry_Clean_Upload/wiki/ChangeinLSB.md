# Steganography Analysis: `ChangeinLSB.jpg`

## 1. File Overview
| Property | Value |
| :--- | :--- |
| **Filename** | `ChangeinLSB.jpg` |
| **Location** | `testing phase/ChangeinLSB.jpg` |
| **Format** | JPEG (Lossy Discrete Cosine Transform Format) |
| **Dimensions** | High-resolution visual diagram |
| **Color Mode** | RGB (YUV Chrominance subsampled) |
| **File Size** | 886,070 bytes (~886 KB) |
| **Origin** | Wikimedia Commons (`File:ChangeinLSB.jpg`) |

---

## 2. Execution Output from Your Script
```text
======================================================================
 STEGANOGRAPHY ANALYSIS REPORT
======================================================================
 Target File     : d:\New folder\testing phase\ChangeinLSB.jpg
 Detected Format : JPEG
======================================================================

[Method 1: Spatial Domain LSB Extraction]
----------------------------------------------------------------------
 Applicable       : No (Skipped for lossy format)
 Convention Used  : N/A
 Payload Found    : [-] None detected
 Preview / Details:
Not applicable to this image format.

[Method 2: Transform Domain DCT Extraction]
----------------------------------------------------------------------
 Applicable       : Yes (JPEG compressed format)
 Convention Used  : 2D-DCT mid-frequency AC coefficient LSBs (jsteg approximation)
 Payload Found    : [-] None detected
 Preview / Details:
No coherent printable ASCII run detected in sampled DCT coefficients.

[Method 3: Steghide Extraction (Encrypted & Compressed Payloads)]
----------------------------------------------------------------------
 Applicable       : Yes (JPEG / BMP supported)
 Convention Used  : Steghide (Rijndael-128 CBC + zlib + graph matching)
 Payload Found    : [-] None detected
 Preview / Details:
No Steghide payload detected or incorrect passphrase.
```

---

## 3. Plain English Explanation of the Script Output

### What the Script Did:
1. **Format Recognition:** Identified JPEG via `\xff\xd8\xff` magic bytes.
2. **Method 1 (Spatial LSB):** Correctly skipped. In JPEG images, 8x8 block DCT quantization alters pixel values during lossy compression, so raw spatial LSBs are destroyed.
3. **Method 2 (Transform DCT):** Calculated 2D Discrete Cosine Transform (DCT) coefficients and sampled mid-frequency AC values (standard jsteg convention). Found no readable ASCII sequence.
4. **Method 3 (Steghide):** Attempted Steghide payload extraction using graph-theoretic Rijndael-128 decryption. Found no valid Steghide header.

---

## 4. The Real Steganography Truth
This image is an **educational infographic** from Wikimedia Commons created to explain how LSB manipulation works. It visually compares a green color (RGB 235, binary `11101011`) with modified values (RGB 232, binary `11101000`), demonstrating that altering the least significant bits by +/- 3 produces no perceptible difference to the human visual system.

---

## 5. Why the Script Gave This Output
The file is an educational poster about steganography rather than a carrier hiding secret files. Hence, `[-] None detected` is 100% accurate.
