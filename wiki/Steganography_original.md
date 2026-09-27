# Steganography Analysis: `Steganography_original.png`

## 1. File Overview
| Property | Value |
| :--- | :--- |
| **Filename** | `Steganography_original.png` |
| **Location** | `testing phase/Steganography_original.png` |
| **Format** | PNG (Lossless Spatial Format) |
| **Dimensions** | 200 x 200 pixels |
| **Color Mode** | RGB (24-bit True Color) |
| **File Size** | 90,235 bytes (~90.2 KB) |
| **Origin** | Wikimedia Commons (`File:Steganography original.png` by User:Cyp) |

---

## 2. Execution Output from Your Script
```text
======================================================================
 STEGANOGRAPHY ANALYSIS REPORT
======================================================================
 Target File     : d:\New folder\testing phase\Steganography_original.png
 Detected Format : PNG
======================================================================

[Method 1: Spatial Domain LSB Extraction]
----------------------------------------------------------------------
 Applicable       : Yes (Spatial/Lossless image)
 Convention Used  : Spatial LSB (Bitstream sequential extraction)
 Payload Found    : [-] None detected
 Preview / Details:
No coherent printable ASCII run or valid length header detected.

[Method 2: Transform Domain DCT Extraction]
----------------------------------------------------------------------
 Applicable       : No (Skipped for spatial format)
 Convention Used  : N/A
 Payload Found    : [-] None detected
 Preview / Details:
Not applicable to this image format.
```

---

## 3. Plain English Explanation of the Script Output

### What the Script Did:
1. **Format Check:** The script inspected the first 8 bytes of the file and matched the PNG magic header (`\x89PNG\r\n\x1a\n`).
2. **Method 1 (Spatial LSB):** Because PNG is a lossless format, the script tested whether secret data was hidden sequentially in the least significant bits (LSB) of each pixel. It looked for:
   - A 32-bit big-endian length header indicating an embedded file.
   - A sequential stream of readable English text (ASCII characters).
3. **Verdict `[-] None detected`:** The script found neither a valid length header nor a readable ASCII string, so it reported that no payload was detected.
4. **Method 2 (DCT):** Skipped because DCT frequency analysis is designed specifically for lossy JPEG compression, not lossless PNG images.

---

## 4. The Real Steganography Truth

### What is actually hidden inside this picture?
Hidden inside this photograph of a tree is a **full-color image of a cat**!

### How is it hidden?
This image uses **2-bit visual LSB encoding**:
- Each pixel in the tree image has Red, Green, and Blue values ranging from 0 to 255 (8 bits each).
- The author replaced the **2 least significant bits** (bits 0 and 1) of every color channel in the tree with the **2 most significant bits** (bits 6 and 7) of the secret cat picture.
- Because changing only the bottom 2 bits alters color intensity by at most 3 units (out of 255), the human eye cannot see any difference in the tree photo.

---

## 5. Why the Script Gave This Output
Your script is engineered to detect **1-bit sequential text files or length-prefixed data**. 
Because the hidden payload is a **visual 2-bit color image of a cat** rather than English text:
1. The bits in the LSBs do not map to printable ASCII characters (letters, digits, punctuation).
2. There is no 4-byte integer at the beginning telling the script the payload length.
Therefore, the script correctly determined that no sequential ASCII text or standard length header was present.

---

## 6. How to Extract the Hidden Cat
To extract and see the secret cat, take the bottom 2 bits of each pixel channel and multiply by 85 (or shift left by 6 bits: `(pixel & 0x03) * 85`) to scale the 2 bits across the full 0–255 brightness range.

### Extracted File:
The secret cat image has been successfully extracted and saved in this directory:
- **Respective Format File:** [`Steganography_original_extracted_cat.png`](file:///d:/New%20folder/wiki/Steganography_original_extracted_cat.png)
