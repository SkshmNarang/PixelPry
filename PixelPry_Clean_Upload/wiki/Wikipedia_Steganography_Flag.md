# Steganography Analysis: `Wikipedia_Steganography_Flag.png`

## 1. File Overview
| Property | Value |
| :--- | :--- |
| **Filename** | `Wikipedia_Steganography_Flag.png` |
| **Location** | `testing phase/Wikipedia_Steganography_Flag.png` |
| **Format** | PNG (Palette-based Lossless Format) |
| **Dimensions** | 1,875 x 1,250 pixels |
| **Color Mode** | P (Indexed Palette, 8-bit) |
| **File Size** | 3,049 bytes (~3.0 KB) |
| **Origin** | Wikimedia Commons (`File:Wikipedia Steganography Flag.png`) |

---

## 2. Execution Output from Your Script
```text
======================================================================
 STEGANOGRAPHY ANALYSIS REPORT
======================================================================
 Target File     : d:\New folder\testing phase\Wikipedia_Steganography_Flag.png
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
1. Checked for hidden sequential 1-bit LSB text or file headers.
2. Reported `[-] None detected`.

---

## 4. The Real Steganography Truth

### What is actually hidden inside this picture?
The image displays a three-stripe flag. The colors of the stripes literally spell the word **"Wikipedia"**!

### How is it hidden?
This image uses **Color-as-Text Steganography** (Hex Code Translation):
- Instead of hiding secret bits invisibly inside pixel noise, the author made each stripe's color byte values correspond to the ASCII characters of the secret word:
  1. **Top Stripe:** RGB `(87, 105, 107)` -> Hex `#57696B` -> ASCII chars: `W`, `i`, `k` (**"Wik"**)
  2. **Middle Stripe:** RGB `(105, 112, 101)` -> Hex `#697065` -> ASCII chars: `i`, `p`, `e` (**"ipe"**)
  3. **Bottom Stripe:** RGB `(100, 105, 97)` -> Hex `#646961` -> ASCII chars: `d`, `i`, `a` (**"dia"**)

Putting them together spells: **"Wikipedia"**!

---

## 5. Why the Script Gave This Output
Your script checks the **Least Significant Bit (bit 0)** of pixels for an invisible message. In this flag, the message is stored in the **entire visible 24-bit color value** (the whole pixel color IS the message). Therefore, an LSB-only bitstream scan did not find standard sequential text.

---

## 6. Extracted Payload File
The decoded payload has been saved as a readable text document:
- **Respective Format File:** [`Wikipedia_Steganography_Flag_extracted_text.txt`](file:///d:/New%20folder/wiki/Wikipedia_Steganography_Flag_extracted_text.txt)
