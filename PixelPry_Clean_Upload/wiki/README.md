# Steganography Secret Payloads & Forensic Wiki

This repository contains the extracted secret payloads in their **true native format** (images, decoded text, bit-planes, and physical dot matrices) along with plain-English analysis guides.

---

## 1. Extracted Secrets in Their True Format

| Source Image in `testing phase/` | Hidden Secret Type | True Format | Extracted Secret File | Description of Extracted Secret |
| :--- | :--- | :--- | :--- | :--- |
| **`Steganography_original.png`** | Secret Image | **PNG Image** | [`Steganography_original_extracted_cat.png`](file:///d:/New%20folder/wiki/Steganography_original_extracted_cat.png) | Full-color hidden cat photograph extracted by shifting the 2 LSBs: `(pixel & 0x03) * 85`. |
| **`Steganography_recovered.png`** | Secret Image | **PNG Image** | [`Steganography_recovered_secret_cat.png`](file:///d:/New%20folder/wiki/Steganography_recovered_secret_cat.png) | The decoded ground-truth secret cat image. |
| **`Wikipedia_Steganography_Flag.png`** | Secret Text | **Plain Text** | [`Wikipedia_Steganography_Flag_extracted_secret.txt`](file:///d:/New%20folder/wiki/Wikipedia_Steganography_Flag_extracted_secret.txt)<br>[`Wikipedia_Steganography_Flag_visual_stripes.png`](file:///d:/New%20folder/wiki/Wikipedia_Steganography_Flag_visual_stripes.png) | Decoded secret word **"Wikipedia"** extracted from the RGB hex color byte values (`#57696B`="Wik", `#697065`="ipe", `#646961`="dia"). |
| **`Steganography.png`** | Secret Planes | **PNG Images** | [`Steganography_extracted_red_plane.png`](file:///d:/New%20folder/wiki/Steganography_extracted_red_plane.png)<br>[`Steganography_extracted_green_plane.png`](file:///d:/New%20folder/wiki/Steganography_extracted_green_plane.png)<br>[`Steganography_extracted_blue_plane.png`](file:///d:/New%20folder/wiki/Steganography_extracted_blue_plane.png) | Isolated binary bit-planes for Red, Green, and Blue channels demonstrating multi-layer optical steganography. |
| **`Spectrogram_-_Nine_Inch_Nails_-_My_Violent_Heart.png`** | Secret Visual Art | **PNG Image** | [`Spectrogram_The_Presence_extracted_hand.png`](file:///d:/New%20folder/wiki/Spectrogram_The_Presence_extracted_hand.png) | "The Presence" — the famous secret ghostly arm and hand artwork isolated and enhanced from the sound frequency spectrum. |
| **`Image_hidden_in_an_audio.png`** | Secret Visual Art | **PNG Image** | [`Image_hidden_in_an_audio_extracted_payload.png`](file:///d:/New%20folder/wiki/Image_hidden_in_an_audio_extracted_payload.png) | The visual artwork payload isolated from the audio frequency canvas in Sonic Visualiser. |
| **`Printer_Steganography.jpg`** | Hardware Code | **PNG Image** | [`Printer_Steganography_extracted_dots.png`](file:///d:/New%20folder/wiki/Printer_Steganography_extracted_dots.png) | Isolated Machine Identification Code (MIC) yellow tracking dot grid extracted via blue-channel absorption filtering. |
| **`ChangeinLSB.jpg`** | Perception Guide | **PNG Image** | [`ChangeinLSB_visual_comparison.png`](file:///d:/New%20folder/wiki/ChangeinLSB_visual_comparison.png) | Full-fidelity lossless visual diagram demonstrating LSB manipulation invisibility. |

---

## 2. Documentation Guides
Each image also has an associated plain-English explanation guide in Markdown (`.md`) and Text (`.txt`):
- `ChangeinLSB.md` / `ChangeinLSB.txt`
- `Image_hidden_in_an_audio.md` / `Image_hidden_in_an_audio.txt`
- `Printer_Steganography.md` / `Printer_Steganography.txt`
- `Spectrogram_-_Nine_Inch_Nails_-_My_Violent_Heart.md` / `Spectrogram_-_Nine_Inch_Nails_-_My_Violent_Heart.txt`
- `Steganography.md` / `Steganography.txt`
- `Steganography_original.md` / `Steganography_original.txt`
- `Steganography_recovered.md` / `Steganography_recovered.txt`
- `Wikipedia_Steganography_Flag.md` / `Wikipedia_Steganography_Flag.txt`
