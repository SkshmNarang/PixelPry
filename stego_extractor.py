#!/usr/bin/env python3
"""
Steganography Extractor
Attempts to extract hidden data from images using LSB and DCT methods.
"""

import sys
import os
from PIL import Image
import numpy as np


def identify_image_format(image_path):
    """
    Identify the image format (PNG, JPEG, BMP, etc.)

    Args:
        image_path: Path to the image file

    Returns:
        Image format as string, or None if unable to determine
    """
    try:
        with Image.open(image_path) as img:
            format_name = img.format
            print(f"[+] Image format detected: {format_name}")
            print(f"[+] Image size: {img.size[0]}x{img.size[1]} pixels")
            print(f"[+] Image mode: {img.mode}")
            return format_name
    except Exception as e:
        print(f"[-] Error identifying image: {e}")
        return None


def lsb_extract(image_path):
    """
    Extract data using Least Significant Bit (LSB) steganography.
    This method extracts the least significant bit from each color channel.

    LSB steganography hides data in the least significant bits of pixel values,
    which has minimal visual impact but can store information.

    Args:
        image_path: Path to the image file

    Returns:
        Extracted binary string and decoded text (if printable)
    """
    print("\n" + "="*60)
    print("LSB EXTRACTION")
    print("="*60)

    try:
        # Open image and convert to RGB (works for PNG, JPEG, BMP)
        img = Image.open(image_path)

        # Convert to RGB if not already (handles RGBA, grayscale, etc.)
        if img.mode != 'RGB':
            img = img.convert('RGB')

        # Convert image to numpy array for easier manipulation
        pixels = np.array(img)
        height, width, channels = pixels.shape

        print(f"[+] Extracting LSBs from {height}x{width} image ({channels} channels)")

        # Extract LSB from each color channel of each pixel
        binary_data = ''
        for row in pixels:
            for pixel in row:
                for color_value in pixel:
                    # Extract the least significant bit (LSB)
                    binary_data += str(color_value & 1)

        print(f"[+] Extracted {len(binary_data)} bits")

        # Try to decode as bytes (8 bits = 1 byte)
        extracted_bytes = []
        for i in range(0, len(binary_data), 8):
            byte = binary_data[i:i+8]
            if len(byte) == 8:
                extracted_bytes.append(int(byte, 2))

        # Convert to bytes object
        byte_data = bytes(extracted_bytes)

        # Try to find printable ASCII text
        # Look for sequences of printable characters
        text_data = ''
        current_string = ''

        for byte in byte_data[:10000]:  # Check first 10000 bytes
            if 32 <= byte <= 126 or byte in [9, 10, 13]:  # Printable ASCII + tab/newline/return
                current_string += chr(byte)
            else:
                if len(current_string) >= 4:  # If we found a string of 4+ chars, it might be data
                    text_data += current_string + '\n'
                current_string = ''

        # Add any remaining string
        if len(current_string) >= 4:
            text_data += current_string

        # Display results
        print(f"\n[+] First 256 bits: {binary_data[:256]}...")
        print(f"[+] First 32 bytes (hex): {byte_data[:32].hex()}")

        if text_data:
            print(f"\n[+] Potential text found:")
            print("-" * 60)
            print(text_data[:500])  # Show first 500 chars
            if len(text_data) > 500:
                print(f"... ({len(text_data) - 500} more characters)")
        else:
            print(f"\n[-] No obvious text found in LSB data")
            print(f"[*] First 100 characters (forced decode): {byte_data[:100]}")

        return binary_data, byte_data

    except Exception as e:
        print(f"[-] Error during LSB extraction: {e}")
        return None, None


def dct_extract_jpeg(image_path):
    """
    Extract data using DCT (Discrete Cosine Transform) coefficients.
    This is specific to JPEG images which use DCT for compression.

    JPEG steganography can hide data by modifying DCT coefficients,
    which are the frequency domain representation of 8x8 pixel blocks.

    Note: This is a simplified extraction that looks at DCT coefficient patterns.
    Full JPEG steganography extraction requires libraries like jpegio or direct
    JPEG parsing, which can access quantized DCT coefficients before inverse DCT.

    Args:
        image_path: Path to the JPEG image file
    """
    print("\n" + "="*60)
    print("DCT EXTRACTION (JPEG)")
    print("="*60)

    try:
        # Check if it's actually a JPEG
        with Image.open(image_path) as img:
            if img.format not in ['JPEG', 'JPG']:
                print(f"[-] Image is {img.format}, not JPEG. Skipping DCT extraction.")
                return

        print("[*] Note: Basic DCT analysis. Full JPEG coefficient extraction")
        print("[*] requires specialized libraries (jpegio, jpeg2dct, etc.)")

        # For a basic approach, we can analyze the image after JPEG decompression
        # and look for patterns that might indicate steganography
        img = Image.open(image_path)
        img_array = np.array(img.convert('YCbCr'))  # JPEG uses YCbCr color space

        print(f"[+] Analyzing JPEG image: {img_array.shape}")

        # Simple analysis: Check for unusual patterns in LSBs of decompressed data
        # Real JPEG stego would modify quantized DCT coefficients before IDCT
        y_channel = img_array[:, :, 0]

        # Extract LSBs from Y channel (luminance)
        lsb_pattern = y_channel & 1

        # Calculate statistics
        zero_count = np.sum(lsb_pattern == 0)
        one_count = np.sum(lsb_pattern == 1)
        total = lsb_pattern.size

        print(f"\n[+] Y-channel LSB statistics:")
        print(f"    Zeros: {zero_count} ({zero_count/total*100:.2f}%)")
        print(f"    Ones:  {one_count} ({one_count/total*100:.2f}%)")

        # A roughly 50/50 distribution might indicate hidden data
        ratio = min(zero_count, one_count) / max(zero_count, one_count)
        if ratio > 0.9:
            print(f"[!] LSB distribution is very balanced (ratio: {ratio:.3f})")
            print(f"[!] This might indicate steganography")
        else:
            print(f"[*] LSB distribution ratio: {ratio:.3f}")

        # Try to extract as binary string
        binary_data = ''.join(str(bit) for bit in lsb_pattern.flatten())

        # Convert to bytes
        extracted_bytes = []
        for i in range(0, min(len(binary_data), 8000), 8):
            byte = binary_data[i:i+8]
            if len(byte) == 8:
                extracted_bytes.append(int(byte, 2))

        byte_data = bytes(extracted_bytes)
        print(f"\n[+] First 32 bytes from Y-channel LSBs (hex): {byte_data[:32].hex()}")

        # Check for printable text
        try:
            text = byte_data.decode('ascii', errors='ignore')
            printable = ''.join(c for c in text[:200] if c.isprintable() or c in '\n\r\t')
            if len(printable) > 10:
                print(f"[+] Potential text in DCT data:")
                print(f"    {printable[:200]}")
        except:
            pass

    except Exception as e:
        print(f"[-] Error during DCT extraction: {e}")


def save_extracted_data(binary_data, byte_data, output_prefix):
    """
    Save extracted data to files for further analysis.

    Args:
        binary_data: Binary string of extracted bits
        byte_data: Bytes object of extracted data
        output_prefix: Prefix for output filenames
    """
    if binary_data:
        # Save binary representation
        with open(f"{output_prefix}_binary.txt", 'w') as f:
            f.write(binary_data)
        print(f"[+] Binary data saved to {output_prefix}_binary.txt")

    if byte_data:
        # Save raw bytes
        with open(f"{output_prefix}_bytes.bin", 'wb') as f:
            f.write(byte_data)
        print(f"[+] Byte data saved to {output_prefix}_bytes.bin")

        # Try to save as text (UTF-8 with errors ignored)
        try:
            text = byte_data.decode('utf-8', errors='ignore')
            with open(f"{output_prefix}_text.txt", 'w', encoding='utf-8') as f:
                f.write(text)
            print(f"[+] Text data saved to {output_prefix}_text.txt")
        except:
            pass


def main():
    """
    Main function to run the steganography extractor.
    """
    print("="*60)
    print("STEGANOGRAPHY EXTRACTOR")
    print("="*60)

    # Check command line arguments
    if len(sys.argv) < 2:
        print(f"\nUsage: python {sys.argv[0]} <image_file>")
        print(f"\nExample: python {sys.argv[0]} hidden_message.png")
        sys.exit(1)

    image_path = sys.argv[1]

    # Check if file exists
    if not os.path.exists(image_path):
        print(f"[-] Error: File '{image_path}' not found")
        sys.exit(1)

    print(f"\n[+] Analyzing: {image_path}")

    # Step 1: Identify image format
    img_format = identify_image_format(image_path)

    if not img_format:
        print("[-] Failed to identify image format")
        sys.exit(1)

    # Step 2: Attempt LSB extraction (works for all formats)
    binary_data, byte_data = lsb_extract(image_path)

    # Step 3: Attempt DCT extraction (JPEG specific)
    if img_format in ['JPEG', 'JPG']:
        dct_extract_jpeg(image_path)
    else:
        print(f"\n[*] DCT extraction skipped (only applicable to JPEG images)")

    # Step 4: Save extracted data
    if binary_data and byte_data:
        print("\n" + "="*60)
        print("SAVING EXTRACTED DATA")
        print("="*60)
        base_name = os.path.splitext(os.path.basename(image_path))[0]
        save_extracted_data(binary_data, byte_data, f"{base_name}_extracted")

    print("\n" + "="*60)
    print("EXTRACTION COMPLETE")
    print("="*60)


if __name__ == "__main__":
    main()
