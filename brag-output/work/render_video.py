import os
import sys
import math
import subprocess
import numpy as np
from PIL import Image, ImageDraw, ImageFont, ImageFilter
import imageio
import imageio_ffmpeg

# Paths
BASE_DIR = r"d:\New folder"
OUTPUT_DIR = os.path.join(BASE_DIR, "brag-output")
WORK_DIR = os.path.join(OUTPUT_DIR, "work")
COMP_DIR = os.path.join(OUTPUT_DIR, "composition")
ASSETS_DIR = os.path.join(COMP_DIR, "assets")
MUSIC_PATH = os.path.join(ASSETS_DIR, "music", "music.mp3")
SFX_DIR = os.path.join(ASSETS_DIR, "sfx")

BANNER_PATH = os.path.join(BASE_DIR, "assets", "pixelpry_banner.jpg")
CAT_PATH = os.path.join(BASE_DIR, "wiki", "Steganography_original_extracted_cat.png")
ORIGINAL_IMG_PATH = os.path.join(BASE_DIR, "samples", "Steganography_original.png")
FLAG_IMG_PATH = os.path.join(BASE_DIR, "wiki", "challenge_flag.png")
CHALLENGE_REC_PATH = os.path.join(BASE_DIR, "ctf_challenges", "challenge_recovered.png")

FINAL_VIDEO_PATH = os.path.join(OUTPUT_DIR, "brag.mp4")
POSTER_PATH = os.path.join(OUTPUT_DIR, "brag.jpg")
AUDIO_MIX_PATH = os.path.join(WORK_DIR, "mixed_audio.aac")
TEMP_VIDEO_PATH = os.path.join(WORK_DIR, "video_no_audio.mp4")

# Specifications
WIDTH = 1920
HEIGHT = 1080
FPS = 30
TOTAL_FRAMES = 600  # 20.0 seconds
DURATION = 20.0

# Fonts
def get_font(name_or_file, size, bold=False):
    for fn in [name_or_file, "consola.ttf", "segoeuib.ttf" if bold else "segoeui.ttf", "arial.ttf"]:
        try:
            return ImageFont.truetype(fn, size)
        except Exception:
            continue
    return ImageFont.load_default()

FONT_MONO_14 = get_font("consola.ttf", 14)
FONT_MONO_16 = get_font("consola.ttf", 16)
FONT_MONO_18 = get_font("consola.ttf", 18)
FONT_MONO_20 = get_font("consola.ttf", 20)
FONT_MONO_22 = get_font("consola.ttf", 22)
FONT_MONO_26 = get_font("consola.ttf", 26)
FONT_MONO_32 = get_font("consola.ttf", 32)
FONT_MONO_38 = get_font("consola.ttf", 38, bold=True)
FONT_MONO_48 = get_font("consolab.ttf", 48, bold=True)

FONT_UI_16 = get_font("segoeui.ttf", 16)
FONT_UI_20 = get_font("segoeui.ttf", 20)
FONT_UI_24 = get_font("segoeuib.ttf", 24, bold=True)
FONT_UI_28 = get_font("segoeuib.ttf", 28, bold=True)
FONT_UI_36 = get_font("segoeuib.ttf", 36, bold=True)
FONT_UI_52 = get_font("segoeuib.ttf", 52, bold=True)
FONT_UI_68 = get_font("segoeuib.ttf", 68, bold=True)

# Color constants
C_BG = (8, 12, 20)
C_CARD_BG = (15, 23, 42)
C_CARD_BORDER = (30, 48, 80)
C_CYAN = (0, 216, 255)
C_GREEN = (0, 255, 163)
C_WHITE = (255, 255, 255)
C_SLATE = (148, 163, 184)
C_DARK_SLATE = (71, 85, 105)
C_RED = (255, 59, 92)
C_PURPLE = (168, 85, 247)
C_YELLOW = (250, 204, 21)
C_ORANGE = (251, 146, 60)

# Preload Images
img_banner = Image.open(BANNER_PATH).convert("RGB") if os.path.exists(BANNER_PATH) else None
img_cat = Image.open(CAT_PATH).convert("RGB") if os.path.exists(CAT_PATH) else None
img_original = Image.open(ORIGINAL_IMG_PATH).convert("RGB") if os.path.exists(ORIGINAL_IMG_PATH) else None
img_flag = Image.open(FLAG_IMG_PATH).convert("RGBA") if os.path.exists(FLAG_IMG_PATH) else None
img_challenge = Image.open(CHALLENGE_REC_PATH).convert("RGB") if os.path.exists(CHALLENGE_REC_PATH) else None

def ease_out_cubic(x):
    return 1.0 - math.pow(1.0 - min(max(x, 0.0), 1.0), 3)

def draw_card(draw, x, y, w, h, bg_color=C_CARD_BG, border_color=C_CARD_BORDER, radius=12, border_width=2):
    draw.rounded_rectangle([x, y, x + w, y + h], radius=radius, fill=bg_color, outline=border_color, width=border_width)

def draw_pill(draw, x, y, text, font, bg_color, text_color, pad_x=14, pad_y=6, radius=8):
    bbox = draw.textbbox((0, 0), text, font=font)
    tw = bbox[2] - bbox[0]
    th = bbox[3] - bbox[1]
    w = tw + pad_x * 2
    h = th + pad_y * 2
    draw.rounded_rectangle([x, y, x + w, y + h], radius=radius, fill=bg_color)
    draw.text((x + pad_x, y + pad_y - 1), text, font=font, fill=text_color)
    return w, h

def draw_hud_header(draw, frame_idx, t):
    # Top bar background
    draw.rectangle([0, 0, WIDTH, 54], fill=(11, 15, 25))
    draw.line([0, 54, WIDTH, 54], fill=(30, 48, 80), width=1)
    
    # Left logo/system
    draw.text((36, 16), "[ PIXELPRY // FORENSIC RECONNAISSANCE SUITE ]", font=FONT_MONO_18, fill=C_CYAN)
    
    # Center telemetry
    draw.text((700, 16), "STEGANOGRAPHY ANALYSIS & FORENSIC CARVING ENGINE", font=FONT_MONO_16, fill=C_SLATE)
    
    # Right recording / status
    rec_color = C_RED if (frame_idx // 15) % 2 == 0 else (120, 20, 30)
    draw.ellipse([1600, 22, 1612, 34], fill=rec_color)
    draw.text((1622, 16), f"REC // T: {t:05.2f}s | F: {frame_idx:03d}/600", font=FONT_MONO_16, fill=C_WHITE)

def draw_hud_footer(draw, frame_idx, t):
    # Bottom footer bar
    draw.rectangle([0, 1030, WIDTH, HEIGHT], fill=(11, 15, 25))
    draw.line([0, 1030, WIDTH, 1030], fill=(30, 48, 80), width=1)
    
    # Status ticker
    draw.text((36, 1046), "VECTOR ENGINES: SPATIAL LSB | TRANSFORM 2D-DCT | PNG CHUNK RECONSTRUCTION | 11-FORMAT CARVER", font=FONT_MONO_16, fill=C_SLATE)
    
    # Audio-reactive meters
    for i in range(14):
        bx = 1620 + i * 18
        freq = (i + 1) * 3.5
        bh = int(8 + 14 * abs(math.sin(t * freq + i * 0.5)))
        color = C_CYAN if i < 10 else C_GREEN
        draw.rectangle([bx, 1068 - bh, bx + 12, 1068], fill=color)

def draw_cyber_grid(draw, frame_idx):
    # Subtle cyber grid
    grid_spacing = 60
    for gx in range(0, WIDTH, grid_spacing):
        draw.line([gx, 55, gx, 1030], fill=(14, 20, 34), width=1)
    for gy in range(55, 1030, grid_spacing):
        draw.line([0, gy, WIDTH, gy], fill=(14, 20, 34), width=1)


# ==============================================================================
# SCENE 1: THE HOOK: BENEATH THE PIXELS (0.00s - 3.70s, Frames 0 - 110)
# ==============================================================================
def render_scene_1(frame_idx, t):
    img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
    draw = ImageDraw.Draw(img)
    draw_cyber_grid(draw, frame_idx)
    draw_hud_header(draw, frame_idx, t)
    draw_hud_footer(draw, frame_idx, t)
    
    # Left: Target Image Card
    card_x, card_y, card_w, card_h = 100, 110, 760, 880
    draw_card(draw, card_x, card_y, card_w, card_h, C_CARD_BG, (38, 56, 92), radius=16)
    
    draw.text((card_x + 36, card_y + 30), "TARGET CARRIER ANALYSIS // Steganography_original.png", font=FONT_MONO_22, fill=C_CYAN)
    draw.line([card_x + 36, card_y + 65, card_x + card_w - 36, card_y + 65], fill=(30, 48, 80), width=1)
    
    # Image container
    img_box_x, img_box_y = card_x + 70, card_y + 90
    img_size = 620
    draw.rectangle([img_box_x - 4, img_box_y - 4, img_box_x + img_size + 4, img_box_y + img_size + 4], fill=(20, 30, 50))
    
    if img_original:
        scaled_orig = img_original.resize((img_size, img_size), Image.Resampling.NEAREST)
        img.paste(scaled_orig, (img_box_x, img_box_y))
    
    # Laser scanline & Binary stream mask after t >= 1.60s (frame 48)
    if t >= 1.60:
        scan_progress = min((t - 1.60) / 1.50, 1.0)
        laser_y = int(img_box_y + scan_progress * img_size)
        
        # Binary stream overlay above laser
        revealed_h = laser_y - img_box_y
        if revealed_h > 0:
            bin_overlay = Image.new("RGBA", (img_size, revealed_h), (0, 20, 10, 210))
            b_draw = ImageDraw.Draw(bin_overlay)
            bits = "01001100 01101111 01110011 01110011 01101100 01100101 01110011 01110011 01001100 01010011 01000010 00100000"
            for row in range(0, revealed_h, 24):
                shift = (row // 24 + frame_idx) % len(bits)
                row_str = bits[shift:] + bits[:shift]
                b_draw.text((10, row + 2), row_str, font=FONT_MONO_16, fill=(0, 255, 163, 230))
            img.paste(bin_overlay, (img_box_x, img_box_y), bin_overlay)
        
        # Laser line
        draw.line([img_box_x - 10, laser_y, img_box_x + img_size + 10, laser_y], fill=C_CYAN, width=4)
        draw.line([img_box_x - 15, laser_y - 2, img_box_x + img_size + 15, laser_y - 2], fill=(255, 255, 255), width=2)
    
    # Metadata footer on card
    draw.text((card_x + 50, card_y + 740), "FORMAT: PNG 24-Bit RGB | DIMENSIONS: 200x200 | SIZE: 415 KB", font=FONT_MONO_18, fill=C_SLATE)
    draw.text((card_x + 50, card_y + 775), "SPATIAL BITPLANES: Red(8), Green(8), Blue(8) | CRC: 0x8C3B621C", font=FONT_MONO_18, fill=C_SLATE)
    draw_pill(draw, card_x + 50, card_y + 815, "CARRIER INTEGRITY: SUSPICIOUS LSB PATTERN", FONT_MONO_16, (40, 20, 25), C_RED)
    
    # Right: The Hook Typography
    right_x, right_y, right_w, right_h = 920, 110, 900, 880
    draw_card(draw, right_x, right_y, right_w, right_h, C_CARD_BG, (38, 56, 92), radius=16)
    
    draw.text((right_x + 48, right_y + 50), "FORENSIC REVEAL // SPATIAL DOMAIN", font=FONT_MONO_22, fill=C_GREEN)
    
    # Hook text animations
    draw.text((right_x + 48, right_y + 130), "THINK THIS IS", font=FONT_UI_52, fill=C_WHITE)
    draw.text((right_x + 48, right_y + 200), "JUST AN IMAGE?", font=FONT_UI_52, fill=C_WHITE)
    
    if t >= 1.20:
        draw.text((right_x + 48, right_y + 300), "LOOK CLOSER.", font=FONT_UI_68, fill=C_GREEN)
    
    if t >= 2.00:
        draw.line([right_x + 48, right_y + 400, right_x + right_w - 48, right_y + 400], fill=(30, 48, 80), width=2)
        
        draw.text((right_x + 48, right_y + 430), "Concealed beneath the RGB pixel grid:", font=FONT_UI_24, fill=C_SLATE)
        
        telemetry = [
            ("24-Bit Spatial LSB Stream", "ACTIVE BITSTREAM DETECTED", C_CYAN),
            ("Length Prefix Evaluation", "3,420 BYTES EMBEDDED", C_GREEN),
            ("Channel Allocation", "FLATTENED RGB PLANE EXTRACTION", C_WHITE),
            ("Shannon Diversity Metric", "H = 7.98 bits/byte (HIGH DENSITY)", C_PURPLE)
        ]
        
        ty = right_y + 485
        for label, val, col in telemetry:
            draw.text((right_x + 48, ty), f"► {label}:", font=FONT_MONO_22, fill=C_SLATE)
            draw.text((right_x + 440, ty), val, font=FONT_MONO_22, fill=col)
            ty += 52
        
        draw_pill(draw, right_x + 48, right_y + 740, "DEEP PAYLOAD RECONSTRUCTION ENGAGED", FONT_MONO_22, (10, 40, 30), C_GREEN, pad_x=24, pad_y=12)
    
    return img


# ==============================================================================
# SCENE 2: THE CORE ENGINE: MULTI-DOMAIN FORENSICS (3.70s - 8.96s, Frames 111 - 268)
# ==============================================================================
def render_scene_2(frame_idx, t):
    img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
    draw = ImageDraw.Draw(img)
    draw_cyber_grid(draw, frame_idx)
    draw_hud_header(draw, frame_idx, t)
    draw_hud_footer(draw, frame_idx, t)
    
    # Title Header
    draw.text((100, 85), "PIXELPRY FORENSIC ENGINE // 4-TIER MULTI-DOMAIN AUDIT", font=FONT_UI_36, fill=C_WHITE)
    draw.text((100, 135), "Simultaneous inspection across container headers, spatial channels, DCT frequencies, and entropy heuristics", font=FONT_MONO_18, fill=C_SLATE)
    
    cards = [
        {
            "id": "01",
            "title": "MAGIC BYTES VERIFICATION",
            "target": "Raw File Signature Header",
            "body": "Reads binary magic bytes directly to identify true file type rather than trusting spoofed extensions.\n\nValidated Signatures:\n• PNG:  \\x89PNG\\r\\n\\x1a\\n\n• JPEG: \\xff\\xd8\\xff\n• BMP:  BM (Windows Bitmap)",
            "pill": "HEADER SIGNATURE: VALIDATED",
            "pill_col": C_GREEN,
            "x": 100, "y": 180, "w": 830, "h": 380,
            "start_t": 3.70
        },
        {
            "id": "02",
            "title": "SPATIAL-DOMAIN LSB ANALYSIS",
            "target": "RGB/RGBA 24-Bit Planes",
            "body": "Extracts bitstream sequences from flattened channel arrays.\n\nEvaluation Vectors:\n• Big-Endian 32-bit length prefixes for exact-payload carving\n• Sequential ASCII evaluation with letter-frequency heuristics\n• Multi-channel isolation (Red, Green, Blue, Alpha)",
            "pill": "3,420 BYTE PAYLOAD CARVED",
            "pill_col": C_CYAN,
            "x": 990, "y": 180, "w": 830, "h": 380,
            "start_t": 4.75
        },
        {
            "id": "03",
            "title": "TRANSFORM-DOMAIN 2D-DCT",
            "target": "8x8 JPEG Block Frequency Coefficients",
            "body": "Transforms luminance matrices into frequency space using 2D-DCT (scipy.fftpack.dct).\n\nFrequency Analysis:\n• Evaluates mid-frequency AC coefficient LSBs\n• Mirrored Jsteg embedding detection\n• Frequency distribution anomaly identification",
            "pill": "AC-LSB EMBEDDINGS LOCKED",
            "pill_col": C_PURPLE,
            "x": 100, "y": 590, "w": 830, "h": 380,
            "start_t": 5.80
        },
        {
            "id": "04",
            "title": "SHANNON ENTROPY & HEURISTICS",
            "target": "False-Positive Elimination Engine",
            "body": "Filters out compression noise and uniform color bitplane artifacts.\n\nFiltering Metrics:\n• Shannon Diversity: H = -sum(p * log2(p))\n• Single-character noise suppression\n• Chi-square randomness verification",
            "pill": "ZERO FALSE POSITIVES",
            "pill_col": C_GREEN,
            "x": 990, "y": 590, "w": 830, "h": 380,
            "start_t": 6.86
        }
    ]
    
    for c in cards:
        if t >= c["start_t"]:
            progress = ease_out_cubic((t - c["start_t"]) / 0.35)
            alpha_y = int(c["y"] + (1.0 - progress) * 30)
            
            draw_card(draw, c["x"], alpha_y, c["w"], c["h"], C_CARD_BG, (38, 56, 92), radius=14)
            
            # Header
            draw.text((c["x"] + 28, alpha_y + 24), f"{c['id']} // {c['title']}", font=FONT_UI_24, fill=C_CYAN)
            draw.text((c["x"] + 28, alpha_y + 60), f"Target: {c['target']}", font=FONT_MONO_16, fill=C_SLATE)
            draw.line([c["x"] + 28, alpha_y + 88, c["x"] + c["w"] - 28, alpha_y + 88], fill=(30, 48, 80), width=1)
            
            # Body lines
            by = alpha_y + 105
            for line in c["body"].split("\n"):
                if line.startswith("•"):
                    draw.text((c["x"] + 40, by), line, font=FONT_MONO_18, fill=C_WHITE)
                elif ":" in line:
                    draw.text((c["x"] + 28, by), line, font=FONT_MONO_18, fill=C_CYAN)
                else:
                    draw.text((c["x"] + 28, by), line, font=FONT_MONO_18, fill=C_SLATE)
                by += 28
            
            # Pill badge
            draw_pill(draw, c["x"] + 28, alpha_y + c["h"] - 55, c["pill"], FONT_MONO_16, (15, 35, 30), c["pill_col"], pad_x=16, pad_y=8)
    
    return img


# ==============================================================================
# SCENE 3: THE DISCOVERY: 11 NATIVE FORMATS REVEALED (8.96s - 13.70s, Frames 269 - 410)
# ==============================================================================
def render_scene_3(frame_idx, t):
    img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
    draw = ImageDraw.Draw(img)
    draw_cyber_grid(draw, frame_idx)
    draw_hud_header(draw, frame_idx, t)
    draw_hud_footer(draw, frame_idx, t)
    
    # Title
    draw.text((100, 85), "PAYLOAD EXTRACTION // TRUE-FORMAT RECONSTITUTION", font=FONT_UI_36, fill=C_WHITE)
    draw.text((100, 135), "PixelPry automatically carves raw bitstreams and converts them into native, runnable files", font=FONT_MONO_18, fill=C_SLATE)
    
    # Left Box: Visual Bitplane Separation
    left_x, left_y, left_w, left_h = 100, 180, 820, 810
    draw_card(draw, left_x, left_y, left_w, left_h, C_CARD_BG, (38, 56, 92), radius=16)
    
    draw.text((left_x + 32, left_y + 24), "VISUAL BIT-PLANE SEPARATION", font=FONT_UI_28, fill=C_GREEN)
    draw.text((left_x + 32, left_y + 64), "Extracting 2-Bit concealed visual layer: (arr & 3) * 85", font=FONT_MONO_18, fill=C_SLATE)
    draw.line([left_x + 32, left_y + 98, left_x + left_w - 32, left_y + 98], fill=(30, 48, 80), width=1)
    
    # Previews side-by-side
    prev_size = 320
    px1, py1 = left_x + 40, left_y + 130
    px2, py2 = left_x + 460, left_y + 130
    
    draw.rectangle([px1 - 4, py1 - 4, px1 + prev_size + 4, py1 + prev_size + 4], fill=(20, 30, 50))
    if img_original:
        scaled_orig = img_original.resize((prev_size, prev_size), Image.Resampling.NEAREST)
        img.paste(scaled_orig, (px1, py1))
    draw.text((px1 + 50, py1 + prev_size + 15), "ORIGINAL CARRIER", font=FONT_MONO_18, fill=C_SLATE)
    draw.text((px1 + 75, py1 + prev_size + 40), "[ 200x200 PNG ]", font=FONT_MONO_16, fill=C_DARK_SLATE)
    
    # Arrow
    draw.text((left_x + 385, py1 + 130), "►►", font=FONT_UI_36, fill=C_CYAN)
    
    draw.rectangle([px2 - 4, py2 - 4, px2 + prev_size + 4, py2 + prev_size + 4], fill=(20, 30, 50))
    if img_cat:
        scaled_cat = img_cat.resize((prev_size, prev_size), Image.Resampling.NEAREST)
        img.paste(scaled_cat, (px2, py2))
    draw.text((px2 + 35, py2 + prev_size + 15), "EXTRACTED PAYLOAD", font=FONT_MONO_18, fill=C_GREEN)
    draw.text((px2 + 60, py2 + prev_size + 40), "[ SECRET CAT PHOTO ]", font=FONT_MONO_16, fill=C_CYAN)
    
    # Forensic note below images
    draw_card(draw, left_x + 32, left_y + 550, left_w - 64, 220, (11, 18, 32), (30, 48, 80), radius=12)
    draw.text((left_x + 55, left_y + 575), "FORENSIC DISCOVERY:", font=FONT_MONO_22, fill=C_GREEN)
    draw.text((left_x + 55, left_y + 615), "The original cover image appeared completely benign.", font=FONT_MONO_18, fill=C_WHITE)
    draw.text((left_x + 55, left_y + 645), "PixelPry isolated the lowest 2 bits across all RGB channels,", font=FONT_MONO_18, fill=C_SLATE)
    draw.text((left_x + 55, left_y + 675), "reconstructing the hidden photograph in full 8-bit contrast.", font=FONT_MONO_18, fill=C_SLATE)
    draw_pill(draw, left_x + 55, left_y + 715, "STEGANOGRAPHY CLASS: 2-BIT SPATIAL VISUAL LSB", FONT_MONO_16, (20, 35, 45), C_CYAN)
    
    # Right Box: Multi-Format Converter Badges
    right_x, right_y, right_w, right_h = 960, 180, 860, 810
    draw_card(draw, right_x, right_y, right_w, right_h, C_CARD_BG, (38, 56, 92), radius=16)
    
    draw.text((right_x + 32, right_y + 24), "NATIVE MULTI-FORMAT CARVER", font=FONT_UI_28, fill=C_CYAN)
    draw.text((right_x + 32, right_y + 64), "Instant conversion of decoded bitstreams into true native files:", font=FONT_MONO_18, fill=C_SLATE)
    draw.line([right_x + 32, right_y + 98, right_x + right_w - 32, right_y + 98], fill=(30, 48, 80), width=1)
    
    badges = [
        (".PNG", "Embedded Raster Images & Photo Payloads", C_CYAN, 8.96),
        (".WAV", "Steganographic Audio Streams & Carriers", C_PURPLE, 9.50),
        (".ZIP", "Compressed PKZip Archive File Containers", C_ORANGE, 10.01),
        (".PEM", "RSA Private & Public Cryptographic Keys", C_GREEN, 10.54),
        (".JSON", "Structured Forensic Data & Configurations", C_YELLOW, 11.06),
        (".PY", "Executable Python Source Code Scripts", (56, 189, 248), 11.60),
        (".TXT", "Recovered Human-Readable Plaintext", C_SLATE, 12.12),
    ]
    
    by = right_y + 120
    for ext, desc, col, bt in badges:
        if t >= bt:
            draw_card(draw, right_x + 32, by, right_w - 64, 60, (18, 26, 44), (35, 52, 85), radius=10)
            draw_pill(draw, right_x + 48, by + 12, ext, FONT_MONO_22, (25, 35, 60), col, pad_x=16, pad_y=4)
            draw.text((right_x + 175, by + 18), desc, font=FONT_MONO_20, fill=C_WHITE)
            draw.text((right_x + right_w - 120, by + 20), "RECOVERED", font=FONT_MONO_14, fill=C_GREEN)
        by += 72
    
    # Verification confirmation
    if t >= 12.65:
        draw_card(draw, right_x + 32, right_y + 660, right_w - 64, 110, (10, 35, 25), (0, 255, 163), radius=12)
        draw.text((right_x + 55, right_y + 685), "✓ FORENSIC BENCHMARK VALIDATED", font=FONT_UI_24, fill=C_GREEN)
        draw.text((right_x + 55, right_y + 725), "All 11 sample test carrier fixtures verified byte-for-byte.", font=FONT_MONO_18, fill=C_WHITE)
    
    return img


# ==============================================================================
# SCENE 4: BINARY CHUNK REPAIR & CTF FLAG (13.70s - 17.91s, Frames 411 - 537)
# ==============================================================================
def render_scene_4(frame_idx, t):
    img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
    draw = ImageDraw.Draw(img)
    draw_cyber_grid(draw, frame_idx)
    draw_hud_header(draw, frame_idx, t)
    draw_hud_footer(draw, frame_idx, t)
    
    draw.text((100, 85), "BYTE MAIT RECRUITMENT TASK // PNG CHUNK RECONSTRUCTION", font=FONT_UI_36, fill=C_WHITE)
    draw.text((100, 135), "Real-world CTF forensic reconstruction of intentionally corrupted image container", font=FONT_MONO_18, fill=C_SLATE)
    
    # Left: Corrupted Challenge File Card
    left_x, left_y, left_w, left_h = 100, 180, 780, 810
    draw_card(draw, left_x, left_y, left_w, left_h, C_CARD_BG, (38, 56, 92), radius=16)
    
    draw.text((left_x + 32, left_y + 24), "CHALLENGE TARGET: challenge.png", font=FONT_UI_28, fill=C_CYAN)
    draw.text((left_x + 32, left_y + 64), "Size: 415,143 bytes | Status: Initial Load Failed", font=FONT_MONO_18, fill=C_SLATE)
    draw.line([left_x + 32, left_y + 98, left_x + left_w - 32, left_y + 98], fill=(30, 48, 80), width=1)
    
    # Image frame: expands from 800 to 850 in height between 15.8s and 17.0s
    disp_w = 480
    if t < 15.8:
        disp_h = 530  # represents 800 rows
    else:
        expand_p = min((t - 15.8) / 1.2, 1.0)
        disp_h = int(530 + expand_p * 35)  # reveals 850 rows
    
    ix, iy = left_x + 150, left_y + 130
    draw.rectangle([ix - 4, iy - 4, ix + disp_w + 4, iy + 565 + 4], fill=(20, 30, 50))
    
    if img_challenge:
        # Crop based on rows
        crop_h = 800 if t < 15.8 else int(800 + (t - 15.8) / 1.2 * 50)
        crop_h = min(crop_h, 850)
        cropped_c = img_challenge.crop((0, 0, 724, crop_h))
        scaled_c = cropped_c.resize((disp_w, int(crop_h * 565 / 850)), Image.Resampling.BILINEAR)
        img.paste(scaled_c, (ix, iy))
    
    if t < 15.0:
        # Alert Box
        draw_card(draw, left_x + 32, left_y + 570, left_w - 64, 180, (40, 15, 20), C_RED, radius=12)
        draw.text((left_x + 55, left_y + 595), "[!] CRITICAL CONTAINER ERROR", font=FONT_MONO_22, fill=C_RED)
        draw.text((left_x + 55, left_y + 635), "cannot identify image file 'challenge.png'", font=FONT_MONO_18, fill=C_WHITE)
        draw.text((left_x + 55, left_y + 665), "IHDR CRC Mismatch: Expected 0xcad1ced6 != Calculated 0x8c3b621c", font=FONT_MONO_16, fill=C_SLATE)
        draw.text((left_x + 55, left_y + 695), "12 extraneous corrupting bytes injected at offset 196677", font=FONT_MONO_16, fill=C_SLATE)
    else:
        # Repaired Box
        draw_card(draw, left_x + 32, left_y + 570, left_w - 64, 180, (10, 35, 25), C_GREEN, radius=12)
        draw.text((left_x + 55, left_y + 595), "[+] FORENSIC RECONSTRUCTION COMPLETED", font=FONT_MONO_22, fill=C_GREEN)
        draw.text((left_x + 55, left_y + 635), "• Stripped 12 extraneous corrupting bytes between IDAT chunks", font=FONT_MONO_16, fill=C_WHITE)
        draw.text((left_x + 55, left_y + 665), "• Solved IHDR CRC: Brute-forced true height (724x800 -> 724x850)", font=FONT_MONO_16, fill=C_WHITE)
        draw.text((left_x + 55, left_y + 695), "• 50 hidden bottom scanlines unlocked revealing flag banner!", font=FONT_MONO_16, fill=C_CYAN)
    
    # Right Stage: Flag Extraction & Climax
    right_x, right_y, right_w, right_h = 920, 180, 900, 810
    draw_card(draw, right_x, right_y, right_w, right_h, C_CARD_BG, (38, 56, 92), radius=16)
    
    draw.text((right_x + 36, right_y + 24), "RECONSTRUCTED ARTIFACTS & PAYLOAD", font=FONT_UI_28, fill=C_GREEN)
    draw.text((right_x + 36, right_y + 64), "Unveiling the hidden forensic payload in the bottom canvas rows:", font=FONT_MONO_18, fill=C_SLATE)
    draw.line([right_x + 36, right_y + 98, right_x + right_w - 36, right_y + 98], fill=(30, 48, 80), width=1)
    
    # Flag Banner Graphic
    draw.text((right_x + 36, right_y + 130), "RECOVERED IMAGE FOOTER BANNER:", font=FONT_MONO_20, fill=C_CYAN)
    
    if img_flag:
        flag_scaled = img_flag.resize((820, 56), Image.Resampling.BILINEAR)
        img.paste(flag_scaled, (right_x + 36, right_y + 170), flag_scaled)
    
    # Big Climax Flag Box
    draw_card(draw, right_x + 36, right_y + 270, right_w - 72, 380, (10, 24, 38), C_GREEN, radius=16, border_width=3)
    
    draw.text((right_x + 65, right_y + 310), "CTF FLAG CAPTURED // BYTE MAIT TASK 02", font=FONT_MONO_22, fill=C_CYAN)
    
    # Massive Glowing Flag Text
    draw.text((right_x + 65, right_y + 370), "BYTE{g0t_1t_1n_plA1n_s1ght}", font=FONT_MONO_38, fill=C_GREEN)
    
    draw.line([right_x + 65, right_y + 450, right_x + right_w - 105, right_y + 450], fill=(30, 48, 80), width=1)
    
    draw.text((right_x + 65, right_y + 480), "Forensic Translation:", font=FONT_MONO_20, fill=C_SLATE)
    draw.text((right_x + 65, right_y + 515), "flag{g0t_1t_1n_plA1n_s1ght}  ──►  BYTE{g0t_1t_1n_plA1n_s1ght}", font=FONT_MONO_20, fill=C_WHITE)
    draw.text((right_x + 65, right_y + 555), "Verified against official challenge scoreboard.", font=FONT_MONO_18, fill=C_SLATE)
    
    draw_pill(draw, right_x + 36, right_y + 700, "100% CTF CHALLENGE SOLVED & VERIFIED", FONT_MONO_22, (15, 45, 30), C_GREEN, pad_x=24, pad_y=12)
    
    return img


# ==============================================================================
# SCENE 5: OUTRO & PUNCHLINE: NOTHING STAYS HIDDEN (17.91s - 20.00s, Frames 538 - 599)
# ==============================================================================
def render_scene_5(frame_idx, t):
    img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
    draw = ImageDraw.Draw(img)
    draw_cyber_grid(draw, frame_idx)
    draw_hud_header(draw, frame_idx, t)
    draw_hud_footer(draw, frame_idx, t)
    
    # Center Banner
    bw, bh = 1100, 480
    bx, by = (WIDTH - bw) // 2, 110
    
    if img_banner:
        banner_scaled = img_banner.resize((bw, bh), Image.Resampling.BILINEAR)
        img.paste(banner_scaled, (bx, by))
        draw.rounded_rectangle([bx - 2, by - 2, bx + bw + 2, by + bh + 2], radius=12, outline=C_CYAN, width=3)
    
    # Typography below banner
    draw.text((WIDTH // 2 - 250, by + bh + 35), "P I X E L P R Y", font=FONT_UI_52, fill=C_CYAN)
    
    draw.text((WIDTH // 2 - 470, by + bh + 110), "Steganography Analysis, Extraction & Forensic Recovery Suite", font=FONT_UI_28, fill=C_WHITE)
    
    draw.text((WIDTH // 2 - 340, by + bh + 165), "INNOCENT PIXELS. ZERO SECRETS.", font=FONT_UI_36, fill=C_GREEN)
    
    # Badges
    pills = [
        "CLI & Standalone Windows EXE",
        "github.com/skshmnarang/PixelPry",
        "MIT Open Source License"
    ]
    px = WIDTH // 2 - 440
    for p in pills:
        pw, _ = draw_pill(draw, px, by + bh + 240, p, FONT_MONO_18, (18, 28, 50), C_WHITE, pad_x=18, pad_y=8)
        px += pw + 24
    
    return img


# ==============================================================================
# MASTER RENDERER DISPATCH
# ==============================================================================
def render_frame(frame_idx):
    t = frame_idx / float(FPS)
    if frame_idx < 111:       # 0.00s - 3.70s
        return render_scene_1(frame_idx, t)
    elif frame_idx < 269:     # 3.70s - 8.96s
        return render_scene_2(frame_idx, t)
    elif frame_idx < 411:     # 8.96s - 13.70s
        return render_scene_3(frame_idx, t)
    elif frame_idx < 538:     # 13.70s - 17.91s
        return render_scene_4(frame_idx, t)
    else:                     # 17.91s - 20.00s
        return render_scene_5(frame_idx, t)


# ==============================================================================
# AUDIO MIXING PIPELINE
# ==============================================================================
def mix_audio():
    print("[*] Mixing music and SFX audio tracks using FFmpeg...")
    ffmpeg_exe = imageio_ffmpeg.get_ffmpeg_exe()
    
    sfx_switch1 = os.path.join(SFX_DIR, "switch1.ogg")
    sfx_glitch = os.path.join(SFX_DIR, "glitch_002.ogg")
    sfx_click1 = os.path.join(SFX_DIR, "click1.ogg")
    sfx_click2 = os.path.join(SFX_DIR, "click2.ogg")
    sfx_error = os.path.join(SFX_DIR, "error_005.ogg")
    sfx_drop = os.path.join(SFX_DIR, "drop_001.ogg")
    sfx_switch2 = os.path.join(SFX_DIR, "switch2.ogg")
    
    filter_complex = (
        "[0:a]atrim=0:20,afade=t=out:st=19.0:d=1.0,volume=0.85[music];"
        "[1:a]adelay=100|100,volume=0.5[s1];"
        "[2:a]adelay=1600|1600,volume=0.6[s2];"
        "[3:a]adelay=4230|4230,volume=0.4[s3];"
        "[4:a]adelay=8960|8960,volume=0.5[s4];"
        "[5:a]adelay=13750|13750,volume=0.6[s5];"
        "[6:a]adelay=15800|15800,volume=0.5[s6];"
        "[7:a]adelay=17910|17910,volume=0.7[s7];"
        "[music][s1][s2][s3][s4][s5][s6][s7]amix=inputs=8:duration=first:dropout_transition=2[outa]"
    )
    cmd = [
        ffmpeg_exe, "-y",
        "-i", MUSIC_PATH,
        "-i", sfx_switch1,
        "-i", sfx_glitch,
        "-i", sfx_click1,
        "-i", sfx_click2,
        "-i", sfx_error,
        "-i", sfx_drop,
        "-i", sfx_switch2,
        "-filter_complex", filter_complex,
        "-map", "[outa]",
        "-c:a", "aac",
        "-b:a", "192k",
        AUDIO_MIX_PATH
    ]
    
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print("[-] FFmpeg audio mix error:", res.stderr)
        raise RuntimeError("Audio mix failed")
    print(f"[+] Audio successfully mixed and saved to: {AUDIO_MIX_PATH}")


# ==============================================================================
# MAIN RENDER LOOP
# ==============================================================================
def main():
    print("=" * 70)
    print(" PixelPry /brag Video Synthesis & Render Pipeline")
    print("=" * 70)
    print(f"[*] Canvas: {WIDTH}x{HEIGHT} @ {FPS} fps | Total Frames: {TOTAL_FRAMES} ({DURATION}s)")
    print(f"[*] Output video path: {FINAL_VIDEO_PATH}")
    print(f"[*] Output poster path: {POSTER_PATH}")
    print("-" * 70)
    
    # 1. Mix Audio
    mix_audio()
    
    # 2. Extract and save poster frame from Scene 5 (Frame 560)
    print("[*] Generating high-resolution poster frame (Frame 560)...")
    poster_img = render_frame(560)
    poster_img.save(POSTER_PATH, "JPEG", quality=95)
    print(f"[+] Poster successfully saved to: {POSTER_PATH}")
    
    # 3. Render all 600 frames to temporary video
    print("[*] Rendering 600 video frames...")
    writer = imageio.get_writer(
        TEMP_VIDEO_PATH,
        fps=FPS,
        codec="libx264",
        quality=8,
        macro_block_size=None,
        ffmpeg_params=["-pix_fmt", "yuv420p"]
    )
    
    for f in range(TOTAL_FRAMES):
        if f == 0:
            # Bake poster frame as frame 0 for platform idle thumbnail
            frame_img = poster_img
        else:
            frame_img = render_frame(f)
        
        writer.append_data(np.array(frame_img))
        
        if (f + 1) % 60 == 0 or f == TOTAL_FRAMES - 1:
            print(f"    Progress: {f + 1} / {TOTAL_FRAMES} frames rendered ({(f + 1) / FPS:.1f}s / {DURATION}s)...")
    
    writer.close()
    print(f"[+] Raw video rendered to: {TEMP_VIDEO_PATH}")
    
    # 4. Mux Video + Mixed Audio into final brag.mp4
    print("[*] Muxing video with mixed audio stream...")
    ffmpeg_exe = imageio_ffmpeg.get_ffmpeg_exe()
    cmd = [
        ffmpeg_exe, "-y",
        "-i", TEMP_VIDEO_PATH,
        "-i", AUDIO_MIX_PATH,
        "-c:v", "copy",
        "-c:a", "copy",
        FINAL_VIDEO_PATH
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print("[-] Muxing error:", res.stderr)
        raise RuntimeError("Video muxing failed")
    
    print("=" * 70)
    print(f"[+] SUCCESS! Video rendered and delivered to:")
    print(f"    VIDEO:  {FINAL_VIDEO_PATH}")
    print(f"    POSTER: {POSTER_PATH}")
    print("=" * 70)

if __name__ == "__main__":
    main()
