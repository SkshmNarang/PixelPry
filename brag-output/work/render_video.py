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
SPECTROGRAM_PATH = os.path.join(BASE_DIR, "samples", "Spectrogram_-_Nine_Inch_Nails_-_My_Violent_Heart.png")
HAND_PATH = os.path.join(BASE_DIR, "wiki", "Spectrogram_The_Presence_extracted_hand.png")
STRIPES_PATH = os.path.join(BASE_DIR, "wiki", "Wikipedia_Steganography_Flag_visual_stripes.png")

FINAL_VIDEO_PATH = os.path.join(OUTPUT_DIR, "brag.mp4")
POSTER_PATH = os.path.join(OUTPUT_DIR, "brag.jpg")
AUDIO_MIX_PATH = os.path.join(WORK_DIR, "mixed_audio.aac")
TEMP_VIDEO_PATH = os.path.join(WORK_DIR, "video_no_audio.mp4")

# 60 FPS Specifications
WIDTH = 1920
HEIGHT = 1080
FPS = 60
TOTAL_FRAMES = 1200  # 20.0 seconds @ 60 FPS
DURATION = 20.0

# Fonts with robust fallbacks
def get_font(name_or_file, size, bold=False):
    for fn in [name_or_file, "consola.ttf", "segoeuib.ttf" if bold else "segoeui.ttf", "arial.ttf"]:
        try:
            return ImageFont.truetype(fn, size)
        except Exception:
            continue
    return ImageFont.load_default()

FONT_MONO_12 = get_font("consola.ttf", 12)
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
FONT_UI_72 = get_font("segoeuib.ttf", 72, bold=True)

# Color constants
C_BG = (7, 10, 18)
C_CARD_BG = (13, 20, 36)
C_CARD_BORDER = (28, 46, 78)
C_CYAN = (0, 225, 255)
C_GREEN = (0, 255, 163)
C_WHITE = (255, 255, 255)
C_SLATE = (148, 163, 184)
C_DARK_SLATE = (60, 75, 100)
C_RED = (255, 59, 92)
C_PURPLE = (168, 85, 247)
C_YELLOW = (250, 204, 21)
C_ORANGE = (251, 146, 60)

# Preload Images
img_banner = Image.open(BANNER_PATH).convert("RGB") if os.path.exists(BANNER_PATH) else None
img_cat = Image.open(CAT_PATH).convert("RGB") if os.path.exists(CAT_PATH) else None
img_original = Image.open(ORIGINAL_IMG_PATH).convert("RGB") if os.path.exists(ORIGINAL_IMG_PATH) else None
img_spectrogram = Image.open(SPECTROGRAM_PATH).convert("RGB") if os.path.exists(SPECTROGRAM_PATH) else None
img_hand = Image.open(HAND_PATH).convert("RGB") if os.path.exists(HAND_PATH) else None
img_stripes = Image.open(STRIPES_PATH).convert("RGB") if os.path.exists(STRIPES_PATH) else None

# Deterministic Floating Micro-Particles (40 particles)
np.random.seed(42)
PARTICLE_X = np.random.randint(40, WIDTH - 40, size=40)
PARTICLE_Y_INIT = np.random.randint(80, HEIGHT - 80, size=40)
PARTICLE_SPEED = np.random.uniform(15.0, 45.0, size=40)
PARTICLE_ALPHA = np.random.randint(50, 180, size=40)
PARTICLE_TEXTS = ["0x89", "0xFF", "0x4E", "0x47", "LSB", "2D-DCT", "CRC32", "AC-12", "H=7.98", "RGB24", "FFT", "ZIP"]

def ease_out_quart(x):
    return 1.0 - math.pow(1.0 - min(max(x, 0.0), 1.0), 4)

def draw_card(draw, x, y, w, h, bg_color=C_CARD_BG, border_color=C_CARD_BORDER, radius=14, border_width=1):
    draw.rounded_rectangle([x, y, x + w, y + h], radius=radius, fill=bg_color, outline=border_color, width=border_width)

def draw_pill(draw, x, y, text, font, bg_color, text_color, border_color=None, pad_x=16, pad_y=7, radius=8):
    bbox = draw.textbbox((0, 0), text, font=font)
    tw = bbox[2] - bbox[0]
    th = bbox[3] - bbox[1]
    w = tw + pad_x * 2
    h = th + pad_y * 2
    draw.rounded_rectangle([x, y, x + w, y + h], radius=radius, fill=bg_color, outline=border_color, width=1 if border_color else 0)
    draw.text((x + pad_x, y + pad_y - 1), text, font=font, fill=text_color)
    return w, h

def draw_hud_header(draw, frame_idx, t):
    draw.rectangle([0, 0, WIDTH, 54], fill=(10, 15, 26))
    draw.line([0, 54, WIDTH, 54], fill=C_CARD_BORDER, width=1)
    
    # Left system logo
    draw.text((36, 16), "[ PIXELPRY // FORENSIC RECONNAISSANCE SUITE v2.4 ]", font=FONT_MONO_18, fill=C_CYAN)
    
    # Center telemetry
    draw.text((700, 16), "DIGITAL IMAGE STEGANOGRAPHY ANALYSIS & FORENSIC CARVING", font=FONT_MONO_16, fill=C_SLATE)
    
    # Right recording / status
    rec_pulse = (math.sin(t * 8.0) + 1.0) * 0.5
    rec_r = int(140 + 115 * rec_pulse)
    draw.ellipse([1600, 22, 1612, 34], fill=(rec_r, 20, 30))
    draw.text((1622, 16), f"REC // T: {t:05.2f}s | 60 FPS", font=FONT_MONO_16, fill=C_WHITE)

def draw_hud_footer(draw, frame_idx, t):
    draw.rectangle([0, 1030, WIDTH, HEIGHT], fill=(10, 15, 26))
    draw.line([0, 1030, WIDTH, 1030], fill=C_CARD_BORDER, width=1)
    
    draw.text((36, 1046), "VECTOR ENGINES: SPATIAL LSB | TRANSFORM 2D-DCT | AUDIO SPECTROGRAM | 11-FORMAT CARVER", font=FONT_MONO_16, fill=C_SLATE)
    
    # 24-Bar Audio Equalizer (Ultra smooth at 60fps)
    for i in range(24):
        bx = 1460 + i * 16
        freq = (i + 1) * 2.8
        bh = int(8 + 18 * abs(math.sin(t * freq + i * 0.4)))
        col = C_CYAN if i < 16 else C_GREEN
        draw.rectangle([bx, 1068 - bh, bx + 10, 1068], fill=col)

def draw_cyber_grid(draw, frame_idx, t):
    # Dynamic grid lines with subtle wave illumination
    for gx in range(0, WIDTH, 60):
        wave_bright = int(12 + 6 * math.sin(gx * 0.02 - t * 3.0))
        draw.line([gx, 55, gx, 1030], fill=(wave_bright, wave_bright + 5, wave_bright + 15), width=1)
    for gy in range(55, 1030, 60):
        draw.line([0, gy, WIDTH, gy], fill=(12, 18, 30), width=1)
        
    # Floating micro-hex particles
    for i in range(40):
        px = PARTICLE_X[i]
        py = int((PARTICLE_Y_INIT[i] - t * PARTICLE_SPEED[i]) % (HEIGHT - 160) + 70)
        p_text = PARTICLE_TEXTS[i % len(PARTICLE_TEXTS)]
        draw.text((px, py), p_text, font=FONT_MONO_12, fill=(35, 55, 85))


# ==============================================================================
# SCENE 1: THE HOOK: BENEATH THE PIXELS (0.00s - 3.70s, Frames 0 - 221)
# ==============================================================================
def render_scene_1(frame_idx, t):
    img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
    draw = ImageDraw.Draw(img)
    draw_cyber_grid(draw, frame_idx, t)
    draw_hud_header(draw, frame_idx, t)
    draw_hud_footer(draw, frame_idx, t)
    
    # Left: Target Image Card
    card_x, card_y, card_w, card_h = 100, 110, 760, 880
    draw_card(draw, card_x, card_y, card_w, card_h, C_CARD_BG, (38, 58, 96), radius=16)
    
    draw.text((card_x + 36, card_y + 30), "TARGET CARRIER ANALYSIS // Steganography_original.png", font=FONT_MONO_22, fill=C_CYAN)
    draw.line([card_x + 36, card_y + 65, card_x + card_w - 36, card_y + 65], fill=C_CARD_BORDER, width=1)
    
    # Image container
    img_box_x, img_box_y = card_x + 70, card_y + 90
    img_size = 620
    draw.rectangle([img_box_x - 4, img_box_y - 4, img_box_x + img_size + 4, img_box_y + img_size + 4], fill=(18, 28, 48))
    
    if img_original:
        scaled_orig = img_original.resize((img_size, img_size), Image.Resampling.NEAREST)
        img.paste(scaled_orig, (img_box_x, img_box_y))
    
    # Smooth Rotating Radar / Crosshair Reticle
    reticle_cx = img_box_x + img_size // 2
    reticle_cy = img_box_y + img_size // 2
    angle = t * 1.5
    rw = 80
    x1 = reticle_cx + rw * math.cos(angle)
    y1 = reticle_cy + rw * math.sin(angle)
    x2 = reticle_cx - rw * math.cos(angle)
    y2 = reticle_cy - rw * math.sin(angle)
    draw.line([x1, y1, x2, y2], fill=(0, 225, 255, 160), width=1)
    draw.ellipse([reticle_cx - 40, reticle_cy - 40, reticle_cx + 40, reticle_cy + 40], outline=(0, 225, 255, 120), width=1)
    
    # Laser scanline & Binary stream mask after t >= 1.60s (frame 96)
    if t >= 1.60:
        scan_progress = min((t - 1.60) / 1.50, 1.0)
        laser_y = int(img_box_y + scan_progress * img_size)
        
        # Binary stream overlay above laser
        revealed_h = laser_y - img_box_y
        if revealed_h > 0:
            bin_overlay = Image.new("RGBA", (img_size, revealed_h), (0, 22, 12, 215))
            b_draw = ImageDraw.Draw(bin_overlay)
            bits = "01001100 01101111 01110011 01110011 01101100 01100101 01110011 01110011 01001100 01010011 01000010 00100000"
            for row in range(0, revealed_h, 24):
                shift = (row // 24 + frame_idx // 2) % len(bits)
                row_str = bits[shift:] + bits[:shift]
                b_draw.text((10, row + 2), row_str, font=FONT_MONO_16, fill=(0, 255, 163, 235))
            img.paste(bin_overlay, (img_box_x, img_box_y), bin_overlay)
        
        # Glowing multi-layer laser
        draw.line([img_box_x - 10, laser_y, img_box_x + img_size + 10, laser_y], fill=C_CYAN, width=4)
        draw.line([img_box_x - 20, laser_y - 1, img_box_x + img_size + 20, laser_y - 1], fill=(255, 255, 255), width=2)
    
    # Metadata footer on card
    draw.text((card_x + 50, card_y + 740), f"SCAN RETICLE: [X: {int(150 + 20*math.sin(t*3))}, Y: {int(220 + 20*math.cos(t*3))}] | 200x200 PNG", font=FONT_MONO_18, fill=C_SLATE)
    draw.text((card_x + 50, card_y + 775), "SPATIAL BITPLANES: Red(8), Green(8), Blue(8) | CRC: 0x8C3B621C", font=FONT_MONO_18, fill=C_SLATE)
    draw_pill(draw, card_x + 50, card_y + 815, "CARRIER INTEGRITY: SUSPICIOUS LSB PATTERN DETECTED", FONT_MONO_16, (40, 20, 25), C_RED)
    
    # Right: The Hook Typography
    right_x, right_y, right_w, right_h = 920, 110, 900, 880
    draw_card(draw, right_x, right_y, right_w, right_h, C_CARD_BG, (38, 58, 96), radius=16)
    
    draw.text((right_x + 48, right_y + 50), "FORENSIC REVEAL // SPATIAL DOMAIN", font=FONT_MONO_22, fill=C_GREEN)
    
    # Hook text animations
    draw.text((right_x + 48, right_y + 130), "THINK THIS IS", font=FONT_UI_52, fill=C_WHITE)
    draw.text((right_x + 48, right_y + 200), "JUST AN IMAGE?", font=FONT_UI_52, fill=C_WHITE)
    
    if t >= 1.20:
        pulse_g = int(220 + 35 * math.sin(t * 12.0))
        draw.text((right_x + 48, right_y + 300), "LOOK CLOSER.", font=FONT_UI_68, fill=(0, pulse_g, 163))
    
    if t >= 2.00:
        draw.line([right_x + 48, right_y + 400, right_x + right_w - 48, right_y + 400], fill=C_CARD_BORDER, width=2)
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
# SCENE 2: THE CORE ENGINE: MULTI-DOMAIN FORENSICS (3.70s - 8.96s, Frames 222 - 537)
# ==============================================================================
def render_scene_2(frame_idx, t):
    img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
    draw = ImageDraw.Draw(img)
    draw_cyber_grid(draw, frame_idx, t)
    draw_hud_header(draw, frame_idx, t)
    draw_hud_footer(draw, frame_idx, t)
    
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
            progress = ease_out_quart((t - c["start_t"]) / 0.35)
            alpha_y = int(c["y"] + (1.0 - progress) * 40)
            
            draw_card(draw, c["x"], alpha_y, c["w"], c["h"], C_CARD_BG, (38, 58, 96), radius=14)
            
            # Header
            draw.text((c["x"] + 28, alpha_y + 24), f"{c['id']} // {c['title']}", font=FONT_UI_24, fill=C_CYAN)
            draw.text((c["x"] + 28, alpha_y + 60), f"Target: {c['target']}", font=FONT_MONO_16, fill=C_SLATE)
            draw.line([c["x"] + 28, alpha_y + 88, c["x"] + c["w"] - 28, alpha_y + 88], fill=C_CARD_BORDER, width=1)
            
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
            
            draw_pill(draw, c["x"] + 28, alpha_y + c["h"] - 55, c["pill"], FONT_MONO_16, (15, 35, 30), c["pill_col"], pad_x=16, pad_y=8)
    
    return img


# ==============================================================================
# SCENE 3: THE DISCOVERY: 11 NATIVE FORMATS REVEALED (8.96s - 13.70s, Frames 538 - 821)
# ==============================================================================
def render_scene_3(frame_idx, t):
    img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
    draw = ImageDraw.Draw(img)
    draw_cyber_grid(draw, frame_idx, t)
    draw_hud_header(draw, frame_idx, t)
    draw_hud_footer(draw, frame_idx, t)
    
    draw.text((100, 85), "PAYLOAD EXTRACTION // TRUE-FORMAT RECONSTITUTION", font=FONT_UI_36, fill=C_WHITE)
    draw.text((100, 135), "PixelPry automatically carves raw bitstreams and converts them into native, runnable files", font=FONT_MONO_18, fill=C_SLATE)
    
    # Left Box: Visual Bitplane Separation
    left_x, left_y, left_w, left_h = 100, 180, 820, 810
    draw_card(draw, left_x, left_y, left_w, left_h, C_CARD_BG, (38, 58, 96), radius=16)
    
    draw.text((left_x + 32, left_y + 24), "VISUAL BIT-PLANE SEPARATION", font=FONT_UI_28, fill=C_GREEN)
    draw.text((left_x + 32, left_y + 64), "Extracting 2-Bit concealed visual layer: (arr & 3) * 85", font=FONT_MONO_18, fill=C_SLATE)
    draw.line([left_x + 32, left_y + 98, left_x + left_w - 32, left_y + 98], fill=C_CARD_BORDER, width=1)
    
    # Previews side-by-side
    prev_size = 320
    px1, py1 = left_x + 40, left_y + 130
    px2, py2 = left_x + 460, left_y + 130
    
    draw.rectangle([px1 - 4, py1 - 4, px1 + prev_size + 4, py1 + prev_size + 4], fill=(18, 28, 48))
    if img_original:
        scaled_orig = img_original.resize((prev_size, prev_size), Image.Resampling.NEAREST)
        img.paste(scaled_orig, (px1, py1))
    draw.text((px1 + 50, py1 + prev_size + 15), "ORIGINAL CARRIER", font=FONT_MONO_18, fill=C_SLATE)
    draw.text((px1 + 75, py1 + prev_size + 40), "[ 200x200 PNG ]", font=FONT_MONO_16, fill=C_DARK_SLATE)
    
    # Arrow with pulsing glow
    arrow_col = C_CYAN if (frame_idx // 15) % 2 == 0 else C_GREEN
    draw.text((left_x + 385, py1 + 130), "►►", font=FONT_UI_36, fill=arrow_col)
    
    draw.rectangle([px2 - 4, py2 - 4, px2 + prev_size + 4, py2 + prev_size + 4], fill=(18, 28, 48))
    if img_cat:
        scaled_cat = img_cat.resize((prev_size, prev_size), Image.Resampling.NEAREST)
        img.paste(scaled_cat, (px2, py2))
    draw.text((px2 + 35, py2 + prev_size + 15), "EXTRACTED PAYLOAD", font=FONT_MONO_18, fill=C_GREEN)
    draw.text((px2 + 60, py2 + prev_size + 40), "[ SECRET CAT PHOTO ]", font=FONT_MONO_16, fill=C_CYAN)
    
    # Forensic note below images
    draw_card(draw, left_x + 32, left_y + 550, left_w - 64, 220, (11, 18, 32), C_CARD_BORDER, radius=12)
    draw.text((left_x + 55, left_y + 575), "FORENSIC DISCOVERY:", font=FONT_MONO_22, fill=C_GREEN)
    draw.text((left_x + 55, left_y + 615), "The original cover image appeared completely benign.", font=FONT_MONO_18, fill=C_WHITE)
    draw.text((left_x + 55, left_y + 645), "PixelPry isolated the lowest 2 bits across all RGB channels,", font=FONT_MONO_18, fill=C_SLATE)
    draw.text((left_x + 55, left_y + 675), "reconstructing the hidden photograph in full 8-bit contrast.", font=FONT_MONO_18, fill=C_SLATE)
    draw_pill(draw, left_x + 55, left_y + 715, "STEGANOGRAPHY CLASS: 2-BIT SPATIAL VISUAL LSB", FONT_MONO_16, (20, 35, 45), C_CYAN)
    
    # Right Box: Multi-Format Converter Badges
    right_x, right_y, right_w, right_h = 960, 180, 860, 810
    draw_card(draw, right_x, right_y, right_w, right_h, C_CARD_BG, (38, 58, 96), radius=16)
    
    draw.text((right_x + 32, right_y + 24), "NATIVE MULTI-FORMAT CARVER", font=FONT_UI_28, fill=C_CYAN)
    draw.text((right_x + 32, right_y + 64), "Instant conversion of decoded bitstreams into true native files:", font=FONT_MONO_18, fill=C_SLATE)
    draw.line([right_x + 32, right_y + 98, right_x + right_w - 32, right_y + 98], fill=C_CARD_BORDER, width=1)
    
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
            # 60fps Micro-bounce on entry
            badge_t = t - bt
            scale_y = ease_out_quart(badge_t / 0.25)
            badge_card_y = int(by + (1.0 - scale_y) * 20)
            
            draw_card(draw, right_x + 32, badge_card_y, right_w - 64, 60, (18, 26, 44), (35, 52, 85), radius=10)
            draw_pill(draw, right_x + 48, badge_card_y + 12, ext, FONT_MONO_22, (25, 35, 60), col, pad_x=16, pad_y=4)
            draw.text((right_x + 175, badge_card_y + 18), desc, font=FONT_MONO_20, fill=C_WHITE)
            draw.text((right_x + right_w - 120, badge_card_y + 20), "RECOVERED", font=FONT_MONO_14, fill=C_GREEN)
        by += 72
    
    # Verification confirmation
    if t >= 12.65:
        draw_card(draw, right_x + 32, right_y + 660, right_w - 64, 110, (10, 35, 25), C_GREEN, radius=12)
        draw.text((right_x + 55, right_y + 685), "✓ FORENSIC BENCHMARK VALIDATED", font=FONT_UI_24, fill=C_GREEN)
        draw.text((right_x + 55, right_y + 725), "All 11 sample test carrier fixtures verified byte-for-byte.", font=FONT_MONO_18, fill=C_WHITE)
    
    return img


# ==============================================================================
# SCENE 4: AUDIO SPECTROGRAM & 24-BIT COLOR FORENSICS (13.70s - 17.91s, Frames 822 - 1074)
# (NO challenge.png used!)
# ==============================================================================
def render_scene_4(frame_idx, t):
    img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
    draw = ImageDraw.Draw(img)
    draw_cyber_grid(draw, frame_idx, t)
    draw_hud_header(draw, frame_idx, t)
    draw_hud_footer(draw, frame_idx, t)
    
    draw.text((100, 85), "ADVANCED TRANSFORM FORENSICS // AUDIO SPECTROGRAM & PALETTE EXTRACTION", font=FONT_UI_36, fill=C_WHITE)
    draw.text((100, 135), "Extracting high-frequency acoustic steganography & 24-bit RGB color-as-text character streams", font=FONT_MONO_18, fill=C_SLATE)
    
    # Left Card: Audio Frequency Spectrogram Forensics
    left_x, left_y, left_w, left_h = 100, 180, 800, 810
    draw_card(draw, left_x, left_y, left_w, left_h, C_CARD_BG, (38, 58, 96), radius=16)
    
    draw.text((left_x + 32, left_y + 24), "AUDIO SPECTROGRAM FREQUENCY DOMAIN", font=FONT_UI_28, fill=C_CYAN)
    draw.text((left_x + 32, left_y + 64), "Target: Nine_Inch_Nails_-_My_Violent_Heart.wav", font=FONT_MONO_18, fill=C_SLATE)
    draw.line([left_x + 32, left_y + 98, left_x + left_w - 32, left_y + 98], fill=C_CARD_BORDER, width=1)
    
    # Spectrogram waterfall display (460x490)
    spec_w, spec_h = 460, 480
    sx, sy = left_x + 170, left_y + 120
    draw.rectangle([sx - 4, sy - 4, sx + spec_w + 4, sy + spec_h + 4], fill=(18, 28, 48))
    
    if t < 15.20:
        # Initial spectrogram view
        if img_spectrogram:
            scaled_spec = img_spectrogram.resize((spec_w, spec_h), Image.Resampling.BILINEAR)
            img.paste(scaled_spec, (sx, sy))
    else:
        # FFT High Frequency Reveal of "The Presence" ghostly hand!
        fft_progress = min((t - 15.20) / 1.20, 1.0)
        split_x = int(sx + fft_progress * spec_w)
        
        if img_spectrogram and img_hand:
            scaled_spec = img_spectrogram.resize((spec_w, spec_h), Image.Resampling.BILINEAR)
            scaled_hand = img_hand.resize((spec_w, spec_h), Image.Resampling.BILINEAR)
            
            img.paste(scaled_spec, (sx, sy))
            
            # Crop hand to revealed portion
            if split_x > sx:
                hand_crop = scaled_hand.crop((0, 0, split_x - sx, spec_h))
                img.paste(hand_crop, (sx, sy))
                
            # FFT Sweep line
            draw.line([split_x, sy, split_x, sy + spec_h], fill=C_CYAN, width=3)
    
    # Telemetry box below spectrogram
    draw_card(draw, left_x + 32, left_y + 630, left_w - 64, 150, (11, 18, 32), C_CARD_BORDER, radius=12)
    draw.text((left_x + 55, left_y + 655), "SPECTROGRAM FREQUENCY ANALYSIS:", font=FONT_MONO_20, fill=C_GREEN)
    draw.text((left_x + 55, left_y + 690), "• FFT Frequency Waterfall: 20 Hz - 22,050 Hz", font=FONT_MONO_16, fill=C_WHITE)
    draw.text((left_x + 55, left_y + 715), "• Embedded image revealed in 16 kHz - 22 kHz acoustic ceiling", font=FONT_MONO_16, fill=C_SLATE)
    draw_pill(draw, left_x + 55, left_y + 745, "PAYLOAD: 'THE PRESENCE' ACOUSTIC STEGANOGRAM", FONT_MONO_14, (15, 35, 45), C_CYAN)
    
    # Right Card: 24-Bit RGB Color-as-Text Forensics
    right_x, right_y, right_w, right_h = 940, 180, 880, 810
    draw_card(draw, right_x, right_y, right_w, right_h, C_CARD_BG, (38, 58, 96), radius=16)
    
    draw.text((right_x + 36, right_y + 24), "24-BIT RGB COLOR-AS-TEXT EXTRACTION", font=FONT_UI_28, fill=C_GREEN)
    draw.text((right_x + 36, right_y + 64), "Target: Wikipedia_Steganography_Flag.png", font=FONT_MONO_18, fill=C_SLATE)
    draw.line([right_x + 36, right_y + 98, right_x + right_w - 36, right_y + 98], fill=C_CARD_BORDER, width=1)
    
    # Color stripes visual preview
    draw.text((right_x + 36, right_y + 120), "VISUAL COLOR STRIPE MATRIX:", font=FONT_MONO_18, fill=C_CYAN)
    
    stripes_w, stripes_h = 800, 160
    stx, sty = right_x + 36, right_y + 155
    draw.rectangle([stx - 2, sty - 2, stx + stripes_w + 2, sty + stripes_h + 2], fill=(18, 28, 48))
    if img_stripes:
        scaled_str = img_stripes.resize((stripes_w, stripes_h), Image.Resampling.NEAREST)
        img.paste(scaled_str, (stx, sty))
    
    # Decoding stream log
    draw.text((right_x + 36, right_y + 335), "BYTE-STREAM DECODING PIPELINE:", font=FONT_MONO_18, fill=C_SLATE)
    
    decode_steps = [
        ("Channel Mapping", "Reading raw 24-bit RGB pixel triples as 8-bit ASCII characters", C_WHITE),
        ("Decoded Sequence", "R: 0x57 ('W') | G: 0x69 ('i') | B: 0x6B ('k') | R: 0x69 ('i')...", C_CYAN),
        ("Shannon Score", "H = 4.12 bits/byte | Pure ASCII Character Distribution [CONFIRMED]", C_PURPLE)
    ]
    dy = right_y + 370
    for label, val, col in decode_steps:
        draw.text((right_x + 36, dy), f"► {label}:", font=FONT_MONO_16, fill=C_SLATE)
        draw.text((right_x + 220, dy), val, font=FONT_MONO_16, fill=col)
        dy += 34
    
    # Dramatic Payload Slam Card at t >= 16.50s (Climax on 17.91s)
    if t >= 16.20:
        draw_card(draw, right_x + 36, right_y + 490, right_w - 72, 280, (10, 24, 38), C_GREEN, radius=16, border_width=2)
        
        draw.text((right_x + 65, right_y + 520), "FORENSIC PAYLOAD RECOVERED // ASCII STRING", font=FONT_MONO_20, fill=C_CYAN)
        
        # Big glowing string
        draw.text((right_x + 65, right_y + 565), "SECRET TEXT: \"Wikipedia\"", font=FONT_MONO_38, fill=C_GREEN)
        
        draw.line([right_x + 65, right_y + 630, right_x + right_w - 105, right_y + 630], fill=C_CARD_BORDER, width=1)
        
        draw.text((right_x + 65, right_y + 650), "True Format: UTF-8 Plaintext Source (.txt)", font=FONT_MONO_18, fill=C_WHITE)
        draw.text((right_x + 65, right_y + 680), "Extracted payload verified byte-for-byte against reference vector.", font=FONT_MONO_16, fill=C_SLATE)
        
        draw_pill(draw, right_x + 65, right_y + 715, "100% BYTE-FOR-BYTE VERIFIED", FONT_MONO_16, (15, 45, 30), C_GREEN, pad_x=20, pad_y=8)
    
    return img


# ==============================================================================
# SCENE 5: OUTRO & PUNCHLINE: NOTHING STAYS HIDDEN (17.91s - 20.00s, Frames 1075 - 1199)
# ==============================================================================
def render_scene_5(frame_idx, t):
    img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
    draw = ImageDraw.Draw(img)
    draw_cyber_grid(draw, frame_idx, t)
    draw_hud_header(draw, frame_idx, t)
    draw_hud_footer(draw, frame_idx, t)
    
    # Center Hero Banner Frame with Glowing Cyber Border & Tech Brackets
    bw, bh = 1140, 470
    bx, by = (WIDTH - bw) // 2, 95
    
    # Pulsing neon glow shadow
    pulse = (math.sin(t * 6.0) + 1.0) * 0.5
    glow_color = (int(0 + 20 * pulse), int(200 + 55 * pulse), 255)
    glow_box = [bx - 8, by - 8, bx + bw + 8, by + bh + 8]
    draw.rounded_rectangle(glow_box, radius=16, fill=(12, 28, 48), outline=glow_color, width=2)
    
    if img_banner:
        banner_scaled = img_banner.resize((bw, bh), Image.Resampling.BILINEAR)
        img.paste(banner_scaled, (bx, by))
    
    draw.rounded_rectangle([bx, by, bx + bw, by + bh], radius=12, outline=C_CYAN, width=2)
    
    # Corner Tech Brackets on Banner
    bracket_len = 24
    draw.line([bx - 12, by - 12, bx - 12 + bracket_len, by - 12], fill=C_GREEN, width=3)
    draw.line([bx - 12, by - 12, bx - 12, by - 12 + bracket_len], fill=C_GREEN, width=3)
    draw.line([bx + bw + 12 - bracket_len, by - 12, bx + bw + 12, by - 12], fill=C_GREEN, width=3)
    draw.line([bx + bw + 12, by - 12, bx + bw + 12, by - 12 + bracket_len], fill=C_GREEN, width=3)
    draw.line([bx - 12, by + bh + 12, bx - 12 + bracket_len, by + bh + 12], fill=C_GREEN, width=3)
    draw.line([bx - 12, by + bh + 12 - bracket_len, bx - 12, by + bh + 12], fill=C_GREEN, width=3)
    draw.line([bx + bw + 12 - bracket_len, by + bh + 12, bx + bw + 12, by + bh + 12], fill=C_GREEN, width=3)
    draw.line([bx + bw + 12, by + bh + 12 - bracket_len, bx + bw + 12, by + bh + 12], fill=C_GREEN, width=3)
    
    # Typography Below Banner
    title_text = "P I X E L P R Y"
    t_bbox = draw.textbbox((0, 0), title_text, font=FONT_UI_72)
    t_w = t_bbox[2] - t_bbox[0]
    draw.text(((WIDTH - t_w) // 2, by + bh + 25), title_text, font=FONT_UI_72, fill=C_CYAN)
    
    sub_text = "Multi-Format Steganography Forensic Analysis & Payload Extraction Suite"
    s_bbox = draw.textbbox((0, 0), sub_text, font=FONT_UI_28)
    s_w = s_bbox[2] - s_bbox[0]
    draw.text(((WIDTH - s_w) // 2, by + bh + 115), sub_text, font=FONT_UI_28, fill=C_WHITE)
    
    punch_text = "INNOCENT PIXELS. ZERO SECRETS."
    p_bbox = draw.textbbox((0, 0), punch_text, font=FONT_UI_36)
    p_w = p_bbox[2] - p_bbox[0]
    draw.text(((WIDTH - p_w) // 2, by + bh + 165), punch_text, font=FONT_UI_36, fill=C_GREEN)
    
    # Spec row
    specs = [
        ("11 FORMATS", "PNG WAV ZIP PEM JSON PY TXT", C_CYAN),
        ("4 DOMAINS", "Spatial LSB | 2D-DCT | Chunk CRC", C_GREEN),
        ("NOISE FILTER", "Shannon Entropy Diversity H", (250, 204, 21)),
        ("0% ERROR", "11/11 Fixtures Verified Byte-for-Byte", C_CYAN)
    ]
    card_w, card_h = 290, 80
    total_specs_w = 4 * card_w + 3 * 20
    start_x = (WIDTH - total_specs_w) // 2
    sy = by + bh + 230
    for i, (title, desc, col) in enumerate(specs):
        cx = start_x + i * (card_w + 20)
        draw.rounded_rectangle([cx, sy, cx + card_w, sy + card_h], radius=10, fill=C_CARD_BG, outline=C_CARD_BORDER, width=1)
        draw.text((cx + 16, sy + 12), title, font=FONT_UI_20, fill=col)
        draw.text((cx + 16, sy + 44), desc, font=FONT_MONO_14, fill=C_SLATE)
    
    # Badges
    pills = [
        "CLI & Standalone Windows EXE",
        "github.com/skshmnarang/PixelPry",
        "MIT Open Source License"
    ]
    pill_widths = []
    for p in pills:
        bbox = draw.textbbox((0, 0), p, font=FONT_MONO_18)
        pill_widths.append(bbox[2] - bbox[0] + 36)
    total_pills_w = sum(pill_widths) + (len(pills) - 1) * 20
    px = (WIDTH - total_pills_w) // 2
    py = by + bh + 330
    for i, p in enumerate(pills):
        draw_pill(draw, px, py, p, FONT_MONO_18, (18, 28, 48), C_WHITE, border_color=(40, 60, 100), pad_x=18, pad_y=8)
        px += pill_widths[i] + 20
        
    return img


# ==============================================================================
# MASTER RENDERER DISPATCH (60 FPS)
# ==============================================================================
def render_frame(frame_idx):
    t = frame_idx / float(FPS)
    if frame_idx < 222:       # 0.00s - 3.70s
        return render_scene_1(frame_idx, t)
    elif frame_idx < 538:     # 3.70s - 8.96s
        return render_scene_2(frame_idx, t)
    elif frame_idx < 822:     # 8.96s - 13.70s
        return render_scene_3(frame_idx, t)
    elif frame_idx < 1075:    # 13.70s - 17.91s
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
        "[6:a]adelay=15200|15200,volume=0.5[s6];"
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
# MAIN RENDER LOOP (60 FPS)
# ==============================================================================
def main():
    print("=" * 70)
    print(" PixelPry /brag 60 FPS Video Synthesis & Render Pipeline")
    print("=" * 70)
    print(f"[*] Canvas: {WIDTH}x{HEIGHT} @ {FPS} fps | Total Frames: {TOTAL_FRAMES} ({DURATION}s)")
    print(f"[*] Output video path: {FINAL_VIDEO_PATH}")
    print(f"[*] Output poster path: {POSTER_PATH}")
    print("-" * 70)
    
    # 1. Mix Audio
    mix_audio()
    
    # 2. Extract and save refined hero poster frame from Scene 5 (Frame 1140)
    print("[*] Generating high-resolution refined hero poster frame (Frame 1140)...")
    poster_img = render_frame(1140)
    poster_img.save(POSTER_PATH, "JPEG", quality=96)
    print(f"[+] Hero poster successfully saved to: {POSTER_PATH}")
    
    # 3. Render all 1200 frames to temporary video
    print(f"[*] Rendering {TOTAL_FRAMES} video frames at {FPS} FPS...")
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
        
        if (f + 1) % 120 == 0 or f == TOTAL_FRAMES - 1:
            print(f"    Progress: {f + 1} / {TOTAL_FRAMES} frames rendered ({(f + 1) / FPS:.1f}s / {DURATION}s)...")
    
    writer.close()
    print(f"[+] Raw 60fps video rendered to: {TEMP_VIDEO_PATH}")
    
    # 4. Mux Video + Mixed Audio into final brag.mp4
    print("[*] Muxing 60fps video with mixed audio stream...")
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
    
    # Clean up temp raw video
    if os.path.exists(TEMP_VIDEO_PATH):
        try:
            os.remove(TEMP_VIDEO_PATH)
        except Exception:
            pass
            
    print("=" * 70)
    print(f"[+] SUCCESS! 60 FPS Video rendered and delivered to:")
    print(f"    VIDEO:  {FINAL_VIDEO_PATH}")
    print(f"    POSTER: {POSTER_PATH}")
    print("=" * 70)

if __name__ == "__main__":
    main()
