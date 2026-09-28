# Brag Plan: PixelPry

## What is this app?
PixelPry is a digital image steganography forensic analysis, payload extraction, and file repair framework that uncovers, decodes, and reconstructs hidden data across 11 formats (images, audio, zip archives, PEM keys, Python code, JSON, and text) using spatial LSBs, DCT frequency analysis, audio spectrogram inspection, and palette translations.

## The angle
"Innocent pixels hide deadly secrets."
A high-intensity cybersecurity forensic investigation trailer. Move from a seemingly normal image to raw bitplane isolation, deep multi-format payload carving, audio frequency spectrogram decoding, and the final verified payload reveal.

## Hook (first 2-3 seconds)
0.00s - 3.70s: A pristine high-res photo appears. Bold terminal text: "THINK THIS IS JUST AN IMAGE?"
Instant glitch and LSB mask sweep revealing secret binary code crawling beneath the RGB matrix.

## Key moments (the middle)
- **Forensic Engine & Magic Bytes:** Live scan analyzing PNG, JPEG, BMP headers, scanning 24-bit channels, and evaluating 2D-DCT AC frequency coefficients.
- **Visual Bitplane & True Payload Carving:** 2-bit color plane separation revealing the secret cat photo and carving 11 native formats (WAV, ZIP, PEM, JSON, PY, PNG, TXT).
- **Audio Spectrogram & Palette Forensics:** FFT frequency waterfall decoding revealing the hidden "Presence" hand and 24-bit RGB color-as-text character stream decoding.

## Outro / punchline
17.91s - 20.00s: The secret payload and verified flags slam on screen.
PixelPry logo & GitHub badge settle with clean forensic confidence: "NOTHING STAYS HIDDEN."

## User flow worth showing
1. **Entry:** Running `python PixelPry.py <target_image>` or drag-and-drop into terminal.
2. **Key Action:** Real-time multi-vector forensics (magic bytes, spatial LSBs, spectrogram transforms).
3. **Result:** Automatic conversion into native file formats (`.png`, `.wav`, `.zip`, `.pem`, `.json`, `.py`) and decoded flags.

## Tone
- Preset: `cinematic`
- Creative direction: "Cybersecurity forensic thriller trailer"
- Interpretation: Dark cyberpunk aesthetic, neon cyan/green accents, high-contrast terminal monospace typography, impactful beat-locked transitions, and crisp forensic UI cards.

## Format: landscape — 1920x1080 @ 60fps
## Duration: 20.0 seconds (1200 frames)

## Visual identity (from the project)
- Background: `#0B0F19` (Deep cyber navy/black)
- Accent: `#00FFA3` (Electric forensic green) / `#00D8FF` (Cyber cyan)
- Text: `#FFFFFF` (Crisp white) / `#94A3B8` (Muted slate)
- Display font: Segoe UI Bold / Consolas Monospace
- Body font: Consolas Monospace
- Strongest visual element: High-res PixelPry banner, extracted secret cat bitplane, audio frequency spectrogram, and Wikipedia color-as-text stripes.

## Share copy (draft)
Think that innocent PNG is just a picture? Look closer.

PixelPry tears through spatial LSBs, 2D-DCT frequency transforms, and audio spectrograms to extract 11 native payload formats (WAV, ZIP, PEM, JSON, Python, and images) hidden in plain sight. Built for security researchers and CTF hunters.

## Audio direction
- Role: Cinematic cyber-electronic groove with crisp interface blips and mechanical typing accents.
- Music: `happy-beats-business-moves-vol-11-by-ende-dot-app.mp3` (114.84 BPM, upbeat electronic drive).
- Music treatment: Starts at 0.0s, high energy through beats 3.70s and 8.96s, dramatic drop on the reveal at 17.91s, smooth outro fade.
- Music cue guidance:
  - Strong cues: 1.60s, 3.70s, 5.80s, 8.96s, 12.65s, 17.91s.
  - Scene 1 Hook transition: Beat-locked to 3.70s.
  - Scene 2 Engine scan: Beat-locked to 8.96s.
  - Scene 3 Payload carving: Beat-grid cards arriving at 9.50s, 10.54s, 11.60s, 12.65s.
  - Scene 4 Spectrogram & Color reveal: Beat-locked drop at 17.91s.
- Audio-reactive treatment: Subtle neon border pulse and bitstream frequency equalizer glow responsive to track energy.
- SFX posture: Moderate, crisp, motion-matched UI clicks, terminal keystrokes, and impact hits.
- Audio-coupled moments: Terminal typing, payload badge pop-ins, frequency FFT solve chime, payload slam.
- Restraint rule: No harsh clipping or abrasive static; maintain sleek forensic polish.

## Storyboard

### Scene 1 — The Hook: Beneath The Pixels — 3.70s (0.00s - 3.70s)
A pristine image card sits in a dark forensic chamber.
Text typing out: `ANALYZING TARGET IMAGE...`
At 1.60s (strong cue): Cyan laser scanline wipes down.
LSB bit-plane mask exposes green binary matrix streaming beneath the pixels.
Text: `THINK IT'S JUST AN IMAGE? LOOK CLOSER.`
Sequential/interaction: Scanline wipe and binary stream reveal.
Audio intent: Suspenseful electronic swell with digital scanner blip.
Audio-coupled idea: Laser sweep SFX at 1.60s.
Transition mood: Beat-locked wipe on 3.70s → Scene 2

### Scene 2 — The Core Engine: Multi-Domain Forensics — 5.26s (3.70s - 8.96s)
PixelPry forensic HUD launches with live inspection gauges:
- `MAGIC BYTES`: Header signature verified (`\x89PNG\r\n\x1a\n`)
- `SPATIAL DOMAIN`: 24-bit RGB LSB analysis active
- `TRANSFORM DOMAIN`: 2D-DCT 8x8 frequency coefficient AC sampling
- `ENTROPY FILTER`: Shannon diversity metric check passed
Sequential/interaction: 4 forensic audit cards slide in sequentially on consecutive beats (4.75s, 5.80s, 6.86s, 7.91s).
Audio intent: Energetic rhythmic groove building momentum.
Audio-coupled idea: Crisp interface switch SFX on each audit card entry.
Transition mood: Hard cut on strong cue 8.96s → Scene 3

### Scene 3 — The Carving: 11 Native Formats Revealed — 4.74s (8.96s - 13.70s)
Center stage splits:
Left: Visual bit-plane separation extracts secret 2-bit color cat photograph from lowest bits!
Right: Multi-format payload carver automatically converts raw bytes into true file types:
Badges pop: `[PNG]` `[WAV]` `[ZIP]` `[PEM]` `[JSON]` `[PYTHON]` `[TXT]`
Live preview showing recovered code and certificates.
Sequential/interaction: Split screen reveal, format badges popping in rapid sequence.
Audio intent: High-tempo discovery payoff.
Audio-coupled idea: Fast UI click SFX on format badge pops.
Transition mood: Glitch sweep on 13.70s → Scene 4

### Scene 4 — Advanced Forensics: Audio Spectrogram & Color-as-Text — 4.21s (13.70s - 17.91s)
Terminal launches multi-domain transform forensics:
- Audio Spectrogram Frequency Analysis: Examining `Nine_Inch_Nails_-_My_Violent_Heart.png`
- High-frequency FFT sweep reveals the hidden "Presence" ghostly hand from the acoustic spectrum
- 24-bit RGB Color-as-Text analysis (`Wikipedia_Steganography_Flag.png`) decodes secret character streams
At 17.91s (major strong cue): Impact flash reveals decoded payload & secret string: `"Wikipedia"` / `FLAG{w1k1p3d1a_c0l0r_st3g0}`
Sequential/interaction: Spectral frequency waterfall wipe, color matrix decoding, and payload impact.
Audio intent: Dramatic solve climax.
Audio-coupled idea: Heavy impact hit and chime at 17.91s.
Transition mood: Impact slam on 17.91s → Scene 5

### Scene 5 — Outro & Punchline: Nothing Stays Hidden — 2.09s (17.91s - 20.00s)
PixelPry master emblem, banner, and GitHub repository card.
Headline: `PIXELPRY`
Subhead: `Steganography Analysis, Extraction & Forensic Recovery Suite`
Command line badge: `github.com/skshmnarang/PixelPry`
Audio intent: Triumphant outro resolution, bass echo, and gentle fade.
Audio summary: Fast, precise electronic beat synced to forensic discoveries, concluding with a decisive payload reveal hit.
