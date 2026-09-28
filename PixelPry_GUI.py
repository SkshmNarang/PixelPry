#!/usr/bin/env python3
"""
PixelPry_GUI.py - Modern Graphical Forensic Analysis & Steganography Suite for PixelPry
Built with CustomTkinter for high-DPI modern desktop forensic inspection.
"""

import os
import sys
import io
import time
import json
import threading
import queue
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
import numpy as np
import customtkinter as ctk

# Import core forensic engine from PixelPry.py
try:
    import PixelPry as pp
except ImportError:
    # If launched from another directory, add the script's directory to sys.path
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)
    import PixelPry as pp


class StdoutRedirector:
    """Thread-safe stdout redirector that sends print statements to a queue."""
    def __init__(self, log_queue):
        self.log_queue = log_queue

    def write(self, text):
        if text:
            self.log_queue.put(text)

    def flush(self):
        pass


class PixelPryGUI(ctk.CTk):
    def __init__(self, initial_image=None):
        super().__init__()

        # Window Configuration
        self.title("PixelPry - Forensic Steganography & Payload Extraction Suite")
        self.geometry("1260x860")
        self.minsize(1050, 720)

        # Set default theme
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")

        # Set Icon if available
        self.icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "PixelPry.ico")
        if os.path.isfile(self.icon_path):
            try:
                self.iconbitmap(self.icon_path)
            except Exception:
                pass

        # Forensic State
        self.current_image_path = None
        self.current_verify_path = None
        self.current_output_dir = None
        self.is_scanning = False
        self.log_queue = queue.Queue()
        self.results_queue = queue.Queue()
        self.scan_results = {}
        self.pil_source_image = None
        self.pil_repaired_image = None
        self.pil_visual_image = None
        self.active_payloads = []  # list of tuples: (bytes, info_dict, suffix_name)

        # Build Interface
        self._create_header()
        self._create_input_panel()
        self._create_main_content()
        self._create_statusbar()

        # Start Log & Results Polling loop
        self.after(80, self._poll_queues)

        # Handle initial image if passed via command line
        if initial_image and os.path.isfile(initial_image):
            self.entry_image.insert(0, os.path.abspath(initial_image))
            self.after(300, self.start_analysis)

    # =========================================================================
    # UI CREATION: HEADER & INPUT CONTROLS
    # =========================================================================

    def _create_header(self):
        header_frame = ctk.CTkFrame(self, corner_radius=0, fg_color=("#1f2328", "#0d1117"))
        header_frame.pack(fill="x", padx=0, pady=0)

        title_container = ctk.CTkFrame(header_frame, fg_color="transparent")
        title_container.pack(side="left", padx=20, pady=12)

        title_label = ctk.CTkLabel(
            title_container,
            text="PIXELPRY",
            font=ctk.CTkFont(family="Segoe UI", size=24, weight="bold"),
            text_color=("#0969da", "#58a6ff")
        )
        title_label.pack(side="left", padx=(0, 10))

        badge = ctk.CTkLabel(
            title_container,
            text="FORENSIC SUITE v2.0",
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color=("#ddf4ff", "#1f3a5f"),
            text_color=("#0969da", "#79c0ff"),
            corner_radius=6,
            padx=8,
            pady=2
        )
        badge.pack(side="left", padx=(0, 12))

        subtitle = ctk.CTkLabel(
            title_container,
            text="Autonomous Digital Steganography Forensics & Payload Carving Engine",
            font=ctk.CTkFont(size=12),
            text_color=("#656d76", "#8b949e")
        )
        subtitle.pack(side="left")

        # Theme toggle on the right
        theme_container = ctk.CTkFrame(header_frame, fg_color="transparent")
        theme_container.pack(side="right", padx=20, pady=12)

        self.theme_switch = ctk.CTkSwitch(
            theme_container,
            text="Dark Theme",
            command=self._toggle_theme,
            onvalue="Dark",
            offvalue="Light",
            font=ctk.CTkFont(size=12)
        )
        self.theme_switch.select()
        self.theme_switch.pack(side="right")

    def _create_input_panel(self):
        panel = ctk.CTkFrame(self, corner_radius=10, fg_color=("#f6f8fa", "#161b22"))
        panel.pack(fill="x", padx=16, pady=(12, 6))

        # Row 1: Target Image File
        r1 = ctk.CTkFrame(panel, fg_color="transparent")
        r1.pack(fill="x", padx=14, pady=(10, 4))

        lbl_img = ctk.CTkLabel(r1, text="Target Image:", width=130, anchor="w", font=ctk.CTkFont(weight="bold"))
        lbl_img.pack(side="left")

        self.entry_image = ctk.CTkEntry(r1, placeholder_text="Select or drop image file (PNG, JPG, BMP, GIF, WEBP)...")
        self.entry_image.pack(side="left", fill="x", expand=True, padx=(4, 10))

        btn_browse_img = ctk.CTkButton(r1, text="Browse Image", width=120, command=self._browse_image)
        btn_browse_img.pack(side="right")

        # Row 2: Verification Reference File (Optional)
        r2 = ctk.CTkFrame(panel, fg_color="transparent")
        r2.pack(fill="x", padx=14, pady=4)

        lbl_ref = ctk.CTkLabel(r2, text="Reference File (Opt):", width=130, anchor="w", font=ctk.CTkFont(size=12))
        lbl_ref.pack(side="left")

        self.entry_verify = ctk.CTkEntry(r2, placeholder_text="Optional reference file for byte-for-byte verification (--verify)...")
        self.entry_verify.pack(side="left", fill="x", expand=True, padx=(4, 10))

        btn_browse_ref = ctk.CTkButton(r2, text="Browse Ref", width=120, fg_color=("#6c757d", "#30363d"), command=self._browse_reference)
        btn_browse_ref.pack(side="right")

        # Row 3: Output Save Directory & Action Buttons
        r3 = ctk.CTkFrame(panel, fg_color="transparent")
        r3.pack(fill="x", padx=14, pady=(4, 10))

        lbl_out = ctk.CTkLabel(r3, text="Export Folder (Opt):", width=130, anchor="w", font=ctk.CTkFont(size=12))
        lbl_out.pack(side="left")

        self.entry_output = ctk.CTkEntry(r3, placeholder_text="Optional folder to automatically save all carved payloads (--save)...")
        self.entry_output.pack(side="left", fill="x", expand=True, padx=(4, 10))

        btn_browse_out = ctk.CTkButton(r3, text="Browse Folder", width=120, fg_color=("#6c757d", "#30363d"), command=self._browse_output)
        btn_browse_out.pack(side="right")

        # Action Buttons Row
        actions = ctk.CTkFrame(panel, fg_color="transparent")
        actions.pack(fill="x", padx=14, pady=(4, 10))

        self.btn_scan = ctk.CTkButton(
            actions,
            text="🚀 Run Forensic Scan",
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color=("#2ea043", "#238636"),
            hover_color=("#2c974b", "#2ea043"),
            height=38,
            command=self.start_analysis
        )
        self.btn_scan.pack(side="left", padx=(0, 10))

        self.btn_save_all = ctk.CTkButton(
            actions,
            text="💾 Save Payloads",
            height=38,
            state="disabled",
            fg_color=("#0969da", "#1f6feb"),
            command=self._export_all_payloads
        )
        self.btn_save_all.pack(side="left", padx=(0, 10))

        self.btn_gen_script = ctk.CTkButton(
            actions,
            text="🐍 Export Python Extractor",
            height=38,
            state="disabled",
            fg_color=("#6e7681", "#30363d"),
            command=self._save_python_script
        )
        self.btn_gen_script.pack(side="left", padx=(0, 10))

        self.btn_clear = ctk.CTkButton(
            actions,
            text="🧹 Clear / Reset",
            width=100,
            height=38,
            fg_color=("#8c959f", "#21262d"),
            hover_color=("#6e7681", "#30363d"),
            command=self._reset_all
        )
        self.btn_clear.pack(side="right")

    # =========================================================================
    # UI CREATION: MAIN TABS & VIEWS
    # =========================================================================

    def _create_main_content(self):
        self.tabview = ctk.CTkTabview(self, corner_radius=10)
        self.tabview.pack(fill="both", expand=True, padx=16, pady=(4, 6))

        self.tab_overview = self.tabview.add("📊 Forensic Overview")
        self.tab_visual = self.tabview.add("🖼️ Bit-Plane & Visual Explorer")
        self.tab_payload = self.tabview.add("💾 Carved Payloads & Hex")
        self.tab_chunks = self.tabview.add("🔬 PNG Chunks & Stream Health")
        self.tab_terminal = self.tabview.add("📜 Terminal & Python Script")

        self._build_overview_tab()
        self._build_visual_tab()
        self._build_payload_tab()
        self._build_chunks_tab()
        self._build_terminal_tab()

    def _build_overview_tab(self):
        # Top Metrics Cards
        cards_container = ctk.CTkFrame(self.tab_overview, fg_color="transparent")
        cards_container.pack(fill="x", padx=10, pady=(10, 6))
        cards_container.columnconfigure((0, 1, 2, 3), weight=1, uniform="card")

        self.card_format = self._make_metric_card(cards_container, 0, "FORMAT & DIMENSIONS", "None Loaded", "#58a6ff")
        self.card_size = self._make_metric_card(cards_container, 1, "FILE SIZE", "0 Bytes", "#79c0ff")
        self.card_stego = self._make_metric_card(cards_container, 2, "STEGO DETECTION", "Awaiting Scan", "#8b949e")
        self.card_verify = self._make_metric_card(cards_container, 3, "VERIFICATION", "N/A", "#8b949e")

        # Split pane: Left = Method Matrix, Right = Discovered Payload Summary
        split_frame = ctk.CTkFrame(self.tab_overview, fg_color="transparent")
        split_frame.pack(fill="both", expand=True, padx=10, pady=6)
        split_frame.columnconfigure(0, weight=5)
        split_frame.columnconfigure(1, weight=5)
        split_frame.rowconfigure(0, weight=1)

        # Left: Methodology Findings Box
        left_box = ctk.CTkFrame(split_frame, corner_radius=8, fg_color=("#f6f8fa", "#161b22"))
        left_box.grid(row=0, column=0, sticky="nsew", padx=(0, 6), pady=0)

        ctk.CTkLabel(
            left_box,
            text="FORENSIC METHODOLOGY ANALYSIS",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=("#0969da", "#58a6ff")
        ).pack(anchor="w", padx=14, pady=(12, 6))

        self.txt_methods = ctk.CTkTextbox(
            left_box,
            wrap="word",
            font=ctk.CTkFont(family="Consolas", size=11),
            fg_color=("#ffffff", "#0d1117")
        )
        self.txt_methods.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        # Right: Payload & Flag Card
        right_box = ctk.CTkFrame(split_frame, corner_radius=8, fg_color=("#f6f8fa", "#161b22"))
        right_box.grid(row=0, column=1, sticky="nsew", padx=(6, 0), pady=0)

        ctk.CTkLabel(
            right_box,
            text="DISCOVERED PAYLOAD & CTF ARTIFACTS",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=("#2ea043", "#3fb950")
        ).pack(anchor="w", padx=14, pady=(12, 6))

        self.txt_payload_summary = ctk.CTkTextbox(
            right_box,
            wrap="word",
            font=ctk.CTkFont(family="Consolas", size=11),
            fg_color=("#ffffff", "#0d1117")
        )
        self.txt_payload_summary.pack(fill="both", expand=True, padx=12, pady=(0, 12))

    def _make_metric_card(self, parent, col, title, initial_val, color):
        card = ctk.CTkFrame(parent, corner_radius=8, fg_color=("#f6f8fa", "#161b22"))
        card.grid(row=0, column=col, sticky="ew", padx=4, pady=0)

        lbl_title = ctk.CTkLabel(
            card,
            text=title,
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=("#656d76", "#8b949e")
        )
        lbl_title.pack(anchor="w", padx=12, pady=(8, 2))

        lbl_val = ctk.CTkLabel(
            card,
            text=initial_val,
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=color
        )
        lbl_val.pack(anchor="w", padx=12, pady=(0, 8))
        return lbl_val

    def _build_visual_tab(self):
        # Controls for interactive bitplane viewing
        ctrl_frame = ctk.CTkFrame(self.tab_visual, fg_color=("#f6f8fa", "#161b22"))
        ctrl_frame.pack(fill="x", padx=10, pady=(10, 6))

        ctk.CTkLabel(ctrl_frame, text="Channel:", font=ctk.CTkFont(weight="bold")).pack(side="left", padx=(14, 6), pady=8)
        self.combo_channel = ctk.CTkComboBox(
            ctrl_frame,
            values=["RGB (Combined)", "Red Channel", "Green Channel", "Blue Channel", "Alpha Channel"],
            width=160,
            command=self._on_bitplane_change
        )
        self.combo_channel.set("RGB (Combined)")
        self.combo_channel.pack(side="left", padx=6)

        ctk.CTkLabel(ctrl_frame, text="Bitplane:", font=ctk.CTkFont(weight="bold")).pack(side="left", padx=(16, 6))
        self.combo_bitplane = ctk.CTkComboBox(
            ctrl_frame,
            values=[
                "Original Canvas",
                "2-Bit Visual LSB ((pixel & 3) * 85)",
                "Bit 0 (Least Significant Bit)",
                "Bit 1",
                "Bit 2",
                "Bit 3",
                "Bit 4",
                "Bit 5",
                "Bit 6",
                "Bit 7 (Most Significant Bit)",
                "Recovered CTF Banner (if repaired)",
                "Visual Watermark (if discovered)"
            ],
            width=260,
            command=self._on_bitplane_change
        )
        self.combo_bitplane.set("Original Canvas")
        self.combo_bitplane.pack(side="left", padx=6)

        self.btn_save_current_view = ctk.CTkButton(
            ctrl_frame,
            text="💾 Save Rendered View",
            width=160,
            command=self._save_rendered_view
        )
        self.btn_save_current_view.pack(side="right", padx=14)

        # Image Display Area
        disp_container = ctk.CTkFrame(self.tab_visual, fg_color=("#0d1117", "#0d1117"))
        disp_container.pack(fill="both", expand=True, padx=10, pady=(4, 10))

        self.lbl_visual_canvas = ctk.CTkLabel(disp_container, text="No image loaded for visual analysis", text_color="#8b949e")
        self.lbl_visual_canvas.pack(fill="both", expand=True, padx=10, pady=10)

        # Keep current rendered PIL image in memory for saving
        self.current_rendered_image = None

    def _build_payload_tab(self):
        top_ctrls = ctk.CTkFrame(self.tab_payload, fg_color=("#f6f8fa", "#161b22"))
        top_ctrls.pack(fill="x", padx=10, pady=(10, 6))

        ctk.CTkLabel(top_ctrls, text="Extracted Payload:", font=ctk.CTkFont(weight="bold")).pack(side="left", padx=(14, 6), pady=8)
        self.combo_payload_select = ctk.CTkComboBox(
            top_ctrls,
            values=["No payloads available"],
            width=280,
            command=self._on_payload_select_change
        )
        self.combo_payload_select.pack(side="left", padx=6)

        ctk.CTkLabel(top_ctrls, text="View Mode:", font=ctk.CTkFont(weight="bold")).pack(side="left", padx=(16, 6))
        self.seg_view_mode = ctk.CTkSegmentedButton(
            top_ctrls,
            values=["Clean Text / Structure", "Forensic Hex Dump", "Metadata & Hashes"],
            command=self._on_view_mode_change
        )
        self.seg_view_mode.set("Clean Text / Structure")
        self.seg_view_mode.pack(side="left", padx=6)

        self.btn_copy_payload = ctk.CTkButton(
            top_ctrls,
            text="📋 Copy to Clipboard",
            width=140,
            fg_color=("#6c757d", "#30363d"),
            command=self._copy_payload_text
        )
        self.btn_copy_payload.pack(side="right", padx=(6, 14))

        self.btn_export_payload = ctk.CTkButton(
            top_ctrls,
            text="💾 Save Payload File",
            width=140,
            fg_color=("#0969da", "#1f6feb"),
            command=self._export_selected_payload
        )
        self.btn_export_payload.pack(side="right", padx=6)

        # Content Box
        self.txt_payload_content = ctk.CTkTextbox(
            self.tab_payload,
            wrap="none",
            font=ctk.CTkFont(family="Consolas", size=11),
            fg_color=("#ffffff", "#0d1117")
        )
        self.txt_payload_content.pack(fill="both", expand=True, padx=10, pady=(4, 10))

    def _build_chunks_tab(self):
        container = ctk.CTkFrame(self.tab_chunks, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=10, pady=10)

        lbl = ctk.CTkLabel(
            container,
            text="PNG CONTAINER HEALTH, CHUNK DIRECTORY & ANOMALIES",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=("#0969da", "#58a6ff")
        )
        lbl.pack(anchor="w", padx=4, pady=(0, 6))

        self.txt_chunks = ctk.CTkTextbox(
            container,
            wrap="none",
            font=ctk.CTkFont(family="Consolas", size=11),
            fg_color=("#ffffff", "#0d1117")
        )
        self.txt_chunks.pack(fill="both", expand=True, padx=0, pady=0)

    def _build_terminal_tab(self):
        split = ctk.CTkFrame(self.tab_terminal, fg_color="transparent")
        split.pack(fill="both", expand=True, padx=10, pady=10)
        split.columnconfigure(0, weight=5)
        split.columnconfigure(1, weight=5)
        split.rowconfigure(0, weight=1)

        # Left: Live Terminal Log
        left_box = ctk.CTkFrame(split, corner_radius=8, fg_color=("#f6f8fa", "#161b22"))
        left_box.grid(row=0, column=0, sticky="nsew", padx=(0, 6), pady=0)

        ctk.CTkLabel(
            left_box,
            text="LIVE FORENSIC ENGINE STREAM",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=("#58a6ff", "#58a6ff")
        ).pack(anchor="w", padx=12, pady=(10, 6))

        self.txt_log = ctk.CTkTextbox(
            left_box,
            wrap="word",
            font=ctk.CTkFont(family="Consolas", size=10),
            fg_color=("#ffffff", "#0d1117")
        )
        self.txt_log.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        # Right: Python Script Generator
        right_box = ctk.CTkFrame(split, corner_radius=8, fg_color=("#f6f8fa", "#161b22"))
        right_box.grid(row=0, column=1, sticky="nsew", padx=(6, 0), pady=0)

        right_top = ctk.CTkFrame(right_box, fg_color="transparent")
        right_top.pack(fill="x", padx=12, pady=(10, 6))

        ctk.CTkLabel(
            right_top,
            text="REPRODUCIBLE PYTHON SCRIPT",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=("#2ea043", "#3fb950")
        ).pack(side="left")

        btn_copy_py = ctk.CTkButton(
            right_top,
            text="📋 Copy Script",
            width=100,
            height=28,
            font=ctk.CTkFont(size=11),
            fg_color=("#6c757d", "#30363d"),
            command=self._copy_python_script
        )
        btn_copy_py.pack(side="right")

        self.txt_script = ctk.CTkTextbox(
            right_box,
            wrap="none",
            font=ctk.CTkFont(family="Consolas", size=10),
            fg_color=("#ffffff", "#0d1117")
        )
        self.txt_script.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def _create_statusbar(self):
        bar = ctk.CTkFrame(self, height=28, corner_radius=0, fg_color=("#1f2328", "#0d1117"))
        bar.pack(fill="x", side="bottom")

        self.progress_bar = ctk.CTkProgressBar(bar, width=180, height=12)
        self.progress_bar.pack(side="left", padx=16, pady=8)
        self.progress_bar.set(0)

        self.lbl_status = ctk.CTkLabel(
            bar,
            text="Ready. Select an image and click 'Run Forensic Scan'.",
            font=ctk.CTkFont(size=11),
            text_color=("#656d76", "#8b949e")
        )
        self.lbl_status.pack(side="left", padx=6)

    # =========================================================================
    # EVENT HANDLERS & FILE BROWSING
    # =========================================================================

    def _toggle_theme(self):
        mode = self.theme_switch.get()
        ctk.set_appearance_mode(mode)

    def _browse_image(self):
        filetypes = [
            ("Supported Image Files", "*.png;*.jpg;*.jpeg;*.bmp;*.gif;*.webp"),
            ("PNG Images (*.png)", "*.png"),
            ("JPEG Images (*.jpg;*.jpeg)", "*.jpg;*.jpeg"),
            ("BMP Bitmaps (*.bmp)", "*.bmp"),
            ("GIF Images (*.gif)", "*.gif"),
            ("WebP Images (*.webp)", "*.webp"),
            ("All Files", "*.*")
        ]
        chosen = filedialog.askopenfilename(title="Select Target Image for Forensics", filetypes=filetypes)
        if chosen:
            self.entry_image.delete(0, "end")
            self.entry_image.insert(0, os.path.abspath(chosen))
            self._load_image_meta_preview(os.path.abspath(chosen))

    def _browse_reference(self):
        chosen = filedialog.askopenfilename(title="Select Reference File for Verification")
        if chosen:
            self.entry_verify.delete(0, "end")
            self.entry_verify.insert(0, os.path.abspath(chosen))

    def _browse_output(self):
        chosen = filedialog.askdirectory(title="Select Folder to Export Payloads")
        if chosen:
            self.entry_output.delete(0, "end")
            self.entry_output.insert(0, os.path.abspath(chosen))

    def _load_image_meta_preview(self, path):
        try:
            size_bytes = os.path.getsize(path)
            self.card_size.configure(text=f"{size_bytes:,} B")
            with Image.open(path) as img:
                self.card_format.configure(text=f"{img.format} ({img.width}x{img.height}, {img.mode})")
                self.pil_source_image = img.copy()
            self._render_visual_canvas(self.pil_source_image)
        except Exception as e:
            self.card_format.configure(text="Error loading format")

    # =========================================================================
    # FORENSIC SCAN ENGINE (THREADED EXECUTION)
    # =========================================================================

    def start_analysis(self):
        img_path = self.entry_image.get().strip().strip('"').strip("'")
        if not img_path or not os.path.isfile(img_path):
            messagebox.showerror("Error", "Please select a valid existing image file to analyze.")
            return

        if self.is_scanning:
            return

        self.is_scanning = True
        self.btn_scan.configure(state="disabled")
        self.progress_bar.set(0.1)
        self.progress_bar.start()
        self.lbl_status.configure(text="Forensic analysis running in background...")

        self.current_image_path = os.path.abspath(img_path)
        self.current_verify_path = self.entry_verify.get().strip().strip('"').strip("'") or None
        self.current_output_dir = self.entry_output.get().strip().strip('"').strip("'") or None

        # Reset Previous Scan Views
        self.active_payloads.clear()
        self.combo_payload_select.configure(values=["Processing..."])
        self.combo_payload_select.set("Processing...")
        self.txt_methods.delete("1.0", "end")
        self.txt_payload_summary.delete("1.0", "end")
        self.txt_chunks.delete("1.0", "end")
        self.txt_script.delete("1.0", "end")
        self.card_stego.configure(text="Scanning...", text_color="#d29922")
        self.card_verify.configure(text="Verifying...", text_color="#8b949e")

        # Launch scan thread
        thread = threading.Thread(target=self._run_scan_thread, daemon=True)
        thread.start()

    def _run_scan_thread(self):
        old_stdout = sys.stdout
        redirector = StdoutRedirector(self.log_queue)
        sys.stdout = redirector

        results = {}
        try:
            image_path = self.current_image_path
            format_name = pp.identify_format(image_path)
            results["format_name"] = format_name

            print(f"[*] Starting PixelPry Forensic Scan on: {image_path}")
            print(f"[*] Identified Container Format: {format_name}")

            # 0. PNG Stream Healing
            repair_info = None
            repaired_img = None
            repaired_bytes = None
            if format_name == "PNG":
                repair_info = pp.repair_png_image(image_path)
                results["repair_info"] = repair_info
                if repair_info.get("was_repaired"):
                    repaired_img = repair_info.get("repaired_image")
                    repaired_bytes = repair_info.get("repaired_bytes")
                    self.pil_repaired_image = repaired_img

            # 1. Overlay Detection
            overlay_res = pp.detect_overlay_data(image_path, format_name, repaired_bytes=repaired_bytes)
            results["overlay"] = overlay_res

            # 2. PNG Chunk Inspection
            chunk_res = None
            if format_name == "PNG":
                chunk_res = pp.inspect_png_chunks(image_path, repair_info=repair_info)
                results["chunks"] = chunk_res

            # 3. Palette & Color-as-Text
            palette_res = pp.inspect_palette_and_colors(image_path, repaired_img=repaired_img)
            results["palette"] = palette_res

            # 4. Visual Bit-Plane Analysis
            visual_res = pp.inspect_visual_bitplanes(image_path, repaired_img=repaired_img)
            results["visual"] = visual_res
            if visual_res.get("recovered_image"):
                self.pil_visual_image = visual_res["recovered_image"]

            # 5. Spatial LSB (PNG, BMP, GIF, WEBP)
            lsb_res = {"applicable": False, "payload_found": False, "convention": "N/A", "preview": "Not applicable."}
            if format_name in ("PNG", "BMP", "GIF", "WEBP"):
                lsb_res = pp.extract_lsb(image_path, repaired_img=repaired_img)
            results["lsb"] = lsb_res

            # 6. Transform DCT (JPEG)
            dct_res = {"applicable": False, "payload_found": False, "convention": "N/A", "preview": "Not applicable."}
            if format_name in ("JPEG", "JPG"):
                dct_res = pp.extract_dct(image_path)
            results["dct"] = dct_res

            # 7. Steghide (JPEG / BMP)
            steghide_res = None
            if format_name in ("JPEG", "JPG", "BMP"):
                steghide_res = pp.extract_steghide(image_path)
            results["steghide"] = steghide_res

            # 8. Collect all payloads
            all_payloads = []
            if lsb_res and lsb_res.get("raw_bytes"):
                all_payloads.append((lsb_res["raw_bytes"], lsb_res.get("payload_info"), "lsb_payload"))
            if overlay_res and overlay_res.get("overlay_bytes"):
                all_payloads.append((overlay_res["overlay_bytes"], overlay_res.get("info"), "overlay_payload"))
            if steghide_res and steghide_res.get("raw_bytes"):
                all_payloads.append((steghide_res["raw_bytes"], steghide_res.get("payload_info"), "steghide_payload"))
            if dct_res and dct_res.get("raw_bytes"):
                all_payloads.append((dct_res["raw_bytes"], dct_res.get("payload_info"), "dct_payload"))

            # Save recovered banner / flag text as payload if present
            if repair_info and repair_info.get("flag"):
                flag_text = f"flag: {repair_info.get('flag')}\nverbatim: {repair_info.get('verbatim_flag', '')}\n"
                flag_info = {"type": "CTF Flag", "ext": ".txt", "preview": flag_text, "is_text": True}
                all_payloads.append((flag_text.encode("utf-8"), flag_info, "ctf_flag"))

            results["all_payloads"] = all_payloads

            # 9. Verification against reference file if provided
            verify_status = "N/A"
            if self.current_verify_path and os.path.isfile(self.current_verify_path):
                try:
                    with open(self.current_verify_path, "rb") as rf:
                        ref_bytes = rf.read()
                    matched = False
                    for p_bytes, p_info, _ in all_payloads:
                        if p_bytes == ref_bytes:
                            matched = True
                            break
                        if p_info and p_info.get("is_text"):
                            if p_bytes.strip() == ref_bytes.strip() or ref_bytes in p_bytes or p_bytes in ref_bytes:
                                matched = True
                                break
                            if p_info.get("ext") == ".json":
                                try:
                                    if json.loads(p_bytes.decode("utf-8")) == json.loads(ref_bytes.decode("utf-8")):
                                        matched = True
                                        break
                                except Exception:
                                    pass
                        elif ref_bytes in p_bytes or p_bytes in ref_bytes:
                            matched = True
                            break
                    verify_status = "MATCH (Verified!)" if matched else "MISMATCH"
                except Exception as e:
                    verify_status = f"Error: {e}"

            results["verify_status"] = verify_status

            # 10. Auto-Save if output directory specified
            if self.current_output_dir:
                try:
                    os.makedirs(self.current_output_dir, exist_ok=True)
                    base = os.path.splitext(os.path.basename(image_path))[0]
                    for p_bytes, p_info, suffix in all_payloads:
                        ext = p_info["ext"] if p_info else ".bin"
                        out_path = os.path.join(self.current_output_dir, f"{base}_{suffix}{ext}")
                        pp.safe_write_file(out_path, p_bytes, mode="wb")
                        print(f"[+] Automatically saved payload: {out_path}")
                except Exception as e:
                    print(f"[-] Auto-export error: {e}")

            # 11. Code generation
            try:
                gen_code = pp.generate_extraction_code(
                    image_path,
                    format_name,
                    lsb_result=lsb_res,
                    dct_result=dct_res,
                    steghide_result=steghide_res,
                    overlay_result=overlay_res,
                    palette_result=palette_res,
                    visual_result=visual_res,
                    repair_info=repair_info
                )
                results["generated_code"] = gen_code
            except Exception as e:
                results["generated_code"] = f"# Error generating extraction code: {e}"

            print("[+] Forensic Scan Completed Successfully!")

        except Exception as e:
            traceback.print_exc()
            results["error"] = str(e)
        finally:
            sys.stdout = old_stdout
            self.results_queue.put(results)

    def _on_scan_completed(self, results):
        self.is_scanning = False
        self.progress_bar.stop()
        self.progress_bar.set(1.0)
        self.btn_scan.configure(state="normal")
        self.scan_results = results

        if "error" in results:
            self.lbl_status.configure(text=f"Scan error: {results['error']}")
            messagebox.showerror("Scan Error", f"An error occurred during forensic scanning:\n{results['error']}")
            return

        self.lbl_status.configure(text="Scan complete. Inspect tabs for detailed evidence.")

        # Update Payloads
        self.active_payloads = results.get("all_payloads", [])
        if self.active_payloads:
            self.btn_save_all.configure(state="normal")
            names = [f"Payload {i+1}: {p[1].get('type', 'Binary')} ({len(p[0]):,} B)" for i, p in enumerate(self.active_payloads)]
            self.combo_payload_select.configure(values=names)
            self.combo_payload_select.set(names[0])
            self._render_payload_view(0)
        else:
            self.btn_save_all.configure(state="disabled")
            self.combo_payload_select.configure(values=["No payloads detected"])
            self.combo_payload_select.set("No payloads detected")
            self.txt_payload_content.delete("1.0", "end")
            self.txt_payload_content.insert("1.0", "No steganographic payload data was discovered.")

        # Update Generated Script
        code = results.get("generated_code", "")
        if code:
            self.btn_gen_script.configure(state="normal")
            self.txt_script.delete("1.0", "end")
            self.txt_script.insert("1.0", code)
        else:
            self.btn_gen_script.configure(state="disabled")

        # Update Stego Status Card
        any_found = (
            (results.get("lsb") and results["lsb"].get("payload_found")) or
            (results.get("overlay") and results["overlay"].get("found")) or
            (results.get("visual") and results["visual"].get("found")) or
            (results.get("palette") and results["palette"].get("found")) or
            (results.get("repair_info") and results["repair_info"].get("flag")) or
            (results.get("dct") and results["dct"].get("payload_found"))
        )

        if any_found:
            self.card_stego.configure(text="PAYLOAD DETECTED", text_color="#3fb950")
        else:
            self.card_stego.configure(text="CLEAN (No Stego)", text_color="#8b949e")

        # Update Verification Card
        v_status = results.get("verify_status", "N/A")
        if "MATCH" in v_status:
            self.card_verify.configure(text="MATCH (Verified)", text_color="#3fb950")
        elif "MISMATCH" in v_status:
            self.card_verify.configure(text="MISMATCH", text_color="#f85149")
        else:
            self.card_verify.configure(text=v_status, text_color="#8b949e")

        # Populate Method Findings Textbox
        self._populate_overview_methods(results)

        # Populate Payload Summary Textbox
        self._populate_payload_summary(results)

        # Populate Chunks Tab
        self._populate_chunks_view(results)

        # Update Visual Tab
        self._on_bitplane_change()

    def _populate_overview_methods(self, res):
        lines = []
        lines.append("=" * 65)
        lines.append(" FORENSIC VECTOR EVALUATION MATRIX")
        lines.append("=" * 65)

        # 1. Overlay
        o = res.get("overlay", {})
        if o.get("found"):
            lines.append(f"[+] [CONTAINER OVERLAY] DETECTED")
            lines.append(f"    Offset : {o.get('offset'):,} bytes")
            lines.append(f"    Length : {o.get('length'):,} bytes")
            lines.append(f"    Type   : {o.get('info', {}).get('type', 'Binary Data')}")
        else:
            lines.append("[-] [CONTAINER OVERLAY] Clean EOF (No trailing appended bytes)")

        # 2. Visual Bitplanes
        v = res.get("visual", {})
        if v.get("found"):
            lines.append(f"[+] [VISUAL BITPLANES] DETECTED")
            lines.append(f"    Type   : {v.get('type')}")
            lines.append(f"    Details: Concealed graphic embedded in lower bitplanes")
        else:
            lines.append("[-] [VISUAL BITPLANES] Natural bitplane distribution (No watermark)")

        # 3. Palette & Color-as-Text
        p = res.get("palette", {})
        if p.get("found"):
            lines.append(f"[+] [PALETTE COLOR-AS-TEXT] DETECTED")
            lines.append(f"    Hidden Text: \"{p.get('word', '')}\"")
        else:
            lines.append("[-] [PALETTE COLOR-AS-TEXT] No secret palette text found")

        # 4. Spatial LSB
        l = res.get("lsb", {})
        if l.get("applicable"):
            if l.get("payload_found"):
                lines.append(f"[+] [SPATIAL LSB] PAYLOAD DETECTED")
                lines.append(f"    Convention : {l.get('convention')}")
                lines.append(f"    Carved Type: {l.get('payload_info', {}).get('type', 'Binary')}")
            else:
                lines.append("[-] [SPATIAL LSB] No coherent LSB bitstream discovered")
        else:
            lines.append("[*] [SPATIAL LSB] Skipped (Non-spatial container format)")

        # 5. Transform DCT
        d = res.get("dct", {})
        if d.get("applicable"):
            if d.get("payload_found"):
                lines.append(f"[+] [TRANSFORM DCT] PAYLOAD DETECTED")
                lines.append(f"    Convention : {d.get('convention')}")
            else:
                lines.append("[-] [TRANSFORM DCT] No AC coefficient frequency payload found")
        else:
            lines.append("[*] [TRANSFORM DCT] Skipped (Spatial format)")

        # 6. Stream Health & Flag Banner
        r = res.get("repair_info")
        if r and r.get("was_repaired"):
            lines.append(f"[+] [STREAM HEALING & ANOMALIES] TAMPERED FILE REPAIRED")
            lines.append(f"    Old Height : {r.get('old_height')}px -> Restored: {r.get('new_height')}px")
            if r.get("flag"):
                lines.append(f"    Captured Flag: {r.get('flag')}")

        self.txt_methods.delete("1.0", "end")
        self.txt_methods.insert("1.0", "\n".join(lines))

    def _populate_payload_summary(self, res):
        lines = []
        lines.append("=" * 65)
        lines.append(" DISCOVERED ARTIFACTS & EVIDENCE RECOVERY")
        lines.append("=" * 65)

        r = res.get("repair_info")
        if r and r.get("flag"):
            lines.append(f"\n[+] CAPTURED CTF FLAG:")
            lines.append(f"    Flag Value : {r.get('flag')}")
            if r.get("verbatim_flag"):
                lines.append(f"    Verbatim   : {r.get('verbatim_flag')}")
            lines.append("    Source     : Repaired PNG Canvas & Isolated Banner")

        p = res.get("palette")
        if p and p.get("found"):
            lines.append(f"\n[+] PALETTE TEXT ARTIFACT:")
            lines.append(f"    Secret Word: \"{p.get('word')}\"")

        l = res.get("lsb")
        if l and l.get("payload_found"):
            info = l.get("payload_info", {})
            raw = l.get("raw_bytes", b"")
            lines.append(f"\n[+] SPATIAL LSB CARVED PAYLOAD:")
            lines.append(f"    Type       : {info.get('type')}")
            lines.append(f"    Native Ext : {info.get('ext')}")
            lines.append(f"    Clean Size : {len(raw):,} bytes")
            if info.get("preview"):
                clean_prev = "".join(c if (32 <= ord(c) <= 126 or c in "\n\r\t") else "." for c in info.get("preview", ""))
                lines.append(f"    Preview    :\n{clean_prev[:250]}")

        o = res.get("overlay")
        if o and o.get("found"):
            lines.append(f"\n[+] APPENDED OVERLAY CARVED PAYLOAD:")
            lines.append(f"    Length     : {o.get('length'):,} bytes at offset {o.get('offset'):,}")
            lines.append(f"    Type       : {o.get('info', {}).get('type')}")

        if not lines or len(lines) <= 3:
            lines.append("\n[-] No hidden payloads, flags, or secret messages were found in this image.")

        self.txt_payload_summary.delete("1.0", "end")
        self.txt_payload_summary.insert("1.0", "\n".join(lines))

    def _populate_chunks_view(self, res):
        lines = []
        r = res.get("repair_info")
        if r:
            lines.append("=== PNG STREAM DIAGNOSIS & REPAIR LOG ===")
            lines.append(f"Was Repaired     : {r.get('was_repaired')}")
            lines.append(f"Original Height  : {r.get('old_height')}")
            lines.append(f"Restored Height  : {r.get('new_height')}")
            lines.append(f"Healed Fake IEND : {r.get('fake_iend_removed')}")
            lines.append(f"Captured CTF Flag: {r.get('flag')}\n")

        c = res.get("chunks")
        if c:
            lines.append("=== DETECTED PNG CHUNK DIRECTORY ===")
            for idx, cname, clen, crc_valid in c.get("chunks", []):
                crc_str = "VALID CRC" if crc_valid else "CRC INVALID!"
                lines.append(f" Chunk [{cname}] @ offset 0x{idx:08X} ({idx:8d}) | Length: {clen:7d} bytes | {crc_str}")

            if c.get("anomalies"):
                lines.append("\n=== DETECTED CHUNK ANOMALIES ===")
                for anom in c["anomalies"]:
                    lines.append(f" [!] {anom}")

            if c.get("text_chunks"):
                lines.append("\n=== METADATA TEXT CHUNKS (tEXt / zTXt) ===")
                for k, v in c["text_chunks"].items():
                    lines.append(f" [{k}] = {v}")

            if c.get("custom_chunks"):
                lines.append("\n=== PRIVATE / CUSTOM CHUNKS ===")
                for name, clen, _ in c["custom_chunks"]:
                    lines.append(f" [{name}] Length: {clen:,} bytes")
        else:
            lines.append("PNG chunk analysis is not applicable to non-PNG formats.")

        self.txt_chunks.delete("1.0", "end")
        self.txt_chunks.insert("1.0", "\n".join(lines))

    # =========================================================================
    # VISUAL BIT-PLANE EXPLORER
    # =========================================================================

    def _on_bitplane_change(self, *args):
        # Determine source image to manipulate
        src = self.pil_repaired_image or self.pil_source_image
        if src is None:
            return

        choice = self.combo_bitplane.get()
        channel_choice = self.combo_channel.get()

        # Handle special views
        if choice == "Recovered CTF Banner (if repaired)":
            r = self.scan_results.get("repair_info")
            if r and r.get("banner_image"):
                self._render_visual_canvas(r["banner_image"])
                return
            else:
                self.lbl_visual_canvas.configure(text="No repaired CTF banner was detected in this image.", image="")
                return

        if choice == "Visual Watermark (if discovered)":
            if self.pil_visual_image:
                self._render_visual_canvas(self.pil_visual_image)
                return
            else:
                self.lbl_visual_canvas.configure(text="No visual bitplane watermark was detected.", image="")
                return

        if choice == "Original Canvas":
            self._render_visual_canvas(src)
            return

        # Bitplane calculation
        try:
            arr = np.array(src.convert("RGBA" if "Alpha" in channel_choice else "RGB"), dtype=np.uint8)

            # Filter channel
            if channel_choice == "Red Channel":
                chan_data = arr[:, :, 0]
            elif channel_choice == "Green Channel":
                chan_data = arr[:, :, 1]
            elif channel_choice == "Blue Channel":
                chan_data = arr[:, :, 2]
            elif channel_choice == "Alpha Channel" and arr.shape[2] == 4:
                chan_data = arr[:, :, 3]
            else:
                chan_data = arr[:, :, :3]

            if "2-Bit Visual LSB" in choice:
                rendered_arr = (chan_data & 0x03) * 85
            else:
                # Extract bit 0 to 7
                for bit in range(8):
                    if f"Bit {bit}" in choice:
                        rendered_arr = ((chan_data >> bit) & 1) * 255
                        break
                else:
                    rendered_arr = chan_data

            rendered_img = Image.fromarray(rendered_arr.astype(np.uint8))
            self._render_visual_canvas(rendered_img)
        except Exception as e:
            self.lbl_visual_canvas.configure(text=f"Rendering error: {e}", image="")

    def _render_visual_canvas(self, pil_img):
        self.current_rendered_image = pil_img

        # Scale nicely to fit preview container (e.g. max 900x520)
        max_w, max_h = 880, 500
        w, h = pil_img.size
        scale = min(max_w / max(1, w), max_h / max(1, h), 1.0)
        disp_w = max(1, int(w * scale))
        disp_h = max(1, int(h * scale))

        ctk_img = ctk.CTkImage(light_image=pil_img, dark_image=pil_img, size=(disp_w, disp_h))
        self.lbl_visual_canvas.configure(image=ctk_img, text="")
        self.lbl_visual_canvas.image = ctk_img

    def _save_rendered_view(self):
        if not self.current_rendered_image:
            messagebox.showwarning("Warning", "No rendered image view is currently active.")
            return

        dest = filedialog.asksaveasfilename(
            title="Save Rendered Bitplane View",
            defaultextension=".png",
            filetypes=[("PNG Image (*.png)", "*.png")]
        )
        if dest:
            try:
                self.current_rendered_image.save(dest)
                messagebox.showinfo("Saved", f"Rendered view successfully saved to:\n{dest}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save image:\n{e}")

    # =========================================================================
    # PAYLOAD VIEWER & HEX DUMP
    # =========================================================================

    def _on_payload_select_change(self, *args):
        idx = self.combo_payload_select.cget("values").index(self.combo_payload_select.get())
        if 0 <= idx < len(self.active_payloads):
            self._render_payload_view(idx)

    def _on_view_mode_change(self, mode):
        idx = 0
        try:
            idx = self.combo_payload_select.cget("values").index(self.combo_payload_select.get())
        except Exception:
            pass
        if 0 <= idx < len(self.active_payloads):
            self._render_payload_view(idx)

    def _render_payload_view(self, payload_idx):
        if not (0 <= payload_idx < len(self.active_payloads)):
            return

        p_bytes, p_info, suffix = self.active_payloads[payload_idx]
        mode = self.seg_view_mode.get()

        self.txt_payload_content.delete("1.0", "end")

        if mode == "Clean Text / Structure":
            # Show formatted text
            try:
                text = p_bytes.decode("utf-8")
                # Try pretty print if JSON
                if p_info and p_info.get("ext") == ".json":
                    try:
                        text = json.dumps(json.loads(text), indent=4)
                    except Exception:
                        pass
                self.txt_payload_content.insert("1.0", text)
            except UnicodeDecodeError:
                # Binary fallback
                self.txt_payload_content.insert(
                    "1.0",
                    f"[Binary Data - {len(p_bytes):,} bytes]\n"
                    f"Type: {p_info.get('type') if p_info else 'Binary'}\n"
                    f"Select 'Forensic Hex Dump' above to inspect binary stream."
                )

        elif mode == "Forensic Hex Dump":
            # Generate hex dump
            lines = []
            max_dump = min(len(p_bytes), 16384)  # first 16KB for responsive UI
            for offset in range(0, max_dump, 16):
                chunk = p_bytes[offset:offset+16]
                hex_str = " ".join(f"{b:02x}" for b in chunk)
                ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
                lines.append(f"{offset:08x}  {hex_str:<48}  |{ascii_str}|")

            if len(p_bytes) > max_dump:
                lines.append(f"\n[... Truncated for display performance: {len(p_bytes) - max_dump:,} bytes remaining ...]")

            self.txt_payload_content.insert("1.0", "\n".join(lines))

        elif mode == "Metadata & Hashes":
            import hashlib
            lines = [
                f"=== PAYLOAD FORENSIC METADATA ===",
                f"Payload Type     : {p_info.get('type') if p_info else 'Binary'}",
                f"Suggested Ext    : {p_info.get('ext') if p_info else '.bin'}",
                f"Byte Size        : {len(p_bytes):,} bytes",
                f"MD5 Hash         : {hashlib.md5(p_bytes).hexdigest()}",
                f"SHA-1 Hash       : {hashlib.sha1(p_bytes).hexdigest()}",
                f"SHA-256 Hash     : {hashlib.sha256(p_bytes).hexdigest()}",
                f"Entropy (Shannon): {self._calc_entropy(p_bytes):.4f} bits/byte",
            ]
            self.txt_payload_content.insert("1.0", "\n".join(lines))

    def _calc_entropy(self, data):
        if not data:
            return 0.0
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        total = len(data)
        entropy = 0.0
        import math
        for c in counts:
            if c > 0:
                p = c / total
                entropy -= p * math.log2(p)
        return entropy

    def _copy_payload_text(self):
        text = self.txt_payload_content.get("1.0", "end-1c")
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)
            messagebox.showinfo("Copied", "Payload content copied to clipboard!")

    def _export_selected_payload(self):
        idx = 0
        try:
            idx = self.combo_payload_select.cget("values").index(self.combo_payload_select.get())
        except Exception:
            return
        if not (0 <= idx < len(self.active_payloads)):
            return

        p_bytes, p_info, suffix = self.active_payloads[idx]
        ext = p_info.get("ext", ".bin") if p_info else ".bin"
        base = os.path.splitext(os.path.basename(self.current_image_path or "payload"))[0]

        dest = filedialog.asksaveasfilename(
            title="Save Extracted Payload",
            initialfile=f"{base}_{suffix}{ext}",
            defaultextension=ext
        )
        if dest:
            try:
                pp.safe_write_file(dest, p_bytes, mode="wb")
                messagebox.showinfo("Saved", f"Payload successfully saved to:\n{dest}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save payload:\n{e}")

    def _export_all_payloads(self):
        if not self.active_payloads:
            messagebox.showwarning("Warning", "No extracted payloads to save.")
            return

        dest_dir = filedialog.askdirectory(title="Select Destination Folder for All Payloads")
        if not dest_dir:
            return

        try:
            os.makedirs(dest_dir, exist_ok=True)
            base = os.path.splitext(os.path.basename(self.current_image_path or "extracted"))[0]
            saved = 0
            for p_bytes, p_info, suffix in self.active_payloads:
                ext = p_info.get("ext", ".bin") if p_info else ".bin"
                out_path = os.path.join(dest_dir, f"{base}_{suffix}{ext}")
                pp.safe_write_file(out_path, p_bytes, mode="wb")
                saved += 1

            # Save visual image if discovered
            if self.pil_visual_image:
                vis_path = os.path.join(dest_dir, f"{base}_visual_watermark.png")
                self.pil_visual_image.save(vis_path)
                saved += 1

            # Save repaired image if repaired
            if self.pil_repaired_image:
                rep_path = os.path.join(dest_dir, f"{base}_repaired_canvas.png")
                self.pil_repaired_image.save(rep_path)
                saved += 1

            messagebox.showinfo("Success", f"Saved {saved} payload artifacts to:\n{dest_dir}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export payloads:\n{e}")

    # =========================================================================
    # SCRIPT & TERMINAL HELPERS
    # =========================================================================

    def _poll_queues(self):
        while not self.log_queue.empty():
            msg = self.log_queue.get_nowait()
            self.txt_log.insert("end", msg)
            self.txt_log.see("end")

        while not self.results_queue.empty():
            results = self.results_queue.get_nowait()
            self._on_scan_completed(results)

        self.after(80, self._poll_queues)

    def _copy_python_script(self):
        code = self.txt_script.get("1.0", "end-1c")
        if code:
            self.clipboard_clear()
            self.clipboard_append(code)
            messagebox.showinfo("Copied", "Python extraction script copied to clipboard!")

    def _save_python_script(self):
        code = self.txt_script.get("1.0", "end-1c")
        if not code:
            messagebox.showwarning("Warning", "No extraction script has been generated yet.")
            return

        base = os.path.splitext(os.path.basename(self.current_image_path or "extractor"))[0]
        dest = filedialog.asksaveasfilename(
            title="Save Python Extraction Script",
            initialfile=f"{base}_extract.py",
            defaultextension=".py",
            filetypes=[("Python Script (*.py)", "*.py")]
        )
        if dest:
            try:
                pp.safe_write_file(dest, code, mode="w", encoding="utf-8")
                messagebox.showinfo("Saved", f"Python script saved to:\n{dest}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save script:\n{e}")

    def _reset_all(self):
        self.entry_image.delete(0, "end")
        self.entry_verify.delete(0, "end")
        self.entry_output.delete(0, "end")
        self.current_image_path = None
        self.current_verify_path = None
        self.current_output_dir = None
        self.active_payloads.clear()
        self.scan_results.clear()
        self.pil_source_image = None
        self.pil_repaired_image = None
        self.pil_visual_image = None
        self.current_rendered_image = None

        self.card_format.configure(text="None Loaded")
        self.card_size.configure(text="0 Bytes")
        self.card_stego.configure(text="Awaiting Scan", text_color="#8b949e")
        self.card_verify.configure(text="N/A", text_color="#8b949e")

        self.txt_methods.delete("1.0", "end")
        self.txt_payload_summary.delete("1.0", "end")
        self.txt_chunks.delete("1.0", "end")
        self.txt_script.delete("1.0", "end")
        self.txt_payload_content.delete("1.0", "end")
        self.txt_log.delete("1.0", "end")

        self.lbl_visual_canvas.configure(text="No image loaded for visual analysis", image="")
        self.combo_payload_select.configure(values=["No payloads available"])
        self.combo_payload_select.set("No payloads available")
        self.btn_save_all.configure(state="disabled")
        self.btn_gen_script.configure(state="disabled")
        self.progress_bar.set(0)
        self.lbl_status.configure(text="Ready. Select an image and click 'Run Forensic Scan'.")


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else None
    app = PixelPryGUI(initial_image=target)
    app.mainloop()


if __name__ == "__main__":
    main()
