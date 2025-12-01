#!/usr/bin/env python3
"""TR4C3R GUI Application.

A sleek, dark-themed graphical interface for TR4C3R OSINT searches.
Designed with a modern reconnaissance/cybersecurity aesthetic.
"""

import asyncio
import json
import logging
import os
import sys
import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any, Callable, List, Optional

# Ensure src is in path for imports when running as frozen executable
if getattr(sys, "frozen", False):
    BASE_DIR = Path(getattr(sys, "_MEIPASS", "."))
    os.chdir(BASE_DIR)
else:
    BASE_DIR = Path(__file__).parent.parent.parent


# ═══════════════════════════════════════════════════════════════════════════════
# DARK THEME COLOR PALETTE
# ═══════════════════════════════════════════════════════════════════════════════


class Colors:
    """Dark recon theme color palette."""

    # Backgrounds
    BG_DARKEST = "#0a0a0f"  # Main background
    BG_DARK = "#12121a"  # Panel backgrounds
    BG_MEDIUM = "#1a1a24"  # Card backgrounds
    BG_LIGHT = "#252532"  # Input backgrounds
    BG_HOVER = "#2a2a3a"  # Hover states

    # Accent colors
    CYBER_GREEN = "#00ff88"  # Primary accent (matrix green)
    CYBER_BLUE = "#00d4ff"  # Secondary accent
    CYBER_PURPLE = "#a855f7"  # Tertiary accent
    CYBER_RED = "#ff3366"  # Error/danger
    CYBER_ORANGE = "#ff9500"  # Warning
    CYBER_YELLOW = "#ffd700"  # Highlight

    # Text colors
    TEXT_PRIMARY = "#e4e4e7"  # Main text
    TEXT_SECONDARY = "#a1a1aa"  # Muted text
    TEXT_MUTED = "#71717a"  # Very muted text
    TEXT_ACCENT = "#00ff88"  # Accent text

    # Borders
    BORDER_DARK = "#2a2a3a"
    BORDER_LIGHT = "#3a3a4a"
    BORDER_ACCENT = "#00ff8855"

    # Status colors
    SUCCESS = "#00ff88"
    ERROR = "#ff3366"
    WARNING = "#ff9500"
    INFO = "#00d4ff"


# ═══════════════════════════════════════════════════════════════════════════════
# CUSTOM WIDGETS
# ═══════════════════════════════════════════════════════════════════════════════


class CyberText(tk.Text):
    """Custom styled text widget with dark theme."""

    def __init__(self, parent: tk.Widget, **kwargs: Any):
        defaults = {
            "bg": Colors.BG_DARK,
            "fg": Colors.TEXT_PRIMARY,
            "insertbackground": Colors.CYBER_GREEN,
            "selectbackground": Colors.CYBER_GREEN,
            "selectforeground": Colors.BG_DARKEST,
            "relief": "flat",
            "borderwidth": 0,
            "font": ("Consolas", 10),
            "padx": 10,
            "pady": 10,
        }
        defaults.update(kwargs)
        super().__init__(parent, **defaults)

        # Configure tags for log levels
        self.tag_configure("INFO", foreground=Colors.TEXT_PRIMARY)
        self.tag_configure("SUCCESS", foreground=Colors.SUCCESS)
        self.tag_configure("WARNING", foreground=Colors.WARNING)
        self.tag_configure("ERROR", foreground=Colors.ERROR)
        self.tag_configure("DEBUG", foreground=Colors.TEXT_MUTED)
        self.tag_configure("TIMESTAMP", foreground=Colors.TEXT_MUTED)
        self.tag_configure("ACCENT", foreground=Colors.CYBER_GREEN)
        self.tag_configure("HEADER", foreground=Colors.CYBER_BLUE, font=("Consolas", 10, "bold"))


class CyberEntry(tk.Entry):
    """Custom styled entry widget with dark theme and glow effect."""

    def __init__(self, parent: tk.Widget, **kwargs: Any):
        defaults = {
            "bg": Colors.BG_LIGHT,
            "fg": Colors.TEXT_PRIMARY,
            "insertbackground": Colors.CYBER_GREEN,
            "selectbackground": Colors.CYBER_GREEN,
            "selectforeground": Colors.BG_DARKEST,
            "relief": "flat",
            "font": ("Consolas", 12),
            "highlightthickness": 2,
            "highlightbackground": Colors.BORDER_DARK,
            "highlightcolor": Colors.CYBER_GREEN,
        }
        defaults.update(kwargs)
        super().__init__(parent, **defaults)

        # Bind focus events for glow effect
        self.bind("<FocusIn>", self._on_focus_in)
        self.bind("<FocusOut>", self._on_focus_out)

    def _on_focus_in(self, event: Any) -> None:
        self.configure(highlightbackground=Colors.CYBER_GREEN)

    def _on_focus_out(self, event: Any) -> None:
        self.configure(highlightbackground=Colors.BORDER_DARK)


class CyberButton(tk.Canvas):
    """Custom styled button with hover effects."""

    def __init__(
        self,
        parent: tk.Widget,
        text: str = "",
        command: Optional[Callable[[], None]] = None,
        width: int = 200,
        height: int = 40,
        accent: str = Colors.CYBER_GREEN,
        style: str = "filled",  # filled, outlined, ghost
        **kwargs: Any,
    ):
        super().__init__(
            parent, width=width, height=height, bg=Colors.BG_MEDIUM, highlightthickness=0, **kwargs
        )

        self.text = text
        self.command = command
        self.accent = accent
        self.style = style
        self.btn_width = width
        self.btn_height = height
        self._hover = False
        self._pressed = False

        self._draw()

        # Bind events
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<Button-1>", self._on_press)
        self.bind("<ButtonRelease-1>", self._on_release)

    def _draw(self) -> None:
        self.delete("all")

        # Determine colors based on state and style
        if self.style == "filled":
            if self._pressed:
                bg = self._darken(self.accent)
                fg = Colors.BG_DARKEST
            elif self._hover:
                bg = self.accent
                fg = Colors.BG_DARKEST
            else:
                bg = self._darken(self.accent, 0.3)
                fg = self.accent
        elif self.style == "outlined":
            bg = Colors.BG_MEDIUM if not self._hover else Colors.BG_HOVER
            fg = self.accent
        else:  # ghost
            bg = Colors.BG_MEDIUM if not self._hover else Colors.BG_HOVER
            fg = Colors.TEXT_PRIMARY if not self._hover else self.accent

        # Draw rounded rectangle
        r = 6  # corner radius
        self.create_polygon(
            r,
            0,
            self.btn_width - r,
            0,
            self.btn_width,
            r,
            self.btn_width,
            self.btn_height - r,
            self.btn_width - r,
            self.btn_height,
            r,
            self.btn_height,
            0,
            self.btn_height - r,
            0,
            r,
            fill=bg,
            outline=self.accent if self.style == "outlined" else "",
            width=2,
            smooth=True,
        )

        # Draw text
        self.create_text(
            self.btn_width // 2,
            self.btn_height // 2,
            text=self.text,
            fill=fg,
            font=("Consolas", 11, "bold"),
        )

    def _darken(self, color: str, factor: float = 0.7) -> str:
        """Darken a hex color."""
        color = color.lstrip("#")
        r, g, b = int(color[:2], 16), int(color[2:4], 16), int(color[4:], 16)
        r, g, b = int(r * factor), int(g * factor), int(b * factor)
        return f"#{r:02x}{g:02x}{b:02x}"

    def _on_enter(self, event: Any) -> None:
        self._hover = True
        self._draw()

    def _on_leave(self, event: Any) -> None:
        self._hover = False
        self._pressed = False
        self._draw()

    def _on_press(self, event: Any) -> None:
        self._pressed = True
        self._draw()

    def _on_release(self, event: Any) -> None:
        self._pressed = False
        self._draw()
        if self._hover and self.command:
            self.command()


class AnimatedProgressBar(tk.Canvas):
    """Custom animated progress bar with cyber styling."""

    def __init__(self, parent: tk.Widget, width: int = 300, height: int = 4, **kwargs: Any):
        super().__init__(
            parent, width=width, height=height, bg=Colors.BG_DARK, highlightthickness=0, **kwargs
        )
        self.bar_width = width
        self.bar_height = height
        self.position = 0
        self.running = False
        self._draw()

    def _draw(self) -> None:
        self.delete("all")
        # Background track
        self.create_rectangle(
            0, 0, self.bar_width, self.bar_height, fill=Colors.BG_LIGHT, outline=""
        )

        if self.running:
            # Animated segment
            seg_width = 60
            x1 = self.position - seg_width
            x2 = self.position

            # Create gradient effect
            for i in range(seg_width):
                alpha = i / seg_width
                color = self._interpolate_color(Colors.BG_LIGHT, Colors.CYBER_GREEN, alpha)
                self.create_line(x1 + i, 0, x1 + i, self.bar_height, fill=color)

    def _interpolate_color(self, c1: str, c2: str, t: float) -> str:
        """Interpolate between two hex colors."""
        c1, c2 = c1.lstrip("#"), c2.lstrip("#")
        r1, g1, b1 = int(c1[:2], 16), int(c1[2:4], 16), int(c1[4:], 16)
        r2, g2, b2 = int(c2[:2], 16), int(c2[2:4], 16), int(c2[4:], 16)
        r = int(r1 + (r2 - r1) * t)
        g = int(g1 + (g2 - g1) * t)
        b = int(b1 + (b2 - b1) * t)
        return f"#{r:02x}{g:02x}{b:02x}"

    def start(self) -> None:
        self.running = True
        self._animate()

    def stop(self) -> None:
        self.running = False
        self._draw()

    def _animate(self) -> None:
        if not self.running:
            return
        self.position = (self.position + 3) % (self.bar_width + 60)
        self._draw()
        self.after(20, self._animate)


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN APPLICATION
# ═══════════════════════════════════════════════════════════════════════════════


class TR4C3RApp:
    """Main GUI application for TR4C3R with dark recon theme."""

    # ASCII Art Logo
    LOGO = """
 ████████╗██████╗ ██╗  ██╗ ██████╗██████╗ ██████╗ 
 ╚══██╔══╝██╔══██╗██║  ██║██╔════╝╚════██╗██╔══██╗
    ██║   ██████╔╝███████║██║      █████╔╝██████╔╝
    ██║   ██╔══██╗╚════██║██║      ╚═══██╗██╔══██╗
    ██║   ██║  ██║     ██║╚██████╗██████╔╝██║  ██║
    ╚═╝   ╚═╝  ╚═╝     ╚═╝ ╚═════╝╚═════╝ ╚═╝  ╚═╝"""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("TR4C3R // OSINT RECONNAISSANCE PLATFORM")
        self.root.geometry("1400x900")
        self.root.minsize(1200, 800)
        self.root.configure(bg=Colors.BG_DARKEST)

        # Lazy load modules
        self._orchestrator: Any = None
        self._database: Any = None
        self._config: Any = None

        # State
        self.search_results: List[Any] = []
        self.is_searching = False

        # Setup
        self._configure_styles()
        self._create_ui()

        # Async setup
        self._loop = asyncio.new_event_loop()
        self._loop_thread = threading.Thread(target=self._run_event_loop, daemon=True)
        self._loop_thread.start()

        # Initial log
        self._log_startup_banner()

    def _run_event_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def _run_async(self, coro: Any, callback: Optional[Callable[[Any], None]] = None) -> None:
        cb = callback

        def done_callback(future: Any) -> None:
            try:
                result = future.result()
                if cb is not None:
                    self.root.after(0, lambda r=result, c=cb: c(r))  # type: ignore[misc]
            except Exception as e:
                self.root.after(0, lambda err=e: self._handle_error(err))

        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        future.add_done_callback(done_callback)

    @property
    def orchestrator(self) -> Any:
        if self._orchestrator is None:
            from src.core.orchestrator import Orchestrator

            self._orchestrator = Orchestrator()
        return self._orchestrator

    @property
    def database(self) -> Any:
        if self._database is None:
            from src.storage.database import Database

            self._database = Database()
        return self._database

    def _configure_styles(self) -> None:
        """Configure ttk styles for dark theme."""
        style = ttk.Style()
        style.theme_use("clam")

        # Configure all ttk widgets to use dark theme
        style.configure(".", background=Colors.BG_MEDIUM, foreground=Colors.TEXT_PRIMARY)
        style.configure("TFrame", background=Colors.BG_MEDIUM)
        style.configure("TLabel", background=Colors.BG_MEDIUM, foreground=Colors.TEXT_PRIMARY)
        style.configure("TButton", background=Colors.BG_LIGHT, foreground=Colors.TEXT_PRIMARY)

        # Treeview styling
        style.configure(
            "Cyber.Treeview",
            background=Colors.BG_DARK,
            foreground=Colors.TEXT_PRIMARY,
            fieldbackground=Colors.BG_DARK,
            borderwidth=0,
            font=("Consolas", 10),
            rowheight=28,
        )
        style.configure(
            "Cyber.Treeview.Heading",
            background=Colors.BG_LIGHT,
            foreground=Colors.CYBER_GREEN,
            font=("Consolas", 10, "bold"),
            borderwidth=0,
        )
        style.map(
            "Cyber.Treeview",
            background=[("selected", Colors.CYBER_GREEN)],
            foreground=[("selected", Colors.BG_DARKEST)],
        )

        # Notebook styling
        style.configure("Cyber.TNotebook", background=Colors.BG_MEDIUM, borderwidth=0)
        style.configure(
            "Cyber.TNotebook.Tab",
            background=Colors.BG_LIGHT,
            foreground=Colors.TEXT_SECONDARY,
            padding=[20, 10],
            font=("Consolas", 10),
        )
        style.map(
            "Cyber.TNotebook.Tab",
            background=[("selected", Colors.BG_MEDIUM)],
            foreground=[("selected", Colors.CYBER_GREEN)],
        )

    def _create_ui(self) -> None:
        """Create the main UI layout."""
        # Main container
        self.main_container = tk.Frame(self.root, bg=Colors.BG_DARKEST)
        self.main_container.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

        # Header
        self._create_header()

        # Content area (sidebar + main)
        content = tk.Frame(self.main_container, bg=Colors.BG_DARKEST)
        content.pack(fill=tk.BOTH, expand=True)

        # Left sidebar
        self._create_sidebar(content)

        # Main content area
        self._create_main_area(content)

        # Status bar
        self._create_statusbar()

    def _create_header(self) -> None:
        """Create the header with logo and title."""
        header = tk.Frame(self.main_container, bg=Colors.BG_DARK, height=60)
        header.pack(fill=tk.X, pady=(0, 2))
        header.pack_propagate(False)

        # Left section - Logo/Title
        left = tk.Frame(header, bg=Colors.BG_DARK)
        left.pack(side=tk.LEFT, padx=20, pady=10)

        # Terminal-style prefix
        prefix = tk.Label(
            left, text="▶", bg=Colors.BG_DARK, fg=Colors.CYBER_GREEN, font=("Consolas", 16)
        )
        prefix.pack(side=tk.LEFT)

        title = tk.Label(
            left,
            text=" TR4C3R",
            bg=Colors.BG_DARK,
            fg=Colors.TEXT_PRIMARY,
            font=("Consolas", 20, "bold"),
        )
        title.pack(side=tk.LEFT)

        subtitle = tk.Label(
            left,
            text="  //  OSINT RECONNAISSANCE PLATFORM",
            bg=Colors.BG_DARK,
            fg=Colors.TEXT_MUTED,
            font=("Consolas", 10),
        )
        subtitle.pack(side=tk.LEFT, padx=(10, 0))

        # Right section - Status indicators
        right = tk.Frame(header, bg=Colors.BG_DARK)
        right.pack(side=tk.RIGHT, padx=20, pady=10)

        # Connection status
        self.status_dot = tk.Label(
            right, text="●", bg=Colors.BG_DARK, fg=Colors.CYBER_GREEN, font=("Consolas", 12)
        )
        self.status_dot.pack(side=tk.LEFT)

        status_text = tk.Label(
            right, text=" ONLINE", bg=Colors.BG_DARK, fg=Colors.TEXT_MUTED, font=("Consolas", 10)
        )
        status_text.pack(side=tk.LEFT)

        # Time display
        self.time_label = tk.Label(
            right, text="", bg=Colors.BG_DARK, fg=Colors.TEXT_MUTED, font=("Consolas", 10)
        )
        self.time_label.pack(side=tk.LEFT, padx=(20, 0))
        self._update_time()

    def _update_time(self) -> None:
        """Update the time display."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.time_label.configure(text=f"[{now}]")
        self.root.after(1000, self._update_time)

    def _create_sidebar(self, parent: tk.Frame) -> None:
        """Create the left sidebar with search controls."""
        sidebar = tk.Frame(parent, bg=Colors.BG_DARK, width=320)
        sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 2))
        sidebar.pack_propagate(False)

        # Scrollable content
        canvas = tk.Canvas(sidebar, bg=Colors.BG_DARK, highlightthickness=0)
        scroll_frame = tk.Frame(canvas, bg=Colors.BG_DARK)

        scroll_frame.bind(
            "<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scroll_frame, anchor="nw", width=320)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # === SEARCH TYPE SECTION ===
        self._create_section(scroll_frame, "TARGET TYPE", self._create_search_type_content)

        # === QUERY INPUT SECTION ===
        self._create_section(scroll_frame, "QUERY INPUT", self._create_query_input_content)

        # === OPTIONS SECTION ===
        self._create_section(scroll_frame, "SCAN OPTIONS", self._create_options_content)

        # === EXECUTE SECTION ===
        self._create_section(scroll_frame, "EXECUTE", self._create_execute_content)

        # === QUICK ACTIONS ===
        self._create_section(scroll_frame, "QUICK ACTIONS", self._create_quick_actions_content)

    def _create_section(
        self, parent: tk.Frame, title: str, content_func: Callable[[tk.Frame], None]
    ) -> None:
        """Create a collapsible section in the sidebar."""
        section = tk.Frame(parent, bg=Colors.BG_DARK)
        section.pack(fill=tk.X, padx=15, pady=(15, 0))

        # Section header
        header = tk.Frame(section, bg=Colors.BG_DARK)
        header.pack(fill=tk.X)

        indicator = tk.Label(
            header, text="◆", bg=Colors.BG_DARK, fg=Colors.CYBER_GREEN, font=("Consolas", 8)
        )
        indicator.pack(side=tk.LEFT)

        title_label = tk.Label(
            header,
            text=f" {title}",
            bg=Colors.BG_DARK,
            fg=Colors.TEXT_SECONDARY,
            font=("Consolas", 9, "bold"),
        )
        title_label.pack(side=tk.LEFT)

        # Separator line
        sep = tk.Frame(section, bg=Colors.BORDER_DARK, height=1)
        sep.pack(fill=tk.X, pady=(5, 10))

        # Content area
        content = tk.Frame(section, bg=Colors.BG_DARK)
        content.pack(fill=tk.X)
        content_func(content)

    def _create_search_type_content(self, parent: tk.Frame) -> None:
        """Create search type radio buttons."""
        self.search_type = tk.StringVar(value="username")

        search_types = [
            ("👤  USERNAME", "username"),
            ("📧  EMAIL", "email"),
            ("📝  NAME", "name"),
            ("📱  PHONE", "phone"),
            ("🔍  FULL SCAN", "all"),
        ]

        for text, value in search_types:
            frame = tk.Frame(parent, bg=Colors.BG_DARK)
            frame.pack(fill=tk.X, pady=2)

            rb = tk.Radiobutton(
                frame,
                text=text,
                variable=self.search_type,
                value=value,
                bg=Colors.BG_DARK,
                fg=Colors.TEXT_PRIMARY,
                selectcolor=Colors.BG_LIGHT,
                activebackground=Colors.BG_DARK,
                activeforeground=Colors.CYBER_GREEN,
                font=("Consolas", 10),
                indicatoron=False,
                width=25,
                anchor="w",
                padx=10,
                pady=5,
                relief="flat",
                highlightthickness=1,
                highlightbackground=Colors.BG_DARK,
                highlightcolor=Colors.CYBER_GREEN,
            )
            rb.pack(fill=tk.X)

            # Hover effects
            rb.bind("<Enter>", lambda e, r=rb: r.configure(bg=Colors.BG_HOVER))
            rb.bind("<Leave>", lambda e, r=rb: r.configure(bg=Colors.BG_DARK))

    def _create_query_input_content(self, parent: tk.Frame) -> None:
        """Create the query input field."""
        # Input frame with border effect
        input_frame = tk.Frame(parent, bg=Colors.BORDER_DARK, padx=1, pady=1)
        input_frame.pack(fill=tk.X, pady=5)

        self.search_entry = CyberEntry(input_frame)
        self.search_entry.pack(fill=tk.X, ipady=8)
        self.search_entry.bind("<Return>", lambda e: self._start_search())

        # Placeholder text
        self._placeholder_text = "Enter target identifier..."
        self.search_entry.insert(0, self._placeholder_text)
        self.search_entry.configure(fg=Colors.TEXT_MUTED)

        def on_focus_in(e: Any) -> None:
            if self.search_entry.get() == self._placeholder_text:
                self.search_entry.delete(0, tk.END)
                self.search_entry.configure(fg=Colors.TEXT_PRIMARY)

        def on_focus_out(e: Any) -> None:
            if not self.search_entry.get():
                self.search_entry.insert(0, self._placeholder_text)
                self.search_entry.configure(fg=Colors.TEXT_MUTED)

        self.search_entry.bind("<FocusIn>", on_focus_in, add="+")
        self.search_entry.bind("<FocusOut>", on_focus_out, add="+")

    def _create_options_content(self, parent: tk.Frame) -> None:
        """Create search options checkboxes."""
        self.fuzzy_var = tk.BooleanVar(value=False)
        self.dedupe_var = tk.BooleanVar(value=True)
        self.cache_var = tk.BooleanVar(value=True)

        options = [
            ("Fuzzy Matching", self.fuzzy_var),
            ("Deduplicate", self.dedupe_var),
            ("Use Cache", self.cache_var),
        ]

        for text, var in options:
            frame = tk.Frame(parent, bg=Colors.BG_DARK)
            frame.pack(fill=tk.X, pady=3)

            cb = tk.Checkbutton(
                frame,
                text=f"  {text}",
                variable=var,
                bg=Colors.BG_DARK,
                fg=Colors.TEXT_PRIMARY,
                selectcolor=Colors.BG_LIGHT,
                activebackground=Colors.BG_DARK,
                activeforeground=Colors.CYBER_GREEN,
                font=("Consolas", 10),
                highlightthickness=0,
                anchor="w",
            )
            cb.pack(fill=tk.X)

    def _create_execute_content(self, parent: tk.Frame) -> None:
        """Create the execute button and progress bar."""
        # Main search button
        self.search_btn = CyberButton(
            parent,
            text="▶  INITIATE SCAN",
            command=self._start_search,
            width=280,
            height=45,
            accent=Colors.CYBER_GREEN,
            style="filled",
        )
        self.search_btn.pack(pady=(5, 10))

        # Stop button (hidden initially)
        self.stop_btn = CyberButton(
            parent,
            text="■  ABORT SCAN",
            command=self._stop_search,
            width=280,
            height=45,
            accent=Colors.CYBER_RED,
            style="outlined",
        )

        # Progress bar
        self.progress = AnimatedProgressBar(parent, width=280, height=3)
        self.progress.pack(pady=(0, 5))

    def _create_quick_actions_content(self, parent: tk.Frame) -> None:
        """Create quick action buttons."""
        actions = [
            ("📜  View History", self._show_history),
            ("💾  Export Results", self._export_results),
            ("📊  Statistics", self._show_stats),
            ("⚙️  Settings", self._show_settings),
        ]

        for text, command in actions:
            btn = CyberButton(
                parent,
                text=text,
                command=command,
                width=280,
                height=35,
                accent=Colors.CYBER_BLUE,
                style="ghost",
            )
            btn.pack(pady=3)

    def _create_main_area(self, parent: tk.Frame) -> None:
        """Create the main content area with results and logs."""
        main = tk.Frame(parent, bg=Colors.BG_DARKEST)
        main.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # Notebook for tabs
        self.notebook = ttk.Notebook(main, style="Cyber.TNotebook")
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

        # Results tab
        self._create_results_tab()

        # Console/Log tab
        self._create_console_tab()

        # Details tab
        self._create_details_tab()

    def _create_results_tab(self) -> None:
        """Create the results display tab."""
        results_frame = tk.Frame(self.notebook, bg=Colors.BG_MEDIUM)
        self.notebook.add(results_frame, text="  📋 RESULTS  ")

        # Treeview for results
        columns = ("source", "identifier", "url", "confidence", "timestamp")

        tree_frame = tk.Frame(results_frame, bg=Colors.BG_MEDIUM)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.results_tree = ttk.Treeview(
            tree_frame, columns=columns, show="headings", style="Cyber.Treeview"
        )

        # Configure columns
        self.results_tree.heading("source", text="SOURCE")
        self.results_tree.heading("identifier", text="IDENTIFIER")
        self.results_tree.heading("url", text="URL")
        self.results_tree.heading("confidence", text="CONF")
        self.results_tree.heading("timestamp", text="TIMESTAMP")

        self.results_tree.column("source", width=120)
        self.results_tree.column("identifier", width=180)
        self.results_tree.column("url", width=350)
        self.results_tree.column("confidence", width=60)
        self.results_tree.column("timestamp", width=150)

        # Scrollbars
        scroll_y = tk.Scrollbar(
            tree_frame,
            orient=tk.VERTICAL,
            command=self.results_tree.yview,
            bg=Colors.BG_DARK,
            troughcolor=Colors.BG_LIGHT,
        )
        scroll_x = tk.Scrollbar(
            tree_frame,
            orient=tk.HORIZONTAL,
            command=self.results_tree.xview,
            bg=Colors.BG_DARK,
            troughcolor=Colors.BG_LIGHT,
        )

        self.results_tree.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)

        self.results_tree.grid(row=0, column=0, sticky="nsew")
        scroll_y.grid(row=0, column=1, sticky="ns")
        scroll_x.grid(row=1, column=0, sticky="ew")

        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        # Bind events
        self.results_tree.bind("<Double-1>", self._open_result_url)
        self.results_tree.bind("<<TreeviewSelect>>", self._show_result_details)

    def _create_console_tab(self) -> None:
        """Create the console/log tab."""
        console_frame = tk.Frame(self.notebook, bg=Colors.BG_DARK)
        self.notebook.add(console_frame, text="  🖥️ CONSOLE  ")

        # Console output
        self.console = CyberText(console_frame)
        self.console.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.console.configure(state="disabled")

    def _create_details_tab(self) -> None:
        """Create the details tab."""
        details_frame = tk.Frame(self.notebook, bg=Colors.BG_DARK)
        self.notebook.add(details_frame, text="  🔎 DETAILS  ")

        self.details_text = CyberText(details_frame)
        self.details_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def _create_statusbar(self) -> None:
        """Create the status bar."""
        statusbar = tk.Frame(self.main_container, bg=Colors.BG_DARK, height=30)
        statusbar.pack(fill=tk.X, pady=(2, 0))
        statusbar.pack_propagate(False)

        # Left side - status message
        left = tk.Frame(statusbar, bg=Colors.BG_DARK)
        left.pack(side=tk.LEFT, padx=15, pady=5)

        status_icon = tk.Label(
            left, text="◉", bg=Colors.BG_DARK, fg=Colors.CYBER_GREEN, font=("Consolas", 8)
        )
        status_icon.pack(side=tk.LEFT)

        self.status_label = tk.Label(
            left, text=" READY", bg=Colors.BG_DARK, fg=Colors.TEXT_MUTED, font=("Consolas", 9)
        )
        self.status_label.pack(side=tk.LEFT)

        # Right side - results count
        right = tk.Frame(statusbar, bg=Colors.BG_DARK)
        right.pack(side=tk.RIGHT, padx=15, pady=5)

        self.results_count = tk.Label(
            right, text="RESULTS: 0", bg=Colors.BG_DARK, fg=Colors.TEXT_MUTED, font=("Consolas", 9)
        )
        self.results_count.pack(side=tk.RIGHT)

    # ═══════════════════════════════════════════════════════════════════════════
    # LOGGING & STATUS
    # ═══════════════════════════════════════════════════════════════════════════

    def _log_startup_banner(self) -> None:
        """Log the startup banner to console."""
        self.log_message("=" * 60, "HEADER")
        for line in self.LOGO.split("\n"):
            self.log_message(line, "ACCENT")
        self.log_message("=" * 60, "HEADER")
        self.log_message("", "INFO")
        self.log_message("TR4C3R OSINT Platform initialized", "SUCCESS")
        self.log_message("Ready for reconnaissance operations", "INFO")
        self.log_message("", "INFO")

    def log_message(self, message: str, level: str = "INFO") -> None:
        """Add a message to the console."""
        self.console.configure(state="normal")

        if level != "HEADER" and level != "ACCENT" and message:
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            prefix = f"[{timestamp}] "
            self.console.insert(tk.END, prefix, "TIMESTAMP")

            level_tags = {
                "INFO": ("INFO", "▸ "),
                "SUCCESS": ("SUCCESS", "✓ "),
                "WARNING": ("WARNING", "⚠ "),
                "ERROR": ("ERROR", "✗ "),
                "DEBUG": ("DEBUG", "◦ "),
            }
            tag, symbol = level_tags.get(level, ("INFO", "▸ "))
            self.console.insert(tk.END, symbol, tag)

        self.console.insert(
            tk.END, f"{message}\n", level if level in ["HEADER", "ACCENT"] else "INFO"
        )
        self.console.see(tk.END)
        self.console.configure(state="disabled")

    def _update_status(self, message: str) -> None:
        """Update the status bar."""
        self.status_label.configure(text=f" {message.upper()}")

    def _update_results_count(self) -> None:
        """Update the results count."""
        count = len(self.results_tree.get_children())
        self.results_count.configure(text=f"RESULTS: {count}")

    # ═══════════════════════════════════════════════════════════════════════════
    # SEARCH OPERATIONS
    # ═══════════════════════════════════════════════════════════════════════════

    def _start_search(self) -> None:
        """Start the search operation."""
        query = self.search_entry.get().strip()
        if not query or query == self._placeholder_text:
            self._show_warning("INPUT REQUIRED", "Please enter a target identifier.")
            return

        if self.is_searching:
            self._show_info("SCAN IN PROGRESS", "A scan is already running.")
            return

        self.is_searching = True
        search_type = self.search_type.get()

        # UI updates
        self.search_btn.pack_forget()
        self.stop_btn.pack(pady=(5, 10))
        self.progress.start()

        self._update_status(f"Scanning {search_type}: {query}")
        self.log_message(f"Initiating {search_type.upper()} scan for: {query}", "INFO")
        self.log_message(f"Target: {query}", "ACCENT")

        # Run search
        self._run_async(self._execute_search(search_type, query), self._on_search_complete)

    async def _execute_search(self, search_type: str, query: str) -> List[Any]:
        """Execute the search operation."""
        results: List[Any] = []
        fuzzy = self.fuzzy_var.get()

        try:
            if search_type == "username":
                results = await self.orchestrator.search_username(query, fuzzy=fuzzy)
            elif search_type == "email":
                results = await self.orchestrator.search_email(query)
            elif search_type == "name":
                results = await self.orchestrator.search_name(query)
            elif search_type == "phone":
                results = await self.orchestrator.search_phone(query)
            elif search_type == "all":
                all_results = await self.orchestrator.search_all(query)
                for result_list in all_results.values():
                    results.extend(result_list)

            # Deduplicate if enabled
            if self.dedupe_var.get() and results:
                from src.core.deduplication import deduplicate_results
                from src.core.data_models import Result

                if results and isinstance(results[0], Result):
                    results = deduplicate_results(results)

        except Exception:
            raise

        return results

    def _on_search_complete(self, results: List[Any]) -> None:
        """Handle search completion."""
        self.is_searching = False

        # UI updates
        self.stop_btn.pack_forget()
        self.search_btn.pack(pady=(5, 10))
        self.progress.stop()

        # Display results
        self.search_results = results
        self._display_results(results)

        self.log_message(f"Scan complete. Found {len(results)} results.", "SUCCESS")
        self._update_status(f"Complete - {len(results)} results")

    def _stop_search(self) -> None:
        """Stop the current search."""
        self.is_searching = False
        self.stop_btn.pack_forget()
        self.search_btn.pack(pady=(5, 10))
        self.progress.stop()
        self.log_message("Scan aborted by user", "WARNING")
        self._update_status("Scan aborted")

    def _display_results(self, results: List[Any]) -> None:
        """Display results in the treeview."""
        # Clear existing
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)

        # Add results
        for result in results:
            if hasattr(result, "source"):
                source = getattr(result, "source", "Unknown")
                identifier = getattr(result, "identifier", "")
                url = getattr(result, "url", "")
                confidence = getattr(result, "confidence", 0)
                timestamp = getattr(result, "timestamp", "")
            else:
                source = result.get("source", "Unknown")
                identifier = result.get("identifier", "")
                url = result.get("url", "")
                confidence = result.get("confidence", 0)
                timestamp = result.get("timestamp", "")

            conf_str = f"{confidence:.0%}" if isinstance(confidence, float) else str(confidence)

            self.results_tree.insert(
                "", tk.END, values=(source, identifier, url, conf_str, timestamp)
            )

        self._update_results_count()

    def _show_result_details(self, event: Any) -> None:
        """Show details for selected result."""
        selection = self.results_tree.selection()
        if not selection:
            return

        item = self.results_tree.item(selection[0])
        values = item["values"]
        if not values:
            return

        source, identifier = values[0], values[1]
        result_detail: Any = None

        for result in self.search_results:
            result_source = (
                getattr(result, "source", None)
                if hasattr(result, "source")
                else result.get("source")
            )
            result_id = (
                getattr(result, "identifier", None)
                if hasattr(result, "identifier")
                else result.get("identifier")
            )
            if result_source == source and result_id == identifier:
                result_detail = result
                break

        self.details_text.delete(1.0, tk.END)

        if result_detail:
            detail_dict = (
                result_detail.__dict__ if hasattr(result_detail, "__dict__") else result_detail
            )
            formatted = json.dumps(detail_dict, indent=2, default=str)
            self.details_text.insert(tk.END, formatted)
        else:
            self.details_text.insert(tk.END, f"Source: {values[0]}\n")
            self.details_text.insert(tk.END, f"Identifier: {values[1]}\n")
            self.details_text.insert(tk.END, f"URL: {values[2]}\n")
            self.details_text.insert(tk.END, f"Confidence: {values[3]}\n")
            self.details_text.insert(tk.END, f"Timestamp: {values[4]}\n")

        # Switch to details tab
        self.notebook.select(2)

    def _open_result_url(self, event: Any) -> None:
        """Open URL in browser."""
        selection = self.results_tree.selection()
        if not selection:
            return

        item = self.results_tree.item(selection[0])
        url = item["values"][2]

        if url:
            import webbrowser

            webbrowser.open(url)

    # ═══════════════════════════════════════════════════════════════════════════
    # DIALOGS & UTILITIES
    # ═══════════════════════════════════════════════════════════════════════════

    def _handle_error(self, error: Exception) -> None:
        """Handle errors."""
        self.is_searching = False
        self.stop_btn.pack_forget()
        self.search_btn.pack(pady=(5, 10))
        self.progress.stop()

        self.log_message(f"Error: {error}", "ERROR")
        self._update_status("Error occurred")
        self._show_error("ERROR", str(error))

    def _show_error(self, title: str, message: str) -> None:
        """Show error dialog."""
        messagebox.showerror(title, message)

    def _show_warning(self, title: str, message: str) -> None:
        """Show warning dialog."""
        messagebox.showwarning(title, message)

    def _show_info(self, title: str, message: str) -> None:
        """Show info dialog."""
        messagebox.showinfo(title, message)

    def _export_results(self) -> None:
        """Export results to file."""
        if not self.search_results:
            self._show_info("NO RESULTS", "No results to export.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("CSV", "*.csv"), ("All", "*.*")],
        )
        if not file_path:
            return

        try:
            export_data = []
            for result in self.search_results:
                if hasattr(result, "__dict__"):
                    export_data.append({k: str(v) for k, v in result.__dict__.items()})
                else:
                    export_data.append({k: str(v) for k, v in result.items()})

            if file_path.endswith(".csv"):
                import csv

                with open(file_path, "w", newline="") as f:
                    if export_data:
                        writer = csv.DictWriter(f, fieldnames=export_data[0].keys())
                        writer.writeheader()
                        writer.writerows(export_data)
            else:
                with open(file_path, "w") as f:
                    json.dump(export_data, f, indent=2)

            self.log_message(f"Exported {len(export_data)} results to {file_path}", "SUCCESS")
            self._show_info("EXPORT COMPLETE", f"Exported to {file_path}")

        except Exception as e:
            self.log_message(f"Export error: {e}", "ERROR")
            self._show_error("EXPORT ERROR", str(e))

    def _show_history(self) -> None:
        """Show search history dialog."""
        dialog = tk.Toplevel(self.root)
        dialog.title("SEARCH HISTORY")
        dialog.geometry("700x500")
        dialog.configure(bg=Colors.BG_DARKEST)
        dialog.transient(self.root)

        # Header
        header = tk.Label(
            dialog,
            text="📜 SEARCH HISTORY",
            bg=Colors.BG_DARKEST,
            fg=Colors.CYBER_GREEN,
            font=("Consolas", 14, "bold"),
        )
        header.pack(pady=20)

        # Treeview
        columns = ("id", "type", "query", "results", "timestamp")
        tree = ttk.Treeview(dialog, columns=columns, show="headings", style="Cyber.Treeview")

        for col in columns:
            tree.heading(col, text=col.upper())
            tree.column(col, width=100)

        tree.column("query", width=200)
        tree.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))

        # Load history
        try:
            history = self.database.get_search_history(limit=100)
            for entry in history:
                tree.insert(
                    "",
                    tk.END,
                    values=(
                        entry.get("id", ""),
                        entry.get("search_type", ""),
                        entry.get("query", ""),
                        entry.get("result_count", 0),
                        entry.get("timestamp", ""),
                    ),
                )
        except Exception as e:
            self.log_message(f"Error loading history: {e}", "ERROR")

    def _show_stats(self) -> None:
        """Show statistics dialog."""
        dialog = tk.Toplevel(self.root)
        dialog.title("STATISTICS")
        dialog.geometry("500x400")
        dialog.configure(bg=Colors.BG_DARKEST)
        dialog.transient(self.root)

        header = tk.Label(
            dialog,
            text="📊 DATABASE STATISTICS",
            bg=Colors.BG_DARKEST,
            fg=Colors.CYBER_GREEN,
            font=("Consolas", 14, "bold"),
        )
        header.pack(pady=20)

        stats_text = CyberText(dialog, height=15)
        stats_text.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))

        try:
            stats = self.database.get_statistics()
            for key, value in stats.items():
                stats_text.insert(tk.END, f"{key}: ", "ACCENT")
                stats_text.insert(tk.END, f"{value}\n", "INFO")
        except Exception as e:
            stats_text.insert(tk.END, f"Error: {e}", "ERROR")

    def _show_settings(self) -> None:
        """Show settings dialog."""
        dialog = tk.Toplevel(self.root)
        dialog.title("SETTINGS")
        dialog.geometry("400x300")
        dialog.configure(bg=Colors.BG_DARKEST)
        dialog.transient(self.root)

        header = tk.Label(
            dialog,
            text="⚙️ SETTINGS",
            bg=Colors.BG_DARKEST,
            fg=Colors.CYBER_GREEN,
            font=("Consolas", 14, "bold"),
        )
        header.pack(pady=20)

        info = tk.Label(
            dialog,
            text="Settings coming in future update.",
            bg=Colors.BG_DARKEST,
            fg=Colors.TEXT_MUTED,
            font=("Consolas", 10),
        )
        info.pack(pady=20)

    def _on_close(self) -> None:
        """Handle application close."""
        if self.is_searching:
            if not messagebox.askyesno("CONFIRM EXIT", "A scan is in progress. Exit anyway?"):
                return

        self._loop.call_soon_threadsafe(self._loop.stop)
        self.root.destroy()


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════


def main() -> None:
    """Main entry point."""
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    root = tk.Tk()

    # Set icon
    icon_path = BASE_DIR / "docs" / "assets" / "icon.ico"
    if icon_path.exists():
        try:
            root.iconbitmap(icon_path)
        except tk.TclError:
            pass

    app = TR4C3RApp(root)
    root.protocol("WM_DELETE_WINDOW", app._on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
