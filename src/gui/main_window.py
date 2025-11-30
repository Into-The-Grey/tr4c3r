#!/usr/bin/env python3
"""TR4C3R GUI Application.

A tkinter-based graphical interface for TR4C3R OSINT searches.
This module provides an easy-to-use interface for users who prefer
a visual application over command-line usage.
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
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Any, Callable, Dict, List, Optional

# Ensure src is in path for imports when running as frozen executable
if getattr(sys, "frozen", False):
    # Running as compiled executable
    # PyInstaller stores data files in _MEIPASS
    BASE_DIR = Path(getattr(sys, "_MEIPASS", "."))
    os.chdir(BASE_DIR)
else:
    BASE_DIR = Path(__file__).parent.parent.parent


class TR4C3RApp:
    """Main GUI application for TR4C3R."""

    def __init__(self, root: tk.Tk):
        """Initialize the TR4C3R GUI application.

        Args:
            root: The root tkinter window
        """
        self.root = root
        self.root.title("TR4C3R - OSINT Investigation Tool")
        self.root.geometry("1000x700")
        self.root.minsize(800, 600)

        # Configure logging

        # Lazy load the heavy modules
        self._orchestrator = None
        self._database = None
        self._config = None

        # State

        self.search_results = []
        self.is_searching = False

        # Setup UI
        self._setup_styles()
        self._create_menu()
        self._create_main_layout()
        self._create_statusbar()

        # Initialize async event loop in background thread
        self._loop = asyncio.new_event_loop()
        self._loop_thread = threading.Thread(target=self._run_event_loop, daemon=True)
        self._loop_thread.start()

        # Log startup
        self.log_message("TR4C3R GUI initialized", "INFO")
        self._update_status("Ready")

    def _run_event_loop(self):
        """Run the asyncio event loop in a background thread."""
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def _run_async(self, coro: Any, callback: Optional[Callable[[Any], None]] = None) -> None:
        """Run an async coroutine from the GUI thread.

        Args:
            coro: The coroutine to run
            callback: Optional callback to run with the result
        """
        cb = callback  # Capture for closure

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
    def orchestrator(self):
        """Lazy load the orchestrator."""
        if self._orchestrator is None:
            from src.core.orchestrator import Orchestrator

            self._orchestrator = Orchestrator()
        return self._orchestrator

    @property
    def database(self):
        """Lazy load the database."""
        if self._database is None:
            from src.storage.database import Database

            self._database = Database()
        return self._database

    @property
    def config(self):
        """Lazy load the config."""
        if self._config is None:
            from src.core.config import get_config

            self._config = get_config()
        return self._config

    def _setup_styles(self):
        """Configure ttk styles for the application."""
        style = ttk.Style()

        # Try to use a modern theme
        available_themes = style.theme_names()
        if "clam" in available_themes:
            style.theme_use("clam")
        elif "vista" in available_themes:
            style.theme_use("vista")

        # Custom styles
        style.configure("Title.TLabel", font=("Helvetica", 16, "bold"))
        style.configure("Header.TLabel", font=("Helvetica", 12, "bold"))
        style.configure("Status.TLabel", font=("Helvetica", 10))
        style.configure("Search.TButton", font=("Helvetica", 11, "bold"), padding=10)

    def _create_menu(self):
        """Create the application menu bar."""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Export Results...", command=self._export_results)
        file_menu.add_command(label="Import Targets...", command=self._import_targets)
        file_menu.add_separator()
        file_menu.add_command(label="Clear Results", command=self._clear_results)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self._on_close)

        # Search menu
        search_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Search", menu=search_menu)
        search_menu.add_command(
            label="Username Search", command=lambda: self._set_search_type("username")
        )
        search_menu.add_command(
            label="Email Search", command=lambda: self._set_search_type("email")
        )
        search_menu.add_command(label="Name Search", command=lambda: self._set_search_type("name"))
        search_menu.add_command(
            label="Phone Search", command=lambda: self._set_search_type("phone")
        )
        search_menu.add_separator()
        search_menu.add_command(label="All Searches", command=lambda: self._set_search_type("all"))

        # History menu
        history_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="History", menu=history_menu)
        history_menu.add_command(label="View Search History", command=self._show_history)
        history_menu.add_command(label="Clear History", command=self._clear_history)

        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Database Statistics", command=self._show_stats)
        tools_menu.add_command(label="Cache Management", command=self._show_cache_manager)
        tools_menu.add_command(label="Settings", command=self._show_settings)

        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Documentation", command=self._show_docs)
        help_menu.add_command(label="About TR4C3R", command=self._show_about)

    def _create_main_layout(self):
        """Create the main application layout."""
        # Main container with padding
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Left panel - Search controls
        left_panel = ttk.Frame(main_frame, width=300)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        left_panel.pack_propagate(False)

        self._create_search_panel(left_panel)

        # Right panel - Results
        right_panel = ttk.Frame(main_frame)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        self._create_results_panel(right_panel)

    def _create_search_panel(self, parent: ttk.Frame):
        """Create the search input panel.

        Args:
            parent: The parent frame
        """
        # Title
        title_label = ttk.Label(parent, text="TR4C3R", style="Title.TLabel")
        title_label.pack(pady=(0, 5))

        subtitle = ttk.Label(parent, text="OSINT Investigation Tool")
        subtitle.pack(pady=(0, 20))

        # Search type selection
        type_frame = ttk.LabelFrame(parent, text="Search Type", padding=10)
        type_frame.pack(fill=tk.X, pady=(0, 10))

        self.search_type = tk.StringVar(value="username")
        search_types = [
            ("Username", "username"),
            ("Email", "email"),
            ("Name", "name"),
            ("Phone", "phone"),
            ("All", "all"),
        ]

        for text, value in search_types:
            rb = ttk.Radiobutton(type_frame, text=text, value=value, variable=self.search_type)
            rb.pack(anchor=tk.W, pady=2)

        # Search input
        input_frame = ttk.LabelFrame(parent, text="Search Query", padding=10)
        input_frame.pack(fill=tk.X, pady=(0, 10))

        self.search_entry = ttk.Entry(input_frame, font=("Helvetica", 11))
        self.search_entry.pack(fill=tk.X, pady=(0, 10))
        self.search_entry.bind("<Return>", lambda e: self._start_search())

        # Options
        options_frame = ttk.LabelFrame(parent, text="Options", padding=10)
        options_frame.pack(fill=tk.X, pady=(0, 10))

        self.fuzzy_var = tk.BooleanVar(value=False)
        fuzzy_cb = ttk.Checkbutton(
            options_frame, text="Enable Fuzzy Matching", variable=self.fuzzy_var
        )
        fuzzy_cb.pack(anchor=tk.W, pady=2)

        self.dedupe_var = tk.BooleanVar(value=True)
        dedupe_cb = ttk.Checkbutton(
            options_frame, text="Deduplicate Results", variable=self.dedupe_var
        )
        dedupe_cb.pack(anchor=tk.W, pady=2)

        self.cache_var = tk.BooleanVar(value=True)
        cache_cb = ttk.Checkbutton(options_frame, text="Use Cache", variable=self.cache_var)
        cache_cb.pack(anchor=tk.W, pady=2)

        # Search button
        self.search_btn = ttk.Button(
            parent, text="🔍 Start Search", style="Search.TButton", command=self._start_search
        )
        self.search_btn.pack(fill=tk.X, pady=10)

        # Stop button (hidden initially)
        self.stop_btn = ttk.Button(parent, text="⏹ Stop Search", command=self._stop_search)

        # Progress bar
        self.progress = ttk.Progressbar(parent, mode="indeterminate")
        self.progress.pack(fill=tk.X, pady=(0, 10))

        # Quick actions
        actions_frame = ttk.LabelFrame(parent, text="Quick Actions", padding=10)
        actions_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Button(actions_frame, text="View History", command=self._show_history).pack(
            fill=tk.X, pady=2
        )
        ttk.Button(actions_frame, text="Export Results", command=self._export_results).pack(
            fill=tk.X, pady=2
        )
        ttk.Button(actions_frame, text="Statistics", command=self._show_stats).pack(
            fill=tk.X, pady=2
        )

    def _create_results_panel(self, parent: ttk.Frame):
        """Create the results display panel.

        Args:
            parent: The parent frame
        """
        # Notebook for tabbed results
        self.notebook = ttk.Notebook(parent)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Results tab
        results_frame = ttk.Frame(self.notebook)
        self.notebook.add(results_frame, text="Results")

        # Results tree
        columns = ("Source", "Identifier", "URL", "Confidence", "Timestamp")
        self.results_tree = ttk.Treeview(results_frame, columns=columns, show="headings")

        for col in columns:
            self.results_tree.heading(col, text=col)
            self.results_tree.column(col, width=100)

        self.results_tree.column("URL", width=250)
        self.results_tree.column("Identifier", width=150)

        # Scrollbars for results
        results_scroll_y = ttk.Scrollbar(
            results_frame, orient=tk.VERTICAL, command=self.results_tree.yview
        )
        results_scroll_x = ttk.Scrollbar(
            results_frame, orient=tk.HORIZONTAL, command=self.results_tree.xview
        )
        self.results_tree.configure(
            yscrollcommand=results_scroll_y.set, xscrollcommand=results_scroll_x.set
        )

        self.results_tree.grid(row=0, column=0, sticky="nsew")
        results_scroll_y.grid(row=0, column=1, sticky="ns")
        results_scroll_x.grid(row=1, column=0, sticky="ew")

        results_frame.grid_rowconfigure(0, weight=1)
        results_frame.grid_columnconfigure(0, weight=1)

        # Bind double-click to open URL
        self.results_tree.bind("<Double-1>", self._open_result_url)

        # Log tab
        log_frame = ttk.Frame(self.notebook)
        self.notebook.add(log_frame, text="Log")

        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=20)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.configure(state="disabled")

        # Configure log colors
        self.log_text.tag_configure("INFO", foreground="black")
        self.log_text.tag_configure("WARNING", foreground="orange")
        self.log_text.tag_configure("ERROR", foreground="red")
        self.log_text.tag_configure("SUCCESS", foreground="green")
        self.log_text.tag_configure("DEBUG", foreground="gray")

        # Details tab
        details_frame = ttk.Frame(self.notebook)
        self.notebook.add(details_frame, text="Details")

        self.details_text = scrolledtext.ScrolledText(details_frame, wrap=tk.WORD)
        self.details_text.pack(fill=tk.BOTH, expand=True)

        # Bind selection to show details
        self.results_tree.bind("<<TreeviewSelect>>", self._show_result_details)

    def _create_statusbar(self):
        """Create the status bar at the bottom of the window."""
        status_frame = ttk.Frame(self.root)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)

        self.status_label = ttk.Label(status_frame, text="Ready", style="Status.TLabel")
        self.status_label.pack(side=tk.LEFT, padx=10, pady=5)

        self.results_count = ttk.Label(status_frame, text="Results: 0", style="Status.TLabel")
        self.results_count.pack(side=tk.RIGHT, padx=10, pady=5)

    def _update_status(self, message: str):
        """Update the status bar message.

        Args:
            message: The status message to display
        """
        self.status_label.config(text=message)

    def _update_results_count(self):
        """Update the results count display."""
        count = len(self.results_tree.get_children())
        self.results_count.config(text=f"Results: {count}")

    def log_message(self, message: str, level: str = "INFO"):
        """Add a message to the log panel.

        Args:
            message: The message to log
            level: The log level (INFO, WARNING, ERROR, SUCCESS, DEBUG)
        """
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted = f"[{timestamp}] [{level}] {message}\n"

        self.log_text.configure(state="normal")
        self.log_text.insert(tk.END, formatted, level)
        self.log_text.see(tk.END)
        self.log_text.configure(state="disabled")

    def _set_search_type(self, search_type: str):
        """Set the search type from menu.

        Args:
            search_type: The type of search to perform
        """
        self.search_type.set(search_type)
        self.search_entry.focus_set()

    def _start_search(self):
        """Start the search operation."""
        query = self.search_entry.get().strip()
        if not query:
            messagebox.showwarning("Input Required", "Please enter a search query.")
            return

        if self.is_searching:
            messagebox.showinfo("Search in Progress", "A search is already in progress.")
            return

        self.is_searching = True
        search_type = self.search_type.get()

        # Update UI
        self.search_btn.pack_forget()
        self.stop_btn.pack(fill=tk.X, pady=10)
        self.progress.start(10)
        self._update_status(f"Searching for {search_type}: {query}...")
        self.log_message(f"Starting {search_type} search for: {query}", "INFO")

        # Run search asynchronously
        self._run_async(self._execute_search(search_type, query), self._on_search_complete)

    async def _execute_search(self, search_type: str, query: str) -> List[Any]:
        """Execute the search operation.

        Args:
            search_type: The type of search to perform
            query: The search query

        Returns:
            List of search results
        """
        results: List[Any] = []
        fuzzy = self.fuzzy_var.get()

        try:
            if search_type == "username":
                results = await self.orchestrator.search_username(query, fuzzy=fuzzy)
            elif search_type == "email":
                results = await self.orchestrator.search_email(query)
            elif search_type == "name":
                # Name search takes the full name as a single string
                results = await self.orchestrator.search_name(query)
            elif search_type == "phone":
                results = await self.orchestrator.search_phone(query)
            elif search_type == "all":
                all_results = await self.orchestrator.search_all(query)
                # Flatten dict results into a single list
                results = []
                for result_list in all_results.values():
                    results.extend(result_list)

            # Deduplicate if enabled
            if self.dedupe_var.get() and results:
                from src.core.deduplication import deduplicate_results
                from src.core.data_models import Result

                # Ensure we have a list of Result objects
                if results and isinstance(results[0], Result):
                    results = deduplicate_results(results)

        except Exception as e:

            raise

        return results

    def _on_search_complete(self, results: List[Any]) -> None:
        """Handle search completion.

        Args:
            results: The search results
        """
        self.is_searching = False

        # Update UI
        self.stop_btn.pack_forget()
        self.search_btn.pack(fill=tk.X, pady=10)
        self.progress.stop()

        # Display results
        self.search_results = results
        self._display_results(results)

        self.log_message(f"Search complete. Found {len(results)} results.", "SUCCESS")
        self._update_status(f"Search complete - {len(results)} results found")

    def _stop_search(self):
        """Stop the current search operation."""
        # Note: Proper cancellation would require more sophisticated async handling
        self.is_searching = False
        self.stop_btn.pack_forget()
        self.search_btn.pack(fill=tk.X, pady=10)
        self.progress.stop()
        self.log_message("Search stopped by user", "WARNING")
        self._update_status("Search stopped")

    def _display_results(self, results: List[Any]) -> None:
        """Display search results in the tree view.

        Args:
            results: The search results to display
        """
        # Clear existing results
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)

        # Add new results
        for result in results:
            # Handle both dict and Result object
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

            confidence_str = (
                f"{confidence:.0%}" if isinstance(confidence, float) else str(confidence)
            )

            self.results_tree.insert(
                "", tk.END, values=(source, identifier, url, confidence_str, timestamp)
            )

        self._update_results_count()

    def _show_result_details(self, event: Any) -> None:
        """Show details for the selected result.

        Args:
            event: The selection event
        """
        selection = self.results_tree.selection()
        if not selection:
            return

        item = self.results_tree.item(selection[0])
        values = item["values"]

        if not values:
            return

        # Find the corresponding result
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

        # Display details
        self.details_text.delete(1.0, tk.END)

        if result_detail:
            if hasattr(result_detail, "__dict__"):
                detail_dict = result_detail.__dict__
            else:
                detail_dict = result_detail

            formatted = json.dumps(detail_dict, indent=2, default=str)
            self.details_text.insert(tk.END, formatted)
        else:
            self.details_text.insert(tk.END, f"Source: {values[0]}\n")
            self.details_text.insert(tk.END, f"Identifier: {values[1]}\n")
            self.details_text.insert(tk.END, f"URL: {values[2]}\n")
            self.details_text.insert(tk.END, f"Confidence: {values[3]}\n")
            self.details_text.insert(tk.END, f"Timestamp: {values[4]}\n")

    def _open_result_url(self, event):
        """Open the URL of the selected result in a browser.

        Args:
            event: The double-click event
        """
        selection = self.results_tree.selection()
        if not selection:
            return

        item = self.results_tree.item(selection[0])
        url = item["values"][2]

        if url:
            import webbrowser

            webbrowser.open(url)

    def _handle_error(self, error: Exception):
        """Handle errors during async operations.

        Args:
            error: The exception that occurred
        """
        self.is_searching = False
        self.stop_btn.pack_forget()
        self.search_btn.pack(fill=tk.X, pady=10)
        self.progress.stop()

        self.log_message(f"Error: {error}", "ERROR")
        self._update_status("Error occurred")
        messagebox.showerror("Error", str(error))

    def _export_results(self):
        """Export current results to a file."""
        if not self.search_results:
            messagebox.showinfo("No Results", "No results to export.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("CSV files", "*.csv"), ("All files", "*.*")],
        )

        if not file_path:
            return

        try:
            # Convert results to serializable format
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
            messagebox.showinfo("Export Complete", f"Results exported to {file_path}")

        except Exception as e:
            self.log_message(f"Export error: {e}", "ERROR")
            messagebox.showerror("Export Error", str(e))

    def _import_targets(self):
        """Import search targets from a file."""
        file_path = filedialog.askopenfilename(
            filetypes=[("Text files", "*.txt"), ("JSON files", "*.json"), ("All files", "*.*")]
        )

        if not file_path:
            return

        try:
            targets = []
            if file_path.endswith(".json"):
                with open(file_path, "r") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        targets = data
                    else:
                        targets = [data]
            else:
                with open(file_path, "r") as f:
                    targets = [line.strip() for line in f if line.strip()]

            self.log_message(f"Imported {len(targets)} targets from {file_path}", "INFO")
            messagebox.showinfo(
                "Import Complete",
                f"Imported {len(targets)} targets.\n\nFirst target loaded in search field.",
            )

            if targets:
                self.search_entry.delete(0, tk.END)
                self.search_entry.insert(0, str(targets[0]))

        except Exception as e:
            self.log_message(f"Import error: {e}", "ERROR")
            messagebox.showerror("Import Error", str(e))

    def _clear_results(self):
        """Clear all current results."""
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        self.search_results = []
        self.details_text.delete(1.0, tk.END)
        self._update_results_count()
        self.log_message("Results cleared", "INFO")

    def _show_history(self):
        """Show search history in a dialog."""
        history_window = tk.Toplevel(self.root)
        history_window.title("Search History")
        history_window.geometry("600x400")
        history_window.transient(self.root)

        # History tree
        columns = ("ID", "Type", "Query", "Results", "Timestamp")
        history_tree = ttk.Treeview(history_window, columns=columns, show="headings")

        for col in columns:
            history_tree.heading(col, text=col)
            history_tree.column(col, width=100)

        history_tree.column("Query", width=200)

        scrollbar = ttk.Scrollbar(history_window, orient=tk.VERTICAL, command=history_tree.yview)
        history_tree.configure(yscrollcommand=scrollbar.set)

        history_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Load history
        try:
            history = self.database.get_search_history(limit=100)
            for entry in history:
                history_tree.insert(
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

    def _clear_history(self):
        """Clear search history."""
        if messagebox.askyesno("Confirm", "Are you sure you want to clear all search history?"):
            try:
                # Use direct SQL since clear_history doesn't exist
                with self.database._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("DELETE FROM results")
                    cursor.execute("DELETE FROM search_history")
                self.log_message("Search history cleared", "INFO")
                messagebox.showinfo("Success", "Search history cleared.")
            except Exception as e:
                self.log_message(f"Error clearing history: {e}", "ERROR")
                messagebox.showerror("Error", str(e))

    def _show_stats(self):
        """Show database and cache statistics."""
        stats_window = tk.Toplevel(self.root)
        stats_window.title("Statistics")
        stats_window.geometry("400x300")
        stats_window.transient(self.root)

        stats_text = scrolledtext.ScrolledText(stats_window, wrap=tk.WORD)
        stats_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        try:
            stats = self.database.get_statistics()
            stats_text.insert(tk.END, "Database Statistics\n")
            stats_text.insert(tk.END, "=" * 40 + "\n\n")
            for key, value in stats.items():
                stats_text.insert(tk.END, f"{key}: {value}\n")
        except Exception as e:
            stats_text.insert(tk.END, f"Error loading stats: {e}")

    def _show_cache_manager(self):
        """Show cache management dialog."""
        cache_window = tk.Toplevel(self.root)
        cache_window.title("Cache Management")
        cache_window.geometry("300x150")
        cache_window.transient(self.root)

        frame = ttk.Frame(cache_window, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Cache Management", style="Header.TLabel").pack(pady=(0, 20))

        def clear_cache():
            try:
                self.database.cache_clear()
                self.log_message("Cache cleared", "INFO")
                messagebox.showinfo("Success", "Cache cleared successfully.")
                cache_window.destroy()
            except Exception as e:
                messagebox.showerror("Error", str(e))

        ttk.Button(frame, text="Clear All Cache", command=clear_cache).pack(fill=tk.X, pady=5)
        ttk.Button(frame, text="Close", command=cache_window.destroy).pack(fill=tk.X, pady=5)

    def _show_settings(self):
        """Show settings dialog."""
        settings_window = tk.Toplevel(self.root)
        settings_window.title("Settings")
        settings_window.geometry("400x300")
        settings_window.transient(self.root)

        frame = ttk.Frame(settings_window, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Settings", style="Header.TLabel").pack(pady=(0, 20))

        # Placeholder settings
        ttk.Label(frame, text="Settings will be available in a future update.").pack()

        ttk.Button(frame, text="Close", command=settings_window.destroy).pack(
            side=tk.BOTTOM, pady=10
        )

    def _show_docs(self):
        """Open documentation."""
        docs_path = BASE_DIR / "docs" / "README.md"
        if docs_path.exists():
            import webbrowser

            webbrowser.open(docs_path.as_uri())
        else:
            messagebox.showinfo(
                "Documentation",
                "Documentation is available at: https://github.com/your-repo/tr4c3r",
            )

    def _show_about(self):
        """Show about dialog."""
        about_text = """TR4C3R - OSINT Investigation Tool

Version: 1.0.0

An open-source intelligence gathering tool for investigating digital footprints.

Features:
• Username search across platforms
• Email breach checking
• Name-based people search
• Phone number lookup
• Result correlation and visualization

Licensed under MIT License
"""
        messagebox.showinfo("About TR4C3R", about_text)

    def _on_close(self):
        """Handle application close."""
        if self.is_searching:
            if not messagebox.askyesno("Confirm Exit", "A search is in progress. Exit anyway?"):
                return

        # Stop the event loop
        self._loop.call_soon_threadsafe(self._loop.stop)
        self.root.destroy()


def main():
    """Main entry point for the GUI application."""
    # Configure basic logging
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # Create root window
    root = tk.Tk()

    # Set icon if available
    icon_path = BASE_DIR / "docs" / "assets" / "icon.ico"
    if icon_path.exists():
        try:
            root.iconbitmap(icon_path)
        except tk.TclError:
            pass  # Icon not supported on this platform

    # Create app
    app = TR4C3RApp(root)

    # Handle close
    root.protocol("WM_DELETE_WINDOW", app._on_close)

    # Run
    root.mainloop()


if __name__ == "__main__":
    main()
