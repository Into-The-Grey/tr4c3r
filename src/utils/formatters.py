"""Output formatting utilities for TR4C3R.

Provides formatters for:
- JSON output
- Table output
- CSV export
- Report generation
"""

import csv
import io
import json
from dataclasses import asdict, is_dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Optional, Sequence


class OutputFormat(str, Enum):
    """Supported output formats."""

    JSON = "json"
    TABLE = "table"
    CSV = "csv"
    TEXT = "text"
    MARKDOWN = "markdown"


class DataFormatter:
    """Formats data for various output types."""

    @staticmethod
    def to_dict(obj: Any) -> Any:
        """Convert object to dictionary representation.

        Args:
            obj: Object to convert

        Returns:
            Dictionary or primitive value
        """
        if obj is None:
            return None
        if isinstance(obj, (str, int, float, bool)):
            return obj
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, Enum):
            return obj.value
        if is_dataclass(obj):
            return asdict(obj)
        if isinstance(obj, dict):
            return {k: DataFormatter.to_dict(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple, set)):
            return [DataFormatter.to_dict(item) for item in obj]
        if hasattr(obj, "__dict__"):
            return {
                k: DataFormatter.to_dict(v)
                for k, v in obj.__dict__.items()
                if not k.startswith("_")
            }
        return str(obj)


class JSONFormatter:
    """Formats data as JSON."""

    def __init__(self, indent: int = 2, sort_keys: bool = False):
        """Initialize JSON formatter.

        Args:
            indent: Indentation level
            sort_keys: Whether to sort dictionary keys
        """
        self.indent = indent
        self.sort_keys = sort_keys

    def format(self, data: Any) -> str:
        """Format data as JSON string.

        Args:
            data: Data to format

        Returns:
            JSON string
        """
        converted = DataFormatter.to_dict(data)
        return json.dumps(
            converted,
            indent=self.indent,
            sort_keys=self.sort_keys,
            default=str,
        )

    def format_compact(self, data: Any) -> str:
        """Format data as compact JSON.

        Args:
            data: Data to format

        Returns:
            Compact JSON string
        """
        converted = DataFormatter.to_dict(data)
        return json.dumps(converted, default=str)


class TableFormatter:
    """Formats data as ASCII tables."""

    def __init__(
        self,
        max_width: int = 80,
        column_separator: str = " | ",
        header_separator: str = "-",
    ):
        """Initialize table formatter.

        Args:
            max_width: Maximum column width
            column_separator: Separator between columns
            header_separator: Character for header separator line
        """
        self.max_width = max_width
        self.column_separator = column_separator
        self.header_separator = header_separator

    def format(
        self,
        data: Sequence[dict],
        columns: Optional[list[str]] = None,
        headers: Optional[dict[str, str]] = None,
    ) -> str:
        """Format data as ASCII table.

        Args:
            data: List of dictionaries
            columns: Columns to include (defaults to all keys)
            headers: Custom column headers

        Returns:
            Formatted table string
        """
        if not data:
            return "(no data)"

        # Get columns from first row if not specified
        if columns is None:
            columns = list(data[0].keys())

        # Get headers
        if headers is None:
            headers = {col: col.replace("_", " ").title() for col in columns}

        # Calculate column widths
        widths = {}
        for col in columns:
            header_width = len(headers.get(col, col))
            max_data_width = max((len(str(row.get(col, ""))) for row in data), default=0)
            widths[col] = min(max(header_width, max_data_width), self.max_width)

        # Build table
        lines = []

        # Header row
        header_parts = [headers.get(col, col).ljust(widths[col])[: widths[col]] for col in columns]
        lines.append(self.column_separator.join(header_parts))

        # Separator row
        sep_parts = [self.header_separator * widths[col] for col in columns]
        lines.append(self.column_separator.join(sep_parts))

        # Data rows
        for row in data:
            row_parts = [str(row.get(col, "")).ljust(widths[col])[: widths[col]] for col in columns]
            lines.append(self.column_separator.join(row_parts))

        return "\n".join(lines)

    def format_simple(self, data: dict) -> str:
        """Format a single dictionary as key-value pairs.

        Args:
            data: Dictionary to format

        Returns:
            Formatted string
        """
        if not data:
            return "(no data)"

        max_key_len = max(len(str(k)) for k in data.keys())
        lines = [f"{str(k).ljust(max_key_len)}: {v}" for k, v in data.items()]
        return "\n".join(lines)


class CSVFormatter:
    """Formats data as CSV."""

    def __init__(
        self,
        delimiter: str = ",",
        quoting: int = csv.QUOTE_MINIMAL,
    ):
        """Initialize CSV formatter.

        Args:
            delimiter: Field delimiter
            quoting: CSV quoting style
        """
        self.delimiter = delimiter
        self.quoting = quoting

    def format(
        self,
        data: Sequence[dict],
        columns: Optional[list[str]] = None,
    ) -> str:
        """Format data as CSV string.

        Args:
            data: List of dictionaries
            columns: Columns to include

        Returns:
            CSV string
        """
        if not data:
            return ""

        if columns is None:
            columns = list(data[0].keys())

        output = io.StringIO()
        writer = csv.DictWriter(
            output,
            fieldnames=columns,
            delimiter=self.delimiter,
            quoting=self.quoting,
            extrasaction="ignore",
        )

        writer.writeheader()
        for row in data:
            # Convert values to strings
            row_str = {k: str(v) if v is not None else "" for k, v in row.items()}
            writer.writerow(row_str)

        return output.getvalue()


class MarkdownFormatter:
    """Formats data as Markdown."""

    def format_table(
        self,
        data: Sequence[dict],
        columns: Optional[list[str]] = None,
        headers: Optional[dict[str, str]] = None,
    ) -> str:
        """Format data as Markdown table.

        Args:
            data: List of dictionaries
            columns: Columns to include
            headers: Custom column headers

        Returns:
            Markdown table string
        """
        if not data:
            return "*No data*"

        if columns is None:
            columns = list(data[0].keys())

        if headers is None:
            headers = {col: col.replace("_", " ").title() for col in columns}

        lines = []

        # Header row
        header_row = " | ".join(headers.get(col, col) for col in columns)
        lines.append(f"| {header_row} |")

        # Separator row
        sep_row = " | ".join("---" for _ in columns)
        lines.append(f"| {sep_row} |")

        # Data rows
        for row in data:
            data_row = " | ".join(str(row.get(col, "")).replace("|", "\\|") for col in columns)
            lines.append(f"| {data_row} |")

        return "\n".join(lines)

    def format_list(self, items: Sequence[str], ordered: bool = False) -> str:
        """Format list as Markdown.

        Args:
            items: List items
            ordered: Whether to use ordered list

        Returns:
            Markdown list string
        """
        lines = []
        for i, item in enumerate(items, 1):
            prefix = f"{i}." if ordered else "-"
            lines.append(f"{prefix} {item}")
        return "\n".join(lines)

    def format_code_block(self, code: str, language: str = "") -> str:
        """Format code block.

        Args:
            code: Code content
            language: Programming language

        Returns:
            Markdown code block
        """
        return f"```{language}\n{code}\n```"

    def format_section(self, title: str, content: str, level: int = 2) -> str:
        """Format section with heading.

        Args:
            title: Section title
            content: Section content
            level: Heading level (1-6)

        Returns:
            Markdown section
        """
        heading = "#" * min(max(level, 1), 6)
        return f"{heading} {title}\n\n{content}"


class ReportGenerator:
    """Generates formatted reports from search results."""

    def __init__(self):
        """Initialize report generator."""
        self.json_formatter = JSONFormatter()
        self.table_formatter = TableFormatter()
        self.csv_formatter = CSVFormatter()
        self.markdown_formatter = MarkdownFormatter()

    def generate(
        self,
        data: Any,
        format: OutputFormat = OutputFormat.JSON,
        title: Optional[str] = None,
        columns: Optional[list[str]] = None,
    ) -> str:
        """Generate formatted report.

        Args:
            data: Data to format
            format: Output format
            title: Optional report title
            columns: Columns for table/CSV formats

        Returns:
            Formatted report string
        """
        # Convert to list of dicts if needed
        if is_dataclass(data):
            data = [asdict(data)]
        elif isinstance(data, dict):
            if not any(isinstance(v, (dict, list)) for v in data.values()):
                data = [data]

        if format == OutputFormat.JSON:
            result = self.json_formatter.format(data)
        elif format == OutputFormat.TABLE:
            if isinstance(data, list):
                result = self.table_formatter.format(data, columns)
            else:
                result = self.table_formatter.format_simple(data)
        elif format == OutputFormat.CSV:
            result = self.csv_formatter.format(data, columns)
        elif format == OutputFormat.MARKDOWN:
            if isinstance(data, list):
                result = self.markdown_formatter.format_table(data, columns)
            else:
                result = self.json_formatter.format(data)
        elif format == OutputFormat.TEXT:
            result = self._format_text(data)
        else:
            result = str(data)

        if title:
            if format == OutputFormat.MARKDOWN:
                result = f"# {title}\n\n{result}"
            else:
                result = f"{title}\n{'=' * len(title)}\n\n{result}"

        return result

    def _format_text(self, data: Any, indent: int = 0) -> str:
        """Format data as plain text.

        Args:
            data: Data to format
            indent: Indentation level

        Returns:
            Plain text representation
        """
        prefix = "  " * indent

        if data is None:
            return f"{prefix}(none)"

        if isinstance(data, (str, int, float, bool)):
            return f"{prefix}{data}"

        if isinstance(data, dict):
            lines = []
            for key, value in data.items():
                if isinstance(value, (dict, list)):
                    lines.append(f"{prefix}{key}:")
                    lines.append(self._format_text(value, indent + 1))
                else:
                    lines.append(f"{prefix}{key}: {value}")
            return "\n".join(lines)

        if isinstance(data, list):
            lines = []
            for i, item in enumerate(data):
                if isinstance(item, dict):
                    lines.append(f"{prefix}[{i}]")
                    lines.append(self._format_text(item, indent + 1))
                else:
                    lines.append(f"{prefix}- {item}")
            return "\n".join(lines)

        return f"{prefix}{str(data)}"


# Singleton instances
_json_formatter = JSONFormatter()
_table_formatter = TableFormatter()
_csv_formatter = CSVFormatter()
_markdown_formatter = MarkdownFormatter()
_report_generator = ReportGenerator()


def to_json(data: Any, indent: int = 2) -> str:
    """Format data as JSON."""
    return JSONFormatter(indent=indent).format(data)


def to_table(data: Sequence[dict], columns: Optional[list[str]] = None) -> str:
    """Format data as ASCII table."""
    return _table_formatter.format(data, columns)


def to_csv(data: Sequence[dict], columns: Optional[list[str]] = None) -> str:
    """Format data as CSV."""
    return _csv_formatter.format(data, columns)


def to_markdown(data: Sequence[dict], columns: Optional[list[str]] = None) -> str:
    """Format data as Markdown table."""
    return _markdown_formatter.format_table(data, columns)


def generate_report(
    data: Any,
    format: OutputFormat = OutputFormat.JSON,
    title: Optional[str] = None,
) -> str:
    """Generate formatted report."""
    return _report_generator.generate(data, format, title)
