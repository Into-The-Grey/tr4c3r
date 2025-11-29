"""Report generation for TR4C3R.

Generates professional PDF and HTML reports from search results,
including visualizations, statistics, and executive summaries.
"""

from __future__ import annotations

import base64
import io
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import html as html_module

logger = logging.getLogger(__name__)


class ReportFormat(Enum):
    """Supported report output formats."""

    HTML = "html"
    PDF = "pdf"
    MARKDOWN = "markdown"


class ReportSection(Enum):
    """Sections that can be included in a report."""

    EXECUTIVE_SUMMARY = "executive_summary"
    SEARCH_DETAILS = "search_details"
    RESULTS_TABLE = "results_table"
    TIMELINE = "timeline"
    GRAPH_VISUALIZATION = "graph_visualization"
    STATISTICS = "statistics"
    SOURCE_BREAKDOWN = "source_breakdown"
    CONFIDENCE_ANALYSIS = "confidence_analysis"
    RAW_DATA = "raw_data"
    METHODOLOGY = "methodology"
    DISCLAIMER = "disclaimer"


@dataclass
class ReportConfig:
    """Configuration for report generation."""

    title: str = "TR4C3R Investigation Report"
    subtitle: str = ""
    author: str = "TR4C3R OSINT Platform"
    organization: str = ""
    classification: str = "CONFIDENTIAL"
    include_sections: List[ReportSection] = field(
        default_factory=lambda: [
            ReportSection.EXECUTIVE_SUMMARY,
            ReportSection.SEARCH_DETAILS,
            ReportSection.RESULTS_TABLE,
            ReportSection.STATISTICS,
            ReportSection.SOURCE_BREAKDOWN,
            ReportSection.DISCLAIMER,
        ]
    )
    theme: str = "dark"  # dark, light, professional
    logo_path: Optional[str] = None
    include_timestamp: bool = True
    include_page_numbers: bool = True
    redact_sensitive: bool = False
    max_results_per_page: int = 50


@dataclass
class SearchSummary:
    """Summary of a search for reporting."""

    search_type: str
    query: str
    timestamp: datetime
    total_results: int
    unique_sources: int
    avg_confidence: float
    high_confidence_count: int  # confidence > 0.7
    results: List[Dict[str, Any]] = field(default_factory=list)
    graph_data: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class ReportTheme:
    """CSS themes for HTML reports."""

    DARK = """
        :root {
            --bg-primary: #1a1a2e;
            --bg-secondary: #16213e;
            --bg-tertiary: #0f3460;
            --text-primary: #eaeaea;
            --text-secondary: #a0a0a0;
            --accent: #e94560;
            --accent-secondary: #16c79a;
            --border: #333;
            --success: #16c79a;
            --warning: #ff9a3c;
            --danger: #e94560;
        }
    """

    LIGHT = """
        :root {
            --bg-primary: #ffffff;
            --bg-secondary: #f5f5f5;
            --bg-tertiary: #e0e0e0;
            --text-primary: #333333;
            --text-secondary: #666666;
            --accent: #2563eb;
            --accent-secondary: #059669;
            --border: #ddd;
            --success: #059669;
            --warning: #d97706;
            --danger: #dc2626;
        }
    """

    PROFESSIONAL = """
        :root {
            --bg-primary: #ffffff;
            --bg-secondary: #f8fafc;
            --bg-tertiary: #e2e8f0;
            --text-primary: #1e293b;
            --text-secondary: #64748b;
            --accent: #0f172a;
            --accent-secondary: #475569;
            --border: #cbd5e1;
            --success: #15803d;
            --warning: #a16207;
            --danger: #b91c1c;
        }
    """


class ReportGenerator:
    """Generates professional reports from search results."""

    def __init__(self, config: Optional[ReportConfig] = None):
        """Initialize the report generator.

        Args:
            config: Report configuration options
        """
        self.config = config or ReportConfig()
        self.logger = logging.getLogger(self.__class__.__name__)

    def generate(
        self,
        summary: SearchSummary,
        output_path: str,
        format: ReportFormat = ReportFormat.HTML,
    ) -> bool:
        """Generate a report from search results.

        Args:
            summary: Search summary data
            output_path: Path to save the report
            format: Output format (HTML, PDF, Markdown)

        Returns:
            True if generation was successful
        """
        try:
            self.logger.info(f"Generating {format.value} report: {output_path}")

            if format == ReportFormat.HTML:
                content = self._generate_html(summary)
            elif format == ReportFormat.MARKDOWN:
                content = self._generate_markdown(summary)
            elif format == ReportFormat.PDF:
                return self._generate_pdf(summary, output_path)
            else:
                raise ValueError(f"Unsupported format: {format}")

            # Write content to file
            output_path_obj = Path(output_path)
            output_path_obj.parent.mkdir(parents=True, exist_ok=True)
            output_path_obj.write_text(content, encoding="utf-8")

            self.logger.info(f"Report generated successfully: {output_path}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to generate report: {e}", exc_info=True)
            return False

    def _get_theme_css(self) -> str:
        """Get CSS for the selected theme."""
        themes = {
            "dark": ReportTheme.DARK,
            "light": ReportTheme.LIGHT,
            "professional": ReportTheme.PROFESSIONAL,
        }
        return themes.get(self.config.theme, ReportTheme.DARK)

    def _generate_html(self, summary: SearchSummary) -> str:
        """Generate an HTML report."""
        sections_html = []

        for section in self.config.include_sections:
            if section == ReportSection.EXECUTIVE_SUMMARY:
                sections_html.append(self._html_executive_summary(summary))
            elif section == ReportSection.SEARCH_DETAILS:
                sections_html.append(self._html_search_details(summary))
            elif section == ReportSection.RESULTS_TABLE:
                sections_html.append(self._html_results_table(summary))
            elif section == ReportSection.STATISTICS:
                sections_html.append(self._html_statistics(summary))
            elif section == ReportSection.SOURCE_BREAKDOWN:
                sections_html.append(self._html_source_breakdown(summary))
            elif section == ReportSection.CONFIDENCE_ANALYSIS:
                sections_html.append(self._html_confidence_analysis(summary))
            elif section == ReportSection.TIMELINE:
                sections_html.append(self._html_timeline(summary))
            elif section == ReportSection.METHODOLOGY:
                sections_html.append(self._html_methodology())
            elif section == ReportSection.DISCLAIMER:
                sections_html.append(self._html_disclaimer())

        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html_module.escape(self.config.title)}</title>
    <style>
        {self._get_theme_css()}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, Oxygen, Ubuntu, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 0;
        }}
        
        .report-container {{
            max-width: 1000px;
            margin: 0 auto;
            padding: 40px;
        }}
        
        .header {{
            text-align: center;
            padding: 40px 0;
            border-bottom: 3px solid var(--accent);
            margin-bottom: 40px;
        }}
        
        .header h1 {{
            font-size: 2.5rem;
            font-weight: 700;
            color: var(--text-primary);
            margin-bottom: 10px;
        }}
        
        .header .subtitle {{
            font-size: 1.2rem;
            color: var(--text-secondary);
        }}
        
        .header .classification {{
            display: inline-block;
            background: var(--accent);
            color: white;
            padding: 5px 20px;
            border-radius: 4px;
            font-size: 0.9rem;
            font-weight: 600;
            margin-top: 15px;
            letter-spacing: 1px;
        }}
        
        .header .metadata {{
            margin-top: 20px;
            font-size: 0.9rem;
            color: var(--text-secondary);
        }}
        
        .section {{
            background: var(--bg-secondary);
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 30px;
            border: 1px solid var(--border);
        }}
        
        .section h2 {{
            font-size: 1.5rem;
            color: var(--text-primary);
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid var(--accent);
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .section h2 .icon {{
            font-size: 1.3rem;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        
        .stat-card {{
            background: var(--bg-tertiary);
            padding: 25px;
            border-radius: 10px;
            text-align: center;
        }}
        
        .stat-card .value {{
            font-size: 2.5rem;
            font-weight: 700;
            color: var(--accent);
        }}
        
        .stat-card .label {{
            font-size: 0.9rem;
            color: var(--text-secondary);
            margin-top: 5px;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}
        
        table th {{
            background: var(--bg-tertiary);
            padding: 15px;
            text-align: left;
            font-weight: 600;
            color: var(--text-primary);
            border-bottom: 2px solid var(--border);
        }}
        
        table td {{
            padding: 15px;
            border-bottom: 1px solid var(--border);
            color: var(--text-primary);
        }}
        
        table tr:hover {{
            background: var(--bg-tertiary);
        }}
        
        .confidence-badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 600;
        }}
        
        .confidence-high {{
            background: rgba(22, 199, 154, 0.2);
            color: var(--success);
        }}
        
        .confidence-medium {{
            background: rgba(255, 154, 60, 0.2);
            color: var(--warning);
        }}
        
        .confidence-low {{
            background: rgba(233, 69, 96, 0.2);
            color: var(--danger);
        }}
        
        .source-tag {{
            display: inline-block;
            background: var(--accent);
            color: white;
            padding: 3px 10px;
            border-radius: 4px;
            font-size: 0.8rem;
            margin: 2px;
        }}
        
        .progress-bar {{
            height: 8px;
            background: var(--bg-tertiary);
            border-radius: 4px;
            overflow: hidden;
        }}
        
        .progress-bar .fill {{
            height: 100%;
            background: var(--accent);
            border-radius: 4px;
        }}
        
        .source-row {{
            display: flex;
            align-items: center;
            padding: 15px 0;
            border-bottom: 1px solid var(--border);
        }}
        
        .source-row .name {{
            flex: 1;
            font-weight: 500;
        }}
        
        .source-row .count {{
            width: 60px;
            text-align: right;
            margin-right: 20px;
            color: var(--text-secondary);
        }}
        
        .source-row .bar {{
            width: 200px;
        }}
        
        .footer {{
            text-align: center;
            padding: 40px;
            color: var(--text-secondary);
            font-size: 0.9rem;
            border-top: 1px solid var(--border);
            margin-top: 40px;
        }}
        
        .disclaimer {{
            background: rgba(233, 69, 96, 0.1);
            border-left: 4px solid var(--danger);
            padding: 20px;
            margin-top: 20px;
            font-size: 0.9rem;
            color: var(--text-secondary);
        }}
        
        .url-link {{
            color: var(--accent);
            text-decoration: none;
            word-break: break-all;
        }}
        
        .url-link:hover {{
            text-decoration: underline;
        }}
        
        @media print {{
            body {{
                background: white;
                color: black;
            }}
            .section {{
                break-inside: avoid;
            }}
            .no-print {{
                display: none;
            }}
        }}
    </style>
</head>
<body>
    <div class="report-container">
        <div class="header">
            <h1>🔍 {html_module.escape(self.config.title)}</h1>
            {f'<p class="subtitle">{html_module.escape(self.config.subtitle)}</p>' if self.config.subtitle else ''}
            <div class="classification">{html_module.escape(self.config.classification)}</div>
            <div class="metadata">
                <p>Generated: {timestamp}</p>
                {f'<p>Author: {html_module.escape(self.config.author)}</p>' if self.config.author else ''}
                {f'<p>Organization: {html_module.escape(self.config.organization)}</p>' if self.config.organization else ''}
            </div>
        </div>
        
        {''.join(sections_html)}
        
        <div class="footer">
            <p>Generated by TR4C3R OSINT Platform</p>
            <p>{timestamp}</p>
        </div>
    </div>
</body>
</html>
"""
        return html

    def _html_executive_summary(self, summary: SearchSummary) -> str:
        """Generate executive summary section."""
        confidence_desc = (
            "high"
            if summary.avg_confidence > 0.7
            else "medium" if summary.avg_confidence > 0.4 else "low"
        )

        return f"""
        <div class="section">
            <h2><span class="icon">📋</span> Executive Summary</h2>
            <p>
                This report presents the findings from an OSINT investigation conducted on 
                <strong>{html_module.escape(summary.query)}</strong> ({summary.search_type} search).
            </p>
            <p style="margin-top: 15px;">
                The investigation identified <strong>{summary.total_results} result(s)</strong> across 
                <strong>{summary.unique_sources} unique source(s)</strong>. 
                The average confidence level is <strong>{summary.avg_confidence:.0%}</strong> ({confidence_desc}), 
                with <strong>{summary.high_confidence_count}</strong> high-confidence finding(s).
            </p>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="value">{summary.total_results}</div>
                    <div class="label">Total Results</div>
                </div>
                <div class="stat-card">
                    <div class="value">{summary.unique_sources}</div>
                    <div class="label">Unique Sources</div>
                </div>
                <div class="stat-card">
                    <div class="value">{summary.avg_confidence:.0%}</div>
                    <div class="label">Avg Confidence</div>
                </div>
                <div class="stat-card">
                    <div class="value">{summary.high_confidence_count}</div>
                    <div class="label">High Confidence</div>
                </div>
            </div>
        </div>
        """

    def _html_search_details(self, summary: SearchSummary) -> str:
        """Generate search details section."""
        return f"""
        <div class="section">
            <h2><span class="icon">🔎</span> Search Details</h2>
            <table>
                <tr>
                    <th style="width: 200px;">Parameter</th>
                    <th>Value</th>
                </tr>
                <tr>
                    <td><strong>Search Type</strong></td>
                    <td>{html_module.escape(summary.search_type.upper())}</td>
                </tr>
                <tr>
                    <td><strong>Query</strong></td>
                    <td><code>{html_module.escape(summary.query)}</code></td>
                </tr>
                <tr>
                    <td><strong>Timestamp</strong></td>
                    <td>{summary.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}</td>
                </tr>
            </table>
        </div>
        """

    def _html_results_table(self, summary: SearchSummary) -> str:
        """Generate results table section."""
        if not summary.results:
            return """
            <div class="section">
                <h2><span class="icon">📊</span> Results</h2>
                <p>No results found.</p>
            </div>
            """

        rows = []
        for i, result in enumerate(summary.results[: self.config.max_results_per_page], 1):
            source = result.get("source", "Unknown")
            identifier = result.get("identifier", "")
            url = result.get("url", "")
            confidence = result.get("confidence", 0)

            # Determine confidence class
            if confidence > 0.7:
                conf_class = "confidence-high"
            elif confidence > 0.4:
                conf_class = "confidence-medium"
            else:
                conf_class = "confidence-low"

            # Redact if configured
            if self.config.redact_sensitive:
                identifier = self._redact(identifier)

            url_html = (
                f'<a href="{html_module.escape(url)}" class="url-link" target="_blank">{html_module.escape(url[:50])}...</a>'
                if url
                else "-"
            )

            rows.append(
                f"""
                <tr>
                    <td>{i}</td>
                    <td><span class="source-tag">{html_module.escape(source)}</span></td>
                    <td>{html_module.escape(identifier)}</td>
                    <td>{url_html}</td>
                    <td><span class="confidence-badge {conf_class}">{confidence:.0%}</span></td>
                </tr>
            """
            )

        truncated_notice = ""
        if len(summary.results) > self.config.max_results_per_page:
            truncated_notice = f'<p style="margin-top: 15px; color: var(--text-secondary);">Showing {self.config.max_results_per_page} of {len(summary.results)} results.</p>'

        return f"""
        <div class="section">
            <h2><span class="icon">📊</span> Results ({len(summary.results)})</h2>
            <table>
                <tr>
                    <th style="width: 50px;">#</th>
                    <th style="width: 120px;">Source</th>
                    <th>Identifier</th>
                    <th>URL</th>
                    <th style="width: 100px;">Confidence</th>
                </tr>
                {''.join(rows)}
            </table>
            {truncated_notice}
        </div>
        """

    def _html_statistics(self, summary: SearchSummary) -> str:
        """Generate statistics section."""
        # Calculate additional stats
        if summary.results:
            confidences = [r.get("confidence", 0) for r in summary.results]
            max_conf = max(confidences)
            min_conf = min(confidences)
        else:
            max_conf = min_conf = 0

        return f"""
        <div class="section">
            <h2><span class="icon">📈</span> Statistics</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="value">{summary.total_results}</div>
                    <div class="label">Total Results</div>
                </div>
                <div class="stat-card">
                    <div class="value">{summary.unique_sources}</div>
                    <div class="label">Sources Queried</div>
                </div>
                <div class="stat-card">
                    <div class="value">{max_conf:.0%}</div>
                    <div class="label">Max Confidence</div>
                </div>
                <div class="stat-card">
                    <div class="value">{min_conf:.0%}</div>
                    <div class="label">Min Confidence</div>
                </div>
            </div>
        </div>
        """

    def _html_source_breakdown(self, summary: SearchSummary) -> str:
        """Generate source breakdown section."""
        # Count results by source
        source_counts: Dict[str, int] = {}
        for result in summary.results:
            source = result.get("source", "Unknown")
            source_counts[source] = source_counts.get(source, 0) + 1

        if not source_counts:
            return ""

        max_count = max(source_counts.values())

        rows = []
        for source, count in sorted(source_counts.items(), key=lambda x: -x[1]):
            percentage = (count / max_count) * 100
            rows.append(
                f"""
                <div class="source-row">
                    <div class="name">{html_module.escape(source)}</div>
                    <div class="count">{count}</div>
                    <div class="bar">
                        <div class="progress-bar">
                            <div class="fill" style="width: {percentage}%"></div>
                        </div>
                    </div>
                </div>
            """
            )

        return f"""
        <div class="section">
            <h2><span class="icon">🗂️</span> Source Breakdown</h2>
            {''.join(rows)}
        </div>
        """

    def _html_confidence_analysis(self, summary: SearchSummary) -> str:
        """Generate confidence analysis section."""
        if not summary.results:
            return ""

        # Group by confidence level
        high = sum(1 for r in summary.results if r.get("confidence", 0) > 0.7)
        medium = sum(1 for r in summary.results if 0.4 < r.get("confidence", 0) <= 0.7)
        low = sum(1 for r in summary.results if r.get("confidence", 0) <= 0.4)
        total = len(summary.results)

        return f"""
        <div class="section">
            <h2><span class="icon">🎯</span> Confidence Analysis</h2>
            <div class="source-row">
                <div class="name"><span class="confidence-badge confidence-high">High (&gt;70%)</span></div>
                <div class="count">{high}</div>
                <div class="bar">
                    <div class="progress-bar">
                        <div class="fill" style="width: {(high/total)*100 if total else 0}%; background: var(--success);"></div>
                    </div>
                </div>
            </div>
            <div class="source-row">
                <div class="name"><span class="confidence-badge confidence-medium">Medium (40-70%)</span></div>
                <div class="count">{medium}</div>
                <div class="bar">
                    <div class="progress-bar">
                        <div class="fill" style="width: {(medium/total)*100 if total else 0}%; background: var(--warning);"></div>
                    </div>
                </div>
            </div>
            <div class="source-row">
                <div class="name"><span class="confidence-badge confidence-low">Low (&lt;40%)</span></div>
                <div class="count">{low}</div>
                <div class="bar">
                    <div class="progress-bar">
                        <div class="fill" style="width: {(low/total)*100 if total else 0}%; background: var(--danger);"></div>
                    </div>
                </div>
            </div>
        </div>
        """

    def _html_timeline(self, summary: SearchSummary) -> str:
        """Generate timeline section."""
        # Extract timestamps from results
        events = []
        for result in summary.results:
            ts = result.get("timestamp")
            if ts:
                if isinstance(ts, str):
                    try:
                        ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    except ValueError:
                        continue
                events.append(
                    {
                        "time": ts,
                        "source": result.get("source", "Unknown"),
                        "identifier": result.get("identifier", ""),
                    }
                )

        if not events:
            return ""

        # Sort by time
        events.sort(key=lambda x: x["time"], reverse=True)

        timeline_items = []
        for event in events[:20]:  # Limit to 20 items
            timeline_items.append(
                f"""
                <div style="display: flex; padding: 15px 0; border-bottom: 1px solid var(--border);">
                    <div style="width: 180px; color: var(--text-secondary); font-size: 0.9rem;">
                        {event["time"].strftime("%Y-%m-%d %H:%M")}
                    </div>
                    <div style="flex: 1;">
                        <span class="source-tag">{html_module.escape(event["source"])}</span>
                        <span style="margin-left: 10px;">{html_module.escape(event["identifier"])}</span>
                    </div>
                </div>
            """
            )

        return f"""
        <div class="section">
            <h2><span class="icon">📅</span> Timeline</h2>
            {''.join(timeline_items)}
        </div>
        """

    def _html_methodology(self) -> str:
        """Generate methodology section."""
        return """
        <div class="section">
            <h2><span class="icon">📖</span> Methodology</h2>
            <p>
                This investigation was conducted using TR4C3R, an Open Source Intelligence (OSINT) 
                platform. The following data sources were queried:
            </p>
            <ul style="margin-top: 15px; margin-left: 20px;">
                <li>Social media platforms (Twitter/X, Instagram, Facebook, LinkedIn, Reddit)</li>
                <li>Professional networks and job boards</li>
                <li>Public records and registries</li>
                <li>Code repositories (GitHub, GitLab)</li>
                <li>Domain and DNS records</li>
                <li>Data breach databases (with appropriate authorization)</li>
            </ul>
            <p style="margin-top: 15px;">
                All data was collected from publicly available sources. Confidence scores are 
                calculated based on source reliability, data freshness, and corroboration across 
                multiple sources.
            </p>
        </div>
        """

    def _html_disclaimer(self) -> str:
        """Generate disclaimer section."""
        return """
        <div class="section">
            <h2><span class="icon">⚠️</span> Disclaimer</h2>
            <div class="disclaimer">
                <p>
                    <strong>IMPORTANT:</strong> This report is generated from publicly available 
                    information and should be used for lawful purposes only. The accuracy of 
                    individual data points cannot be guaranteed.
                </p>
                <p style="margin-top: 10px;">
                    Users are responsible for ensuring their use of this information complies 
                    with applicable laws and regulations, including privacy laws and terms of 
                    service of data sources.
                </p>
                <p style="margin-top: 10px;">
                    This report is confidential and intended only for authorized recipients. 
                    Unauthorized distribution is prohibited.
                </p>
            </div>
        </div>
        """

    def _generate_markdown(self, summary: SearchSummary) -> str:
        """Generate a Markdown report."""
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        md = f"""# {self.config.title}

**Classification:** {self.config.classification}  
**Generated:** {timestamp}  
**Author:** {self.config.author}  

---

## Executive Summary

Investigation of **{summary.query}** ({summary.search_type} search) identified **{summary.total_results} result(s)** across **{summary.unique_sources} source(s)**.

| Metric | Value |
|--------|-------|
| Total Results | {summary.total_results} |
| Unique Sources | {summary.unique_sources} |
| Average Confidence | {summary.avg_confidence:.0%} |
| High Confidence Results | {summary.high_confidence_count} |

---

## Search Details

- **Search Type:** {summary.search_type}
- **Query:** `{summary.query}`
- **Timestamp:** {summary.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}

---

## Results

| # | Source | Identifier | Confidence |
|---|--------|------------|------------|
"""

        for i, result in enumerate(summary.results[: self.config.max_results_per_page], 1):
            source = result.get("source", "Unknown")
            identifier = result.get("identifier", "")
            confidence = result.get("confidence", 0)

            if self.config.redact_sensitive:
                identifier = self._redact(identifier)

            md += f"| {i} | {source} | {identifier} | {confidence:.0%} |\n"

        if len(summary.results) > self.config.max_results_per_page:
            md += f"\n*Showing {self.config.max_results_per_page} of {len(summary.results)} results.*\n"

        md += """
---

## Disclaimer

This report is generated from publicly available information. Users are responsible for 
ensuring lawful use of this data. Unauthorized distribution is prohibited.

---

*Generated by TR4C3R OSINT Platform*
"""

        return md

    def _generate_pdf(self, summary: SearchSummary, output_path: str) -> bool:
        """Generate a PDF report using weasyprint or fallback to HTML.

        Args:
            summary: Search summary data
            output_path: Path to save the PDF

        Returns:
            True if successful
        """
        try:
            from weasyprint import HTML  # type: ignore[import-untyped]

            # Generate HTML first
            html_content = self._generate_html(summary)

            # Convert to PDF
            HTML(string=html_content).write_pdf(output_path)
            self.logger.info(f"PDF generated: {output_path}")
            return True

        except ImportError:
            self.logger.warning("weasyprint not installed, falling back to HTML")
            # Save as HTML instead
            html_path = output_path.replace(".pdf", ".html")
            return self.generate(summary, html_path, ReportFormat.HTML)
        except Exception as e:
            self.logger.error(f"PDF generation failed: {e}")
            return False

    def _redact(self, text: str) -> str:
        """Redact sensitive parts of text."""
        if not text:
            return text

        # Keep first and last character, redact middle
        if len(text) <= 4:
            return text[0] + "*" * (len(text) - 1)

        return text[0] + "*" * (len(text) - 2) + text[-1]


def create_report_from_results(
    results: List[Any],
    search_type: str,
    query: str,
    output_path: str,
    format: ReportFormat = ReportFormat.HTML,
    config: Optional[ReportConfig] = None,
) -> bool:
    """Convenience function to create a report from search results.

    Args:
        results: List of Result objects
        search_type: Type of search performed
        query: Search query
        output_path: Path to save report
        format: Output format
        config: Report configuration

    Returns:
        True if successful
    """
    # Convert results to dicts
    result_dicts = []
    sources: set = set()

    for result in results:
        if hasattr(result, "to_dict"):
            d = result.to_dict()
        elif isinstance(result, dict):
            d = result
        else:
            d = {"identifier": str(result)}

        result_dicts.append(d)
        sources.add(d.get("source", "Unknown"))

    # Calculate stats
    confidences = [r.get("confidence", 0) for r in result_dicts]
    avg_conf = sum(confidences) / len(confidences) if confidences else 0
    high_conf = sum(1 for c in confidences if c > 0.7)

    summary = SearchSummary(
        search_type=search_type,
        query=query,
        timestamp=datetime.now(timezone.utc),
        total_results=len(result_dicts),
        unique_sources=len(sources),
        avg_confidence=avg_conf,
        high_confidence_count=high_conf,
        results=result_dicts,
    )

    generator = ReportGenerator(config)
    return generator.generate(summary, output_path, format)
