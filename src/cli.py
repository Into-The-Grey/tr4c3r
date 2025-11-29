#!/usr/bin/env python3
"""Command‑line interface for TR4C3R.

This script exposes a simple CLI allowing users to perform OSINT searches from
the terminal.  It is intended as a starting point and will evolve as the
modules mature.  The CLI supports searching for usernames, emails, names and
phone numbers, and optionally performing all searches together.

Additional commands:
- history: View past searches
- export: Export search results
- stats: View database and cache statistics
- cache: Manage the cache
- validate: Validate configuration
"""

import argparse
import asyncio
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.core.logging_setup import configure_comprehensive_logging
from src.core.orchestrator import Orchestrator
from src.core.config import get_config
from src.core.deduplication import deduplicate_results
from src.core.progress import get_progress_reporter
from src.storage.database import Database

# Global audit and performance loggers
audit_logger = None
performance_logger = None


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="TR4C3R OSINT CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  tr4c3r username octocat --fuzzy
  tr4c3r email john@example.com
  tr4c3r history --limit 10
  tr4c3r export 1 --format json --output results.json
  tr4c3r stats
  tr4c3r cache clear
  tr4c3r validate
        """,
    )
    parser.add_argument(
        "--log-dir",
        type=Path,
        default=Path("logs"),
        help="Directory for log files (default: logs)",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Logging level (default: INFO)",
    )
    parser.add_argument(
        "--json-logs",
        action="store_true",
        help="Use JSON structured logging format",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable result caching for this run",
    )
    parser.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable progress bar",
    )
    parser.add_argument(
        "--dedupe",
        action="store_true",
        default=True,
        help="Enable result deduplication (default: on)",
    )
    parser.add_argument(
        "--no-dedupe",
        action="store_false",
        dest="dedupe",
        help="Disable result deduplication",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Username
    user_parser = subparsers.add_parser("username", help="Search for a username")
    user_parser.add_argument("username", help="The username to search for")
    user_parser.add_argument("--fuzzy", action="store_true", help="Enable fuzzy variant search")

    # Email
    email_parser = subparsers.add_parser("email", help="Search for an email address")
    email_parser.add_argument("email", help="The email address to search for")

    # Name
    name_parser = subparsers.add_parser("name", help="Search for a full name")
    name_parser.add_argument("name", help="The full name to search for")

    # Phone
    phone_parser = subparsers.add_parser("phone", help="Search for a phone number")
    phone_parser.add_argument("number", help="The phone number to search for")

    # All
    all_parser = subparsers.add_parser("all", help="Search across all modules")
    all_parser.add_argument("identifier", help="The identifier to search for")

    # History command
    history_parser = subparsers.add_parser("history", help="View search history")
    history_parser.add_argument(
        "--limit", "-n", type=int, default=20, help="Number of records to show (default: 20)"
    )
    history_parser.add_argument(
        "--type",
        "-t",
        choices=["username", "email", "name", "phone", "all"],
        help="Filter by search type",
    )
    history_parser.add_argument("--json", action="store_true", help="Output as JSON")
    history_parser.add_argument(
        "--show", type=int, metavar="ID", help="Show detailed results for a specific search ID"
    )

    # Export command
    export_parser = subparsers.add_parser("export", help="Export search results")
    export_parser.add_argument("search_id", type=int, help="Search ID to export")
    export_parser.add_argument(
        "--format",
        "-f",
        choices=["json", "csv", "xml"],
        default="json",
        help="Export format (default: json)",
    )
    export_parser.add_argument("--output", "-o", type=Path, help="Output file (default: stdout)")

    # Stats command
    stats_parser = subparsers.add_parser("stats", help="Show database and cache statistics")
    stats_parser.add_argument("--json", action="store_true", help="Output as JSON")

    # Cache command
    cache_parser = subparsers.add_parser("cache", help="Manage cache")
    cache_subparsers = cache_parser.add_subparsers(dest="cache_action", required=True)
    cache_subparsers.add_parser("clear", help="Clear all cache entries")
    cache_subparsers.add_parser("cleanup", help="Remove expired cache entries")
    cache_stats_parser = cache_subparsers.add_parser("stats", help="Show cache statistics")
    cache_stats_parser.add_argument("--json", action="store_true", help="Output as JSON")

    # Validate command
    validate_parser = subparsers.add_parser("validate", help="Validate configuration")
    validate_parser.add_argument(
        "--strict", action="store_true", help="Exit with error if validation fails"
    )

    return parser.parse_args(argv)


async def main_async(args: argparse.Namespace) -> int:
    """Main async entry point.

    Returns:
        Exit code (0 for success, non-zero for errors)
    """
    global audit_logger, performance_logger

    # Configure comprehensive logging
    log_level = getattr(logging, args.log_level)
    audit_logger, performance_logger = configure_comprehensive_logging(
        log_dir=args.log_dir,
        level=log_level,
        use_json=args.json_logs,
        console_output=True,
    )

    logger = logging.getLogger(__name__)
    logger.info(f"TR4C3R CLI started with command: {args.command}")

    # Handle non-search commands first
    if args.command == "history":
        return await handle_history(args)
    elif args.command == "export":
        return await handle_export(args)
    elif args.command == "stats":
        return await handle_stats(args)
    elif args.command == "cache":
        return await handle_cache(args)
    elif args.command == "validate":
        return await handle_validate(args)

    # Search commands
    orchestrator = Orchestrator()
    results = []

    if args.command == "username":
        audit_logger.log_search(
            user_id="cli_user",
            search_type="username",
            identifier=args.username,
            purpose="CLI search",
        )
        results = await orchestrator.search_username(args.username, fuzzy=args.fuzzy)
        if args.dedupe:
            results = deduplicate_results(results)
        print(f"Username search results for {args.username}:")
        for result in results:
            print(result.to_dict())
        audit_logger.log_search(
            user_id="cli_user",
            search_type="username",
            identifier=args.username,
            results_count=len(results),
        )
    elif args.command == "email":
        audit_logger.log_search(
            user_id="cli_user",
            search_type="email",
            identifier=args.email,
            purpose="CLI search",
        )
        results = await orchestrator.search_email(args.email)
        if args.dedupe:
            results = deduplicate_results(results)
        print(f"Email search results for {args.email}:")
        for result in results:
            print(result.to_dict())
        audit_logger.log_search(
            user_id="cli_user",
            search_type="email",
            identifier=args.email,
            results_count=len(results),
        )
    elif args.command == "name":
        audit_logger.log_search(
            user_id="cli_user",
            search_type="name",
            identifier=args.name,
            purpose="CLI search",
        )
        results = await orchestrator.search_name(args.name)
        if args.dedupe:
            results = deduplicate_results(results)
        print(f"Name search results for {args.name}:")
        for result in results:
            print(result.to_dict())
        audit_logger.log_search(
            user_id="cli_user",
            search_type="name",
            identifier=args.name,
            results_count=len(results),
        )
    elif args.command == "phone":
        audit_logger.log_search(
            user_id="cli_user",
            search_type="phone",
            identifier=args.number,
            purpose="CLI search",
        )
        results = await orchestrator.search_phone(args.number)
        if args.dedupe:
            results = deduplicate_results(results)
        print(f"Phone search results for {args.number}:")
        for result in results:
            print(result.to_dict())
        audit_logger.log_search(
            user_id="cli_user",
            search_type="phone",
            identifier=args.number,
            results_count=len(results),
        )
    elif args.command == "all":
        audit_logger.log_search(
            user_id="cli_user",
            search_type="all",
            identifier=args.identifier,
            purpose="CLI search",
        )
        all_results = await orchestrator.search_all(args.identifier)
        print(f"All search results for {args.identifier}:")
        total_results = 0
        for module_name, module_results in all_results.items():
            if args.dedupe:
                module_results = deduplicate_results(module_results)
            print(f"\n=== {module_name.capitalize()} ===")
            for result in module_results:
                print(result.to_dict())
            total_results += len(module_results)
        audit_logger.log_search(
            user_id="cli_user",
            search_type="all",
            identifier=args.identifier,
            results_count=total_results,
        )

    logger.info(f"TR4C3R CLI completed command: {args.command}")
    return 0


async def handle_history(args: argparse.Namespace) -> int:
    """Handle the history command."""
    db = Database()

    if args.show:
        # Show detailed results for a specific search
        results = db.get_search_results(args.show)
        if not results:
            print(f"No results found for search ID {args.show}")
            return 1

        if args.json:
            output = [
                {
                    "source": r.source,
                    "identifier": r.identifier,
                    "url": r.url,
                    "confidence": r.confidence,
                    "timestamp": r.timestamp.isoformat(),
                    "metadata": r.metadata,
                }
                for r in results
            ]
            print(json.dumps(output, indent=2))
        else:
            print(f"Results for search ID {args.show}:")
            print("-" * 60)
            for r in results:
                print(f"  Source: {r.source}")
                print(f"  Identifier: {r.identifier}")
                print(f"  URL: {r.url}")
                print(f"  Confidence: {r.confidence:.2f}")
                print(f"  Timestamp: {r.timestamp}")
                if r.metadata:
                    print(f"  Metadata: {r.metadata}")
                print("-" * 60)
        return 0

    # List search history
    history = db.get_search_history(search_type=args.type, limit=args.limit)

    if args.json:
        print(json.dumps(history, indent=2, default=str))
    else:
        if not history:
            print("No search history found.")
            return 0

        print(f"{'ID':>5} | {'Type':<10} | {'Query':<25} | {'Results':>7} | {'Timestamp':<20}")
        print("-" * 80)
        for record in history:
            query = record.get("query", "")[:25]
            print(
                f"{record['id']:>5} | {record['search_type']:<10} | "
                f"{query:<25} | {record['result_count']:>7} | "
                f"{record['timestamp']:<20}"
            )
    return 0


async def handle_export(args: argparse.Namespace) -> int:
    """Handle the export command."""
    db = Database()

    try:
        exported = db.export_search(args.search_id, format=args.format)
    except Exception as e:
        print(f"Error exporting search {args.search_id}: {e}", file=sys.stderr)
        return 1

    if args.output:
        args.output.write_text(exported)
        print(f"Exported to {args.output}")
    else:
        print(exported)

    return 0


async def handle_stats(args: argparse.Namespace) -> int:
    """Handle the stats command."""
    db = Database()
    stats = db.get_statistics()

    if args.json:
        print(json.dumps(stats, indent=2))
    else:
        print("TR4C3R Database Statistics")
        print("=" * 40)
        print(f"Total searches:     {stats.get('total_searches', 0):,}")
        print(f"Total results:      {stats.get('total_results', 0):,}")
        print(f"Cache entries:      {stats.get('cache_entries', 0):,}")
        print(f"Cache hits:         {stats.get('cache_hits', 0):,}")
        print(f"Database size:      {stats.get('database_size_bytes', 0):,} bytes")
        print()
        print("Searches by type:")
        for stype, count in stats.get("searches_by_type", {}).items():
            print(f"  {stype:<15} {count:,}")

    return 0


async def handle_cache(args: argparse.Namespace) -> int:
    """Handle the cache command."""
    db = Database()

    if args.cache_action == "clear":
        cleared = db.cache_clear()
        print(f"Cleared {cleared} cache entries.")
    elif args.cache_action == "cleanup":
        cleaned = db.cleanup_expired_cache()
        print(f"Removed {cleaned} expired cache entries.")
    elif args.cache_action == "stats":
        stats = db.get_statistics()
        cache_stats = {
            "entries": stats.get("cache_entries", 0),
            "hits": stats.get("cache_hits", 0),
        }
        if hasattr(args, "json") and args.json:
            print(json.dumps(cache_stats, indent=2))
        else:
            print("Cache Statistics")
            print("=" * 30)
            print(f"Entries:  {cache_stats['entries']:,}")
            print(f"Hits:     {cache_stats['hits']:,}")

    return 0


async def handle_validate(args: argparse.Namespace) -> int:
    """Handle the validate command."""
    config = get_config()
    result = config.validate()

    print(result)

    if args.strict and not result.is_valid:
        return 1

    return 0


def main() -> None:
    args = parse_args(sys.argv[1:])
    try:
        exit_code = asyncio.run(main_async(args))
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\nAborted by user")
        sys.exit(130)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
