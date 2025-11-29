"""Tests for the username search module."""

from __future__ import annotations

import httpx
import pytest

from src.search.username import SiteConfig, UsernameSearch


@pytest.mark.asyncio
async def test_username_search_exact_match(httpx_mock):
    site = SiteConfig(
        name="mocksite",
        url_template="https://mock.local/{username}",
        positive_markers=("found",),
    )
    httpx_mock.add_response(
        method="GET",
        url="https://mock.local/octocat",
        status_code=200,
        text="found octocat",
    )

    searcher = UsernameSearch(sites=[site], concurrency=1)
    results = await searcher.search("octocat")

    assert len(results) == 1
    result = results[0]
    assert result.source == "username:mocksite"
    assert result.url.endswith("/octocat")
    assert result.confidence == 1.0


@pytest.mark.asyncio
@pytest.mark.httpx_mock(can_send_already_matched_responses=True)
async def test_username_search_fuzzy_variant(httpx_mock):
    site = SiteConfig(
        name="variantsite",
        url_template="https://variant.local/{username}",
        positive_markers=("match",),
    )
    # Mock all possible requests to this domain
    import re

    httpx_mock.add_callback(
        lambda request: (
            httpx.Response(200, text="match")
            if re.match(r"https://variant\.local/", str(request.url))
            else None
        )
    )

    searcher = UsernameSearch(sites=[site], concurrency=1)
    results = await searcher.search("octocat", fuzzy=True, max_variants=5)

    # Verify we got results from fuzzy search
    assert len(results) >= 1
    assert all(result.source == "username:variantsite" for result in results)


@pytest.mark.asyncio
async def test_username_search_negative_marker(httpx_mock):
    site = SiteConfig(
        name="negsite",
        url_template="https://neg.local/{username}",
        positive_markers=("user",),
        negative_markers=("Not Found",),
    )
    httpx_mock.add_response(
        method="GET",
        url="https://neg.local/octocat",
        status_code=200,
        text="Not Found",
    )

    searcher = UsernameSearch(sites=[site], concurrency=1)
    results = await searcher.search("octocat")

    assert results == []
