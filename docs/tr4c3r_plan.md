# TR4C3R Development Plan

This document outlines a phased roadmap to build TR4C3R, a free, open‑source OSINT suite written primarily in Python.  The goal is to deliver a robust toolset that can search usernames, emails, names and phone numbers across the public web, social media and the dark web, correlate the results, and display them through a dashboard with log/history tracking.  Each phase is self‑contained—no phase should be started until the previous one is fully tested, raises no unhandled exceptions and has graceful failure paths.

Ethical note: OSINT is a powerful technique for mapping online footprints, but it must be used legally and responsibly.  Reputable sources emphasise that OSINT draws on data from public websites, social media, public records, domain registries and even the dark web ; it is about linking publicly available data to derive intelligence .  All modules should enforce respect for privacy and follow local laws.

Phase 1 – Project foundations and environment

 1. Define requirements and scope
 • Document each feature in detail.  Clarify which OSINT sources to query (e.g., search engines, social networks, data‑breach dumps) and ensure they are free.  Recognise that OSINT tools gather data from websites, social media and public databases .
 • Identify legal restrictions and ethical guidelines; ensure the tool does not encourage harassment or privacy invasion.
 • Decide whether the tool will run on the command line, a GUI or both.  The final web dashboard will be built later.
 2. Architecture design
 • Choose a modular architecture: each search type (username, email, etc.) becomes its own module with a standard interface (e.g., search(term) -> results).  Use asynchronous programming (e.g., asyncio, httpx) to handle multiple web requests concurrently.
 • Define a common data model for results (e.g., Result objects with source, type, confidence, timestamp).  This ensures later correlation and graphing is consistent.
 • Plan a central orchestrator that calls each module, merges results and writes logs.
 • Consider using SQLite for local storage of query history and results; it’s lightweight, requires no external server and fits the “function over fortune” philosophy.
 3. Environment and tooling
 • Set up a Python ≥3.9 environment.  Use pipenv or poetry for dependency management and to ensure reproducible builds.
 • Implement a robust logging framework using logging with rotating file handlers to capture info/debug/error levels.  Logging is essential for OSINT operations and later dashboards.
 • Establish coding conventions (PEP 8), commit hooks and continuous integration (e.g., GitHub Actions) to run linting (flake8, black) and unit tests (pytest) on every commit.
 • Create a directory structure:
 • tr4c3r/ – core package
 • tr4c3r/modules/ – individual OSINT modules
 • tr4c3r/utils/ – helpers (HTTP client, parsing, fuzzy matching, logging)
 • tests/ – unit tests
 • scripts/ – CLI entrypoints
 • dashboard/ – later web UI

Phase 2 – Core username search module

 1. Design the module interface
 • Define a UsernameSearch class with a search(username: str) -> List[Result] method.  Accept a username string and return a list of results with metadata (platform name, URL, confidence).
 • Include optional parameters (e.g., exact=True, timeout, max_sites).
 2. Source selection
 • Research free, publicly accessible sites and APIs that allow searching by username.  Examples include general search engines (Google/Bing with query operators), community forums, code repositories (GitHub, GitLab), social media (Twitter, Reddit, Instagram via scraping if allowed) and niche platforms like dating sites or crypto forums .
 • Where scraping is involved, respect robots.txt and terms of service.  Many sites block automated scraping; prefer APIs or search queries when possible.
 3. HTTP client & concurrency
 • Implement a reusable HTTP client using httpx with asynchronous calls and connection pooling.  Handle timeouts, retries (exponential backoff) and randomised user‑agent headers to avoid being flagged as a bot.
 • Use asyncio.gather() to fire requests concurrently to multiple sites.  Provide graceful fallbacks for network failures and rate limits.
 4. HTML parsing and result extraction
 • Use beautifulsoup4 or lxml to parse returned HTML pages.  Extract presence of the username by checking for markers (e.g., profile exists, “user not found”).
 • For sites with JSON responses, decode directly and map fields to the result model.
 • Store additional attributes such as profile name, join date, followers and any hints about the user’s other accounts.
 5. Error handling and resilience
 • Catch and log all exceptions.  Unhandled exceptions should never propagate.
 • Implement per-site timeouts and fallback logic (e.g., if Google search fails, skip gracefully).
 • Include unit tests covering typical and edge cases (username exists, does not exist, network failure).  Use mocking to avoid hitting real websites in tests.
 6. Result storage and history
 • Save search requests and results into SQLite with fields: query, module, timestamp, status, result_count.  Persist detailed results in a separate table or JSON column.
 • Implement functions for retrieving past searches for the dashboard.
 7. CLI for username search
 • Provide a command‑line tool, e.g., `python -m tr4c3r username <username>` that prints results in a readable table and writes to the log/history.  Offer export to JSON/CSV for later correlation.

Phase 3 – Fuzzy and variant username search

 1. Variant generation
 • Many users vary their handles across sites by altering spelling or adding prefixes/suffixes (e.g., john_doe, joan.doe, johnnydoe1).  Implement a generator that produces plausible variants.
 • Use heuristics:
 • Insert/replace common separators (_, ., -).
 • Add numbers or years (birth year, two‑digit variations).
 • Replace similar‑looking characters (e.g., 0 ↔ o, 1 ↔ l).
 • Use fuzzywuzzy/rapidfuzz for Levenshtein distance to find near‑matches on sites that provide search suggestions.
 • Provide a configuration file to enable/disable certain variant types to avoid generating thousands of useless permutations.
 2. Enhanced search logic
 • Adapt the UsernameSearch module to accept a list of candidate usernames.  For each variant, search concurrently but track which result came from which variant.
 • Provide ranking or scoring.  For example, exact matches get higher confidence than fuzzy matches.  If multiple variants resolve to the same user on a platform, merge them.
 3. Similarity filtering
 • After retrieving results, cluster them by similarity.  Use Jaro‑Winkler or Levenshtein distance on profile names to group identical individuals.
 • Remove duplicates and produce a cleaned result list for correlation.
 4. User interface and options
 • Update the CLI: allow --fuzzy flag to enable variant search.  Provide --max-variants to limit permutations.
 • Log variant generation details for transparency.
 5. Testing and validation
 • Write unit tests for variant generation to ensure expected permutations.
 • Run integration tests that query a mock server or sanitized test websites.
 • Confirm that the system gracefully handles large variant lists without exhausting resources.

Phase 4 – Email and full‑name search modules

 1. Email search module
 • Create EmailSearch class following the same interface as UsernameSearch.  Accept an email address; return results with metadata.
 • Use OSINT tools that search emails across websites, forums, breaches and social networks.  Many OSINT platforms (e.g., Intelligence X, Hunter.io, HaveIBeenPwned) provide APIs; prefer free tiers.
 • For each source:
 • Build an asynchronous request to the API or search endpoint.
 • Parse results: associated domains, social media accounts, data‑breach records.
 • Map the data to the result model (include breach date, leaked fields).
 • Follow legal guidelines: avoid downloading actual breach contents.  Provide metadata only.
 2. Full‑name search module
 • Create NameSearch class that accepts a full name and optional location filters.
 • Use search engines and people‑search websites to find references (news articles, public records, directories).  OSINT sources emphasise that relevant information may include public‑facing assets, addresses and connections .
 • Implement simple natural‑language processing to detect context (distinguish between different individuals with the same name).  Use heuristics like co‑occurring terms (e.g., location, employer) to rank results.
 • Provide a --exact option to restrict to exact matches.
 3. Integrating email and name searches
 • Allow cross‑module correlation: if an email result returns a full name, push it into the name search module automatically.
 • Save results and history to the central database for later graphing.
 4. Testing
 • Write tests that feed known sample emails/names and confirm that the parsing code handles typical outputs and error cases.
 • Mock external APIs to avoid rate limits during testing.

Phase 5 – Phone number search module

 1. Module design
 • Create PhoneSearch class with search(number: str) -> List[Result].  Accept phone number strings with optional country codes.
 • Recognise that OSINT techniques can search phone numbers in social media, public records and directories .  Tools like UserSearch can find social profiles and email addresses linked to a phone number .  Use such free resources where terms allow.
 2. Normalization and validation
 • Validate phone numbers (E.164 format).  Use phonenumbers library to parse and identify country codes.
 • Provide helpful error messages when numbers are invalid or unsupported.
 3. Source integration
 • Query public directories, social media search endpoints and search engines with the number.
 • Use OSINT sites like usersearch.ai for phone numbers (free limited lookups).  When scraping, follow terms of service.
 • If available, query regulatory registries (e.g., FCC’s reverse lookup) and dark‑web leak indices for the number.
 • Parse results for associated names, addresses and accounts.
 4. Enrich and cross‑link
 • When a phone search returns an email or username, automatically invoke the relevant modules to enrich the profile.
 • Save cross‑links to the database for correlation.
 5. Testing & error handling
 • Handle absent results gracefully by returning an empty list.
 • Write tests that verify phone number parsing and search behaviour with various country formats.

Phase 6 – Social media search (with NSFW detection)

 1. Platform selection and compliance
 • Identify which social networks to support: Twitter (X), Reddit, LinkedIn, Instagram, Mastodon, plus adult‑focused communities for NSFW detection.
 • Check each platform’s terms of service for scraping.  Many forbid automated scraping; if scraping is disallowed, rely on official APIs, search engine queries or public RSS feeds.
 • Provide configuration to enable/disable specific platforms to respect legal constraints.
 2. Search implementation
 • For each platform, implement a separate SocialMediaSite class with methods like search_username(), search_email(), etc.  Use asynchronous HTTP calls and parse JSON or HTML responses.
 • For NSFW content detection, incorporate open‑source machine‑learning libraries (e.g., nsfw_detector) or call a moderation API on retrieved images.  This helps flag adult content while complying with host policies.
 • Gather metadata: user bio, follower counts, latest posts, and cross‑platform links.
 3. Integration
 • Extend UsernameSearch to include social media modules when the user enables social search.
 • Provide rate limiting and user‑agent rotation to avoid detection.
 • Respect privacy: do not store or display explicit content; instead, record that NSFW material is present and provide a flagged indicator.
 4. Testing
 • Mock social media endpoints for tests to avoid hitting live APIs.
 • Validate NSFW detection by feeding test images and verifying flagging behaviour.
 • Ensure the module returns consistent results across multiple runs.

Phase 7 – Dark web media‑leak search

 1. Understand dark‑web sources
 • Dark web search engines like DarkSearch.io crawl Tor hidden services for data dumps and leaked documents .  The OSINT community acknowledges that threat intelligence can involve dark‑web forums and data dumps .
 • Accessing these resources requires Tor; implement all Tor connections via stem or torpy library to route requests securely.  Never expose the user’s real IP.
 2. Module design
 • Create DarkWebSearch class with methods to query specific dark‑web search APIs (e.g., DarkSearch.io).  Accept search terms (username, email, phone number) and return metadata about leaks (source, date, type of data, link).
 • Avoid downloading or exposing sensitive content.  Provide only meta‑information (e.g., “email found in data breach from 2023”).
 • Allow the user to configure Tor proxies and onion service addresses via settings.
 3. Security and ethics
 • Use a sandbox environment for Tor connections to isolate them from the host OS.
 • Warn users about legal and ethical considerations of accessing dark‑web content.  Provide a disclaimer that the tool only lists presence in leaks and does not fetch the leaked data.
 4. Testing
 • Use dummy onion addresses in tests and mock responses.
 • Ensure the module handles unreachable nodes and connection timeouts gracefully.

Phase 8 – Correlation engine, graph visualisation and web dashboard

 1. Correlation engine
 • Build a central correlation module that takes results from different searches and identifies relationships (e.g., email <→ username <→ social profile).
 • Use matching on unique identifiers (e.g., same email in multiple results) and fuzzy matching on names.  The aim is to “make sense of the chaos” and link data points .
 • Store relations as a graph data structure with nodes (entities) and edges (relationships).  Each edge can carry a weight representing confidence.
 2. Graph generation
 • Use networkx to build the graph in Python.  Visualising relationships helps reveal insights that raw data cannot .
 • For interactive visualization, integrate pyvis to render the graph as an HTML file that can be embedded in the dashboard.  Pyvis accepts a networkx graph and produces a navigable, filterable display .
 • Provide options to export graphs to GraphML or JSON so other tools (e.g., Gephi or Maltego) can ingest them.
 3. Web dashboard and API
 • Build a REST API using Flask or FastAPI to expose endpoints for starting searches, retrieving history and fetching graph data.  Include authentication (e.g., API key or OAuth) if the tool will be hosted publicly.
 • Develop a web front‑end (React, Vue or simple server‑rendered templates) that displays:
 • A dashboard with search forms for each module.
 • A log/history table showing past queries, timestamps, and statuses.
 • Result lists with ability to click through to details.
 • Embedded network graphs using the pyvis HTML output.
 • Ensure the UI clearly marks NSFW or dark‑web results and requires additional user confirmation to view them.
 4. Authentication and user management
 • Implement basic user management if needed (login, session tokens).  Use secure password hashing (bcrypt).
 • Provide role‑based permissions (e.g., view only vs. search and manage).  Store user preferences (e.g., which modules are enabled) in the database.
 5. Testing and quality assurance
 • Write end‑to‑end tests that spin up the API and ensure it handles typical user flows.  Use pytest with httpx or requests to simulate clients.
 • Test the dashboard using a headless browser (e.g., playwright) to ensure graphs render and user interactions work.
 • Perform load testing on the API to ensure concurrency doesn’t break the system.
 6. Documentation and packaging
 • Provide comprehensive documentation: installation instructions, module usage, API reference, examples and legal/ethical guidance.
 • Package the project as a Python package (setup.cfg/pyproject.toml) and optionally provide Docker images for easy deployment.
 • Include sample configuration files demonstrating how to enable/disable modules, set timeouts and choose OSINT sources.

Cross‑phase considerations
 • Ethics & compliance – Each module should comply with the terms of the sources it queries.  OSINT experts note that ethical OSINT respects boundaries and doesn’t download sensitive data .  Incorporate usage warnings into the CLI and dashboard.
 • Internationalisation – Because OSINT may involve data from different countries, design modules to handle international characters and varying data formats.  Use chardet to detect encoding and unidecode to normalise strings.
 • Security – Sanitize all user input before using it in queries.  Avoid command injection when interfacing with third‑party tools.  Use TLS for all external requests.  For dark‑web interactions, isolate Tor connections.
 • Performance – Provide caching for frequent queries to avoid hitting external sites repeatedly.  Consider storing results in a local cache with expiry times.
 • Community contributions – As an open‑source project, maintain clear contribution guidelines.  Use a MIT or GPL license depending on the desired level of freedom.
 • Future enhancements – Consider adding modules for IP address/domain lookup, image reverse search, metadata extraction (exif), and integration with threat intelligence feeds once core functionality is complete.

Conclusion

TR4C3R is ambitious but achievable.  By following a phased approach, you can build a modular, free OSINT platform that searches usernames, emails, names and phone numbers, correlates results, visualises connections and presents them in a web dashboard.  The plan emphasises building each module to a high standard—robust error handling, unit tests and respect for legal boundaries—before moving on to the next phase.  Using Python’s rich ecosystem (asyncio, httpx, BeautifulSoup, NetworkX, Pyvis) and the wealth of publicly available OSINT sources  , TR4C3R can become a powerful tool in the hands of security researchers and investigators.
