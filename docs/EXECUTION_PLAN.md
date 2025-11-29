# TR4C3R Implementation: Step-by-Step Execution Plan

This document provides a detailed, actionable execution plan for building and testing TR4C3R through incremental phases.

## Status: Phase 1 Complete ✅

### Completed Work

#### Phase 1.1: Tooling & CI Infrastructure ✅

- **Pipenv setup** with Python 3.14, virtualenv in `.venv/`
- **Dependencies**: httpx, beautifulsoup4, rapidfuzz, phonenumbers, networkx, pyvis, python-dotenv
- **Dev tools**: pytest, pytest-asyncio, pytest-httpx, black, isort, flake8, mypy
- **Configuration files**:
  - `Pipfile` for dependency management
  - `pyproject.toml` for tool configs (pytest, black, isort, mypy)
  - `.flake8` for linting rules
  - `.gitignore` for Python artifacts
  - `.env.example` for configuration template
  - `Makefile` for common tasks
- **GitHub Actions CI** workflow for automated linting and testing

#### Phase 1.2: Core Username Search Implementation ✅

- **Fully functional `UsernameSearch` module** with:
  - Configurable site adapters (GitHub, Reddit, Keybase built-in)
  - Asynchronous concurrent HTTP requests with semaphore-controlled parallelism
  - Fuzzy variant search via `variant_generator.py` integration
  - Positive/negative marker detection for result filtering
  - Confidence scoring (1.0 for exact, 0.7 for variants)
  - Graceful error handling and retry logic
- **Variant generator** preserving original username and generating plausible alternatives
- **AsyncHTTPClient** with exponential backoff
- **Data models** using timezone-aware datetime
- **CLI integration** with `--fuzzy` flag support
- **Test suite** with 10 passing tests covering:
  - Data model validation
  - Username exact match
  - Fuzzy variant search
  - Negative marker filtering
  - Variant generation logic

#### Validation ✅

- All tests passing (`pytest -v`)
- Live smoke tests successful against GitHub and Reddit APIs
- CLI operational for both exact and fuzzy searches

---

## Next Steps: Phase 2 - Persistence & Configuration

### Phase 2.1: Database Layer (SQLite)

**Goal**: Persist search history and results for later correlation and dashboard display.

**Tasks**:

1. **Schema design** (`database/schema.sql`):

   ```sql
   CREATE TABLE search_requests (
       id INTEGER PRIMARY KEY AUTOINCREMENT,
       query TEXT NOT NULL,
       module TEXT NOT NULL,
       timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
       status TEXT NOT NULL,
       result_count INTEGER DEFAULT 0
   );

   CREATE TABLE results (
       id INTEGER PRIMARY KEY AUTOINCREMENT,
       request_id INTEGER NOT NULL,
       source TEXT NOT NULL,
       identifier TEXT NOT NULL,
       url TEXT,
       confidence REAL NOT NULL,
       timestamp DATETIME NOT NULL,
       metadata JSON,
       FOREIGN KEY (request_id) REFERENCES search_requests(id)
   );

   CREATE TABLE entities (
       id INTEGER PRIMARY KEY AUTOINCREMENT,
       entity_type TEXT NOT NULL,
       value TEXT NOT NULL UNIQUE,
       first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
       last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
   );

   CREATE TABLE relationships (
       id INTEGER PRIMARY KEY AUTOINCREMENT,
       entity_a_id INTEGER NOT NULL,
       entity_b_id INTEGER NOT NULL,
       relationship_type TEXT NOT NULL,
       confidence REAL NOT NULL,
       source TEXT NOT NULL,
       created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
       FOREIGN KEY (entity_a_id) REFERENCES entities(id),
       FOREIGN KEY (entity_b_id) REFERENCES entities(id)
   );
   ```

2. **Repository module** (`tr4c3r/utils/storage.py`):
   - Async-safe connection management (aiosqlite)
   - CRUD operations for search requests and results
   - Transaction support
   - Migration runner for versioned schema updates

3. **Testing**:
   - Unit tests with in-memory SQLite databases
   - Integration tests exercising full search-to-storage flow
   - Migration rollback tests

**Acceptance criteria**:

- CLI persists all searches automatically
- Queries retrievable by ID, module, or date range
- Test coverage ≥90% for storage module

### Phase 2.2: Configuration System

**Goal**: Externalize site configs, API keys, and feature flags.

**Tasks**:

1. **Config loader** (`tr4c3r/utils/config.py`):
   - Load from `.env` and optional YAML/TOML files
   - Override order: env vars > config file > defaults
   - Validate required fields at startup

2. **Site registry** (`tr4c3r/modules/sites/`):
   - Move site configs to `sites/username.yaml`
   - Allow user overrides in `~/.config/tr4c3r/sites/`
   - Hot-reload on file change (optional)

3. **Feature flags**:
   - `ENABLE_FUZZY_SEARCH`, `MAX_VARIANTS`, `HTTP_TIMEOUT`, `CONCURRENCY`
   - Respect per-module enable/disable flags

**Acceptance criteria**:

- CLI accepts `--config` flag to override default paths
- Site definitions externalized and user-editable
- All defaults documented in `.env.example`

---

## Phase 3: Email, Name, and Phone Modules

### Phase 3.1: Email Search

**Goal**: Query breach databases, search engines, and social platforms by email.

**Tasks**:

1. **Email validation** using `email-validator` library
2. **Adapters**:
   - HaveIBeenPwned API (metadata only)
   - Hunter.io free tier
   - Google/Bing dorking (e.g., `"email@example.com"`)
3. **Cross-linking**: Extract usernames/names from results, trigger sub-searches
4. **Tests**: Mock API responses, validate parsing

**Acceptance criteria**:

- CLI command: `tr4c3r email test@example.com`
- Breach metadata displayed (date, fields leaked)
- Cross-triggers username search if username found

### Phase 3.2: Name Search

**Goal**: Find public records, news, and social mentions by full name.

**Tasks**:

1. **NLP preprocessing**: Split name into components, handle international names
2. **Adapters**:
   - Google News search
   - LinkedIn public profiles (via search)
   - People-search sites (free tier)
3. **Disambiguation heuristics**: Co-occurring location/employer terms
4. **Tests**: Mock search results, validate ranking

**Acceptance criteria**:

- CLI command: `tr4c3r name "John Doe"`
- `--exact` flag for strict matching
- Results ranked by relevance

### Phase 3.3: Phone Search

**Goal**: Reverse-lookup phone numbers in public directories.

**Tasks**:

1. **Validation** with `phonenumbers` library (E.164 format)
2. **Adapters**:
   - UserSearch.ai free lookups
   - Carrier lookup APIs
   - Social media search by phone
3. **Cross-linking**: Trigger email/username searches on matches
4. **Tests**: Multi-region phone format tests

**Acceptance criteria**:

- CLI command: `tr4c3r phone +1234567890`
- Country code auto-detection
- Invalid number errors clear and actionable

---

## Phase 4: Social Media & NSFW Detection

### Phase 4.1: Social Media Search

**Goal**: Search Twitter/X, Instagram, LinkedIn, Mastodon, etc.

**Tasks**:

1. **Per-platform adapters** (`tr4c3r/modules/sites/social/`):
   - Twitter: Official API or scraping fallback
   - Reddit: Already implemented in username search
   - Instagram: Public profile checks
   - LinkedIn: Profile name extraction
   - Mastodon: Federated instance search
2. **Rate limiting**: Per-site token bucket or backoff
3. **User-agent rotation**: Randomize headers to avoid detection
4. **Tests**: Heavy mocking, contract tests per platform

**Acceptance criteria**:

- CLI flag: `tr4c3r username alice --social`
- Configurable platform enable/disable
- Respects robots.txt and ToS

### Phase 4.2: NSFW Detection

**Goal**: Flag adult content without storing images.

**Tasks**:

1. **Detector integration**: `nsfw-detector` or equivalent
2. **Opt-in config**: `ENABLE_NSFW_CHECK=true`
3. **Flagging**: Add `nsfw` boolean to result metadata
4. **CLI warning**: Require `--show-nsfw` to display flagged results

**Acceptance criteria**:

- NSFW results hidden by default
- Test images correctly classified (use public benchmark dataset)
- No explicit content logged or cached

---

## Phase 5: Dark Web Search

### Phase 5.1: Tor Integration

**Goal**: Query dark-web search engines for breach/leak metadata.

**Tasks**:

1. **Tor client**: Use `stem` or `torpy` library
2. **Proxy config**: `TOR_PROXY=socks5://127.0.0.1:9050` in `.env`
3. **Adapters**:
   - DarkSearch.io API
   - Onion service indexers (read-only)
4. **Security**: Sandboxed execution, no data download
5. **Legal disclaimer**: CLI warning on first dark-web search

**Acceptance criteria**:

- CLI command: `tr4c3r dark alice@example.com`
- Returns metadata only (source, date, leak type)
- Graceful fallback if Tor unavailable
- Tests use dummy onion addresses

---

## Phase 6: Correlation Engine & Visualization

### Phase 6.1: Correlation Logic

**Goal**: Link entities across searches to build knowledge graphs.

**Tasks**:

1. **Entity extraction**: Deduplicate usernames/emails/names across results
2. **Relationship inference**:
   - Same email → same user
   - Fuzzy name match → possible alias
   - Cross-platform username match → high confidence link
3. **Graph storage**: Store nodes/edges in SQLite `entities`/`relationships` tables
4. **Confidence scoring**: Weight edges by evidence strength

**Acceptance criteria**:

- Automated entity merging after each search
- CLI command: `tr4c3r correlate <query_id>`
- Graph queryable by entity ID

### Phase 6.2: Graph Visualization

**Goal**: Generate interactive HTML graphs with NetworkX + pyvis.

**Tasks**:

1. **NetworkX graph builder**: Load entities/relationships from DB
2. **pyvis renderer**: Export to standalone HTML
3. **Export formats**: GraphML, JSON for external tools (Gephi, Maltego)
4. **CLI integration**: `tr4c3r graph <query_id> --output graph.html`

**Acceptance criteria**:

- HTML file opens in browser with navigable graph
- Export formats validated with Gephi import
- Node tooltips show metadata

---

## Phase 7: Web Dashboard & API

### Phase 7.1: REST API

**Goal**: FastAPI service for programmatic access.

**Tasks**:

1. **Endpoints**:
   - `POST /search/username`, `/search/email`, etc.
   - `GET /history`, `/results/{id}`, `/graph/{id}`
2. **Authentication**: API key or OAuth
3. **Rate limiting**: Per-key quotas
4. **OpenAPI docs**: Auto-generated at `/docs`

**Acceptance criteria**:

- All CLI commands available via API
- Swagger UI accessible
- Tests with `httpx` client

### Phase 7.2: Web Dashboard

**Goal**: Browser-based UI for searches and history.

**Tasks**:

1. **Frontend**: FastAPI + Jinja2 templates or React SPA
2. **Features**:
   - Search forms for each module
   - History table with filtering
   - Embedded pyvis graphs
   - Export buttons (JSON/CSV)
3. **Authentication**: Login system with bcrypt
4. **Playwright tests**: Headless browser smoke tests

**Acceptance criteria**:

- Dashboard accessible at `http://localhost:8000`
- All CLI features replicated
- Mobile-responsive layout

---

## Phase 8: Packaging & Deployment

### Phase 8.1: Python Package

**Goal**: Distribute via PyPI or GitHub releases.

**Tasks**:

1. **setup.cfg** or **pyproject.toml** for package metadata
2. **Entry points**: `tr4c3r` command in PATH
3. **Versioning**: Semantic versioning with git tags
4. **Documentation**: Sphinx or MkDocs site

**Acceptance criteria**:

- `pip install tr4c3r` works
- Docs hosted on ReadTheDocs or GitHub Pages

### Phase 8.2: Docker Deployment

**Goal**: Containerize for easy deployment.

**Tasks**:

1. **Dockerfile**: Multi-stage build with pipenv
2. **docker-compose.yml**: Include Tor container if needed
3. **Volume mounts**: Persist `.env`, `logs/`, database
4. **Health checks**: API liveness probe

**Acceptance criteria**:

- `docker-compose up` starts full stack
- Container restarts preserve data
- Image published to Docker Hub or GHCR

---

## Testing Strategy

### Per-Phase Requirements

- **Unit tests**: ≥90% coverage for new modules
- **Integration tests**: End-to-end CLI/API workflows
- **Performance tests**: Concurrency limits, rate limiting
- **Security tests**: Input sanitization, SQL injection prevention

### Continuous Integration

- **GitHub Actions**: Run on every commit
- **Test matrix**: macOS + Linux, Python 3.11+
- **Linting**: black, isort, flake8, mypy all pass
- **Badges**: Coverage, build status in README

---

## Ethical & Legal Compliance

### Cross-Phase Guardrails

1. **Terms of Service**: Audit each data source, document restrictions
2. **Rate limiting**: Respect site limits, add backoff
3. **Robots.txt**: Check before scraping
4. **User consent**: CLI disclaimer on first run
5. **Data minimization**: Store only metadata, no sensitive payloads
6. **Audit logs**: Track all searches for accountability

### Documentation

- **Ethical use guide** in `ETHICS.md`
- **Legal disclaimers** in CLI help text
- **Contribution guidelines** enforce ToS compliance

---

## Success Metrics

### Phase 1 (Current) ✅

- [x] 10/10 tests passing
- [x] CLI functional for username search
- [x] Live API validation successful

### Phase 2 Goals

- [ ] Database schema finalized
- [ ] 100% of searches persisted
- [ ] Config externalized

### Phase 3-8 Goals

- [ ] All modules functional
- [ ] Dashboard deployed
- [ ] First external user onboarded

---

## Maintenance Plan

### Post-Launch

1. **Dependency updates**: Monthly Pipfile sync
2. **Site adapter maintenance**: Quarterly review of ToS changes
3. **Security patches**: Immediate response to CVEs
4. **Feature requests**: GitHub issues triage
5. **Performance monitoring**: Query latency < 10s p95

---

## Timeline Estimate

| Phase | Duration | Dependencies |
|-------|----------|--------------|
| Phase 1 | ✅ Complete | None |
| Phase 2 | 1-2 weeks | None |
| Phase 3 | 2-3 weeks | Phase 2 |
| Phase 4 | 2-3 weeks | Phase 3 |
| Phase 5 | 1-2 weeks | Phase 2 |
| Phase 6 | 2-3 weeks | Phases 2-5 |
| Phase 7 | 3-4 weeks | Phase 6 |
| Phase 8 | 1-2 weeks | Phase 7 |

**Total**: 12-19 weeks for full roadmap

---

## Contact & Contribution

- **Project Lead**: [Your Name]
- **Repository**: <https://github.com/yourusername/tr4c3r>
- **Issues**: Use GitHub issue tracker
- **Contributing**: See `CONTRIBUTING.md`

---

*Document version: 1.0*  
*Last updated: 2025-11-18*
