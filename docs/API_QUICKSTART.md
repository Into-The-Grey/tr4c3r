# TR4C3R API Quick Reference

## Start the API Server

```bash
# Development mode (auto-reload)
pipenv run uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000

# Production mode
pipenv run uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --workers 4
```

## Access Documentation

- Swagger UI: <http://localhost:8000/docs>
- ReDoc: <http://localhost:8000/redoc>

## Common API Calls

### Search

```bash
# Email search
curl -X POST http://localhost:8000/api/v1/search \
  -H "Authorization: Bearer demo_token" \
  -H "Content-Type: application/json" \
  -d '{"identifier": "user@example.com", "search_type": "email"}'

# Phone search
curl -X POST http://localhost:8000/api/v1/search \
  -H "Authorization: Bearer demo_token" \
  -H "Content-Type: application/json" \
  -d '{"identifier": "+1234567890", "search_type": "phone"}'

# Social media search
curl -X POST http://localhost:8000/api/v1/search \
  -H "Authorization: Bearer demo_token" \
  -H "Content-Type: application/json" \
  -d '{"identifier": "username123", "search_type": "social"}'
```

### List Searches

```bash
curl -X GET "http://localhost:8000/api/v1/searches?limit=10" \
  -H "Authorization: Bearer demo_token"
```

### Correlate

```bash
curl -X POST http://localhost:8000/api/v1/correlate \
  -H "Authorization: Bearer demo_token" \
  -H "Content-Type: application/json" \
  -d '{"search_ids": [1, 2, 3], "min_confidence": 0.5}'
```

### Export Graph

```bash
curl -X POST http://localhost:8000/api/v1/export/graph \
  -H "Authorization: Bearer demo_token" \
  -H "Content-Type: application/json" \
  -d '{"search_ids": [1, 2], "format": "gexf"}' \
  --output graph.gexf
```

## Test the API

```bash
# Run API tests only
pipenv run pytest tests/test_api.py -v

# Run all tests
pipenv run pytest -v
```

## Configuration

Edit `config/tr4c3r.yaml`:

```yaml
api:
  auth_token: "your_secure_token_here"
  
database:
  path: "./tr4c3r.db"
```

Or use environment variables:

```bash
export TR4C3R_API_AUTH_TOKEN="your_token"
export TR4C3R_DATABASE_PATH="./tr4c3r.db"
```
