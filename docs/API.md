# TR4C3R Web API

FastAPI-based REST API for the TR4C3R OSINT framework.

## Features

- **RESTful API** - Clean, well-documented endpoints
- **Authentication** - Bearer token authentication
- **Search Operations** - Email, phone, name, username, social media searches
- **Correlation Analysis** - Build relationship graphs, find connections
- **Export** - JSON, CSV, XML, GEXF, Pyvis, GraphML formats
- **WebSocket** - Real-time search updates
- **Documentation** - Auto-generated OpenAPI docs

## Quick Start

### Install Dependencies

```bash
pipenv install
```

### Configure

Set your API token in `config/tr4c3r.yaml`:

```yaml
api:
  auth_token: "your_secure_token_here"
```

Or use environment variable:

```bash
export TR4C3R_API_AUTH_TOKEN="your_secure_token_here"
```

### Run Server

```bash
# Development mode with auto-reload
pipenv run uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000

# Production mode
pipenv run uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --workers 4
```

Server will start on <http://localhost:8000>

## API Documentation

- **Swagger UI**: <http://localhost:8000/docs>
- **ReDoc**: <http://localhost:8000/redoc>

## API Endpoints

### Health Check

```bash
GET /health
```

### Search Operations

```bash
# Perform search
POST /api/v1/search
{
  "identifier": "user@example.com",
  "search_type": "email",
  "max_variants": 10
}

# Get search by ID
GET /api/v1/search/{search_id}

# List recent searches
GET /api/v1/searches?search_type=email&limit=50
```

### Correlation

```bash
# Correlate searches
POST /api/v1/correlate
{
  "search_ids": [1, 2, 3],
  "min_confidence": 0.5,
  "max_depth": 3
}

# Find connections
POST /api/v1/connections?identifier=user@example.com&max_depth=2
```

### Export

```bash
# Export search results
POST /api/v1/export/search
{
  "search_id": 1,
  "format": "json"
}

# Export correlation graph
POST /api/v1/export/graph
{
  "search_ids": [1, 2, 3],
  "format": "gexf",
  "output_filename": "graph.gexf"
}
```

### Statistics

```bash
GET /api/v1/stats
```

### WebSocket

```javascript
// Connect to WebSocket for real-time updates
const ws = new WebSocket('ws://localhost:8000/ws');

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Update:', data);
};

// Send heartbeat
ws.send('ping');
```

## Authentication

All API endpoints (except `/health` and `/ws`) require Bearer token authentication:

```bash
curl -H "Authorization: Bearer your_token_here" \
  http://localhost:8000/api/v1/searches
```

## Search Types

- `email` - Email address search
- `phone` - Phone number search
- `name` - Name search
- `username` - Username search
- `social` - Social media platform search

## Export Formats

### Search Results

- `json` - JSON format
- `csv` - CSV format
- `xml` - XML format

### Correlation Graphs

- `gexf` - Gephi format
- `pyvis` - Interactive HTML
- `graphml` - GraphML format
- `json` - JSON format

## Examples

### Python Client

```python
import httpx

BASE_URL = "http://localhost:8000"
TOKEN = "your_token_here"
headers = {"Authorization": f"Bearer {TOKEN}"}

# Perform email search
response = httpx.post(
    f"{BASE_URL}/api/v1/search",
    headers=headers,
    json={
        "identifier": "user@example.com",
        "search_type": "email"
    }
)
search = response.json()
print(f"Found {search['result_count']} results")

# Correlate multiple searches
response = httpx.post(
    f"{BASE_URL}/api/v1/correlate",
    headers=headers,
    json={
        "search_ids": [1, 2, 3],
        "min_confidence": 0.7
    }
)
correlation = response.json()
print(f"Found {correlation['statistics']['total_nodes']} nodes")
```

### cURL Examples

```bash
# Health check
curl http://localhost:8000/health

# Search
curl -X POST http://localhost:8000/api/v1/search \
  -H "Authorization: Bearer demo_token" \
  -H "Content-Type: application/json" \
  -d '{
    "identifier": "user@example.com",
    "search_type": "email"
  }'

# List searches
curl -X GET "http://localhost:8000/api/v1/searches?limit=10" \
  -H "Authorization: Bearer demo_token"

# Export graph
curl -X POST http://localhost:8000/api/v1/export/graph \
  -H "Authorization: Bearer demo_token" \
  -H "Content-Type: application/json" \
  -d '{
    "search_ids": [1, 2],
    "format": "gexf"
  }' \
  --output graph.gexf
```

## Testing

```bash
# Run API tests
pipenv run pytest tests/test_api.py -v

# Run all tests
pipenv run pytest -v
```

## Architecture

- **FastAPI** - Modern async web framework
- **Pydantic** - Data validation
- **WebSocket** - Real-time updates
- **CORS** - Cross-origin resource sharing
- **Bearer Auth** - Simple token authentication

## Error Handling

API returns standard HTTP status codes:

- `200` - Success
- `400` - Bad request (invalid parameters)
- `401` - Unauthorized (invalid token)
- `404` - Not found
- `500` - Internal server error

Error response format:

```json
{
  "detail": "Error message here"
}
```

## Performance

- Async operations for concurrent searches
- Database connection pooling
- Response streaming for large exports
- WebSocket for real-time updates

## Security

- Bearer token authentication
- CORS configuration
- Input validation with Pydantic
- SQL injection protection (parameterized queries)

## Deployment

### Docker

```dockerfile
FROM python:3.14-slim

WORKDIR /app
COPY . .

RUN pip install pipenv && pipenv install --system --deploy

CMD ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Systemd Service

```ini
[Unit]
Description=TR4C3R API
After=network.target

[Service]
Type=simple
User=tr4c3r
WorkingDirectory=/opt/tr4c3r
ExecStart=/usr/local/bin/pipenv run uvicorn src.api.main:app --host 0.0.0.0 --port 8000
Restart=always

[Install]
WantedBy=multi-user.target
```

## License

MIT License - See LICENSE file for details
