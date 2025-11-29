# Comprehensive Logging Infrastructure

## Overview

TR4C3R now includes a comprehensive logging infrastructure that provides structured logging, audit trails, and performance monitoring across all components.

## Features

### 1. Structured JSON Logging

All log entries can be output in JSON format for easy parsing by log aggregation systems:

```python
from src.core.logging_setup import configure_logging

# Enable JSON logging
configure_logging(
    log_file=Path("logs/tr4c3r.log"),
    use_json=True
)
```

JSON log entry example:

```json
{
  "timestamp": "2025-11-24T01:30:00.123456Z",
  "level": "INFO",
  "logger": "src.api.main",
  "message": "Search request: email for 'test@example.com'",
  "module": "main",
  "function": "search",
  "line": 215
}
```

### 2. Audit Logging

Dedicated audit logging for compliance and security monitoring:

```python
from src.core.logging_setup import setup_audit_logging

# Initialize audit logger
audit_logger = setup_audit_logging(log_dir=Path("logs"))

# Log search operations
audit_logger.log_search(
    user_id="user123",
    search_type="email",
    identifier="target@example.com",
    purpose="Investigation",
    results_count=5
)

# Log data exports
audit_logger.log_export(
    user_id="user123",
    export_format="JSON",
    data_types=["email", "phone"],
    record_count=10
)

# Log API key usage
audit_logger.log_api_key_usage(
    user_id="user123",
    api_name="haveibeenpwned",
    operation="check_email",
    success=True
)
```

Audit logs are stored in `logs/audit.log` with JSON formatting for easy compliance reporting.

### 3. Performance Logging

Track operation performance with dedicated performance logging:

```python
from src.core.logging_setup import setup_performance_logging, log_performance

# Initialize performance logger
perf_logger = setup_performance_logging(log_dir=Path("logs"))

# Log individual operations
perf_logger.log_operation(
    operation="database_query",
    duration_ms=125.5,
    success=True,
    metadata={"query_type": "search", "rows": 100}
)

# Use context manager for automatic timing
with log_performance("database_query"):
    # perform operation
    results = db.query()
```

### 4. Performance Decorators

Automatically time function execution:

```python
from src.core.logging_setup import timing_decorator

@timing_decorator
def expensive_operation():
    # function code
    return result
```

The decorator logs execution time at DEBUG level.

## Configuration

### CLI Configuration

The CLI supports comprehensive logging options:

```bash
# Basic usage with default logging
python -m src.cli username johndoe

# Enable DEBUG level logging
python -m src.cli --log-level DEBUG username johndoe

# Use JSON structured logging
python -m src.cli --json-logs username johndoe

# Custom log directory
python -m src.cli --log-dir /var/log/tr4c3r username johndoe
```

### API Configuration

The API initializes logging on startup using configuration from `tr4c3r.yaml`:

```yaml
logging:
  directory: logs
  level: INFO
  json_format: false
```

### Comprehensive Setup

For applications that need all logging subsystems:

```python
from src.core.logging_setup import configure_comprehensive_logging
from pathlib import Path

# Configure all logging subsystems at once
audit_logger, performance_logger = configure_comprehensive_logging(
    log_dir=Path("logs"),
    level=logging.INFO,
    use_json=True,
    console_output=True
)
```

This sets up:

- Main application logging → `logs/tr4c3r.log`
- Audit logging → `logs/audit.log`
- Performance logging → `logs/performance.log`

## Log Files

### Default Log Locations

- **Main Application Log**: `logs/tr4c3r.log`
  - Standard application logs (INFO, DEBUG, WARNING, ERROR)
  - Rotating files: 5MB max, 3 backups
  - Format: Text or JSON

- **Audit Log**: `logs/audit.log`
  - Security and compliance events
  - Rotating files: 10MB max, 10 backups
  - Format: JSON only

- **Performance Log**: `logs/performance.log`
  - Operation timing and performance metrics
  - Rotating files: 10MB max, 5 backups
  - Format: JSON only

### Log Rotation

All logs use rotating file handlers to prevent disk space issues:

- Main logs rotate at 5MB
- Audit logs rotate at 10MB (long retention)
- Performance logs rotate at 10MB

## Integration Examples

### CLI Integration

The CLI automatically sets up comprehensive logging:

```python
# CLI logs all searches to audit log
python -m src.cli email test@example.com

# Check logs/audit.log for:
{
  "timestamp": "2025-11-24T01:30:00Z",
  "level": "INFO",
  "logger": "tr4c3r.audit",
  "message": "Search performed",
  "event_type": "search",
  "user_id": "cli_user",
  "search_type": "email",
  "identifier": "test@example.com",
  "purpose": "CLI search",
  "results_count": 3
}
```

### API Integration

The API logs all operations automatically:

```python
# Search endpoint logs:
# 1. Audit: Search initiated
# 2. Performance: Search execution time
# 3. Audit: Results count
# 4. Main: Status messages

POST /api/v1/search
{
  "identifier": "test@example.com",
  "search_type": "email"
}
```

### Custom Integration

For custom scripts or modules:

```python
import logging
from pathlib import Path
from src.core.logging_setup import (
    configure_comprehensive_logging,
    log_performance
)

# Setup logging
audit_logger, perf_logger = configure_comprehensive_logging(
    log_dir=Path("logs"),
    level=logging.INFO
)

# Use in your code
logger = logging.getLogger(__name__)
logger.info("Starting custom operation")

with log_performance("custom_operation"):
    # Your code here
    pass

audit_logger.log_search(
    user_id="script",
    search_type="custom",
    identifier="target",
    results_count=10
)
```

## Log Analysis

### Query Audit Logs

Since audit logs are in JSON format, they're easy to query:

```bash
# Find all searches by a user
cat logs/audit.log | jq 'select(.user_id == "user123")'

# Find all exports
cat logs/audit.log | jq 'select(.event_type == "export")'

# Find failed API calls
cat logs/audit.log | jq 'select(.event_type == "api_usage" and .success == false)'
```

### Query Performance Logs

Analyze performance patterns:

```bash
# Find slow operations (>1000ms)
cat logs/performance.log | jq 'select(.duration_ms > 1000)'

# Average duration per operation
cat logs/performance.log | jq -s 'group_by(.operation) | map({operation: .[0].operation, avg_ms: (map(.duration_ms) | add / length)})'

# Count failures
cat logs/performance.log | jq -s 'map(select(.success == false)) | length'
```

### Integration with Log Aggregation

The JSON format works seamlessly with popular log aggregation tools:

- **Elasticsearch/Logstash/Kibana (ELK)**: Direct JSON ingestion
- **Splunk**: JSON source type
- **Datadog**: JSON log format
- **CloudWatch Logs**: JSON parsing
- **Grafana Loki**: JSON labels

## Testing

Comprehensive test coverage (25 tests) in `tests/test_logging.py`:

```bash
# Run logging tests
pytest tests/test_logging.py -v

# Run all tests (398 total)
pytest
```

Test coverage includes:

- JSON formatter with extra fields and exceptions
- Audit logging (search, export, API usage)
- Performance logging and timing
- Decorators and context managers
- Configuration functions
- Integration scenarios

## Best Practices

### 1. Use Appropriate Log Levels

```python
logger.debug("Detailed debug information")
logger.info("General informational messages")
logger.warning("Warning messages")
logger.error("Error messages", exc_info=True)
logger.critical("Critical errors")
```

### 2. Include Context

```python
logger.info(f"Processing {count} items for user {user_id}")
```

### 3. Use Audit Logging for Compliance

Always log:

- User searches (who, what, when, why)
- Data exports (what data, in what format)
- API key usage (which APIs, for what purpose)

### 4. Use Performance Logging for Monitoring

Track:

- Database query times
- API call durations
- Processing times
- Resource usage

### 5. Enable JSON Logging in Production

JSON logs are easier to parse and analyze:

```python
configure_comprehensive_logging(
    log_dir=Path("logs"),
    level=logging.INFO,
    use_json=True  # Enable for production
)
```

## Troubleshooting

### Issue: Duplicate Log Entries

**Solution**: The `configure_logging()` function prevents duplicates automatically. If you see duplicates, ensure you're not calling it multiple times or configuring root logger elsewhere.

### Issue: Logs Not Written

**Solution**: Check:

1. Log directory exists and is writable
2. Disk space is available
3. File permissions are correct

### Issue: Missing Audit Logs

**Solution**: Ensure audit logger is initialized:

```python
# Check if audit_logger is set up
if audit_logger is None:
    audit_logger = setup_audit_logging()
```

### Issue: Performance Overhead

**Solution**: 

1. Use appropriate log levels (DEBUG only when needed)
2. Disable console output in production if not needed
3. Use async logging if high volume

## Future Enhancements

Planned improvements:

- [ ] Async logging for high-volume scenarios
- [ ] Log streaming to external services
- [ ] Real-time log monitoring dashboard
- [ ] Automated log analysis and alerting
- [ ] Log retention policies
- [ ] Compressed log archives

## Summary

The comprehensive logging infrastructure provides:

✅ **Structured JSON logging** for easy parsing  
✅ **Audit logging** for compliance and security  
✅ **Performance logging** for monitoring  
✅ **Automatic log rotation** to prevent disk issues  
✅ **CLI and API integration** out of the box  
✅ **25 comprehensive tests** (398 total tests passing)  
✅ **Production-ready** with best practices

All logs are automatically configured in CLI and API - just start using TR4C3R and your operations are logged!
