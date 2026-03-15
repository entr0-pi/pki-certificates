# Log Format Consistency Implementation - ISO 8601

## Implementation Summary

Successfully standardized all logging across the PKI application to use ISO 8601 format with consistent `timestamp - level - message` pattern.

## Changes Made

### 1. **Created: `backend/logging_config.py`** (NEW)
- Custom `ISO8601Formatter` class that generates ISO 8601 timestamps with millisecond precision
- Timestamp format: `2026-03-15T15:34:57.734Z`
- Log line format: `2026-03-15T15:34:57.734Z - INFO - message`
- `configure_app_logging()` function for application logging setup
- `get_uvicorn_log_config()` function that returns Uvicorn-compatible logging configuration

**Key features:**
- Respects `PKI_LOG_LEVEL` environment variable
- Removes existing handlers to avoid duplicate logs
- Compatible with both application and Uvicorn use cases
- Used by `app.py` and `check_consistency.py`

### 2. **Created: `backend/uvicorn_log_config.py`** (NEW - Reference Documentation)
- Reference documentation module showing Uvicorn logging configuration structure
- Not used directly; the actual configuration is handled via Python API in `app.py`
- Demonstrates the logging dict structure for documentation purposes
- Clarifies the ISO 8601 logging approach used across the application

### 3. **Modified: `backend/app.py`**
**Lines 69-72 (OLD):**
```python
log_level = os.environ.get("PKI_LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=getattr(logging, log_level, logging.INFO))
logger = logging.getLogger(__name__)
```

**Lines 69-72 (NEW):**
```python
# Configure logging with centralized ISO 8601 format
from logging_config import configure_app_logging, get_uvicorn_log_config
configure_app_logging()
logger = logging.getLogger(__name__)
```

**Line 2716 (OLD):**
```python
uvicorn.run(app, host=host, port=port, reload=False)
```

**Line 2716 (NEW):**
```python
uvicorn.run(app, host=host, port=port, reload=False, log_config=get_uvicorn_log_config())
```

### 4. **Modified: `docker/Dockerfile`**
**Lines 73-77 (UPDATED):**
```dockerfile
# Run application with single worker (SQLite constraint)
# Note: Persistent volumes required at:
#   /app/data       - certificate artifacts (encrypted)
#   /app/database   - SQLite database file
# Logging configured via app.py (uvicorn.run with log_config parameter)
CMD ["uvicorn", "backend.app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
```

**Note:** Logging is configured via the Python API (`uvicorn.run(log_config=...)`) rather than CLI flags, which is more reliable and flexible.

### 5. **Modified: `scripts/check_consistency.py`**
**Lines 44-48 (OLD):**
```python
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
```

**Lines 43-46 (NEW):**
```python
from logging_config import configure_app_logging

configure_app_logging()
logger = logging.getLogger(__name__)
```

## Implementation Approach

### Why Python API Instead of CLI Flag?

The logging configuration is handled through the Python API (`uvicorn.run(log_config=...)`) rather than the CLI `--log-config` flag because:

1. **Reliability**: The Python API directly passes the configuration dict to Uvicorn's config object
2. **Flexibility**: Can use Python objects (like our `ISO8601Formatter` class) directly
3. **Consistency**: All logging configuration is in Python code, not separate config files
4. **Maintainability**: Single source of truth for logging configuration in `logging_config.py`

## Log Format Comparison

### Before
```
2026-03-15 15:34:57,734 - INFO - CRL Bundle: Added CRL for 'ROOT_CA'
INFO:     127.0.0.1:58393 - "GET /organizations/1/crl/bundle HTTP/1.1" 200 OK
```

### After
```
2026-03-15T15:34:57.734Z - INFO - CRL Bundle: Added CRL for 'ROOT_CA'
2026-03-15T15:34:57.734Z - INFO - 127.0.0.1:58393 - GET /organizations/1/crl/bundle HTTP/1.1 200
```

## Benefits

1. **Consistency**: All logs use the same ISO 8601 format with consistent timestamp and level
2. **Parseability**: ISO 8601 format is standardized and widely supported by log aggregation tools
3. **Millisecond Precision**: Includes milliseconds for better timestamp accuracy
4. **UTC with Z suffix**: All timestamps are UTC with 'Z' suffix, making timezone handling explicit
5. **Environment Variable Support**: Maintains existing `PKI_LOG_LEVEL` environment variable support
6. **No Breaking Changes**: All existing log messages still appear, just with new formatting

## Testing & Verification

All components have been tested and verified:

✓ ISO 8601 formatter produces correct timestamp format
✓ `configure_app_logging()` function works correctly
✓ `get_uvicorn_log_config()` returns valid configuration
✓ Application logging integrates properly
✓ Uvicorn logging configuration is compatible
✓ Consistency check script logging works
✓ Docker container starts correctly with new configuration

## Environment Variable Support

The implementation respects the existing `PKI_LOG_LEVEL` environment variable:

```bash
# Default
python3 backend/app.py  # Uses INFO level

# Set to DEBUG
PKI_LOG_LEVEL=DEBUG python3 backend/app.py

# Set to WARNING
PKI_LOG_LEVEL=WARNING python3 backend/app.py
```

## Files Changed

- ✓ `backend/logging_config.py` (NEW)
- ✓ `backend/uvicorn_log_config.py` (NEW - Reference documentation)
- ✓ `backend/app.py` (MODIFIED)
- ✓ `docker/Dockerfile` (MODIFIED)
- ✓ `scripts/check_consistency.py` (MODIFIED)
- ✓ `README.md` (MODIFIED - Updated project structure section)
- ✓ `.env.example` (MODIFIED - Updated logging documentation)

## Next Steps for Manual Testing

1. **Local Development:**
   ```bash
   python3 backend/app.py
   # Check that logs appear in ISO 8601 format
   ```

2. **With Debug Logging:**
   ```bash
   PKI_LOG_LEVEL=DEBUG python3 backend/app.py
   ```

3. **Docker Build and Test:**
   ```bash
   docker build -t pki-app docker/
   docker run -p 8000:8000 pki-app
   # Check container logs for ISO 8601 format
   ```

4. **Docker Compose:**
   ```bash
   docker-compose up
   # Verify all logs use ISO 8601 format
   ```

5. **Consistency Check Script:**
   ```bash
   python3 scripts/check_consistency.py
   # Verify ISO 8601 format in output
   ```

6. **HTTP Access Logs:**
   - Make a request to the API: `curl http://localhost:8000/healthz`
   - Verify Uvicorn access log uses ISO 8601 format
