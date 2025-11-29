# Ethics System Enhancement - Safety Levels & Override Code

**Date**: 2025-11-23  
**Feature**: Enhanced ethics enforcement with 5 safety levels and emergency override

---

## New Safety Levels

The ethics enforcement system now supports 5 distinct safety levels:

### 1. NONE (`safety_level: "none"`)

**Use Case**: False positive scenarios, development, testing

**Behavior**:

- ✅ Bypasses ALL ethics checks
- ✅ No acknowledgment required
- ✅ All operations marked as compliant
- ⚠️ Use with caution - no ethical safeguards

**Example**:

```python
checker = EthicsChecker(config={"safety_level": "none"})
```

---

### 2. LOW (`safety_level: "low"`)

**Use Case**: Minimal checks for trusted environments

**Behavior**:

- ✅ Checks only for explicitly prohibited purposes (stalking, harassment, fraud, etc.)
- ✅ Allows unclear purposes
- ❌ No acknowledgment requirement
- ❌ No sensitive data warnings

**Example**:

```python
checker = EthicsChecker(config={"safety_level": "low"})
```

---

### 3. MEDIUM (`safety_level: "medium"`) - **DEFAULT**

**Use Case**: Standard operations, balanced approach

**Behavior**:

- ✅ Checks for prohibited purposes → **Issues**
- ⚠️ Flags unclear purposes → **Warnings**
- ⚠️ Warns on sensitive data collection
- ❌ No acknowledgment requirement
- ✅ Provides ethical recommendations

**Example**:

```python
checker = EthicsChecker(config={"safety_level": "medium"})  # Default
```

---

### 4. HIGH (`safety_level: "high"`)

**Use Case**: Strict ethical compliance, professional investigations

**Behavior**:

- ✅ Checks for prohibited purposes → **Issues**
- ✅ Requires clear legitimate purpose → **Issues if unclear**
- ⚠️ Warns on sensitive data with recommendations
- ⚠️ Warns on email/phone searches
- ✅ **Requires acknowledgment** → **Issue if not acknowledged**
- ✅ Extensive recommendations

**Example**:

```python
checker = EthicsChecker(config={"safety_level": "high"})
```

---

### 5. TOTAL (`safety_level: "total"`)

**Use Case**: Maximum enforcement, legal compliance, high-risk investigations

**Behavior**:

- ✅ All warnings become **Issues**
- ✅ Requires explicit legitimate purpose (20+ chars)
- ✅ Sensitive data → **Issue** (not just warning)
- ✅ Email searches → **Issue** (requires explicit consent)
- ✅ Phone searches → **Issue** (requires authorization)
- ✅ **Requires acknowledgment** → **Issue if not acknowledged**
- ✅ Additional compliance checks
- ✅ Maximum recommendations (including legal counsel, privacy impact assessment)

**Example**:

```python
checker = EthicsChecker(config={"safety_level": "total"})
```

---

## Emergency Override Code

### Purpose

Bypass ALL ethics checks during:

- Initial setup and configuration
- Development and testing
- False positive troubleshooting
- Emergency operations

### Override Code

**Code**: `3825`

⚠️ **WARNING**: This completely disables ethical safeguards. Use responsibly.

### Usage

```python
from src.enhancement.ethics import EthicsChecker

# Create checker with any safety level
checker = EthicsChecker(config={"safety_level": "total"})

# Activate override with code
success = checker.activate_override("3825")
if success:
    print("Ethics override active - all checks bypassed")

# Check if override is active
if checker.is_override_active():
    # Perform operations without ethics checks
    result = checker.check_compliance("personal", "user@example.com", "testing")
    # result["is_compliant"] will always be True

# Deactivate when done
checker.deactivate_override()
print("Ethics enforcement restored")
```

### Override Behavior

When active:

- ✅ `check_compliance()` always returns `is_compliant=True`
- ✅ `check_acknowledgment()` always returns `True`
- ✅ `validate_purpose()` bypasses all validation
- ⚠️ Warning added to results: "⚠️ Ethics override is active - checks bypassed"

### Security

- Invalid codes fail silently (logged as error)
- Override state is per-instance (not global)
- Can be deactivated at any time
- Override status can be checked with `is_override_active()`

---

## Configuration Examples

### YAML Configuration

```yaml
# config/tr4c3r.yaml

ethics:
  safety_level: medium  # none, low, medium, high, total
  require_acknowledgment: true
  consent_file: .tr4c3r_consent.json
```

### Python Configuration

```python
# Using safety_level (new)
config = {
    "safety_level": "high",
    "consent_file": ".tr4c3r_consent.json"
}
checker = EthicsChecker(config=config)

# Legacy strict_mode (maps to HIGH)
config = {
    "strict_mode": True  # Equivalent to safety_level="high"
}
checker = EthicsChecker(config=config)
```

---

## API Example

```python
from src.enhancement.ethics import EthicsChecker, SafetyLevel

# Example 1: NONE level for testing
checker = EthicsChecker({"safety_level": "none"})
result = checker.check_compliance("email", "test@example.com", "testing")
# Always compliant, no issues

# Example 2: MEDIUM level (default)
checker = EthicsChecker({"safety_level": "medium"})
result = checker.check_compliance("email", "test@example.com", "unclear purpose")
# Compliant but with warnings

# Example 3: TOTAL level for maximum compliance
checker = EthicsChecker({"safety_level": "total"})
checker.record_acknowledgment(user_id="analyst1", purpose="security research")
result = checker.check_compliance(
    "public",
    "username",
    "comprehensive security research and threat intelligence investigation"
)
# Strict checks, detailed recommendations

# Example 4: Override code for emergencies
checker = EthicsChecker({"safety_level": "total"})
checker.activate_override("3825")
# All checks bypassed
result = checker.check_compliance("any", "any", "any")
# Always compliant
checker.deactivate_override()
# Checks resume
```

---

## Testing

Added 9 comprehensive tests:

1. ✅ `test_safety_level_none` - Verifies NONE bypasses all checks
2. ✅ `test_safety_level_low` - Verifies LOW only checks prohibited purposes
3. ✅ `test_safety_level_medium` - Verifies MEDIUM warnings
4. ✅ `test_safety_level_high` - Verifies HIGH strict checks
5. ✅ `test_safety_level_total` - Verifies TOTAL maximum enforcement
6. ✅ `test_override_code_activation` - Tests correct/incorrect codes
7. ✅ `test_override_code_bypasses_checks` - Verifies override functionality
8. ✅ `test_override_code_deactivation` - Tests deactivation
9. ✅ `test_legacy_strict_mode_maps_to_high` - Backward compatibility

**Total Tests**: 373 (up from 364)
**Test Status**: ✅ All passing

---

## Backward Compatibility

The system maintains full backward compatibility:

- `strict_mode: True` → Maps to `safety_level: "high"`
- `strict_mode: False` → Maps to `safety_level: "medium"`
- Legacy code continues to work unchanged
- `self.strict_mode` property maintained (True for HIGH/TOTAL)

---

## Use Case Matrix

| Scenario | Recommended Level | Override? |
|----------|-------------------|-----------|
| Development/Testing | NONE or LOW | Optional |
| Production (Low Risk) | MEDIUM | No |
| Professional Investigations | HIGH | No |
| Legal/Compliance Critical | TOTAL | No |
| False Positive Issues | NONE | Yes (if needed) |
| Initial Setup | Any | Yes (with code) |
| Emergency Operations | Any | Yes (with code) |

---

## Code Locations

- **Implementation**: `src/enhancement/ethics.py`
- **Tests**: `tests/test_enhancements.py`
- **Enum**: `SafetyLevel` (NONE, LOW, MEDIUM, HIGH, TOTAL)
- **Override Code**: `OVERRIDE_CODE = "3825"`

---

## Logging

All operations are logged:

- `INFO`: Safety level initialization, override activation/deactivation
- `WARNING`: Override active, no acknowledgment found
- `ERROR`: Invalid override code

---

## Summary

✅ **5 Safety Levels**: none → low → medium → high → total  
✅ **Emergency Override**: Code 3825  
✅ **Backward Compatible**: Legacy strict_mode supported  
✅ **Comprehensive Testing**: 9 new tests, all passing  
✅ **Production Ready**: 373/373 tests passing  

**Use responsibly and in compliance with all applicable laws.**
