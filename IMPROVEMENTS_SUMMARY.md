# AI Reliability Scanner Conversion Summary

This repository was converted from a security-oriented SAST prototype into a reliability-oriented
production-readiness scanner.

## Current Focus

- Detect missing operational safeguards in generated services.
- Preserve the existing Click CLI, pattern registry, SARIF export, GitHub integration, and optional
  PostgreSQL persistence architecture.
- Report reliability findings for timeouts, retries, circuit breakers, database pooling, health
  checks, idempotency, queue backpressure, observability, graceful shutdown, and configuration
  safety.

## Compatibility Notes

- The package path remains `ai_security_scanner`.
- `ai-reliability-scanner` is the primary CLI command.
- `ai-security-scanner` remains as a legacy command alias.
- Some model and database names retain `vulnerability` for compatibility with the original API and
  migration history.

## Validation

The reliability conversion is covered by unit, functional, integration, and database tests. The
main regression suite is:

```bash
pytest tests -q
```
