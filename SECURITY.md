# Security Policy

This project scans source code and may process proprietary service logic. Treat scan targets,
reports, SARIF output, database records, and LLM prompts as sensitive operational data.

## Reporting Security Issues

Do not report security issues through public GitHub issues. Use a private disclosure channel such
as a GitHub Security Advisory or email `security@[your-domain].com`.

Please include:

- Affected version or commit
- Reproduction steps
- Impact
- Suggested mitigation, if known

## Handling Secrets

- Do not commit `.env` files, API keys, database credentials, scan outputs, or SARIF files that may
  include source snippets.
- Prefer short-lived credentials for GitHub and LLM providers.
- Use a separate database for scanner history and restrict access to scan records.

## LLM Use

AI analysis can send code snippets to an external provider. Disable it with `--no-ai` for local,
CI, or regulated scans unless provider usage is explicitly approved.

## Dependency Hygiene

Run dependency and static checks before release:

```bash
bandit -r ai_security_scanner/
safety check
pre-commit run --all-files
```
