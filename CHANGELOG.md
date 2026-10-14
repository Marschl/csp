# Changelog

## 0.1.0

First version, extracted from a project-specific helper class.

- Profiles per host in `redaxo/data/addons/csp/profiles.yml` with the modes `off`, `report-only` and `enforce`
- Header builder with validation (no header injection, no fixed nonces, unknown directives rejected) and warnings
- Per-request nonce, correctly quoted
- `csp::addPolicy()` while the page renders
- Report endpoint `csp_report` (`report-uri` and `report-to`), aggregated storage without IP address and user agent
- Backend pages for profiles (with preview) and reports
