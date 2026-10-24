# Changelog

## 0.2.0

- Fix: the right `csp[]` is registered, so it appears in the role form (with a label) and editors with that role can open the pages
- Tests for the profiles file: host patterns (case, port, wildcards), validation of every field, the seeded default profile (71 → 109 checks)
- Release files: `SECURITY.md`, issue templates, `README.txt`; `supportpage` points to GitHub
- Requires REDAXO 5.21.4 (the version it was tested with), older versions are not tested
- Live mode (`live_mode: true`): the profiles page is read-only (preview and warnings stay), a POST is ignored on the server
- README: what a fresh install sends, the Git exception for `profiles.yml`, class names
- Checked in a real REDAXO 5.21.4: install, reinstall (keeps `profiles.yml`), uninstall (drops the table), header for report-only/enforce/nonce, report endpoint with both formats, profile and report pages as admin and as editor, broken profiles file

## 0.1.0

First version, extracted from a project-specific helper class.

- Profiles per host in `redaxo/data/addons/csp/profiles.yml` with the modes `off`, `report-only` and `enforce`
- Header builder with validation (no header injection, no fixed nonces, unknown directives rejected) and warnings
- Per-request nonce, correctly quoted
- `csp::addPolicy()` while the page renders
- Report endpoint `csp_report` (`report-uri` and `report-to`), aggregated storage without IP address and user agent
- Backend pages for profiles (with preview) and reports
