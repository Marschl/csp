# CSP – Content Security Policy for REDAXO

Sends a `Content-Security-Policy` header for the website (not for the backend), chosen by host name, with a report
endpoint so a policy can be observed before it is enforced.

- **Profiles per host** (`dev`, `review`, `live`): mode `off`, `report-only` or `enforce`
- **Configuration is a file**, `redaxo/data/addons/csp/profiles.yml`. It belongs in the project repository and travels
  with the deploy. The backend page edits the same file and validates it before saving.
- **Per-request nonce** with a correctly quoted header value (`'nonce-…'`)
- **Violation reports**, stored aggregated, without IP address or user agent
- No dependencies. Requires REDAXO 5.18+, PHP 8.1+.

## Profiles

```yaml
profiles:
    -
        name: Live
        hosts: [example.org, www.example.org]
        mode: enforce            # off | report-only | enforce
        report: false            # send violations to the report endpoint
        policy:
            - "default-src 'self'"
            - "img-src 'self' data:"
            - "script-src 'self' 'nonce'"
    -
        name: Everything else
        hosts: ['*']
        mode: report-only
        report: true
        policy:
            - "default-src 'self'"
```

The first profile whose pattern matches the host wins (`*` and `?` work, the port is ignored). No match, `mode: off`
or an invalid file means: **no header**. A broken file never breaks the website, but it silently disables the policy,
so the error is written to the REDAXO log and shown on the backend page.

Each policy line is one directive in header spelling. Keywords may be written without quotes. `'nonce'` stands for the
nonce of the request. The following is rejected on purpose: a fixed `'nonce-abc'` or an unquoted `nonce-abc` (browsers
would read it as a host name), characters that could end the directive or split the header (`;`, `,`, whitespace,
line breaks), unknown directives, `'none'` combined with other sources.

Not an error but a warning in the backend preview: `'unsafe-inline'` next to a nonce, a hash or `'strict-dynamic'`.
Browsers then **ignore** `'unsafe-inline'`, so every inline script without a nonce is blocked.

> The profiles file is read from the project. If the backend is used on the live server, the next deploy overwrites
> the change with the file from the repository.

## Roll-out: observe first, then enforce

1. Put the new policy in a profile with `mode: report-only` and `report: true`.
2. Browse the site. Violations show up under *Reports* (directive, blocked origin, page path, count).
3. Fix the site or extend the policy until the list is quiet.
4. Switch the profile to `enforce`.

Reports are sent with `report-uri` (all browsers) and `report-to` / `Reporting-Endpoints` (Chromium, sent delayed and in
batches).

## Nonce

```php
<script <?= csp::nonceAttr() ?>>…</script>   // nonce="…" or nothing
echo csp::nonce();                              // the value, empty while the policy has no 'nonce'
```

A nonce changes with every request. Pages that carry one must not be served from a full-page cache.

## Extending the policy from code

```php
csp::addPolicy('img-src', 'https://tiles.example.org');
```

The header is sent right before the output, so modules and templates can still add sources while the page renders.
Invalid input throws in debug mode and is logged otherwise.

## Report endpoint and privacy

`POST /index.php?rex-api-call=csp_report` accepts `application/csp-report` and `application/reports+json` and always
answers `204`. Only this is stored, one row per combination: violated directive, **origin** of the blocked source, **path**
of the page (no host, no query, no fragment, because queries can carry tokens), disposition and an 80 character code
sample, plus a counter. Not stored: IP address, user agent, referrer, full URLs. Reports from browser extensions are
dropped. Bodies above 16 KB are ignored and the table stops growing at 2 000 rows (existing rows still count up).
Anyone can post to the endpoint, so treat the numbers as hints, not as statistics.

Delete reports under *Reports* in the backend. Uninstalling the addon drops the table and keeps the profiles file.

## Tests

```bash
php tests/run.php
```

No framework and no REDAXO boot needed. They cover the header builder, the profile text parser and the report parser.

## License

MIT, see `LICENSE`.
