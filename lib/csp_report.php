<?php

/**
 * Turns the body of a CSP violation report into small, privacy-friendly records. Pure PHP, no REDAXO dependency.
 *
 * Understands both wire formats:
 *  - report-uri:  Content-Type application/csp-report, {"csp-report": {"document-uri": ..., ...}}
 *  - report-to:   Content-Type application/reports+json, [{"type": "csp-violation", "body": {"documentURL": ..., ...}}]
 *
 * What is kept: the violated directive, the blocked source reduced to its origin, the path of the page without
 * query and fragment (queries can carry tokens), the disposition and a short code sample. What is never kept:
 * IP address, user agent, referrer, the full URLs.
 */
final class csp_report
{
    public const MAX_BODY = 16384;

    /** Schemes of browser extensions: their violations are noise and not caused by the site */
    private const EXTENSION_SCHEMES = ['chrome-extension', 'moz-extension', 'safari-extension', 'safari-web-extension', 'ms-browser-extension', 'webkit-masked-url'];

    /**
     * @return list<array{directive: string, blocked: string, path: string, disposition: string, sample: string}>
     */
    public static function parse(string $body): array
    {
        if ($body === '' || strlen($body) > self::MAX_BODY) {
            return [];
        }
        try {
            $data = json_decode($body, true, 8, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return [];
        }
        if (!is_array($data)) {
            return [];
        }

        $raw = [];
        if (isset($data['csp-report']) && is_array($data['csp-report'])) {
            $raw[] = $data['csp-report'];
        } else {
            // report-to sends a list, a single object is tolerated
            $items = array_is_list($data) ? $data : [$data];
            foreach (array_slice($items, 0, 20) as $item) {
                if (is_array($item) && ($item['type'] ?? '') === 'csp-violation' && is_array($item['body'] ?? null)) {
                    $raw[] = $item['body'];
                }
            }
        }

        $records = [];
        foreach ($raw as $r) {
            $record = self::record($r);
            if ($record !== null) {
                $records[] = $record;
            }
        }

        return $records;
    }

    /**
     * @param array<mixed> $r
     *
     * @return array{directive: string, blocked: string, path: string, disposition: string, sample: string}|null
     */
    private static function record(array $r): ?array
    {
        $directive = self::str($r['effective-directive'] ?? $r['effectiveDirective'] ?? $r['violated-directive'] ?? $r['violatedDirective'] ?? '');
        $directive = strtolower(strtok($directive, ' ') ?: '');
        if (!preg_match('/^[a-z][a-z-]{1,40}$/', $directive)) {
            return null;
        }

        $blockedRaw = self::str($r['blocked-uri'] ?? $r['blockedURL'] ?? $r['blockedURI'] ?? '');
        $sourceFile = self::str($r['source-file'] ?? $r['sourceFile'] ?? '');
        foreach ([$blockedRaw, $sourceFile] as $url) {
            if (in_array(strtolower((string) parse_url($url, PHP_URL_SCHEME)), self::EXTENSION_SCHEMES, true)) {
                return null;
            }
        }

        $disposition = strtolower(self::str($r['disposition'] ?? 'enforce'));

        return [
            'directive' => $directive,
            'blocked' => self::origin($blockedRaw),
            'path' => self::path(self::str($r['document-uri'] ?? $r['documentURL'] ?? $r['documentURI'] ?? '')),
            'disposition' => $disposition === 'report' ? 'report' : 'enforce',
            'sample' => self::clean(self::str($r['script-sample'] ?? $r['sample'] ?? ''), 80),
        ];
    }

    /**
     * Blocked sources are reduced to scheme://host[:port]. Keywords the browser reports (inline, eval, data, ...)
     * stay as they are.
     */
    private static function origin(string $url): string
    {
        $url = trim($url);
        if ($url === '') {
            return '';
        }
        $parts = parse_url($url);
        if ($parts === false || !isset($parts['scheme'])) {
            return self::clean($url, 40);
        }
        $scheme = strtolower($parts['scheme']);
        if (!isset($parts['host'])) {
            return self::clean($scheme, 40); // data:, blob:, about:, ...
        }

        return self::clean($scheme . '://' . strtolower($parts['host']) . (isset($parts['port']) ? ':' . $parts['port'] : ''), 255);
    }

    /**
     * Only the path of the page: no host (the profile already says which site), no query, no fragment
     */
    private static function path(string $url): string
    {
        $path = parse_url($url, PHP_URL_PATH);

        return is_string($path) && $path !== '' ? self::clean($path, 255) : '/';
    }

    private static function str(mixed $value): string
    {
        return is_string($value) ? $value : '';
    }

    /**
     * Strips control characters and cuts to a length so nothing odd reaches the database or the backend list
     */
    private static function clean(string $value, int $max): string
    {
        $value = preg_replace('/[\x00-\x1F\x7F]+/', ' ', $value) ?? '';

        return mb_substr(trim($value), 0, $max);
    }
}
