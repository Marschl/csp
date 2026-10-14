<?php

/**
 * Tests for csp_policy. No framework and no REDAXO boot needed:
 *
 *     php tests/run.php
 */
require __DIR__ . '/../lib/csp_policy.php';
require __DIR__ . '/../lib/csp_report.php';

$results = [];
$check = static function (string $name, bool $ok, string $detail = '') use (&$results): void {
    $results[] = [$name, $ok, $detail];
};
$throws = static function (callable $fn): bool {
    try {
        $fn();
    } catch (InvalidArgumentException) {
        return true;
    }

    return false;
};

// Keywords are quoted, with or without quotes in the input
$p = (new csp_policy())->add('default-src', 'self')->add('base-uri', "'none'");
$check('keyword self is quoted', $p->toHeader() === "default-src 'self'; base-uri 'none'", $p->toHeader());
$p = (new csp_policy())->add('script-src', "'SELF'", 'Unsafe-Inline');
$check('keywords are case-insensitive and normalized', $p->toHeader() === "script-src 'self' 'unsafe-inline'", $p->toHeader());

// Nonce
$p = (new csp_policy())->add('script-src', 'self', 'nonce');
$check('nonce becomes quoted nonce-<value>', $p->toHeader('abc123==') === "script-src 'self' 'nonce-abc123=='", $p->toHeader('abc123=='));
$check('nonce is left out without a value', $p->toHeader() === "script-src 'self'", $p->toHeader());
$check('usesNonce() is true', $p->usesNonce());
$check('a directive with only a nonce is dropped without one', (new csp_policy())->add('script-src', 'nonce')->toHeader() === '');
$check('fixed quoted nonce is rejected', $throws(fn () => (new csp_policy())->add('script-src', "'nonce-abc'")));
$check('fixed unquoted nonce is rejected (would be read as host)', $throws(fn () => (new csp_policy())->add('script-src', 'nonce-abc')));

// Hashes
$hash = 'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=';
$check('hash without quotes is quoted', (new csp_policy())->add('script-src', $hash)->toHeader() === "script-src '" . $hash . "'");
$check('hash with quotes is kept', (new csp_policy())->add('script-src', "'" . $hash . "'")->toHeader() === "script-src '" . $hash . "'");
$check('malformed hash is rejected', $throws(fn () => (new csp_policy())->add('script-src', "'sha256-@@@'")));

// Hosts and schemes keep their case, in particular the path
$p = (new csp_policy())->add('img-src', 'https://Cdn.Example.org/Images/A.png', 'data:', 'HTTPS:', '*.example.org:8443', 'wss:', 'localhost:3000');
$check('path case is kept', str_contains($p->toHeader(), 'https://Cdn.Example.org/Images/A.png'), $p->toHeader());
$check('scheme sources are lower-cased', (new csp_policy())->add('img-src', 'HTTPS:')->toHeader() === 'img-src https:');
$check('wildcard host with port is accepted', str_contains($p->toHeader(), '*.example.org:8443'));

// Header injection and malformed sources
foreach ([
    'semicolon' => 'https://a.example; script-src *',
    'comma' => 'https://a.example,https://b.example',
    'newline' => "https://a.example\nX-Evil: 1",
    'carriage return' => "https://a.example\rX",
    'space' => 'https://a.example https://b.example',
    'double quote' => 'https://a".example',
    'angle bracket' => 'https://a.example/<script>',
    'backslash' => 'https://a.example\\x',
    'empty' => '',
    'unknown keyword' => "'unsafe-everything'",
    'no host' => 'https://',
] as $name => $value) {
    $check("invalid source rejected: $name", $throws(fn () => (new csp_policy())->add('script-src', $value)));
}
$check('one bad source does not change the directive', (function () {
    $p = (new csp_policy())->add('script-src', 'self');
    try {
        $p->add('script-src', 'https://ok.example', 'bad;source');
    } catch (InvalidArgumentException) {
    }

    return $p->toHeader() === "script-src 'self'";
})());

// Structure rules
$check('unknown directive is rejected', $throws(fn () => (new csp_policy())->add('script-sorce', 'self')));
$check("'none' with other sources is rejected", $throws(fn () => (new csp_policy())->add('object-src', 'none', 'self')));
$check('duplicate sources are dropped', (new csp_policy())->add('img-src', 'self', "'self'", 'https://a.example', 'https://a.example')->toHeader() === "img-src 'self' https://a.example");
$check('flag directive without value', (new csp_policy())->add('upgrade-insecure-requests')->toHeader() === 'upgrade-insecure-requests');
$check('flag directive with value is rejected', $throws(fn () => (new csp_policy())->add('upgrade-insecure-requests', 'self')));
$check('source directive without value is rejected', $throws(fn () => (new csp_policy())->add('script-src')));
$check('bare sandbox is allowed', (new csp_policy())->add('sandbox')->toHeader() === 'sandbox');
$check('report-uri accepts a path', (new csp_policy())->add('report-uri', '/index.php?rex-api-call=csp_report')->toHeader() === 'report-uri /index.php?rex-api-call=csp_report');
$check('report-uri rejects a semicolon', $throws(fn () => (new csp_policy())->add('report-uri', '/a;b')));
$check('empty policy renders empty', (new csp_policy())->toHeader() === '' && (new csp_policy())->isEmpty());

// Warnings
$w = (new csp_policy())->add('script-src-elem', 'self', 'nonce', 'unsafe-inline')->warnings();
$check("'unsafe-inline' next to a nonce warns", count($w) === 1 && str_contains($w[0], 'script-src-elem'), implode(' | ', $w));
$w = (new csp_policy())->add('script-src', 'self', 'unsafe-inline', 'strict-dynamic')->warnings();
$check("'unsafe-inline' next to strict-dynamic warns", count($w) === 1);
$w = (new csp_policy())->add('script-src', 'self', "'" . $hash . "'", 'unsafe-inline')->warnings();
$check("'unsafe-inline' next to a hash warns", count($w) === 1);
$check("'unsafe-inline' alone does not warn", (new csp_policy())->add('style-src-attr', 'self', 'unsafe-inline')->warnings() === []);

// Parser
$text = "# comment\n\ndefault-src 'self'\nscript-src 'self' 'nonce' https://stats.example.org;\nupgrade-insecure-requests\n";
['policy' => $p, 'errors' => $e] = csp_policy::parse($text);
$check('parser reads a valid text without errors', $e === [], implode(' | ', $e));
$check('parser ignores comments, blank lines and a trailing semicolon', $p->toHeader('N') === "default-src 'self'; script-src 'self' 'nonce-N' https://stats.example.org; upgrade-insecure-requests", $p->toHeader('N'));
$check('parse(toText()) is the identity', csp_policy::parse($p->toText())['policy']->toText() === $p->toText());
$check('toText() keeps the nonce placeholder', str_contains($p->toText(), "'nonce'"));

['policy' => $p, 'errors' => $e] = csp_policy::parse("default-src 'self'\nscript-src https://a.example;evil\nfoo-src 'self'\nimg-src data:\nimg-src 'self'\n");
$check('parser reports every bad line with its number', count($e) === 3 && str_starts_with($e[0], 'line 2') && str_starts_with($e[1], 'line 3') && str_starts_with($e[2], 'line 5'), implode(' | ', $e));
$check('parser keeps the valid lines', $p->toHeader() === "default-src 'self'; img-src data:", $p->toHeader());
$check('directive names are lower-cased', csp_policy::parse("Default-SRC 'self'")['policy']->toHeader() === "default-src 'self'");
$check('CRLF line endings work', count(csp_policy::parse("default-src 'self'\r\nimg-src data:\r\n")['policy']->directives()) === 2);
$check('empty text gives an empty policy without errors', csp_policy::parse('')['errors'] === [] && csp_policy::parse('')['policy']->isEmpty());

// Header names
$check('header name enforce', csp_policy::headerName(false) === 'Content-Security-Policy');
$check('header name report-only', csp_policy::headerName(true) === 'Content-Security-Policy-Report-Only');

// Reports: report-uri format
$legacy = json_encode(['csp-report' => [
    'document-uri' => 'https://example.org/de/jobs/?token=SECRET&application=7f53b9ca#frag',
    'blocked-uri' => 'https://www.googleapis.com/maps/api/js?key=SECRET',
    'violated-directive' => 'script-src-elem',
    'effective-directive' => 'script-src-elem',
    'disposition' => 'report',
    'script-sample' => "window.location\n.href",
]]);
$rec = csp_report::parse($legacy);
$check('report-uri format yields one record', count($rec) === 1);
$check('document path has no query, fragment or host', ($rec[0]['path'] ?? '') === '/de/jobs/', $rec[0]['path'] ?? '');
$check('blocked uri is reduced to its origin', ($rec[0]['blocked'] ?? '') === 'https://www.googleapis.com', $rec[0]['blocked'] ?? '');
$check('the record contains no token anywhere', !str_contains(json_encode($rec), 'SECRET') && !str_contains(json_encode($rec), '7f53b9ca'));
$check('disposition and directive are kept', ($rec[0]['disposition'] ?? '') === 'report' && ($rec[0]['directive'] ?? '') === 'script-src-elem');
$check('sample has no control characters', !preg_match('/[\x00-\x1F]/', $rec[0]['sample'] ?? ''), $rec[0]['sample'] ?? '');

// Reports: report-to format
$modern = json_encode([
    ['type' => 'csp-violation', 'url' => 'https://example.org/', 'body' => ['documentURL' => 'https://example.org/a?x=1', 'blockedURL' => 'inline', 'effectiveDirective' => 'script-src-elem', 'disposition' => 'enforce']],
    ['type' => 'deprecation', 'body' => ['id' => 'x']],
    ['type' => 'csp-violation', 'body' => ['documentURL' => 'https://example.org/b', 'blockedURL' => 'data', 'effectiveDirective' => 'img-src']],
]);
$rec = csp_report::parse($modern);
$check('report-to format keeps only csp-violation entries', count($rec) === 2, (string) count($rec));
$check('keyword blocked uris (inline, data) stay as they are', ($rec[0]['blocked'] ?? '') === 'inline' && ($rec[1]['blocked'] ?? '') === 'data');
$check('missing disposition counts as enforce', ($rec[1]['disposition'] ?? '') === 'enforce');

// Reports: noise and abuse
foreach (['chrome-extension://abcdef/content.js', 'moz-extension://1234/x.js', 'safari-web-extension://z/a.js'] as $ext) {
    $check("extension report dropped: $ext", csp_report::parse(json_encode(['csp-report' => ['document-uri' => 'https://k.example/', 'blocked-uri' => $ext, 'effective-directive' => 'script-src']])) === []);
}
$check('extension script as source file is dropped', csp_report::parse(json_encode(['csp-report' => ['document-uri' => 'https://k.example/', 'blocked-uri' => 'inline', 'source-file' => 'moz-extension://1/a.js', 'effective-directive' => 'script-src']])) === []);
$check('invalid json gives no records', csp_report::parse('{ nope') === []);
$check('empty body gives no records', csp_report::parse('') === []);
$check('scalar json gives no records', csp_report::parse('42') === [] && csp_report::parse('"x"') === []);
$check('oversized body gives no records', csp_report::parse(str_repeat(' ', csp_report::MAX_BODY) . $legacy) === []);
$check('directive with odd characters is dropped', csp_report::parse(json_encode(['csp-report' => ['effective-directive' => "script-src'; DROP TABLE"]])) === []);
$check('very long values are cut', strlen(csp_report::parse(json_encode(['csp-report' => ['effective-directive' => 'img-src', 'document-uri' => 'https://k.example/' . str_repeat('a', 5000), 'script-sample' => str_repeat('x', 5000)]]))[0]['path']) <= 255);
$many = json_encode(array_fill(0, 100, ['type' => 'csp-violation', 'body' => ['effectiveDirective' => 'img-src']]));
$check('at most 20 entries are taken from a report-to batch', count(csp_report::parse($many)) === 20);

$failed = 0;
foreach ($results as [$name, $ok, $detail]) {
    echo ($ok ? 'OK   ' : 'FAIL ') . $name . ($detail !== '' && !$ok ? "  [$detail]" : '') . "\n";
    $failed += $ok ? 0 : 1;
}
echo "\n" . (count($results) - $failed) . '/' . count($results) . " passed\n";
exit($failed ? 1 : 0);
