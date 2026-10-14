<?php

/**
 * Builds and parses a Content-Security-Policy. Pure PHP, no REDAXO dependency, so it can be tested without a boot.
 *
 * Text format (one directive per line, same spelling as in the header):
 *
 *     default-src 'self'
 *     script-src 'self' 'nonce' https://stats.example.org
 *     upgrade-insecure-requests
 *
 * `'nonce'` stands for the per-request nonce and is replaced when the header is rendered. A literal
 * `'nonce-abc'` is rejected on purpose: a nonce that does not change per request protects nothing.
 */
final class csp_policy
{
    /** Placeholder source that becomes 'nonce-<value>' in the rendered header */
    public const NONCE = "'nonce'";

    /** @var list<string> Keywords that are written in single quotes */
    private const KEYWORDS = [
        'self', 'none', 'unsafe-inline', 'unsafe-eval', 'wasm-unsafe-eval', 'strict-dynamic',
        'unsafe-hashes', 'report-sample', 'inline-speculation-rules',
    ];

    /** @var list<string> Directives with a list of sources */
    private const SOURCE_DIRECTIVES = [
        'default-src', 'script-src', 'script-src-elem', 'script-src-attr', 'style-src', 'style-src-elem',
        'style-src-attr', 'img-src', 'font-src', 'connect-src', 'media-src', 'object-src', 'frame-src',
        'child-src', 'worker-src', 'manifest-src', 'prefetch-src', 'base-uri', 'form-action', 'frame-ancestors',
    ];

    /** @var list<string> Directives with free tokens (a URI, a group name, sandbox flags, ...) */
    private const TOKEN_DIRECTIVES = ['report-uri', 'report-to', 'sandbox', 'trusted-types', 'require-trusted-types-for'];

    /** @var list<string> Directives without a value */
    private const FLAG_DIRECTIVES = ['upgrade-insecure-requests', 'block-all-mixed-content'];

    /** @var array<string, list<string>> Directive => sources, in insertion order */
    private array $directives = [];

    /**
     * Parses the text format. Never throws: problems are returned, the valid lines are kept.
     *
     * @return array{policy: self, errors: list<string>}
     */
    public static function parse(string $text): array
    {
        $policy = new self();
        $errors = [];

        foreach (preg_split('/\R/', $text) ?: [] as $no => $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#') {
                continue;
            }
            $line = rtrim($line, "; \t");
            $parts = preg_split('/\s+/', $line) ?: [];
            $name = strtolower((string) array_shift($parts));

            if (isset($policy->directives[$name])) {
                $errors[] = sprintf('line %d: directive "%s" is defined twice', $no + 1, $name);
                continue;
            }
            foreach ($policy->tryAdd($name, $parts) as $error) {
                $errors[] = sprintf('line %d: %s', $no + 1, $error);
            }
        }

        return ['policy' => $policy, 'errors' => $errors];
    }

    /**
     * Adds sources to a directive. Keywords may be given without quotes ('self' or self); `nonce` means the
     * per-request nonce. Invalid input throws, use parse() for text that comes from a form.
     *
     * @throws InvalidArgumentException
     */
    public function add(string $directive, string ...$sources): self
    {
        $errors = $this->tryAdd(strtolower(trim($directive)), $sources);
        if ($errors) {
            throw new InvalidArgumentException(implode('; ', $errors));
        }

        return $this;
    }

    /**
     * Adds a directive only when the policy does not define it yet
     */
    public function addIfMissing(string $directive, string ...$sources): self
    {
        return isset($this->directives[strtolower(trim($directive))]) ? $this : $this->add($directive, ...$sources);
    }

    /**
     * @return array<string, list<string>>
     */
    public function directives(): array
    {
        return $this->directives;
    }

    public function isEmpty(): bool
    {
        return $this->directives === [];
    }

    /**
     * Whether any directive uses the per-request nonce
     */
    public function usesNonce(): bool
    {
        foreach ($this->directives as $sources) {
            if (in_array(self::NONCE, $sources, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Problems that do not make the policy invalid but change its meaning
     *
     * @return list<string>
     */
    public function warnings(): array
    {
        $warnings = [];
        foreach ($this->directives as $name => $sources) {
            $hasUnsafeInline = in_array("'unsafe-inline'", $sources, true);
            $hasNonceOrHash = (bool) array_filter($sources, static fn ($s) => $s === self::NONCE || preg_match("/^'sha(256|384|512)-/", $s));
            if ($hasUnsafeInline && ($hasNonceOrHash || in_array("'strict-dynamic'", $sources, true))) {
                $warnings[] = sprintf("%s: 'unsafe-inline' is ignored by browsers as soon as a nonce, a hash or 'strict-dynamic' is present", $name);
            }
        }

        return $warnings;
    }

    /**
     * The header value
     *
     * @param string|null $nonce Value for `'nonce'`. Without one the nonce source is left out.
     */
    public function toHeader(?string $nonce = null): string
    {
        $out = [];
        foreach ($this->directives as $name => $sources) {
            $rendered = [];
            foreach ($sources as $source) {
                if ($source === self::NONCE) {
                    if ($nonce === null || $nonce === '') {
                        continue;
                    }
                    $source = "'nonce-" . $nonce . "'";
                }
                $rendered[] = $source;
            }
            if ($sources !== [] && $rendered === []) {
                continue; // only a nonce was given and there is none: an empty directive would mean "allow nothing"
            }
            $out[] = trim($name . ' ' . implode(' ', $rendered));
        }

        return implode('; ', $out);
    }

    /**
     * The text format, the inverse of parse()
     */
    public function toText(): string
    {
        $lines = [];
        foreach ($this->directives as $name => $sources) {
            $lines[] = trim($name . ' ' . implode(' ', $sources));
        }

        return implode("\n", $lines);
    }

    public static function headerName(bool $reportOnly): string
    {
        return $reportOnly ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy';
    }

    /**
     * @param list<string> $sources
     *
     * @return list<string> error messages, empty when everything was added
     */
    private function tryAdd(string $name, array $sources): array
    {
        $isSourceList = in_array($name, self::SOURCE_DIRECTIVES, true);
        $isToken = in_array($name, self::TOKEN_DIRECTIVES, true);
        $isFlag = in_array($name, self::FLAG_DIRECTIVES, true);

        if (!$isSourceList && !$isToken && !$isFlag) {
            return [sprintf('unknown directive "%s"', $name)];
        }
        if ($isFlag) {
            if ($sources) {
                return [sprintf('"%s" takes no value', $name)];
            }
            $this->directives[$name] = [];

            return [];
        }
        if (!$sources) {
            if ($name === 'sandbox') {
                $this->directives[$name] = []; // a bare "sandbox" is the strictest form

                return [];
            }

            return [sprintf('"%s" needs at least one value', $name)];
        }

        $errors = [];
        $clean = $this->directives[$name] ?? [];
        foreach ($sources as $source) {
            $normalized = $isToken ? self::normalizeToken($source) : self::normalizeSource($source);
            if (is_array($normalized)) {
                $errors[] = sprintf('%s: %s', $name, $normalized[0]);
            } elseif (!in_array($normalized, $clean, true)) {
                $clean[] = $normalized;
            }
        }

        if ($isSourceList && count($clean) > 1 && in_array("'none'", $clean, true)) {
            $errors[] = sprintf("%s: 'none' cannot be combined with other sources", $name);
        }
        if (!$errors) {
            $this->directives[$name] = $clean;
        }

        return $errors;
    }

    /**
     * @return string|array{0: string} the normalized source, or a one-element array with the error
     */
    private static function normalizeSource(string $source): string|array
    {
        $source = trim($source);
        if ($source === '') {
            return ['empty source'];
        }
        if (strlen($source) > 2048) {
            return ['source is too long'];
        }
        // Everything that could end the directive, split the header or smuggle a second one
        if (preg_match('/[\s;,\x00-\x1F\x7F"<>\\\\]/', $source)) {
            return [sprintf('invalid character in "%s"', self::shorten($source))];
        }

        $bare = strtolower($source);
        if (preg_match("/^'?nonce-/", $bare)) {
            return ["a fixed nonce is not allowed, use 'nonce'"]; // unquoted it would silently be read as a host name
        }
        if ($bare === 'nonce' || $bare === self::NONCE) {
            return self::NONCE;
        }
        if (in_array($bare, self::KEYWORDS, true)) {
            return "'" . $bare . "'";
        }
        if ($source[0] === "'") {
            $inner = substr($source, 1, -1);
            if (substr($source, -1) === "'" && in_array(strtolower($inner), self::KEYWORDS, true)) {
                return "'" . strtolower($inner) . "'";
            }
            if (substr($source, -1) === "'" && preg_match('/^sha(256|384|512)-[A-Za-z0-9+\/_-]+={0,2}$/', $inner)) {
                return $source;
            }

            return [sprintf('unknown keyword %s', self::shorten($source))];
        }
        if (preg_match('/^sha(256|384|512)-[A-Za-z0-9+\/_-]+={0,2}$/', $source)) {
            return "'" . $source . "'"; // a hash written without quotes
        }
        if ($source === '*') {
            return $source;
        }
        // scheme-source: "https:", "data:", "wss:"
        if (preg_match('/^[A-Za-z][A-Za-z0-9+.-]*:$/', $source)) {
            return strtolower($source);
        }
        // host-source: optional scheme, optional leading wildcard, optional port, optional path. Case of the path is kept.
        if (preg_match('/^(?:[A-Za-z][A-Za-z0-9+.-]*:\/\/)?(?:\*\.)?(?:[A-Za-z0-9-]+\.)*[A-Za-z0-9-]+(?::(?:\d{1,5}|\*))?(?:\/[^\s]*)?$/', $source)) {
            return $source;
        }

        return [sprintf('"%s" is not a valid source', self::shorten($source))];
    }

    /**
     * @return string|array{0: string}
     */
    private static function normalizeToken(string $token): string|array
    {
        $token = trim($token);
        if ($token === '' || strlen($token) > 2048 || preg_match('/[\s;,\x00-\x1F\x7F"<>\\\\]/', $token)) {
            return [sprintf('invalid value "%s"', self::shorten($token))];
        }

        return $token;
    }

    private static function shorten(string $value): string
    {
        return mb_strlen($value) > 40 ? mb_substr($value, 0, 40) . '…' : $value;
    }
}
