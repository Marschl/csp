<?php

/**
 * Sends the Content-Security-Policy header for the website.
 *
 * The policy comes from the profile that matches the host (see csp_profiles). Other code can extend it while the
 * page is rendered, the header is sent right before the output:
 *
 *     csp::addPolicy('img-src', 'https://tiles.example.org');
 *
 * For inline scripts or styles that cannot be avoided, put `'nonce'` into the policy and write the attribute:
 *
 *     <script <?= csp::nonceAttr() ?>>…</script>
 *
 * A nonce changes with every request, so pages with a nonce must not be served from a full-page cache.
 */
final class csp
{
    private static ?csp_policy $policy = null;
    private static bool $reportOnly = false;
    private static bool $report = false;
    private static ?string $nonce = null;

    /**
     * Chooses the profile for this request and arranges the header. Called from boot.php, frontend only.
     */
    public static function boot(): void
    {
        $profile = csp_profiles::find(rex_request::server('HTTP_HOST', 'string', ''));
        if ($profile === null || $profile['mode'] === 'off') {
            return;
        }

        self::$policy = csp_profiles::policy($profile);
        self::$reportOnly = $profile['mode'] === 'report-only';
        self::$report = $profile['report'];
        if (self::$policy->usesNonce()) {
            self::createNonce();
        }

        // OUTPUT_FILTER runs right before the headers go out, so modules and templates can still call addPolicy()
        rex_extension::register('OUTPUT_FILTER', static function (): void {
            csp::send();
        }, rex_extension::LATE);
    }

    /**
     * Adds sources to a directive of the active policy. Does nothing while no profile is active.
     */
    public static function addPolicy(string $directive, string ...$sources): void
    {
        if (self::$policy === null) {
            return;
        }
        try {
            self::$policy->add($directive, ...$sources);
            if (self::$nonce === null && self::$policy->usesNonce()) {
                self::createNonce();
            }
        } catch (InvalidArgumentException $e) {
            if (rex::isDebugMode()) {
                throw $e;
            }
            rex_logger::logException($e);
        }
    }

    /**
     * The nonce of this request, empty while the active policy does not use one
     */
    public static function nonce(): string
    {
        return self::$nonce ?? '';
    }

    /**
     * `nonce="…"` for a script or style tag, empty while the active policy does not use a nonce
     */
    public static function nonceAttr(): string
    {
        return self::$nonce === null ? '' : 'nonce="' . self::$nonce . '"';
    }

    /**
     * The active policy, or null while no profile applies
     */
    public static function policy(): ?csp_policy
    {
        return self::$policy;
    }

    /**
     * URL the browser posts violations to
     */
    public static function reportUrl(): string
    {
        return rex_request::server('SCRIPT_NAME', 'string', '/index.php') . '?' . rex_api_function::REQ_CALL_PARAM . '=csp_report';
    }

    private static function send(): void
    {
        if (self::$policy === null || self::$policy->isEmpty()) {
            return;
        }

        if (self::$report) {
            self::$policy->addIfMissing('report-uri', self::reportUrl());
            self::$policy->addIfMissing('report-to', 'csp');
            rex_response::setHeader('Reporting-Endpoints', 'csp="' . self::reportUrl() . '"');
        }

        rex_response::setHeader(csp_policy::headerName(self::$reportOnly), self::$policy->toHeader(self::$nonce));
    }

    private static function createNonce(): void
    {
        self::$nonce = base64_encode(random_bytes(16));
    }
}
