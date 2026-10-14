<?php

/**
 * Reads, validates and writes the profiles (redaxo/data/addons/csp/profiles.yml).
 *
 * A profile is chosen by host name, the first one that matches wins:
 *
 *     profiles:
 *         - name: Live
 *           hosts: [example.org, www.example.org]
 *           mode: enforce          # off | report-only | enforce
 *           report: true           # send violations to the report endpoint
 *           policy:
 *               - "default-src 'self'"
 *               - "img-src 'self' data:"
 *
 * The file is configuration and lives in the project repository, so it travels with the deploy.
 */
final class csp_profiles
{
    public const MODES = ['off', 'report-only', 'enforce'];

    /** @var list<array{name: string, hosts: list<string>, mode: string, report: bool, policy: list<string>}>|null */
    private static ?array $cache = null;

    public static function file(): string
    {
        return rex_path::addonData('csp', 'profiles.yml');
    }

    /**
     * A conservative example for a fresh install: observe, do not block
     *
     * @return list<array{name: string, hosts: list<string>, mode: string, report: bool, policy: list<string>}>
     */
    public static function defaults(): array
    {
        return [[
            'name' => 'Default',
            'hosts' => ['*'],
            'mode' => 'report-only',
            'report' => true,
            'policy' => [
                "default-src 'self'",
                "img-src 'self' data:",
                "object-src 'none'",
                "base-uri 'self'",
                "frame-ancestors 'self'",
            ],
        ]];
    }

    /**
     * All profiles from the file. Problems never reach the visitor: the error is logged and the result is empty,
     * which means no header.
     *
     * @return list<array{name: string, hosts: list<string>, mode: string, report: bool, policy: list<string>}>
     */
    public static function all(): array
    {
        if (self::$cache !== null) {
            return self::$cache;
        }

        self::$cache = [];
        try {
            $data = rex_file::getConfig(self::file(), []);
            [$profiles, $errors] = self::normalize($data);
            if ($errors) {
                throw new RuntimeException('csp: profiles.yml is invalid: ' . implode('; ', $errors));
            }
            self::$cache = $profiles;
        } catch (Throwable $e) {
            rex_logger::logException($e);
        }

        return self::$cache;
    }

    /**
     * Problems with the saved file, without logging. The backend shows them, because a broken file silently
     * means "no header".
     *
     * @return list<string>
     */
    public static function problems(): array
    {
        if (!is_file(self::file())) {
            return ['profiles.yml does not exist'];
        }
        try {
            return self::normalize(rex_file::getConfig(self::file(), []))[1];
        } catch (Throwable $e) {
            return [$e->getMessage()];
        }
    }

    /**
     * The profile for a host, or null
     *
     * @return array{name: string, hosts: list<string>, mode: string, report: bool, policy: list<string>}|null
     */
    public static function find(string $host): ?array
    {
        foreach (self::all() as $profile) {
            if (self::matches($profile, $host)) {
                return $profile;
            }
        }

        return null;
    }

    /**
     * @param array{hosts: list<string>} $profile
     */
    public static function matches(array $profile, string $host): bool
    {
        $host = strtolower(preg_replace('/:\d+$/', '', trim($host)) ?? '');
        foreach ($profile['hosts'] as $pattern) {
            if (fnmatch(strtolower($pattern), $host)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Parses and checks the decoded YAML. Returns the cleaned profiles and every problem found.
     *
     * @return array{0: list<array{name: string, hosts: list<string>, mode: string, report: bool, policy: list<string>}>, 1: list<string>}
     */
    public static function normalize(mixed $data): array
    {
        $errors = [];
        $profiles = [];

        if (!is_array($data) || !is_array($data['profiles'] ?? null) || !array_is_list($data['profiles'])) {
            return [[], ['the file needs a list "profiles"']];
        }

        foreach ($data['profiles'] as $i => $raw) {
            $label = sprintf('profile %d', $i + 1);
            if (!is_array($raw)) {
                $errors[] = $label . ': must be a map';
                continue;
            }
            $name = is_string($raw['name'] ?? null) ? trim($raw['name']) : '';
            if ($name === '') {
                $errors[] = $label . ': name is missing';
            } else {
                $label = sprintf('profile "%s"', $name);
            }

            $hosts = array_values(array_filter((array) ($raw['hosts'] ?? []), static fn ($h) => is_string($h) && preg_match('/^[A-Za-z0-9*?.-]+$/', $h)));
            if (!$hosts || count($hosts) !== count((array) ($raw['hosts'] ?? []))) {
                $errors[] = $label . ': hosts needs a list of host names or patterns such as *.example.org';
            }

            $mode = $raw['mode'] ?? '';
            if (!in_array($mode, self::MODES, true)) {
                $errors[] = $label . ': mode must be one of ' . implode(', ', self::MODES);
                $mode = 'off';
            }

            $lines = $raw['policy'] ?? [];
            $lines = is_string($lines) ? preg_split('/\R/', $lines) : $lines;
            if (!is_array($lines) || array_filter($lines, static fn ($l) => !is_string($l))) {
                $errors[] = $label . ': policy must be a list of directive lines';
                $lines = [];
            }
            $parsed = csp_policy::parse(implode("\n", $lines));
            foreach ($parsed['errors'] as $error) {
                $errors[] = $label . ': ' . $error;
            }

            $profiles[] = [
                'name' => $name,
                'hosts' => $hosts,
                'mode' => $mode,
                'report' => (bool) ($raw['report'] ?? false),
                'policy' => $parsed['policy']->isEmpty() ? [] : explode("\n", $parsed['policy']->toText()),
            ];
        }

        return [$profiles, $errors];
    }

    /**
     * @param array{policy: list<string>} $profile
     */
    public static function policy(array $profile): csp_policy
    {
        return csp_policy::parse(implode("\n", $profile['policy']))['policy'];
    }

    /**
     * Writes the profiles file. The input is checked first, an invalid set is never written.
     *
     * @param array<mixed> $profiles
     *
     * @throws InvalidArgumentException with every problem in the message
     */
    public static function save(array $profiles): void
    {
        [$clean, $errors] = self::normalize(['profiles' => $profiles]);
        if ($errors) {
            throw new InvalidArgumentException(implode("\n", $errors));
        }
        if (!rex_file::putConfig(self::file(), ['profiles' => $clean], 5)) {
            throw new RuntimeException('csp: could not write ' . self::file());
        }
        self::$cache = null;
    }
}
