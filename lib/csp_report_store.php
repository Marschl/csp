<?php

/**
 * Stores violation reports aggregated: one row per directive, blocked source, page path and disposition, with a
 * counter. Anyone on the internet can post to the endpoint, so the table has a hard row limit.
 */
final class csp_report_store
{
    public const MAX_ROWS = 2000;

    public static function table(): string
    {
        return rex::getTable('csp_report');
    }

    /**
     * @param array{directive: string, blocked: string, path: string, disposition: string, sample: string} $r
     */
    public static function record(array $r): void
    {
        $hash = sha1(implode("\0", [$r['directive'], $r['blocked'], $r['path'], $r['disposition']]));

        $sql = rex_sql::factory();
        $sql->setQuery('UPDATE ' . self::table() . ' SET hits = hits + 1, last_seen = NOW() WHERE hash = :hash', [':hash' => $hash]);
        if ($sql->getRows() > 0) {
            return;
        }

        if (self::count() >= self::MAX_ROWS) {
            return;
        }

        // INSERT IGNORE: a second request with the same report may have won the race, the unique key keeps one row
        $sql->setQuery(
            'INSERT IGNORE INTO ' . self::table() . ' (hash, directive, blocked, path, disposition, sample, hits, first_seen, last_seen)
             VALUES (:hash, :directive, :blocked, :path, :disposition, :sample, 1, NOW(), NOW())',
            [
                ':hash' => $hash,
                ':directive' => $r['directive'],
                ':blocked' => $r['blocked'],
                ':path' => $r['path'],
                ':disposition' => $r['disposition'],
                ':sample' => $r['sample'] === '' ? null : $r['sample'],
            ],
        );
    }

    public static function count(): int
    {
        return (int) rex_sql::factory()->getArray('SELECT COUNT(*) AS c FROM ' . self::table())[0]['c'];
    }

    public static function delete(?int $id = null): void
    {
        $sql = rex_sql::factory();
        if ($id === null) {
            $sql->setQuery('DELETE FROM ' . self::table());
        } else {
            $sql->setQuery('DELETE FROM ' . self::table() . ' WHERE id = :id', [':id' => $id]);
        }
    }
}
