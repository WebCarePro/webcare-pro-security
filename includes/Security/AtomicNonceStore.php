<?php
declare(strict_types=1);

namespace WebCareProScanner\Security;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Atomic Single-Use Nonce Store.
 *
 * Implements strict atomic nonce consumption to prevent replay attacks across
 * loopback calls, asynchronous tasks, and background workers.
 *
 * Employs external object caching (wp_cache_add) when available, or atomic
 * direct database insertion fallback.
 *
 * @package WebCareProScanner\Security
 * @author  Mir Alamin (WebCare Pro)
 */
final class AtomicNonceStore {

    private const TABLE_NAME = 'webcareproscan_atomic_nonces';
    public const MIN_TTL = 5;
    public const MAX_TTL = 86400;
    public const PRUNE_BATCH_LIMIT = 50;
    public const PRUNE_THROTTLE_SECONDS = 60;
    public const PRUNE_THROTTLE_KEY = 'wcp_nonce_prune_last_run';

    /**
     * Resolve and validate the WordPress options table identifier from $wpdb->options.
     */
    private static function get_validated_options_table(): string {
        global $wpdb;
        if (!($wpdb instanceof \wpdb) || empty($wpdb->options) || !is_string($wpdb->options)) {
            return '';
        }
        $table = $wpdb->options;
        return preg_match('/^[A-Za-z0-9_]+$/', $table) === 1 ? $table : '';
    }

    /**
     * Atomically consume a nonce.
     *
     * @param string $namespace Logical grouping for the nonce (e.g. 'scan_tick', 'cf_flush').
     * @param string $nonce     The raw nonce string.
     * @param int    $ttl       Time to live in seconds (default: 300, clamped to 5..86400).
     * @return bool True if nonce was successfully consumed (first time seen), false if already consumed or empty.
     * @throws \InvalidArgumentException When $ttl <= 0.
     */
    public static function consume(string $namespace, string $nonce, int $ttl = 300): bool {
        if ($ttl <= 0) {
            throw new \InvalidArgumentException('AtomicNonceStore TTL must be a positive integer.');
        }

        $ttl = min(max($ttl, self::MIN_TTL), self::MAX_TTL);

        if ($nonce === '') {
            return false;
        }

        // 1. Key Derivation (SHA-256):
        $key = 'wcp_nonce_' . substr(hash('sha256', $namespace . '|' . $nonce), 0, 40);
        $group = 'webcare_nonces';

        // 2. If persistent/external object cache is active, wp_cache_add is atomic across concurrent threads
        if (wp_using_ext_object_cache()) {
            return (bool) wp_cache_add($key, 1, $group, $ttl);
        }

        // 3. Single-Statement Atomic DB Fallback (Zero Multi-Step Race)
        // Store a single expiry-bearing row in $wpdb->options (option_name has a UNIQUE index).
        // Using INSERT ... ON DUPLICATE KEY UPDATE:
        // - Insert succeeds (returns 1 affected row) if fresh nonce -> claimed.
        // - If duplicate key exists, updates expiry ONLY IF previous value has expired (returns 2 affected rows) -> claimed.
        // - If duplicate key exists and is unexpired, no update occurs (returns 0 affected rows) -> replay rejected.
        global $wpdb;
        $now = time();
        $expires_at = $now + $ttl;

        $options_table = self::get_validated_options_table();
        if ($options_table !== '') {
            // phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- $options_table is strictly validated as [A-Za-z0-9_]+ from $wpdb->options; all query values are prepared.
            $affected = $wpdb->query(
                $wpdb->prepare(
                    "INSERT INTO {$options_table} (option_name, option_value, autoload)
                     VALUES (%s, %s, 'no')
                     ON DUPLICATE KEY UPDATE
                       option_value = IF(CAST(option_value AS UNSIGNED) < %d, VALUES(option_value), option_value)",
                    $key,
                    (string) $expires_at,
                    $now
                )
            );
            // phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

            // 1 = fresh row inserted, 2 = expired row updated, 0 = unexpired row unmodified
            $claimed = ($affected === 1 || $affected === 2);
            if ($claimed) {
                self::maybe_prune_expired_db_nonces($now, $key);
            }
            return $claimed;
        }

        // Fallback if $wpdb is unavailable (e.g. unit test minimal mock environment)
        $existing = get_option($key, null);
        if ($existing !== null) {
            $existing_expires = (int) $existing;
            if ($existing_expires >= $now) {
                return false; // Still active
            }
            // Expired, update
            $claimed = update_option($key, (string) $expires_at, false);
        } else {
            $claimed = add_option($key, (string) $expires_at, '', 'no');
        }

        if ($claimed) {
            self::maybe_prune_expired_db_nonces($now, $key);
        }

        return $claimed;
    }

    /**
     * Throttled opportunistic cleanup of expired wcp_nonce_% database rows.
     * Uses an atomic single-statement DB claim so concurrent requests cannot race into duplicate prunes;
     * runs at most once every PRUNE_THROTTLE_SECONDS (60s) and removes up to PRUNE_BATCH_LIMIT (50) expired rows.
     */
    private static function maybe_prune_expired_db_nonces(int $now, string $exclude_key = ''): void {
        if (!self::claim_prune_throttle($now)) {
            return;
        }

        self::prune_expired_db_nonces($now, $exclude_key, self::PRUNE_BATCH_LIMIT);
    }

    /**
     * Atomically claim the once-per-60-second opportunistic pruning slot.
     */
    private static function claim_prune_throttle(int $now): bool {
        $next_allowed = $now + self::PRUNE_THROTTLE_SECONDS;

        global $wpdb;
        $options_table = self::get_validated_options_table();
        if ($options_table !== '') {
            // phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- $options_table is strictly validated as [A-Za-z0-9_]+ from $wpdb->options; all query values are prepared.
            $affected = $wpdb->query(
                $wpdb->prepare(
                    "INSERT INTO {$options_table} (option_name, option_value, autoload)
                     VALUES (%s, %s, 'no')
                     ON DUPLICATE KEY UPDATE
                       option_value = IF(CAST(option_value AS UNSIGNED) < %d, VALUES(option_value), option_value)",
                    self::PRUNE_THROTTLE_KEY,
                    (string) $next_allowed,
                    $now
                )
            );
            // phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
            return ($affected === 1 || $affected === 2);
        }

        $existing = get_option(self::PRUNE_THROTTLE_KEY, null);
        if ($existing !== null) {
            if ((int) $existing >= $now) {
                return false;
            }
            return update_option(self::PRUNE_THROTTLE_KEY, (string) $next_allowed, false);
        }
        return add_option(self::PRUNE_THROTTLE_KEY, (string) $next_allowed, '', 'no');
    }

    /**
     * Reset opportunistic pruning throttle state (used for deterministic test isolation).
     */
    public static function reset_prune_throttle(): void {
        delete_option(self::PRUNE_THROTTLE_KEY);
        delete_transient(self::PRUNE_THROTTLE_KEY);
    }

    /**
     * Execute bounded cleanup of expired wcp_nonce_% option rows while strictly protecting
     * unexpired rows and any newly claimed $exclude_key.
     *
     * @param int    $now         Current UNIX timestamp.
     * @param string $exclude_key Active nonce option_name to explicitly exclude from deletion.
     * @param int    $limit       Maximum expired rows to prune in a single batch (clamped 1..500).
     * @return int Number of expired rows deleted.
     */
    public static function prune_expired_db_nonces(int $now, string $exclude_key = '', int $limit = self::PRUNE_BATCH_LIMIT): int {
        $limit = max(1, min(500, $limit));

        global $wpdb;
        $options_table = self::get_validated_options_table();
        if ($options_table !== '') {
            $like_prefix = method_exists($wpdb, 'esc_like')
                ? $wpdb->esc_like('wcp_nonce_') . '%'
                : 'wcp_nonce\\_%';
            $protected_key = $exclude_key !== '' ? $exclude_key : self::PRUNE_THROTTLE_KEY;

            // phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- $options_table is strictly validated as [A-Za-z0-9_]+ from $wpdb->options; all query values are prepared.
            $deleted = $wpdb->query(
                $wpdb->prepare(
                    "DELETE FROM {$options_table}
                     WHERE option_name LIKE %s
                       AND option_name NOT IN (%s, %s)
                       AND option_value REGEXP '^[0-9]+$'
                       AND CAST(option_value AS UNSIGNED) > 0
                       AND CAST(option_value AS UNSIGNED) < %d
                     LIMIT %d",
                    $like_prefix,
                    self::PRUNE_THROTTLE_KEY,
                    $protected_key,
                    $now,
                    $limit
                )
            );
            // phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

            return is_int($deleted) ? max(0, $deleted) : 0;
        }

        // Minimal mock environment fallback (when $wpdb->options is not active in unit tests)
        if (!isset($GLOBALS['wp_mock_options']) || !is_array($GLOBALS['wp_mock_options'])) {
            return 0;
        }

        $deleted = 0;
        foreach (array_keys($GLOBALS['wp_mock_options']) as $opt_name) {
            if ($deleted >= $limit) {
                break;
            }
            $opt_key = (string) $opt_name;
            if (!str_starts_with($opt_key, 'wcp_nonce_') || $opt_key === self::PRUNE_THROTTLE_KEY || $opt_key === $exclude_key) {
                continue;
            }
            $raw_val = $GLOBALS['wp_mock_options'][$opt_key] ?? null;
            if (!is_int($raw_val) && !(is_string($raw_val) && ctype_digit($raw_val))) {
                continue;
            }
            $exp = (int) $raw_val;
            if ($exp > 0 && $exp < $now) {
                delete_option($opt_key);
                $deleted++;
            }
        }

        return $deleted;
    }
}
