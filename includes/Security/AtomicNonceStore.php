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

    /**
     * Atomically consume a nonce.
     *
     * @param string $namespace Logical grouping for the nonce (e.g. 'scan_tick', 'cf_flush').
     * @param string $nonce     The raw nonce string.
     * @param int    $ttl       Time to live in seconds (default: 300).
     * @return bool True if nonce was successfully consumed (first time seen), false if already consumed or expired.
     */
    public static function consume(string $namespace, string $nonce, int $ttl = 300): bool {
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

        if ($wpdb instanceof \wpdb && !empty($wpdb->options)) {
            $options_table = $wpdb->options;
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

            // 1 = fresh row inserted, 2 = expired row updated, 0 = unexpired row unmodified
            return $affected === 1 || $affected === 2;
        }

        // Fallback if $wpdb is unavailable (e.g. unit test minimal mock environment)
        $existing = get_option($key, null);
        if ($existing !== null) {
            $existing_expires = (int) $existing;
            if ($existing_expires >= $now) {
                return false; // Still active
            }
            // Expired, update
            return update_option($key, (string) $expires_at, false);
        }

        return add_option($key, (string) $expires_at, '', 'no');
    }
}
