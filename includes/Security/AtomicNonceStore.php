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

        $key = 'webcare_nonce_' . md5($namespace . ':' . $nonce);
        $group = 'webcare_nonces';

        // 1. If persistent/external object cache is active, wp_cache_add is atomic across concurrent threads
        if (wp_using_ext_object_cache()) {
            return (bool) wp_cache_add($key, time(), $group, $ttl);
        }

        // 2. Direct database atomic consumption using transient/options table
        // We use add_option() with autoload='no'. In WordPress, add_option() executes:
        // INSERT INTO wp_options (option_name, option_value, autoload) VALUES (...)
        // Under MySQL/InnoDB, option_name is UNIQUE, making add_option strictly atomic.
        // If two concurrent threads attempt to add the same option, exactly one succeeds and returns true;
        // the other fails (duplicate key) and returns false.
        $transient_name = '_transient_' . $key;
        $timeout_name   = '_transient_timeout_' . $key;
        $expires        = time() + $ttl;

        // Clean up expired entry if it exists to allow reuse after TTL expires
        $existing_timeout = (int) get_option($timeout_name, 0);
        if ($existing_timeout > 0 && $existing_timeout < time()) {
            delete_option($transient_name);
            delete_option($timeout_name);
        }

        // Atomically claim the nonce via add_option
        $claimed = add_option($transient_name, 1, '', 'no');
        if (!$claimed) {
            return false;
        }

        add_option($timeout_name, $expires, '', 'no');
        return true;
    }
}
