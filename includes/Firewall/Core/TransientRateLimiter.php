<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall\Core;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * TransientRateLimiter
 *
 * Lightweight transient-backed rate limiting and velocity tracker.
 * Serializes window evaluation with remaining TTL and attempt counters.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
final class TransientRateLimiter {

    /**
     * Check and record a rate limit attempt.
     *
     * Atomic concurrency implementation:
     * 1. APCu: uses atomic `apcu_inc` with `apcu_add` window initialization.
     * 2. Persistent Object Cache (Redis/Memcached): uses atomic `wp_cache_incr` with `wp_cache_add`.
     * 3. Transient fallback: bounded sliding transient.
     *
     * @param string $key Identifier for the rate limit bucket.
     * @param int    $limit Max requests allowed within window.
     * @param int    $window_seconds Window duration in seconds.
     * @return array{allowed: bool, retry_after: int, current: int, limit: int}
     */
    public static function check_rate_limit(string $key, int $limit, int $window_seconds): array {
        $now = time();
        $window_idx = (int) floor($now / $window_seconds);
        $window_start = $window_idx * $window_seconds;
        $elapsed = max(0, $now - $window_start);
        $remaining_window_ttl = max(1, $window_seconds - $elapsed);
        $cache_key = 'webcareproscan_trl_' . substr(md5($key), 0, 20) . '_w' . $window_idx;

        $is_apcu = function_exists('apcu_inc') && function_exists('apcu_add') && ini_get('apc.enabled') && (php_sapi_name() !== 'cli' || ini_get('apc.enable_cli'));

        if ($is_apcu) {
            apcu_add($cache_key, 0, $window_seconds);
            $success = false;
            $count = apcu_inc($cache_key, 1, $success);
            if (!$success || $count === false) {
                if (apcu_add($cache_key, 1, $window_seconds)) {
                    $count = 1;
                } else {
                    $count = apcu_inc($cache_key, 1, $success);
                    if (!$success || $count === false) {
                        $count = null; // Degrade to file transaction rather than non-atomic reset
                    }
                }
            }

            if ($count !== null) {
                $allowed = ($count <= $limit);
                return [
                    'allowed'     => $allowed,
                    'retry_after' => $allowed ? 0 : $remaining_window_ttl,
                    'current'     => (int) $count,
                    'limit'       => $limit,
                ];
            }
        }

        if (function_exists('wp_using_ext_object_cache') && wp_using_ext_object_cache()) {
            wp_cache_add($cache_key, 0, 'webcareproscan_rl', $window_seconds);
            $count = wp_cache_incr($cache_key, 1, 'webcareproscan_rl');
            if ($count === false) {
                if (wp_cache_add($cache_key, 1, 'webcareproscan_rl', $window_seconds)) {
                    $count = 1;
                } else {
                    $count = wp_cache_incr($cache_key, 1, 'webcareproscan_rl');
                    if ($count === false) {
                        $count = null; // Degrade to file transaction rather than non-atomic reset
                    }
                }
            }

            if ($count !== null) {
                $allowed = ($count <= $limit);
                return [
                    'allowed'     => $allowed,
                    'retry_after' => $allowed ? 0 : $remaining_window_ttl,
                    'current'     => (int) $count,
                    'limit'       => $limit,
                ];
            }
        }

        if (class_exists('\\WebCareProScanner\\Firewall\\AdaptiveRateLimiter')) {
            $base_key = 'trl_' . substr(md5($key), 0, 16);
            $counts = \WebCareProScanner\Firewall\AdaptiveRateLimiter::file_atomic_window_increment(
                $base_key,
                $window_idx,
                $window_seconds * 2
            );

            if ($counts !== null) {
                $count = (int) $counts['curr'];
                $allowed = ($count <= $limit);
                return [
                    'allowed'     => $allowed,
                    'retry_after' => $allowed ? 0 : $remaining_window_ttl,
                    'current'     => $count,
                    'limit'       => $limit,
                ];
            }

            // Controlled fail-safe under file-lock contention: do not allow silent non-atomic downgrades
            if (class_exists('\\WebCareProScanner\\System\\WebCareActivityLogger')) {
                \WebCareProScanner\System\WebCareActivityLogger::warning('transient_rl_lock_contention', 'firewall', [
                    'key'         => $key,
                    'description' => sprintf('TransientRateLimiter file lock contention for key %s; applied fail-safe policy.', $key),
                ]);
            }

            // Sensitive auth/warning strikes fail closed
            if (str_contains($key, 'warning_strike') || str_contains($key, 'auth')) {
                return [
                    'allowed'     => false,
                    'retry_after' => $remaining_window_ttl,
                    'current'     => $limit + 1,
                    'limit'       => $limit,
                ];
            }

            return [
                'allowed'     => true,
                'retry_after' => 0,
                'current'     => 1,
                'limit'       => $limit,
            ];
        }

        // Fail-safe handling when AdaptiveRateLimiter class is unavailable (v3.23.2):
        // Concurrency defense: Never use non-atomic read-modify-write transients.
        // For sensitive authentication and admin probes, fail-closed to prevent abuse under degradation.
        $is_sensitive_key = str_contains($key, 'login') || str_contains($key, 'auth') || str_contains($key, 'xmlrpc');
        if ($is_sensitive_key) {
            return [
                'allowed'     => false,
                'retry_after' => 30,
                'current'     => $limit + 1,
                'limit'       => $limit,
            ];
        }

        // For non-sensitive traffic under class load failure, permit benign single hit
        return [
            'allowed'     => true,
            'retry_after' => 0,
            'current'     => 1,
            'limit'       => $limit,
        ];
    }

    /**
     * Inspect current strike count without incrementing (read-only query).
     *
     * @param string $ip Client IP
     * @param int    $max_strikes Maximum warning strikes allowed before temporary ban
     * @return array{strike: int, max_strikes: int, is_terminal_ban: bool, remaining_strikes: int}
     */
    public static function get_warning_strike(string $ip, int $max_strikes = 4): array {
        $key = 'warning_strike:' . md5($ip);
        $transient_name = 'webcareproscan_rl_' . substr(md5($key), 0, 24);
        $data = get_transient($transient_name);
        $count = (is_array($data) && !empty($data['count'])) ? (int) $data['count'] : 0;
        $strike = min($max_strikes, $count);
        $remaining = max(0, $max_strikes - $strike);

        return [
            'strike'            => $strike,
            'max_strikes'       => $max_strikes,
            'is_terminal_ban'   => ($count >= $max_strikes),
            'remaining_strikes' => $remaining,
        ];
    }

    /**
     * Record and inspect strike count for progressive warnings (default: 4 strikes within 15 mins).
     * @param string $ip Client IP
     * @param int    $max_strikes Maximum warning strikes allowed before temporary ban
     * @param int    $window_seconds Strike decay window
     * @return array{strike: int, max_strikes: int, is_terminal_ban: bool, remaining_strikes: int}
     */
    public static function record_warning_strike(string $ip, int $max_strikes = 4, int $window_seconds = 900): array {
        $key = 'warning_strike:' . md5($ip);
        $res = self::check_rate_limit($key, $max_strikes, $window_seconds);
        $strike = min($max_strikes, (int) $res['current']);
        $remaining = max(0, $max_strikes - $strike);

        return [
            'strike'             => $strike,
            'max_strikes'        => $max_strikes,
            'is_terminal_ban'    => !$res['allowed'],
            'remaining_strikes'  => $remaining,
        ];
    }
}
