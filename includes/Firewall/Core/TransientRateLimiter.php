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
     * @param string $key Identifier for the rate limit bucket.
     * @param int    $limit Max requests allowed within window.
     * @param int    $window_seconds Window duration in seconds.
     * @return array{allowed: bool, retry_after: int, current: int}
     */
    public static function check_rate_limit(string $key, int $limit, int $window_seconds): array {
        $transient_name = 'webcareproscan_rl_' . substr(md5($key), 0, 24);
        $data = get_transient($transient_name);
        $now = time();

        if ($data === false || !is_array($data) || empty($data['reset'])) {
            $data = [
                'count' => 1,
                'reset' => $now + $window_seconds,
            ];
            set_transient($transient_name, $data, $window_seconds);
            return [
                'allowed'     => true,
                'retry_after' => 0,
                'current'     => 1,
                'limit'       => $limit,
            ];
        }

        if ($now > $data['reset']) {
            $data = [
                'count' => 1,
                'reset' => $now + $window_seconds,
            ];
            set_transient($transient_name, $data, $window_seconds);
            return [
                'allowed'     => true,
                'retry_after' => 0,
                'current'     => 1,
                'limit'       => $limit,
            ];
        }

        $data['count'] = (int) $data['count'] + 1;
        $remaining_ttl = max(1, $data['reset'] - $now);
        set_transient($transient_name, $data, $remaining_ttl);

        if ($data['count'] > $limit) {
            return [
                'allowed'     => false,
                'retry_after' => $remaining_ttl,
                'current'     => $data['count'],
                'limit'       => $limit,
            ];
        }

        return [
            'allowed'     => true,
            'retry_after' => 0,
            'current'     => $data['count'],
            'limit'       => $limit,
        ];
    }

    /**
     * Record and inspect strike count for progressive warnings (default: 4 strikes within 15 mins).
     *
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
