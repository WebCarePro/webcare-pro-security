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
            ];
        }

        return [
            'allowed'     => true,
            'retry_after' => 0,
            'current'     => $data['count'],
        ];
    }
}
