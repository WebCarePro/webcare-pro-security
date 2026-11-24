<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall\Core;

use WebCareProScanner\Firewall\FirewallEngine;
use WebCareProScanner\System\SettingsManager;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Subnet Swarm Guard & Multi-Level Crawler Intelligence
 *
 * Implements bounded rolling counters across three distinct scopes:
 * 1. Individual IP (for direct enforcement)
 * 2. IPv4 /24 or IPv6 /48 (for nearby coordinated activity)
 * 3. Broader prefix / normalized crawler family (e.g. 114.119.0.0/16 PetalBot) for rate-limit intelligence ONLY.
 *
 * Non-Negotiable Invariants:
 * - NEVER auto-block broad prefixes (/16 or /24). Auto-blocking applies strictly to individual IPs.
 * - Strict Data-Model Separation: Ordinary public commercial crawler counters live in a completely
 *   separate namespace ('webcare_crawler_swarm_*') from sensitive-file recon counters ('webcare_recon_swarm_*').
 * - Presets for Commercial/SEO Crawlers (PetalBot, Bytespider, MJ12bot, DotBot, AhrefsBot, SemrushBot):
 *   - 'allow': Unrestricted crawl within server bandwidth.
 *   - 'throttle': 429 Retry-After: 120 (max 10 req/min), rule_id 'WAF-SUBNET-SWARM-THROTTLE'.
 *   - 'block': 403 Forbidden on matching crawler family, rule_id 'WAF-CRAWLER-POLICY-BLOCKED'.
 *
 * Author: Mir Alamin (WebCare Pro)
 * Senior Linux SysAdmin & WordPress Security Engineer
 *
 * @package WebCareProScanner\Firewall\Core
 */
final class SubnetSwarmGuard {

    public const POLICY_ALLOW    = 'allow';
    public const POLICY_THROTTLE = 'throttle';
    public const POLICY_BLOCK    = 'block';

    public const THROTTLE_RULE_ID = 'WAF-SUBNET-SWARM-THROTTLE';
    public const BLOCK_RULE_ID    = 'WAF-CRAWLER-POLICY-BLOCKED';

    /**
     * Recognized commercial and aggressive SEO crawler families with their known primary subnets.
     */
    private const CRAWLER_FAMILIES = [
        'petalbot' => [
            'tokens'  => ['petalbot'],
            'name'    => 'PetalBot',
            'subnets' => ['114.119.0.0/16'],
            'default_policy' => self::POLICY_THROTTLE,
        ],
        'bytespider' => [
            'tokens'  => ['bytespider'],
            'name'    => 'Bytespider',
            'subnets' => [],
            'default_policy' => self::POLICY_THROTTLE,
        ],
        'mj12bot' => [
            'tokens'  => ['mj12bot'],
            'name'    => 'MJ12bot',
            'subnets' => [],
            'default_policy' => self::POLICY_THROTTLE,
        ],
        'dotbot' => [
            'tokens'  => ['dotbot'],
            'name'    => 'DotBot',
            'subnets' => [],
            'default_policy' => self::POLICY_ALLOW,
        ],
        'ahrefsbot' => [
            'tokens'  => ['ahrefsbot'],
            'name'    => 'AhrefsBot',
            'subnets' => [],
            'default_policy' => self::POLICY_ALLOW,
        ],
        'semrushbot' => [
            'tokens'  => ['semrushbot', 'siteauditbot'],
            'name'    => 'SemrushBot',
            'subnets' => [],
            'default_policy' => self::POLICY_ALLOW,
        ],
    ];

    /**
     * Calculate network prefix key based on IP family (/24 for IPv4, /48 for IPv6).
     *
     * @param string $ip
     * @return string
     */
    public static function get_subnet_prefix(string $ip): string {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return 'invalid';
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $octets = explode('.', $ip);
            return count($octets) === 4 ? $octets[0] . '.' . $octets[1] . '.' . $octets[2] . '.0/24' : $ip;
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $expanded = inet_ntop((string) inet_pton($ip));
            if ($expanded === false) {
                return $ip;
            }
            // First 3 hextets correspond to /48
            $hextets = explode(':', $expanded);
            $p = array_slice($hextets, 0, 3);
            return implode(':', $p) . '::/48';
        }

        return $ip;
    }

    /**
     * Detect matching crawler family from User-Agent or known subnets.
     *
     * @param string $ip
     * @param string $user_agent
     * @return string|null Family key or null
     */
    public static function detect_crawler_family(string $ip, string $user_agent): ?string {
        $ua_lower = strtolower($user_agent);

        foreach (self::CRAWLER_FAMILIES as $family_key => $info) {
            foreach ($info['tokens'] as $token) {
                if (str_contains($ua_lower, $token)) {
                    return $family_key;
                }
            }
            // Check broad subnet match
            foreach ($info['subnets'] as $subnet) {
                if (FirewallEngine::ip_in_range($ip, $subnet)) {
                    return $family_key;
                }
            }
        }

        return null;
    }

    /**
     * Inspect crawler swarm activity against configured crawler policy.
     *
     * @param string $ip
     * @param string $user_agent
     * @param array<string, mixed> $settings
     * @return array{action: string, rule_id?: string, message?: string, retry_after?: int}|null
     */
    public static function inspect_crawler_swarm(string $ip, string $user_agent, array $settings = []): ?array {
        $family = self::detect_crawler_family($ip, $user_agent);
        if ($family === null) {
            return null;
        }

        $policy = self::get_crawler_policy($family, $settings);
        if ($policy === self::POLICY_ALLOW) {
            return null;
        }

        if ($policy === self::POLICY_BLOCK) {
            return [
                'action'   => 'block',
                'rule_id'  => self::BLOCK_RULE_ID,
                'message'  => sprintf('Commercial crawler %s blocked by policy.', self::CRAWLER_FAMILIES[$family]['name']),
            ];
        }

        if ($policy === self::POLICY_THROTTLE) {
            // Track bounded rolling counters across 3 scopes in crawler namespace:
            // 1. IP scope
            $ip_hits = self::increment_rolling_counter('crawler_ip', $ip, 60);

            // 2. Subnet /24 or /48 scope
            $subnet = self::get_subnet_prefix($ip);
            $subnet_hits = self::increment_rolling_counter('crawler_subnet', $subnet, 60);

            // 3. Broader crawler family scope
            $family_hits = self::increment_rolling_counter('crawler_family', $family, 60);

            // Throttle criteria: IP hits > 10/min OR Subnet hits > 60/min OR Family hits > 150/min
            if ($ip_hits > 10 || $subnet_hits > 60 || $family_hits > 150) {
                return [
                    'action'      => 'throttle',
                    'rule_id'     => self::THROTTLE_RULE_ID,
                    'message'     => sprintf('Commercial crawler %s rate limited (%d req/min in subnet).', self::CRAWLER_FAMILIES[$family]['name'], $subnet_hits),
                    'retry_after' => 120,
                ];
            }
        }

        return null;
    }

    /**
     * Track reconnaissance probes in a STRICTLY SEPARATE data-model namespace.
     * Ordinary public crawlers NEVER increment these counters.
     *
     * @param string $ip
     * @param string $target_type e.g. 'sensitive_file', 'webshell', 'env_probe'
     * @return array{ip_hits: int, subnet_hits: int}
     */
    public static function record_recon_probe(string $ip, string $target_type = 'recon'): array {
        $ip_hits = self::increment_rolling_counter('recon_ip', $ip, 60);
        $subnet = self::get_subnet_prefix($ip);
        $subnet_hits = self::increment_rolling_counter('recon_subnet', $subnet, 60);

        return [
            'ip_hits'     => $ip_hits,
            'subnet_hits' => $subnet_hits,
        ];
    }

    /**
     * Get configured policy for a crawler family.
     *
     * @param string $family
     * @param array<string, mixed> $settings
     * @return string 'allow'|'throttle'|'block'
     */
    public static function get_crawler_policy(string $family, array $settings = []): string {
        $setting_key = 'waf_crawler_policy_' . $family;
        $val = $settings[$setting_key] ?? null;

        if (in_array($val, [self::POLICY_ALLOW, self::POLICY_THROTTLE, self::POLICY_BLOCK], true)) {
            return (string) $val;
        }

        return self::CRAWLER_FAMILIES[$family]['default_policy'] ?? self::POLICY_ALLOW;
    }

    /**
     * Increment an in-memory/transient rolling counter with strict namespace isolation.
     *
     * Namespaces:
     * - 'crawler_ip', 'crawler_subnet', 'crawler_family'
     * - 'recon_ip', 'recon_subnet'
     *
     * @param string $namespace
     * @param string $key
     * @param int $ttl_seconds
     * @return int Current count after increment
     */
    public static function increment_rolling_counter(string $namespace, string $key, int $ttl_seconds = 60): int {
        $clean_key = 'wcps_swarm_' . $namespace . '_' . substr(hash('xxh128', $key), 0, 16);

        // Fast APCu path if available
        if (function_exists('apcu_inc')) {
            $success = false;
            $val = apcu_inc($clean_key, 1, $success);
            if ($success) {
                return (int) $val;
            }
            apcu_store($clean_key, 1, $ttl_seconds);
            return 1;
        }

        // WordPress transient fallback
        $val = (int) get_transient($clean_key);
        $val++;
        set_transient($clean_key, $val, $ttl_seconds);
        return $val;
    }

    /**
     * Clear counters for testing.
     *
     * @param string $namespace
     * @param string $key
     */
    public static function reset_counter_for_testing(string $namespace, string $key): void {
        $clean_key = 'wcps_swarm_' . $namespace . '_' . substr(hash('xxh128', $key), 0, 16);
        if (function_exists('apcu_delete')) {
            @apcu_delete($clean_key);
        }
        delete_transient($clean_key);
    }
}
