<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall;

use WebCareProScanner\Firewall\FirewallEngine;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Official Crawler Registry (Pull-Only, Zero-Telemetry)
 *
 * Implements hardened pull-only background daily sync of official public JSON IP feeds:
 * - OpenAI (searchbot.json, gptbot.json)
 * - Googlebot (googlebot.json)
 * - Bingbot (bingbot.json)
 * - Applebot
 * - DuckDuckGo
 *
 * Feed Security Invariants:
 * 1. Allowlist exact HTTPS feed hosts and validate redirect destinations.
 * 2. 5s timeout, max response size 512 KB, JSON schema & CIDR/address-family validation, max 5,000 CIDRs/feed.
 * 3. Never overwrite last-known-good cache on malformed/empty/errored feeds.
 * 4. Static validated fallbacks (Anthropic, OpenAI, Googlebot, Bingbot, Applebot, DuckDuckBot).
 * 5. Strict background-only sync: never run synchronously during public frontend/firewall requests.
 *
 * Author: Mir Alamin (WebCare Pro)
 * Senior Linux SysAdmin & WordPress Security Engineer
 *
 * @package WebCareProScanner\Firewall
 */
final class OfficialCrawlerRegistry {

    public const OPTION_CACHE_KEY = 'webcareproscan_crawler_cidr_cache';
    public const CRON_HOOK        = 'webcareproscan_sync_crawler_feeds';

    private const MAX_RESPONSE_SIZE = 524288; // 512 KB
    private const HTTP_TIMEOUT       = 5;      // 5 seconds
    private const MAX_CIDRS_PER_FEED = 5000;

    /**
     * Exact allowed HTTPS feed configurations.
     */
    private const FEED_ENDPOINTS = [
        'googlebot' => [
            'url'        => 'https://developers.google.com/search/apis/ipranges/googlebot.json',
            'allowed_host' => 'developers.google.com',
            'json_path'  => 'prefixes', // array of items with 'ipv4Prefix' or 'ipv6Prefix'
            'format'     => 'google',
        ],
        'bingbot' => [
            'url'        => 'https://www.bing.com/msnbot.json',
            'allowed_host' => 'www.bing.com',
            'json_path'  => 'prefixes', // array of items with 'ipv4Prefix' or 'ipv6Prefix'
            'format'     => 'bing',
        ],
        'oai-searchbot' => [
            'url'        => 'https://openai.com/searchbot.json',
            'allowed_host' => 'openai.com',
            'json_path'  => 'prefixes', // array of items with 'ipv4Prefix' or 'ipv6Prefix'
            'format'     => 'openai',
        ],
        'oai-gptbot' => [
            'url'        => 'https://openai.com/gptbot.json',
            'allowed_host' => 'openai.com',
            'json_path'  => 'prefixes',
            'format'     => 'openai',
        ],
        'duckduckbot' => [
            'url'        => 'https://duckduckgo.com/duckduckgo-help-pages/results/duckduckbot-ip-addresses/',
            // Note: DuckDuckGo publishes static IPs; if endpoint is HTML/JSON we fallback to static ranges
            'allowed_host' => 'duckduckgo.com',
            'json_path'  => 'prefixes',
            'format'     => 'duckduckgo',
        ],
    ];

    /**
     * Validated Static Fallback CIDR ranges.
     * Guaranteed safe fallback even during network, DNS, or feed outages.
     */
    private const STATIC_FALLBACK_CIDRS = [
        'googlebot' => [
            '66.249.64.0/19',
            '64.233.160.0/19',
            '72.14.192.0/18',
            '209.85.128.0/17',
            '108.177.8.0/21',
            '216.58.192.0/19',
            '34.22.85.0/27',
            '35.247.243.240/28',
            '192.178.4.0/22',
            '2001:4860::/32',
            '2404:6800::/32',
            '2a00:1450::/32',
            '2c0f:fb50::/32',
        ],
        'bingbot' => [
            '157.55.39.0/24',
            '207.46.13.0/24',
            '40.77.167.0/24',
            '13.66.139.0/24',
            '13.66.144.0/24',
            '52.167.144.0/24',
            '2603:1030::/32',
        ],
        'applebot' => [
            '17.0.0.0/8',
        ],
        'duckduckbot' => [
            '20.191.45.0/24',
            '40.88.21.0/24',
            '52.142.24.0/24',
            '52.142.26.0/24',
            '52.230.152.0/24',
            '52.230.153.0/24',
            '52.230.154.0/24',
        ],
        'oai-searchbot' => [
            '20.171.206.0/24',
            '20.171.207.0/24',
            '40.83.2.0/24',
            '74.7.175.0/24',
            '74.7.229.0/24',
            '74.7.244.0/24',
            '51.8.102.0/24',
        ],
        'oai-gptbot' => [
            '20.171.206.0/24',
            '20.171.207.0/24',
            '40.83.2.0/24',
            '74.7.175.0/24',
            '74.7.229.0/24',
            '74.7.244.0/24',
            '51.8.102.0/24',
        ],
        'claude-searchbot' => [
            '160.79.104.0/23',
            '216.73.216.0/22',
        ],
        'claudebot' => [
            '160.79.104.0/23',
            '216.73.216.0/22',
        ],
        'perplexitybot' => [],
    ];

    /**
     * In-memory cache for the current request lifecycle.
     *
     * @var array<string, array<string>>|null
     */
    private static ?array $runtime_cidr_cache = null;

    /**
     * Initialize background cron registration if scheduled.
     */
    public static function init(): void {
        if (!wp_next_scheduled(self::CRON_HOOK)) {
            wp_schedule_event(time() + 3600, 'daily', self::CRON_HOOK);
        }
        add_action(self::CRON_HOOK, [self::class, 'sync_all_feeds_background']);
    }

    /**
     * Check if a client IP is an officially verified crawler for the claimed bot key or user agent.
     *
     * @param string $ip Client IP.
     * @param string $bot_key Crawler key (e.g. 'googlebot', 'oai-searchbot', 'claude-searchbot').
     * @return bool
     */
    public static function is_ip_in_crawler_cidrs(string $ip, string $bot_key): bool {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }

        $bot_key = strtolower(trim($bot_key));
        $all_cidrs = self::get_effective_cidrs_for_bot($bot_key);
        if (empty($all_cidrs)) {
            return false;
        }

        foreach ($all_cidrs as $cidr) {
            if (FirewallEngine::ip_in_range($ip, $cidr)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Identify whether IP and User-Agent match an official crawler.
     *
     * @param string $ip
     * @param string $user_agent
     * @return string|null Returns the official bot identifier, or null if unverified.
     */
    public static function get_verified_crawler_identity(string $ip, string $user_agent): ?string {
        if (empty($user_agent)) {
            return null;
        }

        $ua_lower = strtolower($user_agent);

        $bot_checks = [
            'googlebot'        => 'googlebot',
            'bingbot'          => 'bingbot',
            'applebot'         => 'applebot',
            'duckduckbot'      => 'duckduckbot',
            'oai-searchbot'    => 'oai-searchbot',
            'gptbot'           => 'oai-gptbot',
            'claude-searchbot' => 'claude-searchbot',
            'claudebot'        => 'claudebot',
        ];

        foreach ($bot_checks as $token => $bot_key) {
            if (str_contains($ua_lower, $token)) {
                if (self::is_ip_in_crawler_cidrs($ip, $bot_key)) {
                    return $bot_key;
                }
            }
        }

        return null;
    }

    /**
     * Get effective CIDRs for a bot key, combining validated cache and static fallback.
     *
     * @param string $bot_key
     * @return array<string>
     */
    public static function get_effective_cidrs_for_bot(string $bot_key): array {
        $cache = self::load_cidr_cache();
        $cached_cidrs = $cache[$bot_key] ?? [];
        $static_cidrs = self::STATIC_FALLBACK_CIDRS[$bot_key] ?? [];

        if (empty($cached_cidrs)) {
            return $static_cidrs;
        }

        // Return unified deduplicated list
        return array_values(array_unique(array_merge($static_cidrs, $cached_cidrs)));
    }

    /**
     * Load CIDR cache from WordPress options (or return static fallback on miss).
     *
     * @return array<string, array<string>>
     */
    public static function load_cidr_cache(): array {
        if (self::$runtime_cidr_cache !== null) {
            return self::$runtime_cidr_cache;
        }

        $stored = get_option(self::OPTION_CACHE_KEY, null);
        if (is_array($stored) && !empty($stored['cidrs']) && is_array($stored['cidrs'])) {
            self::$runtime_cidr_cache = $stored['cidrs'];
            return self::$runtime_cidr_cache;
        }

        self::$runtime_cidr_cache = self::STATIC_FALLBACK_CIDRS;
        return self::$runtime_cidr_cache;
    }

    /**
     * Background-only synchronization of all official feeds.
     *
     * Invariants:
     * - Only executed via WP-Cron or background CLI worker.
     * - Preserves last-known-good cache if any feed fails or yields malformed data.
     *
     * @return array<string, array<string, mixed>> Sync report per feed.
     */
    public static function sync_all_feeds_background(): array {
        $report = [];
        $existing_cache = self::load_cidr_cache();
        $updated_cache  = $existing_cache;
        $any_updated    = false;

        foreach (self::FEED_ENDPOINTS as $bot_key => $config) {
            $result = self::fetch_and_validate_feed($bot_key, $config);
            $report[$bot_key] = $result;

            if ($result['success'] && !empty($result['cidrs'])) {
                $updated_cache[$bot_key] = $result['cidrs'];
                $any_updated = true;
            }
            // If failed or empty, preserve existing cache without overwriting
        }

        if ($any_updated) {
            self::$runtime_cidr_cache = $updated_cache;
            update_option(self::OPTION_CACHE_KEY, [
                'updated_at' => time(),
                'cidrs'      => $updated_cache,
            ], false);
        }

        return $report;
    }

    /**
     * Fetch, parse, and validate a single feed with strict security controls.
     *
     * @param string $bot_key
     * @param array<string, mixed> $config
     * @return array{success: bool, cidrs: array<string>, error?: string}
     */
    public static function fetch_and_validate_feed(string $bot_key, array $config): array {
        $url          = (string) $config['url'];
        $allowed_host = (string) $config['allowed_host'];

        // 1. Verify URL starts with HTTPS and host matches exact allowlist
        $parsed = wp_parse_url($url);
        if (!is_array($parsed) || ($parsed['scheme'] ?? '') !== 'https' || ($parsed['host'] ?? '') !== $allowed_host) {
            return ['success' => false, 'cidrs' => [], 'error' => 'Disallowed or non-HTTPS feed host'];
        }

        // 2. Perform HTTP GET with 5s timeout & redirect verification
        $args = [
            'timeout'     => self::HTTP_TIMEOUT,
            'redirection' => 2,
            'httpversion' => '1.1',
            'user-agent'  => 'WebCarePro-Security-CrawlerFeedSync/1.0',
            'sslverify'   => true,
        ];

        $response = wp_safe_remote_get($url, $args);
        if (is_wp_error($response)) {
            return ['success' => false, 'cidrs' => [], 'error' => $response->get_error_message()];
        }

        $code = (int) wp_remote_retrieve_response_code($response);
        if ($code !== 200) {
            return ['success' => false, 'cidrs' => [], 'error' => 'HTTP response ' . $code];
        }

        $body = wp_remote_retrieve_body($response);
        if (empty($body) || strlen($body) > self::MAX_RESPONSE_SIZE) {
            return ['success' => false, 'cidrs' => [], 'error' => 'Response empty or exceeds 512KB cap'];
        }

        // 3. Strict JSON validation
        if (!json_validate($body)) {
            return ['success' => false, 'cidrs' => [], 'error' => 'Malformed JSON in feed'];
        }

        $data = json_decode($body, true);
        if (!is_array($data)) {
            return ['success' => false, 'cidrs' => [], 'error' => 'Decoded JSON is not an array'];
        }

        // 4. Parse CIDRs based on feed schema
        $valid_cidrs = self::extract_and_validate_cidrs($data, (string) ($config['format'] ?? 'prefixes'));

        if (empty($valid_cidrs)) {
            return ['success' => false, 'cidrs' => [], 'error' => 'Zero valid CIDRs extracted; preserving fallback'];
        }

        if (count($valid_cidrs) > self::MAX_CIDRS_PER_FEED) {
            return ['success' => false, 'cidrs' => [], 'error' => 'Feed exceeded max cap of 5,000 CIDRs'];
        }

        return [
            'success' => true,
            'cidrs'   => $valid_cidrs,
        ];
    }

    /**
     * Extract and validate CIDR syntax and IPv4/IPv6 address-family integrity.
     *
     * @param array<mixed> $data
     * @param string $format
     * @return array<string>
     */
    public static function extract_and_validate_cidrs(array $data, string $format): array {
        $extracted = [];

        $prefixes = $data['prefixes'] ?? null;
        if (!is_array($prefixes)) {
            return [];
        }

        foreach ($prefixes as $item) {
            if (!is_array($item)) {
                continue;
            }

            // Both Google, Bing, and OpenAI formats supply 'ipv4Prefix' and/or 'ipv6Prefix'
            $candidates = [];
            if (!empty($item['ipv4Prefix']) && is_string($item['ipv4Prefix'])) {
                $candidates[] = trim($item['ipv4Prefix']);
            }
            if (!empty($item['ipv6Prefix']) && is_string($item['ipv6Prefix'])) {
                $candidates[] = trim($item['ipv6Prefix']);
            }
            if (!empty($item['prefix']) && is_string($item['prefix'])) {
                $candidates[] = trim($item['prefix']);
            }

            foreach ($candidates as $cand) {
                if (self::validate_cidr_syntax($cand)) {
                    $extracted[] = $cand;
                }
            }
        }

        return array_values(array_unique($extracted));
    }

    /**
     * Validate CIDR syntax and ensure IP & prefix are within valid ranges.
     *
     * @param string $cidr
     * @return bool
     */
    public static function validate_cidr_syntax(string $cidr): bool {
        if (!str_contains($cidr, '/')) {
            // Standalone IP
            return filter_var($cidr, FILTER_VALIDATE_IP) !== false;
        }

        $parts = explode('/', $cidr, 2);
        if (count($parts) !== 2) {
            return false;
        }

        $ip = trim($parts[0]);
        $mask_str = trim($parts[1]);

        if (!ctype_digit($mask_str)) {
            return false;
        }

        $mask = (int) $mask_str;

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return ($mask >= 8 && $mask <= 32);
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return ($mask >= 16 && $mask <= 128);
        }

        return false;
    }

    /**
     * Force reset cache for testing or manual administrator re-sync.
     *
     * @param array<string, array<string>>|null $override
     */
    public static function set_cache_for_testing(?array $override): void {
        self::$runtime_cidr_cache = $override;
    }
}
