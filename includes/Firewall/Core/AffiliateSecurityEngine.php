<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall\Core;

use WebCareProScanner\Firewall\FirewallEngine;
use WebCareProScanner\System\SettingsManager;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Affiliate Ecosystem Shield & Anti-Fraud Armor (Rule #43).
 *
 * Super-smart, zero-overhead firewall defense designed specifically for
 * AffiliateWP (and all official add-ons), SliceWP, Solid Affiliate, Easy Affiliate,
 * Ultimate Affiliate Pro, YITH WooCommerce Affiliates, and affiliate-focused themes.
 *
 * CONDITIONAL ARCHITECTURE:
 * This engine dynamically detects if an affiliate plugin or theme is present.
 * If no affiliate ecosystem exists on the website, evaluation skips in O(1) time
 * with zero memory, CPU, or database overhead.
 *
 * DEFENSIVE CAPABILITIES:
 * 1. Referral Parameter Anti-Injection & Sanitization Guard (SQLi, XSS, Path Traversal in ?ref=, ?aff=, etc.)
 * 2. Click-Fraud & High-Velocity Visit Rate Limiting (Default: 10 referral clicks/min per IP)
 * 3. Silent Database Bloat Suppression (prevents millions of fake rows in affwp_visits)
 * 4. Direct Link Tracking & Referer Integrity Verification (AffiliateWP Addon)
 * 5. Affiliate Registration Anti-Spam Gate & Honeypot Protection
 * 6. Zero False-Positive Adapters for Affiliate Portal & REST API routes (affwp/v1, slicewp/v1, etc.)
 *
 * @package WebCareProScanner\Firewall\Core
 */
class AffiliateSecurityEngine {

    /**
     * Cache key for detected affiliate stack in transients.
     */
    public const TRANSIENT_AFFILIATE_STACK = 'webcareproscan_affiliate_detected_stack';

    /**
     * Transient prefix for sliding-window referral click tracking.
     */
    public const TRANSIENT_CLICK_PREFIX = 'webcareproscan_aff_clk_';

    /**
     * Known referral query parameters used across major affiliate suites.
     */
    public const REFERRAL_PARAM_KEYS = [
        'ref',             // AffiliateWP, standard referral parameter
        'affwp_ref',       // AffiliateWP fallback explicit param
        'aff',             // SliceWP, general affiliate param
        'slice',           // SliceWP alternative param
        'sld',             // Solid Affiliate default param
        'solid_aff',       // Solid Affiliate alternative param
        'ea',              // Easy Affiliate (MemberPress) default param
        'easy_affiliate',  // Easy Affiliate alternative param
        'yith_aff',        // YITH WooCommerce Affiliates param
        'yith_ref',        // YITH WooCommerce Affiliates alternative param
        'uap_aff',         // Ultimate Affiliate Pro param
        'iaff',            // Ultimate Affiliate Pro short param
        'affiliate',       // Generic affiliate param
        'affwp_campaign',  // AffiliateWP campaign tracking
        'affwp_slug',      // AffiliateWP custom slug tracking
    ];

    /**
     * Documented legitimate public guest REST API routes for affiliate suites mapped to allowed HTTP methods.
     */
    public const PUBLIC_REST_ROUTES = [
        'affwp/v1/visits'                    => ['POST'],
        'affwp-portal/v1/creatives/generate' => ['POST'],
        'affwp-portal/v1/urls/generate'      => ['POST'],
        'affwp-portal/v1/payouts/request'    => ['POST'],
        'slicewp/v1/visits'                  => ['POST'],
        'solid-affiliate/v1/track'           => ['POST'],
    ];

    /**
     * Allowed guest mutation methods for each documented affiliate REST route.
     * Maintained for backward compatibility.
     */
    public const PUBLIC_REST_ROUTE_METHODS = self::PUBLIC_REST_ROUTES;

    /**
     * Documented legitimate guest AJAX actions for affiliate suites.
     */
    public const PUBLIC_AJAX_ACTIONS = [
        'affwp_track_visit',
        'affwp_check_username',
        'affwp_generate_ref_url',
        'affwp_get_payout_methods',
        'affwp_record_click',
        'slicewp_track_visit',
        'sld_track_visit',
        'uap_track_visit',
        'yith_wc_af_track_visit',
    ];

    /**
     * Runtime static cache to avoid repeated checks within the same request.
     * @var array|null
     */
    private static ?array $detected_ecosystem = null;

    /**
     * Whether early firewall inspection has already processed the raw JSON request body.
     */
    private static bool $early_json_inspected = false;

    /**
     * Check whether early firewall inspection has processed a JSON body on the current request.
     */
    public static function is_early_json_inspected(): bool {
        return self::$early_json_inspected;
    }

    /**
     * Set early JSON inspection state (used by integration tests).
     */
    public static function set_early_json_inspected(bool $state): void {
        self::$early_json_inspected = $state;
    }

    /**
     * Invalidate ecosystem cache when plugins or themes change so activation is detected instantly.
     */
    public static function register_cache_invalidation_hooks(): void {
        add_action('activated_plugin', [__CLASS__, 'invalidate_detection_cache']);
        add_action('deactivated_plugin', [__CLASS__, 'invalidate_detection_cache']);
        add_action('switch_theme', [__CLASS__, 'invalidate_detection_cache']);
    }

    /**
     * Always register detection invalidation hooks, then attach affiliate runtime hooks when enabled and detected.
     */
    public static function init(): void {
        self::register_cache_invalidation_hooks();

        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_affiliate_shield_enabled'])) {
            return;
        }

        $ecosystem = self::get_detected_ecosystem();
        if (empty($ecosystem['is_active'])) {
            return;
        }

        // REST JSON bodies are parsed by WordPress after the early firewall inspection.
        // Inspect affiliate payloads immediately before the endpoint callback runs.
        add_filter('rest_pre_dispatch', [__CLASS__, 'inspect_rest_dispatch'], 9, 3);

        // Hook into AffiliateWP visit validation filter to silently suppress click floods and database bloat
        add_filter('affwp_tracking_is_valid_visit', [__CLASS__, 'filter_affwp_is_valid_visit'], 10, 2);

        // Hook into AffiliateWP direct link tracking validation (addon)
        add_filter('affwp_direct_link_tracking_is_valid_visit', [__CLASS__, 'filter_affwp_direct_link_visit'], 10, 2);

        // Hook into SliceWP visit validation filter
        add_filter('slicewp_is_valid_visit', [__CLASS__, 'filter_slicewp_is_valid_visit'], 10, 2);

        // Hook into AffiliateWP registration anti-spam validation
        add_action('affwp_process_register_form', [__CLASS__, 'validate_affwp_registration'], 5);
    }

    /**
     * Smart Detection: Check if any affiliate plugin or theme is present on the website.
     *
     * Scans active plugins, network plugins, installed classes, and active themes.
     * Cached in runtime memory and a 12-hour transient.
     *
     * @return array Array describing detection state, detected plugins, and themes.
     */
    public static function get_detected_ecosystem(): array {
        if (self::$detected_ecosystem !== null) {
            return self::$detected_ecosystem;
        }

        $cached = get_transient(self::TRANSIENT_AFFILIATE_STACK);
        if (is_array($cached) && isset($cached['is_active'])) {
            self::$detected_ecosystem = $cached;
            return self::$detected_ecosystem;
        }

        $detected_plugins = [];
        $detected_themes  = [];

        // 1. Check Active Plugins (Single site & Multisite network)
        $active_plugins = (array) get_option('active_plugins', []);
        if (is_multisite()) {
            $network_plugins = array_keys((array) get_site_option('active_sitewide_plugins', []));
            $active_plugins  = array_merge($active_plugins, $network_plugins);
        }

        $known_plugin_patterns = [
            'affiliate-wp/affiliate-wp.php'             => 'AffiliateWP Core',
            'affiliate-wp-direct-link-tracking'         => 'AffiliateWP Direct Link Tracking',
            'affiliate-wp-rest-api-extended'            => 'AffiliateWP REST API Extended',
            'affiliate-wp-affiliate-portal'             => 'AffiliateWP Affiliate Portal',
            'affiliate-wp-payouts-service'              => 'AffiliateWP Payouts Service',
            'affiliate-wp-recurring-referrals'          => 'AffiliateWP Recurring Referrals',
            'affiliate-wp-tiered-affiliate-rates'       => 'AffiliateWP Tiered Rates',
            'affiliate-wp-multi-tier-commissions'       => 'AffiliateWP Multi-Tier Commissions',
            'affiliate-wp-lifetime-commissions'         => 'AffiliateWP Lifetime Commissions',
            'affiliate-wp-custom-affiliate-slugs'       => 'AffiliateWP Custom Slugs',
            'slicewp/slicewp.php'                       => 'SliceWP',
            'solid-affiliate/solid-affiliate.php'       => 'Solid Affiliate',
            'easy-affiliate/easy-affiliate.php'         => 'Easy Affiliate',
            'indeed-affiliate-pro/indeed-affiliate-pro.php' => 'Ultimate Affiliate Pro',
            'yith-woocommerce-affiliates'               => 'YITH WooCommerce Affiliates',
            'coupon-affiliates/coupon-affiliates.php'   => 'Coupon Affiliates',
            'post-affiliate-pro'                        => 'Post Affiliate Pro',
            'thirstyaffiliates/thirstyaffiliates.php'   => 'ThirstyAffiliates',
            'pretty-link/pretty-link.php'               => 'Pretty Links',
        ];

        foreach ($active_plugins as $plugin_path) {
            $p_lower = strtolower((string) $plugin_path);
            foreach ($known_plugin_patterns as $pattern => $label) {
                if (str_contains($p_lower, strtolower($pattern))) {
                    $detected_plugins[$pattern] = $label;
                }
            }
            // Broad match for any bespoke or custom affiliate plugin
            if (!isset($detected_plugins[$plugin_path]) && str_contains($p_lower, 'affiliate')) {
                $dir_name = basename(dirname($plugin_path));
                $detected_plugins[$plugin_path] = ucwords(str_replace(['-', '_'], ' ', $dir_name !== '.' ? $dir_name : basename($plugin_path, '.php')));
            }
        }

        // 2. Check Defined Constants & Classes
        if (defined('AFFILIATEWP_VERSION') || class_exists('Affiliate_WP', false)) {
            $detected_plugins['affiliatewp_core'] = 'AffiliateWP Core (Runtime)';
        }
        if (defined('SLICEWP_VERSION') || class_exists('SliceWP', false)) {
            $detected_plugins['slicewp_core'] = 'SliceWP (Runtime)';
        }
        if (defined('SOLID_AFFILIATE_VERSION') || class_exists('SolidAffiliate', false)) {
            $detected_plugins['solid_affiliate_core'] = 'Solid Affiliate (Runtime)';
        }
        if (defined('EASY_AFFILIATE_VERSION')) {
            $detected_plugins['easy_affiliate_core'] = 'Easy Affiliate (Runtime)';
        }
        if (defined('UAP_PATH')) {
            $detected_plugins['uap_core'] = 'Ultimate Affiliate Pro (Runtime)';
        }
        if (defined('YITH_WCAF_VERSION')) {
            $detected_plugins['yith_wcaf_core'] = 'YITH WooCommerce Affiliates (Runtime)';
        }

        // 3. Check Installed & Active Themes (e.g. ReHub, CouponXL, Kupon)
        if (function_exists('wp_get_theme')) {
            $theme = wp_get_theme();
            if ($theme->exists()) {
                $theme_slug = strtolower((string) $theme->get_template());
                $child_slug = strtolower((string) $theme->get_stylesheet());
                $theme_name = strtolower((string) $theme->get('Name'));
                $theme_tags = array_map('strtolower', (array) $theme->get('Tags'));

                $affiliate_theme_keywords = ['affiliate', 'rehub', 'couponxl', 'kupon', 'affiliatetheme', 'bluchic', 'price-comparison'];
                foreach ($affiliate_theme_keywords as $kw) {
                    if (str_contains($theme_slug, $kw) || str_contains($child_slug, $kw) || str_contains($theme_name, $kw) || in_array($kw, $theme_tags, true)) {
                        $detected_themes[$theme_slug] = (string) $theme->get('Name');
                        break;
                    }
                }
            }
        }

        $is_active = (!empty($detected_plugins) || !empty($detected_themes));

        $result = [
            'is_active' => $is_active,
            'plugins'   => array_values($detected_plugins),
            'themes'    => array_values($detected_themes),
            'summary'   => $is_active
                ? sprintf('%d affiliate suite(s) and %d theme(s) active', count($detected_plugins), count($detected_themes))
                : 'No affiliate ecosystem detected',
        ];

        set_transient(self::TRANSIENT_AFFILIATE_STACK, $result, 12 * HOUR_IN_SECONDS);
        self::$detected_ecosystem = $result;

        return $result;
    }

    /**
     * Invalidate cached detection on plugin or theme changes.
     */
    public static function invalidate_detection_cache(): void {
        delete_transient(self::TRANSIENT_AFFILIATE_STACK);
        self::$detected_ecosystem = null;
    }

    /**
     * Evaluate incoming request against Rule #43 (Affiliate Ecosystem Shield & Anti-Fraud Armor).
     *
     * @param string $client_ip
     * @param string $request_uri
     * @param array $settings
     * @return void
     */
    public static function inspect_request(string $client_ip, string $request_uri, array $settings): void {
        // Fast O(1) conditional check: if master rule is disabled or no affiliate stack exists, exit immediately
        if (empty($settings['waf_affiliate_shield_enabled'])) {
            return;
        }

        $ecosystem = self::get_detected_ecosystem();
        if (empty($ecosystem['is_active'])) {
            return;
        }

        $content_type = isset($_SERVER['CONTENT_TYPE']) ? strtolower((string) $_SERVER['CONTENT_TYPE']) : '';
        $json_values  = [];
        if (str_contains($content_type, 'application/json') && (str_contains($request_uri, 'affwp') || str_contains($request_uri, 'slicewp') || str_contains($request_uri, 'solid-affiliate'))) {
            $raw_json = @file_get_contents('php://input');
            if (is_string($raw_json) && $raw_json !== '' && strlen($raw_json) <= 131072) {
                $decoded = json_decode($raw_json, true);
                if (is_array($decoded)) {
                    $json_values = $decoded;
                }
            }
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.NonceVerification.Missing -- Low-level firewall inspection before authentication.
        $found_params = self::collect_referral_parameters((array) $_GET, (array) $_POST, $json_values);

        if (empty($found_params)) {
            return;
        }

        self::$early_json_inspected = !empty($json_values);
        self::inspect_referral_values($found_params, $client_ip, $request_uri, $settings);
    }

    /**
     * Collect configured referral values from parsed request sources.
     * GET and POST values are unslashed here; REST JSON values have already been decoded by WordPress.
     *
     * @param array $get_values
     * @param array $post_values
     * @param array $json_values
     * @return array<string, mixed>
     */
    public static function collect_referral_parameters(array $get_values, array $post_values, array $json_values = []): array {
        $found_params = [];
        foreach (['GET' => $get_values, 'POST' => $post_values] as $source => $values) {
            foreach (self::REFERRAL_PARAM_KEYS as $key) {
                if (!isset($values[$key]) || $values[$key] === '') {
                    continue;
                }

                $found_params[$source . ':' . $key] = wp_unslash($values[$key]);
            }
        }

        if (!empty($json_values)) {
            $json_params = self::collect_json_referral_parameters($json_values);
            $found_params = array_merge($found_params, $json_params);
        }

        return $found_params;
    }

    /**
     * Walk a parsed JSON body for configured referral keys with bounded depth and node count.
     *
     * @param array $json_values
     * @return array<string, mixed>
     */
    private static function collect_json_referral_parameters(array $json_values): array {
        $found_params = [];
        $remaining    = 500;
        $known_keys   = array_fill_keys(self::REFERRAL_PARAM_KEYS, true);
        $walk         = static function (array $values, string $prefix, int $depth) use (&$walk, &$found_params, &$remaining, $known_keys): void {
            if ($depth > 8 || $remaining <= 0) {
                return;
            }

            foreach ($values as $key => $value) {
                if ($remaining <= 0) {
                    break;
                }
                --$remaining;
                $key_string = (string) $key;
                $path       = $prefix === '' ? $key_string : $prefix . '.' . $key_string;

                if (isset($known_keys[$key_string])) {
                    if ($value !== '') {
                        $found_params['JSON:' . $path] = $value;
                    }
                    continue;
                }

                if (is_array($value)) {
                    $walk($value, $path, $depth + 1);
                }
            }
        };

        $walk($json_values, '', 0);

        return $found_params;
    }

    /**
     * Inspect parsed affiliate REST JSON before a public endpoint can persist referral data.
     *
     * @param mixed $result
     * @param \WP_REST_Server $server
     * @param \WP_REST_Request $request
     * @return mixed
     */
    public static function inspect_rest_dispatch($result, $server, $request) {
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_affiliate_shield_enabled']) || empty(self::get_detected_ecosystem()['is_active'])) {
            return $result;
        }

        if (self::$early_json_inspected) {
            return $result;
        }

        if (!self::is_public_affiliate_rest_request((string) $request->get_route(), (string) $request->get_method())) {
            return $result;
        }

        $json_values = $request->get_json_params();
        if (!is_array($json_values)) {
            return $result;
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.NonceVerification.Missing -- Low-level firewall inspection before endpoint callbacks.
        $found_params = self::collect_referral_parameters((array) $_GET, (array) $_POST, $json_values);
        $json_params = array_filter(
            $found_params,
            static function ($key): bool {
                return str_starts_with((string) $key, 'JSON:');
            },
            ARRAY_FILTER_USE_KEY
        );
        if (empty($json_params)) {
            return $result;
        }

        $request_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '/';
        $client_ip   = FirewallEngine::get_client_ip();
        // Early request inspection already counts query/form referral values. Count JSON-only visits here.
        $has_non_json_params = count($found_params) > count($json_params);
        self::inspect_referral_values($json_params, $client_ip, $request_uri, $settings, !$has_non_json_params);

        return $result;
    }

    /**
     * Inspect collected referral parameters and apply click-flood suppression when requested.
     *
     * @param array<string, mixed> $found_params
     * @param string $client_ip
     * @param string $request_uri
     * @param array $settings
     * @param bool $track_click_velocity
     * @return void
     */
    private static function inspect_referral_values(array $found_params, string $client_ip, string $request_uri, array $settings, bool $track_click_velocity = true): void {

        // 1. Inspect EVERY present referral parameter (never break on first match)
        if (!empty($settings['waf_affiliate_anti_injection'])) {
            $injection_violation = self::find_referral_injection($found_params, $client_ip, $request_uri);
            if ($injection_violation !== null) {
                FirewallEngine::handle_rule_violation($injection_violation, $settings, $client_ip, 403);
                return;
            }
        }

        // 2. Click-Fraud & High-Velocity Visit Rate Limiter (Default: 10 referral clicks/min per IP)
        // Gated on waf_affiliate_shield_enabled (active whenever Rule #43 is enabled)
        if (!$track_click_velocity) {
            return;
        }

        $max_clicks  = max(3, min(300, (int) ($settings['waf_affiliate_max_clicks_min'] ?? 10)));
        $is_flooding = self::track_referral_click_velocity($client_ip, $max_clicks);

        if (self::suppress_visit_recording_if_flooding($is_flooding)) {
            $first_key = array_key_first($found_params);
            $rule_triggered = [
                'id'          => 'WAF-AFFILIATE-CLICK-FLOOD',
                'name'        => 'Affiliate Referral Click-Flood & Database Bloat Shield (Rule #43)',
                'category'    => 'Affiliate Defense',
                'description' => sprintf(
                    /* translators: 1: client IP address, 2: max clicks per minute */
                    __('High-velocity referral click flood from IP %1$s exceeded safety threshold (%2$d clicks/min). Suppressed database visit logging to prevent table bloat and click-fraud.', 'webcare-pro-security'),
                    $client_ip,
                    $max_clicks
                ),
                'match_type'  => 'Referral Velocity Limit',
                'match_value' => $client_ip,
                'payload'     => "IP: {$client_ip} Param: {$first_key} Clicks: >{$max_clicks}/min",
            ];

            FirewallEngine::log_incident($rule_triggered, 'throttled');
        }
    }

    /**
     * Return the first hostile value in a collected set of referral parameters.
     *
     * @param array<string, mixed> $found_params
     * @param string $client_ip
     * @param string $request_uri
     * @return array|null
     */
    public static function find_referral_injection(array $found_params, string $client_ip, string $request_uri): ?array {
        foreach ($found_params as $param_source => $raw_val) {
            $param_path = explode(':', (string) $param_source, 2)[1] ?? (string) $param_source;
            $last_dot   = strrpos($param_path, '.');
            $param_key  = $last_dot === false ? $param_path : substr($param_path, $last_dot + 1);
            if (is_array($raw_val)) {
                return [
                    'id'          => 'WAF-AFFILIATE-INJECTION',
                    'name'        => 'Affiliate Referral Array Injection Shield (Rule #43)',
                    'category'    => 'Affiliate Defense',
                    'description' => sprintf('Unexpected array payload supplied for scalar affiliate parameter "%s".', $param_key),
                    'match_type'  => 'Type Confusion / Array Injection',
                    'match_value' => $param_key,
                    'payload'     => "Param: {$param_source} (array) IP: {$client_ip}",
                ];
            }
            if (!is_scalar($raw_val)) {
                continue;
            }

            $violation = self::inspect_referral_parameter_value($param_key, (string) $raw_val, $client_ip, $request_uri);
            if ($violation !== null) {
                return $violation;
            }
        }

        return null;
    }

    /**
     * Set the request-scoped flag consumed by AffiliateWP and SliceWP visit filters.
     *
     * @param bool $is_flooding
     * @return bool True when visit logging is suppressed.
     */
    public static function suppress_visit_recording_if_flooding(bool $is_flooding): bool {
        if (!$is_flooding) {
            return false;
        }

        if (!defined('WEBCAREPROSCAN_SUPPRESS_AFFILIATE_VISIT')) {
            define('WEBCAREPROSCAN_SUPPRESS_AFFILIATE_VISIT', true);
        }

        return defined('WEBCAREPROSCAN_SUPPRESS_AFFILIATE_VISIT') && WEBCAREPROSCAN_SUPPRESS_AFFILIATE_VISIT;
    }

    /**
     * Inspect referral parameter for SQL Injection, XSS, Path Traversal, or control character payloads.
     *
     * @param string $key
     * @param string $val
     * @param string $client_ip
     * @param string $request_uri
     * @return array|null Violation rule array if hostile payload detected, null if clean.
     */
    public static function inspect_referral_parameter_value(string $key, string $val, string $client_ip, string $request_uri): ?array {
        // Exceedingly long affiliate parameter is an anomalous buffer/DoS vector
        if (strlen($val) > 128) {
            return [
                'id'          => 'WAF-AFFILIATE-INJECTION',
                'name'        => 'Affiliate Referral Parameter Buffer Overflow Shield (Rule #43)',
                'category'    => 'Affiliate Defense',
                'description' => sprintf('Anomalous referral parameter length (%d characters) rejected.', strlen($val)),
                'match_type'  => 'Buffer Overflow',
                'match_value' => substr($val, 0, 50),
                'payload'     => "Param: {$key} Length: " . strlen($val) . " IP: {$client_ip}",
            ];
        }

        // Check for control characters and null bytes in raw value
        if (preg_match('/[\0\r\n\t]/', $val)) {
            return [
                'id'          => 'WAF-AFFILIATE-INJECTION',
                'name'        => 'Affiliate Referral Parameter Poison Shield (Rule #43)',
                'category'    => 'Affiliate Defense',
                'description' => 'Disallowed control or null byte character inside affiliate referral parameter.',
                'match_type'  => 'Null Byte / Control Character',
                'match_value' => $key,
                'payload'     => "Param: {$key} IP: {$client_ip}",
            ];
        }

        // Multi-pass canonical decode before inspection (blocks %2527%2520UNION and null-byte smuggling)
        if (method_exists(FirewallEngine::class, 'normalize_inspect_value')) {
            $norm_val = FirewallEngine::normalize_inspect_value($val);
        } else {
            $norm_val = str_replace(["\0", "\r", "\n"], '', $val);
            for ($d = 0; $d < 3; $d++) {
                $decoded = rawurldecode($norm_val);
                if ($decoded === $norm_val) {
                    break;
                }
                $norm_val = str_replace(["\0", "\r", "\n"], '', $decoded);
            }
            if (str_contains($norm_val, '&') && str_contains($norm_val, ';')) {
                $html_decoded = html_entity_decode($norm_val, ENT_QUOTES | ENT_HTML5, 'UTF-8');
                if ($html_decoded !== $norm_val) {
                    $norm_val = str_replace(["\0", "\r", "\n"], '', $html_decoded);
                }
            }
        }

        // Check for SQL Injection signatures
        $sqli_patterns = [
            '/(?:^|[^a-z_]|[\d.eE])union(?:\s+|\/\*.*?\*\/|\()+(?:all\s+)?select(?:\b|\()/i',
            '/\b(union(\s+all)?\s+select|select\s+.*\s+from)\b/i',
            '/\b(benchmark\s*\(|sleep\s*\(|pg_sleep\s*\()/i',
            '/\b(drop|truncate|alter)\s+(table|database)\b/i',
            '/(--|\#|\/\*)/', // SQL comment delimiters
            '/(\'|\")\s*(or|and)\s*(\'|\"|\d|\w)/i', // SQL boolean evasion: ' or '1'='1
            '/\/\*![0-9]*\s*(?:select|union|sleep|benchmark)/i',
        ];

        foreach ($sqli_patterns as $pattern) {
            if (preg_match($pattern, $val) || preg_match($pattern, $norm_val)) {
                return [
                    'id'          => 'WAF-AFFILIATE-INJECTION',
                    'name'        => 'Affiliate Referral Parameter SQLi Armor (Rule #43)',
                    'category'    => 'Affiliate Defense',
                    'description' => sprintf('SQL injection exploit detected inside affiliate parameter "%s".', $key),
                    'match_type'  => 'SQL Injection',
                    'match_value' => substr($norm_val !== '' ? $norm_val : $val, 0, 60),
                    'payload'     => "Param: {$key} Value: {$val} IP: {$client_ip}",
                ];
            }
        }

        // Check for Cross-Site Scripting (XSS) signatures
        $xss_patterns = [
            '/<[^>]*script/i',
            '/javascript\s*:/i',
            '/data\s*:\s*text\/html/i',
            '/on(error|load|click|mouseover|submit)\s*=/i',
            '/<[a-z]+[^>]*>/i', // Raw HTML tags
        ];

        foreach ($xss_patterns as $pattern) {
            if (preg_match($pattern, $val) || preg_match($pattern, $norm_val)) {
                return [
                    'id'          => 'WAF-AFFILIATE-INJECTION',
                    'name'        => 'Affiliate Referral Parameter XSS Armor (Rule #43)',
                    'category'    => 'Affiliate Defense',
                    'description' => sprintf('Cross-Site Scripting (XSS) payload intercepted inside affiliate parameter "%s".', $key),
                    'match_type'  => 'Cross-Site Scripting (XSS)',
                    'match_value' => substr($norm_val !== '' ? $norm_val : $val, 0, 60),
                    'payload'     => "Param: {$key} Value: {$val} IP: {$client_ip}",
                ];
            }
        }

        // Check for Path Traversal / File Inclusion
        $traversal_targets = [$val, $norm_val];
        foreach ($traversal_targets as $t_val) {
            if (str_contains($t_val, '../') || str_contains($t_val, '..\\') || str_starts_with($t_val, 'php://') || str_starts_with($t_val, 'phar://')) {
                return [
                    'id'          => 'WAF-AFFILIATE-INJECTION',
                    'name'        => 'Affiliate Referral Parameter Path Traversal Shield (Rule #43)',
                    'category'    => 'Affiliate Defense',
                    'description' => sprintf('Directory traversal payload detected inside affiliate parameter "%s".', $key),
                    'match_type'  => 'Path Traversal',
                    'match_value' => substr($norm_val !== '' ? $norm_val : $val, 0, 60),
                    'payload'     => "Param: {$key} Value: {$val} IP: {$client_ip}",
                ];
            }
        }

        return null;
    }

    /**
     * Track client IP referral clicks in a sliding 60-second window.
     *
     * @param string $client_ip
     * @param int $max_clicks
     * @return bool True if client exceeded velocity limit, false if allowed.
     */
    public static function track_referral_click_velocity(string $client_ip, int $max_clicks): bool {
        if ($client_ip === '' || $client_ip === '127.0.0.1' || $client_ip === '::1') {
            return false;
        }

        if (class_exists('\\WebCareProScanner\\Firewall\\AdaptiveRateLimiter')) {
            $bucket = \WebCareProScanner\Firewall\AdaptiveRateLimiter::check_bucket_velocity(
                'affiliate_click',
                $client_ip,
                $max_clicks,
                60
            );
            return empty($bucket['allowed']);
        }

        $transient_key = self::TRANSIENT_CLICK_PREFIX . md5($client_ip);
        $current_hits  = (int) get_transient($transient_key);

        if ($current_hits >= $max_clicks) {
            return true;
        }

        set_transient($transient_key, $current_hits + 1, 60);
        return false;
    }

    /**
     * Check if client User-Agent matches known headless browser or CLI HTTP client signatures.
     *
     * @param string $ua
     * @return bool
     */
    public static function is_headless_or_scraping_agent(string $ua): bool {
        if ($ua === '') {
            return true;
        }
        $ua_lower = strtolower($ua);
        $headless_signatures = [
            'curl/',
            'python-requests',
            'python-urllib',
            'headlesschrome',
            'go-http-client',
            'phantomjs',
            'postmanruntime',
            'wget/',
            'aiohttp',
            'httpx/',
            'node-fetch',
            'axios/',
            'scrapy',
            'libwww-perl',
            'httpclient',
            'zgrab',
            'sqlmap',
            'nikto',
            'nmap',
        ];

        foreach ($headless_signatures as $sig) {
            if (str_contains($ua_lower, $sig)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Filter AffiliateWP visit logging (`affwp_tracking_is_valid_visit`).
     *
     * If click-flooding was detected for this connection, return false so AffiliateWP
     * skips the database INSERT, preventing database bloat and fake analytics.
     *
     * @param bool $is_valid
     * @param array|null $visit_data
     * @return bool
     */
    public static function filter_affwp_is_valid_visit($is_valid, $visit_data = null): bool {
        if (defined('WEBCAREPROSCAN_SUPPRESS_AFFILIATE_VISIT') && WEBCAREPROSCAN_SUPPRESS_AFFILIATE_VISIT) {
            return false;
        }

        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';
        if (self::is_headless_or_scraping_agent($ua)) {
            return false;
        }

        return (bool) $is_valid;
    }

    /**
     * Filter SliceWP visit logging (`slicewp_is_valid_visit`).
     *
     * @param bool $is_valid
     * @param mixed $data
     * @return bool
     */
    public static function filter_slicewp_is_valid_visit($is_valid, $data = null): bool {
        if (defined('WEBCAREPROSCAN_SUPPRESS_AFFILIATE_VISIT') && WEBCAREPROSCAN_SUPPRESS_AFFILIATE_VISIT) {
            return false;
        }

        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';
        if (self::is_headless_or_scraping_agent($ua)) {
            return false;
        }

        return (bool) $is_valid;
    }

    /**
     * Validate AffiliateWP Direct Link Tracking referer integrity.
     *
     * Drops attribution if a direct link visit arrives with an empty User-Agent
     * or known automated crawler signature.
     *
     * @param bool $is_valid
     * @param array $args
     * @return bool
     */
    public static function filter_affwp_direct_link_visit($is_valid, $args = []): bool {
        if (!$is_valid) {
            return false;
        }

        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_affiliate_direct_link_armor'])) {
            return (bool) $is_valid;
        }

        // Headless requests with no User-Agent or curl probes cannot be genuine browser referrals
        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? trim(sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT']))) : '';
        if ($ua === '' || str_starts_with(strtolower($ua), 'curl/') || str_starts_with(strtolower($ua), 'python-requests')) {
            return false;
        }

        return (bool) $is_valid;
    }

    /**
     * Anti-Spam Gate for AffiliateWP Registration (`affwp_process_register_form`).
     *
     * Checks for bot velocity, honeypots, and disposable throwaway email addresses.
     *
     * @param array $data
     * @return void
     */
    public static function validate_affwp_registration($data): void {
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_affiliate_reg_spam_protection'])) {
            return;
        }

        // Check for disposable throwaway email domains
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $email = isset($_POST['affwp_user_email']) ? sanitize_email(wp_unslash($_POST['affwp_user_email'])) : '';
        if (!empty($email) && str_contains($email, '@')) {
            $domain = strtolower(substr(strrchr($email, '@'), 1));
            if (in_array($domain, FirewallEngine::DISPOSABLE_EMAIL_DOMAINS, true) && function_exists('affiliate_wp')) {
                $affwp = affiliate_wp();
                $err_msg = __('Disposable or temporary email addresses are not permitted for affiliate registration.', 'webcare-pro-security');
                if (isset($affwp->register->errors) && is_object($affwp->register->errors) && method_exists($affwp->register->errors, 'add')) {
                    $affwp->register->errors->add('webcare_disposable_email', $err_msg);
                } elseif (isset($affwp->login->errors) && is_object($affwp->login->errors) && method_exists($affwp->login->errors, 'add')) {
                    $affwp->login->errors->add('webcare_disposable_email', $err_msg);
                }
            }
        }
    }

    /**
     * Check if a given REST route and HTTP method is a documented legitimate affiliate route.
     *
     * @param string $route Normalized REST route path.
     * @param string $method HTTP method (defaults to POST).
     * @return bool
     */
    public static function is_public_affiliate_rest_route(string $route, string $method = 'POST'): bool {
        $clean = trim(strtolower(ltrim($route, '/')), '/');
        if (str_starts_with($clean, 'wp-json/')) {
            $clean = substr($clean, 8);
        }
        $clean_method = strtoupper(trim($method));
        if (!isset(self::PUBLIC_REST_ROUTES[$clean])) {
            return false;
        }
        return in_array($clean_method, self::PUBLIC_REST_ROUTES[$clean], true);
    }

    /**
     * Check whether a REST route and HTTP method are explicitly public for an affiliate integration.
     *
     * @param string $route Normalized REST route path.
     * @param string $method HTTP method.
     * @return bool
     */
    public static function is_public_affiliate_rest_request(string $route, string $method): bool {
        return self::is_public_affiliate_rest_route($route, $method);
    }

    /**
     * Check if a given AJAX action is a documented legitimate affiliate action.
     *
     * @param string $action
     * @return bool
     */
    public static function is_public_affiliate_ajax_action(string $action): bool {
        return in_array($action, self::PUBLIC_AJAX_ACTIONS, true);
    }
}
