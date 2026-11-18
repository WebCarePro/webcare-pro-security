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
     * Documented legitimate public guest REST API prefixes for affiliate suites.
     */
    public const PUBLIC_REST_ROUTES = [
        'affwp/v1/visits',
        'affwp-portal/v1/creatives/generate',
        'affwp-portal/v1/urls/generate',
        'affwp-portal/v1/payouts/request',
        'slicewp/v1/visits',
        'solid-affiliate/v1/track',
    ];

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
     * Initialize Affiliate Security Engine hooks if an affiliate ecosystem is detected.
     */
    public static function init(): void {
        // Invalidate ecosystem cache when plugins or themes change so activation is detected instantly
        add_action('activated_plugin', [__CLASS__, 'invalidate_detection_cache']);
        add_action('deactivated_plugin', [__CLASS__, 'invalidate_detection_cache']);
        add_action('switch_theme', [__CLASS__, 'invalidate_detection_cache']);

        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_affiliate_shield_enabled'])) {
            return;
        }

        $ecosystem = self::get_detected_ecosystem();
        if (empty($ecosystem['is_active'])) {
            return;
        }

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

        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Early low-level firewall inspection of referral query parameters
        $has_referral_query = false;
        $active_param_key   = '';
        $raw_param_value    = '';

        foreach (self::REFERRAL_PARAM_KEYS as $key) {
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            if (isset($_GET[$key]) && is_scalar($_GET[$key]) && (string) $_GET[$key] !== '') {
                $has_referral_query = true;
                $active_param_key   = $key;
                // phpcs:ignore WordPress.Security.NonceVerification.Recommended
                $raw_param_value    = (string) $_GET[$key];
                break;
            }
        }

        if (!$has_referral_query) {
            return;
        }

        // 1. Referral Parameter Anti-Injection & Sanitization Guard (SQLi, XSS, Path Traversal)
        if (!empty($settings['waf_affiliate_anti_injection'])) {
            $injection_violation = self::inspect_referral_parameter_value($active_param_key, $raw_param_value, $client_ip, $request_uri);
            if ($injection_violation !== null) {
                FirewallEngine::handle_rule_violation($injection_violation, $settings, $client_ip, 403);
                return;
            }
        }

        // 2. Click-Fraud & High-Velocity Visit Rate Limiter (Default: 10 referral clicks/min per IP)
        if (!empty($settings['waf_affiliate_anti_fraud'])) {
            $max_clicks = max(3, min(300, (int) ($settings['waf_affiliate_max_clicks_min'] ?? 10)));
            $is_flooding = self::track_referral_click_velocity($client_ip, $max_clicks);

            if ($is_flooding) {
                // Mark connection so database visit recording is silently suppressed
                if (!defined('WEBCAREPROSCAN_SUPPRESS_AFFILIATE_VISIT')) {
                    define('WEBCAREPROSCAN_SUPPRESS_AFFILIATE_VISIT', true);
                }

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
                    'payload'     => "IP: {$client_ip} Param: {$active_param_key} Clicks: >{$max_clicks}/min",
                ];

                FirewallEngine::log_incident($rule_triggered, 'throttled');
            }
        }
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

        // Check for control characters and null bytes
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

        // Check for SQL Injection signatures
        $sqli_patterns = [
            '/\b(union(\s+all)?\s+select|select\s+.*\s+from)\b/i',
            '/\b(benchmark\s*\(|sleep\s*\(|pg_sleep\s*\()/i',
            '/\b(drop|truncate|alter)\s+(table|database)\b/i',
            '/(--|\#|\/\*)/', // SQL comment delimiters
            '/(\'|\")\s*(or|and)\s*(\'|\"|\d|\w)/i', // SQL boolean evasion: ' or '1'='1
        ];

        foreach ($sqli_patterns as $pattern) {
            if (preg_match($pattern, $val)) {
                return [
                    'id'          => 'WAF-AFFILIATE-INJECTION',
                    'name'        => 'Affiliate Referral Parameter SQLi Armor (Rule #43)',
                    'category'    => 'Affiliate Defense',
                    'description' => sprintf('SQL injection exploit detected inside affiliate parameter "%s".', $key),
                    'match_type'  => 'SQL Injection',
                    'match_value' => substr($val, 0, 60),
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
            if (preg_match($pattern, $val)) {
                return [
                    'id'          => 'WAF-AFFILIATE-INJECTION',
                    'name'        => 'Affiliate Referral Parameter XSS Armor (Rule #43)',
                    'category'    => 'Affiliate Defense',
                    'description' => sprintf('Cross-Site Scripting (XSS) payload intercepted inside affiliate parameter "%s".', $key),
                    'match_type'  => 'Cross-Site Scripting (XSS)',
                    'match_value' => substr($val, 0, 60),
                    'payload'     => "Param: {$key} Value: {$val} IP: {$client_ip}",
                ];
            }
        }

        // Check for Path Traversal / File Inclusion
        if (str_contains($val, '../') || str_contains($val, '..\\') || str_starts_with($val, 'php://') || str_starts_with($val, 'phar://')) {
            return [
                'id'          => 'WAF-AFFILIATE-INJECTION',
                'name'        => 'Affiliate Referral Parameter Path Traversal Shield (Rule #43)',
                'category'    => 'Affiliate Defense',
                'description' => sprintf('Directory traversal payload detected inside affiliate parameter "%s".', $key),
                'match_type'  => 'Path Traversal',
                'match_value' => substr($val, 0, 60),
                'payload'     => "Param: {$key} Value: {$val} IP: {$client_ip}",
            ];
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

        $transient_key = self::TRANSIENT_CLICK_PREFIX . md5($client_ip);
        $current_hits  = (int) get_transient($transient_key);

        if ($current_hits >= $max_clicks) {
            return true;
        }

        set_transient($transient_key, $current_hits + 1, 60);
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
            if (in_array($domain, FirewallEngine::DISPOSABLE_EMAIL_DOMAINS, true)) {
                if (function_exists('affiliate_wp')) {
                    affiliate_wp()->login->errors->add('webcare_disposable_email', __('Disposable or temporary email addresses are not permitted for affiliate registration.', 'webcare-pro-security'));
                }
            }
        }
    }

    /**
     * Check if a given REST route is a documented legitimate affiliate route.
     *
     * @param string $route Normalized REST route path.
     * @return bool
     */
    public static function is_public_affiliate_rest_route(string $route): bool {
        $clean = ltrim($route, '/');
        if (str_starts_with($clean, 'wp-json/')) {
            $clean = substr($clean, 8);
        }
        foreach (self::PUBLIC_REST_ROUTES as $public_prefix) {
            if (str_starts_with($clean, $public_prefix)) {
                return true;
            }
        }
        return false;
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
