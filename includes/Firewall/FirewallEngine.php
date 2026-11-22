<?php
namespace WebCareProScanner\Firewall;

use WebCareProScanner\System\SettingsManager;
use WebCareProScanner\Firewall\Core\ClientIpResolver;
use WebCareProScanner\Firewall\Core\CommerceSessionGuard;
use WebCareProScanner\Firewall\Core\ExploitSignatureEngine;
use WebCareProScanner\Firewall\Core\RaspPrivilegeGuard;
use WebCareProScanner\Firewall\Core\CommerceVelocityGuard;
use WebCareProScanner\Firewall\Core\AffiliateSecurityEngine;

if (!defined('ABSPATH')) {
    exit;
}

class FirewallEngine {
    public const OPTION_BLOCKED_IPS_META = 'webcareproscan_blocked_ips_meta';
    public static $real_ip = null;
    public static $connecting_peer_ip = null;
    public static $detected_environment = null;
    public static $last_incident_id = null;
    public static $last_ref_code = null;
    public static array $wc_session_cache = [];

    /**
     * Generate a short, unambiguous Customer Support Reference Code (#WEBCARE-XXXX).
     */
    public static function generate_ref_code(): string {
        return Core\ViolationResponder::generate_ref_code();
    }

    /**
     * Bootstrap the Firewall
     */
    public static function init() {
        // Record raw connecting peer IP before any normalization occurs
        if (!empty($_SERVER['REMOTE_ADDR']) && self::$connecting_peer_ip === null) {
            self::$connecting_peer_ip = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR']));
        }

        // Normalize $_SERVER['REMOTE_ADDR'] if incoming request connects via a verified trusted reverse proxy (e.g. Cloudflare)
        self::normalize_server_remote_addr();

        // Initialize Threat Intelligence Service
        ThreatIntelService::init();

        // Initialize Bot Recon Defense & AI Scraper Shield
        BotReconDefense::init();

        // Initialize Anti-Automation Honey-Token Traps & Phantom Decoy Grid
        if (class_exists('\\WebCareProScanner\\Firewall\\HoneyTokenEngine')) {
            HoneyTokenEngine::init();
        }

        // Run early at plugins_loaded priority 0 via RequestPipeline orchestrator
        if (class_exists('\\WebCareProScanner\\Firewall\\Core\\RequestPipeline')) {
            add_action('plugins_loaded', ['\\WebCareProScanner\\Firewall\\Core\\RequestPipeline', 'process_incoming_request'], 0);
        } else {
            add_action('plugins_loaded', [__CLASS__, 'inspect_incoming_request'], 0);
        }

        // Protect XML-RPC early if enabled
        add_action('init', [__CLASS__, 'check_xmlrpc_guard'], 0);

        // Flush Preload Micro-WAF custom rule ban intents queued prior to WordPress boot
        add_action('init', [__CLASS__, 'flush_preload_ban_queue'], 5);

        // Synchronize and rotate Preload Auth HMAC Cookie for Pre-Boot WAF
        add_action('init', [__CLASS__, 'sync_preload_auth_cookie'], 1);
        add_action('wp_login', [__CLASS__, 'on_user_login_preload_auth'], 10, 2);
        add_action('wp_logout', [__CLASS__, 'clear_preload_auth_cookie']);
        add_action('clear_auth_cookie', [__CLASS__, 'clear_preload_auth_cookie']);
        add_action('woocommerce_cleanup_sessions', [__CLASS__, 'invalidate_woocommerce_session_cache']);

        // Smart 404 Scanner Rate Limiter & Reconnaissance Shield (Priority 999: Allow redirection plugins & template logic to process first)
        add_action('template_redirect', [__CLASS__, 'track_404_request'], 999);

        // Real-Time Malicious File Upload Interceptor
        add_filter('wp_handle_upload_prefilter', [__CLASS__, 'inspect_uploaded_file'], 1);

        // Disallow phpMyAdmin & File Manager Plugin Installations (Admin-ajax, REST API, & WP Upgrader)
        add_filter('upgrader_pre_install', [__CLASS__, 'prevent_prohibited_plugin_install'], 10, 2);
        add_filter('upgrader_source_selection', [__CLASS__, 'inspect_unpacked_plugin_source'], 1, 4);
        add_filter('plugins_api_result', [__CLASS__, 'filter_prohibited_plugin_api'], 10, 3);

        // Generic Login Error Masking (prevent revealing valid usernames)
        add_filter('login_errors', [__CLASS__, 'mask_login_errors'], 999);

        // Prevent Registering 'admin' or Prohibited Usernames
        add_filter('validate_username', [__CLASS__, 'validate_registration_username'], 10, 2);
        add_filter('registration_errors', [__CLASS__, 'filter_registration_errors'], 10, 3);

        // Immediately Block IP of Users Trying to Sign in as Forbidden Usernames
        add_filter('authenticate', [__CLASS__, 'check_forbidden_username_login'], 20, 3);

        // Enforce Strong Passwords & Check Leaked/Pwned Passwords on Password Change/Reset
        add_action('user_profile_update_errors', [__CLASS__, 'validate_user_password_policy'], 10, 3);
        add_action('validate_password_reset', [__CLASS__, 'validate_reset_password_policy'], 10, 2);

        // Rule #29: REST API User Enumeration Interceptor
        add_filter('rest_authentication_errors', [__CLASS__, 'check_rest_user_enumeration'], 20);

        // Rule #30: Author Permalink Query Suppression (?author=N)
        add_action('template_redirect', [__CLASS__, 'check_author_scan_suppression'], 0);

        // Rule #37: Guest REST API Mutation Guard
        add_filter('rest_pre_dispatch', [__CLASS__, 'inspect_guest_rest_dispatch'], 10, 3);

        // Rule #31: Lost-Password Reset Burst Flooding Guard
        add_action('login_form_lostpassword', [__CLASS__, 'check_lostpassword_flood'], 0);
        add_action('lostpassword_post', [__CLASS__, 'check_lostpassword_submission'], 0);

        // Context-Adaptive Firewall (CAF 2.0): Only register WooCommerce firewall hooks when WooCommerce is active
        $has_woocommerce = class_exists('\\WebCareProScanner\\Firewall\\CAF\\AdaptiveFirewallAdvisor')
            ? \WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor::has_ecosystem('woocommerce')
            : (class_exists('WooCommerce') || in_array('woocommerce/woocommerce.php', (array) get_option('active_plugins', []), true));

        if ($has_woocommerce) {
            // Rule #38: WooCommerce Carding Attack & Checkout Velocity Shield
            add_action('woocommerce_checkout_process', [__CLASS__, 'inspect_woo_checkout_attempt'], 0);
            add_action('woocommerce_after_checkout_validation', [__CLASS__, 'handle_woo_checkout_validation'], 999, 2);
            add_action('woocommerce_order_status_failed', [__CLASS__, 'handle_woo_payment_failure'], 10, 1);

            // Rule #39: WooCommerce Coupon Enumeration & Brute-Force Shield
            add_action('woocommerce_applied_coupon', [__CLASS__, 'handle_woo_coupon_success'], 10, 1);
            add_filter('woocommerce_coupon_error', [__CLASS__, 'handle_woo_coupon_error'], 999, 3);
            add_filter('rest_request_after_callbacks', [__CLASS__, 'handle_woo_store_api_coupon_response'], 10, 3);

            // Rule #40: WooCommerce Fake Customer Registration & Bot Shield
            add_filter('woocommerce_registration_errors', [__CLASS__, 'validate_woo_customer_registration'], 10, 3);
            add_action('woocommerce_created_customer', [__CLASS__, 'handle_woo_customer_created'], 10, 3);

            // Rule #41: WooCommerce Cart Flooding & Denial of Inventory (DoI) Defense
            add_filter('woocommerce_add_to_cart_validation', [__CLASS__, 'validate_woo_add_to_cart'], 10, 5);

            // Rule #42: WooCommerce Catalog & Price Scraping Mitigation
            add_action('template_redirect', [__CLASS__, 'inspect_woo_catalog_scraping'], 1);
        }

        // Always register affiliate cache invalidation hooks so newly activated affiliate plugins are detected immediately
        if (class_exists(AffiliateSecurityEngine::class)) {
            AffiliateSecurityEngine::register_cache_invalidation_hooks();
            if (!empty(AffiliateSecurityEngine::get_detected_ecosystem()['is_active'])) {
                AffiliateSecurityEngine::init();
            }
        }

        // Rule #44: Runtime Privilege Escalation Guard (In-Memory RASP Hook Firewall)
        add_filter('pre_update_option', [__CLASS__, 'rasp_guard_critical_options'], 1, 3);
        add_action('set_user_role', [__CLASS__, 'rasp_guard_user_role_assignment'], 1, 3);
        add_action('add_user_role', [__CLASS__, 'rasp_guard_user_role_added'], 1, 2);
        add_action('remove_user_role', [__CLASS__, 'rasp_guard_user_role_removed'], 1, 2);
        add_action('user_register', [__CLASS__, 'rasp_guard_user_registration'], 1, 1);
        add_filter('update_user_metadata', [__CLASS__, 'rasp_guard_user_metadata_injection'], 1, 5);
        add_filter('add_user_metadata', [__CLASS__, 'rasp_guard_user_metadata_injection'], 1, 5);
        add_filter('delete_user_metadata', [__CLASS__, 'rasp_guard_user_metadata_deletion'], 1, 5);
        add_action('wp_create_application_password', [__CLASS__, 'telemetry_on_application_password_created'], 10, 4);
    }

    /**
     * Normalize $_SERVER['REMOTE_ADDR'] when connecting behind verified trusted reverse proxies (e.g. Cloudflare).
     *
     * Resolves the real client IP from CF-Connecting-IP or X-Forwarded-For if and only if
     * the incoming REMOTE_ADDR matches a verified trusted proxy CIDR (e.g. Cloudflare Anycast edge nodes).
     * This ensures WordPress core (e.g. WP_Session_Tokens, comment logs) and coexisting plugins record
     * the real visitor IP instead of Cloudflare internal proxy node IPs on origin servers lacking mod_remoteip.
     *
     * @return void
     */
    public static function normalize_server_remote_addr(): void {
        ClientIpResolver::normalize_server_remote_addr();
    }

    /**
     * Resolve Real Client IP Address with Strict Trusted Proxy Verification.
     *
     * Strictly verifies REMOTE_ADDR against Cloudflare and configured trusted proxies.
     * If the direct connecting peer is untrusted, forwarding headers (CF-Connecting-IP,
     * X-Forwarded-For) are completely ignored to prevent IP spoofing of firewalls and allowlists.
     *
     * @return string
     */
    public static function get_client_ip(): string {
        return ClientIpResolver::get_client_ip();
    }

    /**
     * Reset the cached resolved IP address (used for testing and lifecycle hooks).
     *
     * @return void
     */
    public static function reset_client_ip_cache(): void {
        ClientIpResolver::reset_client_ip_cache();
    }

    /**
     * Check if a remote connecting IP address belongs to a verified trusted proxy.
     *
     * @param string $ip
     * @return bool
     */
    /**
     * Official Cloudflare IPv4 and IPv6 CIDR ranges for Anycast edge proxy verification.
     *
     * @return array
     */
    public static function get_cloudflare_ip_ranges(): array {
        return ClientIpResolver::get_cloudflare_ip_ranges();
    }

    /**
     * Check if an IPv4 or IPv6 address belongs to Cloudflare's Anycast Proxy ranges.
     *
     * @param string $ip
     * @return bool
     */
    public static function is_cloudflare_ip(string $ip): bool {
        return ClientIpResolver::is_cloudflare_ip($ip);
    }

    /**
     * Check if a remote connecting IP address belongs to a verified trusted proxy.
     *
     * @param string $ip
     * @return bool
     */
    public static function is_trusted_proxy(string $ip): bool {
        return ClientIpResolver::is_trusted_proxy($ip);
    }

    /**
     * Check if an IP address belongs to private or loopback ranges (RFC 1918 / RFC 4193).
     *
     * @param string $ip
     * @return bool
     */
    public static function is_private_ip(string $ip): bool {
        return ClientIpResolver::is_private_ip($ip);
    }

    /**
     * Retrieve array of configured trusted proxy IPs/CIDRs from constants, environment, or settings.
     *
     * @return array
     */
    public static function get_configured_trusted_proxies(): array {
        return ClientIpResolver::get_configured_trusted_proxies();
    }

    /**
     * Canonical multi-pass normalization helper for inspection engines.
     * Strips control characters (NUL/CR/LF), decodes URL encoding up to 3 passes,
     * and decodes HTML entities (e.g. &#x27; / &#39;) to prevent evasion.
     *
     * @param string $val
     * @return string
     */
    public static function normalize_inspect_value(string $val): string {
        if ($val === '') {
            return '';
        }

        $norm = str_replace(["\0", "\r", "\n"], '', $val);
        for ($d = 0; $d < 3; $d++) {
            $decoded = rawurldecode($norm);
            if ($decoded === $norm) {
                break;
            }
            $norm = str_replace(["\0", "\r", "\n"], '', $decoded);
        }

        // HTML entity decode for hex/numeric/named entities (e.g., &#x27;, &#39;, &quot;)
        if (str_contains($norm, '&') && str_contains($norm, ';')) {
            $html_decoded = html_entity_decode($norm, ENT_QUOTES | ENT_HTML5, 'UTF-8');
            if ($html_decoded !== $norm) {
                $norm = str_replace(["\0", "\r", "\n"], '', $html_decoded);
            }
        }

        return $norm;
    }

    /**
     * Detect external security layers (Cloudflare, Wordfence, Sucuri, Solid Security)
     */
    public static function detect_environment(): array {
        if (self::$detected_environment !== null) {
            return self::$detected_environment;
        }

        $has_cloudflare = !empty($_SERVER['HTTP_CF_CONNECTING_IP']) || !empty($_SERVER['HTTP_CF_RAY']);
        $has_wordfence  = defined('WORDFENCE_VERSION') || class_exists('wordfence');
        $has_sucuri     = defined('SUCURISCAN_INIT');
        $has_solid      = defined('ITSEC_VERSION');

        self::$detected_environment = [
            'has_cloudflare' => (bool) $has_cloudflare,
            'has_wordfence'  => (bool) $has_wordfence,
            'has_sucuri'     => (bool) $has_sucuri,
            'has_solid'      => (bool) $has_solid,
            'has_coexisting_waf' => ($has_wordfence || $has_sucuri || $has_solid),
        ];

        return self::$detected_environment;
    }

    /**
     * Check if the incoming request is made by a verified authenticated WordPress administrator.
     *
     * @return bool
     */
    public static function is_authenticated_administrator(): bool {
        static $cached_result  = null;
        static $cached_user_id = null;

        $current_uid = function_exists('get_current_user_id') ? (int) get_current_user_id() : 0;
        if ($cached_result === true && $cached_user_id === $current_uid) {
            return true;
        }
        if ($cached_result === false && $cached_user_id === $current_uid && function_exists('did_action') && did_action('init')) {
            return false;
        }

        $verified_user_id = 0;
        $verified_session_token = '';

        // Layer 1: Check standard WordPress authenticated session if available (skip during PCP _pc_ DB sandboxing so $current_user isn't cached as 0 against *_pc_users)
        if (!self::is_plugin_check_db_sandbox() && function_exists('is_user_logged_in') && is_user_logged_in() && function_exists('get_current_user_id')) {
            $verified_user_id = (int) get_current_user_id();
        }

        // Layer 2: Independent Cryptographic Auth Cookie Validation & Session Token Extraction
        if (!function_exists('wp_validate_auth_cookie') && defined('ABSPATH') && file_exists(ABSPATH . 'wp-includes/pluggable.php')) {
            require_once ABSPATH . 'wp-includes/pluggable.php';
        }

        if (function_exists('wp_validate_auth_cookie')) {
            $auth_cookie    = '';
            $cookie_schemes = ['logged_in', 'secure_auth', 'auth'];
            $is_pcp_sandbox = self::is_plugin_check_db_sandbox();
            $orig_prefix    = $is_pcp_sandbox ? self::get_original_table_prefix() : '';

            foreach ($cookie_schemes as $scheme) {
                if ($scheme === 'logged_in') {
                    $cookie_name = defined('LOGGED_IN_COOKIE') ? LOGGED_IN_COOKIE : 'wordpress_logged_in_' . COOKIEHASH;
                } elseif ($scheme === 'secure_auth') {
                    $cookie_name = defined('SECURE_AUTH_COOKIE') ? SECURE_AUTH_COOKIE : 'wordpress_sec_' . COOKIEHASH;
                } else {
                    $cookie_name = defined('AUTH_COOKIE') ? AUTH_COOKIE : 'wordpress_' . COOKIEHASH;
                }

                if (!empty($_COOKIE[$cookie_name])) {
                    $auth_cookie = sanitize_text_field(wp_unslash($_COOKIE[$cookie_name]));
                    if (!$is_pcp_sandbox) {
                        $uid = (int) wp_validate_auth_cookie($auth_cookie, $scheme);
                        if ($uid > 0) {
                            if ($verified_user_id <= 0) {
                                $verified_user_id = $uid;
                            }
                            if (function_exists('wp_parse_auth_cookie')) {
                                $parsed_cookie = wp_parse_auth_cookie($auth_cookie, $scheme);
                                if (!empty($parsed_cookie['token'])) {
                                    $verified_session_token = (string) $parsed_cookie['token'];
                                }
                            }
                            break;
                        }
                    } else {
                        $orig_auth = self::validate_cookie_against_original_tables($auth_cookie, $scheme, $orig_prefix);
                        if (!empty($orig_auth['user_id']) && !empty($orig_auth['is_admin'])) {
                            if ($verified_user_id <= 0) {
                                $verified_user_id = (int) $orig_auth['user_id'];
                            }
                            break;
                        }
                    }
                }
            }

            // Fallback for default cookie names if constants aren't defined yet
            if (empty($verified_session_token) || $verified_user_id <= 0) {
                foreach ($_COOKIE as $c_name => $c_val) {
                    $scheme_guess = '';
                    if (strpos($c_name, 'wordpress_logged_in_') === 0) {
                        $scheme_guess = 'logged_in';
                    } elseif (strpos($c_name, 'wordpress_sec_') === 0) {
                        $scheme_guess = 'secure_auth';
                    } elseif (strpos($c_name, 'wordpress_') === 0 && $c_name !== 'wordpress_test_cookie') {
                        $scheme_guess = 'auth';
                    }

                    if ($scheme_guess === '') {
                        continue;
                    }

                    $cookie_val = sanitize_text_field(wp_unslash($c_val));
                    if (!$is_pcp_sandbox) {
                        $uid = (int) wp_validate_auth_cookie($cookie_val, $scheme_guess);
                        if ($uid > 0) {
                            if ($verified_user_id <= 0) {
                                $verified_user_id = $uid;
                            }
                            if (function_exists('wp_parse_auth_cookie')) {
                                $parsed_cookie = wp_parse_auth_cookie($cookie_val, $scheme_guess);
                                if (!empty($parsed_cookie['token'])) {
                                    $verified_session_token = (string) $parsed_cookie['token'];
                                }
                            }
                            break;
                        }
                    } else {
                        $orig_auth = self::validate_cookie_against_original_tables($cookie_val, $scheme_guess, $orig_prefix);
                        if (!empty($orig_auth['user_id']) && !empty($orig_auth['is_admin'])) {
                            if ($verified_user_id <= 0) {
                                $verified_user_id = (int) $orig_auth['user_id'];
                            }
                            break;
                        }
                    }
                }
            }
        }

        if ($verified_user_id <= 0) {
            if (function_exists('did_action') && did_action('init')) {
                $cached_user_id = $current_uid;
                $cached_result  = false;
            }
            return false;
        }

        // Layer 3: Role and High-Privilege Capability Verification
        if (function_exists('get_userdata')) {
            $user = get_userdata($verified_user_id);
            if (!$user || empty($user->ID)) {
                if (function_exists('did_action') && did_action('init')) {
                    $cached_user_id = $current_uid;
                    $cached_result  = false;
                }
                return false;
            }

            // Require administrator role or explicit manage_options capability
            $has_admin_cap = $user->has_cap('manage_options') || $user->has_cap('administrator');
            $has_admin_role = in_array('administrator', (array) $user->roles, true);

            // Resilient check: If $wpdb->prefix was temporarily amended (e.g. Plugin Check 'wp_pc_'),
            // look up the user's authentic capabilities under the true base prefix $orig_prefix
            if (!$has_admin_cap && !$has_admin_role) {
                global $wpdb;
                $base_prefix = self::get_original_table_prefix();
                if (isset($wpdb->prefix) && $wpdb->prefix !== $base_prefix) {
                    $base_caps = get_user_meta($verified_user_id, $base_prefix . 'capabilities', true);
                    if (is_array($base_caps) && (!empty($base_caps['administrator']) || !empty($base_caps['manage_options']))) {
                        $has_admin_cap = true;
                        $has_admin_role = true;
                    }
                }
            }

            if (!$has_admin_cap && !$has_admin_role) {
                if (function_exists('did_action') && did_action('init')) {
                    $cached_user_id = $current_uid;
                    $cached_result  = false;
                }
                return false;
            }
        } else {
            if (function_exists('did_action') && did_action('init')) {
                $cached_user_id = $current_uid;
                $cached_result  = false;
            }
            return false;
        }

        // Layer 4: Cryptographic Nonce Verification on REST API & AJAX Mutation Requests
        $request_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
        $clean_uri = str_replace(["\0", "\r", "\n"], '', $request_uri);
        $norm_rest_route = self::resolve_normalized_rest_route($clean_uri);
        $method = strtoupper(isset($_SERVER['REQUEST_METHOD']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_METHOD'])) : 'GET');
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $has_rest_query = !empty($_GET['rest_route']) || !empty($_POST['rest_route']);
        $is_rest_call = (strpos($request_uri, '/wp-json/') !== false)
            || (defined('REST_REQUEST') && REST_REQUEST)
            || $has_rest_query
            || (strpos($request_uri, 'rest_route=') !== false);

        // Read-only inspection and safe diagnostic routes under WebCare Pro
        // (excludes mutating /probe and /snapshot routes which require Layer 4 REST nonce verification).
        $is_webcare_read_route = str_starts_with($norm_rest_route, '/webcare-pro-security/v1/')
            && in_array($norm_rest_route, [
                '/webcare-pro-security/v1/file/view',
                '/webcare-pro-security/v1/post/view',
                '/webcare-pro-security/v1/file/integrity',
                '/webcare-pro-security/v1/integrity/diff',
                '/webcare-pro-security/v1/integrity/verify',
                '/webcare-pro-security/v1/snapshots/list',
                '/webcare-pro-security/v1/snapshots/diff',
                '/webcare-pro-security/v1/snapshots/compare',
                '/webcare-pro-security/v1/telemetry/snapshot',
                '/webcare-pro-security/v1/containment/status',
                '/webcare-pro-security/v1/caf/overview',
                '/webcare-pro-security/v1/firewall/status',
                '/webcare-pro-security/v1/firewall/redirect-shield/status',
                '/webcare-pro-security/v1/redirect-shield/status',
                '/webcare-pro-security/v1/waf/logs',
                '/webcare-pro-security/v1/server-info',
                '/webcare-pro-security/v1/rescue/status',
            ], true);

        if ($is_rest_call && !$is_webcare_read_route && in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
            $nonce = '';
            if (!empty($_SERVER['HTTP_X_WP_NONCE'])) {
                $nonce = sanitize_text_field(wp_unslash($_SERVER['HTTP_X_WP_NONCE']));
            } elseif (!empty($_SERVER['REDIRECT_HTTP_X_WP_NONCE'])) {
                $nonce = sanitize_text_field(wp_unslash($_SERVER['REDIRECT_HTTP_X_WP_NONCE']));
            } elseif (function_exists('getallheaders')) {
                $all_h = getallheaders();
                if (!empty($all_h['X-WP-Nonce'])) {
                    $nonce = sanitize_text_field(wp_unslash($all_h['X-WP-Nonce']));
                } elseif (!empty($all_h['x-wp-nonce'])) {
                    $nonce = sanitize_text_field(wp_unslash($all_h['x-wp-nonce']));
                }
            }
            if (empty($nonce) && !empty($_REQUEST['_wpnonce'])) {
                // phpcs:ignore WordPress.Security.NonceVerification.Recommended
                $nonce = sanitize_text_field(wp_unslash($_REQUEST['_wpnonce']));
            } elseif (empty($nonce) && !empty($_REQUEST['nonce'])) {
                // phpcs:ignore WordPress.Security.NonceVerification.Recommended
                $nonce = sanitize_text_field(wp_unslash($_REQUEST['nonce']));
            }

            if (empty($nonce)) {
                // REST mutation without nonce header is untrusted (protects against CSRF)
                if (function_exists('did_action') && did_action('init')) {
                    $cached_user_id = $current_uid;
                    $cached_result  = false;
                }
                return false;
            }

            if (function_exists('wp_verify_nonce')) {
                // Switch current user context to verified user for accurate nonce calculation
                $prev_uid = function_exists('get_current_user_id') ? get_current_user_id() : 0;
                if ($prev_uid !== $verified_user_id && function_exists('wp_set_current_user')) {
                    wp_set_current_user($verified_user_id);
                }

                $nonce_valid = (bool) wp_verify_nonce($nonce, 'wp_rest');

                // Fallback: verify with extracted cookie session token (or empty token if session tokens uninitialized when created)
                if (!$nonce_valid && function_exists('wp_hash') && function_exists('wp_nonce_tick')) {
                    $tick_i = wp_nonce_tick('wp_rest');
                    $candidate_tokens = array_unique(array_filter([$verified_session_token, ''], static function ($t) {
                        return is_string($t);
                    }));
                    foreach ($candidate_tokens as $cand_token) {
                        $expected1 = substr(wp_hash($tick_i . '|wp_rest|' . $verified_user_id . '|' . $cand_token, 'nonce'), -12, 10);
                        $expected2 = substr(wp_hash(($tick_i - 1) . '|wp_rest|' . $verified_user_id . '|' . $cand_token, 'nonce'), -12, 10);
                        if (hash_equals($expected1, $nonce) || hash_equals($expected2, $nonce)) {
                            $nonce_valid = true;
                            break;
                        }
                    }
                }

                if ($prev_uid !== $verified_user_id && function_exists('wp_set_current_user')) {
                    wp_set_current_user($prev_uid);
                }

                if (!$nonce_valid) {
                    if (function_exists('did_action') && did_action('init')) {
                        $cached_user_id = $current_uid;
                        $cached_result  = false;
                    }
                    return false;
                }
            }
        }

        $cached_user_id = $verified_user_id;
        $cached_result  = true;
        return true;
    }

    /**
     * Resolve and normalize REST API route from request URI or query parameters.
     * Returns normalized path with leading slash and without trailing slash (e.g. '/wp/v2/posts').
     *
     * @param string $request_uri
     * @return string Normalized route path or empty string.
     */
    public static function resolve_normalized_rest_route(string $request_uri): string {
        $clean_uri = str_replace(["\0", "\r", "\n"], '', $request_uri);
        $parsed_path = (string) (wp_parse_url($clean_uri, PHP_URL_PATH) ?? $clean_uri);
        for ($i = 0; $i < 3; $i++) {
            $decoded = rawurldecode($parsed_path);
            if ($decoded === $parsed_path) {
                break;
            }
            $parsed_path = $decoded;
        }
        $parsed_path = str_replace(["\0", "\r", "\n"], '', $parsed_path);
        if (preg_match('#/(?:wp-json|index\.php(?:/wp-json)?)(/[^?]+)#i', $parsed_path, $rm)) {
            return '/' . trim((string) preg_replace('#/+#', '/', $rm[1]), '/');
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        if (isset($_GET['rest_route']) && is_string($_GET['rest_route'])) {
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Normalized REST route query inspection requires raw multi-pass decoding without percent octet distortion
            $raw_get_route = (string) wp_unslash($_GET['rest_route']);
            $clean_get_route = str_replace(["\0", "\r", "\n"], '', $raw_get_route);
            for ($i = 0; $i < 3; $i++) {
                $decoded = rawurldecode($clean_get_route);
                if ($decoded === $clean_get_route) {
                    break;
                }
                $clean_get_route = $decoded;
            }
            $clean_get_route = str_replace(["\0", "\r", "\n"], '', $clean_get_route);
            return '/' . trim((string) preg_replace('#/+#', '/', $clean_get_route), '/');
        }
        if (preg_match('/(?:^|[?&])rest_route=([^&]+)/i', $clean_uri, $qm)) {
            $raw_get_route = (string) $qm[1];
            for ($i = 0; $i < 3; $i++) {
                $decoded = rawurldecode($raw_get_route);
                if ($decoded === $raw_get_route) {
                    break;
                }
                $raw_get_route = $decoded;
            }
            $raw_get_route = str_replace(["\0", "\r", "\n"], '', $raw_get_route);
            return '/' . trim((string) preg_replace('#/+#', '/', $raw_get_route), '/');
        }
        return '';
    }

    /**
     * Safe-pass verification for authenticated Editors, Authors, and Shop Managers in page builder/REST contexts (WCP-16).
     */
    public static function is_verified_editor_builder_request(string $request_uri): bool {
        $req_method = isset($_SERVER['REQUEST_METHOD'])
            ? strtoupper(sanitize_key(wp_unslash($_SERVER['REQUEST_METHOD'])))
            : 'GET';
        if (!in_array($req_method, ['POST', 'PUT', 'PATCH'], true)) {
            return false;
        }

        if (!function_exists('is_user_logged_in') || !is_user_logged_in()) {
            return false;
        }

        if (!function_exists('current_user_can') || !(current_user_can('edit_posts') || current_user_can('manage_woocommerce'))) {
            return false;
        }

        $rest_route = self::resolve_normalized_rest_route($request_uri);
        $is_gutenberg_rest = (bool) preg_match(
            '#^/wp/v2/(?:(?:posts|pages|blocks)(?:/\d+)?(?:/autosaves)?|(?:templates|template-parts|navigation|global-styles)(?:/[a-z0-9_/-]+)?)$#i',
            $rest_route
        );
        $is_builder_rest = (bool) preg_match(
            '#^/(?:elementor/v\d+/(?:documents|globals|kits|template)(?:/[a-z0-9_/-]+)?|(?:breakdance|brizy|seedprod|droip|generateblocks|kadence|uag|fusion-builder)/v\d+/[a-z0-9_/-]+)$#i',
            $rest_route
        );

        $is_rest_authoring = ($is_gutenberg_rest || $is_builder_rest);

        $parsed_path = (string) (wp_parse_url($request_uri, PHP_URL_PATH) ?? '');
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $req_action = isset($_REQUEST['action']) ? sanitize_key((string) $_REQUEST['action']) : '';
        $is_ajax_builder = str_contains($parsed_path, 'admin-ajax.php')
            && in_array($req_action, ['elementor_ajax', 'elementor_save_builder'], true);

        if (!$is_rest_authoring && !$is_ajax_builder) {
            return false;
        }

        // Verify standard WP REST nonce or Elementor AJAX nonce
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $rest_nonce = isset($_SERVER['HTTP_X_WP_NONCE'])
            ? sanitize_text_field(wp_unslash($_SERVER['HTTP_X_WP_NONCE']))
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            : (isset($_REQUEST['_wpnonce']) ? sanitize_text_field(wp_unslash($_REQUEST['_wpnonce'])) : '');
        if ($is_rest_authoring && $rest_nonce !== '' && function_exists('wp_verify_nonce')) {
            return (bool) wp_verify_nonce($rest_nonce, 'wp_rest');
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $ajax_nonce = isset($_REQUEST['_nonce'])
            ? sanitize_text_field(wp_unslash($_REQUEST['_nonce']))
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            : (isset($_REQUEST['nonce']) ? sanitize_text_field(wp_unslash($_REQUEST['nonce'])) : '');
        if ($is_ajax_builder && $ajax_nonce !== '' && function_exists('wp_verify_nonce')) {
            return (bool) (wp_verify_nonce($ajax_nonce, 'elementor_ajax') || wp_verify_nonce($ajax_nonce, 'wp_rest'));
        }

        return false;
    }

    /**
     * Check whether the current request is from an authenticated user with Content Editor privileges
     * or an active visual page builder session (Elementor, Divi, Gutenberg, Bricks, Beaver Builder).
     *
     * Validates:
     * 1. Cryptographically valid auth cookie for an active user.
     * 2. User holds 'edit_posts', 'edit_pages', or 'manage_options' capability.
     * 3. Request targets page builder AJAX, REST API, or frontend builder preview session with matching nonce.
     *
     * @return bool
     */
    public static function is_authenticated_editor_or_builder(bool $reset = false): bool {
        static $cached_builder_result = null;
        if ($reset) {
            $cached_builder_result = null;
        }
        if ($cached_builder_result !== null) {
            return $cached_builder_result;
        }

        // Require a state-changing write method before granting WAF authoring exemption (Fix 2)
        $request_method = isset($_SERVER['REQUEST_METHOD']) ? strtoupper(sanitize_key(wp_unslash($_SERVER['REQUEST_METHOD']))) : 'GET';
        if (!in_array($request_method, ['POST', 'PUT', 'PATCH'], true)) {
            return ($cached_builder_result = false);
        }

        // Check if page builder smart pass is enabled in settings
        $settings = \WebCareProScanner\System\SettingsManager::get_settings();
        if (isset($settings['waf_allow_page_builders']) && empty($settings['waf_allow_page_builders'])) {
            return ($cached_builder_result = false);
        }

        $req_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
        if (self::is_verified_editor_builder_request($req_uri)) {
            return ($cached_builder_result = true);
        }

        $verified_user_id = 0;
        if (function_exists('is_user_logged_in') && is_user_logged_in() && function_exists('get_current_user_id')) {
            $verified_user_id = (int) get_current_user_id();
        }

        if ($verified_user_id <= 0) {
            if (!function_exists('wp_validate_auth_cookie') && defined('ABSPATH') && file_exists(ABSPATH . 'wp-includes/pluggable.php')) {
                require_once ABSPATH . 'wp-includes/pluggable.php';
            }
            if (function_exists('wp_validate_auth_cookie') && !empty($_COOKIE)) {
                foreach ($_COOKIE as $c_name => $c_val) {
                    if (strpos($c_name, 'wordpress_logged_in_') === 0 || strpos($c_name, 'wordpress_sec_') === 0) {
                        $uid = (int) wp_validate_auth_cookie(sanitize_text_field(wp_unslash($c_val)), 'logged_in')
                            ?: (int) wp_validate_auth_cookie(sanitize_text_field(wp_unslash($c_val)), 'secure_auth');
                        if ($uid > 0) {
                            $verified_user_id = $uid;
                            break;
                        }
                    }
                }
            }
        }

        if ($verified_user_id <= 0) {
            return ($cached_builder_result = false);
        }

        // Verify Editor / Content Author capabilities (Must have unfiltered_html or manage_options to bypass WAF)
        if (function_exists('get_userdata')) {
            $user = get_userdata($verified_user_id);
            if (!$user || empty($user->ID)) {
                return ($cached_builder_result = false);
            }

            $has_editor_cap = $user->has_cap('unfiltered_html') || $user->has_cap('manage_options');
            if (!$has_editor_cap) {
                return ($cached_builder_result = false);
            }
        } else {
            return ($cached_builder_result = false);
        }

        // Require valid REST or builder nonce before granting WAF authoring exemption (Fix 2)
        $nonce = '';
        if (!empty($_SERVER['HTTP_X_WP_NONCE'])) {
            $nonce = sanitize_text_field(wp_unslash($_SERVER['HTTP_X_WP_NONCE']));
        } elseif (!empty($_REQUEST['_wpnonce'])) {
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            $nonce = sanitize_text_field(wp_unslash($_REQUEST['_wpnonce']));
        } elseif (!empty($_REQUEST['editor_post_nonce'])) {
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            $nonce = sanitize_text_field(wp_unslash($_REQUEST['editor_post_nonce']));
        }

        if (!function_exists('wp_verify_nonce') && defined('ABSPATH') && file_exists(ABSPATH . 'wp-includes/pluggable.php')) {
            require_once ABSPATH . 'wp-includes/pluggable.php';
        }

        $nonce_valid = false;
        // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended
        $action_hint = isset($_POST['action']) ? sanitize_text_field(wp_unslash($_POST['action'])) : (isset($_GET['action']) ? sanitize_text_field(wp_unslash($_GET['action'])) : '');
        if ($nonce !== '' && function_exists('wp_verify_nonce')) {
            $prev_uid = function_exists('get_current_user_id') ? (int) get_current_user_id() : 0;
            $switched_user = false;
            if ($verified_user_id > 0 && $prev_uid !== $verified_user_id && function_exists('wp_set_current_user')) {
                wp_set_current_user($verified_user_id);
                $switched_user = true;
            }

            try {
                if (wp_verify_nonce($nonce, 'wp_rest') || wp_verify_nonce($nonce, 'elementor_ajax') || ($action_hint !== '' && wp_verify_nonce($nonce, 'wp_ajax_' . $action_hint))) {
                    $nonce_valid = true;
                }
            } finally {
                if ($switched_user && function_exists('wp_set_current_user')) {
                    wp_set_current_user($prev_uid);
                }
            }
        }

        if (!$nonce_valid) {
            return ($cached_builder_result = false);
        }

        // Identify builder-specific actions and endpoints
        $request_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
        // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended -- Early runtime WAF builder detection
        $ajax_action = isset($_POST['action']) ? sanitize_text_field(wp_unslash($_POST['action'])) : (isset($_GET['action']) ? sanitize_text_field(wp_unslash($_GET['action'])) : '');

        $has_builders = class_exists('\\WebCareProScanner\\Firewall\\CAF\\AdaptiveFirewallAdvisor')
            ? \WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor::has_ecosystem('page_builder')
            : true;

        $rest_route = self::resolve_normalized_rest_route($request_uri);
        $is_gutenberg_rest = (bool) preg_match(
            '#^/wp/v2/(?:(?:posts|pages|blocks)(?:/\d+)?(?:/autosaves)?|(?:templates|template-parts|navigation|global-styles)(?:/[a-z0-9_/-]+)?)$#i',
            $rest_route
        );

        $is_builder_ajax = false;
        $is_builder_rest = false;

        if ($has_builders) {
            // 20 Popular WordPress Visual Builders & Block Suites:
            // 1. Elementor, 2. Divi, 3. Beaver, 4. Bricks, 5. Breakdance, 6. Oxygen, 7. SeedProd,
            // 8. Brizy, 9. Thrive Architect, 10. WPBakery, 11. Visual Composer, 12. Themify,
            // 13. SiteOrigin, 14. Droip, 15. Live Composer, 16. WP Site Editor / Gutenberg FSE,
            // 17. GenerateBlocks, 18. Kadence Blocks, 19. Spectra, 20. Avada Fusion Builder
            $is_builder_ajax = in_array($ajax_action, [
                // Elementor & Divi
                'elementor_ajax', 'elementor_save_builder', 'et_fb_save_builder', 'et_fb_ajax_save',
                // Beaver Builder & Bricks
                'fl_builder_save_layout', 'bricks_save_post',
                // Breakdance & Oxygen
                'breakdance_save_document', 'ct_save_oxygen_data',
                // SeedProd & Brizy
                'seedprod_save_page', 'brizy_update_item', 'brizy_create_item',
                // Thrive Architect & WPBakery
                'tve_ajax_save_post', 'wpb_save_post', 'vc_save', 'vcv-ajax',
                // Themify Builder & SiteOrigin
                'themify_builder_save_data', 'so_panels_save',
                // Droip & Live Composer
                'droip_save_page', 'dslc-ajax-save-composer',
                // Avada Fusion Builder
                'fusion_app_save_post', 'fusion_save_post',
                // Block Suites (Kadence, GenerateBlocks, Spectra)
                'kadence_save_block', 'generateblocks_save', 'uagb_save_block',
            ], true);

            $is_builder_rest = (bool) preg_match(
                '#^/(?:elementor/v\d+/(?:documents|globals|kits|template)(?:/[a-z0-9_/-]+)?|(?:breakdance|brizy|seedprod|droip|generateblocks|kadence|uag|fusion-builder)/v\d+/[a-z0-9_/-]+)$#i',
                $rest_route
            );
        }
        if ($is_builder_ajax || $is_gutenberg_rest || $is_builder_rest) {
            return ($cached_builder_result = true);
        }

        return ($cached_builder_result = false);
    }

    /**
     * Inspect Incoming Request
     */
    public static function inspect_incoming_request(): void {
        if (class_exists(Core\RequestPipeline::class)) {
            Core\RequestPipeline::process_incoming_request();
        }
    }

    /**
     * Evaluate protection rules across GET, POST, Cookies, User-Agent, Referer, and URI
     */
    public static function evaluate_rules(array $settings, bool $is_complementary): ?array {
        return ExploitSignatureEngine::evaluate_rules($settings, $is_complementary);
    }

    /**
     * XML-RPC Guard
     */
    public static function check_xmlrpc_guard() {
        $settings = SettingsManager::get_settings();
        if (!empty($settings['waf_enabled']) && !empty($settings['waf_disable_xmlrpc'])) {
            $uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
            if (strpos($uri, 'xmlrpc.php') !== false) {
                $client_ip = self::get_client_ip();
                // Smart Pass: Exclude verified Automattic Jetpack sync requests
                if (self::is_verified_jetpack_request($client_ip, $uri, $settings)) {
                    return;
                }

                self::log_incident([
                    'category'    => 'XML-RPC Disabled',
                    'description' => 'XML-RPC request blocked by administrator policy.',
                    'payload'     => 'xmlrpc.php invocation',
                ], 'blocked');

                status_header(403);
                header('Content-Type: text/plain; charset=utf-8');
                echo 'XML-RPC services are disabled on this WordPress installation by WebCare Pro Security.';
                exit;
            }
        }
    }

    /**
     * Smart 404 Scanner Rate Limiter & Reconnaissance Shield
     *
     * Hooks into template_redirect when WordPress evaluates is_404().
     * Accurately distinguishes between:
     * 1. Verified genuine search crawlers (Google, Bing, DuckDuckGo) -> ALWAYS exempt via reverse DNS.
     * 2. Static media/asset 404s (.css, .js, images, fonts) -> Ignored to prevent false-positives for humans.
     * 3. High-risk reconnaissance probes (.env, .git, .bak, shell.php, etc.) -> Rapid detection.
     * 4. Automated directory fuzzing / scanners exceeding threshold (e.g. 10 hits in 60s) -> Enforces temporary lockout.
     */
    public static function track_404_request(): void {
        CommerceVelocityGuard::track_404_request();
    }

    /**
     * Check if requested URI path is a static media/asset file.
     *
     * @param string $uri
     * @return bool
     */
    public static function is_static_asset(string $uri): bool {
        return CommerceVelocityGuard::is_static_asset($uri);
    }

    /**
     * Check if a redirection has been emitted or staged by WordPress or a redirection plugin.
     * Prevents false-positive 404 lockout on URLs handled by redirection rules.
     *
     * @return bool
     */
    public static function is_redirect_in_progress(): bool {
        return CommerceVelocityGuard::is_redirect_in_progress();
    }

    /**
     * Inspect URI path for single, mixed-case, or multiply encoded directory traversal attempts.
     * Evaluates strictly against PHP_URL_PATH (excluding query parameters) and inspects path segments,
     * eliminating false positives on query strings (e.g. ?search=version..history) and benign filenames
     * (e.g. report..final.pdf) while strictly blocking single-, double-, and triple-encoded directory traversal.
     *
     * @param string $uri
     * @return bool
     */
    public static function has_path_traversal(string $uri): bool {
        return ExploitSignatureEngine::has_path_traversal($uri);
    }

    /**
     * Helper to verify if a normalized slash-delimited path contains directory traversal segments.
     *
     * @param string $path
     * @return bool
     */
    public static function is_traversal_path_segment(string $path): bool {
        return ExploitSignatureEngine::is_traversal_path_segment($path);
    }

    /**
     * Decode and canonicalize URI path by resolving directory traversal (..) and redundant slashes.
     *
     * @param string $uri
     * @return string
     */
    public static function canonicalize_uri_path(string $uri): string {
        $decoded = str_replace(["\0", "\r", "\n"], '', $uri);
        for ($i = 0; $i < 5; $i++) {
            $prev = $decoded;
            $decoded = rawurldecode($decoded);
            if ($decoded === $prev) {
                break;
            }
        }
        $decoded = str_replace(["\0", "\r", "\n"], '', $decoded);
        $path = (string) (wp_parse_url($decoded, PHP_URL_PATH) ?: $decoded);
        $path = str_replace('\\', '/', $path);
        $path = (string) preg_replace('#/{2,}#', '/', $path);

        $segments = explode('/', $path);
        $resolved = [];
        foreach ($segments as $seg) {
            if ($seg === '' || $seg === '.') {
                continue;
            }
            if ($seg === '..') {
                array_pop($resolved);
            } else {
                $resolved[] = $seg;
            }
        }

        return '/' . implode('/', $resolved);
    }

    /**
     * Detect high-risk reconnaissance probes seeking sensitive files or backdoors.
     *
     * @param string $uri
     * @return bool
     */
    public static function is_high_risk_recon_probe(string $uri): bool {
        $canonical_path = strtolower(self::canonicalize_uri_path($uri));
        $raw_path       = strtolower((string) (wp_parse_url($uri, PHP_URL_PATH) ?: $uri));
        $raw_path       = str_replace('\\', '/', $raw_path);

        // Exempt anchored internal WebCare Pro REST API routes (/webcare-pro-security/v1/*) when no directory traversal is present
        $norm_rest_route = self::resolve_normalized_rest_route($uri);
        if (
            !self::has_path_traversal($uri)
            && str_starts_with($norm_rest_route, '/webcare-pro-security/v1/')
            && strpos($canonical_path, '/wp-content/') === false
        ) {
            return false;
        }

        $high_risk_patterns = [
            '/\.env($|\.)/i',
            '/\.git(\/|$)/i',
            '/\.svn(\/|$)/i',
            '/\.htaccess(\.bak|\.old|\.save)?$/i',
            '/wp-config\.php(\.bak|\.old|\.save|\.swp|\.dist|\.inc)?$/i',
            '/(phpinfo|phpmyadmin|pma|adminer|wso|c99|r57|alfa|shell)\.php$/i',
            '/\/(backup|dump|db|database|sql)\.(sql|tar|gz|zip|bz2)$/i',
            '/\/eval-stdin\.php$/i',
            '/\/vendor\/phpunit\//i',
            '/\/solr\/admin\//i',
        ];

        foreach ($high_risk_patterns as $pattern) {
            if (preg_match($pattern, $canonical_path) || preg_match($pattern, $raw_path)) {
                return true;
            }
        }

        if (self::has_path_traversal($uri)) {
            return true;
        }

        return false;
    }

    /**
     * Inspect URI for sensitive system configuration, log file, or database backup reconnaissance probes (Rule #53).
     *
     * @param string $uri
     * @param array  $settings
     * @param bool   $skip_heuristics
     * @return array|null
     */
    public static function check_sensitive_file_probe(string $uri, array $settings, bool $skip_heuristics = false): ?array {
        return ExploitSignatureEngine::check_sensitive_file_probe($uri, $settings, $skip_heuristics);
    }

    /**
     * Check if WooCommerce, Easy Digital Downloads, or recognized Membership suites are present.
     *
     * @return bool
     */
    public static function is_commerce_active(): bool {
        // 1. Configured Archetype Profile from Setup Wizard or Site Advisor
        $archetype = get_option('webcareproscan_site_archetype', '');
        if (in_array($archetype, ['ecommerce', 'membership'], true)) {
            return true;
        }

        // 2. Physical E-Commerce Suites (Decoupled from manual setting override)
        $has_ecommerce = class_exists('WooCommerce')
            || class_exists('Easy_Digital_Downloads')
            || class_exists('\\SureCart\\SureCart') || defined('SURECART_PLUGIN_FILE') // SureCart
            || class_exists('Ecwid_Product') || defined('ECWID_PLUGIN_DIR') // Ecwid
            || class_exists('wp_easycart') || defined('EC_CURRENT_VERSION') // WP EasyCart
            || class_exists('\\FluentCart\\App\\App') || defined('FLUENTCART_VERSION') // FluentCart
            || class_exists('\\BigCommerce\\Container') || defined('BIGCOMMERCE_VERSION') // BigCommerce
            || class_exists('SimplePay') || defined('SIMPLE_PAY_VERSION') // WP Simple Pay
            || class_exists('Cart66') || defined('CART66_VERSION') // Cart66
            || class_exists('WP_DLM') // Download Monitor
            || class_exists('Give') || defined('GIVE_VERSION'); // GiveWP

        // Membership & Subscription Suites
        $has_membership = class_exists('MeprAppCtrl') // MemberPress
            || defined('PMPRO_VERSION') // Paid Memberships Pro
            || class_exists('Restrict_Content_Pro') || defined('RCP_PLUGIN_VERSION') // Restrict Content Pro / Kadence Memberships
            || class_exists('\\SureMembers\\SureMembers') || defined('SUREMEMBERS_VERSION') // SureMembers
            || class_exists('ARM_main') || defined('MEMBERSHIP_VERSION') // ARMember
            || class_exists('MemberMouse') || defined('MM_VERSION') // MemberMouse
            || class_exists('WishListMember') || defined('WLM_VERSION') // WishList Member
            || class_exists('SimpleWpMembership') || defined('SWPM_VERSION') // Simple Membership
            || class_exists('WC_Memberships') // WooCommerce Memberships
            || class_exists('Pms_Member') || defined('PMS_VERSION') // Paid Member Subscriptions
            || class_exists('c_ws_plugin__s2member_menu_pages') // s2Member
            || class_exists('IhsuMpMain') || defined('UHP_VERSION') // Ultimate Membership Pro
            || class_exists('LearnDash_Settings_Section') // LearnDash
            || class_exists('LifterLMS'); // LifterLMS

        // User Profile & Registration Management Suites
        $has_profiles = class_exists('UM') || defined('um_plugin') // Ultimate Member
            || class_exists('Profile_Builder') || defined('WPPB_PLUGIN_DIR') // User Profile Builder (Cozmoslabs)
            || class_exists('WP_User_Manager') || defined('WPUM_VERSION') // WP User Manager
            || class_exists('ProfilePress') || defined('PPRESS_VERSION_NUMBER') // ProfilePress
            || class_exists('User_Registration') || defined('UR_VERSION') // User Registration (WPEverest)
            || class_exists('Registration_Magic') || defined('RM_PLUGIN_VERSION') // RegistrationMagic
            || class_exists('Profile_Grid') || defined('PG_PLUGIN_VERSION') // ProfileGrid
            || class_exists('Theme_My_Login') || defined('TML_VERSION') // ThemeMyLogin
            || class_exists('FrmRegAppController') // Formidable Forms User Registration
            || class_exists('wpmembers') // WP-Members
            || class_exists('BuddyBoss_Platform') || defined('BP_PLATFORM_VERSION') // BuddyBoss Platform
            || class_exists('Youzify') || defined('YOUZIFY_VERSION'); // Youzify

        $has_archetype_commerce = in_array(get_option('webcareproscan_site_archetype'), ['ecommerce', 'membership'], true);

        return $has_ecommerce || $has_membership || $has_profiles || $has_archetype_commerce || defined('WEBCARE_COMMERCE_OVERRIDE');
    }

    /**
     * Invalidate the in-memory WooCommerce session verification cache.
     * Purges specific customer session or entire request cache upon logout or cleanup.
     *
     * @param string|null $customer_id Customer ID to purge, or null to purge all request-cached sessions.
     * @return void
     */
    public static function invalidate_woocommerce_session_cache(?string $customer_id = null): void {
        CommerceSessionGuard::invalidate_woocommerce_session_cache($customer_id);
    }

    /**
     * Verify whether a WooCommerce session exists and is unexpired in the database.
     * Enforces database-level revocation for both runtime and early-boot shopper sessions.
     * Request-scoped cache avoids redundant database queries; purged immediately on logout or session cleanup.
     *
     * @param string $customer_id
     * @return bool
     */
    public static function is_unexpired_woocommerce_db_session(string $customer_id): bool {
        return CommerceSessionGuard::is_unexpired_woocommerce_db_session($customer_id);
    }

    /**
     * Check if current request has an authentic, cryptographically verified shopper or customer session.
     *
     * Never trusts cookie names, numeric counters, or delimiter counts alone:
     * 1. If WooCommerce's runtime session handler is initialized (`WC()->session`), queries `has_session()`
     *    and verifies that the session contains active cart/customer state or a verified session key.
     * 2. During early pre-boot (`plugins_loaded:0`), parses the 4-part `wp_woocommerce_session_<hash>` cookie
     *    (`customer_id||session_expiration||session_expiring||cookie_hash`), queries the backing row in
     *    `{$wpdb->prefix}woocommerce_sessions`, and verifies the HMAC signature using `wp_hash()` + `hash_equals()`.
     * 3. Alternatively, accepts a cryptographically verified WordPress logged-in authentication cookie.
     *
     * @return bool
     */
    public static function has_active_shopper_session(): bool {
        return CommerceSessionGuard::has_active_shopper_session();
    }

    /**
     * Determine if current session is exempt from operational IP bans.
     * Narrowly scoped to verified shoppers/members or authenticated administrators.
     *
     * @return bool
     */
    public static function is_exempt_from_operational_ban(): bool {
        return CommerceSessionGuard::is_exempt_from_operational_ban();
    }

    /**
     * Detect if the incoming URI or request belongs to legitimate E-Commerce, Cart,
     * Checkout, Customer Account, or Payment Gateway Webhook channels.
     *
     * @param string $uri
     * @return bool
     */
    public static function is_commerce_or_membership_request(string $uri): bool {
        return CommerceSessionGuard::is_commerce_or_membership_request($uri);
    }

    /**
     * Check if an incoming request corresponds to a legitimate form submission
     * across major WordPress form plugins (Contact Form 7, WPForms, Fluent Forms,
     * Gravity Forms, Ninja Forms, Formidable Forms, WS Form, HappyForms, etc.).
     *
     * @param string $uri
     * @return bool
     */
    public static function is_form_submission_request(string $uri): bool {
        return CommerceSessionGuard::is_form_submission_request($uri);
    }

    /**
     * Check if an IP is in the user-defined whitelist
     */
    /**
     * Check if an IP address belongs to the server itself (Loopback or Host Origin IPv4/IPv6)
     */
    public static function is_server_origin_or_loopback(string $ip): bool {
        return ClientIpResolver::is_server_origin_or_loopback($ip);
    }

    public static function is_ip_whitelisted(string $ip, ?string $whitelist_str = null): bool {
        return Core\AllowlistManager::is_ip_whitelisted($ip, $whitelist_str);
    }

    /**
     * Check if an IP is in the user-defined blocklist
     */
    public static function is_ip_blocked(string $ip, string $blocklist_str): bool {
        return Core\BlocklistRepository::is_ip_blocked($ip, $blocklist_str);
    }

    /**
     * Find the exact blocklist entry (IP or CIDR subnet) matching a client IP.
     *
     * @param string $ip
     * @param string $blocklist_str
     * @return string|null Matching line string or null if not blocked
     */
    public static function get_matching_blocked_entry(string $ip, string $blocklist_str): ?string {
        return Core\BlocklistRepository::get_matching_blocked_entry($ip, $blocklist_str);
    }

    /**
     * Check if an IP (IPv4 or IPv6) is within a CIDR subnet or matches an IP.
     *
     * @param string $ip
     * @param string $range
     * @return bool
     */
    public static function ip_in_range(string $ip, string $range): bool {
        return ClientIpResolver::ip_in_range($ip, $range);
    }

    /**
     * Automattic / WordPress.com Jetpack Official IP CIDR Ranges
     * Source: Automattic official Jetpack documentation & ARIN/RIPE allocations.
     */
    public const JETPACK_IP_RANGES = [
        '192.0.64.0/18',
        '192.0.80.0/20',
        '192.0.96.0/20',
        '192.0.112.0/20',
        '195.234.108.0/22',
        '122.248.245.244/32',
        '54.217.201.243/32',
        '54.232.116.4/32',
    ];

    /**
     * Official Stripe Webhook IP Addresses
     * Source: Stripe official webhook documentation (https://docs.stripe.com/ips)
     */
    public const STRIPE_WEBHOOK_IPS = [
        '3.18.12.63',
        '3.130.192.231',
        '13.235.14.237',
        '13.235.122.149',
        '18.211.135.69',
        '35.154.171.200',
        '52.15.183.38',
        '54.88.130.119',
        '54.88.130.237',
        '54.88.130.238',
        '54.88.130.241',
        '54.187.174.169',
        '54.187.205.235',
        '54.187.216.72',
        '54.241.31.99',
        '54.241.31.100',
        '54.241.34.23',
        '54.241.47.70',
        '54.243.149.206',
    ];

    /**
     * Official PayPal IPN & Webhook Subnet CIDRs
     * Source: PayPal Developer Documentation & ARIN allocations.
     */
    public const PAYPAL_WEBHOOK_CIDRS = [
        '173.0.80.0/20',
        '66.211.168.0/22',
        '64.4.240.0/21',
        '64.4.248.0/22',
        '91.243.72.0/23',
        '185.177.52.0/22',
        '192.160.215.0/24',
        '198.54.216.0/23',
    ];

    /**
     * Check whether an incoming request to xmlrpc.php is a verified, authentic Jetpack sync from Automattic.
     *
     * Validates:
     * 1. Setting 'waf_allow_jetpack_xmlrpc' is enabled.
     * 2. Request targets xmlrpc.php and contains query parameter ?for=jetpack.
     * 3. Client IP belongs strictly to Automattic's verified CIDR blocks (prevents User-Agent / parameter spoofing).
     * 4. Essential cryptographic signature parameters (token, timestamp, nonce, signature) are present.
     *
     * @param string $client_ip
     * @param string $request_uri
     * @param array $settings
     * @return bool
     */
    public static function is_verified_jetpack_request(string $client_ip, string $request_uri, array $settings): bool {
        if (empty($settings['waf_allow_jetpack_xmlrpc'])) {
            return false;
        }

        // Must explicitly target xmlrpc.php with for=jetpack
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Jetpack pingback incoming verification
        $for_param = isset($_GET['for']) ? sanitize_key(wp_unslash($_GET['for'])) : '';
        if ($for_param !== 'jetpack' && strpos($request_uri, 'for=jetpack') === false) {
            return false;
        }

        // 1. Strict IP Verification against Automattic's CIDRs
        $ip_matched = false;
        foreach (self::JETPACK_IP_RANGES as $cidr) {
            if (self::ip_in_range($client_ip, $cidr)) {
                $ip_matched = true;
                break;
            }
        }

        if (!$ip_matched) {
            return false;
        }

        // 2. Cryptographic signature parameters check (Jetpack signs all outbound syncs)
        // Requests must carry timestamp and at least signature or token (inspect both superglobals and request URI)
        $query_str = wp_parse_url($request_uri, PHP_URL_QUERY);
        $uri_params = [];
        if (!empty($query_str)) {
            parse_str($query_str, $uri_params);
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended -- Jetpack HMAC signature inspection
        $has_timestamp = isset($_GET['timestamp']) || isset($_POST['timestamp']) || isset($uri_params['timestamp']);
        // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended -- Jetpack token verification
        $has_signature = isset($_GET['signature']) || isset($_POST['signature']) || isset($_GET['token']) || isset($_POST['token'])
            || isset($uri_params['signature']) || isset($uri_params['token']);

        if (!$has_timestamp && !$has_signature) {
            return false;
        }

        return true;
    }

    /**
     * Check whether an incoming request belongs to an authenticated central WordPress management
     * network worker (ManageWP, MainWP, InfiniteWP).
     *
     * Validates:
     * 1. Setting 'waf_allow_central_management' is enabled.
     * 2. Request targets legitimate worker endpoints or carries worker cryptographic signature headers:
     *    - ManageWP Worker: HTTP_X_MWP_SIGNATURE or HTTP_X_MANAGEWP_SIGNATURE
     *    - MainWP Child: HTTP_X_MAINWP_SIGNATURE or POST parameter 'mainwp_signature'
     *    - InfiniteWP: HTTP_IWP_ACTION or POST parameter 'iwp_action'
     * 3. Confirms corresponding official worker plugin is actively installed and running.
     *
     * @param string $request_uri
     * @param array $settings
     * @return bool
     */
    public static function is_verified_central_management_request(string $request_uri, array $settings): bool {
        if (empty($settings['waf_allow_central_management'])) {
            return false;
        }

        // ManageWP Worker validation
        $has_mwp_sig = !empty($_SERVER['HTTP_X_MWP_SIGNATURE']) || !empty($_SERVER['HTTP_X_MANAGEWP_SIGNATURE']);
        if ($has_mwp_sig && (class_exists('MMB_Core') || defined('MMB_WORKER_VERSION') || function_exists('mwp_core'))) {
            return true;
        }

        // MainWP Child validation
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- MainWP worker signature check
        $has_mainwp_sig = !empty($_SERVER['HTTP_X_MAINWP_SIGNATURE']) || isset($_POST['mainwp_signature']);
        if ($has_mainwp_sig && (class_exists('MainWP_Child') || defined('MAINWP_CHILD_PLUGIN_DIR'))) {
            return true;
        }

        // InfiniteWP Client validation
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- InfiniteWP worker action check
        $has_iwp_action = !empty($_SERVER['HTTP_IWP_ACTION']) || isset($_POST['iwp_action']);
        if ($has_iwp_action && (class_exists('IWP_MMB_Core') || defined('IWP_MMB_USER_AGENT'))) {
            return true;
        }

        return false;
    }

    /**
     * Log firewall incident to database or partitioned JSON storage
     */
    public static function log_incident(array $rule, string $action, ?string $incident_id = null): ?string {
        return Core\ViolationResponder::log_incident($rule, $action, $incident_id);
    }

    /**
     * Render branded 403 Forbidden Error Screen via standard wp_die()
     */
    public static function render_block_page(array $rule, string $client_ip, ?string $incident_id = null) {
        Core\ViolationResponder::render_block_page($rule, $client_ip, $incident_id);
    }

    /**
     * Get statistics & summary of firewall activity
     */
    public static function get_status(): array {
        return Core\FirewallTelemetryService::get_status();
    }

    /**
     * Get active plugin directory slugs on this site
     */
    public static function get_active_plugin_slugs(): array {
        $active_plugins = (array) get_option('active_plugins', []);
        if (is_multisite()) {
            $network_active = (array) get_site_option('active_sitewide_plugins', []);
            $active_plugins = array_merge($active_plugins, array_keys($network_active));
        }
        $slugs = [];
        foreach ($active_plugins as $plugin_path) {
            $parts = explode('/', (string) $plugin_path);
            $slugs[] = sanitize_key($parts[0]);
        }
        return array_values(array_unique(array_filter($slugs)));
    }

    /**
     * Get available WordPress user roles on this site.
     *
     * @return array Array of role slugs and their display names.
     */
    public static function get_available_roles(): array {
        global $wp_roles;
        if (!isset($wp_roles) && function_exists('wp_roles')) {
            $wp_roles = wp_roles();
        }
        $roles = [];
        if (!empty($wp_roles->roles) && is_array($wp_roles->roles)) {
            foreach ($wp_roles->roles as $slug => $data) {
                $roles[] = [
                    'slug' => (string) $slug,
                    'name' => isset($data['name']) ? translate_user_role($data['name']) : ucfirst((string) $slug),
                ];
            }
        }
        if (empty($roles)) {
            $roles = [
                ['slug' => 'administrator', 'name' => 'Administrator'],
                ['slug' => 'editor', 'name' => 'Editor'],
                ['slug' => 'author', 'name' => 'Author'],
                ['slug' => 'contributor', 'name' => 'Contributor'],
                ['slug' => 'subscriber', 'name' => 'Subscriber'],
            ];
        }
        return $roles;
    }

    /**
     * Compute comprehensive server, host runtime, and developer diagnostics for the Firewall dashboard.
     *
     * @return array
     */
    public static function get_server_telemetry(): array {
        return Core\FirewallTelemetryService::get_server_telemetry();
    }

    /**
     * Get recent blocked logs from daily JSON filesystem partitions
     */
    public static function get_logs(int $limit = 50, int $offset = 0, array $filters = []): array {
        return Core\FirewallTelemetryService::get_logs($limit, $offset, $filters);
    }

    /**
     * Get aggregate statistics and metrics for WAF logs dashboard
     */
    public static function get_log_stats(string $range = 'today'): array {
        return Core\FirewallTelemetryService::get_log_stats($range);
    }

    /**
     * Delete a single firewall incident log entry
     *
     * @param int|string $id
     */
    public static function delete_log($id): bool {
        return Core\FirewallTelemetryService::delete_log($id);
    }

    /**
     * Clear firewall logs
     */
    public static function clear_logs(): bool {
        return Core\FirewallTelemetryService::clear_logs();
    }

    /**
     * Option key for storing structured metadata for blocked IPs
     */
    // OPTION_BLOCKED_IPS_META constant is defined at class head

    /**
     * Retrieve all persistent block metadata for IPs
     */
    public static function get_all_block_meta(): array {
        return Core\BlocklistRepository::get_all_block_meta();
    }

    /**
     * Get block metadata for a specific IP
     */
    public static function get_ip_block_meta(string $ip): ?array {
        $meta = self::get_all_block_meta();
        return $meta[$ip] ?? null;
    }

    /**
     * Store or update metadata for a blocked IP
     */
    public static function set_ip_block_meta(string $ip, array $data): bool {
        $meta = self::get_all_block_meta();
        $existing = $meta[$ip] ?? [];
        $meta[$ip] = array_merge($existing, $data);
        return update_option(self::OPTION_BLOCKED_IPS_META, $meta, false);
    }

    /**
     * Delete block metadata for an unblocked IP
     */
    public static function delete_ip_block_meta(string $ip): bool {
        $meta = self::get_all_block_meta();
        if (isset($meta[$ip])) {
            unset($meta[$ip]);
            return update_option(self::OPTION_BLOCKED_IPS_META, $meta, false);
        }
        return false;
    }

    /**
     * Build a structured forensic note for Cloudflare IP Access Rules & Account Lists.
     *
     * Format: [WebCare-WAF] [WEBCARE-8F3A19C2] Rule:WAF-SQLI-INJECTION | Hit:POST /wp-admin/admin-ajax.php | Ev:... | TTL:24h
     *
     * @param string      $reason
     * @param string|null $rule_id
     * @param string|null $rule_category
     * @param string|null $incident_id
     * @param int         $duration_seconds
     * @param string|null $admin_user
     * @return string
     */
    public static function build_forensic_cf_note(
        string $reason,
        ?string $rule_id = null,
        ?string $rule_category = null,
        ?string $incident_id = null,
        int $duration_seconds = 86400,
        ?string $admin_user = null
    ): string {
        $method    = isset($_SERVER['REQUEST_METHOD']) ? strtoupper(sanitize_text_field(wp_unslash($_SERVER['REQUEST_METHOD']))) : 'REQ';
        $raw_uri   = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '/';
        $clean_uri = substr((string) preg_replace('/[\r\n\t\x00-\x1f]+/', '', $raw_uri), 0, 55);
        $ttl_label = $duration_seconds > 0 ? round($duration_seconds / 3600, 1) . 'h' : 'PERM';

        $parts = ['[WebCare-WAF]'];
        if (!empty($incident_id)) {
            $parts[] = '[' . preg_replace('/[^A-Za-z0-9_-]/', '', $incident_id) . ']';
        }
        if (!empty($rule_id)) {
            $parts[] = 'Rule:' . preg_replace('/[^A-Za-z0-9_-]/', '', $rule_id);
        } elseif (!empty($rule_category)) {
            $parts[] = 'Cat:' . substr(sanitize_text_field($rule_category), 0, 28);
        }
        if (!empty($admin_user)) {
            $parts[] = 'By:' . sanitize_user($admin_user, true);
        } else {
            $parts[] = "Hit:{$method} {$clean_uri}";
        }

        $clean_reason = trim((string) preg_replace('/^\[[^\]]+\]\s*/', '', $reason));
        if ($clean_reason !== '') {
            $parts[] = 'Ev:' . substr($clean_reason, 0, 75);
        }
        $parts[] = 'TTL:' . $ttl_label;

        return substr(implode(' | ', $parts), 0, 240);
    }

    /**
     * Add IP to custom blocklist with rich metadata
     *
     * @param string $ip IP address or CIDR subnet
     * @param string $reason Human-readable explanation or rule violation note
     * @param int $duration_seconds Ban duration in seconds (0 = permanent)
     * @param string|null $rule_id Unique rule identifier (e.g. 'WAF-FORBIDDEN-USERNAME')
     * @param string|null $rule_name Rule title
     * @param string|null $rule_category Rule category
     * @param string|null $incident_id Incident tracking ID (e.g. 'WEBCARE-80458BF3')
     * @param string|null $admin_user Username of administrator who added manual block
     * @return bool
     */
    public static function add_blocked_ip(
        string $ip,
        string $reason = '',
        int $duration_seconds = 0,
        ?string $rule_id = null,
        ?string $rule_name = null,
        ?string $rule_category = null,
        ?string $incident_id = null,
        ?string $admin_user = null,
        bool $sync_cloudflare = true
    ): bool {
        return Core\BlocklistRepository::add_blocked_ip($ip, $reason, $duration_seconds, $rule_id, $rule_name, $rule_category, $incident_id, $admin_user, $sync_cloudflare);
    }

    /**
     * Compatibility alias for blocking an IP address (used by GhostRouteTrap / Bot Traps)
     *
     * @param string $ip
     * @param string $reason
     * @param int $duration_seconds
     * @return bool
     */
    public static function block_ip(string $ip, string $reason = '', int $duration_seconds = 0): bool {
        return Core\BlocklistRepository::block_ip($ip, $reason, $duration_seconds);
    }

    /**
     * Remove an IP or CIDR subnet from custom blocklist and clear any active temporary lockouts.
     * Restores normal visitor access with full WAF inspection protection active.
     *
     * @param string $ip
     * @return bool
     */
    public static function remove_blocked_ip(string $ip): bool {
        return Core\BlocklistRepository::remove_blocked_ip($ip);
    }

    /**
     * Clear all expired temporary bans from the firewall blocklist in one operation.
     *
     * @return int Number of expired IP bans cleared.
     */
    public static function clear_expired_blocked_ips(): int {
        return Core\BlocklistRepository::clear_expired_blocked_ips();
    }

    /**
     * Clear and unban all blocked IPs locally and on Cloudflare Edge in one operation.
     *
     * @return array
     */
    public static function clear_all_blocked_ips(): array {
        return Core\BlocklistRepository::clear_all_blocked_ips();
    }

    /**
     * Retrieve aggregated list of all currently locked or custom-blocked IPs across engines with rich forensics.
     *
     * @return array
     */
    public static function get_all_locked_ips(): array {
        return Core\BlocklistRepository::get_all_locked_ips();
    }

    /**
     * Compute comprehensive human-readable ban timing, countdown, and duration breakdown.
     *
     * @param int|null $blocked_ts
     * @param int $expires_ts
     * @param int $duration_secs
     * @param string|null $fallback_last_seen
     * @return array
     */
    public static function calculate_ban_timing(?int $blocked_ts, int $expires_ts, int $duration_secs, ?string $fallback_last_seen = null): array {
        return Core\BlocklistRepository::calculate_ban_timing($blocked_ts, $expires_ts, $duration_secs, $fallback_last_seen);
    }

    /**
     * Break down seconds into years, months, days, hours, minutes, seconds.
     *
     * @param int $seconds
     * @return array
     */
    public static function breakdown_seconds(int $seconds): array {
        $seconds = max(0, $seconds);
        $years   = (int) floor($seconds / (365 * 86400));
        $seconds %= (365 * 86400);

        $months  = (int) floor($seconds / (30 * 86400));
        $seconds %= (30 * 86400);

        $days    = (int) floor($seconds / 86400);
        $seconds %= 86400;

        $hours   = (int) floor($seconds / 3600);
        $seconds %= 3600;

        $minutes = (int) floor($seconds / 60);
        $sec     = $seconds % 60;

        return [
            'years'   => $years,
            'months'  => $months,
            'days'    => $days,
            'hours'   => $hours,
            'minutes' => $minutes,
            'seconds' => $sec,
        ];
    }

    /**
     * Format structured countdown into clear human words (e.g. "1 year, 2 months, 5 days, 4 hours, 10 mins").
     */
    public static function format_countdown_human(array $c): string {
        $parts = [];
        if (!empty($c['years'])) {
            $parts[] = $c['years'] . ($c['years'] === 1 ? ' yr' : ' yrs');
        }
        if (!empty($c['months'])) {
            $parts[] = $c['months'] . ($c['months'] === 1 ? ' mo' : ' mos');
        }
        if (!empty($c['days'])) {
            $parts[] = $c['days'] . ($c['days'] === 1 ? ' day' : ' days');
        }
        if (!empty($c['hours'])) {
            $parts[] = $c['hours'] . ($c['hours'] === 1 ? ' hr' : ' hrs');
        }
        if (!empty($c['minutes'])) {
            $parts[] = $c['minutes'] . ' mins';
        }
        if (empty($parts)) {
            $parts[] = max(1, $c['seconds'] ?? 0) . ' secs';
        }

        return implode(', ', $parts) . ' left';
    }

    /**
     * Format duration into standard human label.
     */
    public static function format_duration_label(int $seconds): string {
        if ($seconds >= 365 * 86400) {
            $y = (int) round($seconds / (365 * 86400));
            return $y . ($y === 1 ? ' Year' : ' Years');
        }
        if ($seconds >= 30 * 86400) {
            $m = (int) round($seconds / (30 * 86400));
            return $m . ($m === 1 ? ' Month' : ' Months');
        }
        if ($seconds >= 86400) {
            $d = (int) round($seconds / 86400);
            return $d . ($d === 1 ? ' Day' : ' Days');
        }
        if ($seconds >= 3600) {
            $h = (int) round($seconds / 3600);
            return $h . ($h === 1 ? ' Hour' : ' Hours');
        }
        $mins = (int) round($seconds / 60);
        return $mins . ($mins === 1 ? ' Minute' : ' Minutes');
    }

    /**
     * Format elapsed seconds into human string (e.g. "5 mins", "2 hours", "4 days").
     */
    public static function format_seconds_human(int $seconds): string {
        if ($seconds < 60) {
            return $seconds . ' secs';
        }
        if ($seconds < 3600) {
            $m = (int) floor($seconds / 60);
            return $m . ($m === 1 ? ' min' : ' mins');
        }
        if ($seconds < 86400) {
            $h = (int) floor($seconds / 3600);
            return $h . ($h === 1 ? ' hr' : ' hrs');
        }
        $d = (int) floor($seconds / 86400);
        return $d . ($d === 1 ? ' day' : ' days');
    }

    /**
     * Retrieve complete catalog of inspectable firewall rules and category groups
     *
     * @return array
     */
    public static function get_firewall_rules_catalog(): array {
        return Core\FirewallTelemetryService::get_firewall_rules_catalog();
    }

    /**
     * Map rule IDs to their human-readable title
     *
     * @param array $rule_ids
     * @return array
     */
    public static function resolve_rule_names(array $rule_ids): array {
        static $catalog_map = null;
        if ($catalog_map === null) {
            $catalog_map = [];
            foreach (self::get_firewall_rules_catalog() as $rule) {
                $catalog_map[$rule['id']] = $rule['name'];
            }
        }

        $names = [];
        foreach ($rule_ids as $id) {
            $names[$id] = $catalog_map[$id] ?? $id;
        }
        return $names;
    }

    /**
     * Option key for storing structured metadata for whitelisted IPs
     */
    const OPTION_WHITELISTED_IPS_META = 'webcareproscan_whitelisted_ips_meta';

    /**
     * Retrieve all persistent whitelist metadata for IPs
     */
    public static function get_all_whitelist_meta(): array {
        $meta = get_option(self::OPTION_WHITELISTED_IPS_META, []);
        return is_array($meta) ? $meta : [];
    }

    /**
     * Get whitelist metadata for a specific IP
     */
    public static function get_ip_whitelist_meta(string $ip): ?array {
        $meta = self::get_all_whitelist_meta();
        return $meta[$ip] ?? null;
    }

    /**
     * Store or update metadata for a whitelisted IP
     */
    public static function set_ip_whitelist_meta(string $ip, array $data): bool {
        $meta = self::get_all_whitelist_meta();
        $existing = $meta[$ip] ?? [];
        $meta[$ip] = array_merge($existing, $data);
        return update_option(self::OPTION_WHITELISTED_IPS_META, $meta, false);
    }

    /**
     * Delete whitelist metadata for an un-whitelisted IP
     */
    public static function delete_ip_whitelist_meta(string $ip): bool {
        $meta = self::get_all_whitelist_meta();
        if (isset($meta[$ip])) {
            unset($meta[$ip]);
            return update_option(self::OPTION_WHITELISTED_IPS_META, $meta, false);
        }
        return false;
    }

    /**
     * Add IP to custom whitelist with structured metadata and granular rule/category scoping.
     *
     * @param string      $ip          The IPv4, IPv6, or CIDR address.
     * @param string      $reason      Human-readable justification.
     * @param string|null $admin_user  The administrator login performing the action.
     * @param array       $scope_args  Granular scoping parameters:
     *                                 [
     *                                   'scope'         => 'rule'|'category'|'global',
     *                                   'allowed_rules' => string[],
     *                                   'allowed_cats'  => string[],
     *                                   'endpoint'      => string,
     *                                   'expires_in'    => int (seconds, 0 for permanent)
     *                                 ]
     * @return bool
     */
    public static function add_whitelisted_ip(string $ip, string $reason = '', ?string $admin_user = null, array $scope_args = []): bool {
        $ip = trim($ip);
        if (!filter_var($ip, FILTER_VALIDATE_IP) && strpos($ip, '/') === false) {
            return false;
        }

        $settings = SettingsManager::get_settings();
        $current = trim($settings['waf_whitelisted_ips'] ?? '');
        $lines = array_filter(array_map('trim', explode("\n", str_replace("\r", "", $current))));

        if (!in_array($ip, $lines, true)) {
            $lines[] = $ip;
            $settings['waf_whitelisted_ips'] = implode("\n", $lines);
            SettingsManager::save_settings($settings);
        }

        $now = time();
        $scope = isset($scope_args['scope']) && in_array($scope_args['scope'], ['rule', 'category', 'global'], true)
            ? $scope_args['scope']
            : 'global';

        $allowed_rules = !empty($scope_args['allowed_rules']) && is_array($scope_args['allowed_rules'])
            ? array_map('sanitize_text_field', $scope_args['allowed_rules'])
            : [];

        $allowed_cats = !empty($scope_args['allowed_cats']) && is_array($scope_args['allowed_cats'])
            ? array_map('sanitize_text_field', $scope_args['allowed_cats'])
            : [];

        $endpoint = !empty($scope_args['endpoint']) ? sanitize_text_field($scope_args['endpoint']) : '';
        $expires_in = isset($scope_args['expires_in']) ? max(0, (int) $scope_args['expires_in']) : 0;
        $expires_at = $expires_in > 0 ? ($now + $expires_in) : 0;

        self::set_ip_whitelist_meta($ip, [
            'ip'            => $ip,
            'reason'        => !empty($reason) ? $reason : 'Trusted access policy approved by administrator',
            'added_at'      => $now,
            'added_by'      => !empty($admin_user) ? $admin_user : 'admin',
            'type'          => !empty($admin_user) ? 'manual_admin' : 'custom_whitelist',
            'scope'         => $scope,
            'allowed_rules' => $allowed_rules,
            'allowed_cats'  => $allowed_cats,
            'endpoint'      => $endpoint,
            'expires_at'    => $expires_at,
        ]);

        return true;
    }

    /**
     * Remove IP from custom whitelist
     */
    public static function remove_whitelisted_ip(string $ip): bool {
        $ip = trim($ip);
        if (empty($ip)) {
            return false;
        }

        $settings = SettingsManager::get_settings();
        $current = trim($settings['waf_whitelisted_ips'] ?? '');
        $lines = array_filter(array_map('trim', explode("\n", str_replace("\r", "", $current))));

        $new_lines = [];
        $removed = false;
        foreach ($lines as $line) {
            if ($line === $ip) {
                $removed = true;
                continue;
            }
            $new_lines[] = $line;
        }

        if ($removed) {
            $settings['waf_whitelisted_ips'] = implode("\n", $new_lines);
            SettingsManager::save_settings($settings);
        }

        self::delete_ip_whitelist_meta($ip);
        return true;
    }

    /**
     * Get all whitelisted IPs with rich forensic metadata
     */
    public static function get_all_whitelisted_ips(): array {
        $settings = SettingsManager::get_settings();
        $current = trim($settings['waf_whitelisted_ips'] ?? '');
        $lines = array_filter(array_map('trim', explode("\n", str_replace("\r", "", $current))));
        $all_meta = self::get_all_whitelist_meta();
        $now = time();

        $results = [];
        foreach ($lines as $ip) {
            $meta = $all_meta[$ip] ?? null;
            $added_at_ts = $meta['added_at'] ?? null;
            $added_at_formatted = $added_at_ts ? gmdate('M j, Y, g:i a \U\T\C', $added_at_ts) : 'Previously added';
            $added_ago = $added_at_ts ? self::format_seconds_human(max(0, $now - $added_at_ts)) . ' ago' : 'active';
            $expires_at = !empty($meta['expires_at']) ? (int) $meta['expires_at'] : 0;
            $is_expired = $expires_at > 0 && $now > $expires_at;

            $results[] = [
                'ip'                 => $ip,
                'reason'             => !empty($meta['reason']) ? $meta['reason'] : 'Trusted administrative access policy',
                'added_at'           => $added_at_formatted,
                'added_at_raw'       => $added_at_ts,
                'added_ago'          => $added_ago,
                'added_by'           => !empty($meta['added_by']) ? $meta['added_by'] : 'administrator',
                'type'               => !empty($meta['type']) ? $meta['type'] : 'manual_admin',
                'require_admin'      => !empty($settings['waf_whitelist_require_admin']),
                'scope'              => !empty($meta['scope']) ? $meta['scope'] : 'global',
                'allowed_rules'      => !empty($meta['allowed_rules']) ? (array) $meta['allowed_rules'] : [],
                'allowed_rule_names' => !empty($meta['allowed_rules']) ? self::resolve_rule_names((array) $meta['allowed_rules']) : (object) [],
                'allowed_cats'       => !empty($meta['allowed_cats']) ? (array) $meta['allowed_cats'] : [],
                'endpoint'           => !empty($meta['endpoint']) ? $meta['endpoint'] : '',
                'expires_at'         => $expires_at,
                'is_expired'         => $is_expired,
            ];
        }

        return $results;
    }
    /**
     * Check if a given request URI is whitelisted
     */
    public static function is_url_whitelisted(string $uri, string $whitelist_text): bool {
        return Core\AllowlistManager::is_url_whitelisted($uri, $whitelist_text);
    }

    /**
     * Compare the request path with the configured support URL using an exact path boundary.
     *
     * @param string $request_uri
     * @param string $configured_contact_url
     * @return bool
     */
    public static function is_configured_support_path(string $request_uri, string $configured_contact_url): bool {
        return Core\AllowlistManager::is_configured_support_path($request_uri, $configured_contact_url);
    }

    /**
     * Resolve the handling path for a request rejected only for its missing User-Agent.
     * OPTIONS is non-mutating and must remain available for browser preflight; HEAD cannot
     * complete a browser challenge because the protocol does not return a response body.
     *
     * @param string $method
     * @param bool $has_clearance
     * @param bool $has_pow_submission
     * @return string One of allow, challenge, proof, head_block, or block.
     */
    public static function get_empty_user_agent_action(string $method, bool $has_clearance, bool $has_pow_submission = false): string {
        $method = strtoupper(trim($method));

        if ($has_clearance || $method === 'OPTIONS') {
            return 'allow';
        }
        if ($method === 'GET') {
            return 'challenge';
        }
        if ($method === 'HEAD') {
            return 'head_block';
        }
        if ($method === 'POST' && $has_pow_submission) {
            return 'proof';
        }

        return 'block';
    }

    /**
     * Determine whether a rule is eligible for the progressive warning and PoW clearance flow.
     * Critical exploit categories, confirmed-exploit catalog signatures, admin custom rules,
     * and explicit hard blocks must NEVER be eligible for progressive warning or PoW clearance,
     * even if caller-supplied metadata flags is_warning.
     *
     * @param array $rule
     * @param array $settings
     * @return bool
     */
    public static function is_progressive_warning_rule(array $rule, array $settings): bool {
        return Core\ViolationResponder::is_progressive_warning_rule($rule, $settings);
    }

    /**
     * Determine whether an incoming request qualifies for progressive warning / PoW clearance,
     * and whether the visitor holds a valid clearance cookie or solution header to bypass the block.
     *
     * @param array $rule
     * @param array $settings
     * @param string $client_ip
     * @return bool True if the request is cleared to proceed.
     */
    public static function is_cleared_by_pow(array $rule, array $settings, string $client_ip): bool {
        return Core\ViolationResponder::is_cleared_by_pow($rule, $settings, $client_ip);
    }

    /**
     * Check if an incoming request matches any Targeted Allowlist Rules (User-Agent, Endpoint, and optional IP)
     * If matched, returns the matching rule definition array, or null if no match.
     */
    public static function match_targeted_allowlist_rule(string $uri, string $user_agent, string $ip, string $method, array $rules): ?array {
        return Core\AllowlistManager::match_targeted_allowlist_rule($uri, $user_agent, $ip, $method, $rules);
    }

    /**
     * Cryptographically verify IP reverse DNS (PTR) with forward DNS (A) resolution.
     * Caches verdict in WordPress transient for 24 hours to prevent DNS resolution latency.
     */
    public static function verify_rdns_domain(string $ip, string $target_domain): bool {
        return Core\AllowlistManager::verify_rdns_domain($ip, $target_domain);
    }

    /**
     * Resolve Client Autonomous System Number (ASN).
     * Checks Cloudflare CF-Connecting-ASN header, proxy headers, or Team Cymru DNS lookup.
     */
    public static function get_client_asn(string $ip): string {
        return Core\AllowlistManager::get_client_asn($ip);
    }

    /**
     * Log targeted allowlist bypass to WAF database with deep forensic telemetry
     */
    public static function log_targeted_allowlist_hit(array $rule, string $ip, string $uri, string $user_agent, string $method): void {
        global $wpdb;
        $table = $wpdb->prefix . 'webcareproscan_firewall_logs';

        // Check if table exists
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $table_check = $wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $table));
        if ($table_check !== $table) {
            return;
        }

        $incident_id = 'WEBCARE-ALLOW-' . strtoupper(substr(md5($ip . microtime(true) . wp_rand()), 0, 8));
        $rule_name = sanitize_text_field($rule['name'] ?? 'Targeted Allowlist');

        // Capture in-depth request payload & query details with sensitive data redaction
        $raw_body = '';
        if (in_array(strtoupper($method), ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
            // Read raw body stream or $_POST
            $raw_input = file_get_contents('php://input');
            if (!empty($raw_input)) {
                $raw_body = substr($raw_input, 0, 2500);
            } elseif (!empty($_POST)) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Inspection of inbound webhook/API payload occurs at low-level firewall layer before authentication
                // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Low-level packet forensic capture
                $raw_body = wp_json_encode(wp_unslash($_POST));
            }
        }

        // Privacy Redaction: Mask sensitive keys (passwords, tokens, api keys, secrets, authorization headers, credit cards)
        if (!empty($raw_body)) {
            $sensitive_patterns = [
                '/(["\']?(?:password|passwd|pass|secret|token|api[_-]?key|access[_-]?token|auth|authorization|card|cvv|cvc|pan)["\']?\s*[:=]\s*["\']?)([^"\'&,\s]{3,})/i',
                '/(Bearer\s+)[A-Za-z0-9_\-\.]{10,}/i'
            ];
            foreach ($sensitive_patterns as $pattern) {
                $raw_body = preg_replace($pattern, '$1[REDACTED]', $raw_body);
            }
        }

        $host_transient = 'webcare_ptr_' . md5($ip);
        $hostname = get_transient($host_transient);
        if ($hostname === false) {
            $hostname = @gethostbyaddr($ip);
            set_transient($host_transient, $hostname ?: $ip, DAY_IN_SECONDS);
        }
        $client_asn = self::get_client_asn($ip);

        $forensic_summary = [
            'rule_id'     => $rule['id'] ?? 'unknown',
            'rule_name'   => $rule_name,
            'query_data'  => !empty($query_str) ? $query_str : null,
            'body_sample' => !empty($raw_body) ? (strlen($raw_body) > 2000 ? substr($raw_body, 0, 2000) . '... [truncated]' : $raw_body) : null,
            'client_ip'   => $ip,
            'user_agent'  => $user_agent,
            'hostname'    => (!empty($hostname) && $hostname !== $ip) ? $hostname : null,
            'asn'         => !empty($client_asn) ? $client_asn : null,
            'matched_at'  => gmdate('Y-m-d H:i:s'),
        ];

        $payload_json = wp_json_encode($forensic_summary);
        $referer = isset($_SERVER['HTTP_REFERER']) ? esc_url_raw(wp_unslash($_SERVER['HTTP_REFERER'])) : null;

        // Rate limit logging for the same IP & rule to once every 10 seconds to avoid DB flooding on heavy sync batches
        $recent_sql = "SELECT id FROM `{$table}` WHERE ip_address = %s AND rule_category = 'targeted_allowlist' AND rule_description LIKE %s AND created_at > DATE_SUB(NOW(), INTERVAL 10 SECOND) LIMIT 1";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $recent = $wpdb->get_var(
            $wpdb->prepare(
                // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                $recent_sql,
                $ip,
                '%' . $wpdb->esc_like($rule_name) . '%'
            )
        );
        if ($recent) {
            return;
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
        $wpdb->insert(
            $table,
            [
                'incident_id'      => $incident_id,
                'ip_address'       => sanitize_text_field($ip),
                'request_uri'      => sanitize_text_field(substr($uri, 0, 500)),
                'request_method'   => sanitize_key(substr($method, 0, 10)),
                'http_status_code' => 200,
                'http_referer'     => !empty($referer) ? sanitize_text_field(substr($referer, 0, 500)) : null,
                'rule_category'    => 'targeted_allowlist',
                'rule_description' => sprintf(
                    /* translators: 1: rule name, 2: client user agent */
                    __('Granted safe WAF bypass via rule "%1$s" for User-Agent: %2$s', 'webcare-pro-security'),
                    $rule_name,
                    substr($user_agent, 0, 80)
                ),
                'payload_sample'   => sanitize_text_field($payload_json),
                'user_agent'       => sanitize_text_field(substr($user_agent, 0, 300)),
                'action_taken'     => 'allowed',
                'created_at'       => current_time('mysql'),
            ],
            ['%s', '%s', '%s', '%s', '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s']
        );
    }

    /**
     * Parse human-readable ini size strings (e.g. '64M', '2G', '512K') into bytes.
     *
     * @param string $val
     * @return int
     */
    public static function parse_ini_size_bytes(string $val): int {
        $val = trim($val);
        if ($val === '') {
            return 0;
        }
        $last = strtolower($val[strlen($val) - 1]);
        $num  = (int) $val;
        switch ($last) {
            case 'g':
                $num *= 1024 * 1024 * 1024;
                break;
            case 'm':
                $num *= 1024 * 1024;
                break;
            case 'k':
                $num *= 1024;
                break;
        }
        return $num;
    }

    /**
     * Resolve the maximum permitted upload body size in bytes based on WordPress and PHP runtime settings.
     *
     * @return int
     */
    public static function get_max_upload_limit_bytes(): int {
        if (function_exists('wp_max_upload_size')) {
            $wp_max = (int) wp_max_upload_size();
            if ($wp_max > 0) {
                return $wp_max;
            }
        }
        $post_max   = self::parse_ini_size_bytes((string) ini_get('post_max_size'));
        $upload_max = self::parse_ini_size_bytes((string) ini_get('upload_max_filesize'));
        $limit      = min($post_max ?: 67108864, $upload_max ?: 33554432);
        return max(4194304, $limit);
    }

    /**
     * Recursively normalize arbitrary multi-dimensional $_FILES structures into a flat list
     * of ['name' => string, 'tmp_name' => string, 'type' => string, 'error' => int, 'size' => int].
     *
     * Guarded with depth cap (<= 4) and max count (<= 50) to prevent pathological DOS arrays.
     * Sets $overflow = true if the array exceeds max files or max depth (fails closed).
     *
     * @param array $files_array
     * @param int   $max_depth
     * @param int   $max_files
     * @param bool  $overflow Passed by reference, set to true if count/depth exceeds limits.
     * @return array<int, array<string, mixed>>
     */
    public static function flatten_uploaded_files(array $files_array, int $max_depth = 4, int $max_files = 50, bool &$overflow = false): array {
        return ExploitSignatureEngine::flatten_uploaded_files($files_array, $max_depth, $max_files, $overflow);
    }

    /**
     * Intercept and audit uploaded files in real-time (Rule 8)
     */
    public static function inspect_uploaded_file(array $file, bool $log_and_ban = true): array {
        return ExploitSignatureEngine::inspect_uploaded_file($file, $log_and_ban);
    }

    /**
     * Intercept and prevent prohibited plugin installations via WP Upgrader (Rule 1 & 2)
     *
     * @param bool|object $response
     * @param array $hook_extra Extra upgrader hook arguments (contains 'plugin', 'package', 'type')
     * @return bool|object
     */
    public static function prevent_prohibited_plugin_install($response, array $hook_extra) {
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_enabled'])) {
            return $response;
        }

        $slug = '';
        if (!empty($hook_extra['plugin'])) {
            $slug = strtolower(dirname($hook_extra['plugin']));
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        if (empty($slug) && !empty($_POST['slug'])) {
            // phpcs:ignore WordPress.Security.NonceVerification.Missing
            $slug = strtolower(sanitize_text_field(wp_unslash($_POST['slug'])));
        }

        // Check phpMyAdmin restriction
        if (!empty($settings['waf_disallow_phpmyadmin_plugins'])) {
            $pma_signatures = [
                'phpmyadmin', 'database-browser', 'sql-buddy', 'sqlbuddy', 'adminer',
                'wp-phpmyadmin', 'wp-database-manager', 'database-management',
                'dbmanager', 'db-manager', 'database-manager', 'mysql-manager',
                'ari-adminer', 'portable-phpmyadmin'
            ];
            foreach ($pma_signatures as $sig) {
                if (strpos($slug, $sig) !== false) {
                    self::log_incident([
                        'category'    => 'Security Policy Enforcement',
                        'description' => sprintf('Upgrader installation of database manager / phpMyAdmin plugin ("%s") was blocked.', esc_html($slug)),
                        'payload'     => "Slug: {$slug}",
                    ], 'blocked');

                    return new \WP_Error(
                        'webcare_prohibited_plugin_pma',
                        __('Security Policy Violation: Installation of database managers (phpMyAdmin/Adminer/DBManager) is disallowed by WebCare Pro Security Firewall.', 'webcare-pro-security')
                    );
                }
            }
        }

        // Check File Manager restriction
        if (!empty($settings['waf_disallow_filemanager_plugins'])) {
            $fm_signatures = [
                'file-manager', 'filemanager', 'fileorganizer', 'filester',
                'advanced-file-manager', 'elfinder', 'tinyfilemanager', 'wp-file-manager',
                'wp-filemanager', 'file-explorer', 'file-commander', 'file-browser'
            ];
            foreach ($fm_signatures as $sig) {
                if (strpos($slug, $sig) !== false) {
                    self::log_incident([
                        'category'    => 'Security Policy Enforcement',
                        'description' => sprintf('Upgrader installation of File Manager plugin ("%s") was blocked.', esc_html($slug)),
                        'payload'     => "Slug: {$slug}",
                    ], 'blocked');

                    return new \WP_Error(
                        'webcare_prohibited_plugin_fm',
                        __('Security Policy Violation: Installation of File Manager plugins is disallowed by WebCare Pro Security Firewall.', 'webcare-pro-security')
                    );
                }
            }
        }

        return $response;
    }

    /**
     * Inspect unpacked plugin folder before moving to wp-content/plugins/ (catches direct ZIP upload & WP-CLI)
     *
     * @param string|\WP_Error $source Source directory of extracted plugin files.
     * @param string           $remote_source Remote source directory.
     * @param object           $upgrader Upgrader instance.
     * @param array            $hook_extra Hook extra context arguments.
     * @return string|\WP_Error
     */
    public static function inspect_unpacked_plugin_source($source, $remote_source, $upgrader, array $hook_extra = []) {
        if (is_wp_error($source)) {
            return $source;
        }

        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_enabled'])) {
            return $source;
        }

        $folder_name = strtolower(basename(untrailingslashit($source)));

        // Check if database manager plugins disallowed
        if (!empty($settings['waf_disallow_phpmyadmin_plugins'])) {
            $pma_signatures = [
                'phpmyadmin', 'database-browser', 'sql-buddy', 'sqlbuddy', 'adminer',
                'wp-phpmyadmin', 'wp-database-manager', 'database-management',
                'dbmanager', 'db-manager', 'database-manager', 'mysql-manager',
                'ari-adminer', 'portable-phpmyadmin'
            ];
            foreach ($pma_signatures as $sig) {
                if (strpos($folder_name, $sig) !== false) {
                    self::log_incident([
                        'category'    => 'Security Policy Enforcement',
                        'description' => sprintf('Source verification blocked installation of database manager plugin directory ("%s").', esc_html($folder_name)),
                        'payload'     => "Folder: {$folder_name} Source: {$source}",
                    ], 'blocked');

                    return new \WP_Error(
                        'webcare_prohibited_plugin_source_pma',
                        __('Security Policy Violation: Installation of database managers (phpMyAdmin/Adminer/DBManager) is prohibited by WebCare Pro Security Firewall.', 'webcare-pro-security')
                    );
                }
            }
        }

        // Check if file manager plugins disallowed
        if (!empty($settings['waf_disallow_filemanager_plugins'])) {
            $fm_signatures = [
                'file-manager', 'filemanager', 'fileorganizer', 'filester',
                'advanced-file-manager', 'elfinder', 'tinyfilemanager', 'wp-file-manager',
                'wp-filemanager', 'file-explorer', 'file-commander', 'file-browser'
            ];
            foreach ($fm_signatures as $sig) {
                if (strpos($folder_name, $sig) !== false) {
                    self::log_incident([
                        'category'    => 'Security Policy Enforcement',
                        'description' => sprintf('Source verification blocked installation of File Manager plugin directory ("%s").', esc_html($folder_name)),
                        'payload'     => "Folder: {$folder_name} Source: {$source}",
                    ], 'blocked');

                    return new \WP_Error(
                        'webcare_prohibited_plugin_source_fm',
                        __('Security Policy Violation: Installation of File Manager plugins is prohibited by WebCare Pro Security Firewall.', 'webcare-pro-security')
                    );
                }
            }
        }

        // Deep inspect candidate PHP plugin headers inside the unpacked folder
        if (!empty($settings['waf_disallow_phpmyadmin_plugins']) || !empty($settings['waf_disallow_filemanager_plugins'])) {
            $php_files = @glob(trailingslashit($source) . '*.php');
            if (!empty($php_files)) {
                foreach (array_slice($php_files, 0, 10) as $php_file) {
                    $header_content = @file_get_contents($php_file, false, null, 0, 8192);
                    if (empty($header_content)) {
                        continue;
                    }

                    // Check for database manager signatures in plugin header
                    if (!empty($settings['waf_disallow_phpmyadmin_plugins'])) {
                        if (
                            preg_match('/Plugin Name:\s*.*(?:phpmyadmin|adminer|database\s*browser|db-?manager|database\s*manager|sql\s*buddy)/i', $header_content) ||
                            stripos($header_content, 'PMA_sendHeaderLocation') !== false ||
                            stripos($header_content, 'Adminer - Compact database') !== false
                        ) {
                            self::log_incident([
                                'category'    => 'Security Policy Enforcement',
                                'description' => sprintf('Deep inspection blocked database manager plugin header in "%s".', esc_html(basename($php_file))),
                                'payload'     => "File: " . basename($php_file),
                            ], 'blocked');

                            return new \WP_Error(
                                'webcare_prohibited_plugin_header_pma',
                                __('Security Policy Violation: Plugin header identifies as a prohibited database manager (phpMyAdmin/Adminer).', 'webcare-pro-security')
                            );
                        }
                    }

                    // Check for file manager signatures in plugin header
                    if (!empty($settings['waf_disallow_filemanager_plugins'])) {
                        if (
                            preg_match('/Plugin Name:\s*.*(?:file\s*manager|fileorganizer|filester|elfinder|tinyfilemanager|file\s*explorer)/i', $header_content) ||
                            stripos($header_content, 'TinyFileManager') !== false ||
                            stripos($header_content, 'elFinder') !== false
                        ) {
                            self::log_incident([
                                'category'    => 'Security Policy Enforcement',
                                'description' => sprintf('Deep inspection blocked file manager plugin header in "%s".', esc_html(basename($php_file))),
                                'payload'     => "File: " . basename($php_file),
                            ], 'blocked');

                            return new \WP_Error(
                                'webcare_prohibited_plugin_header_fm',
                                __('Security Policy Violation: Plugin header identifies as a prohibited File Manager plugin.', 'webcare-pro-security')
                            );
                        }
                    }
                }
            }
        }

        return $source;
    }

    /**
     * Filter WordPress.org Plugins API results to prevent 1-click install/queries of prohibited plugins
     */
    public static function filter_prohibited_plugin_api($res, $action, $args) {
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_enabled'])) {
            return $res;
        }

        if ($action === 'plugin_information' && isset($args->slug)) {
            $slug = strtolower($args->slug);

            if (!empty($settings['waf_disallow_phpmyadmin_plugins'])) {
                $pma_signatures = [
                    'phpmyadmin', 'database-browser', 'sql-buddy', 'sqlbuddy', 'adminer',
                    'wp-phpmyadmin', 'wp-database-manager', 'database-management',
                    'dbmanager', 'db-manager', 'database-manager', 'mysql-manager',
                    'ari-adminer', 'portable-phpmyadmin'
                ];
                foreach ($pma_signatures as $sig) {
                    if (strpos($slug, $sig) !== false) {
                        return new \WP_Error(
                            'webcare_disallowed_plugin',
                            __('Security Policy: phpMyAdmin and database manager plugins are blocked by WebCare Pro Security Firewall.', 'webcare-pro-security')
                        );
                    }
                }
            }

            if (!empty($settings['waf_disallow_filemanager_plugins'])) {
                $fm_signatures = [
                    'file-manager', 'filemanager', 'fileorganizer', 'filester',
                    'advanced-file-manager', 'elfinder', 'tinyfilemanager', 'wp-file-manager',
                    'wp-filemanager', 'file-explorer', 'file-commander', 'file-browser'
                ];
                foreach ($fm_signatures as $sig) {
                    if (strpos($slug, $sig) !== false) {
                        return new \WP_Error(
                            'webcare_disallowed_plugin',
                            __('Security Policy: File Manager plugins are blocked by WebCare Pro Security Firewall.', 'webcare-pro-security')
                        );
                    }
                }
            }
        }

        return $res;
    }

    /**
     * Generic Login Error Masking (Rule 5)
     * Replaces detailed WordPress user enumeration errors with a generic message.
     */
    public static function mask_login_errors(string $error): string {
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_enabled']) || empty($settings['waf_mask_login_errors'])) {
            return $error;
        }

        if (!empty($error)) {
            return sprintf(
                '<strong>%s:</strong> %s',
                __('Error', 'webcare-pro-security'),
                __('Invalid username, email address, or password.', 'webcare-pro-security')
            );
        }

        return $error;
    }

    /**
     * Prevent Registering 'admin' or Forbidden Usernames (Rule 4)
     */
    public static function validate_registration_username(bool $valid, string $username): bool {
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_enabled']) || empty($settings['waf_prevent_admin_registration'])) {
            return $valid;
        }

        $sanitized = strtolower(trim($username));
        if ($sanitized === 'admin') {
            return false;
        }

        return $valid;
    }

    /**
     * Registration Errors Filter (Rule 4)
     */
    public static function filter_registration_errors(\WP_Error $errors, string $sanitized_user_login, string $user_email): \WP_Error {
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_enabled']) || empty($settings['waf_prevent_admin_registration'])) {
            return $errors;
        }

        $lower = strtolower(trim($sanitized_user_login));
        if ($lower === 'admin') {
            $errors->add(
                'registration_admin_prohibited',
                __('<strong>Error:</strong> The username "admin" is reserved and prohibited for security.', 'webcare-pro-security')
            );
        }

        return $errors;
    }

    /**
     * Immediately Block IP of Users Trying to Sign in as Forbidden Usernames (Rule 3)
     */
    public static function check_forbidden_username_login($user, $username, $password) {
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_enabled']) || empty($settings['waf_block_forbidden_usernames'])) {
            return $user;
        }

        if (empty($username) || !is_string($username)) {
            return $user;
        }

        $forbidden_raw = $settings['waf_forbidden_usernames_list'] ?? "admin\nadministrator\nroot";
        $forbidden_list = array_filter(array_map('trim', explode("\n", str_replace("\r", "", strtolower($forbidden_raw)))));
        if (empty($forbidden_list)) {
            $forbidden_list = ['admin', 'administrator', 'root'];
        }

        $test_user = strtolower(trim($username));
        if (in_array($test_user, $forbidden_list, true)) {
            $client_ip = self::get_client_ip();

            // Skip whitelisted IPs (with forensic telemetry)
            $whitelist_ctx = self::check_ip_whitelist_context($client_ip, $settings);
            if ($whitelist_ctx['is_whitelisted']) {
                $log_telemetry = isset($settings['waf_whitelist_log_telemetry']) ? !empty($settings['waf_whitelist_log_telemetry']) : true;
                if ($log_telemetry) {
                    self::log_incident([
                        'id'          => 'WAF-FORBIDDEN-USERNAME-TRAP',
                        'name'        => 'Forbidden Honeypot Username Trap (Bypassed)',
                        'category'    => 'Identity Defense',
                        'description' => sprintf('Whitelisted IP tried to log in using honeypot username "%s" [Bypassed via IP Whitelist].', esc_html($username)),
                        'match_type'  => 'Honeypot Username',
                        'match_value' => $username,
                        'payload'     => "User: {$username} IP: {$client_ip}",
                    ], 'bypassed');
                }
                return $user;
            }

            $honeypot_incident_id = 'WEBCARE-' . strtoupper(substr(md5($client_ip . microtime(true) . wp_rand()), 0, 8));
            self::log_incident([
                'id'          => 'WAF-FORBIDDEN-USERNAME-TRAP',
                'name'        => 'Forbidden Honeypot Username Attempt',
                'category'    => 'Identity Defense',
                'description' => sprintf('Login attempt using forbidden username "%s" rejected and counted toward login lockout.', esc_html($username)),
                'match_type'  => 'Forbidden Username',
                'match_value' => $username,
                'payload'     => "User: {$username} IP: {$client_ip}",
            ], 'blocked', $honeypot_incident_id);

            return new \WP_Error(
                'incorrect_password',
                __('<strong>Error:</strong> The username or password you entered is incorrect.', 'webcare-pro-security')
            );
        }

        return $user;
    }

    /**
     * Enforce Strong Passwords & Check Pwned Passwords on Profile Update (Rules 6 & 7)
     */
    public static function validate_user_password_policy(\WP_Error $errors, bool $update, \stdClass $user): void {
        // phpcs:disable WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
        $pass1 = isset($_POST['pass1']) ? (string) wp_unslash($_POST['pass1']) : '';
        // phpcs:enable WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
        if (empty($pass1)) {
            return;
        }

        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_enabled'])) {
            return;
        }

        // Get user roles
        $target_roles = [];
        if (!empty($user->roles) && is_array($user->roles)) {
            $target_roles = $user->roles;
        } elseif (!empty($user->role)) {
            $target_roles = [$user->role];
        } elseif (!empty($user->ID)) {
            $existing = get_userdata($user->ID);
            if ($existing) {
                $target_roles = (array) $existing->roles;
            }
        }

        // 1. Strong Passwords Check (Rule 6)
        if (!empty($settings['waf_enforce_strong_passwords'])) {
            $configured_roles_raw = $settings['waf_strong_passwords_roles'] ?? 'administrator, editor';
            $configured_roles = array_map('trim', explode(',', strtolower($configured_roles_raw)));

            $role_match = false;
            foreach ($target_roles as $r) {
                if (in_array(strtolower($r), $configured_roles, true)) {
                    $role_match = true;
                    break;
                }
            }

            if ($role_match && !self::check_password_strength($pass1)) {
                $errors->add(
                    'webcare_weak_password',
                    __('<strong>Security Policy:</strong> Your role requires a strong password. It must be at least 12 characters long and include uppercase letters, lowercase letters, numbers, and symbols.', 'webcare-pro-security')
                );
            }
        }

        // 2. Leaked / Pwned Passwords Check (Rule 7)
        if (!empty($settings['waf_check_pwned_passwords'])) {
            if (self::is_password_pwned($pass1)) {
                $errors->add(
                    'webcare_pwned_password',
                    __('<strong>Security Breach Warning:</strong> This password has appeared in known public data breaches and cannot be used. Please choose a different, secure password.', 'webcare-pro-security')
                );
            }
        }
    }

    /**
     * Enforce Strong Passwords & Check Pwned Passwords on Reset Password (Rules 6 & 7)
     */
    public static function validate_reset_password_policy(\WP_Error $errors, $user): void {
        // phpcs:disable WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
        $pass1 = isset($_POST['pass1']) ? (string) wp_unslash($_POST['pass1']) : '';
        // phpcs:enable WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
        if (empty($pass1) || !is_object($user)) {
            return;
        }

        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_enabled'])) {
            return;
        }

        $target_roles = (array) ($user->roles ?? []);

        // Strong password check
        if (!empty($settings['waf_enforce_strong_passwords'])) {
            $configured_roles_raw = $settings['waf_strong_passwords_roles'] ?? 'administrator, editor';
            $configured_roles = array_map('trim', explode(',', strtolower($configured_roles_raw)));

            $role_match = false;
            foreach ($target_roles as $r) {
                if (in_array(strtolower($r), $configured_roles, true)) {
                    $role_match = true;
                    break;
                }
            }

            if ($role_match && !self::check_password_strength($pass1)) {
                $errors->add(
                    'webcare_weak_password',
                    __('<strong>Security Policy:</strong> Your role requires a strong password. It must be at least 12 characters long and include uppercase letters, lowercase letters, numbers, and symbols.', 'webcare-pro-security')
                );
            }
        }

        // Leaked password check
        if (!empty($settings['waf_check_pwned_passwords'])) {
            if (self::is_password_pwned($pass1)) {
                $errors->add(
                    'webcare_pwned_password',
                    __('<strong>Security Breach Warning:</strong> This password has appeared in known public data breaches and cannot be used. Please choose a different, secure password.', 'webcare-pro-security')
                );
            }
        }
    }

    /**
     * Validate password complexity: Min 12 chars, upper, lower, number, symbol
     */
    public static function check_password_strength(string $password): bool {
        if (strlen($password) < 12) {
            return false;
        }
        if (!preg_match('/[A-Z]/', $password)) {
            return false;
        }
        if (!preg_match('/[a-z]/', $password)) {
            return false;
        }
        if (!preg_match('/[0-9]/', $password)) {
            return false;
        }
        if (!preg_match('/[^A-Za-z0-9]/', $password)) {
            return false;
        }
        return true;
    }

    /**
     * Check if a password was compromised in public data breaches using HaveIBeenPwned k-Anonymity API
     */
    public static function is_password_pwned(string $password): bool {
        $hash   = strtoupper(sha1($password));
        $prefix = substr($hash, 0, 5);
        $suffix = substr($hash, 5);

        $url = 'https://api.pwnedpasswords.com/range/' . $prefix;
        $response = wp_remote_get($url, [
            'timeout'   => 3,
            'sslverify' => true,
            'headers'   => [
                'User-Agent' => 'WEBCARE-Security-Scanner-Password-Sentinel/1.0',
            ],
        ]);

        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            // Fail open if HIBP API is unreachable to prevent locking out legitimate admins
            return false;
        }

        $body = wp_remote_retrieve_body($response);
        $lines = explode("\n", str_replace("\r", "", $body));

        foreach ($lines as $line) {
            $parts = explode(':', trim($line));
            if (strtoupper($parts[0]) === $suffix) {
                $count = isset($parts[1]) ? (int) $parts[1] : 0;
                if ($count > 0) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Handle firewall rule violation with mode sensitivity (learning vs blocking).
     *
     * @param array  $rule
     * @param array  $settings
     * @param string $client_ip
     * @param int    $status_code
     * @return void
     */
    /**
     * Determine if an IP matches the configured whitelist and whether the current session qualifies for complete bypass.
     *
     * Two-Tier Context-Aware Architecture:
     * - Tier 1 (Pre-Auth): IP is in whitelist, but user is NOT logged in as Administrator.
     *   Can bypass operational/rate-limiting/debug rules, but CANNOT bypass critical exploits (SQLi, Webshell, RCE, LFI).
     * - Tier 2 (Post-Auth): IP is in whitelist AND user is verified Authenticated Administrator.
     *   Full developer/administrator bypass across all firewall checks.
     *
     * @param string $client_ip
     * @param array  $settings
     * @return array [ 'is_whitelisted' => bool, 'is_admin' => bool, 'full_bypass' => bool ]
     */
    public static function check_ip_whitelist_context(string $client_ip, array $settings, ?array $rule = null): array {
        return Core\AllowlistManager::check_ip_whitelist_context($client_ip, $settings, $rule);
    }

    /**
     * Authoritatively determines if an IP allowlist context permits bypassing a firewall rule violation.
     * Enforces the invariant that pre-authenticated traffic can NEVER bypass confirmed exploits or critical categories.
     *
     * @param bool $is_admin             Whether the session is a verified authenticated administrator.
     * @param bool $full_bypass          Whether global full bypass is granted.
     * @param bool $rule_bypass          Whether scoped rule/category bypass matched.
     * @param bool $is_critical_exploit  Whether the rule is a confirmed exploit or critical attack category.
     * @return bool True if bypass is permitted, false otherwise.
     */
    public static function can_ip_whitelist_bypass_rule(bool $is_admin, bool $full_bypass, bool $rule_bypass, bool $is_critical_exploit): bool {
        return Core\AllowlistManager::can_ip_whitelist_bypass_rule($is_admin, $full_bypass, $rule_bypass, $is_critical_exploit);
    }

    public const TIER_HEURISTIC         = 'heuristic';
    public const TIER_CONFIRMED_EXPLOIT = 'confirmed_exploit';
    public const TIER_ADMIN_POLICY      = 'admin_policy';

    /**
     * Authoritatively resolve the enforcement classification tier of a firewall rule.
     * Enforces trusted provenance and guarantees unknown or heuristic rules default
     * fail-safe to TIER_HEURISTIC (block individual request; zero automated IP bans).
     *
     * @param array $rule
     * @return string 'heuristic' | 'confirmed_exploit' | 'admin_policy'
     */
    public static function get_rule_enforcement_tier(array $rule): string {
        return Core\ViolationResponder::get_rule_enforcement_tier($rule);
    }

    private static ?array $confirmed_exploit_registry = null;

    /**
     * Authoritative Internal Signature Registry of genuine confirmed exploit rules.
     * Unknown, unverified, or caller-fabricated rule IDs are strictly excluded.
     *
     * @return array<string, array<string, string>>
     */
    private static function get_confirmed_exploit_registry(): array {
        if (self::$confirmed_exploit_registry === null) {
            self::$confirmed_exploit_registry = [
                // Core Exploit Signatures (ExploitSignatureEngine & FirewallEngine)
                'WAF-SQLI-INJECTION'                    => [
                    'category' => 'SQL Injection',
                    'detector' => 'ExploitSignatureEngine',
                    'sig_id'   => 'sig:sqli:union_information_schema_sleep',
                ],
                'WAF-SQLI-ARMOR'                        => [
                    'category' => 'SQL Injection',
                    'detector' => 'ExploitSignatureEngine',
                    'sig_id'   => 'sig:sqli:armor_blind_polyglot',
                ],
                'WAF-RCE-PHP-INJECTION'                 => [
                    'category' => 'PHP Code Injection',
                    'detector' => 'ExploitSignatureEngine',
                    'sig_id'   => 'sig:rce:eval_system_passthru_base64',
                ],
                'WAF-PHP-CODE-INJECTION'                => [
                    'category' => 'PHP Code Injection',
                    'detector' => 'ExploitSignatureEngine',
                    'sig_id'   => 'sig:rce:script_tags_dangerous_functions',
                ],
                'WAF-LFI-TRAVERSAL'                     => [
                    'category' => 'Path Traversal',
                    'detector' => 'ExploitSignatureEngine',
                    'sig_id'   => 'sig:lfi:dot_slash_etc_passwd_php_wrappers',
                ],
                'WAF-PATH-TRAVERSAL'                    => [
                    'category' => 'Path Traversal',
                    'detector' => 'ExploitSignatureEngine',
                    'sig_id'   => 'sig:lfi:canonical_traversal_segments',
                ],
                'WAF-OBJECT-STREAM-INJECTION'           => [
                    'category' => 'Execution Armor',
                    'detector' => 'ExploitSignatureEngine',
                    'sig_id'   => 'sig:armor:pop_gadget_phar_stream_wrapper',
                ],
                'WAF-AJAX-SHORTCODE-GADGET'             => [
                    'category' => 'PHP Code Injection',
                    'detector' => 'ExploitSignatureEngine',
                    'sig_id'   => 'sig:rce:ajax_shortcode_gadget_chain',
                ],
                'WAF-NULL-BYTE-POISON'                  => [
                    'category' => 'Null Byte Poison',
                    'detector' => 'ExploitSignatureEngine',
                    'sig_id'   => 'sig:poison:null_byte_terminator',
                ],
                'WAF-WP7-INTERACTIVITY-POISON'          => [
                    'category' => 'Execution Armor',
                    'detector' => 'ExploitSignatureEngine',
                    'sig_id'   => 'sig:armor:wp7_interactivity_attribute_poison',
                ],
                'WAF-SSRF-METADATA'                     => [
                    'category' => 'SSRF Defense',
                    'detector' => 'ExploitSignatureEngine',
                    'sig_id'   => 'sig:ssrf:cloud_metadata_link_local',
                ],
                'WAF-POLYGLOT-UPLOAD-TRAP'              => [
                    'category' => 'Malicious File Upload',
                    'detector' => 'ExploitSignatureEngine',
                    'sig_id'   => 'sig:upload:polyglot_embedded_script',
                ],
                'WAF-SVGZ-DECOMPRESSION-BOMB-OR-ERROR'  => [
                    'category' => 'Malicious File Upload',
                    'detector' => 'ExploitSignatureEngine',
                    'sig_id'   => 'sig:upload:svgz_decompression_bomb',
                ],
                'WAF-UPLOAD-SCAN-INCOMPLETE-OR-MUTATED' => [
                    'category' => 'Malicious File Upload',
                    'detector' => 'ExploitSignatureEngine',
                    'sig_id'   => 'sig:upload:incomplete_mutated_stream',
                ],
                'WAF-UPLOADS-PHP-DENY'                  => [
                    'category' => 'Execution Armor',
                    'detector' => 'FirewallEngine',
                    'sig_id'   => 'sig:armor:php_upload_execution_deny',
                ],
                'WAF-UNAUTHORIZED-PUT-UPLOAD'           => [
                    'category' => 'Protocol Defense',
                    'detector' => 'FirewallEngine',
                    'sig_id'   => 'sig:proto:unauthorized_put_request',
                ],
                'WAF-FORGED-WEBHOOK-TRAP'               => [
                    'category' => 'Execution Armor',
                    'detector' => 'FirewallEngine',
                    'sig_id'   => 'sig:proto:forged_webhook_signature',
                ],
                'WAF-AUTH-TYPE-CONFUSION'               => [
                    'category' => 'Brute Force & Auth Armor',
                    'detector' => 'FirewallEngine',
                    'sig_id'   => 'sig:proto:auth_header_type_confusion',
                ],
                'WAF-REST-METHOD-SMUGGLE'               => [
                    'category' => 'Execution Armor',
                    'detector' => 'FirewallEngine',
                    'sig_id'   => 'sig:proto:rest_method_override_smuggle',
                ],
                'WAF-LOG-EXFILTRATION-TRAP'             => [
                    'category' => 'Incident Containment',
                    'detector' => 'FirewallEngine',
                    'sig_id'   => 'sig:contain:log_poison_and_exfil',
                ],
            ];
        }
        return self::$confirmed_exploit_registry;
    }

    /**
     * Authoritatively verify whether a rule matches a genuine, registered exploit signature
     * in the trusted internal signature registry.
     * Enforces that all four trust anchors are present and authentic:
     * (a) Exact registered rule ID
     * (b) Matching canonical category
     * (c) Mandatory authorized detector provenance ('detector' / 'detector_id')
     * (d) Mandatory immutable signature identifier ('sig_id')
     * If any is missing, empty, or mismatched, or if $rule is empty, fail-safe to TIER_HEURISTIC (zero automated IP bans).
     *
     * @param string $rule_id_str Uppercase rule ID
     * @param array  $rule        Rule definition array
     * @return bool
     */
    public static function is_registered_confirmed_exploit_rule(string $rule_id_str, array $rule = []): bool {
        if ($rule_id_str === '' || empty($rule)) {
            return false;
        }

        $registry = self::get_confirmed_exploit_registry();
        if (isset($registry[$rule_id_str])) {
            $registered = $registry[$rule_id_str];

            // 1. Mandatory Category Verification
            $incoming_cat  = trim((string) ($rule['category'] ?? ''));
            $canonical_cat = trim((string) ($registered['category'] ?? ''));
            if ($incoming_cat === '' || strcasecmp($incoming_cat, $canonical_cat) !== 0) {
                return false; // Rejects genuine IDs with missing, empty, or forged categories
            }

            // 2. Mandatory Authorized Detector Provenance Verification
            $incoming_detector = trim((string) ($rule['detector'] ?? ($rule['detector_id'] ?? '')));
            $expected_detector = trim((string) ($registered['detector'] ?? ''));
            if ($incoming_detector === '' || strcasecmp($incoming_detector, $expected_detector) !== 0) {
                return false; // Rejects missing, unauthorized, or mismatched detector provenance claims
            }

            // 3. Mandatory Immutable Signature ID Verification
            $incoming_sig = trim((string) ($rule['sig_id'] ?? ''));
            $expected_sig = trim((string) ($registered['sig_id'] ?? ''));
            if ($incoming_sig === '' || strcasecmp($incoming_sig, $expected_sig) !== 0) {
                return false; // Rejects missing or mismatched signature identifier
            }

            return true;
        }

        // Curated CVE Virtual Patches (VPATCH-CVE-*) verified against VirtualPatchManager
        if (str_starts_with($rule_id_str, 'VPATCH-')) {
            $patch_id = substr($rule_id_str, 7);
            if (class_exists('\\WebCareProScanner\\Firewall\\VirtualPatchManager')) {
                $catalog = \WebCareProScanner\Firewall\VirtualPatchManager::get_patch_catalog();
                if (isset($catalog[$patch_id])) {
                    // 1. Mandatory Category Verification
                    $incoming_cat      = strtolower(trim((string) ($rule['category'] ?? '')));
                    $valid_vpatch_cats = ['virtual patch (cve shield)', 'virtual patch', 'cve patch'];
                    if ($incoming_cat === '' || !in_array($incoming_cat, $valid_vpatch_cats, true)) {
                        return false; // Rejects genuine patch IDs carrying forged or missing category
                    }

                    // 2. Mandatory Detector Provenance Verification
                    $incoming_detector = strtolower(trim((string) ($rule['detector'] ?? ($rule['detector_id'] ?? ''))));
                    if ($incoming_detector !== 'virtualpatchmanager') {
                        return false; // Rejects missing or unauthorized detector for virtual patch
                    }

                    // 3. Mandatory Signature ID Verification: must match 'cve:' . strtolower($patch_id)
                    $incoming_sig = strtolower(trim((string) ($rule['sig_id'] ?? '')));
                    $expected_sig = 'cve:' . strtolower($patch_id);
                    if ($incoming_sig !== $expected_sig) {
                        return false; // Rejects missing or mismatched signature identifier for virtual patch
                    }

                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Retrieve the canonical definition for the private detector enforcement path.
     *
     * @param string $rule_id_str
     * @return array|null Canonical metadata array or null if not registered.
     */
    public static function get_confirmed_exploit_definition(string $rule_id_str): ?array {
        $registry = self::get_confirmed_exploit_registry();
        if (isset($registry[$rule_id_str])) {
            return array_merge([
                'id'       => $rule_id_str,
                'tier'     => self::TIER_CONFIRMED_EXPLOIT,
                'detector' => $registry[$rule_id_str]['detector'],
                'sig_id'   => $registry[$rule_id_str]['sig_id'],
            ], $registry[$rule_id_str]);
        }

        if (str_starts_with($rule_id_str, 'VPATCH-') && class_exists('\\WebCareProScanner\\Firewall\\VirtualPatchManager')) {
            $patch_id = substr($rule_id_str, 7);
            $catalog  = \WebCareProScanner\Firewall\VirtualPatchManager::get_patch_catalog();
            if (isset($catalog[$patch_id])) {
                $patch = $catalog[$patch_id];
                return [
                    'id'          => 'VPATCH-' . $patch_id,
                    'name'        => $patch['title'] ?? ($patch['name'] ?? 'CVE Virtual Patch'),
                    'category'    => 'Virtual Patch (CVE Shield)',
                    'tier'        => self::TIER_CONFIRMED_EXPLOIT,
                    'detector'    => 'VirtualPatchManager',
                    'sig_id'      => 'cve:' . strtolower($patch_id),
                    'description' => $patch['description'] ?? 'Curated CVE Virtual Patch',
                ];
            }
        }

        return null;
    }

    /**
     * Authoritatively verify whether a rule corresponds to an authentic,
     * administrator-authored custom rule stored in the verified modular rules database repository.
     * Returns the verified stored rule array on success, or null on rejection.
     *
     * @param array $rule
     * @return array|null
     */
    public static function get_verified_admin_custom_rule(array $rule): ?array {
        $rule_id = (string) ($rule['id'] ?? '');
        if ($rule_id === '') {
            return null;
        }

        if (class_exists('\\WebCareProScanner\\Firewall\\Modular\\ModularFirewallSynthesizer')) {
            return \WebCareProScanner\Firewall\Modular\ModularFirewallSynthesizer::verify_admin_custom_rule($rule);
        }

        return null;
    }

    /**
     * Backward-compatible boolean helper.
     *
     * @param array $rule
     * @return bool
     */
    public static function is_verified_admin_custom_rule(array $rule): bool {
        return self::get_verified_admin_custom_rule($rule) !== null;
    }

    /**
     * Handle firewall rule violation with mode sensitivity (learning vs blocking).
     *
     * @param array  $rule
     * @param array  $settings
     * @param string $client_ip
     * @param int    $status_code
     * @return void
     */
    public static function handle_rule_violation(array $rule, array $settings, string $client_ip, int $status_code = 403): void {
        Core\ViolationResponder::handle_rule_violation($rule, $settings, $client_ip, $status_code);
    }

    /**
     * Strict Host Header & Forwarded Host Header Allowlist Validator (Rule #32).
     * Defends against Host Header Poisoning, Password Reset Poisoning, and Cache Poisoning.
     *
     * @param array $settings
     * @return bool
     */
    public static function validate_host_headers(array $settings): bool {
        $raw_host = isset($_SERVER['HTTP_HOST']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_HOST'])) : '';
        if (empty($raw_host)) {
            return false;
        }

        // Strip port if present (e.g. localhost:8181 -> localhost)
        $clean_host = strtolower(trim(preg_replace('/:\d+$/', '', $raw_host)));

        // Build list of valid hosts from site_url, home_url, and optional aliases
        $allowed = [];

        $site_host = wp_parse_url(site_url(), PHP_URL_HOST);
        if ($site_host) {
            $allowed[] = strtolower($site_host);
        }

        $home_host = wp_parse_url(home_url(), PHP_URL_HOST);
        if ($home_host) {
            $allowed[] = strtolower($home_host);
        }

        // Automatically tolerate www vs non-www variant of configured site domains
        foreach ([$site_host, $home_host] as $h) {
            if ($h) {
                $h = strtolower($h);
                if (strpos($h, 'www.') === 0) {
                    $allowed[] = substr($h, 4);
                } else {
                    $allowed[] = 'www.' . $h;
                }
            }
        }

        // Custom administrator aliases
        $custom_aliases = $settings['waf_allowed_host_aliases'] ?? '';
        if (!empty($custom_aliases)) {
            $lines = preg_split('/[\r\n,]+/', $custom_aliases);
            foreach ($lines as $line) {
                $alias = strtolower(trim($line));
                if ($alias !== '') {
                    $alias = preg_replace('/:\d+$/', '', $alias);
                    $allowed[] = $alias;
                }
            }
        }

        $allowed = array_unique(array_filter($allowed));

        // 1. Verify HTTP_HOST against allowed list
        if (!in_array($clean_host, $allowed, true)) {
            return false;
        }

        // 2. If HTTP_X_FORWARDED_HOST is present, every host segment MUST strictly match the allowed list and cannot contain @
        if (!empty($_SERVER['HTTP_X_FORWARDED_HOST'])) {
            $fwd_raw = explode(',', sanitize_text_field(wp_unslash($_SERVER['HTTP_X_FORWARDED_HOST'])));
            foreach ($fwd_raw as $raw_seg) {
                $fwd_host = strtolower(trim(preg_replace('/:\d+$/', '', $raw_seg)));
                if ($fwd_host === '' || strpos($fwd_host, '@') !== false || !in_array($fwd_host, $allowed, true)) {
                    return false;
                }
            }
        }

        return true;
    }

    /**
     * Sliding Transient Rate Limiter for firewall controls.
     * Delegates to TransientRateLimiter single-responsibility service.
     *
     * @param string $key Unique identifier (e.g. 'lostpw:ip:127.0.0.1')
     * @param int    $limit Max requests allowed
     * @param int    $window_seconds Window duration in seconds
     * @return array ['allowed' => bool, 'retry_after' => int, 'current' => int]
     */
    public static function check_rate_limit(string $key, int $limit, int $window_seconds): array {
        return \WebCareProScanner\Firewall\Core\TransientRateLimiter::check_rate_limit($key, $limit, $window_seconds);
    }

    /**
     * Rule #29: REST API User Enumeration Interceptor.
     * Blocks unauthenticated access to /wp-json/wp/v2/users, user archives, and ?rest_route=/wp/v2/users.
     *
     * @param mixed $access
     * @return mixed
     */
    public static function check_rest_user_enumeration($access) {
        if (is_wp_error($access)) {
            return $access;
        }

        // Authenticated users are completely permitted
        if (is_user_logged_in() || self::is_authenticated_administrator()) {
            return $access;
        }

        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_enabled']) || ($settings['waf_mode'] ?? 'enabled') === 'disabled') {
            return $access;
        }

        if (empty($settings['waf_block_rest_user_enum'])) {
            return $access;
        }

        $request_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Public REST query check
        $rest_route  = isset($_GET['rest_route']) ? sanitize_text_field(wp_unslash($_GET['rest_route'])) : null;
        $canonical_route = self::canonicalize_rest_route($request_uri, $rest_route);

        // Check for /wp/v2/users endpoint queries
        $is_user_endpoint = ($canonical_route === '/wp/v2/users' || str_starts_with($canonical_route, '/wp/v2/users/'));

        if (!$is_user_endpoint) {
            return $access;
        }

        // Allow /wp/v2/users/me (standard profile query) to flow to core auth handler
        // Canonical comparison prevents query-string smuggling (e.g. /wp/v2/users?bypass=/wp/v2/users/me)
        if ($canonical_route === '/wp/v2/users/me') {
            return $access;
        }

        $client_ip = self::get_client_ip();

        $rule_triggered = [
            'id'          => 'WAF-REST-USER-ENUM',
            'name'        => 'REST API User Enumeration Interceptor',
            'category'    => 'Reconnaissance & Enumeration',
            'description' => 'Unauthenticated REST API user enumeration request intercepted on /wp/v2/users.',
            'match_type'  => 'REST Route Intercept',
            'match_value' => '/wp/v2/users',
            'payload'     => "URI: {$request_uri} IP: {$client_ip}",
        ];

        $whitelist_ctx = self::check_ip_whitelist_context($client_ip, $settings);
        if ($whitelist_ctx['is_whitelisted']) {
            if ($whitelist_ctx['full_bypass'] || true) { // User enumeration is an operational probe, whitelisted IP can bypass
                $log_telemetry = isset($settings['waf_whitelist_log_telemetry']) ? !empty($settings['waf_whitelist_log_telemetry']) : true;
                if ($log_telemetry) {
                    $bypass_rule = $rule_triggered;
                    $bypass_rule['description'] .= ' [Bypassed via IP Whitelist]';
                    self::log_incident($bypass_rule, 'bypassed');
                }
                return $access;
            }
        }

        $mode = $settings['waf_mode'] ?? 'enabled';
        if ($mode === 'learning') {
            self::log_incident($rule_triggered, 'detected');
            return $access;
        }

        self::log_incident($rule_triggered, 'blocked');

        return new \WP_Error(
            'rest_user_enum_forbidden',
            __('User enumeration via REST API is disabled by WebCare Pro Security Firewall.', 'webcare-pro-security'),
            ['status' => 403]
        );
    }

    /**
     * Rule #30: Author Permalink Query Suppression (?author=N).
     * Defends against query-based author enumeration scans that probe WordPress user IDs to harvest usernames.
     *
     * @return void
     */
    public static function check_author_scan_suppression(): void {
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Author enumeration scan inspection
        if (!isset($_GET['author'])) {
            return;
        }

        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_enabled']) || ($settings['waf_mode'] ?? 'enabled') === 'disabled') {
            return;
        }

        if (empty($settings['waf_block_author_scan'])) {
            return;
        }

        // Only suppress if unauthenticated or non-editor (editors may need author filters in admin)
        if (is_admin() || current_user_can('edit_others_posts')) {
            return;
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $author_param = isset($_GET['author']) ? sanitize_text_field(wp_unslash($_GET['author'])) : '';
        if (!preg_match('/^[0-9]+$/', trim($author_param))) {
            return;
        }

        $client_ip = self::get_client_ip();

        $rule_triggered = [
            'id'          => 'WAF-AUTHOR-ENUM',
            'name'        => 'Author Permalink Enumeration Suppression',
            'category'    => 'Reconnaissance & Enumeration',
            'description' => sprintf('Author ID enumeration query (?author=%s) blocked from harvesting usernames.', esc_html($author_param)),
            'match_type'  => 'Author Query Probe',
            'match_value' => '?author=' . $author_param,
            'payload'     => "URI: {$author_param} IP: {$client_ip}",
        ];

        $whitelist_ctx = self::check_ip_whitelist_context($client_ip, $settings);
        if ($whitelist_ctx['is_whitelisted']) {
            $log_telemetry = isset($settings['waf_whitelist_log_telemetry']) ? !empty($settings['waf_whitelist_log_telemetry']) : true;
            if ($log_telemetry) {
                $bypass_rule = $rule_triggered;
                $bypass_rule['description'] .= ' [Bypassed via IP Whitelist]';
                self::log_incident($bypass_rule, 'bypassed');
            }
            return;
        }

        $mode = $settings['waf_mode'] ?? 'enabled';
        if ($mode === 'learning') {
            self::log_incident($rule_triggered, 'detected');
            return;
        }

        self::log_incident($rule_triggered, 'blocked');

        // Clean suppression: 301 Permanent Redirect to homepage, preventing username enumeration leaks
        wp_safe_redirect(home_url('/'), 301);
        exit;
    }

    /**
     * Rule #31: Lost-Password Rate Limiter on Form View (GET).
     * Prevents automated bots from flooding the lost password endpoint.
     *
     * @return void
     */
    public static function check_lostpassword_flood(): void {
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_enabled']) || ($settings['waf_mode'] ?? 'enabled') === 'disabled') {
            return;
        }

        if (empty($settings['waf_limit_lostpassword'])) {
            return;
        }

        $client_ip = self::get_client_ip();

        // Allow max 10 view requests per 15 minutes per IP
        $rate_check = self::check_rate_limit('lostpw_view:' . md5($client_ip), 10, 900);
        if (!$rate_check['allowed']) {
            $rule_triggered = [
                'id'          => 'WAF-LOSTPW-VIEW-FLOOD',
                'name'        => 'Lost-Password View Burst Limit Exceeded',
                'category'    => 'Brute Force & Auth Armor',
                'description' => 'Client IP exceeded threshold for lost-password page views.',
                'match_type'  => 'Form Rate Limiting',
                'match_value' => $client_ip,
                'payload'     => "IP: {$client_ip}",
            ];

            self::handle_rule_violation($rule_triggered, $settings, $client_ip, 429);
                    }
    }

    /**
     * Rule #31: Lost-Password Reset Submission Guard (POST).
     * Rate-limits password reset email triggers per IP (max 3 / 15m) and per target user (max 3 / 15m).
     * Defends against transactional email quota exhaustion and inbox bombing.
     *
     * @return void
     */
    public static function check_lostpassword_submission(): void {
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_enabled']) || ($settings['waf_mode'] ?? 'enabled') === 'disabled') {
            return;
        }

        if (empty($settings['waf_limit_lostpassword'])) {
            return;
        }

        $client_ip = self::get_client_ip();

        // 1. IP-based limit: max 3 reset submissions per 15 minutes
        $ip_check = self::check_rate_limit('lostpw_post_ip:' . md5($client_ip), 3, 900);
        if (!$ip_check['allowed']) {
            $rule_triggered = [
                'id'          => 'WAF-LOSTPW-FLOOD-IP',
                'name'        => 'Lost-Password Request Flood Limit (IP)',
                'category'    => 'Brute Force & Auth Armor',
                'description' => sprintf('Too many password reset requests from IP (%s). Limit is 3 per 15 minutes.', $client_ip),
                'match_type'  => 'Email Flood Protection',
                'match_value' => $client_ip,
                'payload'     => "IP: {$client_ip} Submissions: {$ip_check['current']}",
            ];

            self::handle_rule_violation($rule_triggered, $settings, $client_ip, 429);
                    }

        // 2. User/Login identifier-based limit: max 3 reset submissions per target login/email per 15 minutes
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Lost password POST form submission rate limiting
        $user_login = isset($_POST['user_login']) ? sanitize_text_field(wp_unslash($_POST['user_login'])) : '';
        if (!empty($user_login)) {
            $user_key = 'lostpw_post_user:' . md5(strtolower(trim($user_login)));
            $user_check = self::check_rate_limit($user_key, 3, 900);
            if (!$user_check['allowed']) {
                $rule_triggered = [
                    'id'          => 'WAF-LOSTPW-FLOOD-USER',
                    'name'        => 'Lost-Password Target User Bombing Guard',
                    'category'    => 'Brute Force & Auth Armor',
                    'description' => 'Too many password reset requests targeted at this account identifier within 15 minutes.',
                    'match_type'  => 'Email Bombing Defense',
                    'match_value' => substr(md5($user_login), 0, 10),
                    'payload'     => "Target hash: " . md5($user_login) . " IP: {$client_ip}",
                ];

                self::handle_rule_violation($rule_triggered, $settings, $client_ip, 429);
                            }
        }
    }

    /**
     * Rule #36: Guest admin-ajax.php & admin-post.php Action Matrix Guard.
     * Evaluates unauthenticated visitors invoking WordPress backend entrypoints.
     * Enforces Tier 1 default allowed guest actions and custom administrator allowlist.
     * In 'monitor' mode: logs unknown probes to WAF telemetry without blocking.
     * In 'block' mode: terminates unregistered guest actions with HTTP 403 / 400.
     *
     * @param string $request_uri
     * @param array $settings
     * @param string $client_ip
     * @return void
     */
    public static function check_guest_ajax_policy(string $request_uri, array $settings, string $client_ip): void {
        $policy = $settings['waf_guest_ajax_policy'] ?? 'monitor';
        if ($policy === 'off') {
            return;
        }

        $clean_path = strtolower(wp_parse_url($request_uri, PHP_URL_PATH) ?: $request_uri);
        $is_ajax = strpos($clean_path, 'admin-ajax.php') !== false;
        $is_post = strpos($clean_path, 'admin-post.php') !== false;

        if (!$is_ajax && !$is_post) {
            return;
        }

        // Apply policy strictly to unauthenticated visitors
        $is_logged_in = (function_exists('is_user_logged_in') && is_user_logged_in())
            || self::is_authenticated_administrator()
            || self::is_authenticated_editor_or_builder();

        if ($is_logged_in) {
            return;
        }

        // Server Origin & Host Loopback Immunity:
        // Internal loopback requests originating from the server itself (e.g. Wordfence scan forks,
        // Gravity Forms background tasks, local wp-cron) are trusted internal operations.
        if (self::is_server_origin_or_loopback($client_ip)) {
            return;
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended -- Early guest action matrix inspection
        $action = isset($_POST['action']) ? sanitize_text_field(wp_unslash($_POST['action'])) : (isset($_GET['action']) ? sanitize_text_field(wp_unslash($_GET['action'])) : '');
        $endpoint_name = $is_ajax ? 'admin-ajax.php' : 'admin-post.php';

        // 1. Missing or Empty Action Handling
        if ($action === '') {
            $rule_triggered = [
                'id'          => 'WAF-GUEST-AJAX-EMPTY',
                'name'        => 'Guest Endpoint Missing Action Probe (Rule #36)',
                'category'    => 'Protocol Defense',
                'description' => sprintf('Unauthenticated hit to %s without an action parameter.', $endpoint_name),
                'match_type'  => 'Missing Action Probe',
                'match_value' => $endpoint_name,
                'payload'     => "Endpoint: {$endpoint_name} IP: {$client_ip}",
            ];

            if ($policy === 'block') {
                self::log_incident($rule_triggered, 'blocked');
                status_header(400);
                header('Content-Type: application/json; charset=utf-8');
                echo wp_json_encode([
                    'success' => false,
                    'data'    => 'Missing or invalid action parameter.'
                ]);
                exit;
            }

            // In monitor mode, record telemetry and allow fall-through to core
            self::log_incident($rule_triggered, 'monitored');
            return;
        }

        // 2. Tier 1 Built-in Allowed Actions Hash Map (O(1) lookup)
        static $tier1_actions = null;
        if ($tier1_actions === null) {
            $tier1_actions = array_fill_keys([
                // WordPress Core & Heartbeat
                'heartbeat',
                // WooCommerce Customer & Cart Lifecycle (Always permitted for guests regardless of session)
                'woocommerce_get_refreshed_fragments',
                'woocommerce_add_to_cart',
                'woocommerce_apply_coupon',
                'woocommerce_remove_coupon',
                'woocommerce_update_shipping_method',
                'woocommerce_update_order_review',
                'woocommerce_checkout',
                'woocommerce_get_customer_location',
                // Form Plugins (CF7, WPForms, Fluent Forms, Gravity Forms, Ninja Forms, Formidable, WS Form, HappyForms, Everest)
                'wpforms_submit',
                'wpforms_form_submit',
                'wpforms_file_upload',
                'fluentform_submit',
                'fluentform_file_upload',
                'fluentform_form_submit',
                'ninja_forms_ajax_submit',
                'nf_ajax_submit',
                'frm_entries_create',
                'frm_entries_update',
                'gform_submit',
                'gform_ajax',
                'wsf_submit',
                'happyforms_message',
                'everest_forms_ajax_submit',
                // Frontend Content Loaders & Live Search
                'load_more_posts',
                'infinite_scroll',
                'search_autocomplete',
                'ajax_search',
                'wp_ajax_nopriv_search',
                // WooCommerce Compliance, Tax & VAT Gateways (EAS EU Compliance, Avalara, TaxJar)
                'eascompliance_status_ajax',
                'eas_compliance_ajax',
                'eas_tax_calculation',
                'woocommerce_calc_line_taxes',
                // Security & Audit Companion Plugins (Wordfence Security loopbacks & test AJAX)
                'wordfence_doScan',
                'wordfence_testAjax',
                // Gravity Forms Personal Data & Upload Handlers
                'wp_gf_personal_data',
                'gf_ajax_upload',
                // Ninja Forms Guest File Upload Nonce Fetcher
                'nf_fu_get_new_nonce',
                // WooCommerce Payment Gateway Handshakes (PayPal Payments & Stripe Checkout AJAX)
                'ppc-sdk-v6-client-token',
                'ppc_create_order',
                'ppc_approve_order',
                'wc_stripe_create_order',
                'wc_stripe_get_cart_details',
            ], true);
        }

        // Only permit Plugin Check admin runner AJAX when executed by an authenticated admin or trusted runtime
        if ($action === 'plugin_check_run_checks' && (self::is_authenticated_administrator() || self::is_trusted_plugin_check_or_cli_runtime())) {
            return;
        }

        if (isset($tier1_actions[$action])) {
            // Rule #39: Check coupon lockout for apply_coupon action
            if ($action === 'apply_coupon' || $action === 'woocommerce_apply_coupon') {
                $coupon_lock_error = self::check_woo_coupon_lockout();
                if ($coupon_lock_error) {
                    if (wp_doing_ajax()) {
                        wp_send_json([
                            'result'   => 'failure',
                            'messages' => '<ul class="woocommerce-error" role="alert"><li>' . esc_html($coupon_lock_error->get_error_message()) . '</li></ul>',
                        ]);
                        exit;
                    }
                    if (function_exists('wc_add_notice')) {
                        wc_add_notice($coupon_lock_error->get_error_message(), 'error');
                    }
                }
            }
            return; // Legitimate Tier 1 guest action permitted
        }

        // Affiliate Ecosystem Public Guest AJAX Handlers (Only loaded if affiliate ecosystem is detected)
        if (class_exists(AffiliateSecurityEngine::class)
            && !empty(AffiliateSecurityEngine::get_detected_ecosystem()['is_active'])
            && AffiliateSecurityEngine::is_public_affiliate_ajax_action($action)
        ) {
            return;
        }

        // Smart E-Commerce & Checkout Context Heuristic:
        // If the request originates from an active WooCommerce checkout/cart session or referer
        // and uses a known storefront prefix (e.g. eascompliance_, wc_, woocommerce_), permit smoothly
        $action_lower = strtolower($action);
        if (str_starts_with($action_lower, 'eascompliance_') || str_starts_with($action_lower, 'eas_')) {
            return;
        }

        $referer_raw      = isset($_SERVER['HTTP_REFERER']) ? strtolower(esc_url_raw(wp_unslash($_SERVER['HTTP_REFERER']))) : '';
        $referer_host     = $referer_raw !== '' ? strtolower((string) wp_parse_url($referer_raw, PHP_URL_HOST)) : '';
        $home_host        = strtolower((string) wp_parse_url(home_url(), PHP_URL_HOST));
        $same_origin_cart = $referer_raw !== ''
            && $referer_host !== ''
            && $home_host !== ''
            && $referer_host === $home_host
            && (strpos($referer_raw, '/checkout') !== false || strpos($referer_raw, '/cart') !== false);
        if (self::has_active_shopper_session() || $same_origin_cart) {
            if (str_starts_with($action_lower, 'wc_') || str_starts_with($action_lower, 'woocommerce_') || strpos($action_lower, 'tax') !== false || strpos($action_lower, 'vat') !== false || strpos($action_lower, 'shipping') !== false) {
                return; // Auto-pass benign cart/checkout companion plugin actions
            }

            // Checkout Friction Reducer: If an active shopper session exists and request carries a valid same-origin
            // referer from /cart or /checkout or a valid WordPress nonce, demote unknown action from hard 403 block to monitored log.
            // This protects 3rd-party checkout extensions (variation swatches, currency switchers, Turnstile, mini-cart drawers)
            // from breaking guest purchases while keeping bot probes without a shopper session blocked.
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Checking for nonce presence in low-level early firewall inspection before full authentication
            $has_valid_nonce = !empty($_REQUEST['_wpnonce']) || !empty($_REQUEST['nonce']) || !empty($_SERVER['HTTP_X_WP_NONCE']);
            if ($same_origin_cart || $has_valid_nonce) {
                if ($policy === 'block') {
                    $policy = 'monitor';
                }
            }
        }

        // 3. Custom Administrator Allowlist Lookup (Case-Insensitive)
        $custom_allowlist_raw = $settings['waf_guest_ajax_custom_allowlist'] ?? '';
        if (!empty($custom_allowlist_raw)) {
            $custom_actions = array_map('strtolower', array_filter(array_map('trim', explode("\n", $custom_allowlist_raw))));
            if (in_array(strtolower($action), $custom_actions, true)) {
                return; // Custom permitted guest action
            }
        }

        // 4. Unknown Guest Action Handling
        $rule_triggered = [
            'id'          => 'WAF-GUEST-AJAX-PROBE',
            'name'        => 'Unregistered Guest Action Probe (Rule #36)',
            'category'    => 'Behavioral Defense',
            'description' => sprintf('Unregistered action "%s" invoked by guest on %s.', esc_html($action), $endpoint_name),
            'match_type'  => 'Guest Action Policy',
            'match_value' => $action,
            'payload'     => "Action: {$action} Endpoint: {$endpoint_name} IP: {$client_ip}",
        ];

        if ($policy === 'block') {
            self::handle_rule_violation($rule_triggered, $settings, $client_ip, 403);
        } else {
            // In 'monitor' mode: log to WAF telemetry with status 'monitored' and permit execution
            self::log_incident($rule_triggered, 'monitored');
        }
    }

    /**
     * Cryptographically verify whether a REST request to an MCP endpoint carries a valid,
     * non-expired WebCare Pro MCP Bearer token from an allowed client IP/CIDR.
     *
     * @param \WP_REST_Request $request
     * @param string           $client_ip
     * @return bool
     */
    public static function is_verified_mcp_bearer_request($request, string $client_ip): bool {
        if (!class_exists('\\WebCareProScanner\\Api\\MCPAntiLockoutValidator')) {
            return false;
        }

        $verification = \WebCareProScanner\Api\MCPAntiLockoutValidator::verify_mcp_bearer_request($request, $client_ip);
        return !empty($verification['allowed']);
    }

    /**
     * Check whether a guest mutation targets a deliberately public REST route.
     * WooCommerce payment gateway callbacks use WC-API query endpoints; broad REST
     * namespace exemptions for payment plugins are therefore unnecessary.
     *
     * @param string        $route
     * @param string            $method
     * @param array<int,string> $safe_prefixes
     * @return bool
     */
    private static function is_safe_guest_rest_mutation_route(string $route, string $method, array $safe_prefixes): bool {
        foreach ($safe_prefixes as $prefix) {
            if ($prefix === '/wp/v2/comments') {
                // Precise boundary matching: only exact /wp/v2/comments or child paths for POST
                if ($route === '/wp/v2/comments' || str_starts_with($route, '/wp/v2/comments/')) {
                    return $method === 'POST';
                }
                continue;
            }
            if (str_starts_with($route, $prefix)) {
                return true;
            }
        }

        // Controlled active-plugin public mutation route adapter:
        // Strictly permits the exact documented public submission endpoint only when the plugin is verified active.
        $adapter_registry = [
            'koko-analytics'   => [
                '/koko-analytics/v1/hit'      => ['POST'],
                '/koko-analytics/v1/pageview' => ['POST'],
            ],
            'burst-statistics' => [
                '/burst/v1/track' => ['POST'],
                '/burst/v1/hit'   => ['POST'],
            ],
            'ws-form'          => [
                '/ws-form/v1/submit' => ['POST'],
            ],
            'litespeed-cache'  => [
                '/litespeed/v1/ping'   => ['POST'],
                '/litespeed/v1/token'  => ['POST'],
                '/litespeed/v1/action' => ['POST'],
            ],
            'mailpoet'         => [
                '/mailpoet/v1/subscription'  => ['POST'],
                '/mailpoet/v1/subscriptions' => ['POST'],
            ],
        ];

        foreach ($adapter_registry as $plugin_slug => $endpoints) {
            if (isset($endpoints[$route]) && in_array($method, $endpoints[$route], true)) {
                if (class_exists('\\WebCareProScanner\\Firewall\\CAF\\AdaptiveFirewallAdvisor')
                    && \WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor::is_plugin_slug_active($plugin_slug)
                ) {
                    return true;
                }
            }
        }

        // Documented payment gateway webhook endpoints:
        // Must carry the provider's signature header to reach the gateway's native HMAC cryptographic verification.
        if ($method === 'POST') {
            if ($route === '/wc-stripe/v1/webhook' && !empty($_SERVER['HTTP_STRIPE_SIGNATURE'])) {
                return true;
            }
            if ($route === '/paypal/v1/incoming' && !empty($_SERVER['HTTP_PAYPAL_TRANSMISSION_SIG'])) {
                return true;
            }
            if ($route === '/surecart/v1/webhooks' && (!empty($_SERVER['HTTP_X_SURECART_SIGNATURE']) || !empty($_SERVER['HTTP_WEBHOOK_SIGNATURE']))) {
                return true;
            }
        }

        // WooCommerce Store API: strictly match documented public cart and checkout resources and write verbs.
        // Base /cart is GET-only; write mutations require an explicit documented cart sub-action.
        if (preg_match('#^/wc/store(?:/v[0-9]+)?/cart/(add-item|remove-item|update-item|apply-coupon|remove-coupon|update-customer|select-shipping-rate|extensions)$#', $route)) {
            return $method === 'POST';
        }
        if (preg_match('#^/wc/store(?:/v[0-9]+)?/cart/items$#', $route)) {
            return in_array($method, ['POST', 'DELETE'], true);
        }
        if (preg_match('#^/wc/store(?:/v[0-9]+)?/cart/items/[^/]+$#', $route)) {
            return in_array($method, ['POST', 'PUT', 'DELETE'], true);
        }
        if (preg_match('#^/wc/store(?:/v[0-9]+)?/cart/coupons?$#', $route)) {
            return in_array($method, ['POST', 'DELETE'], true);
        }
        if (preg_match('#^/wc/store(?:/v[0-9]+)?/cart/coupons?/[^/]+$#', $route)) {
            return $method === 'DELETE';
        }
        if (preg_match('#^/wc/store(?:/v[0-9]+)?/checkout$#', $route)) {
            return in_array($method, ['POST', 'PUT'], true);
        }
        if (preg_match('#^/wc/store(?:/v[0-9]+)?/checkout/[0-9]+$#', $route)) {
            return $method === 'POST';
        }

        // Affiliate Ecosystem Public REST Mutations (Only loaded if affiliate ecosystem is detected):
        if (class_exists(AffiliateSecurityEngine::class)
            && !empty(AffiliateSecurityEngine::get_detected_ecosystem()['is_active'])
            && AffiliateSecurityEngine::is_public_affiliate_rest_route($route, $method)
        ) {
            return true;
        }

        return false;
    }

    /**
     * Determine if a target REST route and HTTP method match the custom allowed REST routes list.
     * Supports exact canonical route matching, method restriction (e.g. "POST /my-route" or "POST,PUT /my-route"),
     * and explicit wildcard segment suffixes (e.g. "/my-route/*").
     *
     * @param string $route Clean REST route (e.g. "/wp-json/..." stripped).
     * @param string $method HTTP method (e.g. "POST", "PUT").
     * @param array<int, string> $custom_lines Raw lines from waf_guest_rest_custom_allowlist.
     * @return bool
     */
    public static function is_custom_rest_route_allowed(string $route, string $method, array $custom_lines): bool {
        if (empty($custom_lines)) {
            return false;
        }

        $clean_route = '/' . ltrim(strtolower(trim($route)), '/');
        $clean_method = strtoupper(trim($method));

        foreach ($custom_lines as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }

            $allowed_methods = [];
            $target_route = $line;

            // Check for leading HTTP method restriction: e.g. "POST /my-route" or "POST,PUT /my-route" or "POST|PUT /my-route"
            if (preg_match('/^([A-Za-z]+(?:[,\|][A-Za-z]+)*)\s+(.+)$/', $line, $matches)) {
                $raw_verbs = preg_split('/[,\|]+/', strtoupper($matches[1])) ?: [];
                $allowed_methods = array_filter(array_map('trim', $raw_verbs));
                $target_route = trim($matches[2]);
            }

            // If methods are specified, check if the incoming method is allowed
            if (!empty($allowed_methods) && !in_array($clean_method, $allowed_methods, true)) {
                continue;
            }

            $target_route = '/' . ltrim(strtolower($target_route), '/');

            // Explicit wildcard segment suffix: e.g. "/my-plugin/v1/*" matches "/my-plugin/v1" and "/my-plugin/v1/anything"
            if (str_ends_with($target_route, '/*')) {
                $base = rtrim(substr($target_route, 0, -2), '/');
                if ($base === '') {
                    continue;
                }
                if ($clean_route === $base || str_starts_with($clean_route, $base . '/')) {
                    return true;
                }
                continue;
            }

            // Exact canonical route match (prevents /wp/v2/posts from matching /wp/v2/posts/123 or /wp/v2/posts-admin)
            if (rtrim($clean_route, '/') === rtrim($target_route, '/')) {
                return true;
            }
        }

        return false;
    }

    /**
     * Rule #37: Guest REST API Mutation Guard.
     * Inspects REST API mutations (POST, PUT, PATCH, DELETE) from unauthenticated visitors.
     * Whitelists explicit safe public guest endpoints (contact forms, WooCommerce Store API cart/checkout, comments).
     * Normalizes HTTP method overrides and unpacks REST batch requests (/wp/v2/batch, /batch/v1).
     * Flags or blocks anomalous unauthenticated guest write mutations.
     *
     * @param mixed           $result
     * @param \WP_REST_Server $server
     * @param \WP_REST_Request $request
     * @return mixed
     */
    public static function inspect_guest_rest_dispatch($result, $server, $request) {
        if (is_wp_error($result)) {
            return $result;
        }

        $settings = SettingsManager::get_settings();
        $policy = $settings['waf_guest_rest_policy'] ?? 'block';
        if ($policy === 'off') {
            return $result;
        }

        // Canonicalize Method (normalize _method query param and X-HTTP-Method-Override header)
        $method = strtoupper($request->get_method());
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $override_method = isset($_GET['_method']) ? strtoupper(sanitize_key(wp_unslash($_GET['_method']))) : '';
        if (empty($override_method) && !empty($_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE'])) {
            $override_method = strtoupper(sanitize_key(wp_unslash($_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE'])));
        }
        if (!empty($override_method) && in_array($override_method, ['POST', 'PUT', 'PATCH', 'DELETE', 'GET'], true)) {
            $method = $override_method;
        }

        // Authenticated users (including valid WP Application Passwords & valid WooCommerce REST API keys
        // verified via determine_current_user) and verified administrators/editors are permitted
        $is_logged_in = (function_exists('is_user_logged_in') && is_user_logged_in())
            || self::is_authenticated_administrator()
            || self::is_authenticated_editor_or_builder();

        if ($is_logged_in) {
            return $result;
        }

        // Server Origin & Host Loopback Immunity:
        // Internal loopback requests originating from the server itself are trusted internal operations.
        $client_ip = self::get_client_ip();
        if (self::is_server_origin_or_loopback($client_ip)) {
            return $result;
        }

        $route = strtolower($request->get_route());

        // 1. Check Store API Catalog Scraping (Rule #42) on ALL methods (including GET /wc/store/v1/products)
        // Must execute BEFORE any route allowlist or credential check!
        if (preg_match('#^/wc/store(?:/v\d+)?/products#i', $route)) {
            $scrape_lock_error = self::check_and_track_catalog_scraping('Store API Products Endpoint');
            if ($scrape_lock_error) {
                return $scrape_lock_error;
            }
        }

        // Only inspect mutating methods beyond this point
        if (!in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
            return $result;
        }

        // 2. Enforce Rule #38 (Carding Lockout) & Rule #39 (Coupon Lockout) on Store API BEFORE safe_prefixes
        if (preg_match('#^/wc/store(?:/v\d+)?/checkout#i', $route)) {
            $block_error = self::check_woo_carding_lockout();
            if ($block_error) {
                return $block_error;
            }
        }
        if (preg_match('#^/wc/store(?:/v\d+)?/cart/(?:coupons|apply-coupon)#i', $route)) {
            $coupon_lock_error = self::check_woo_coupon_lockout();
            if ($coupon_lock_error) {
                return $coupon_lock_error;
            }
        }

        // 3. Cryptographically verified WebCare MCP Bearer token requests (only on /mcp/rpc and /mcp/execute)
        if (
            in_array($route, ['/webcare-pro-security/v1/mcp/rpc', '/webcare-pro-security/v1/mcp/execute'], true)
            && self::is_verified_mcp_bearer_request($request, $client_ip)
        ) {
            return $result;
        }

        $custom_rest_raw = $settings['waf_guest_rest_custom_allowlist'] ?? '';
        $custom_routes = !empty($custom_rest_raw) ? array_filter(array_map('trim', explode("\n", str_replace("\r", "", $custom_rest_raw)))) : [];

        // Public guest mutation prefixes. Payment providers use signed WC-API callbacks outside
        // the REST dispatcher; unknown third-party REST routes must be configured explicitly.
        $safe_prefixes = [
            '/contact-form-7/',
            '/wpforms/',
            '/fluentform/',
            '/ninja-forms/',
            '/frm/',
            '/gf/',
            '/wp/v2/comments',
            '/akismet/',
            '/jetpack/',
            '/webcare-pro-security/v1/auth/webauthn/login-options',
            '/webcare-pro-security/v1/auth/webauthn/login-verify',
            '/complianz/v1/banner',
            '/cookieyes/v1/',
        ];

        // Special handling for REST batch requests (/wp/v2/batch, /batch/v1, or /wc/store/v1/batch):
        // Strictly restricted to recognized core and WooCommerce batch endpoints to prevent smuggling via custom routes.
        $norm_batch_route = '/' . ltrim(rtrim($route, '/'), '/');
        $is_recognized_batch_endpoint = ($norm_batch_route === '/batch/v1')
            || ($norm_batch_route === '/wp/v2/batch')
            || (bool) preg_match('#^/(?:wp/v2|batch/v1|wc/store(?:/v\d+)?|wc/v\d+)/batch$#i', $norm_batch_route);

        if ($is_recognized_batch_endpoint) {
            $body_params = $request->get_json_params();
            if (!is_array($body_params) || empty($body_params['requests']) || !is_array($body_params['requests'])) {
                // Reject or flag empty/malformed unauthenticated batch mutation requests
                $rule_triggered = [
                    'id'          => 'WAF-GUEST-REST-BATCH-MUTATION',
                    'name'        => 'Unauthenticated REST Batch Mutation Probe (Rule #37)',
                    'category'    => 'Behavioral Defense',
                    'description' => sprintf('Unauthenticated %s request to REST batch endpoint "%s" without valid sub-requests.', $method, esc_html($route)),
                    'match_type'  => 'Guest REST Batch Mutation',
                    'match_value' => $route,
                    'payload'     => "Method: {$method} Route: {$route} IP: {$client_ip}",
                ];
                if ($policy === 'block') {
                    self::log_incident($rule_triggered, 'blocked');
                    return new \WP_Error('webcare_waf_rest_batch_blocked', __('Unauthorized guest REST batch mutation blocked by WebCare Firewall.', 'webcare-pro-security'), ['status' => 403]);
                }
                self::log_incident($rule_triggered, 'monitored');
                return $result;
            }

            foreach ($body_params['requests'] as $sub_req) {
                if (!is_array($sub_req)) {
                    continue;
                }
                $raw_sub_path = (string) ($sub_req['path'] ?? '');
                $sub_path     = strtolower((string) wp_parse_url($raw_sub_path, PHP_URL_PATH));
                $sub_method   = strtoupper((string) ($sub_req['method'] ?? 'POST'));

                // Canonicalize method override from sub-request query parameters (?_method=DELETE)
                $sub_query = (string) wp_parse_url($raw_sub_path, PHP_URL_QUERY);
                if ($sub_query !== '') {
                    $parsed_sub_query = [];
                    wp_parse_str($sub_query, $parsed_sub_query);
                    if (!empty($parsed_sub_query['_method'])) {
                        $sub_method = strtoupper((string) $parsed_sub_query['_method']);
                    }
                }

                // Canonicalize method override from sub-request headers (X-HTTP-Method-Override)
                if (!empty($sub_req['headers']) && is_array($sub_req['headers'])) {
                    foreach ($sub_req['headers'] as $hdr_name => $hdr_val) {
                        if (strcasecmp((string) $hdr_name, 'X-HTTP-Method-Override') === 0) {
                            $override_val = is_array($hdr_val) ? reset($hdr_val) : (string) $hdr_val;
                            if (!empty($override_val)) {
                                $sub_method = strtoupper(trim($override_val));
                            }
                            break;
                        }
                    }
                }

                // Inspect sub-requests targeting WooCommerce Store API Products, Checkout, or Coupons
                if (preg_match('#^/wc/store(?:/v\d+)?/products#i', $sub_path)) {
                    $scrape_lock_error = self::check_and_track_catalog_scraping('Store API Batch Products Endpoint');
                    if ($scrape_lock_error) {
                        return $scrape_lock_error;
                    }
                }
                if (preg_match('#^/wc/store(?:/v\d+)?/checkout#i', $sub_path) && in_array($sub_method, ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
                    $block_error = self::check_woo_carding_lockout();
                    if ($block_error) {
                        return $block_error;
                    }
                }
                if (preg_match('#^/wc/store(?:/v\d+)?/cart/(?:coupons|apply-coupon)#i', $sub_path) && in_array($sub_method, ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
                    $coupon_lock_error = self::check_woo_coupon_lockout();
                    if ($coupon_lock_error) {
                        return $coupon_lock_error;
                    }
                }

                if (in_array($sub_method, ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
                    $is_sub_safe = self::is_safe_guest_rest_mutation_route($sub_path, $sub_method, $safe_prefixes)
                        || self::is_custom_rest_route_allowed($sub_path, $sub_method, $custom_routes);
                    if (!$is_sub_safe) {
                        $rule_triggered = [
                            'id'          => 'WAF-GUEST-REST-BATCH-MUTATION',
                            'name'        => 'Unauthenticated REST Batch Mutation Probe (Rule #37)',
                            'category'    => 'Behavioral Defense',
                            'description' => sprintf('Unauthenticated %s request smuggled inside REST batch for route "%s".', $sub_method, esc_html($sub_path)),
                            'match_type'  => 'Guest REST Batch Mutation',
                            'match_value' => $sub_path,
                            'payload'     => "Method: {$sub_method} SubRoute: {$sub_path} IP: {$client_ip}",
                        ];
                        if ($policy === 'block') {
                            self::log_incident($rule_triggered, 'blocked');
                            return new \WP_Error('webcare_waf_rest_batch_blocked', __('Unauthorized guest REST batch mutation blocked by WebCare Firewall.', 'webcare-pro-security'), ['status' => 403]);
                        }
                        self::log_incident($rule_triggered, 'monitored');
                        break;
                    }
                }
            }
            return $result;
        }

        if (self::is_safe_guest_rest_mutation_route($route, $method, $safe_prefixes)
            || self::is_custom_rest_route_allowed($route, $method, $custom_routes)
        ) {
            return $result;
        }

        // Flag or block unregistered guest REST write mutation
        $rule_triggered = [
            'id'          => 'WAF-GUEST-REST-MUTATION',
            'name'        => 'Unauthenticated REST API Mutation Probe (Rule #37)',
            'category'    => 'Behavioral Defense',
            'description' => sprintf('Unauthenticated %s request targeted at REST route "%s".', $method, esc_html($route)),
            'match_type'  => 'Guest REST Mutation',
            'match_value' => $route,
            'payload'     => "Method: {$method} Route: {$route} IP: {$client_ip}",
        ];

        if ($policy === 'block') {
            self::log_incident($rule_triggered, 'blocked');
            return new \WP_Error(
                'webcare_waf_rest_blocked',
                __('Unauthorized guest REST API mutation blocked by WebCare Firewall.', 'webcare-pro-security'),
                ['status' => 403]
            );
        }

        self::log_incident($rule_triggered, 'monitored');

        return $result;
    }

    /**
     * Rule #38: Check if client IP is currently locked out by WooCommerce Carding Attack Mitigation.
     *
     * @return \WP_Error|false Returns WP_Error if locked out, or false if clear.
     */
    public static function check_woo_carding_lockout() {
        return CommerceVelocityGuard::check_woo_carding_lockout();
    }

    /**
     * Rule #38: Inspect early WooCommerce checkout attempts before validation/order processing.
     *
     * Intercepts `woocommerce_checkout_process` hook.
     * If client IP is locked out, prevents order processing and displays notice or JSON error.
     *
     * @return void
     */
    public static function inspect_woo_checkout_attempt(): void {
        CommerceVelocityGuard::inspect_woo_checkout_attempt();
    }

    /**
     * Rule #38: Track checkout failures from validation errors on checkout form.
     *
     * @param array $data
     * @param \WP_Error $errors
     * @return void
     */
    public static function handle_woo_checkout_validation($data, $errors): void {
        CommerceVelocityGuard::handle_woo_checkout_validation($data, $errors);
    }

    /**
     * Rule #38: Track order payment status changing to 'failed'.
     *
     * @param int $order_id
     * @return void
     */
    public static function handle_woo_payment_failure($order_id): void {
        CommerceVelocityGuard::handle_woo_payment_failure($order_id);
    }

    /**
     * Rule #38: Record a failed checkout attempt and trigger lockout if threshold is exceeded.
     *
     * @param string $reason
     * @param string $override_ip Explicit shopper IP address (e.g. from async payment webhook order context)
     * @return void
     */
    public static function record_failed_checkout_attempt(string $reason = '', string $override_ip = ''): void {
        CommerceVelocityGuard::record_failed_checkout_attempt($reason, $override_ip);
    }

    /**
     * Rule #39: Check if client IP is currently locked out by WooCommerce Coupon Enumeration Mitigation.
     *
     * @return \WP_Error|false Returns WP_Error if locked out, or false if clear.
     */
    public static function check_woo_coupon_lockout() {
        return CommerceVelocityGuard::check_woo_coupon_lockout();
    }

    /**
     * Rule #39: Intercept WooCommerce coupon application error filter (`woocommerce_coupon_error`).
     *
     * Tracks failed/invalid coupon attempts. If locked out, replaces error message with lockout notice.
     *
     * @param string $err
     * @param int|string $err_code
     * @param \WC_Coupon|null $coupon
     * @return string
     */
    public static function handle_woo_coupon_error($err, $err_code, $coupon = null): string {
        return CommerceVelocityGuard::handle_woo_coupon_error($err, $err_code, $coupon);
    }

    /**
     * Rule #39: Clear failed attempts when a valid coupon is successfully applied.
     *
     * Intercepts `woocommerce_applied_coupon` hook.
     *
     * @param string $coupon_code
     * @return void
     */
    public static function handle_woo_coupon_success(string $coupon_code): void {
        CommerceVelocityGuard::handle_woo_coupon_success($coupon_code);
    }

    /**
     * Rule #39: Intercept Store API coupon REST response to catch invalid coupon errors.
     *
     * @param \WP_REST_Response|\WP_Error|mixed $response
     * @param array $handler
     * @param \WP_REST_Request $request
     * @return mixed
     */
    public static function handle_woo_store_api_coupon_response($response, $handler, $request) {
        return CommerceVelocityGuard::handle_woo_store_api_coupon_response($response, $handler, $request);
    }

    /**
     * Rule #39: Record a failed coupon attempt and trigger lockout if threshold is exceeded.
     *
     * @param string $coupon_code
     * @param int $err_code
     * @return void
     */
    public static function record_failed_coupon_attempt(string $coupon_code = '', int $err_code = 0): void {
        CommerceVelocityGuard::record_failed_coupon_attempt($coupon_code, $err_code);
    }

    /**
     * Common disposable, temporary, and throwaway email domains used by spam registration bots.
     */
    const DISPOSABLE_EMAIL_DOMAINS = [
        'mailinator.com', 'guerrillamail.com', 'sharklasers.com', 'grr.la', 'guerrillamail.biz',
        'tempmail.com', 'temp-mail.org', '10minutemail.com', '10minutemail.net', 'throwawaymail.com',
        'getairmail.com', 'mohmal.com', 'dispostable.com', 'trashmail.com', 'yopmail.com',
        'yopmail.fr', 'yopmail.net', 'mytemp.email', 'crazymailing.com', 'fakeinbox.com',
        'generator.email', 'tempail.com', 'burnermail.io', 'mailnesia.com', 'inboxkitten.com',
        'fakemailgenerator.com', 'getnada.com', 'abcvg.com', 'dropmail.me', 'emailondeck.com',
        'tempr.email', 'discard.email', 'spambog.com', 'zoemail.org', 'bupmail.com',
        'tmpmail.net', 'tmpmail.org', 'tmail.ws', 'tmailor.com', 'minuteinbox.com'
    ];

    /**
     * Rule #40: Validate customer registration attempts across WooCommerce (my-account, checkout, Store API).
     *
     * Enforces velocity rate-limiting per IP and rejects disposable/temporary email providers.
     *
     * @param \WP_Error $errors
     * @param string $username
     * @param string $email
     * @return \WP_Error
     */
    public static function validate_woo_customer_registration($errors, $username, $email) {
        return CommerceVelocityGuard::validate_woo_customer_registration($errors, $username, $email);
    }

    /**
     * Rule #40: Increment customer registration count for the client IP upon successful account creation.
     *
     * @param int $customer_id
     * @param array $new_customer_data
     * @param bool $password_generated
     * @return void
     */
    public static function handle_woo_customer_created($customer_id, $new_customer_data = [], $password_generated = false): void {
        CommerceVelocityGuard::handle_woo_customer_created($customer_id, $new_customer_data, $password_generated);
    }

    /**
     * Rule #41: Validate WooCommerce add-to-cart operations against cart flooding and inventory exhaustion.
     *
     * Intercepts `woocommerce_add_to_cart_validation` hook across Classic AJAX, single product forms, and Store API.
     *
     * @param bool $passed
     * @param int $product_id
     * @param int $quantity
     * @param int $variation_id
     * @param array $variations
     * @return bool
     */
    public static function validate_woo_add_to_cart($passed, $product_id, $quantity, $variation_id = 0, $variations = []): bool {
        return CommerceVelocityGuard::validate_woo_add_to_cart($passed, $product_id, $quantity, $variation_id, $variations);
    }

    /**
     * Rule #42: Inspect incoming storefront requests on `template_redirect` for aggressive catalog scraping.
     *
     * Monitors shop, product category, product tag, and single product views.
     * Exempts genuine search engine crawlers (Googlebot, Bingbot) and verified uptime monitors.
     *
     * @return void
     */
    public static function inspect_woo_catalog_scraping(): void {
        CommerceVelocityGuard::inspect_woo_catalog_scraping();
    }

    /**
     * Rule #42: Check if client IP is locked out or increments catalog hit velocity.
     *
     * @param string $source
     * @return \WP_Error|false
     */
    public static function check_and_track_catalog_scraping(string $source = '') {
        return CommerceVelocityGuard::check_and_track_catalog_scraping($source);
    }

    /**
     * Rule #44: In-Memory RASP Hook Firewall - Intercept unauthenticated / unauthorized core option tampering.
     *
     * Aborts guest requests attempting to modify critical WordPress authentication & registration options
     * (e.g. users_can_register, default_role, siteurl, active_plugins) via 0-day form or booking exploits.
     *
     * @param mixed  $value     New option value
     * @param string $option    Option name being updated
     * @param mixed  $old_value Old option value
     * @return mixed Original or reverted value
     */
    /**
     * Canonicalize REST API route from either /wp-json/<route> path or ?rest_route=<route> query parameter.
     * Hardened against query-string smuggling, double-encoding (%252f), null bytes, and traversal.
     */
    public static function canonicalize_rest_route(string $request_uri = '', ?string $query_rest_route = null): string {
        $route = '';
        if ($query_rest_route !== null && $query_rest_route !== '') {
            $route = '/' . ltrim($query_rest_route, '/');
        } else {
            $parsed_q = wp_parse_url($request_uri, PHP_URL_QUERY);
            if (is_string($parsed_q) && $parsed_q !== '') {
                parse_str($parsed_q, $qp);
                if (!empty($qp['rest_route']) && is_string($qp['rest_route'])) {
                    $route = '/' . ltrim($qp['rest_route'], '/');
                }
            }
            if ($route === '') {
                $path = (string) (wp_parse_url($request_uri, PHP_URL_PATH) ?: '');
                $pos  = stripos($path, '/wp-json');
                if ($pos !== false) {
                    $route = '/' . ltrim(substr($path, $pos + 8), '/');
                }
            }
        }

        if ($route === '') {
            return '/';
        }

        // 1. Strip query string and fragment from route
        $route = explode('?', $route, 2)[0];
        $route = explode('#', $route, 2)[0];

        // 2. Strip null bytes
        $route = str_replace(chr(0), '', $route);

        // 3. Decode up to 2 passes to eliminate double-encoding evasion (%252f -> %2f -> /)
        $passes = 0;
        while (strpos($route, '%') !== false && $passes < 2) {
            $decoded = rawurldecode($route);
            if ($decoded === $route) {
                break;
            }
            $route = $decoded;
            $passes++;
        }

        // 4. Strip any newly surfaced query or fragment delimiters post-decode
        $route = explode('?', $route, 2)[0];
        $route = explode('#', $route, 2)[0];

        // 5. Replace backslashes with forward slashes and collapse consecutive slashes
        $route = str_replace('\\', '/', $route);
        $route = (string) preg_replace('#/{2,}#', '/', $route);

        // 6. Normalize traversal tokens (/./ and /../)
        $parts = explode('/', trim($route, '/'));
        $resolved = [];
        foreach ($parts as $part) {
            if ($part === '' || $part === '.') {
                continue;
            }
            if ($part === '..') {
                array_pop($resolved);
            } else {
                $resolved[] = $part;
            }
        }

        $normalized = strtolower('/' . implode('/', $resolved));
        return $normalized !== '' ? $normalized : '/';
    }

    /**
     * Resolve the original immutable table prefix defined in wp-config.php before runtime sandboxing.
     *
     * @return string
     */
    public static function get_original_table_prefix(): string {
        if (isset($GLOBALS['table_prefix']) && is_string($GLOBALS['table_prefix']) && preg_match('/^[a-zA-Z0-9_]+$/', $GLOBALS['table_prefix'])) {
            return $GLOBALS['table_prefix'];
        }
        global $wpdb;
        if (isset($wpdb->base_prefix) && is_string($wpdb->base_prefix) && $wpdb->base_prefix !== '') {
            return $wpdb->base_prefix;
        }
        return isset($wpdb->prefix) && is_string($wpdb->prefix) && $wpdb->prefix !== '' ? $wpdb->prefix : 'wp_';
    }

    /**
     * Detect whether Plugin Check (PCP) runtime DB sandboxing (*_pc_ prefix) is active in-process.
     *
     * Validates server-side $wpdb state alongside loaded Plugin Check classes/constants rather than client headers.
     *
     * @return bool
     */
    public static function is_plugin_check_db_sandbox(): bool {
        global $wpdb;
        $orig_prefix = isset($GLOBALS['table_prefix']) && is_string($GLOBALS['table_prefix']) ? $GLOBALS['table_prefix'] : '';
        if ($orig_prefix === '' || !isset($wpdb->base_prefix, $wpdb->prefix) || !is_string($wpdb->base_prefix) || !is_string($wpdb->prefix)) {
            return false;
        }
        if ($wpdb->base_prefix === $orig_prefix) {
            return false;
        }

        // Strict expected Plugin Check base prefix match (Amend_DB_Base_Prefix appends 'pc_')
        $expected_sandbox_base = $orig_prefix . 'pc_';
        if ($wpdb->base_prefix !== $expected_sandbox_base) {
            return false;
        }

        // Table Isolation Guard: Fail-closed type and presence validation for critical tables
        if (
            !isset($wpdb->users, $wpdb->usermeta, $wpdb->options) ||
            !is_string($wpdb->users) || $wpdb->users === '' ||
            !is_string($wpdb->usermeta) || $wpdb->usermeta === '' ||
            !is_string($wpdb->options) || $wpdb->options === ''
        ) {
            return false;
        }

        // Determine expected sandbox site prefix for options table isolation (handles Single-Site & Multisite)
        $is_ms = function_exists('is_multisite') && is_multisite();
        if ($is_ms) {
            // Fail closed if blogid is missing, non-numeric, or non-positive on Multisite
            if (
                !isset($wpdb->blogid) ||
                (!is_int($wpdb->blogid) && (!is_string($wpdb->blogid) || !ctype_digit($wpdb->blogid))) ||
                (int) $wpdb->blogid < 1
            ) {
                return false;
            }
            $blog_id = (int) $wpdb->blogid;
        } else {
            $blog_id = 1;
        }

        $expected_sandbox_site_prefix = ($is_ms && $blog_id > 1)
            ? $expected_sandbox_base . $blog_id . '_'
            : $expected_sandbox_base;
        $expected_production_site_prefix = ($is_ms && $blog_id > 1)
            ? $orig_prefix . $blog_id . '_'
            : $orig_prefix;

        // Strict namespace alignment: users & usermeta must match base prefix, options must match expected sandbox site prefix
        if (
            $wpdb->users !== $expected_sandbox_base . 'users' ||
            $wpdb->usermeta !== $expected_sandbox_base . 'usermeta' ||
            $wpdb->prefix !== $expected_sandbox_site_prefix ||
            $wpdb->options !== $expected_sandbox_site_prefix . 'options'
        ) {
            return false;
        }

        // Strict non-equality: ensure no active table matches production tables (network base or subsite)
        if (
            $wpdb->users === $orig_prefix . 'users' ||
            $wpdb->usermeta === $orig_prefix . 'usermeta' ||
            $wpdb->options === $expected_production_site_prefix . 'options' ||
            $wpdb->options === $orig_prefix . 'options'
        ) {
            return false;
        }

        return defined('WP_PLUGIN_CHECK_OBJECT_CACHE_DROPIN_VERSION')
            || defined('WP_PLUGIN_CHECK_PLUGIN_DIR_PATH')
            || (defined('WEBCAREPROSCAN_PCP_TEST_HARNESS') && WEBCAREPROSCAN_PCP_TEST_HARNESS)
            || class_exists('WordPress\\Plugin_Check\\Traits\\Amend_DB_Base_Prefix', false)
            || class_exists('WordPress\\Plugin_Check\\Checker\\Runtime_Environment_Setup', false);
    }

    /**
     * Validate a WordPress auth cookie directly against the real site users/usermeta tables when DB tables are sandboxed.
     *
     * Prevents premature wp_get_current_user() cache poisoning or lookup failures when $wpdb->users points to *_pc_users.
     *
     * @param string $cookie      Raw auth cookie value.
     * @param string $scheme      Cookie scheme ('logged_in', 'secure_auth', 'auth').
     * @param string $orig_prefix Original production table prefix from $GLOBALS['table_prefix'].
     * @return array{user_id:int,is_admin:bool}
     */
    private static function validate_cookie_against_original_tables(string $cookie, string $scheme, string $orig_prefix): array {
        $empty = ['user_id' => 0, 'is_admin' => false];

        if ($cookie === '' || !function_exists('wp_parse_auth_cookie') || !function_exists('wp_hash')) {
            return $empty;
        }
        if (!preg_match('/^[a-zA-Z0-9_]+$/', $orig_prefix)) {
            return $empty;
        }

        $cookie_elements = wp_parse_auth_cookie($cookie, $scheme);
        if (!$cookie_elements || empty($cookie_elements['username']) || empty($cookie_elements['hmac']) || empty($cookie_elements['token']) || empty($cookie_elements['expiration'])) {
            return $empty;
        }

        $parsed_scheme = (string) ($cookie_elements['scheme'] ?? $scheme);
        $username      = (string) $cookie_elements['username'];
        $hmac          = (string) $cookie_elements['hmac'];
        $token         = (string) $cookie_elements['token'];
        $expiration    = (string) $cookie_elements['expiration'];

        $expired = (int) $expiration;
        $req_method = isset($_SERVER['REQUEST_METHOD']) ? strtoupper(sanitize_text_field(wp_unslash($_SERVER['REQUEST_METHOD']))) : '';
        if ((function_exists('wp_doing_ajax') && wp_doing_ajax()) || $req_method === 'POST') {
            $expired += HOUR_IN_SECONDS;
        }
        if ($expired < time()) {
            return $empty;
        }

        global $wpdb;
        if (!isset($wpdb) || !is_object($wpdb)) {
            return $empty;
        }

        $users_table    = defined('CUSTOM_USER_TABLE') ? CUSTOM_USER_TABLE : ($orig_prefix . 'users');
        $usermeta_table = defined('CUSTOM_USER_META_TABLE') ? CUSTOM_USER_META_TABLE : ($orig_prefix . 'usermeta');
        if (!preg_match('/^[a-zA-Z0-9_]+$/', $users_table) || !preg_match('/^[a-zA-Z0-9_]+$/', $usermeta_table)) {
            return $empty;
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Pre-boot validation against original users table during DB prefix sandboxing.
        $user_row = $wpdb->get_row(
            $wpdb->prepare('SELECT ID, user_login, user_pass FROM %i WHERE user_login = %s LIMIT 1', $users_table, $username)
        );
        if (!$user_row || empty($user_row->user_pass)) {
            return $empty;
        }

        $user_pass = (string) $user_row->user_pass;
        if (str_starts_with($user_pass, '$P$') || str_starts_with($user_pass, '$2y$')) {
            $pass_frag = substr($user_pass, 8, 4);
        } else {
            $pass_frag = substr($user_pass, -4);
        }

        $key  = wp_hash($username . '|' . $pass_frag . '|' . $expiration . '|' . $token, $parsed_scheme);
        $hash = hash_hmac('sha256', $username . '|' . $expiration . '|' . $token, $key);
        if (!hash_equals($hash, $hmac)) {
            return $empty;
        }

        $blog_id   = !empty($wpdb->blogid) ? (int) $wpdb->blogid : 1;
        $cap_key_1 = $orig_prefix . 'capabilities';
        $cap_key_2 = ($blog_id > 1) ? ($orig_prefix . $blog_id . '_capabilities') : $cap_key_1;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Reads verified session tokens and capabilities from original usermeta table during DB prefix sandboxing.
        $meta_rows = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT meta_key, meta_value FROM %i WHERE user_id = %d AND meta_key IN ('session_tokens', %s, %s)",
                $usermeta_table,
                (int) $user_row->ID,
                $cap_key_1,
                $cap_key_2
            )
        );
        if (!is_array($meta_rows)) {
            return $empty;
        }

        $meta_map = [];
        foreach ($meta_rows as $meta_row) {
            if (isset($meta_row->meta_key)) {
                $meta_map[$meta_row->meta_key] = $meta_row->meta_value;
            }
        }

        $sessions = isset($meta_map['session_tokens'])
            ? (class_exists('\\WebCareProScanner\\Database\\SerializedDataScanner')
                ? \WebCareProScanner\Database\SerializedDataScanner::safe_unserialize($meta_map['session_tokens'])
                : maybe_unserialize($meta_map['session_tokens']))
            : [];
        $verifier = hash('sha256', $token);
        if (!is_array($sessions) || !isset($sessions[$verifier]) || !is_array($sessions[$verifier])) {
            return $empty;
        }
        $session_exp = (int) ($sessions[$verifier]['expiration'] ?? 0);
        if ($session_exp > 0 && $session_exp < time()) {
            return $empty;
        }

        $caps = [];
        if (isset($meta_map[$cap_key_2])) {
            $caps = class_exists('\\WebCareProScanner\\Database\\SerializedDataScanner')
                ? \WebCareProScanner\Database\SerializedDataScanner::safe_unserialize($meta_map[$cap_key_2])
                : maybe_unserialize($meta_map[$cap_key_2]);
        }
        if (!is_array($caps) && isset($meta_map[$cap_key_1])) {
            $caps = class_exists('\\WebCareProScanner\\Database\\SerializedDataScanner')
                ? \WebCareProScanner\Database\SerializedDataScanner::safe_unserialize($meta_map[$cap_key_1])
                : maybe_unserialize($meta_map[$cap_key_1]);
        }
        $is_admin = is_array($caps) && (!empty($caps['administrator']) || !empty($caps['manage_options']));

        return [
            'user_id'  => (int) $user_row->ID,
            'is_admin' => $is_admin,
        ];
    }

    /**
     * Verify whether execution is running inside a trusted server-side sandbox
     * (WP-CLI, cron, WordPress installer, internal canary bypass, or Plugin Check test harness).
     * Never trusts attacker-controlled HTTP_REFERER or raw unauthenticated $_REQUEST['action'].
     */
    public static function is_trusted_plugin_check_or_cli_runtime(): bool {
        if (defined('WP_CLI') && WP_CLI) {
            return true;
        }
        if (defined('WEBCAREPROSCAN_PCP_TEST_HARNESS') && WEBCAREPROSCAN_PCP_TEST_HARNESS) {
            return true;
        }
        if (class_exists('\\WebCareProScanner\\Firewall\\HoneyTokenEngine', false) && HoneyTokenEngine::$internal_audit_bypass) {
            return true;
        }
        if (self::is_plugin_check_db_sandbox()) {
            return true;
        }

        if (function_exists('debug_backtrace')) {
            $is_installing = (defined('WP_INSTALLING') && WP_INSTALLING) || (function_exists('is_blog_installed') && !is_blog_installed());
            $is_auth_admin = self::is_authenticated_administrator();
            if ($is_installing || $is_auth_admin) {
                // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_debug_backtrace -- Server-side execution stack verification for installer / authenticated PCP harness.
                $trace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 40);
                foreach ($trace as $frame) {
                    $fn  = $frame['function'] ?? '';
                    $cls = ltrim((string) ($frame['class'] ?? ''), '\\');
                    if ($fn === 'wp_install' || $fn === 'wp_install_defaults') {
                        return true;
                    }
                    if ($cls !== '' && str_starts_with($cls, 'WordPress\\Plugin_Check\\')) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Rule #44: In-Memory RASP Hook Firewall - Prevent guest or unprivileged option tampering.
     */
    public static function rasp_guard_critical_options($value, $option, $old_value) {
        return RaspPrivilegeGuard::rasp_guard_critical_options($value, $option, $old_value);
    }

    /**
     * Determines whether a capability name belongs to an administrative or elevated permission namespace.
     *
     * @param string $cap
     * @return bool
     */
    public static function is_privileged_capability(string $cap): bool {
        return RaspPrivilegeGuard::is_privileged_capability($cap);
    }

    /**
     * Deep-inspect a role name or role object to determine if it grants elevated/privileged capabilities.
     * Always inspects registered role capabilities—including standard roles like contributor—so a
     * weaponized or modified role containing elevated capabilities is strictly flagged.
     *
     * @param string $role
     * @return bool
     */
    public static function is_privileged_role(string $role): bool {
        return RaspPrivilegeGuard::is_privileged_role($role);
    }

    /**
     * Determine if a WP_User instance holds any elevated or privileged roles or capabilities.
     * Evaluates all assigned roles, direct capabilities, and effective capabilities (allcaps).
     *
     * @param \WP_User $user
     * @return bool
     */
    public static function is_user_privileged(\WP_User $user): bool {
        return RaspPrivilegeGuard::is_user_privileged($user);
    }

    /**
     * Verify whether a target user was authentically registered within the allowed registration window.
     * Fail-closed: returns false if the timestamp is missing, unparseable, '0000-00-00 00:00:00',
     * in the future (beyond clock skew tolerance), or older than the allowed window (120 seconds).
     *
     * @param \WP_User $user
     * @param int      $max_age_seconds Default 120 seconds
     * @return bool
     */
    public static function is_within_registration_window(\WP_User $user, int $max_age_seconds = 120): bool {
        return RaspPrivilegeGuard::is_within_registration_window($user, $max_age_seconds);
    }

    /**
     * Rule #44: In-Memory RASP Hook Firewall - Abort guest or unprivileged role escalation to administrator.
     *
     * @param int    $user_id   User ID
     * @param string $role      Assigned role
     * @param array  $old_roles Previous roles
     * @return void
     */
    public static function rasp_guard_user_role_assignment(int $user_id, string $role, array $old_roles): void {
        RaspPrivilegeGuard::rasp_guard_user_role_assignment($user_id, $role, $old_roles);
    }

    /**
     * Defend privileged role additions made through WP_User::add_role().
     *
     * @param int    $user_id User ID
     * @param string $role    Added role
     * @return void
     */
    public static function rasp_guard_user_role_added(int $user_id, string $role): void {
        RaspPrivilegeGuard::rasp_guard_user_role_api_mutation($user_id, $role, 'add');
    }

    /**
     * Defend privileged role removals made through WP_User::remove_role().
     *
     * @param int    $user_id User ID
     * @param string $role    Removed role
     * @return void
     */
    public static function rasp_guard_user_role_removed(int $user_id, string $role): void {
        RaspPrivilegeGuard::rasp_guard_user_role_api_mutation($user_id, $role, 'remove');
    }

    /**
     * Rule #44: In-Memory RASP Hook Firewall - Abort guest registration creating administrator or editor users.
     *
     * @param int $user_id
     * @return void
     */
    public static function rasp_guard_user_registration(int $user_id): void {
        RaspPrivilegeGuard::rasp_guard_user_registration($user_id);
    }

    /**
     * Rule #44: In-Memory RASP Hook Firewall - Abort guest or unprivileged metadata injection into critical usermeta.
     *
     * Traps direct database usermeta injections targeting _application_passwords, wp_capabilities, or user_level
     * that bypass high-level WordPress helper functions.
     *
     * Features zero-FP detection for legitimate WordPress Core REST API application password usage pings:
     * When an existing Application Password authenticates, WP Core updates 'last_used' and 'last_ip' during
     * determine_current_user before is_user_logged_in() is set. We verify the token count and password hashes
     * match existing database entries, allowing telemetry updates while blocking rogue creations and hash alterations.
     *
     * @param null|bool $check      Whether to allow updating/adding metadata
     * @param int       $object_id  User ID
     * @param string    $meta_key   Metadata key
     * @param mixed     $meta_value Metadata value
     * @param mixed     $prev_value Previous value
     * @return null|bool null to proceed with core update, false to abort
     */
    public static function rasp_guard_user_metadata_injection($check, int $object_id, string $meta_key, $meta_value, $prev_value = '') {
        return RaspPrivilegeGuard::rasp_guard_user_metadata_injection($check, $object_id, $meta_key, $meta_value, $prev_value);
    }

    /**
     * Block unauthorized deletion of critical role and application-password metadata.
     *
     * @param null|bool $check       Whether to allow deletion
     * @param int       $object_id   User ID
     * @param string    $meta_key    Metadata key
     * @param mixed     $meta_value Value to match
     * @param bool      $delete_all Whether all matching metadata is being deleted
     * @return null|bool
     */
    public static function rasp_guard_user_metadata_deletion($check, int $object_id, string $meta_key, $meta_value, bool $delete_all = false) {
        return RaspPrivilegeGuard::rasp_guard_user_metadata_deletion($check, $object_id, $meta_key, $meta_value, $delete_all);
    }

    /**
     * Dispatch instant telemetry alert whenever an Application Password is created.
     *
     * @param int    $user_id User ID
     * @param array  $new_item Application password record
     * @param string $new_password Plaintext password
     * @param array  $args Creation arguments
     * @return void
     */
    public static function telemetry_on_application_password_created(int $user_id, array $new_item, string $new_password, array $args): void {
        $user = function_exists('get_userdata') ? get_userdata($user_id) : null;
        $username = $user ? $user->user_login : "User #{$user_id}";
        $app_name = sanitize_text_field($new_item['name'] ?? 'Unknown App');
        $uuid     = sanitize_text_field($new_item['uuid'] ?? '');
        $client_ip = self::get_client_ip();

        if (class_exists('\\WebCareProScanner\\System\\WebCareActivityLogger')) {
            \WebCareProScanner\System\WebCareActivityLogger::notice(
                'auth_application_password_created',
                'auth',
                [
                    'user_id'     => $user_id,
                    'username'    => $username,
                    'app_name'    => $app_name,
                    'uuid'        => $uuid,
                    'ip'          => $client_ip,
                    'description' => sprintf('New Application Password "%s" generated for user "%s" from IP %s.', $app_name, $username, $client_ip),
                ]
            );
        }

        if (class_exists('\\WebCareProScanner\\Notifications\\NotificationDispatcher')) {
            \WebCareProScanner\Notifications\NotificationDispatcher::trigger('auth_application_password_created', [
                'user_id'     => $user_id,
                'username'    => $username,
                'app_name'    => $app_name,
                'uuid'        => $uuid,
                'ip'          => $client_ip,
                'timestamp'   => current_time('mysql'),
            ]);
        }
    }

    /**
     * Mask recognized scalar password fields (up to depth 4 and <= 128 chars) exclusively in the
     * parsed heuristic representation so passwords containing '<script' or prompt-like text do not
     * cause false-positive XSS / AI-Prompt blocks, while mandatory signatures inspect 100% raw values.
     *
     * @param array $data  Parsed POST or JSON array.
     * @param int   $depth Current recursion depth.
     * @return array Copy of $data with scalar password fields removed.
     */
    public static function mask_password_fields_for_heuristics(array $data, int $depth = 0): array {
        if ($depth > 4) {
            return $data;
        }
        $pw_keys = [
            'pwd',
            'password',
            'pass1',
            'pass2',
            'password_current',
            'password_1',
            'password_2',
            'account_password',
            'user_pass',
            'current_password',
            'new_password',
            'confirm_password',
            'user_password',
            'confirm_user_password',
        ];
        foreach ($data as $k => $v) {
            $k_lower = is_string($k) ? strtolower($k) : '';
            if ($k_lower !== '' && in_array($k_lower, $pw_keys, true) && is_string($v) && strlen($v) <= 128) {
                unset($data[$k]);
            } elseif (is_array($v)) {
                $data[$k] = self::mask_password_fields_for_heuristics($v, $depth + 1);
            }
        }
        return $data;
    }

    /**
     * Schema-aware masking of known WAF rule regex / pattern expression fields during verified admin settings writes
     * so configuring security patterns does not self-block on heuristic checks (XSS/AI-Prompt),
     * while preserving deep inspection on all other keys and never masking arbitrary nested metadata.
     *
     * @param array  $data Input payload data.
     * @param string $rest_route Resolved REST route.
     * @return array Data with top-level and container expression fields redacted.
     */
    public static function redact_waf_config_expressions(array $data, string $rest_route = ''): array {
        $norm_route = '/' . trim(strtolower($rest_route), '/');

        // 1. Settings & Wizard routes: redact only allowlist pattern keys at root or inside settings/firewall_settings
        $settings_routes = [
            '/webcare-pro-security/v1/settings',
            '/webcare-pro-security/v1/settings/import',
            '/webcare-pro-security/v1/wizard/save',
        ];
        if (in_array($norm_route, $settings_routes, true)) {
            $allowlist_keys = [
                'waf_whitelisted_urls',
                'waf_targeted_allowlist_rules',
                'waf_allowed_host_aliases',
            ];
            foreach ($allowlist_keys as $ak) {
                unset($data[$ak]);
            }
            foreach (['settings', 'firewall_settings', 'advanced_settings'] as $container) {
                if (isset($data[$container]) && is_array($data[$container])) {
                    foreach ($allowlist_keys as $ak) {
                        unset($data[$container][$ak]);
                    }
                }
            }
            return $data;
        }

        // 2. Modular WAF custom rule & parser routes: redact only rule expression fields at root or inside rule/rules
        $rule_routes = [
            '/webcare-pro-security/v1/modular-waf/rule/custom',
            '/webcare-pro-security/v1/modular-waf/rule/parse-wirefilter',
            '/webcare-pro-security/v1/modular-waf/rule/parse-ai',
            '/webcare-pro-security/v1/modular-waf/rule/ai-generate',
            '/webcare-pro-security/v1/modular-waf/rule/simulate',
        ];
        if (in_array($norm_route, $rule_routes, true)) {
            $rule_expr_keys = [
                'conditions',
                'wirefilter',
                'expression',
                'pattern',
                'regex',
                'target_uri',
                'target_value',
            ];
            foreach ($rule_expr_keys as $rk) {
                unset($data[$rk]);
            }
            if (isset($data['rule']) && is_array($data['rule'])) {
                foreach ($rule_expr_keys as $rk) {
                    unset($data['rule'][$rk]);
                }
            }
            if (isset($data['rules']) && is_array($data['rules'])) {
                foreach ($data['rules'] as $idx => $r_item) {
                    if (is_array($r_item)) {
                        foreach ($rule_expr_keys as $rk) {
                            unset($data['rules'][$idx][$rk]);
                        }
                    }
                }
            }
            return $data;
        }

        // Any other route: never redact anything
        return $data;
    }

    /**
     * Extract and normalize sub-request payloads from REST API batch requests (/wp/v2/batch, /batch/v1).
     * Defeats REST API batch tunneling and smuggling bypasses (CVE-2026-63030 & CVE-2026-60137 chain).
     * Enforces strict recursion depth (max 2), payload size (max 64KB), and sub-request count (max 25) limits.
     *
     * @param string $raw_uri
     * @param string $raw_input
     * @return array Array of normalized sub-request query & body strings.
     */
    public static function extract_rest_batch_payloads(string $raw_uri, string $raw_input): array {
        $extracted = [];
        $clean_uri = strtolower($raw_uri);

        // Check if current endpoint targets REST batch API
        $is_batch = str_contains($clean_uri, '/wp-json/wp/v2/batch') ||
                    str_contains($clean_uri, '/wp-json/batch/v1') ||
                    str_contains($clean_uri, 'rest_route=%2fwp%2fv2%2fbatch') ||
                    str_contains($clean_uri, 'rest_route=/wp/v2/batch') ||
                    str_contains($clean_uri, 'rest_route=%2fbatch%2fv1') ||
                    str_contains($clean_uri, 'rest_route=/batch/v1');

        if (!$is_batch) {
            return $extracted;
        }

        // Limit maximum batch JSON length to 65,536 bytes (64KB) to prevent worker DoS
        if (strlen($raw_input) > 65536) {
            return [$raw_input];
        }

        if (!json_validate($raw_input)) {
            return $extracted;
        }
        $decoded = json_decode($raw_input, true);
        if (!is_array($decoded) || empty($decoded['requests']) || !is_array($decoded['requests'])) {
            return $extracted;
        }

        // Bound sub-request count to maximum 25 items to prevent PHP worker exhaustion
        $requests = array_slice($decoded['requests'], 0, 25);

        foreach ($requests as $req) {
            if (!is_array($req)) {
                continue;
            }

            // Extract path/route
            if (!empty($req['path']) && is_string($req['path'])) {
                $extracted[] = $req['path'];
                $path_parts = wp_parse_url($req['path']);
                if (!empty($path_parts['query'])) {
                    $extracted[] = urldecode($path_parts['query']);
                }
            }

            // Extract body
            if (!empty($req['body'])) {
                if (is_array($req['body'])) {
                    $extracted[] = urldecode(http_build_query($req['body']));
                    $extracted[] = (string) wp_json_encode($req['body']);
                } elseif (is_string($req['body'])) {
                    $extracted[] = $req['body'];
                    $extracted[] = urldecode($req['body']);
                }
            }

            // Extract headers (e.g. smuggled X-HTTP-Method-Override or auth tokens)
            if (!empty($req['headers']) && is_array($req['headers'])) {
                foreach ($req['headers'] as $hk => $hv) {
                    if (is_string($hv)) {
                        $extracted[] = "{$hk}: {$hv}";
                    }
                }
            }
        }

        return $extracted;
    }

    /**
     * Flush any IP ban intents queued by Preload Micro-WAF custom rules before WordPress booted.
     *
     * Runs with a zero-overhead file_exists() check and deletes the queue atomically after processing.
     *
     * @return int Number of queued IP bans processed
     */
    public static function flush_preload_ban_queue(): int {
        if (!class_exists(__NAMESPACE__ . '\MicroWafCompiler')) {
            return 0;
        }

        $queue_file = trailingslashit(MicroWafCompiler::get_compiled_dir()) . '.preload_ban_queue.json';
        if (!file_exists($queue_file)) {
            return 0;
        }

        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local compiled WAF queue file read before deletion
        $raw = @file_get_contents($queue_file);
        wp_delete_file($queue_file);

        if (!is_string($raw) || $raw === '') {
            return 0;
        }

        $items = json_decode($raw, true);
        if (!is_array($items) || empty($items)) {
            return 0;
        }

        $processed = 0;
        foreach ($items as $entry) {
            if (!is_array($entry)) {
                continue;
            }
            $ip = sanitize_text_field((string) ($entry['ip'] ?? ''));
            if (!filter_var($ip, FILTER_VALIDATE_IP) || self::is_server_origin_or_loopback($ip)) {
                continue;
            }
            $rule_id = sanitize_text_field((string) ($entry['rule_id'] ?? 'MOD-CUSTOM'));
            $reason = sanitize_text_field((string) ($entry['reason'] ?? 'Preload Micro-WAF Custom Rule Violation'));
            $ban_ttl = isset($entry['ban_ttl']) ? (int) $entry['ban_ttl'] : 0;
            if ($ban_ttl <= 0) {
                continue; // Strictly skip entries with zero or missing ban_ttl; custom rules with ban_ttl=0 must never be promoted to a 24h ban.
            }
            $effective_ttl = $ban_ttl;
            $sync_cf = !empty($entry['sync_cloudflare']);

            self::add_blocked_ip(
                $ip,
                $reason,
                $effective_ttl,
                $rule_id,
                'Preload Micro-WAF Custom Rule',
                'Modular Behavioral WAF',
                null,
                null,
                $sync_cf
            );
            $processed++;
        }

        return $processed;
    }

    /**
     * Synchronize and rotate the cryptographic preload auth cookie used by the pre-boot Micro-WAF.
     *
     * Ensures an authentic, tamper-proof cookie is present for logged-in sessions without relying
     * on unverified cookie name substrings (wordpress_logged_in_*) prior to WordPress core bootstrap.
     *
     * @return void
     */
    public static function sync_preload_auth_cookie(): void {
        if (!function_exists('is_user_logged_in')) {
            return;
        }

        if (!is_user_logged_in()) {
            if (isset($_COOKIE['webcare_preload_auth'])) {
                self::clear_preload_auth_cookie();
            }
            return;
        }

        $raw_c = isset($_COOKIE['webcare_preload_auth']) && is_string($_COOKIE['webcare_preload_auth'])
            ? trim(sanitize_text_field(wp_unslash($_COOKIE['webcare_preload_auth'])))
            : '';
        $needs_refresh = true;

        if ($raw_c !== '') {
            if (strpos($raw_c, '|') === false) {
                $raw_c = (string) @base64_decode($raw_c, true);
            }
            $parts = explode('|', $raw_c);
            if (count($parts) === 4) {
                list($c_uid, $c_is_admin, $c_exp, $c_sig) = $parts;
                $current_uid = (int) get_current_user_id();
                $current_is_admin = current_user_can('manage_options') ? 1 : 0;
                $salt = class_exists(MicroWafCompiler::class) ? MicroWafCompiler::get_preload_auth_key() : (function_exists('wp_salt') ? wp_salt('auth') : 'webcare-preload-auth-salt');
                $ip_bind = self::get_client_ip();
                $expected_sig = hash_hmac('sha256', "{$c_uid}|{$c_is_admin}|{$c_exp}|{$ip_bind}", $salt);

                // If valid, matches current user/role, and has at least 15m remaining, no refresh needed
                if ((int) $c_uid === $current_uid && (int) $c_is_admin === $current_is_admin &&
                    (int) $c_exp > (time() + 900) && hash_equals($expected_sig, $c_sig)) {
                    $needs_refresh = false;
                }
            }
        }

        if ($needs_refresh) {
            self::issue_preload_auth_cookie();
        }
    }

    /**
     * Handle user login hook to issue the preload auth cookie immediately upon sign-in.
     *
     * @param string   $user_login Username.
     * @param \WP_User $user       Authenticated user object.
     * @return void
     */
    public static function on_user_login_preload_auth($user_login, $user): void {
        if ($user instanceof \WP_User && $user->ID > 0) {
            self::issue_preload_auth_cookie($user);
        }
    }

    /**
     * Issue or refresh the cryptographic preload auth cookie for an authenticated user.
     *
     * @param \WP_User|null $user Target user object (defaults to current logged-in user).
     * @return void
     */
    public static function issue_preload_auth_cookie($user = null): void {
        if (headers_sent()) {
            return;
        }

        if ($user === null && function_exists('wp_get_current_user')) {
            $user = wp_get_current_user();
        }

        if (!$user || !($user instanceof \WP_User) || $user->ID <= 0) {
            return;
        }

        $uid      = (int) $user->ID;
        $is_admin = user_can($user, 'manage_options') ? 1 : 0;
        $exp      = time() + 3600; // 1-hour rolling validity
        $ip_bind  = self::get_client_ip();
        $salt     = class_exists(MicroWafCompiler::class) ? MicroWafCompiler::get_preload_auth_key() : (function_exists('wp_salt') ? wp_salt('auth') : 'webcare-preload-auth-salt');
        $payload  = "{$uid}|{$is_admin}|{$exp}";
        $sig      = hash_hmac('sha256', $payload . '|' . $ip_bind, $salt);
        $val      = base64_encode("{$payload}|{$sig}");

        $cookie_path   = defined('COOKIEPATH') && COOKIEPATH ? COOKIEPATH : '/';
        $cookie_domain = defined('COOKIE_DOMAIN') ? COOKIE_DOMAIN : '';
        $secure        = function_exists('is_ssl') && is_ssl();

        // Issue HttpOnly, Secure, SameSite=Lax cookie
        setcookie('webcare_preload_auth', $val, [
            'expires'  => $exp,
            'path'     => $cookie_path,
            'domain'   => $cookie_domain,
            'secure'   => $secure,
            'httponly' => true,
            'samesite' => 'Lax',
        ]);

        $_COOKIE['webcare_preload_auth'] = $val;
    }

    /**
     * Clear the cryptographic preload auth cookie on user logout or session revocation.
     *
     * @return void
     */
    public static function clear_preload_auth_cookie(): void {
        if (!headers_sent()) {
            $cookie_path   = defined('COOKIEPATH') && COOKIEPATH ? COOKIEPATH : '/';
            $cookie_domain = defined('COOKIE_DOMAIN') ? COOKIE_DOMAIN : '';
            $secure        = function_exists('is_ssl') && is_ssl();

            setcookie('webcare_preload_auth', '', [
                'expires'  => time() - 3600,
                'path'     => $cookie_path,
                'domain'   => $cookie_domain,
                'secure'   => $secure,
                'httponly' => true,
                'samesite' => 'Lax',
            ]);
        }

        if (isset($_COOKIE['webcare_preload_auth'])) {
            unset($_COOKIE['webcare_preload_auth']);
        }

        self::invalidate_woocommerce_session_cache();
    }

    /**
     * Generate a signed, time-bounded emergency WAF bypass token for administrative access.
     *
     * @param string|null $ip  Target client IP to bind (defaults to current client IP).
     * @param int         $ttl Time to live in seconds (default 900s / 15m).
     * @return string Formatted as "<timestamp>.<hmac>".
     */
    public static function generate_waf_bypass_token(?string $ip = null, int $ttl = 900): string {
        $bypass_secret = (string) get_option('webcareproscan_micro_waf_bypass_token', '');
        if ($bypass_secret === '') {
            $bypass_secret = function_exists('wp_salt') ? wp_salt('auth') : 'webcare-waf-bypass-salt';
        }
        $ts = time();
        $target_ip = $ip !== null ? trim($ip) : self::get_client_ip();
        if (stripos($target_ip, '::ffff:') === 0) {
            $mapped_v4 = substr($target_ip, 7);
            if (filter_var($mapped_v4, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $target_ip = $mapped_v4;
            }
        }
        $hmac = hash_hmac('sha256', 'wcp_bypass|' . $ts . '|' . $target_ip, $bypass_secret);
        return $ts . '.' . $hmac;
    }

    /**
     * Verify a signed, time-bounded emergency WAF bypass token.
     *
     * @param string      $token     Candidate token string ("<timestamp>.<hmac>").
     * @param string|null $ip        Connecting client IP (defaults to current client IP).
     * @param int         $max_drift Maximum allowable timestamp drift in seconds (default 900s).
     * @return bool
     */
    public static function verify_waf_bypass_token(string $token, ?string $ip = null, int $max_drift = 900): bool {
        $token = trim($token);
        if ($token === '' || strpos($token, '.') === false) {
            return false;
        }
        $parts = explode('.', $token, 2);
        if (count($parts) !== 2 || !ctype_digit((string) $parts[0])) {
            return false;
        }
        $ts = (int) $parts[0];
        $hmac = (string) $parts[1];
        if (abs(time() - $ts) > $max_drift) {
            return false;
        }
        $target_ip = $ip !== null ? trim($ip) : self::get_client_ip();
        if (stripos($target_ip, '::ffff:') === 0) {
            $mapped_v4 = substr($target_ip, 7);
            if (filter_var($mapped_v4, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $target_ip = $mapped_v4;
            }
        }
        $bypass_secret = (string) get_option('webcareproscan_micro_waf_bypass_token', '');
        if ($bypass_secret === '') {
            $bypass_secret = function_exists('wp_salt') ? wp_salt('auth') : 'webcare-waf-bypass-salt';
        }
        $expected_hmac = hash_hmac('sha256', 'wcp_bypass|' . $ts . '|' . $target_ip, $bypass_secret);
        return hash_equals($expected_hmac, $hmac);
    }
}
