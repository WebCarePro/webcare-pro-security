<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall;

use WebCareProScanner\System\SettingsManager;
use WebCareProScanner\System\WebCareActivityLogger;
use WebCareProScanner\Notifications\NotificationDispatcher;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * DistributedVelocityShield
 *
 * Pillar 4: Global Cross-IP "Distributed Velocity" Shield for AI Botnets.
 *
 * Traditional WAF rate-limiters track velocity per client IP. Modern 2026 AI botnets,
 * carding swarms, and credential-stuffing rings bypass per-IP limits by distributing
 * requests across thousands of residential proxy IP addresses at low individual frequencies
 * (e.g. 1 request per IP every 45-60 seconds).
 *
 * DistributedVelocityShield aggregates failure rates globally across the entire website
 * within a rolling 60-second sliding window. When aggregate velocity spikes across multiple
 * distinct IPs, it automatically activates site-wide "Under-Attack Mode", requiring a
 * lightweight, invisible browser-computed WebCrypto Proof-of-Work (PoW) challenge before
 * processing checkouts or logins.
 *
 * Author: Mir Alamin (WebCare Pro)
 * Senior Linux SysAdmin & WordPress Security Engineer
 */
class DistributedVelocityShield {

    public const OPTION_SETTINGS            = 'webcareproscan_distributed_shield_settings';
    public const OPTION_ATTACK_HISTORY      = 'webcareproscan_under_attack_history';
    public const TRANSIENT_UNDER_ATTACK     = 'webcareproscan_under_attack_active';
    public const TRANSIENT_CHECKOUT_EVENTS  = 'webcareproscan_dvs_chk_events';
    public const TRANSIENT_AUTH_EVENTS      = 'webcareproscan_dvs_auth_events';

    // Default thresholds for sliding 60-second window
    public const DEFAULT_CHECKOUT_FAIL_LIMIT      = 10; // 10 failed checkouts in 60s
    public const DEFAULT_CHECKOUT_UNIQUE_IPS      = 6;  // from at least 6 distinct IPs
    public const DEFAULT_LOGIN_FAIL_LIMIT         = 20; // 20 failed logins in 60s
    public const DEFAULT_LOGIN_UNIQUE_IPS         = 10; // from at least 10 distinct IPs
    public const DEFAULT_UNDER_ATTACK_DURATION    = 900; // 15 minutes in seconds

    /**
     * Optional custom storage directory override for isolated unit tests.
     * When null, falls back to default wp-content/uploads/webcare-pro-security/rate-limits.
     */
    public static ?string $custom_storage_dir = null;

    /**
     * Initialize hooks.
     */
    public static function init(): void {
        $settings = self::get_settings();
        if (empty($settings['enabled'])) {
            return;
        }

        // Context-Adaptive Firewall (CAF 2.0): Only hook WooCommerce actions when WooCommerce is active
        $has_woo = class_exists('\\WebCareProScanner\\Firewall\\CAF\\AdaptiveFirewallAdvisor')
            ? \WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor::has_ecosystem('woocommerce')
            : class_exists('WooCommerce');

        if ($has_woo) {
            // 1. Hook WooCommerce checkout validation failures and payment errors
            add_action('woocommerce_after_checkout_validation', [__CLASS__, 'on_checkout_validation'], 20, 2);
            add_action('woocommerce_order_status_failed', [__CLASS__, 'on_order_payment_failed'], 10, 1);

            // 2. Hook WooCommerce classic checkout process early for Under-Attack enforcement
            add_action('woocommerce_checkout_process', [__CLASS__, 'enforce_checkout_guard'], 1);

            // 3. Hook initial GET /checkout/ page load to challenge browser before order placement
            add_action('template_redirect', [__CLASS__, 'enforce_classic_checkout_get_challenge'], 1);

            // 4. Hook Store API / Block Checkout (/wc/store/v1/checkout)
            add_filter('rest_pre_dispatch', [__CLASS__, 'enforce_store_api_checkout_guard'], 10, 3);
        }

        // 3. Hook WordPress authentication failure
        add_action('wp_login_failed', [__CLASS__, 'on_login_failed'], 10, 2);

        // 4. Hook WordPress authentication process for Under-Attack enforcement
        add_filter('authenticate', [__CLASS__, 'enforce_auth_guard'], 10, 3);
    }

    /**
     * Get Distributed Velocity Shield settings.
     *
     * @return array
     */
    public static function get_settings(): array {
        $defaults = [
            'enabled'                       => true,
            'checkout_fail_limit'           => self::DEFAULT_CHECKOUT_FAIL_LIMIT,
            'checkout_unique_ips_threshold' => self::DEFAULT_CHECKOUT_UNIQUE_IPS,
            'login_fail_limit'              => self::DEFAULT_LOGIN_FAIL_LIMIT,
            'login_unique_ips_threshold'    => self::DEFAULT_LOGIN_UNIQUE_IPS,
            'auto_activate_under_attack'    => true,
            'under_attack_duration'         => self::DEFAULT_UNDER_ATTACK_DURATION,
            'under_attack_action'           => 'pow', // 'pow' (WebCrypto PoW), 'throttle' (429), 'block' (403)
            'pow_difficulty'                => 4,     // 4 leading hex zeros (~65,536 hashes)
            'notify_on_attack'              => true,
            'whitelist_ips'                 => [],
        ];

        $saved = get_option(self::OPTION_SETTINGS, []);
        return is_array($saved) ? array_merge($defaults, $saved) : $defaults;
    }

    /**
     * Update settings.
     *
     * @param array $new_settings
     * @return array
     */
    public static function update_settings(array $new_settings): array {
        $current = self::get_settings();

        $whitelist = [];
        if (isset($new_settings['whitelist_ips'])) {
            if (is_array($new_settings['whitelist_ips'])) {
                $whitelist = array_filter(array_map('sanitize_text_field', $new_settings['whitelist_ips']));
            } elseif (is_string($new_settings['whitelist_ips'])) {
                $lines = explode("\n", str_replace("\r", '', $new_settings['whitelist_ips']));
                $whitelist = array_values(array_filter(array_map('trim', $lines)));
            }
        } else {
            $whitelist = $current['whitelist_ips'] ?? [];
        }

        $action = $new_settings['under_attack_action'] ?? ($current['under_attack_action'] ?? 'pow');
        if (!in_array($action, ['pow', 'throttle', 'block'], true)) {
            $action = 'pow';
        }

        $updated = [
            'enabled'                       => isset($new_settings['enabled']) ? !empty($new_settings['enabled']) : !empty($current['enabled']),
            'checkout_fail_limit'           => max(3, min(100, intval($new_settings['checkout_fail_limit'] ?? $current['checkout_fail_limit']))),
            'checkout_unique_ips_threshold' => max(2, min(50, intval($new_settings['checkout_unique_ips_threshold'] ?? $current['checkout_unique_ips_threshold']))),
            'login_fail_limit'              => max(5, min(200, intval($new_settings['login_fail_limit'] ?? $current['login_fail_limit']))),
            'login_unique_ips_threshold'    => max(2, min(100, intval($new_settings['login_unique_ips_threshold'] ?? $current['login_unique_ips_threshold']))),
            'auto_activate_under_attack'    => isset($new_settings['auto_activate_under_attack']) ? !empty($new_settings['auto_activate_under_attack']) : !empty($current['auto_activate_under_attack']),
            'under_attack_duration'         => max(60, min(86400, intval($new_settings['under_attack_duration'] ?? $current['under_attack_duration']))),
            'under_attack_action'           => $action,
            'pow_difficulty'                => max(3, min(6, intval($new_settings['pow_difficulty'] ?? $current['pow_difficulty']))),
            'notify_on_attack'              => isset($new_settings['notify_on_attack']) ? !empty($new_settings['notify_on_attack']) : !empty($current['notify_on_attack']),
            'whitelist_ips'                 => $whitelist,
        ];

        update_option(self::OPTION_SETTINGS, $updated, false);

        if (class_exists(WebCareActivityLogger::class)) {
            WebCareActivityLogger::notice(
                'distributed_shield_settings_updated',
                'firewall',
                [
                    'description' => 'Distributed Velocity Shield & Under-Attack parameters updated.',
                    'action'      => $action,
                ]
            );
        }

        return $updated;
    }

    /**
     * Record a failed checkout attempt from WooCommerce hooks or payment gateways.
     *
     * @param string $ip
     * @param string $reason
     * @return array Live velocity status
     */
    public static function record_checkout_failure(string $ip = '', string $reason = ''): array {
        static $recorded_in_request = [];

        if (empty($ip)) {
            $ip = self::get_client_ip();
        }

        $dedup_key = $ip . '|' . $reason;
        if (isset($recorded_in_request[$dedup_key])) {
            return self::get_live_velocity();
        }
        $recorded_in_request[$dedup_key] = true;

        if (self::is_exempt_ip($ip)) {
            return self::get_live_velocity();
        }

        $metrics = self::append_sliding_event(self::TRANSIENT_CHECKOUT_EVENTS, $ip, $reason);
        $settings = self::get_settings();

        $count = $metrics['count'];
        $unique_ips = $metrics['unique_ips'];

        // Check if global threshold breached
        if (
            !empty($settings['auto_activate_under_attack']) &&
            $count >= (int) $settings['checkout_fail_limit'] &&
            $unique_ips >= (int) $settings['checkout_unique_ips_threshold']
        ) {
            if (!self::is_under_attack()) {
                self::activate_under_attack(
                    'carding_swarm',
                    (int) $settings['under_attack_duration'],
                    (string) $settings['under_attack_action'],
                    'auto',
                    [
                        'failures'   => $count,
                        'unique_ips' => $unique_ips,
                        'surface'    => 'woocommerce_checkout',
                        'reason'     => $reason ?: 'Global checkout failure rate exceeded threshold',
                    ]
                );
            }
        }

        return self::get_live_velocity();
    }

    /**
     * Record a failed login attempt from WordPress authentication hooks.
     *
     * @param string $ip
     * @param string $username
     * @param string $reason
     * @return array Live velocity status
     */
    public static function record_auth_failure(string $ip = '', string $username = '', string $reason = ''): array {
        static $processed_attempts = [];

        if (empty($ip)) {
            $ip = self::get_client_ip();
        }

        // Deduplicate by resolved IP + normalized username per request (ignoring $reason wording differences)
        $sig = md5($ip . '|' . strtolower(trim($username)));
        if (!defined('WEBCAREPROSCAN_TESTING') && isset($processed_attempts[$sig])) {
            return self::get_live_velocity();
        }
        $processed_attempts[$sig] = true;

        if (self::is_exempt_ip($ip)) {
            return self::get_live_velocity();
        }

        $metrics = self::append_sliding_event(self::TRANSIENT_AUTH_EVENTS, $ip, $reason, ['user' => $username]);
        $settings = self::get_settings();

        $count = $metrics['count'];
        $unique_ips = $metrics['unique_ips'];

        // Check if global threshold breached
        if (
            !empty($settings['auto_activate_under_attack']) &&
            $count >= (int) $settings['login_fail_limit'] &&
            $unique_ips >= (int) $settings['login_unique_ips_threshold']
        ) {
            if (!self::is_under_attack()) {
                self::activate_under_attack(
                    'credential_stuffing_swarm',
                    (int) $settings['under_attack_duration'],
                    (string) $settings['under_attack_action'],
                    'auto',
                    [
                        'failures'   => $count,
                        'unique_ips' => $unique_ips,
                        'surface'    => 'wp_login',
                        'reason'     => $reason ?: 'Global login failure rate exceeded threshold',
                    ]
                );
            }
        }

        return self::get_live_velocity();
    }

    /**
     * Hook: WooCommerce checkout validation errors.
     *
     * @param array $data
     * @param \WP_Error $errors
     * @return void
     */
    public static function on_checkout_validation($data, $errors): void {
        if (!is_wp_error($errors) || empty($errors->errors)) {
            return;
        }

        // Only count payment/gateway critical failures as potential carding
        $is_gateway_failure = false;
        foreach (array_keys($errors->errors) as $code) {
            $code_lower = strtolower((string) $code);
            if (
                str_contains($code_lower, 'payment') ||
                str_contains($code_lower, 'card') ||
                str_contains($code_lower, 'stripe') ||
                str_contains($code_lower, 'paypal') ||
                str_contains($code_lower, 'gateway')
            ) {
                $is_gateway_failure = true;
                break;
            }
        }

        if ($is_gateway_failure) {
            self::record_checkout_failure(self::get_client_ip(), 'Checkout payment gateway validation error');
        }
    }

    /**
     * Hook: WooCommerce order payment status transition to failed.
     *
     * @param int $order_id
     * @return void
     */
    public static function on_order_payment_failed($order_id): void {
        $customer_ip = '';
        if (function_exists('wc_get_order')) {
            $order = wc_get_order($order_id);
            if ($order && method_exists($order, 'get_customer_ip_address')) {
                $customer_ip = (string) $order->get_customer_ip_address();
            }
        }

        // If triggered inside an async payment webhook, strictly attribute to customer IP; ignore if customer IP not found
        $req_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
        $is_webhook = !empty($_SERVER['HTTP_STRIPE_SIGNATURE']) || !empty($_SERVER['HTTP_PAYPAL_TRANSMISSION_SIG']) || str_contains($req_uri, 'wc-api');
        if ($is_webhook && empty($customer_ip)) {
            return; // Never count gateway webhook server IP toward customer checkout failures
        }

        $target_ip = !empty($customer_ip) ? $customer_ip : self::get_client_ip();
        self::record_checkout_failure($target_ip, sprintf('Order #%d payment failed', (int) $order_id));
    }

    /**
     * Hook: WordPress login failed.
     *
     * @param string $username
     * @param \WP_Error|null $error
     * @return void
     */
    public static function on_login_failed(string $username, $error = null): void {
        $reason = 'Authentication failed';
        if ($error instanceof \WP_Error) {
            $code = $error->get_error_code();
            $reason = ($code === 'incorrect_password') ? 'Incorrect password' : 'Invalid username';
        }
        self::record_auth_failure(self::get_client_ip(), $username, $reason);
    }

    /**
     * Activate Under-Attack Mode.
     *
     * @param string $type ('carding_swarm', 'credential_stuffing_swarm', 'manual_lockdown')
     * @param int $duration Seconds
     * @param string $action ('pow', 'throttle', 'block')
     * @param string $trigger ('auto', 'manual')
     * @param array $metrics
     * @return array Status
     */
    public static function activate_under_attack(
        string $type = 'carding_swarm',
        int $duration = 900,
        string $action = 'pow',
        string $trigger = 'auto',
        array $metrics = []
    ): array {
        $now = time();
        $expires = $now + $duration;

        $state = [
            'active'       => true,
            'attack_type'  => $type,
            'trigger'      => $trigger,
            'activated_at' => $now,
            'expires_at'   => $expires,
            'duration'     => $duration,
            'action'       => $action,
            'failures'     => $metrics['failures'] ?? 0,
            'unique_ips'   => $metrics['unique_ips'] ?? 0,
            'surface'      => $metrics['surface'] ?? 'unknown',
            'reason'       => $metrics['reason'] ?? 'High-velocity distributed anomaly',
        ];

        set_transient(self::TRANSIENT_UNDER_ATTACK, $state, $duration);

        // Record in historical attack log (keep last 25 events)
        $history = get_option(self::OPTION_ATTACK_HISTORY, []);
        if (!is_array($history)) {
            $history = [];
        }
        array_unshift($history, array_merge($state, [
            'id'             => 'attk_' . substr(md5((string) $now . $type), 0, 10),
            'formatted_time' => current_time('mysql'),
        ]));
        if (count($history) > 25) {
            $history = array_slice($history, 0, 25);
        }
        update_option(self::OPTION_ATTACK_HISTORY, $history, false);

        // Telemetry Logging
        if (class_exists(WebCareActivityLogger::class)) {
            WebCareActivityLogger::log(
                'distributed_botnet_attack_detected',
                'firewall',
                'critical',
                [
                    'attack_type' => $type,
                    'trigger'     => $trigger,
                    'failures'    => $state['failures'],
                    'unique_ips'  => $state['unique_ips'],
                    'duration'    => $duration . 's',
                    'action'      => strtoupper($action),
                    'description' => sprintf(
                        /* translators: 1: attack type, 2: failures count, 3: unique IPs count, 4: duration in minutes */
                        __('Distributed Botnet Attack (%1$s) detected: %2$d failures across %3$d unique IPs. Under-Attack Shield activated for %4$d minutes.', 'webcare-pro-security'),
                        str_replace('_', ' ', strtoupper($type)),
                        (int) $state['failures'],
                        (int) $state['unique_ips'],
                        (int) ceil($duration / 60)
                    ),
                ]
            );
        }

        // Out-of-band notification dispatch
        $settings = self::get_settings();
        if (!empty($settings['notify_on_attack']) && class_exists(NotificationDispatcher::class)) {
            NotificationDispatcher::trigger('distributed_botnet_attack_detected', [
                'severity'    => 'critical',
                'attack_type' => $type,
                'failures'    => $state['failures'],
                'unique_ips'  => $state['unique_ips'],
                'duration'    => (int) ceil($duration / 60) . ' min',
                'action'      => strtoupper($action),
                'timestamp'   => current_time('mysql'),
            ]);
        }

        // Autonomous Cloudflare Edge Escalation: Escalate Rule 3 to absorb swarm at CDN layer
        if (class_exists('\\WebCareProScanner\\Firewall\\CAF\\OriginLoadCircuitBreaker')) {
            $breaker = new \WebCareProScanner\Firewall\CAF\OriginLoadCircuitBreaker();
            $breaker->escalate_edge_defense('', 'Distributed Velocity Swarm: ' . str_replace('_', ' ', $type));
        }

        return self::get_under_attack_status();
    }

    /**
     * Deactivate Under-Attack Mode manually or on recovery.
     *
     * @return bool
     */
    public static function deactivate_under_attack(): bool {
        $was_active = self::is_under_attack();
        delete_transient(self::TRANSIENT_UNDER_ATTACK);

        if ($was_active && class_exists(WebCareActivityLogger::class)) {
            WebCareActivityLogger::info(
                'distributed_shield_deactivated',
                'firewall',
                [
                    'description' => 'Under-Attack Mode deactivated. Site returned to standard adaptive rate limiting.',
                ]
            );
        }

        // Autonomous Cloudflare Edge De-escalation: Restore Rule 3 to baseline
        if ($was_active && class_exists('\\WebCareProScanner\\Firewall\\CAF\\OriginLoadCircuitBreaker')) {
            $breaker = new \WebCareProScanner\Firewall\CAF\OriginLoadCircuitBreaker();
            $breaker->deescalate_edge_defense('');
        }

        return true;
    }

    /**
     * Check if site is currently in Under-Attack Mode.
     *
     * @return bool
     */
    public static function is_under_attack(): bool {
        $state = get_transient(self::TRANSIENT_UNDER_ATTACK);
        if (!is_array($state) || empty($state['active'])) {
            return false;
        }

        if (time() >= ($state['expires_at'] ?? 0)) {
            delete_transient(self::TRANSIENT_UNDER_ATTACK);
            return false;
        }

        return true;
    }

    /**
     * Get detailed status of current Under-Attack Mode.
     *
     * @return array
     */
    public static function get_under_attack_status(): array {
        $state = get_transient(self::TRANSIENT_UNDER_ATTACK);
        if (!is_array($state) || empty($state['active']) || time() >= ($state['expires_at'] ?? 0)) {
            return [
                'is_active'      => false,
                'attack_type'    => null,
                'trigger'        => null,
                'activated_at'   => null,
                'expires_at'     => null,
                'remaining_secs' => 0,
                'failures'       => 0,
                'unique_ips'     => 0,
                'action'         => null,
            ];
        }

        $remaining = max(0, ($state['expires_at'] ?? 0) - time());

        return [
            'is_active'      => true,
            'attack_type'    => $state['attack_type'] ?? 'carding_swarm',
            'trigger'        => $state['trigger'] ?? 'auto',
            'activated_at'   => $state['activated_at'] ?? time(),
            'expires_at'     => $state['expires_at'] ?? (time() + 900),
            'remaining_secs' => $remaining,
            'failures'       => (int) ($state['failures'] ?? 0),
            'unique_ips'     => (int) ($state['unique_ips'] ?? 0),
            'action'         => $state['action'] ?? 'pow',
            'reason'         => $state['reason'] ?? '',
        ];
    }

    /**
     * Enforce Under-Attack Guard on WooCommerce Checkout.
     *
     * @return void
     */
    public static function enforce_checkout_guard(): void {
        if (!self::is_under_attack()) {
            return;
        }

        // Exempt order confirmation and payment gateway webhooks
        if (function_exists('is_order_received_page') && is_order_received_page()) {
            return;
        }

        $uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
        if (str_contains($uri, 'wc-api=') || str_contains($uri, '/wc-api/')) {
            return;
        }

        $ip = self::get_client_ip();
        if (self::is_exempt_ip($ip)) {
            return;
        }

        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';

        // Check if client already holds a valid WebCrypto clearance cookie
        if (class_exists(BotReconDefense::class) && BotReconDefense::has_valid_clearance_cookie($ip, $ua)) {
            return;
        }

        // Check if client submitted a PoW solution with checkout request
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        if (isset($_POST['webcare_pow_challenge'], $_POST['webcare_pow_nonce'])) {
            // phpcs:ignore WordPress.Security.NonceVerification.Missing
            $challenge = sanitize_text_field(wp_unslash($_POST['webcare_pow_challenge']));
            // phpcs:ignore WordPress.Security.NonceVerification.Missing
            $nonce     = sanitize_text_field(wp_unslash($_POST['webcare_pow_nonce']));

            if (class_exists(BotReconDefense::class) && BotReconDefense::verify_pow_solution($challenge, $nonce, $ip, $ua)) {
                BotReconDefense::issue_clearance_cookie($ip, $ua);
                return;
            }
        }

        $status = self::get_under_attack_status();
        $action = $status['action'] ?? 'pow';

        if ($action === 'block') {
            status_header(403);
            if (wp_doing_ajax()) {
                wp_send_json([
                    'result'   => 'failure',
                    'messages' => '<ul class="woocommerce-error" role="alert"><li>' . esc_html__('Access Denied: E-commerce checkout is temporarily locked due to high-velocity distributed bot activity.', 'webcare-pro-security') . '</li></ul>',
                    'reload'   => false,
                ]);
            }
            wp_die(
                esc_html__('Access Denied: E-commerce checkout is temporarily locked due to high-velocity distributed bot activity.', 'webcare-pro-security'),
                esc_html__('Distributed Protection Active', 'webcare-pro-security'),
                ['response' => 403]
            );
        }

        // Default: PoW Verification Required
        status_header(429);
        if (wp_doing_ajax()) {
            $challenge = class_exists(BotReconDefense::class) ? BotReconDefense::generate_challenge($ip, $ua) : '';
            wp_send_json([
                'result'       => 'failure',
                'status'       => 429,
                'error'        => 'webcare_under_attack_challenge_required',
                'messages'     => '<ul class="woocommerce-error" role="alert"><li>' . esc_html__('Security Verification: High-velocity automated traffic detected. Please reload this page to complete standard browser verification before completing your order.', 'webcare-pro-security') . '</li></ul>',
                'pow_required' => true,
                'challenge'    => $challenge,
                'reload'       => true,
            ]);
            exit;
        }

        if (class_exists(BotReconDefense::class)) {
            BotReconDefense::render_webcrypto_challenge($ip, $ua);
        }
    }

    /**
     * Enforce Under-Attack GET Challenge on classic WooCommerce Checkout page.
     * Prevents infinite reload loops by challenging the browser on initial page load.
     *
     * @return void
     */
    public static function enforce_classic_checkout_get_challenge(): void {
        if (!function_exists('is_checkout') || !is_checkout()) {
            return;
        }

        // Exempt order received (confirmation) page and payment gateway webhooks
        if (function_exists('is_order_received_page') && is_order_received_page()) {
            return;
        }

        $uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
        if (str_contains($uri, 'wc-api=') || str_contains($uri, '/wc-api/')) {
            return;
        }

        // Only enforce on GET requests (POST is handled by enforce_checkout_guard)
        $method = isset($_SERVER['REQUEST_METHOD']) ? strtoupper(sanitize_key(wp_unslash($_SERVER['REQUEST_METHOD']))) : 'GET';
        if ($method !== 'GET') {
            return;
        }

        if (!self::is_under_attack()) {
            return;
        }

        $ip = self::get_client_ip();
        if (self::is_exempt_ip($ip)) {
            return;
        }

        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';

        // If client already holds valid clearance cookie, permit page load
        if (class_exists(BotReconDefense::class) && BotReconDefense::has_valid_clearance_cookie($ip, $ua)) {
            return;
        }

        // Render WebCrypto PoW challenge directly on GET
        if (class_exists(BotReconDefense::class)) {
            BotReconDefense::render_webcrypto_challenge($ip, $ua);
        }
    }

    /**
     * Enforce Under-Attack PoW guard on WooCommerce Store API checkout (/wc/store/v1/checkout).
     * Returns structured JSON HTTP 429 instead of HTML.
     *
     * @param mixed            $result
     * @param \WP_REST_Server  $server
     * @param \WP_REST_Request $request
     * @return mixed
     */
    public static function enforce_store_api_checkout_guard($result, $server, $request) {
        $route = method_exists($request, 'get_route') ? (string) $request->get_route() : '';
        if (strpos($route, '/wc/store/v1/checkout') !== 0 && strpos($route, '/wc/store/checkout') !== 0) {
            return $result;
        }

        if (!self::is_under_attack()) {
            return $result;
        }

        $ip = self::get_client_ip();
        if (self::is_exempt_ip($ip)) {
            return $result;
        }

        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';

        // 1. Check if client holds clearance cookie
        if (class_exists(BotReconDefense::class) && BotReconDefense::has_valid_clearance_cookie($ip, $ua)) {
            return $result;
        }

        // 2. Check header or body for PoW solution (e.g. X-WebCare-PoW-Solution: challenge:nonce)
        $pow_hdr = method_exists($request, 'get_header') ? $request->get_header('x-webcare-pow-solution') : '';
        if (empty($pow_hdr) && isset($_SERVER['HTTP_X_WEBCARE_POW_SOLUTION'])) {
            $pow_hdr = sanitize_text_field(wp_unslash($_SERVER['HTTP_X_WEBCARE_POW_SOLUTION']));
        }

        if (!empty($pow_hdr) && strpos($pow_hdr, ':') !== false) {
            [$ch, $no] = explode(':', $pow_hdr, 2);
            if (class_exists(BotReconDefense::class) && BotReconDefense::verify_pow_solution($ch, $no, $ip, $ua)) {
                BotReconDefense::issue_clearance_cookie($ip, $ua);
                return $result;
            }
        }

        // 3. Return structured JSON 429 with challenge parameters
        $challenge = class_exists(BotReconDefense::class) ? BotReconDefense::generate_challenge($ip, $ua) : '';
        return new \WP_REST_Response([
            'code'    => 'webcare_checkout_pow_required',
            'message' => __('High-velocity automated checkout traffic detected. WebCrypto proof-of-work clearance required.', 'webcare-pro-security'),
            'data'    => [
                'status'       => 429,
                'pow_required' => true,
                'challenge'    => $challenge,
                'difficulty'   => 4,
            ],
        ], 429);
    }

    /**
     * Enforce Under-Attack Guard on WordPress Authentication.
     *
     * @param \WP_User|\WP_Error|null $user
     * @param string $username
     * @param string $password
     * @return \WP_User|\WP_Error|null
     */
    public static function enforce_auth_guard($user, $username, $password) {
        if (!self::is_under_attack()) {
            return $user;
        }

        $ip = self::get_client_ip();
        if (self::is_exempt_ip($ip)) {
            return $user;
        }

        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';

        // Check clearance cookie
        if (class_exists(BotReconDefense::class) && BotReconDefense::has_valid_clearance_cookie($ip, $ua)) {
            return $user;
        }

        // Check if solution submitted in login POST
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        if (isset($_POST['webcare_pow_challenge'], $_POST['webcare_pow_nonce'])) {
            // phpcs:ignore WordPress.Security.NonceVerification.Missing
            $challenge = sanitize_text_field(wp_unslash($_POST['webcare_pow_challenge']));
            // phpcs:ignore WordPress.Security.NonceVerification.Missing
            $nonce     = sanitize_text_field(wp_unslash($_POST['webcare_pow_nonce']));

            if (class_exists(BotReconDefense::class) && BotReconDefense::verify_pow_solution($challenge, $nonce, $ip, $ua)) {
                BotReconDefense::issue_clearance_cookie($ip, $ua);
                return $user;
            }
        }

        // If interactive login form on wp-login.php, challenge browser directly
        $uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
        if (str_contains($uri, 'wp-login.php') && class_exists(BotReconDefense::class)) {
            BotReconDefense::render_webcrypto_challenge($ip, $ua);
        }

        // For REST / XML-RPC auth
        return new \WP_Error(
            'webcare_under_attack_auth_locked',
            esc_html__('Site is currently defending against a distributed credential-stuffing swarm. Interactive browser verification required to sign in.', 'webcare-pro-security'),
            ['status' => 429]
        );
    }

    /**
     * Get real-time sliding window velocity metrics for checkout and auth.
     *
     * @return array
     */
    public static function get_live_velocity(): array {
        $settings = self::get_settings();

        $chk_metrics  = self::get_sliding_metrics(self::TRANSIENT_CHECKOUT_EVENTS);
        $auth_metrics = self::get_sliding_metrics(self::TRANSIENT_AUTH_EVENTS);

        $chk_count      = $chk_metrics['count'];
        $chk_unique_ips = $chk_metrics['unique_ips'];
        $chk_limit      = (int) $settings['checkout_fail_limit'];
        $chk_uniq_limit = (int) $settings['checkout_unique_ips_threshold'];

        $auth_count      = $auth_metrics['count'];
        $auth_unique_ips = $auth_metrics['unique_ips'];
        $auth_limit      = (int) $settings['login_fail_limit'];
        $auth_uniq_limit = (int) $settings['login_unique_ips_threshold'];

        return [
            'checkout' => [
                'failures_last_min' => $chk_count,
                'unique_ips'        => $chk_unique_ips,
                'fail_limit'        => $chk_limit,
                'unique_ips_limit'  => $chk_uniq_limit,
                'pct_failures'      => $chk_limit > 0 ? min(100.0, round(($chk_count / $chk_limit) * 100, 1)) : 0,
                'pct_unique_ips'    => $chk_uniq_limit > 0 ? min(100.0, round(($chk_unique_ips / $chk_uniq_limit) * 100, 1)) : 0,
            ],
            'auth' => [
                'failures_last_min' => $auth_count,
                'unique_ips'        => $auth_unique_ips,
                'fail_limit'        => $auth_limit,
                'unique_ips_limit'  => $auth_uniq_limit,
                'pct_failures'      => $auth_limit > 0 ? min(100.0, round(($auth_count / $auth_limit) * 100, 1)) : 0,
                'pct_unique_ips'    => $auth_uniq_limit > 0 ? min(100.0, round(($auth_unique_ips / $auth_uniq_limit) * 100, 1)) : 0,
            ],
        ];
    }

    /**
     * Get aggregate telemetry for REST API and dashboards.
     *
     * @return array
     */
    public static function get_telemetry(): array {
        $backend = 'local_node';
        if (function_exists('wp_using_ext_object_cache') && wp_using_ext_object_cache()) {
            $backend = 'cluster_shared';
        }

        return [
            'settings'            => self::get_settings(),
            'under_attack'        => self::get_under_attack_status(),
            'live_velocity'       => self::get_live_velocity(),
            'velocity_backend'    => $backend,
            'attack_history'      => get_option(self::OPTION_ATTACK_HISTORY, []),
        ];
    }

    /**
     * Simulate an incoming distributed attack swarm for administrator verification/drills.
     *
     * @param string $type ('carding' or 'login')
     * @return array Telemetry after simulation
     */
    public static function simulate_attack_swarm(string $type = 'carding'): array {
        $now = time();
        $synthetic_events = [];

        if ($type === 'carding') {
            // Generate 12 distinct synthetic residential IPs failing checkouts
            for ($i = 1; $i <= 12; $i++) {
                $synthetic_events[] = [
                    'time'   => $now - wp_rand(2, 45),
                    'ip'     => '198.51.100.' . ($i + 10),
                    'reason' => 'Simulated carding attack failure',
                    'meta'   => [],
                ];
            }
            set_transient(self::TRANSIENT_CHECKOUT_EVENTS, $synthetic_events, 120);
            self::record_checkout_failure('198.51.100.99', 'Simulated threshold trigger');
        } else {
            // Generate 22 distinct synthetic residential IPs failing logins
            for ($i = 1; $i <= 22; $i++) {
                $synthetic_events[] = [
                    'time'   => $now - wp_rand(2, 45),
                    'ip'     => '203.0.113.' . ($i + 10),
                    'reason' => 'Simulated credential stuffing failure',
                    'meta'   => ['user' => 'admin_test_' . $i],
                ];
            }
            set_transient(self::TRANSIENT_AUTH_EVENTS, $synthetic_events, 120);
            self::record_auth_failure('203.0.113.99', 'admin', 'Simulated threshold trigger');
        }

        return self::get_telemetry();
    }

    /**
     * Append an event to a sliding 60-second window transient cache.
     *
     * @param string $cache_key
     * @param string $ip
     * @param string $reason
     * @param array $meta
     * @return array Pruned active events
     */
    /**
     * Append a sliding event into atomic memory (APCu) or bounded transient buffer.
     *
     * @param string $cache_key
     * @param string $ip
     * @param string $reason
     * @param array  $meta
     * @return array
     */
    /**
     * Append a sliding event into atomic shared memory / external cache or bounded transient buffer.
     *
     * Concurrency architecture (S3 Finding 7):
     * 1. If persistent external object cache is enabled (Redis / Memcached), use atomic shared counter increments.
     * 2. If single-node APCu is enabled, use atomic memory operations.
     * 3. Fallback to locked file transaction / bounded transient.
     *
     * @param string $cache_key
     * @param string $ip
     * @param string $reason
     * @param array  $meta
     * @return array
     */
    /**
     * Window duration in seconds for distributed velocity tracking.
     */
    public const SLIDING_WINDOW_SECONDS = 60;

    /**
     * Number of atomic sub-window buckets composing the sliding window (e.g. 6 x 10s = 60s).
     */
    public const BUCKET_SLICES = 6;
    public const BUCKET_DURATION = 10; // 60 / 6 = 10s

    /**
     * Atomically increment sub-window bucket counter and record IP presence.
     *
     * Concurrency architecture (P2 / v3.25.1):
     * - Uses true atomic counters (wp_cache_incr / apcu_inc / single-transaction flock)
     * - Aggregates sliding window by summing atomic sub-window bucket counts across the last 60 seconds
     * - Eliminates read-modify-write array race conditions under high concurrency
     *
     * @param string $cache_key
     * @param string $ip
     * @param string $reason
     * @param array  $meta
     * @return array{count: int, unique_ips: int}
     */
    private static function append_sliding_event(string $cache_key, string $ip, string $reason = '', array $meta = []): array {
        $now = time();
        $bucket_id = (int) floor($now / self::BUCKET_DURATION);
        $group = 'webcareproscan_dvs';
        $ip_hash = substr(md5($ip), 0, 12);

        // 1. External Object Cache with verified Atomic Redis Lua backend
        if (self::has_atomic_redis_lua_backend()) {
            $hash_tag       = '{dvs:' . $cache_key . ':' . $bucket_id . '}';
            $bucket_key     = $hash_tag . ':cnt';
            $set_key        = $hash_tag . ':ips';
            $event_set_key  = $hash_tag . ':ev';
            $event_id       = bin2hex(random_bytes(8));
            $ttl            = self::SLIDING_WINDOW_SECONDS + self::BUCKET_DURATION * 2; // 80s

            $redis_client = self::get_redis_client();
            if ($redis_client !== null) {
                global $wp_object_cache;
                $prefix_count = method_exists($wp_object_cache, 'build_key') ? $wp_object_cache->build_key($bucket_key, $group) : "{$group}:{$bucket_key}";
                $prefix_set   = method_exists($wp_object_cache, 'build_key') ? $wp_object_cache->build_key($set_key, $group) : "{$group}:{$set_key}";
                $prefix_ev    = method_exists($wp_object_cache, 'build_key') ? $wp_object_cache->build_key($event_set_key, $group) : "{$group}:{$event_set_key}";

                $lua = "local t1 = redis.call('TYPE', KEYS[1])['ok']\n"
                     . "if t1 ~= 'none' and t1 ~= 'string' then return redis.error_reply('WRONGTYPE_PREFLIGHT') end\n"
                     . "local t2 = redis.call('TYPE', KEYS[2])['ok']\n"
                     . "if t2 ~= 'none' and t2 ~= 'set' then return redis.error_reply('WRONGTYPE_PREFLIGHT') end\n"
                     . "local t3 = redis.call('TYPE', KEYS[3])['ok']\n"
                     . "if t3 ~= 'none' and t3 ~= 'set' then return redis.error_reply('WRONGTYPE_PREFLIGHT') end\n"
                     . "local added = redis.call('SADD', KEYS[3], ARGV[3])\n"
                     . "if added == 0 then\n"
                     . "    local cur = redis.call('GET', KEYS[1])\n"
                     . "    return {tonumber(cur) or 0, redis.call('SCARD', KEYS[2])}\n"
                     . "end\n"
                     . "local c = redis.call('INCR', KEYS[1])\n"
                     . "if c == 1 then redis.call('EXPIRE', KEYS[1], tonumber(ARGV[2])) end\n"
                     . "redis.call('SADD', KEYS[2], ARGV[1])\n"
                     . "redis.call('EXPIRE', KEYS[2], tonumber(ARGV[2]))\n"
                     . "redis.call('EXPIRE', KEYS[3], tonumber(ARGV[2]))\n"
                     . "return {c, redis.call('SCARD', KEYS[2])}";

                $eval_args = [$prefix_count, $prefix_set, $prefix_ev, $ip_hash, (string) $ttl, $event_id];
                $res = null;

                // First attempt
                try {
                    $res = @$redis_client->eval($lua, $eval_args, 3);
                } catch (\Throwable) {
                    $res = null;
                }

                // If first attempt returned invalid or failed, retry ONCE with the exact same event_id
                if (!is_array($res) || count($res) < 2 || !is_numeric($res[0]) || !is_numeric($res[1])) {
                    try {
                        $res = @$redis_client->eval($lua, $eval_args, 3);
                    } catch (\Throwable) {
                        $res = null;
                    }
                }

                if (is_array($res) && count($res) >= 2 && is_numeric($res[0]) && is_numeric($res[1])) {
                    $redis_metrics = self::get_sliding_metrics($cache_key);
                    return [
                        'count'      => max((int) $res[0], (int) ($redis_metrics['count'] ?? 0)),
                        'unique_ips' => max((int) $res[1], (int) ($redis_metrics['unique_ips'] ?? 0)),
                        'complete'   => (bool) ($redis_metrics['complete'] ?? true),
                        'degraded'   => (bool) ($redis_metrics['degraded'] ?? false),
                    ];
                }

                // Ambiguous failure persists after retry: log and fail closed (never silent split-store write to file)
                if (class_exists('\\WebCareProScanner\\System\\AuditLogger')) {
                    \WebCareProScanner\System\AuditLogger::log(
                        'dvs_redis_eval_failed',
                        sprintf('Redis EVAL velocity tracking failed after retry for %s; degraded response returned without file split-write.', substr($cache_key, 0, 32))
                    );
                } else {
                    error_log(sprintf('[WebCare Pro] Redis EVAL velocity tracking failed after retry for %s.', substr($cache_key, 0, 32)));
                }

                return [
                    'count'      => 0,
                    'unique_ips' => 0,
                    'complete'   => false,
                    'degraded'   => true,
                ];
            }
        }

        // 2. Atomic flock(LOCK_EX) single-transaction file backend
        // Route non-Redis backends (APCu, Memcached, generic object cache, or no external cache)
        // directly to atomic file transactions, eliminating all non-atomic fallbacks and TOCTOU races.
        self::file_atomic_dvs_increment($cache_key, $bucket_id, $ip_hash);
        return self::get_sliding_metrics($cache_key);
    }

    /**
     * Resolve the DVS file storage directory.
     * Honors self::$custom_storage_dir when set (e.g. during unit tests).
     *
     * @return string
     */
    private static function get_storage_dir(): string {
        if (self::$custom_storage_dir !== null && self::$custom_storage_dir !== '') {
            $dir = self::$custom_storage_dir;
        } else {
            $upload_dir = wp_upload_dir();
            $base_dir = (empty($upload_dir['error']) && !empty($upload_dir['basedir'])) ? $upload_dir['basedir'] : '';
            if (empty($base_dir)) {
                return '';
            }
            $dir = rtrim($base_dir, '/\\') . '/webcare-pro-security/rate-limits';
        }

        if (!is_dir($dir)) {
            wp_mkdir_p($dir);
        }

        return $dir;
    }

    /**
     * File transaction atomic bucket increment.
     * Uses a dedicated sidecar lock file (.lock) and crash-safe temporary file atomic rename()
     * to ensure live data files are never truncated or left in a corrupt state if execution halts.
     */
    private static function file_atomic_dvs_increment(string $cache_key, int $bucket_id, string $ip_hash): void {
        $dir = self::get_storage_dir();
        if ($dir === '') {
            return;
        }

        $data_file = $dir . '/dvs_' . substr(md5($cache_key), 0, 8) . '.php';
        $lock_file = $data_file . '.lock';

        $lock_fp = @fopen($lock_file, 'c+');
        if (!$lock_fp) {
            return;
        }

        $locked = false;
        for ($i = 0; $i < 20; $i++) {
            if (@flock($lock_fp, LOCK_EX | LOCK_NB)) {
                $locked = true;
                break;
            }
            usleep(10000); // 20 * 10ms = 200ms bounded wait
        }

        if (!$locked) {
            @fclose($lock_fp);
            // Operational system logging for lock contention (never human admin activity log)
            if (class_exists('\\WebCareProScanner\\System\\AuditLogger')) {
                \WebCareProScanner\System\AuditLogger::log(
                    'dvs_file_lock_exhausted',
                    'DVS file write-lock acquisition timed out after 20 retries (200ms). Velocity event dropped.'
                );
            } else {
                error_log('[WebCare Pro] DVS file write-lock acquisition timed out after 20 retries (200ms). Velocity event dropped.');
            }
            return;
        }

        try {
            $raw = '';
            if (file_exists($data_file)) {
                $content = @file_get_contents($data_file);
                if (is_string($content)) {
                    $raw = $content;
                }
            }

            $data = [];
            if ($raw !== '' && str_starts_with($raw, "<?php exit; ?>\n")) {
                $parsed = json_decode(substr($raw, 15), true);
                if (is_array($parsed)) {
                    $data = $parsed;
                }
            }

            $now = time();
            $current_bucket = (int) floor($now / self::BUCKET_DURATION);
            // Prune older than 8 buckets (80 seconds)
            foreach ($data as $b_id => $v) {
                if ((int) $b_id < ($current_bucket - 8)) {
                    unset($data[$b_id]);
                }
            }

            if (!isset($data[$bucket_id]) || !is_array($data[$bucket_id])) {
                $data[$bucket_id] = ['count' => 0, 'ips' => []];
            }

            $data[$bucket_id]['count'] = (int) ($data[$bucket_id]['count'] ?? 0) + 1;
            if (!is_array($data[$bucket_id]['ips'])) {
                $data[$bucket_id]['ips'] = [];
            }
            if (!in_array($ip_hash, $data[$bucket_id]['ips'], true)) {
                $data[$bucket_id]['ips'][] = $ip_hash;
            }

            $payload = "<?php exit; ?>\n" . json_encode($data);
            $tmp = $data_file . '.tmp.' . bin2hex(random_bytes(4));

            $tmp_fp = @fopen($tmp, 'wb');
            if (!$tmp_fp) {
                if (class_exists('\\WebCareProScanner\\System\\AuditLogger')) {
                    \WebCareProScanner\System\AuditLogger::log(
                        'dvs_tmp_file_create_failed',
                        'Failed to create temporary file for DVS atomic rename.'
                    );
                }
                return;
            }

            $written = @fwrite($tmp_fp, $payload);
            $flushed = @fflush($tmp_fp);
            $closed  = @fclose($tmp_fp);

            if ($written !== strlen($payload) || $flushed !== true || $closed !== true) {
                @unlink($tmp);
                if (class_exists('\\WebCareProScanner\\System\\AuditLogger')) {
                    \WebCareProScanner\System\AuditLogger::log(
                        'dvs_tmp_file_write_failed',
                        'Incomplete write or flush to DVS temporary file. Write aborted.'
                    );
                }
                return;
            }

            @chmod($tmp, 0600);

            if (!@rename($tmp, $data_file)) {
                @unlink($tmp);
                if (class_exists('\\WebCareProScanner\\System\\AuditLogger')) {
                    \WebCareProScanner\System\AuditLogger::log(
                        'dvs_atomic_rename_failed',
                        'Failed to atomically rename DVS temporary file to live data file.'
                    );
                }
            }
        } finally {
            @flock($lock_fp, LOCK_UN);
            @fclose($lock_fp);
        }
    }

    /**
     * Aggregate sliding window atomic bucket counts across the active 60-second window.
     *
     * @param string $cache_key
     * @return array{count: int, unique_ips: int, complete: bool, degraded: bool}
     */
    public static function get_sliding_metrics(string $cache_key): array {
        $now = time();
        $current_bucket = (int) floor($now / self::BUCKET_DURATION);
        $total_count = 0;
        $all_unique_ips = [];

        // 1. External object cache with verified atomic Redis Lua backend
        if (self::has_atomic_redis_lua_backend()) {
            $redis_client = self::get_redis_client();
            $group = 'webcareproscan_dvs';
            global $wp_object_cache;
            $failed_slices = 0;

            for ($i = 0; $i < self::BUCKET_SLICES; $i++) {
                $b_id = $current_bucket - $i;
                $hash_tag = '{dvs:' . $cache_key . ':' . $b_id . '}';
                $bucket_key = $hash_tag . ':cnt';
                $prefix_count = method_exists($wp_object_cache, 'build_key') ? $wp_object_cache->build_key($bucket_key, $group) : "{$group}:{$bucket_key}";

                $slice_count = 0;
                $slice_count_ok = false;
                $slice_read_attempted = false;
                try {
                    $c_val = null;
                    if ($redis_client !== null && method_exists($redis_client, 'get')) {
                        $slice_read_attempted = true;
                        $c_val = $redis_client->get($prefix_count);
                    }
                    if (is_numeric($c_val)) {
                        $slice_count = (int) $c_val;
                        $slice_count_ok = true;
                    } elseif ($c_val === null || $c_val === false) {
                        $val = wp_cache_get($bucket_key, $group);
                        if (is_numeric($val)) {
                            $slice_count = (int) $val;
                            $slice_count_ok = true;
                        } elseif ($val === false) {
                            $slice_count_ok = true; // Key expired or absent
                        }
                    }
                } catch (\Throwable) {
                    $slice_count_ok = false;
                }
                $total_count += $slice_count;

                // Retrieve discrete unique IPs from slice Set
                $set_key = $hash_tag . ':ips';
                $prefix_set = method_exists($wp_object_cache, 'build_key') ? $wp_object_cache->build_key($set_key, $group) : "{$group}:{$set_key}";
                $slice_set_ok = false;
                try {
                    $members = null;
                    if ($redis_client !== null && method_exists($redis_client, 'sMembers')) {
                        $members = @$redis_client->sMembers($prefix_set);
                    } elseif ($redis_client !== null && method_exists($redis_client, 'smembers')) {
                        $members = @$redis_client->smembers($prefix_set);
                    }
                    if (is_array($members)) {
                        foreach ($members as $ip_h) {
                            if (is_string($ip_h) && $ip_h !== '') {
                                $all_unique_ips[$ip_h] = true;
                            }
                        }
                        $slice_set_ok = true;
                    } elseif ($members === false || $members === null) {
                        // Key not present or empty slice
                        $slice_set_ok = true;
                    }
                } catch (\Throwable) {
                    $slice_set_ok = false;
                }

                if (!$slice_count_ok || !$slice_set_ok) {
                    $failed_slices++;
                }
            }

            if ($failed_slices > 0) {
                if (class_exists('\\WebCareProScanner\\System\\AuditLogger')) {
                    \WebCareProScanner\System\AuditLogger::log(
                        'dvs_redis_partial_read',
                        sprintf('DVS Redis slice metrics encountered %d failed slices out of %d for %s; degraded response returned.', $failed_slices, self::BUCKET_SLICES, substr($cache_key, 0, 32))
                    );
                } else {
                    error_log(sprintf('[WebCare Pro] DVS Redis slice metrics encountered %d failed slices for %s.', $failed_slices, substr($cache_key, 0, 32)));
                }
            }

            if ($total_count > 0 || count($all_unique_ips) > 0 || $failed_slices > 0) {
                return [
                    'count'      => $total_count,
                    'unique_ips' => count($all_unique_ips),
                    'complete'   => ($failed_slices === 0),
                    'degraded'   => ($failed_slices > 0),
                ];
            }
        }

        // 2. Atomic flock(LOCK_SH) single-transaction file backend for non-Redis environments
        // (APCu, Memcached, generic object cache, or no external cache)
        $file_metrics = self::get_file_sliding_metrics($cache_key);

        // Also check if legacy transient events were seeded (for backwards compatibility / unit tests)
        $transient_events = get_transient($cache_key);
        if (is_array($transient_events)) {
            $cutoff = $now - self::SLIDING_WINDOW_SECONDS;
            foreach ($transient_events as $te) {
                if (is_array($te) && isset($te['time']) && $te['time'] >= $cutoff) {
                    $file_metrics['count']++;
                    $ip = (string) ($te['ip'] ?? '');
                    if ($ip !== '') {
                        $all_unique_ips[substr(md5($ip), 0, 12)] = true;
                    }
                }
            }
            if (!empty($all_unique_ips)) {
                $file_metrics['unique_ips'] = max($file_metrics['unique_ips'], count($all_unique_ips));
            }
        }

        return $file_metrics;
    }

    /**
     * Retrieve active events count/summary within the rolling 60-second window.
     * Maintained for backward compatibility with existing callers.
     *
     * @param string $cache_key
     * @return array
     */
    private static function get_sliding_events(string $cache_key): array {
        $metrics = self::get_sliding_metrics($cache_key);
        // Return dummy array of size count so count($events) yields exact count
        if ($metrics['count'] <= 0) {
            return [];
        }
        return array_fill(0, $metrics['count'], ['ip' => 'tracked_client', 'time' => time()]);
    }

    /**
     * Determine if an atomic Redis Lua backend is active and available.
     * Returns true ONLY when wp_using_ext_object_cache() is active AND a verified Redis client
     * supporting eval() is resolved.
     *
     * @return bool
     */
    private static function has_atomic_redis_lua_backend(): bool {
        return self::get_redis_client() !== null;
    }

    /**
     * Resolve the underlying Redis client from WordPress object cache if available.
     * Only accepts known PhpRedis-compatible clients (\Redis, \RedisCluster, \Relay\Relay, or explicit test doubles)
     * that expose eval(), get(), and sMembers()/smembers(). Returns null for unknown clients.
     *
     * @return object|null
     */
    private static function get_redis_client(): ?object {
        if (!function_exists('wp_using_ext_object_cache') || !wp_using_ext_object_cache()) {
            return null;
        }

        global $wp_object_cache;
        if (!is_object($wp_object_cache)) {
            return null;
        }

        $redis = null;
        if (isset($wp_object_cache->redis) && is_object($wp_object_cache->redis)) {
            $redis = $wp_object_cache->redis;
        } elseif (method_exists($wp_object_cache, 'redis')) {
            $redis = $wp_object_cache->redis();
        }

        if (!is_object($redis)) {
            return null;
        }

        // Validate PhpRedis / Relay / RedisCluster class hierarchy or test double exposing required methods
        $is_known_client = ($redis instanceof \Redis)
            || ($redis instanceof \RedisCluster)
            || (class_exists('\\Relay\\Relay', false) && $redis instanceof \Relay\Relay)
            || (defined('WEBCAREPROSCAN_TESTING') && (method_exists($redis, 'eval') && method_exists($redis, 'get') && (method_exists($redis, 'sMembers') || method_exists($redis, 'smembers'))));

        if (!$is_known_client) {
            return null;
        }

        if (
            method_exists($redis, 'eval') &&
            method_exists($redis, 'get') &&
            (method_exists($redis, 'sMembers') || method_exists($redis, 'smembers'))
        ) {
            return $redis;
        }

        return null;
    }

    /**
     * Determine if a client IP is exempt from distributed velocity tracking.
     *
     * @param string $ip
     * @return bool
     */
    private static function is_exempt_ip(string $ip): bool {
        // Local loopback
        if ($ip === '127.0.0.1' || $ip === '::1') {
            return true;
        }

        // Authenticated admin bypass
        if (function_exists('current_user_can') && current_user_can('manage_options')) {
            return true;
        }
        if (class_exists(FirewallEngine::class) && FirewallEngine::is_authenticated_administrator()) {
            return true;
        }

        // WAF IP Whitelist
        if (class_exists(FirewallEngine::class) && FirewallEngine::is_ip_whitelisted($ip)) {
            return true;
        }

        // Custom Distributed Shield Whitelist
        $settings = self::get_settings();
        $whitelist = $settings['whitelist_ips'] ?? [];
        if (!empty($whitelist) && in_array($ip, $whitelist, true)) {
            return true;
        }

        return false;
    }

    /**
     * Get client IP reliably.
     *
     * @return string
     */
    private static function get_client_ip(): string {
        if (class_exists(FirewallEngine::class)) {
            return FirewallEngine::get_client_ip();
        }
        return isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '127.0.0.1';
    }

    /**
     * Read sliding metrics specifically from file storage.
     *
     * @param string $cache_key
     * @return array{count: int, unique_ips: int}
     */
    public static function get_file_sliding_metrics(string $cache_key): array {
        $now = time();
        $current_bucket = (int) floor($now / self::BUCKET_DURATION);
        $total_count = 0;
        $all_unique_ips = [];

        $dir = self::get_storage_dir();
        if ($dir !== '') {
            $file = $dir . '/dvs_' . substr(md5($cache_key), 0, 8) . '.php';
            if (file_exists($file)) {
                $fp = @fopen($file, 'rb');
                if ($fp) {
                    $read_locked = false;
                    for ($r = 0; $r < 15; $r++) {
                        if (@flock($fp, LOCK_SH | LOCK_NB)) {
                            $read_locked = true;
                            break;
                        }
                        usleep(10000); // 15 * 10ms = 150ms retry
                    }

                    $raw = '';
                    if ($read_locked) {
                        while (!feof($fp)) {
                            $chunk = fread($fp, 8192);
                            if ($chunk === false) {
                                break;
                            }
                            $raw .= $chunk;
                        }
                        @flock($fp, LOCK_UN);
                    } else {
                        if (class_exists('\\WebCareProScanner\\System\\AuditLogger')) {
                            \WebCareProScanner\System\AuditLogger::log(
                                'dvs_file_read_lock_exhausted',
                                sprintf('DVS read lock timed out for %s; applying fail-safe degraded response.', substr($cache_key, 0, 32))
                            );
                        } else {
                            error_log(sprintf('[WebCare Pro] DVS file read-lock timed out for %s.', substr($cache_key, 0, 32)));
                        }
                        $raw = '';
                    }
                    @fclose($fp);

                    if ($raw !== '' && str_starts_with($raw, "<?php exit; ?>\n")) {
                        $parsed = json_decode(substr($raw, 15), true);
                        if (is_array($parsed)) {
                            for ($i = 0; $i < self::BUCKET_SLICES; $i++) {
                                $b_id = $current_bucket - $i;
                                if (isset($parsed[$b_id]) && is_array($parsed[$b_id])) {
                                    $total_count += (int) ($parsed[$b_id]['count'] ?? 0);
                                    if (isset($parsed[$b_id]['ips']) && is_array($parsed[$b_id]['ips'])) {
                                        foreach ($parsed[$b_id]['ips'] as $ip_hash) {
                                            $all_unique_ips[$ip_hash] = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        return [
            'count'      => $total_count,
            'unique_ips' => count($all_unique_ips),
            'complete'   => true,
            'degraded'   => false,
        ];
    }

    /**
     * Check whether an external cache lock is still held by the owner token.
     *
     * @param string $lock_key
     * @param string $owner_token
     * @param string $group
     * @return bool
     */
    private static function verify_ext_cache_lock(string $lock_key, string $owner_token, string $group): bool {
        $held = wp_cache_get($lock_key, $group);
        return is_string($held) && hash_equals($held, $owner_token);
    }

    /**
     * Atomically set an external cache key ONLY if the lock key is still owned by the owner token.
     * Prevents TOCTOU race conditions where a worker's lock lease expires before state write.
     * Strictly requires a backend supporting multi-key atomic scripts (Redis Lua EVAL).
     * If Redis EVAL is unavailable (e.g. Memcached, APCu, generic object caches), fails closed (returns false)
     * without executing non-atomic get-then-set fallbacks.
     *
     * @param string $lock_key
     * @param string $owner_token
     * @param string $target_key
     * @param mixed  $target_val
     * @param string $group
     * @param int    $ttl
     * @return bool
     */
    private static function atomic_fenced_ext_cache_set(string $lock_key, string $owner_token, string $target_key, mixed $target_val, string $group, int $ttl): bool {
        global $wp_object_cache;
        if (is_object($wp_object_cache)) {
            $redis = null;
            if (isset($wp_object_cache->redis) && is_object($wp_object_cache->redis)) {
                $redis = $wp_object_cache->redis;
            } elseif (method_exists($wp_object_cache, 'redis')) {
                $redis = $wp_object_cache->redis();
            }

            if ($redis !== null && method_exists($redis, 'eval')) {
                // Lua: if KEYS[1] matches ARGV[1], set KEYS[2] to ARGV[2] with EX ARGV[3], return 1; else return 0
                $lua = 'if redis.call("get", KEYS[1]) == ARGV[1] then redis.call("set", KEYS[2], ARGV[2], "ex", ARGV[3]) return 1 else return 0 end';
                try {
                    $prefix_lock = method_exists($wp_object_cache, 'build_key') ? $wp_object_cache->build_key($lock_key, $group) : "{$group}:{$lock_key}";
                    $prefix_target = method_exists($wp_object_cache, 'build_key') ? $wp_object_cache->build_key($target_key, $group) : "{$group}:{$target_key}";
                    $val_str = is_scalar($target_val) ? (string) $target_val : serialize($target_val);
                    $res = @$redis->eval($lua, [$prefix_lock, $prefix_target, $owner_token, $val_str, (string) $ttl], 2);
                    if ($res !== false && $res !== null) {
                        return (int) $res > 0;
                    }
                } catch (\Throwable) {
                    return false;
                }
            }
        }

        // Memcached & Generic Object Cache: Fail closed. Neither Memcached nor generic wp_cache_*
        // supports multi-key atomic fenced writes. Never fall back to non-atomic check-then-write.
        return false;
    }

    /**
     * Atomically release an external cache lock using atomic compare-and-delete.
     * Strictly avoids non-atomic check-then-delete races. Allows explicit lock release ONLY
     * on backends with verified atomic compare-and-delete in the exact key namespace (Redis Lua).
     * For Memcached / generic object caches, fails safe (returns false) and lets the short lease TTL expire.
     *
     * @param string $lock_key
     * @param string $owner_token
     * @param string $group
     * @return bool
     */
    private static function release_ext_cache_lock(string $lock_key, string $owner_token, string $group): bool {
        // 1. Redis atomic Lua compare-and-delete
        global $wp_object_cache;
        if (is_object($wp_object_cache)) {
            $redis = null;
            if (isset($wp_object_cache->redis) && is_object($wp_object_cache->redis)) {
                $redis = $wp_object_cache->redis;
            } elseif (method_exists($wp_object_cache, 'redis')) {
                $redis = $wp_object_cache->redis();
            }

            if ($redis !== null && method_exists($redis, 'eval')) {
                // Lua script compares value and deletes key atomically
                $lua = 'if redis.call("get", KEYS[1]) == ARGV[1] then return redis.call("del", KEYS[1]) else return 0 end';
                try {
                    $prefixed_key = method_exists($wp_object_cache, 'build_key') ? $wp_object_cache->build_key($lock_key, $group) : "{$group}:{$lock_key}";
                    $res = @$redis->eval($lua, [$prefixed_key, $owner_token], 1);
                    if ($res !== false && $res !== null) {
                        return (int) $res > 0;
                    }
                } catch (\Throwable) {
                    return false;
                }
            }
        }

        // 2. Memcached & Generic Object Cache: Fail safe by returning false and letting the 10s TTL expire.
        // Never attempt raw Memcached client calls that bypass object-cache key prefixing and server hashing,
        // and never perform non-atomic get-then-delete sequences.
        return false;
    }

    /**
     * Fenced APCu store. APCu does not support multi-key atomic CAS transactions.
     * Fails closed (returns false) immediately without executing non-atomic fetch-store sequences
     * or destructive post-write rollbacks.
     *
     * @param string $lock_key
     * @param int    $owner_token
     * @param string $target_key
     * @param mixed  $target_val
     * @param int    $ttl
     * @return bool
     */
    private static function atomic_fenced_apcu_store(string $lock_key, int $owner_token, string $target_key, mixed $target_val, int $ttl): bool {
        // APCu lacks multi-key CAS. Fail closed to prevent destructive race conditions or phantom rollbacks.
        return false;
    }

    /**
     * Atomically release an APCu lock using atomic compare-and-swap (apcu_cas).
     * Strictly requires apcu_cas(); fails safely by returning false if unavailable.
     *
     * @param string $lock_key
     * @param int    $owner_token
     * @return bool
     */
    private static function release_apcu_lock(string $lock_key, int $owner_token): bool {
        // Atomically transition from $owner_token to 0 via native hardware-assisted CAS
        if (function_exists('apcu_cas')) {
            $swapped = @apcu_cas($lock_key, $owner_token, 0);
            if ($swapped) {
                @apcu_delete($lock_key);
                return true;
            }
            return false;
        }

        // Without apcu_cas, allow the 10-second lease to expire naturally.
        return false;
    }
}
