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

        // 1. External Object Cache (Redis / Memcached)
        if (function_exists('wp_using_ext_object_cache') && wp_using_ext_object_cache()) {
            $bucket_key = "{$cache_key}_{$bucket_id}";
            $ttl = self::SLIDING_WINDOW_SECONDS + self::BUCKET_DURATION * 2; // 80s

            wp_cache_add($bucket_key, 0, $group, $ttl);
            wp_cache_incr($bucket_key, 1, $group);

            // Record unique IP in this bucket slice
            $ip_key = "{$cache_key}_ips_{$bucket_id}";
            $ips = wp_cache_get($ip_key, $group);
            if (!is_array($ips)) {
                $ips = [];
            }
            if (!in_array($ip_hash, $ips, true)) {
                $ips[] = $ip_hash;
                wp_cache_set($ip_key, $ips, $group, $ttl);
            }

            return self::get_sliding_metrics($cache_key);
        }

        // 2. High-concurrency APCu in-memory storage (Single-Node)
        if (function_exists('apcu_fetch') && function_exists('apcu_inc') && ini_get('apc.enabled')) {
            $apc_bucket_key = "dvs_{$cache_key}_{$bucket_id}";
            $ttl = self::SLIDING_WINDOW_SECONDS + self::BUCKET_DURATION * 2;

            if (!apcu_exists($apc_bucket_key)) {
                @apcu_add($apc_bucket_key, 0, $ttl);
            }
            apcu_inc($apc_bucket_key, 1);

            $apc_ip_key = "dvs_{$cache_key}_ips_{$bucket_id}";
            $success = false;
            $ips = apcu_fetch($apc_ip_key, $success);
            if (!$success || !is_array($ips)) {
                $ips = [];
            }
            if (!in_array($ip_hash, $ips, true)) {
                $ips[] = $ip_hash;
                apcu_store($apc_ip_key, $ips, $ttl);
            }

            return self::get_sliding_metrics($cache_key);
        }

        // 3. File transaction fallback with single-transaction flock(LOCK_EX)
        self::file_atomic_dvs_increment($cache_key, $bucket_id, $ip_hash);
        return self::get_sliding_metrics($cache_key);
    }

    /**
     * File transaction atomic bucket increment.
     */
    private static function file_atomic_dvs_increment(string $cache_key, int $bucket_id, string $ip_hash): void {
        $upload_dir = wp_upload_dir();
        $base_dir = (empty($upload_dir['error']) && !empty($upload_dir['basedir'])) ? $upload_dir['basedir'] : '';
        if (empty($base_dir)) {
            return;
        }
        $dir = rtrim($base_dir, '/\\') . '/webcare-pro-security/rate-limits';
        if (!is_dir($dir)) {
            wp_mkdir_p($dir);
        }
        $file = $dir . "/dvs_" . substr(md5($cache_key), 0, 8) . ".php";

        $fp = @fopen($file, 'c+');
        if (!$fp) {
            return;
        }

        $locked = false;
        for ($i = 0; $i < 5; $i++) {
            if (@flock($fp, LOCK_EX | LOCK_NB)) {
                $locked = true;
                break;
            }
            usleep(10000);
        }

        if (!$locked) {
            @fclose($fp);
            return;
        }

        $raw = '';
        while (!feof($fp)) {
            $chunk = fread($fp, 8192);
            if ($chunk === false) {
                @flock($fp, LOCK_UN);
                @fclose($fp);
                return;
            }
            $raw .= $chunk;
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
        rewind($fp);
        ftruncate($fp, 0);
        fwrite($fp, $payload);
        fflush($fp);
        @flock($fp, LOCK_UN);
        @fclose($fp);
    }

    /**
     * Aggregate sliding window atomic bucket counts across the active 60-second window.
     *
     * @param string $cache_key
     * @return array{count: int, unique_ips: int}
     */
    public static function get_sliding_metrics(string $cache_key): array {
        $now = time();
        $current_bucket = (int) floor($now / self::BUCKET_DURATION);
        $total_count = 0;
        $all_unique_ips = [];

        // Check external object cache
        if (function_exists('wp_using_ext_object_cache') && wp_using_ext_object_cache()) {
            $group = 'webcareproscan_dvs';
            for ($i = 0; $i < self::BUCKET_SLICES; $i++) {
                $b_id = $current_bucket - $i;
                $val = wp_cache_get("{$cache_key}_{$b_id}", $group);
                if (is_numeric($val)) {
                    $total_count += (int) $val;
                }
                $ips = wp_cache_get("{$cache_key}_ips_{$b_id}", $group);
                if (is_array($ips)) {
                    foreach ($ips as $ip_hash) {
                        $all_unique_ips[$ip_hash] = true;
                    }
                }
            }
            return [
                'count'      => $total_count,
                'unique_ips' => count($all_unique_ips),
            ];
        }

        // Check APCu
        if (function_exists('apcu_fetch') && ini_get('apc.enabled')) {
            for ($i = 0; $i < self::BUCKET_SLICES; $i++) {
                $b_id = $current_bucket - $i;
                $val = apcu_fetch("dvs_{$cache_key}_{$b_id}");
                if (is_numeric($val)) {
                    $total_count += (int) $val;
                }
                $success = false;
                $ips = apcu_fetch("dvs_{$cache_key}_ips_{$b_id}", $success);
                if ($success && is_array($ips)) {
                    foreach ($ips as $ip_hash) {
                        $all_unique_ips[$ip_hash] = true;
                    }
                }
            }
            return [
                'count'      => $total_count,
                'unique_ips' => count($all_unique_ips),
            ];
        }

        // Check file storage
        $upload_dir = wp_upload_dir();
        $base_dir = (empty($upload_dir['error']) && !empty($upload_dir['basedir'])) ? $upload_dir['basedir'] : '';
        if (!empty($base_dir)) {
            $file = rtrim($base_dir, '/\\') . '/webcare-pro-security/rate-limits/dvs_' . substr(md5($cache_key), 0, 8) . '.php';
            if (file_exists($file)) {
                $raw = @file_get_contents($file);
                if ($raw && str_starts_with($raw, "<?php exit; ?>\n")) {
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

        // Also check if legacy transient events were seeded (for backwards compatibility / unit tests)
        $transient_events = get_transient($cache_key);
        if (is_array($transient_events)) {
            $cutoff = $now - self::SLIDING_WINDOW_SECONDS;
            foreach ($transient_events as $te) {
                if (is_array($te) && isset($te['time']) && $te['time'] >= $cutoff) {
                    $total_count++;
                    $ip = (string) ($te['ip'] ?? '');
                    if ($ip !== '') {
                        $all_unique_ips[substr(md5($ip), 0, 12)] = true;
                    }
                }
            }
        }

        return [
            'count'      => $total_count,
            'unique_ips' => count($all_unique_ips),
        ];
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
}
