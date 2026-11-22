<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall\Core;

use WebCareProScanner\Firewall\FirewallEngine;
use WebCareProScanner\Firewall\BotReconDefense;
use WebCareProScanner\System\SettingsManager;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Commerce Velocity Guard & 404 Scanner Rate Limiter.
 *
 * Enforces rate limiting on checkout failures (carding defense), coupon enumeration,
 * customer registration bursts, add-to-cart hoarding, and catalog price scraping,
 * while protecting legitimate customers from 404 lockout penalties.
 *
 * @package WebCareProScanner\Firewall\Core
 */
class CommerceVelocityGuard {

    /**
     * Common disposable, temporary, and throwaway email domains used by spam registration bots.
     */
    public const DISPOSABLE_EMAIL_DOMAINS = [
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
     * Rule #38: Check if client IP is currently locked out by WooCommerce Carding Defense.
     *
     * @return \WP_Error|false
     */
    public static function check_woo_carding_lockout() {
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_woo_carding_protection'])) {
            return false;
        }

        $client_ip = ClientIpResolver::get_client_ip();
        if (empty($client_ip)) {
            return false;
        }

        $lock_key = 'webcareproscan_chk_lock_' . md5($client_ip);
        $is_locked = get_transient($lock_key);
        if (!$is_locked) {
            return false;
        }

        $rule_triggered = [
            'id'          => 'WAF-WOO-CARDING-BLOCKED',
            'name'        => 'WooCommerce Carding Attack & Checkout Velocity Mitigation (Rule #38)',
            'category'    => 'Behavioral Defense',
            'description' => sprintf(
                /* translators: 1: Client IP address */
                __('Blocked repeated checkout attempt from temporarily locked-out IP %1$s (Carding Velocity Defense).', 'webcare-pro-security'),
                $client_ip
            ),
            'match_type'  => 'Carding Velocity Threshold',
            'match_value' => $client_ip,
            'payload'     => "IP: {$client_ip} Locked due to excessive failed checkout attempts",
        ];

        FirewallEngine::log_incident($rule_triggered, 'blocked');

        return new \WP_Error(
            'webcareproscan_carding_lockout',
            esc_html__('Too many checkout attempts detected from your connection. For security purposes, checkout has been temporarily paused for 30 minutes. Please contact customer support if you need immediate assistance.', 'webcare-pro-security'),
            ['status' => 429]
        );
    }

    /**
     * Rule #38: Inspect early WooCommerce checkout attempts before validation/order processing.
     *
     * @return void
     */
    public static function inspect_woo_checkout_attempt(): void {
        $lock_error = self::check_woo_carding_lockout();
        if (!$lock_error) {
            return;
        }

        $error_message = $lock_error->get_error_message();

        if (wp_doing_ajax()) {
            wp_send_json([
                'result'   => 'failure',
                'messages' => '<ul class="woocommerce-error" role="alert"><li>' . esc_html($error_message) . '</li></ul>',
                'refresh'  => false,
                'reload'   => false,
            ]);
            exit;
        }

        if (function_exists('wc_add_notice')) {
            wc_add_notice($error_message, 'error');
        }
    }

    /**
     * Rule #38: Track checkout failures from validation errors on checkout form.
     *
     * @param array $data
     * @param \WP_Error $errors
     * @return void
     */
    public static function handle_woo_checkout_validation($data, $errors): void {
        if (!is_wp_error($errors) || empty($errors->errors)) {
            return;
        }

        $has_critical_failure = false;
        foreach ($errors->errors as $code => $messages) {
            $code_lower = strtolower((string) $code);
            if (str_contains($code_lower, 'payment') || str_contains($code_lower, 'card') || str_contains($code_lower, 'stripe') || str_contains($code_lower, 'paypal') || str_contains($code_lower, 'gateway')) {
                $has_critical_failure = true;
                break;
            }
        }

        if ($has_critical_failure) {
            self::record_failed_checkout_attempt('Payment gateway validation error');
        }
    }

    /**
     * Rule #38: Track order payment status changing to 'failed'.
     *
     * @param int $order_id
     * @return void
     */
    public static function handle_woo_payment_failure($order_id): void {
        $customer_ip = '';
        if (function_exists('wc_get_order')) {
            $order = wc_get_order($order_id);
            if ($order && method_exists($order, 'get_customer_ip_address')) {
                $customer_ip = (string) $order->get_customer_ip_address();
            }
        }
        self::record_failed_checkout_attempt('Order status transitioned to failed', $customer_ip);
    }

    /**
     * Rule #38: Record a failed checkout attempt and trigger lockout if threshold is exceeded.
     *
     * @param string $reason
     * @param string $override_ip Explicit shopper IP address
     * @return void
     */
    public static function record_failed_checkout_attempt(string $reason = '', string $override_ip = ''): void {
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_woo_carding_protection'])) {
            return;
        }

        $req_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
        $is_webhook = !empty($_SERVER['HTTP_STRIPE_SIGNATURE']) || !empty($_SERVER['HTTP_PAYPAL_TRANSMISSION_SIG']) || str_contains($req_uri, 'wc-api');
        if ($is_webhook && empty($override_ip)) {
            return;
        }

        $client_ip = !empty($override_ip) ? trim($override_ip) : ClientIpResolver::get_client_ip();
        if (empty($client_ip)) {
            return;
        }

        if (FirewallEngine::is_ip_whitelisted($client_ip)) {
            return;
        }

        $max_attempts = (int) ($settings['waf_woo_checkout_max_attempts'] ?? 3);
        $lockout_duration_mins = (int) ($settings['waf_woo_carding_lockout_duration'] ?? 30);
        $window_seconds = 300;

        $attempt_key = 'webcareproscan_chk_fail_' . md5($client_ip);
        $lock_key    = 'webcareproscan_chk_lock_' . md5($client_ip);

        if (get_transient($lock_key)) {
            return;
        }

        $current_attempts = (int) get_transient($attempt_key);
        $new_attempts = $current_attempts + 1;

        if ($new_attempts >= $max_attempts) {
            set_transient($lock_key, [
                'ip'         => $client_ip,
                'attempts'   => $new_attempts,
                'locked_at'  => time(),
                'expires_at' => time() + ($lockout_duration_mins * MINUTE_IN_SECONDS),
                'reason'     => $reason,
            ], $lockout_duration_mins * MINUTE_IN_SECONDS);

            delete_transient($attempt_key);

            $rule_triggered = [
                'id'          => 'WAF-WOO-CARDING-THRESHOLD',
                'name'        => 'WooCommerce Carding Attack Velocity Threshold Exceeded (Rule #38)',
                'category'    => 'Behavioral Defense',
                'description' => sprintf(
                    /* translators: 1: Client IP address, 2: Number of failed attempts, 3: Lockout duration in minutes */
                    __('IP %1$s exceeded checkout failure threshold (%2$d attempts in 5 min) - locked out for %3$d minutes.', 'webcare-pro-security'),
                    $client_ip,
                    $new_attempts,
                    $lockout_duration_mins
                ),
                'match_type'  => 'Carding Velocity Exceeded',
                'match_value' => $client_ip,
                'payload'     => "IP: {$client_ip} Trigger: {$reason} Attempts: {$new_attempts} / Limit: {$max_attempts}",
            ];

            FirewallEngine::log_incident($rule_triggered, 'blocked');
        } else {
            set_transient($attempt_key, $new_attempts, $window_seconds);
        }
    }

    /**
     * Rule #39: Check if client IP is currently locked out by WooCommerce Coupon Enumeration Mitigation.
     *
     * @return \WP_Error|false
     */
    public static function check_woo_coupon_lockout() {
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_woo_coupon_protection'])) {
            return false;
        }

        $client_ip = ClientIpResolver::get_client_ip();
        if (empty($client_ip)) {
            return false;
        }

        $lock_key = 'webcareproscan_cpn_lock_' . md5($client_ip);
        $is_locked = get_transient($lock_key);
        if (!$is_locked) {
            return false;
        }

        $rule_triggered = [
            'id'          => 'WAF-WOO-COUPON-BLOCKED',
            'name'        => 'WooCommerce Coupon Enumeration & Brute-Force Shield (Rule #39)',
            'category'    => 'Behavioral Defense',
            'description' => sprintf(
                /* translators: 1: Client IP address */
                __('Blocked repeated coupon testing attempt from temporarily locked-out IP %1$s (Coupon Brute-Force Defense).', 'webcare-pro-security'),
                $client_ip
            ),
            'match_type'  => 'Coupon Velocity Threshold',
            'match_value' => $client_ip,
            'payload'     => "IP: {$client_ip} Locked due to excessive invalid coupon attempts",
        ];

        FirewallEngine::log_incident($rule_triggered, 'blocked');

        return new \WP_Error(
            'webcareproscan_coupon_lockout',
            esc_html__('Too many invalid coupon attempts detected from your connection. For security purposes, coupon redemption has been temporarily paused for 15 minutes. Please contact support if you need assistance.', 'webcare-pro-security'),
            ['status' => 429]
        );
    }

    /**
     * Rule #39: Intercept WooCommerce coupon application error filter (`woocommerce_coupon_error`).
     *
     * @param string $err
     * @param int|string $err_code
     * @param \WC_Coupon|null $coupon
     * @return string
     */
    public static function handle_woo_coupon_error($err, $err_code, $coupon = null): string {
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_woo_coupon_protection'])) {
            return $err;
        }

        $lock_error = self::check_woo_coupon_lockout();
        if ($lock_error) {
            return $lock_error->get_error_message();
        }

        $coupon_code = ($coupon instanceof \WC_Coupon) ? $coupon->get_code() : '';
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        if (empty($coupon_code) && !empty($_POST['coupon_code'])) {
            // phpcs:ignore WordPress.Security.NonceVerification.Missing
            $coupon_code = sanitize_text_field(wp_unslash($_POST['coupon_code']));
        }

        self::record_failed_coupon_attempt($coupon_code, is_numeric($err_code) ? (int) $err_code : 0);

        $recheck_lock = self::check_woo_coupon_lockout();
        if ($recheck_lock) {
            return $recheck_lock->get_error_message();
        }

        return $err;
    }

    /**
     * Rule #39: Clear failed attempts when a valid coupon is successfully applied.
     *
     * @param string $coupon_code
     * @return void
     */
    public static function handle_woo_coupon_success(string $coupon_code): void {
        $client_ip = ClientIpResolver::get_client_ip();
        if (!empty($client_ip)) {
            delete_transient('webcareproscan_cpn_fail_' . md5($client_ip));
        }
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
        $route = $request->get_route();
        if (!preg_match('#^/wc/store(?:/v\d+)?/cart/(?:coupons|apply-coupon)#i', $route)) {
            return $response;
        }

        if (is_wp_error($response)) {
            $code = $response->get_error_code();
            if ($code === 'woocommerce_rest_cart_coupon_error' || $code === 'invalid_coupon') {
                $coupon_code = $request->get_param('code') ?: '';
                self::record_failed_coupon_attempt($coupon_code, 0);

                $lock_error = self::check_woo_coupon_lockout();
                if ($lock_error) {
                    return $lock_error;
                }
            }
        } elseif ($response instanceof \WP_REST_Response && $response->get_status() >= 400) {
            $coupon_code = $request->get_param('code') ?: '';
            self::record_failed_coupon_attempt($coupon_code, 0);

            $lock_error = self::check_woo_coupon_lockout();
            if ($lock_error) {
                return $lock_error;
            }
        }

        return $response;
    }

    /**
     * Rule #39: Record a failed coupon attempt and trigger lockout if threshold is exceeded.
     *
     * @param string $coupon_code
     * @param int $err_code
     * @return void
     */
    public static function record_failed_coupon_attempt(string $coupon_code = '', int $err_code = 0): void {
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_woo_coupon_protection'])) {
            return;
        }

        $client_ip = ClientIpResolver::get_client_ip();
        if (empty($client_ip)) {
            return;
        }

        if (FirewallEngine::is_ip_whitelisted($client_ip)) {
            return;
        }

        $max_failures = (int) ($settings['waf_woo_coupon_max_failures'] ?? 8);
        $lockout_duration_mins = (int) ($settings['waf_woo_coupon_lockout_duration'] ?? 15);
        $window_seconds = 300;

        if (CommerceSessionGuard::has_active_shopper_session()) {
            $max_failures += 4;
        }

        $attempt_key = 'webcareproscan_cpn_fail_' . md5($client_ip);
        $lock_key    = 'webcareproscan_cpn_lock_' . md5($client_ip);

        if (get_transient($lock_key)) {
            return;
        }

        $current_attempts = (int) get_transient($attempt_key);
        $new_attempts = $current_attempts + 1;

        if ($new_attempts >= $max_failures) {
            set_transient($lock_key, [
                'ip'         => $client_ip,
                'attempts'   => $new_attempts,
                'locked_at'  => time(),
                'expires_at' => time() + ($lockout_duration_mins * MINUTE_IN_SECONDS),
                'last_code'  => $coupon_code,
            ], $lockout_duration_mins * MINUTE_IN_SECONDS);

            delete_transient($attempt_key);

            $rule_triggered = [
                'id'          => 'WAF-WOO-COUPON-THRESHOLD',
                'name'        => 'WooCommerce Coupon Enumeration Velocity Threshold Exceeded (Rule #39)',
                'category'    => 'Behavioral Defense',
                'description' => sprintf(
                    /* translators: 1: Client IP address, 2: Number of failed attempts, 3: Lockout duration in minutes */
                    __('IP %1$s exceeded coupon failure threshold (%2$d invalid attempts in 5 min) - locked out from coupon testing for %3$d minutes.', 'webcare-pro-security'),
                    $client_ip,
                    $new_attempts,
                    $lockout_duration_mins
                ),
                'match_type'  => 'Coupon Velocity Exceeded',
                'match_value' => $client_ip,
                'payload'     => "IP: {$client_ip} Last Coupon: {$coupon_code} ErrorCode: {$err_code} Attempts: {$new_attempts} / Limit: {$max_failures}",
            ];

            FirewallEngine::log_incident($rule_triggered, 'blocked');
        } else {
            set_transient($attempt_key, $new_attempts, $window_seconds);
        }
    }

    /**
     * Rule #40: Validate customer registration attempts across WooCommerce.
     *
     * @param \WP_Error $errors
     * @param string $username
     * @param string $email
     * @return \WP_Error
     */
    public static function validate_woo_customer_registration($errors, $username, $email) {
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_woo_registration_protection'])) {
            return $errors;
        }

        if (!is_wp_error($errors)) {
            $errors = new \WP_Error();
        }

        $client_ip = ClientIpResolver::get_client_ip();
        if (empty($client_ip)) {
            return $errors;
        }

        if (FirewallEngine::is_ip_whitelisted($client_ip)) {
            return $errors;
        }

        // 1. Disposable / Temporary Email Domain Filter
        if (!empty($settings['waf_woo_reg_block_disposable_emails']) && !empty($email)) {
            $parts = explode('@', $email);
            if (count($parts) === 2) {
                $domain = strtolower(trim($parts[1]));
                if (in_array($domain, self::DISPOSABLE_EMAIL_DOMAINS, true)) {
                    $rule_triggered = [
                        'id'          => 'WAF-WOO-REG-DISPOSABLE-EMAIL',
                        'name'        => 'WooCommerce Disposable Email Registration Block (Rule #40)',
                        'category'    => 'Behavioral Defense',
                        'description' => sprintf(
                            /* translators: 1: Client IP, 2: Disposable email domain */
                            __('Blocked customer registration from IP %1$s using throwaway email domain "@%2$s".', 'webcare-pro-security'),
                            $client_ip,
                            $domain
                        ),
                        'match_type'  => 'Disposable Email Domain',
                        'match_value' => $domain,
                        'payload'     => "IP: {$client_ip} Email: {$email} Domain: {$domain}",
                    ];

                    FirewallEngine::log_incident($rule_triggered, 'blocked');

                    $errors->add(
                        'webcareproscan_disposable_email_blocked',
                        esc_html__('Temporary and disposable email addresses are not permitted. Please register with a permanent, valid email address.', 'webcare-pro-security')
                    );
                    return $errors;
                }
            }
        }

        // 2. IP Registration Velocity Rate-Limiting
        $max_registrations = (int) ($settings['waf_woo_reg_max_per_ip'] ?? 3);
        $window_hours = (int) ($settings['waf_woo_reg_window_hours'] ?? 1);
        $window_seconds = $window_hours * HOUR_IN_SECONDS;

        $reg_key = 'webcareproscan_reg_ip_' . md5($client_ip);
        $count = (int) get_transient($reg_key);

        if ($count >= $max_registrations) {
            $rule_triggered = [
                'id'          => 'WAF-WOO-REG-VELOCITY-BLOCKED',
                'name'        => 'WooCommerce Customer Registration Velocity Limit (Rule #40)',
                'category'    => 'Behavioral Defense',
                'description' => sprintf(
                    /* translators: 1: Client IP, 2: Registration limit, 3: Window hours */
                    __('Customer registration rate limit exceeded from IP %1$s (%2$d accounts created in %3$d hour(s)).', 'webcare-pro-security'),
                    $client_ip,
                    $max_registrations,
                    $window_hours
                ),
                'match_type'  => 'Registration Velocity Exceeded',
                'match_value' => $client_ip,
                'payload'     => "IP: {$client_ip} Attempted Email: {$email} Count: {$count} / Limit: {$max_registrations}",
            ];

            FirewallEngine::log_incident($rule_triggered, 'blocked');

            $errors->add(
                'webcareproscan_reg_velocity_limit',
                esc_html__('Too many accounts have been created from your connection recently. Please wait before attempting to register another account or contact customer service.', 'webcare-pro-security')
            );
            return $errors;
        }

        return $errors;
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
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_woo_registration_protection'])) {
            return;
        }

        $client_ip = ClientIpResolver::get_client_ip();
        if (empty($client_ip)) {
            return;
        }

        $window_hours = (int) ($settings['waf_woo_reg_window_hours'] ?? 1);
        $window_seconds = $window_hours * HOUR_IN_SECONDS;

        $reg_key = 'webcareproscan_reg_ip_' . md5($client_ip);
        $count = (int) get_transient($reg_key);
        set_transient($reg_key, $count + 1, $window_seconds);
    }

    /**
     * Rule #41: Validate WooCommerce add-to-cart operations against cart flooding and inventory exhaustion.
     *
     * @param bool $passed
     * @param int $product_id
     * @param int $quantity
     * @param int $variation_id
     * @param array $variations
     * @return bool
     */
    public static function validate_woo_add_to_cart($passed, $product_id, $quantity, $variation_id = 0, $variations = []): bool {
        if (!$passed) {
            return false;
        }

        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_woo_cart_flood_protection'])) {
            return $passed;
        }

        $client_ip = ClientIpResolver::get_client_ip();
        if (empty($client_ip)) {
            return $passed;
        }

        if (FirewallEngine::is_ip_whitelisted($client_ip)) {
            return $passed;
        }

        // 1. Add-to-Cart Velocity Rate-Limiting
        $rate_limit = (int) ($settings['waf_woo_add_to_cart_rate_limit'] ?? 15);
        $velocity_key = 'webcareproscan_cart_vel_' . md5($client_ip);
        $current_hits = (int) get_transient($velocity_key);

        if ($current_hits >= $rate_limit) {
            $rule_triggered = [
                'id'          => 'WAF-WOO-CART-VELOCITY-BLOCKED',
                'name'        => 'WooCommerce Cart Flooding Velocity Limit (Rule #41)',
                'category'    => 'Behavioral Defense',
                'description' => sprintf(
                    /* translators: 1: Client IP, 2: Rate limit count */
                    __('Blocked rapid add-to-cart flood from IP %1$s (exceeded %2$d additions per minute).', 'webcare-pro-security'),
                    $client_ip,
                    $rate_limit
                ),
                'match_type'  => 'Cart Addition Velocity',
                'match_value' => $client_ip,
                'payload'     => "IP: {$client_ip} Product: {$product_id} Hits: {$current_hits} / Limit: {$rate_limit}",
            ];

            FirewallEngine::log_incident($rule_triggered, 'blocked');

            if (function_exists('wc_add_notice')) {
                wc_add_notice(
                    esc_html__('You are adding items too quickly. Please pause for a moment before adding more items to your cart.', 'webcare-pro-security'),
                    'error'
                );
            }
            return false;
        }

        set_transient($velocity_key, $current_hits + 1, 60);

        // 2. Maximum Cumulative Cart Items Check
        if (function_exists('WC') && WC()->cart) {
            $max_cart_items = (int) ($settings['waf_woo_max_cart_items'] ?? 50);
            $current_cart_count = (int) WC()->cart->get_cart_contents_count();
            $target_count = $current_cart_count + max(1, (int) $quantity);

            if ($target_count > $max_cart_items) {
                $rule_triggered = [
                    'id'          => 'WAF-WOO-INVENTORY-HOARDING',
                    'name'        => 'WooCommerce Denial of Inventory Cap Exceeded (Rule #41)',
                    'category'    => 'Behavioral Defense',
                    'description' => sprintf(
                        /* translators: 1: Client IP, 2: Target item count, 3: Max allowed items */
                        __('Blocked inventory hoarding attempt from IP %1$s (cart item count %2$d would exceed cap %3$d).', 'webcare-pro-security'),
                        $client_ip,
                        $target_count,
                        $max_cart_items
                    ),
                    'match_type'  => 'Cart Volume Cap',
                    'match_value' => $client_ip,
                    'payload'     => "IP: {$client_ip} Current: {$current_cart_count} Adding: {$quantity} Cap: {$max_cart_items}",
                ];

                FirewallEngine::log_incident($rule_triggered, 'blocked');

                if (function_exists('wc_add_notice')) {
                    wc_add_notice(
                        sprintf(
                            /* translators: %d: Maximum allowed items in cart */
                            esc_html__('Your shopping cart has reached the maximum permitted volume of %d items. Please proceed to checkout or remove unused items.', 'webcare-pro-security'),
                            $max_cart_items
                        ),
                        'error'
                    );
                }
                return false;
            }
        }

        return $passed;
    }

    /**
     * Rule #42: Inspect incoming storefront requests on `template_redirect` for aggressive catalog scraping.
     *
     * @return void
     */
    public static function inspect_woo_catalog_scraping(): void {
        if (!function_exists('is_woocommerce') && !function_exists('is_product')) {
            return;
        }

        $is_catalog_page = (function_exists('is_shop') && is_shop())
            || (function_exists('is_product_taxonomy') && is_product_taxonomy())
            || (function_exists('is_product_category') && is_product_category())
            || (function_exists('is_product_tag') && is_product_tag())
            || (function_exists('is_product') && is_product());

        if (!$is_catalog_page) {
            return;
        }

        $lock_error = self::check_and_track_catalog_scraping('Storefront Catalog Page');
        if ($lock_error) {
            status_header(429);
            header('Retry-After: 900');
            $client_ip = ClientIpResolver::get_client_ip();
            $rule_triggered = [
                'id'          => 'WAF-WOO-SCRAPING-BLOCKED',
                'name'        => 'WooCommerce Catalog & Price Scraping Mitigation (Rule #42)',
                'category'    => 'Behavioral Defense',
                'description' => sprintf(
                    /* translators: 1: Client IP address */
                    __('Catalog request blocked from IP %1$s due to aggressive price/inventory scraping velocity.', 'webcare-pro-security'),
                    $client_ip
                ),
                'match_type'  => 'Catalog Scraping Velocity',
                'match_value' => $client_ip,
                'payload'     => "IP: {$client_ip} URI: " . (isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : ''),
            ];
            FirewallEngine::log_incident($rule_triggered, 'blocked');
            wp_die(
                esc_html__('Too many requests. Automated catalog scraping has been temporarily restricted for your connection. Please wait 15 minutes before browsing again.', 'webcare-pro-security'),
                esc_html__('Too Many Requests', 'webcare-pro-security'),
                ['response' => 429]
            );
        }
    }

    /**
     * Rule #42: Check if client IP is locked out or increments catalog hit velocity.
     *
     * @param string $source
     * @return \WP_Error|false
     */
    public static function check_and_track_catalog_scraping(string $source = '') {
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_woo_scraping_protection'])) {
            return false;
        }

        $client_ip = ClientIpResolver::get_client_ip();
        if (empty($client_ip)) {
            return false;
        }

        if (FirewallEngine::is_ip_whitelisted($client_ip)) {
            return false;
        }

        if (is_user_logged_in() && (current_user_can('manage_woocommerce') || current_user_can('manage_options'))) {
            return false;
        }

        $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';
        if (class_exists(BotReconDefense::class)) {
            if (BotReconDefense::is_genuine_search_engine($client_ip, $user_agent)) {
                return false;
            }
            if (BotReconDefense::is_genuine_uptime_monitor($client_ip, $user_agent, $settings)) {
                return false;
            }
        }

        $lock_key = 'webcareproscan_scrape_lock_' . md5($client_ip);
        if (get_transient($lock_key)) {
            return new \WP_Error(
                'webcareproscan_catalog_scrape_lockout',
                esc_html__('Catalog and pricing access temporarily restricted due to high-frequency scraping. Please try again later.', 'webcare-pro-security'),
                ['status' => 429]
            );
        }

        $max_requests = (int) ($settings['waf_woo_scraping_max_requests'] ?? 60);
        $lockout_mins = (int) ($settings['waf_woo_scraping_lockout_duration'] ?? 15);
        $velocity_key = 'webcareproscan_scrape_vel_' . md5($client_ip);
        $current_hits = (int) get_transient($velocity_key);
        $new_hits = $current_hits + 1;

        if ($new_hits > $max_requests) {
            set_transient($lock_key, [
                'ip'         => $client_ip,
                'hits'       => $new_hits,
                'locked_at'  => time(),
                'expires_at' => time() + ($lockout_mins * MINUTE_IN_SECONDS),
                'source'     => $source,
            ], $lockout_mins * MINUTE_IN_SECONDS);

            delete_transient($velocity_key);

            $rule_triggered = [
                'id'          => 'WAF-WOO-SCRAPING-THRESHOLD',
                'name'        => 'WooCommerce Catalog Scraping Threshold Exceeded (Rule #42)',
                'category'    => 'Behavioral Defense',
                'description' => sprintf(
                    /* translators: 1: Client IP, 2: Hit count, 3: Lockout duration in minutes */
                    __('IP %1$s exceeded catalog scraping threshold (%2$d requests in 1 min) - locked out for %3$d minutes.', 'webcare-pro-security'),
                    $client_ip,
                    $new_hits,
                    $lockout_mins
                ),
                'match_type'  => 'Scraping Threshold Exceeded',
                'match_value' => $client_ip,
                'payload'     => "IP: {$client_ip} Source: {$source} Hits: {$new_hits} / Limit: {$max_requests}",
            ];

            FirewallEngine::log_incident($rule_triggered, 'blocked');

            return new \WP_Error(
                'webcareproscan_catalog_scrape_lockout',
                esc_html__('Catalog and pricing access temporarily restricted due to high-frequency scraping. Please try again later.', 'webcare-pro-security'),
                ['status' => 429]
            );
        }

        set_transient($velocity_key, $new_hits, 60);
        return false;
    }

    /**
     * Smart 404 Vulnerability Scanner & Rate Limiter (Rule 6).
     *
     * @return void
     */
    public static function track_404_request(): void {
        if (!function_exists('is_404') || !is_404()) {
            return;
        }

        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_enabled']) || ($settings['waf_mode'] ?? 'enabled') === 'disabled') {
            return;
        }

        if (empty($settings['waf_block_404_scanners'])) {
            return;
        }

        $client_ip = ClientIpResolver::get_client_ip();

        // 1. Skip if client IP is whitelisted by administrator
        $whitelist_ctx = FirewallEngine::check_ip_whitelist_context($client_ip, $settings);
        if ($whitelist_ctx['is_whitelisted']) {
            $log_telemetry = isset($settings['waf_whitelist_log_telemetry']) ? !empty($settings['waf_whitelist_log_telemetry']) : true;
            if ($log_telemetry && FirewallEngine::is_high_risk_recon_probe(isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '/')) {
                FirewallEngine::log_incident([
                    'id'          => 'RATE-LIMIT-404-PROBE',
                    'name'        => '404 Vulnerability Probe (Bypassed)',
                    'category'    => '404 Scanner Rate Limit',
                    'description' => '404 probe detected on sensitive path [Bypassed via IP Whitelist]',
                    'payload'     => 'Probe: ' . substr(sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'] ?? '/')), 0, 200),
                ], 'bypassed');
            }
            return;
        }

        $raw_uri    = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '/';
        $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';

        // 2. Ignore missing static assets
        if (self::is_static_asset($raw_uri)) {
            return;
        }

        // 2b. Standard RFC 8615 well-known endpoints
        $parsed_path = wp_parse_url($raw_uri, PHP_URL_PATH) ?: $raw_uri;
        if (str_starts_with($parsed_path, '/.well-known/') && !FirewallEngine::is_high_risk_recon_probe($raw_uri)) {
            return;
        }

        // 3. Genuine Search Engine, Uptime Monitor, & Synthetic Performance Audit Exemption
        if (BotReconDefense::is_genuine_search_engine($client_ip, $user_agent)) {
            return;
        }
        if (BotReconDefense::is_genuine_uptime_monitor($client_ip, $user_agent, $settings)) {
            return;
        }
        if (BotReconDefense::is_synthetic_performance_tool($user_agent)) {
            return;
        }

        // 4. Redirection & Header Exemption
        if (self::is_redirect_in_progress()) {
            return;
        }

        // 5. E-Commerce Shopper & Verified Privilege Immunity (Subscribers do not bypass velocity controls)
        if (
            CommerceSessionGuard::is_exempt_from_operational_ban()
            || (!empty($settings['waf_ecommerce_safe_mode']) && (
                CommerceSessionGuard::has_active_shopper_session()
                || CommerceSessionGuard::is_commerce_or_membership_request($raw_uri)
            ))
        ) {
            return;
        }

        $threshold        = (int) ($settings['waf_404_threshold'] ?? 10);
        $window_seconds   = (int) ($settings['waf_404_window_seconds'] ?? 60);
        $lockout_duration = (int) ($settings['waf_404_lockout_duration'] ?? 30);

        $is_high_risk = FirewallEngine::is_high_risk_recon_probe($raw_uri);

        $counter_transient = 'webcareproscan_404_cnt_' . md5($client_ip);
        $current_count     = (int) get_transient($counter_transient);

        $increment = $is_high_risk ? 3 : 1;
        $new_count = $current_count + $increment;

        if (class_exists('\\WebCareProScanner\\Firewall\\CAF\\ThreatScoreTracker')) {
            $event_category = $is_high_risk ? 'honeypot' : 'probe_404';
            \WebCareProScanner\Firewall\CAF\ThreatScoreTracker::record_event($client_ip, $event_category);
        }

        if ($new_count >= $threshold) {
            $lockout_transient = 'webcareproscan_404_lock_' . md5($client_ip);
            set_transient($lockout_transient, [
                'ip'       => $client_ip,
                'count'    => $new_count,
                'window'   => $window_seconds,
                'duration' => $lockout_duration,
                'last_uri' => substr($raw_uri, 0, 200),
            ], $lockout_duration * MINUTE_IN_SECONDS);

            delete_transient($counter_transient);

            $rule_triggered = [
                'id'          => 'RATE-LIMIT-404-LOCKOUT',
                'name'        => '404 Scanner Rate Limit Enforced',
                'category'    => '404 Scanner Rate Limit',
                'description' => sprintf(
                    'IP triggered %d non-existent 404 endpoints within %d seconds. Enforced %d-minute automated lockout.',
                    $new_count,
                    $window_seconds,
                    $lockout_duration
                ),
                'match_type'  => '404 Flood Detection',
                'match_value' => $client_ip,
                'payload'     => 'Probe: ' . substr($raw_uri, 0, 200),
            ];

            $mode = $settings['waf_mode'] ?? 'enabled';
            if ($mode === 'learning') {
                FirewallEngine::log_incident($rule_triggered, 'detected');
            } else {
                $incident_id = 'WEBCARE-' . strtoupper(substr(md5($client_ip . microtime(true) . wp_rand()), 0, 8));
                FirewallEngine::log_incident($rule_triggered, 'throttled', $incident_id);
                if (!headers_sent()) {
                    status_header(429);
                    header('Retry-After: ' . max(60, $lockout_duration * 60));
                    header('Content-Type: text/plain; charset=utf-8');
                }
                echo 'Too Many Requests: Temporary 404 rate limit exceeded. Please wait before retrying.';
                exit;
            }
        } else {
            set_transient($counter_transient, $new_count, $window_seconds);
        }
    }

    /**
     * Check if requested URI path is a static media/asset file.
     *
     * @param string $uri
     * @return bool
     */
    public static function is_static_asset(string $uri): bool {
        $path = wp_parse_url($uri, PHP_URL_PATH);
        if (!$path) {
            return false;
        }

        $static_extensions = '/\.(jpg|jpeg|png|gif|webp|svg|ico|css|js|map|woff|woff2|ttf|eot|otf|mp4|webm|mp3|ogg|wav|pdf)$/i';
        if (preg_match($static_extensions, $path)) {
            return true;
        }

        if ($path === '/favicon.ico' || $path === '/robots.txt' || $path === '/sitemap.xml') {
            return true;
        }

        return false;
    }

    /**
     * Check if a redirection has been emitted or staged by WordPress or a redirection plugin.
     *
     * @return bool
     */
    public static function is_redirect_in_progress(): bool {
        $http_code = http_response_code();
        if ($http_code && in_array($http_code, [301, 302, 303, 307, 308], true)) {
            return true;
        }

        $headers = headers_list();
        foreach ($headers as $header) {
            if (stripos($header, 'Location:') === 0) {
                return true;
            }
        }

        return false;
    }
}
