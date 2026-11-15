<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall\Core;

/**
 * Commerce Session Guard & Webhook Verifier.
 *
 * Provides cryptographic verification of WooCommerce customer sessions, database revocation
 * checks, zero-false-positive exemption for shoppers/members, form submission detection,
 * and verified Stripe/PayPal webhook verification.
 *
 * @package WebCareProScanner\Firewall\Core
 */
class CommerceSessionGuard {

    /**
     * Request-scoped cache for verified WooCommerce session keys.
     *
     * @var array<string, bool>
     */
    private static array $wc_session_cache = [];

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
     * Invalidate the in-memory WooCommerce session verification cache.
     * Purges specific customer session or entire request cache upon logout or cleanup.
     *
     * @param string|null $customer_id Customer ID to purge, or null to purge all request-cached sessions.
     * @return void
     */
    public static function invalidate_woocommerce_session_cache(?string $customer_id = null): void {
        if ($customer_id !== null && $customer_id !== '') {
            unset(self::$wc_session_cache[$customer_id]);
        } else {
            self::$wc_session_cache = [];
        }
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
        if ($customer_id === '') {
            return false;
        }

        if (isset(self::$wc_session_cache[$customer_id])) {
            return self::$wc_session_cache[$customer_id];
        }

        global $wpdb;
        if (!isset($wpdb) || !is_object($wpdb) || empty($wpdb->prefix)) {
            return false;
        }

        $sess_table = $wpdb->prefix . 'woocommerce_sessions';
        if (!preg_match('/^[a-zA-Z0-9_]+$/', $sess_table)) {
            return false;
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Early WAF session authenticity verification
        $db_expiry = $wpdb->get_var(
            $wpdb->prepare(
                'SELECT session_expiry FROM %i WHERE session_key = %s LIMIT 1',
                $sess_table,
                $customer_id
            )
        );

        $is_valid = is_numeric($db_expiry) && (int) $db_expiry > time();
        self::$wc_session_cache[$customer_id] = $is_valid;

        return $is_valid;
    }

    /**
     * Check if current request has an authentic, cryptographically verified shopper or customer session.
     *
     * @return bool
     */
    public static function has_active_shopper_session(): bool {
        // CAF 2.0: Instant O(1) short-circuit if site runs zero commerce or membership plugins
        if (class_exists('\\WebCareProScanner\\Firewall\\CAF\\AdaptiveFirewallAdvisor')) {
            if (!\WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor::has_ecosystem('commerce') &&
                !\WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor::has_ecosystem('lms_membership')) {
                return false;
            }
        }

        // 1. If WooCommerce session handler is already initialized in runtime, cryptographically verify via official API + active session check
        if (function_exists('WC') && is_object(WC()) && isset(WC()->session) && is_object(WC()->session)) {
            if (method_exists(WC()->session, 'has_session') && method_exists(WC()->session, 'get_session_cookie') && WC()->session->has_session()) {
                $wc_cookie = WC()->session->get_session_cookie();
                if (is_array($wc_cookie) && count($wc_cookie) === 4 && !empty($wc_cookie[0])) {
                    [$c_id, $s_exp, $s_expiring, $c_hash] = $wc_cookie;
                    if (ctype_digit((string) $s_exp) && (int) $s_exp > time() && preg_match('/^[a-f0-9]{32,64}$/i', (string) $c_hash)) {
                        $to_hash     = $c_id . '|' . $s_exp;
                        $wp_hash_key = function_exists('wp_hash') ? wp_hash($to_hash) : '';
                        if ($wp_hash_key !== '') {
                            $expected_hmac = hash_hmac('md5', $to_hash, $wp_hash_key);
                            if (hash_equals($expected_hmac, (string) $c_hash)) {
                                if (self::is_unexpired_woocommerce_db_session((string) $c_id)) {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }

        // 2. Cryptographically validate `wp_woocommerce_session_*` against `wp_woocommerce_sessions` DB table and `wp_hash()`
        if (!empty($_COOKIE) && is_array($_COOKIE)) {
            foreach ($_COOKIE as $cookie_name => $cookie_val) {
                if (!is_string($cookie_name) || !is_string($cookie_val) || $cookie_val === '') {
                    continue;
                }

                if (str_starts_with($cookie_name, 'wp_woocommerce_session_')) {
                    $raw_val = wp_unslash($cookie_val);
                    $parts   = explode('||', $raw_val);
                    if (count($parts) !== 4) {
                        continue;
                    }

                    [$customer_id, $session_expiration, $session_expiring, $cookie_hash] = $parts;
                    if (
                        $customer_id === ''
                        || !ctype_digit((string) $session_expiration)
                        || !ctype_digit((string) $session_expiring)
                        || (int) $session_expiration <= time()
                        || !preg_match('/^[a-f0-9]{32,64}$/i', $cookie_hash)
                    ) {
                        continue;
                    }

                    // Verify HMAC signature
                    $to_hash = $customer_id . '|' . $session_expiration;
                    if (function_exists('wp_hash')) {
                        $wp_hash_key = wp_hash($to_hash);
                    } elseif (
                        defined('AUTH_KEY') && defined('AUTH_SALT')
                        && is_string(AUTH_KEY) && is_string(AUTH_SALT)
                        && AUTH_KEY !== '' && AUTH_SALT !== ''
                        && (!function_exists('has_filter') || !has_filter('salt'))
                    ) {
                        $wp_hash_key = hash_hmac('md5', $to_hash, AUTH_KEY . AUTH_SALT);
                    } else {
                        continue;
                    }

                    $expected_hmac = hash_hmac('md5', $to_hash, $wp_hash_key);
                    if (!hash_equals($expected_hmac, $cookie_hash)) {
                        continue;
                    }

                    if (self::is_unexpired_woocommerce_db_session((string) $customer_id)) {
                        return true;
                    }
                }
            }
        }

        // 3. Verified Authenticated Customer or Membership Session
        $user_id = 0;
        if (function_exists('is_user_logged_in') && is_user_logged_in()) {
            $user_id = (int) get_current_user_id();
        } elseif (function_exists('wp_validate_auth_cookie')) {
            $user_id = (int) wp_validate_auth_cookie('', 'logged_in');
        }

        if ($user_id > 0) {
            $user = function_exists('get_userdata') ? get_userdata($user_id) : null;
            if ($user instanceof \WP_User) {
                // Check if user possesses customer or membership roles/capabilities
                $roles = (array) $user->roles;
                $is_customer_or_member = in_array('customer', $roles, true)
                    || in_array('member', $roles, true)
                    || !empty(get_user_meta($user_id, 'paying_customer', true))
                    || !empty(get_user_meta($user_id, '_woocommerce_load_saved_cart_after_login', true))
                    || (function_exists('user_can') && user_can($user, 'customer'));

                if ($is_customer_or_member) {
                    return true;
                }

                // Check active WooCommerce cart presence if WooCommerce is initialized
                if (function_exists('WC') && isset(WC()->cart) && is_object(WC()->cart) && !WC()->cart->is_empty()) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Determine if the current session qualifies for operational-ban exemption.
     * Narrowly scoped to verified shoppers/members or authenticated administrators.
     * Generic subscriber or low-privilege accounts do NOT bypass operational bans.
     *
     * @return bool
     */
    public static function is_exempt_from_operational_ban(): bool {
        // 1. Verified WooCommerce / Membership customer or active shopper cart session
        if (self::has_active_shopper_session()) {
            return true;
        }

        // 2. Narrowly-scoped administrator exemption
        if (function_exists('current_user_can') && current_user_can('manage_options')) {
            return true;
        }

        // Early-boot auth cookie validation for administrators prior to current_user_can setup
        if (function_exists('wp_validate_auth_cookie') && function_exists('get_userdata')) {
            $admin_uid = (int) wp_validate_auth_cookie('', 'logged_in');
            if ($admin_uid > 0) {
                $admin_user = get_userdata($admin_uid);
                if ($admin_user instanceof \WP_User && $admin_user->has_cap('manage_options')) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Detect if the incoming URI or request belongs to legitimate E-Commerce, Cart,
     * Checkout, Customer Account, or Payment Gateway Webhook channels.
     *
     * @param string $uri
     * @return bool
     */
    public static function is_commerce_or_membership_request(string $uri): bool {
        // CAF 2.0: Instant O(1) short-circuit if site runs zero commerce or membership plugins
        if (class_exists('\\WebCareProScanner\\Firewall\\CAF\\AdaptiveFirewallAdvisor')) {
            if (!\WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor::has_ecosystem('commerce') &&
                !\WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor::has_ecosystem('lms_membership')) {
                return false;
            }
        }

        $parsed_path  = strtolower(wp_parse_url($uri, PHP_URL_PATH) ?: $uri);
        $query_string = isset($_SERVER['QUERY_STRING']) ? strtolower(sanitize_text_field(wp_unslash($_SERVER['QUERY_STRING']))) : '';

        // 1. Direct E-Commerce AJAX & API parameters
        if (str_contains($uri, 'wc-ajax=') || str_contains($query_string, 'wc-ajax=')) {
            return true;
        }
        if (str_contains($uri, 'wc-api=') || str_contains($query_string, 'wc-api=')) {
            return true;
        }
        if (str_contains($uri, 'surecart_action=') || str_contains($query_string, 'surecart_action=')) {
            return true;
        }
        if (str_contains($uri, 'give-api=') || str_contains($query_string, 'give-api=')) {
            return true;
        }

        // 2. REST API Store, Cart, Profile & Webhook Endpoints
        $commerce_rest_prefixes = [
            '/wp-json/wc/store/',
            '/wp-json/wc/v3/',
            '/wp-json/wc/v2/',
            '/wp-json/stripe/',
            '/wp-json/wc-stripe/',
            '/wp-json/paypal/',
            '/wp-json/mollie/',
            '/wp-json/square/',
            '/wp-json/edd/',
            '/wp-json/surecart/',
            '/wp-json/give-api/',
            '/wp-json/fluentcart/',
            '/wp-json/bigcommerce/',
            '/wp-json/mp/v1/',       // MemberPress
            '/wp-json/pmpro/v1/',    // Paid Memberships Pro
            '/wp-json/rcp/v1/',      // Restrict Content Pro
            '/wp-json/suremembers/', // SureMembers
            '/wp-json/armember/',    // ARMember
            '/wp-json/wpum/',        // WP User Manager
            '/wp-json/profilepress/',
            '/wp-json/user-registration/',
            '/wp-json/buddyboss/',
            '/wp-json/youzify/',
        ];
        foreach ($commerce_rest_prefixes as $prefix) {
            if (str_contains($parsed_path, $prefix)) {
                return true;
            }
        }

        // 3. Typical Store, Cart, Checkout, Profile, and Member Portal URI slugs
        $store_slug_patterns = [
            '/\/shop(\/|$)/i',
            '/\/product(\/|$)/i',
            '/\/cart(\/|$)/i',
            '/\/checkout(\/|$)/i',
            '/\/my-account(\/|$)/i',
            '/\/order-received(\/|$)/i',
            '/\/member-account(\/|$)/i',
            '/\/membership-account(\/|$)/i',
            '/\/membership-checkout(\/|$)/i',
            '/\/register-membership(\/|$)/i',
            '/\/user-profile(\/|$)/i',
            '/\/my-profile(\/|$)/i',
            '/\/client-portal(\/|$)/i',
            '/\/donations(\/|$)/i',
            '/\/donate(\/|$)/i',
            '/\/give(\/|$)/i',
        ];
        foreach ($store_slug_patterns as $spat) {
            if (preg_match($spat, $parsed_path)) {
                return true;
            }
        }

        // 4. Payment Gateway Webhook Identifiers in Query String
        $gateway_webhook_signals = [
            'wc_stripe_webhook',
            'wc_square_webhook',
            'mollie_webhook',
            'paypal_ipn',
            'ipn_listener',
            'payment_listener',
            'razorpay_webhook',
            'paystack_webhook',
            'klarna_notification',
            'edd-listener',
            'authorizenet_silent_post',
            'wc_gateway_authorizenet',
            'surecart_webhook',
            'give_webhook',
            'fluentcart_webhook',
            'simple_pay_webhook',
        ];
        foreach ($gateway_webhook_signals as $signal) {
            if (str_contains($query_string, $signal) || str_contains($uri, $signal)) {
                return true;
            }
        }

        // 5. Cryptographic Payment Gateway Webhook Signatures
        $client_ip = ClientIpResolver::get_client_ip();
        $is_verified_stripe_ip = in_array($client_ip, self::STRIPE_WEBHOOK_IPS, true) || in_array($client_ip, ['54.241.31.102', '54.241.34.107'], true);
        $is_verified_paypal_ip = false;
        foreach (array_merge(self::PAYPAL_WEBHOOK_CIDRS, ['185.177.189.0/24', '3.253.0.0/16', '52.212.0.0/15']) as $paypal_cidr) {
            if (ClientIpResolver::ip_in_range($client_ip, $paypal_cidr)) {
                $is_verified_paypal_ip = true;
                break;
            }
        }

        if ($is_verified_stripe_ip || $is_verified_paypal_ip) {
            return true;
        }

        $is_webhook_endpoint = (
            str_contains($parsed_path, '/wp-json/mollie')
            || str_contains($parsed_path, '/wp-json/square')
            || str_contains($parsed_path, '/wp-json/surecart')
            || str_contains($uri, 'wc-api=')
            || str_contains($query_string, 'wc-api=')
        );

        if ($is_webhook_endpoint && (
            !empty($_SERVER['HTTP_X_SQUARE_HMACSHA256_SIGNATURE'])
            || !empty($_SERVER['HTTP_X_WC_WEBHOOK_SIGNATURE'])
            || !empty($_SERVER['HTTP_X_RAZORPAY_SIGNATURE'])
            || !empty($_SERVER['HTTP_X_SHOPIFY_HMAC_SHA256'])
            || !empty($_SERVER['HTTP_X_MOLLIE_SIGNATURE'])
            || !empty($_SERVER['HTTP_X_SURECART_SIGNATURE'])
        )) {
            return true;
        }

        return false;
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
        $parsed_path  = strtolower(wp_parse_url($uri, PHP_URL_PATH) ?: $uri);
        $query_string = isset($_SERVER['QUERY_STRING']) ? strtolower(sanitize_text_field(wp_unslash($_SERVER['QUERY_STRING']))) : '';
        $req_method   = strtoupper(isset($_SERVER['REQUEST_METHOD']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_METHOD'])) : 'GET');

        $is_submit_method = in_array($req_method, ['POST', 'PUT', 'PATCH'], true);

        // 1. Contact Form 7 (CF7) REST API & Feedback Routes
        if (str_contains($parsed_path, '/contact-form-7/v1/contact-forms/') || str_contains($uri, 'contact-form-7/v1')) {
            return true;
        }
        if (str_contains($query_string, 'contact-form-7') || str_contains($query_string, '_wpcf7')) {
            return true;
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended
        if (!empty($_POST['_wpcf7']) || !empty($_POST['_wpcf7_version']) || !empty($_POST['_wpcf7_unit_tag'])) {
            return true;
        }

        // 2. WPForms AJAX & REST Submissions
        // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended
        $action = isset($_POST['action']) ? sanitize_text_field(wp_unslash($_POST['action'])) : (isset($_GET['action']) ? sanitize_text_field(wp_unslash($_GET['action'])) : '');
        if ($action === 'wpforms_submit' || $action === 'wpforms_form_submit' || $action === 'wpforms_file_upload') {
            return true;
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended
        if (!empty($_POST['wpforms']) && is_array($_POST['wpforms'])) {
            return true;
        }
        if (str_contains($parsed_path, '/wp-json/wpforms/')) {
            return true;
        }

        // 3. Fluent Forms AJAX & REST Submissions
        if ($action === 'fluentform_submit' || $action === 'fluentform_file_upload' || $action === 'fluentform_form_submit') {
            return true;
        }
        if (str_contains($parsed_path, '/wp-json/fluentform/v1/')) {
            return true;
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended
        if (!empty($_POST['fluent_forms_nonce']) || !empty($_POST['__fluent_form_embded_post_id'])) {
            return true;
        }

        // 4. Gravity Forms AJAX & Standard Submissions
        // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended
        if (!empty($_POST['gform_submit']) || !empty($_POST['gform_ajax']) || (isset($_POST['is_submit_']) && is_numeric($_POST['is_submit_']))) {
            return true;
        }
        if (str_contains($parsed_path, '/wp-json/gf/v2/')) {
            return true;
        }

        // 5. Ninja Forms AJAX Submissions
        if ($action === 'nf_ajax_submit' || $action === 'ninja_forms_ajax_submit' || $action === 'nf_async_upload') {
            return true;
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended
        if (!empty($_POST['nf_form_id']) || !empty($_POST['ninja_forms_form_id'])) {
            return true;
        }

        // 6. Formidable Forms Submissions
        if ($action === 'frm_entries_create' || $action === 'frm_entries_update' || $action === 'frm_forms_preview') {
            return true;
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended
        if (!empty($_POST['frm_action']) || !empty($_POST['form_id']) && isset($_POST['frm_hide_fields_'])) {
            return true;
        }

        // 7. WS Form, HappyForms, Kali Forms & Everest Forms
        if ($action === 'wsf_submit' || $action === 'happyforms_message' || $action === 'everest_forms_ajax_submit') {
            return true;
        }
        if (str_contains($parsed_path, '/wp-json/ws-form/') || str_contains($parsed_path, '/wp-json/everest-forms/')) {
            return true;
        }

        // 8. General Generic Form POST detection with verified nonces/honeytokens
        if ($is_submit_method) {
            // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended
            if (!empty($_POST['_wp_http_referer']) && (!empty($_POST['form_id']) || !empty($_POST['form_token']) || !empty($_POST['_wpnonce']))) {
                if (str_contains($parsed_path, '/wp-admin/admin-post.php')) {
                    return true;
                }
            }
        }

        return false;
    }
}
