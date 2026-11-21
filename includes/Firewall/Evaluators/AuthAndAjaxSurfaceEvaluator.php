<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall\Evaluators;

use WebCareProScanner\Contracts\EvaluatorFailurePolicy;
use WebCareProScanner\Contracts\RequestContext;
use WebCareProScanner\Contracts\RouteClass;
use WebCareProScanner\Contracts\WafAction;
use WebCareProScanner\Contracts\WafEvaluatorInterface;
use WebCareProScanner\Contracts\WafVerdict;
use WebCareProScanner\Firewall\Core\CommerceSessionGuard;
use WebCareProScanner\Firewall\Core\TransientRateLimiter;
use WebCareProScanner\Firewall\FirewallEngine;
use WebCareProScanner\System\SettingsManager;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * AuthAndAjaxSurfaceEvaluator
 *
 * Route-scoped evaluator for WordPress authentication endpoints, XML-RPC,
 * admin-ajax.php burst traffic, guest action policies, and database/file-manager plugin guards.
 *
 * Scoped strictly to:
 * - RouteClass::AuthLogin
 * - RouteClass::AdminAjax
 * - RouteClass::AdminUi
 * (Must NOT run on RouteClass::PublicGet or RouteClass::PublicMutation frontend traffic).
 *
 * Author: Mir Alamin (WebCare Pro)
 * Senior Linux SysAdmin & WordPress Security Engineer
 */
final readonly class AuthAndAjaxSurfaceEvaluator implements WafEvaluatorInterface {

    public function get_module_id(): string {
        return 'auth-and-ajax-surface-evaluator';
    }

    public function is_required(): bool {
        return false;
    }

    /**
     * @return array<RouteClass>
     */
    public function get_route_classes(): array {
        return [
            RouteClass::AuthLogin,
            RouteClass::AdminAjax,
            RouteClass::AdminUi,
        ];
    }

    /**
     * @return array<string>
     */
    public function get_required_capabilities(): array {
        return [];
    }

    public function get_failure_policy(): EvaluatorFailurePolicy {
        return EvaluatorFailurePolicy::DegradedLog;
    }

    public function compile_preload_ast(): array {
        return [
            'id'        => 'WAF-AUTH-AND-AJAX-SURFACE',
            'category'  => 'Authentication & AJAX Surface Defense',
            'evaluator' => self::class,
        ];
    }

    /**
     * Safely resolve translatable string respecting early-boot conditions.
     */
    private static function translatable_string(string $string): string {
        if (function_exists('did_action') && did_action('init')) {
            return __($string, 'webcare-pro-security');
        }
        return $string;
    }

    /**
     * Evaluate incoming request at plugins_loaded runtime.
     *
     * @param RequestContext $ctx
     * @return WafVerdict|null
     */
    public function evaluate_runtime_request(RequestContext $ctx): ?WafVerdict {
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_enabled']) || ($settings['waf_mode'] ?? 'enabled') === 'disabled') {
            return null;
        }

        $client_ip = $ctx->ip;
        $request_uri = $ctx->uri;
        $clean_path = strtolower($ctx->cleanUri !== '' ? $ctx->cleanUri : (wp_parse_url($request_uri, PHP_URL_PATH) ?: $request_uri));

        // Skip operational heuristics for authenticated administrators and builders
        $is_admin = (function_exists('current_user_can') && current_user_can('manage_options'))
            || FirewallEngine::is_authenticated_administrator();
        $is_builder = FirewallEngine::is_authenticated_editor_or_builder();

        // 1. admin-ajax.php Unauthenticated Burst Rate-Limiter & Guest Action Matrix
        $verdict_ajax = self::evaluate_admin_ajax($ctx, $settings, $clean_path, $is_admin, $is_builder);
        if ($verdict_ajax !== null) {
            return $verdict_ajax;
        }

        // 2. XML-RPC Disabled Guard
        $verdict_xmlrpc = self::evaluate_xmlrpc($ctx, $settings, $clean_path);
        if ($verdict_xmlrpc !== null) {
            return $verdict_xmlrpc;
        }

        // 3. Authentication & Password-Reset Array Type-Confusion Trap (Smart Rule #49)
        if (!$is_admin && !$is_builder) {
            $verdict_confusion = self::evaluate_auth_type_confusion($ctx, $request_uri);
            if ($verdict_confusion !== null) {
                return $verdict_confusion;
            }
        }

        // 4. phpMyAdmin & File Manager Plugin Installation Guards
        $verdict_plugins = self::evaluate_prohibited_plugins($ctx, $settings, $request_uri);
        if ($verdict_plugins !== null) {
            return $verdict_plugins;
        }

        return null;
    }

    /**
     * Block 1: admin-ajax.php Burst Rate-Limiter & Guest Action Policy.
     */
    private static function evaluate_admin_ajax(
        RequestContext $ctx,
        array $settings,
        string $clean_path,
        bool $is_admin,
        bool $is_builder
    ): ?WafVerdict {
        if ($is_admin || $is_builder) {
            return null;
        }

        $is_ajax = str_contains($clean_path, 'admin-ajax.php');
        $is_post = str_contains($clean_path, 'admin-post.php');

        if (!$is_ajax && !$is_post) {
            return null;
        }

        $client_ip = $ctx->ip;
        $request_uri = $ctx->uri;
        $is_logged_in = (function_exists('is_user_logged_in') && is_user_logged_in());

        // Extract action strictly from queryParams or formParams
        $ajax_action_raw = $ctx->queryParams['action'] ?? ($ctx->formParams['action'] ?? ($ctx->params['action'] ?? ''));
        $ajax_action = is_string($ajax_action_raw) ? sanitize_text_field(wp_unslash($ajax_action_raw)) : '';

        // Burst rate limiter for unauthenticated admin-ajax.php hits
        if ($is_ajax && !$is_logged_in && !empty($settings['waf_limit_admin_ajax'])) {
            $is_woo_public = !empty($settings['waf_ecommerce_safe_mode']) && in_array($ajax_action, [
                'woocommerce_get_refreshed_fragments',
                'woocommerce_apply_coupon',
                'woocommerce_remove_coupon',
                'woocommerce_update_shipping_method',
                'woocommerce_update_order_review',
                'woocommerce_checkout',
                'woocommerce_add_to_cart',
            ], true);

            $is_form_submission = !empty($settings['waf_forms_safe_mode']) && (
                CommerceSessionGuard::is_form_submission_request($request_uri) ||
                in_array($ajax_action, [
                    'wpforms_submit',
                    'wpforms_form_submit',
                    'wpforms_file_upload',
                    'fluentform_submit',
                    'fluentform_file_upload',
                    'fluentform_form_submit',
                    'nf_ajax_submit',
                    'ninja_forms_ajax_submit',
                    'frm_entries_create',
                    'frm_entries_update',
                    'wsf_submit',
                    'happyforms_message',
                    'everest_forms_ajax_submit',
                ], true)
            );

            if (!$is_woo_public && !$is_form_submission) {
                $limit_per_min = (int) ($settings['waf_admin_ajax_limit_per_min'] ?? 60);
                $rate_check = TransientRateLimiter::check_rate_limit('ajax:' . md5($client_ip), $limit_per_min, 60);
                if (!$rate_check['allowed']) {
                    return new WafVerdict(
                        WafAction::RateLimit,
                        'WAF-ADMIN-AJAX-BURST',
                        sprintf(
                            self::translatable_string('Unauthenticated client exceeded rate threshold (%d requests/min) on admin-ajax.php.'),
                            $limit_per_min
                        ),
                        [
                            'category'    => 'DoS & Resource Shield',
                            'status_code' => 429,
                            'match_type'  => 'AJAX Rate Limiting',
                            'match_value' => $ajax_action ?: 'unknown',
                            'payload'     => "Action: {$ajax_action} IP: {$client_ip}",
                            'retry_after' => (int) ($rate_check['retry_after'] ?? 60),
                        ]
                    );
                }
            }
        }

        // Guest admin-ajax.php & admin-post.php Action Matrix Guard
        if (!$is_logged_in) {
            $policy = $settings['waf_guest_ajax_policy'] ?? 'monitor';
            if ($policy !== 'off') {
                $matrix_verdict = self::evaluate_guest_action_matrix($ctx, $settings, $ajax_action, $is_ajax, $policy);
                if ($matrix_verdict !== null) {
                    return $matrix_verdict;
                }
            }
        }

        return null;
    }

    /**
     * Evaluate guest action matrix rules (Rule #36).
     */
    private static function evaluate_guest_action_matrix(
        RequestContext $ctx,
        array $settings,
        string $action,
        bool $is_ajax,
        string $policy
    ): ?WafVerdict {
        $endpoint_name = $is_ajax ? 'admin-ajax.php' : 'admin-post.php';
        $client_ip = $ctx->ip;

        if (FirewallEngine::is_server_origin_or_loopback($client_ip)) {
            return null;
        }

        // 1. Missing or Empty Action Handling
        if ($action === '') {
            $rule = [
                'id'          => 'WAF-GUEST-AJAX-EMPTY',
                'name'        => 'Guest Endpoint Missing Action Probe (Rule #36)',
                'category'    => 'Protocol Defense',
                'description' => sprintf(
                    self::translatable_string('Unauthenticated hit to %s without an action parameter.'),
                    $endpoint_name
                ),
                'match_type'  => 'Missing Action Probe',
                'match_value' => $endpoint_name,
                'payload'     => "Endpoint: {$endpoint_name} IP: {$client_ip}",
            ];

            if ($policy === 'block') {
                return new WafVerdict(
                    WafAction::Block,
                    'WAF-GUEST-AJAX-EMPTY',
                    $rule['description'],
                    [
                        'category'    => 'Protocol Defense',
                        'status_code' => 400,
                        'rule'        => $rule,
                    ]
                );
            }

            FirewallEngine::log_incident($rule, 'monitored');
            return null;
        }

        // 2. Tier 1 Built-in Allowed Actions Hash Map (O(1) lookup)
        static $tier1_actions = null;
        if ($tier1_actions === null) {
            $tier1_actions = array_fill_keys([
                'heartbeat',
                'woocommerce_get_refreshed_fragments',
                'woocommerce_add_to_cart',
                'woocommerce_apply_coupon',
                'woocommerce_remove_coupon',
                'woocommerce_update_shipping_method',
                'woocommerce_update_order_review',
                'woocommerce_checkout',
                'woocommerce_get_customer_location',
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
                'load_more_posts',
                'infinite_scroll',
                'search_autocomplete',
                'ajax_search',
                'wp_ajax_nopriv_search',
                'eascompliance_status_ajax',
                'eas_compliance_ajax',
                'eas_tax_calculation',
                'woocommerce_calc_line_taxes',
                'wordfence_doScan',
                'wordfence_testAjax',
                'wp_gf_personal_data',
                'gf_ajax_upload',
                'nf_fu_get_new_nonce',
                'ppc-sdk-v6-client-token',
                'ppc_create_order',
                'ppc_approve_order',
                'wc_stripe_create_order',
                'wc_stripe_get_cart_details',
            ], true);
        }

        if (isset($tier1_actions[$action])) {
            return null;
        }

        // Affiliate Ecosystem Public Guest AJAX Handlers
        if (class_exists('\\WebCareProScanner\\Firewall\\Core\\AffiliateSecurityEngine')
            && !empty(\WebCareProScanner\Firewall\Core\AffiliateSecurityEngine::get_detected_ecosystem()['is_active'])
            && \WebCareProScanner\Firewall\Core\AffiliateSecurityEngine::is_public_affiliate_ajax_action($action)
        ) {
            return null;
        }

        // Smart E-Commerce & Checkout Context Heuristic
        $action_lower = strtolower($action);
        if (str_starts_with($action_lower, 'eascompliance_') || str_starts_with($action_lower, 'eas_')) {
            return null;
        }

        $referer_raw = $ctx->referer !== '' ? strtolower(esc_url_raw($ctx->referer)) : '';
        $referer_host = $referer_raw !== '' ? strtolower((string) wp_parse_url($referer_raw, PHP_URL_HOST)) : '';
        $home_host = function_exists('home_url') ? strtolower((string) wp_parse_url(home_url(), PHP_URL_HOST)) : '';
        $same_origin_cart = $referer_raw !== ''
            && $referer_host !== ''
            && $home_host !== ''
            && $referer_host === $home_host
            && (str_contains($referer_raw, '/checkout') || str_contains($referer_raw, '/cart'));

        if (CommerceSessionGuard::has_active_shopper_session() || $same_origin_cart) {
            if (str_starts_with($action_lower, 'wc_') || str_starts_with($action_lower, 'woocommerce_') || str_contains($action_lower, 'tax') || str_contains($action_lower, 'vat') || str_contains($action_lower, 'shipping')) {
                return null;
            }

            $has_valid_nonce = !empty($ctx->queryParams['_wpnonce']) || !empty($ctx->formParams['_wpnonce']) || !empty($ctx->headers['x-wp-nonce']);
            if ($same_origin_cart || $has_valid_nonce) {
                if ($policy === 'block') {
                    $policy = 'monitor';
                }
            }
        }

        // Custom Administrator Allowlist Lookup (Case-Insensitive)
        $custom_allowlist_raw = $settings['waf_guest_ajax_custom_allowlist'] ?? '';
        if (!empty($custom_allowlist_raw)) {
            $custom_actions = array_map('strtolower', array_filter(array_map('trim', explode("\n", (string) $custom_allowlist_raw))));
            if (in_array(strtolower($action), $custom_actions, true)) {
                return null;
            }
        }

        // Unknown Guest Action
        $rule_triggered = [
            'id'          => 'WAF-GUEST-AJAX-PROBE',
            'name'        => 'Unregistered Guest Action Probe (Rule #36)',
            'category'    => 'Behavioral Defense',
            'description' => sprintf(
                self::translatable_string('Unregistered action "%s" invoked by guest on %s.'),
                esc_html($action),
                $endpoint_name
            ),
            'match_type'  => 'Guest Action Policy',
            'match_value' => $action,
            'payload'     => "Action: {$action} Endpoint: {$endpoint_name} IP: {$client_ip}",
        ];

        if ($policy === 'block') {
            return new WafVerdict(
                WafAction::Block,
                'WAF-GUEST-AJAX-PROBE',
                $rule_triggered['description'],
                [
                    'category'    => 'Behavioral Defense',
                    'status_code' => 403,
                    'rule'        => $rule_triggered,
                ]
            );
        }

        FirewallEngine::log_incident($rule_triggered, 'monitored');
        return null;
    }

    /**
     * Block 2: XML-RPC Disabled Guard.
     */
    private static function evaluate_xmlrpc(RequestContext $ctx, array $settings, string $clean_path): ?WafVerdict {
        if (empty($settings['waf_disable_xmlrpc'])) {
            return null;
        }

        $script_name = (string) ($ctx->server['SCRIPT_NAME'] ?? '');
        $is_xmlrpc = str_contains($clean_path, 'xmlrpc.php')
            || str_contains($ctx->uri, 'xmlrpc.php')
            || str_contains($script_name, 'xmlrpc.php');

        if (!$is_xmlrpc) {
            return null;
        }

        // Smart Pass: Exclude verified Automattic Jetpack sync requests
        if (FirewallEngine::is_verified_jetpack_request($ctx->ip, $ctx->uri, $settings)) {
            return null;
        }

        $rule = [
            'id'          => 'WAF-XMLRPC-DISABLED',
            'name'        => 'XML-RPC Access Prohibited',
            'category'    => 'XML-RPC Disabled',
            'description' => self::translatable_string('XML-RPC request blocked by administrator security policy.'),
            'match_type'  => 'Endpoint Block',
            'match_value' => 'xmlrpc.php',
            'payload'     => 'xmlrpc.php invocation',
        ];

        $mode = $settings['waf_mode'] ?? 'enabled';
        if ($mode === 'learning') {
            FirewallEngine::log_incident($rule, 'detected');
            return null;
        }

        return new WafVerdict(
            WafAction::Block,
            'WAF-XMLRPC-DISABLED',
            self::translatable_string('XML-RPC services are disabled on this WordPress installation by WebCare Pro Security.'),
            [
                'category'    => 'XML-RPC Disabled',
                'status_code' => 403,
                'rule'        => $rule,
            ]
        );
    }

    /**
     * Block 3: Authentication & Password-Reset Array Type-Confusion Trap (Rule #49).
     */
    private static function evaluate_auth_type_confusion(RequestContext $ctx, string $request_uri): ?WafVerdict {
        $is_auth_endpoint = (
            str_contains($request_uri, 'wp-login.php')
            || str_contains($request_uri, '/my-account')
            || str_contains($request_uri, 'wc-ajax')
            || str_contains($request_uri, 'lost-password')
            || str_contains($request_uri, 'action=rp')
            || str_contains($request_uri, 'action=resetpass')
        );

        $sensitive_auth_keys = $is_auth_endpoint
            ? ['log', 'pwd', 'user_login', 'user_email', 'rp_key', 'key', 'pass1', 'pass2', 'username', 'password']
            : ['log', 'pwd', 'user_login', 'rp_key', 'pass1', 'pass2'];

        $has_auth_type_confusion = false;
        $confusion_key = '';

        foreach ($sensitive_auth_keys as $s_key) {
            if ((isset($ctx->queryParams[$s_key]) && is_array($ctx->queryParams[$s_key]))
                || (isset($ctx->formParams[$s_key]) && is_array($ctx->formParams[$s_key]))
                || (isset($_GET[$s_key]) && is_array($_GET[$s_key]))
                || (isset($_POST[$s_key]) && is_array($_POST[$s_key]))
            ) {
                $has_auth_type_confusion = true;
                $confusion_key = $s_key;
                break;
            }
        }

        if ($has_auth_type_confusion) {
            $desc_fmt = self::translatable_string('Non-scalar array submitted for authentication credential (%s) to induce type-confusion or error state.');
            $rule = [
                'id'          => 'WAF-AUTH-TYPE-CONFUSION',
                'name'        => 'Authentication Array Type-Confusion Trap (Rule #49)',
                'category'    => 'Brute Force & Auth Armor',
                'detector'    => 'AuthAndAjaxSurfaceEvaluator',
                'sig_id'      => 'sig:proto:auth_header_type_confusion',
                'description' => sprintf($desc_fmt, esc_html($confusion_key)),
                'match_type'  => 'Type Confusion Exploit',
                'match_value' => $confusion_key . '[]',
                'payload'     => "Parameter: {$confusion_key}[] URI: {$request_uri} IP: {$ctx->ip}",
            ];

            return new WafVerdict(
                WafAction::Block,
                'WAF-AUTH-TYPE-CONFUSION',
                $rule['description'],
                [
                    'category'    => 'Brute Force & Auth Armor',
                    'status_code' => 403,
                    'rule'        => $rule,
                ]
            );
        }

        return null;
    }

    /**
     * Block 4: phpMyAdmin & File Manager Plugin Installation Guards.
     */
    private static function evaluate_prohibited_plugins(RequestContext $ctx, array $settings, string $request_uri): ?WafVerdict {
        $pma_active = !empty($settings['waf_disallow_phpmyadmin_plugins']);
        $fm_active  = !empty($settings['waf_disallow_filemanager_plugins']);

        if (!$pma_active && !$fm_active) {
            return null;
        }

        // Extract slug candidate strictly
        $slug_val = $ctx->formParams['slug'] ?? ($ctx->queryParams['slug'] ?? ($ctx->formParams['plugin'] ?? ($ctx->queryParams['plugin'] ?? '')));
        if (!is_string($slug_val) || $slug_val === '') {
            $post_data = $ctx->formParams['data'] ?? null;
            if (is_array($post_data) && !empty($post_data['slug']) && is_string($post_data['slug'])) {
                $slug_val = $post_data['slug'];
            }
        }
        if ((!is_string($slug_val) || $slug_val === '') && preg_match('/(?:[?&]|%26)(?:slug|plugin)=([a-z0-9_-]+)/i', $request_uri, $sm)) {
            $slug_val = $sm[1];
        }

        $req_slug = is_string($slug_val) ? strtolower(sanitize_text_field(wp_unslash($slug_val))) : '';
        if ($req_slug === '') {
            return null;
        }

        // phpMyAdmin check
        if ($pma_active) {
            static $pma_signatures = [
                'phpmyadmin', 'database-browser', 'sql-buddy', 'sqlbuddy', 'adminer',
                'wp-phpmyadmin', 'wp-database-manager', 'database-management',
                'dbmanager', 'db-manager', 'database-manager', 'mysql-manager',
                'ari-adminer', 'portable-phpmyadmin',
            ];
            foreach ($pma_signatures as $sig) {
                if (str_contains($req_slug, $sig)) {
                    $rule = [
                        'id'          => 'WAF-DISALLOW-PHPMYADMIN-PLUGIN',
                        'name'        => 'Prohibited Database Manager Plugin Installation',
                        'category'    => 'Security Policy Enforcement',
                        'description' => sprintf(
                            self::translatable_string('Attempted installation of database manager / phpMyAdmin plugin ("%s") was blocked.'),
                            esc_html($req_slug)
                        ),
                        'match_type'  => 'Plugin Installation Policy',
                        'match_value' => $req_slug,
                        'payload'     => "Slug: {$req_slug} IP: {$ctx->ip}",
                    ];

                    $mode = $settings['waf_mode'] ?? 'enabled';
                    if ($mode === 'learning') {
                        FirewallEngine::log_incident($rule, 'detected');
                        return null;
                    }

                    return new WafVerdict(
                        WafAction::Block,
                        'WAF-DISALLOW-PHPMYADMIN-PLUGIN',
                        $rule['description'],
                        [
                            'category'    => 'Security Policy Enforcement',
                            'status_code' => 403,
                            'rule'        => $rule,
                        ]
                    );
                }
            }
        }

        // File Manager check
        if ($fm_active) {
            static $fm_signatures = [
                'file-manager', 'filemanager', 'fileorganizer', 'filester',
                'advanced-file-manager', 'elfinder', 'tinyfilemanager', 'wp-file-manager',
                'wp-filemanager', 'file-explorer', 'file-commander', 'file-browser',
            ];
            foreach ($fm_signatures as $sig) {
                if (str_contains($req_slug, $sig)) {
                    $rule = [
                        'id'          => 'WAF-DISALLOW-FILEMANAGER-PLUGIN',
                        'name'        => 'Prohibited File Manager Plugin Installation',
                        'category'    => 'Security Policy Enforcement',
                        'description' => sprintf(
                            self::translatable_string('Attempted installation of file manager plugin ("%s") was blocked.'),
                            esc_html($req_slug)
                        ),
                        'match_type'  => 'Plugin Installation Policy',
                        'match_value' => $req_slug,
                        'payload'     => "Slug: {$req_slug} IP: {$ctx->ip}",
                    ];

                    $mode = $settings['waf_mode'] ?? 'enabled';
                    if ($mode === 'learning') {
                        FirewallEngine::log_incident($rule, 'detected');
                        return null;
                    }

                    return new WafVerdict(
                        WafAction::Block,
                        'WAF-DISALLOW-FILEMANAGER-PLUGIN',
                        $rule['description'],
                        [
                            'category'    => 'Security Policy Enforcement',
                            'status_code' => 403,
                            'rule'        => $rule,
                        ]
                    );
                }
            }
        }

        return null;
    }
}
