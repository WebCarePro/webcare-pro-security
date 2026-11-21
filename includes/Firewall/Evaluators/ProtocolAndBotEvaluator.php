<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall\Evaluators;

use WebCareProScanner\Contracts\EvaluatorFailurePolicy;
use WebCareProScanner\Contracts\RequestContext;
use WebCareProScanner\Contracts\RouteClass;
use WebCareProScanner\Contracts\WafEvaluatorInterface;
use WebCareProScanner\Contracts\WafVerdict;
use WebCareProScanner\Firewall\AdaptiveRateLimiter;
use WebCareProScanner\Firewall\BotReconDefense;
use WebCareProScanner\Firewall\CAF\ThreatScoreTracker;
use WebCareProScanner\Firewall\Core\AllowlistManager;
use WebCareProScanner\Firewall\Core\CommerceSessionGuard;
use WebCareProScanner\Firewall\FirewallEngine;
use WebCareProScanner\System\SettingsManager;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * ProtocolAndBotEvaluator
 *
 * Operational heuristic & protocol anomaly evaluator.
 * Evaluates behavioral threat scores, adaptive token-bucket rate limits, WebCrypto PoW
 * enforced suspicious IP sentinel, HTTP/2 & HTTP/3 pseudo-header and client-hint anomalies,
 * CAF dormant attack surface lockdown, blank User-Agent / Referer POST guards, and
 * Bot Recon Defense / AI scraper shielding.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
final readonly class ProtocolAndBotEvaluator implements WafEvaluatorInterface {

    public function get_module_id(): string {
        return 'protocol-and-bot-evaluator';
    }

    public function is_required(): bool {
        return false;
    }

    public function get_route_classes(): array {
        return RouteClass::cases();
    }

    public function get_required_capabilities(): array {
        return [];
    }

    public function get_failure_policy(): EvaluatorFailurePolicy {
        return EvaluatorFailurePolicy::DegradedLog;
    }

    public function compile_preload_ast(): array {
        return [
            'id'        => 'WAF-PROTOCOL-AND-BOT-EVALUATOR',
            'category'  => 'Protocol & Bot Heuristic Defense',
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

    public function evaluate_runtime_request(RequestContext $ctx): ?WafVerdict {
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_enabled']) || ($settings['waf_mode'] ?? 'enabled') === 'disabled') {
            return null;
        }

        $client_ip = $ctx->ip;
        $request_uri = $ctx->uri;
        $method = $ctx->method;

        // 0. Operational heuristic exemption checks
        // Authenticated administrators and builders bypass operational heuristics
        $is_admin = (function_exists('current_user_can') && current_user_can('manage_options'))
            || FirewallEngine::is_authenticated_administrator();
        $is_builder = FirewallEngine::is_authenticated_editor_or_builder();

        if ($is_admin || $is_builder) {
            return null;
        }

        // IP allowlist check
        $whitelist_ctx = AllowlistManager::check_ip_whitelist_context($client_ip, $settings);
        if ($whitelist_ctx['is_whitelisted']) {
            return null;
        }

        // URL allowlist checks
        if (!empty($settings['waf_whitelisted_urls']) && AllowlistManager::is_url_whitelisted($request_uri, (string) $settings['waf_whitelisted_urls'])) {
            return null;
        }

        if (!empty($settings['waf_contact_support_url']) && AllowlistManager::is_configured_support_path($request_uri, (string) $settings['waf_contact_support_url'])) {
            return null;
        }

        // 1. Differential Threat Score & Behavioral Pre-Flight (CAF Phase 3)
        if (!empty($settings['caf_threat_score_enabled']) && class_exists(ThreatScoreTracker::class)) {
            // Verified active WooCommerce shoppers are exempt from threat scoring
            $is_shopper = class_exists(CommerceSessionGuard::class) && CommerceSessionGuard::has_active_shopper_session();
            if (!$is_shopper) {
                $score = ThreatScoreTracker::get_current_score($client_ip);
                if ($score > 0.0) {
                    if ($score >= ThreatScoreTracker::THRESHOLD_THROTTLE) {
                        return WafVerdict::rate_limit(
                            'WAF-BEHAVIORAL-THREAT-SCORE',
                            self::translatable_string('Behavioral threat score threshold exceeded. Temporary rate limit enforced.'),
                            [
                                'category'    => 'Behavioral Threat Defense',
                                'status_code' => 429,
                                'threat_score'=> $score,
                            ]
                        );
                    }
                    if ($score >= ThreatScoreTracker::THRESHOLD_POW) {
                        $is_json = wp_is_json_request()
                            || (defined('REST_REQUEST') && REST_REQUEST)
                            || (function_exists('wp_doing_ajax') && wp_doing_ajax())
                            || str_contains($request_uri, '/wp-json/')
                            || str_contains($request_uri, 'rest_route=')
                            || str_contains($request_uri, 'wc-ajax=');

                        if ($is_json) {
                            return WafVerdict::rate_limit(
                                'WAF-THREAT-SCORE-JSON-RATELIMIT',
                                self::translatable_string('Suspicious threat velocity detected. Please retry with solved PoW token.'),
                                [
                                    'category'    => 'Behavioral Threat Defense',
                                    'status_code' => 429,
                                    'threat_score'=> $score,
                                ]
                            );
                        }

                        return WafVerdict::challenge(
                            'WAF-THREAT-SCORE-POW-CHALLENGE',
                            self::translatable_string('Suspicious behavioral threat velocity detected. WebCrypto PoW challenge required.'),
                            [
                                'category'    => 'Behavioral Threat Defense',
                                'threat_score'=> $score,
                            ]
                        );
                    }
                }
            }
        }

        // 2. Adaptive Rate Limiter & Token-Bucket Throttling
        if (class_exists(AdaptiveRateLimiter::class) && !in_array($client_ip, ['127.0.0.1', '::1'], true)) {
            $rl_settings = AdaptiveRateLimiter::get_settings();
            if (!empty($rl_settings['enabled'])) {
                // Determine rate limiting bucket
                $bucket = AdaptiveRateLimiter::BUCKET_GLOBAL;
                $limit = (int) ($rl_settings['limit_global'] ?? AdaptiveRateLimiter::LIMIT_GLOBAL);
                $window = (int) ($rl_settings['window_global'] ?? AdaptiveRateLimiter::WINDOW_GLOBAL);

                $decoded_uri = rawurldecode($request_uri);
                if (
                    str_contains($decoded_uri, 'wp-login.php') ||
                    str_contains($decoded_uri, 'xmlrpc.php') ||
                    str_contains($decoded_uri, '/wp-json/jwt-auth/') ||
                    str_contains($decoded_uri, 'wc-ajax=login')
                ) {
                    $bucket = AdaptiveRateLimiter::BUCKET_AUTH;
                    $limit = (int) ($rl_settings['limit_auth'] ?? AdaptiveRateLimiter::LIMIT_AUTH);
                    $window = (int) ($rl_settings['window_auth'] ?? AdaptiveRateLimiter::WINDOW_AUTH);
                } elseif (
                    str_contains($decoded_uri, 'wc-ajax=checkout') ||
                    str_contains($decoded_uri, '/wp-json/wc/store/v1/checkout') ||
                    str_contains($decoded_uri, '/wp-json/wc/v3/orders')
                ) {
                    $bucket = AdaptiveRateLimiter::BUCKET_CHECKOUT;
                    $limit = (int) ($rl_settings['limit_checkout'] ?? AdaptiveRateLimiter::LIMIT_CHECKOUT);
                    $window = (int) ($rl_settings['window_checkout'] ?? AdaptiveRateLimiter::WINDOW_CHECKOUT);
                } elseif (
                    str_contains($decoded_uri, 'wc-ajax=') ||
                    str_contains($decoded_uri, 'add_to_cart') ||
                    str_contains($decoded_uri, 'update_order_review') ||
                    str_contains($decoded_uri, 'get_refreshed_fragments')
                ) {
                    $bucket = AdaptiveRateLimiter::BUCKET_CART_AJAX;
                    $limit = (int) ($rl_settings['limit_cart_ajax'] ?? AdaptiveRateLimiter::LIMIT_CART_AJAX);
                    $window = (int) ($rl_settings['window_cart_ajax'] ?? AdaptiveRateLimiter::WINDOW_CART_AJAX);
                } elseif (
                    str_contains($decoded_uri, '/wp-json/') &&
                    in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE'], true)
                ) {
                    $bucket = AdaptiveRateLimiter::BUCKET_REST_WRITE;
                    $limit = (int) ($rl_settings['limit_rest_write'] ?? AdaptiveRateLimiter::LIMIT_REST_WRITE);
                    $window = (int) ($rl_settings['window_rest_write'] ?? AdaptiveRateLimiter::WINDOW_REST_WRITE);
                } elseif (!empty($ctx->queryParams['s']) || str_contains($decoded_uri, '/wp-json/wp/v2/search')) {
                    $bucket = AdaptiveRateLimiter::BUCKET_SEARCH_PROBE;
                    $limit = (int) ($rl_settings['limit_search_probe'] ?? AdaptiveRateLimiter::LIMIT_SEARCH_PROBE);
                    $window = (int) ($rl_settings['window_search_probe'] ?? AdaptiveRateLimiter::WINDOW_SEARCH_PROBE);
                }

                $rate_result = AdaptiveRateLimiter::check_bucket_velocity($bucket, $client_ip, $limit, $window);
                if (empty($rate_result['allowed'])) {
                    return WafVerdict::rate_limit(
                        'WAF-RATE-LIMIT-THROTTLED',
                        self::translatable_string(sprintf('Too many %s requests. Velocity threshold reached.', esc_html($bucket))),
                        [
                            'category'    => 'Velocity Defense',
                            'status_code' => 429,
                            'bucket'      => $bucket,
                            'retry_after' => $rate_result['retry_after'] ?? 30,
                            'limit'       => $limit,
                        ]
                    );
                }
            }
        }

        // 3. WebCrypto PoW Enforced Suspicious IP Sentinel
        $pow_ips = get_option('webcare_pow_enforced_ips', []);
        if (is_array($pow_ips) && isset($pow_ips[$client_ip])) {
            $pow_exp = (int) ($pow_ips[$client_ip]['expires_at'] ?? 0);
            if ($pow_exp > 0 && time() > $pow_exp) {
                unset($pow_ips[$client_ip]);
                update_option('webcare_pow_enforced_ips', $pow_ips, false);
            } elseif (class_exists(BotReconDefense::class)) {
                $has_clearance = BotReconDefense::has_valid_clearance_cookie($client_ip, $ctx->userAgent)
                    || BotReconDefense::verify_and_clear_pow_header($client_ip, $ctx->userAgent);
                if (!$has_clearance) {
                    $is_json = wp_is_json_request()
                        || (defined('REST_REQUEST') && REST_REQUEST)
                        || (function_exists('wp_doing_ajax') && wp_doing_ajax())
                        || str_contains($request_uri, '/wp-json/')
                        || str_contains($request_uri, 'rest_route=')
                        || str_contains($request_uri, 'wc-ajax=');

                    if ($is_json) {
                        return WafVerdict::rate_limit(
                            'WAF-SUSPICIOUS-IP-RATELIMIT',
                            self::translatable_string('Suspicious IP address. WebCrypto PoW clearance required.'),
                            [
                                'category'    => 'Bot Defense',
                                'status_code' => 429,
                            ]
                        );
                    }

                    return WafVerdict::challenge(
                        'WAF-SUSPICIOUS-IP-POW-CHALLENGE',
                        self::translatable_string('Suspicious IP address. WebCrypto Proof-of-Work challenge required.'),
                        [
                            'category' => 'Bot Defense',
                        ]
                    );
                }
            }
        }

        // 4. HTTP/2 & HTTP/3 Pseudo-Header and Client-Hint Anomaly Sentinel (CAF Phase 3)
        $h2_anomaly = self::check_http2_pseudo_header_anomaly_from_ctx($ctx);
        if ($h2_anomaly !== null) {
            if (class_exists(ThreatScoreTracker::class)) {
                ThreatScoreTracker::record_event($client_ip, 'header_anomaly', 15.0);
            }

            // Only hard-block malformed uppercase HTTP/2 pseudo-headers (or when strict HTTP/2 blocking is explicitly enabled)
            if (($h2_anomaly['anomaly'] ?? '') === 'uppercase_pseudo_header' || !empty($settings['waf_block_http2_anomalies'])) {
                return new WafVerdict(
                    'block',
                    'BOT-H2-HEADER-ANOMALY',
                    $h2_anomaly['description'] ?? 'HTTP/2 Header / Client-Hint Anomaly',
                    [
                        'category'    => 'Protocol Anomaly Defense',
                        'status_code' => 403,
                        'anomaly'     => $h2_anomaly['anomaly'] ?? '',
                    ]
                );
            }
        }

        // 5. Context-Adaptive Firewall (CAF): Dormant Attack Surface Lockdown
        $lock_dormant = (bool) get_option('webcareproscan_caf_lock_dormant_surface', get_option('webcare_caf_lock_dormant_surface', true));
        if ($lock_dormant) {
            $decoded_check_uri = rawurldecode($request_uri);

            if (preg_match('#/wp-content/plugins/([a-zA-Z0-9_-]+)/#i', $decoded_check_uri, $plugin_matches)) {
                $target_slug = strtolower($plugin_matches[1]);
                $cached_snapshot = get_option('webcareproscan_caf_stack_snapshot', get_option('webcare_caf_stack_snapshot'));
                $inactive_plugins = is_array($cached_snapshot) && !empty($cached_snapshot['inactive_plugins']) ? array_keys($cached_snapshot['inactive_plugins']) : [];

                if (in_array($target_slug, $inactive_plugins, true)) {
                    $desc = self::translatable_string(
                        sprintf('Request targets deactivated plugin "%s". Direct requests to inactive components are strictly blocked.', esc_html($target_slug))
                    );
                    return new WafVerdict(
                        'block',
                        'WAF-CAF-DORMANT-SURFACE',
                        $desc,
                        [
                            'category'    => 'Dormant Surface Shield',
                            'status_code' => 403,
                            'target_slug' => $target_slug,
                        ]
                    );
                }
            } elseif (preg_match('#/wp-content/themes/([a-zA-Z0-9_-]+)/#i', $decoded_check_uri, $theme_matches)) {
                $target_theme = strtolower($theme_matches[1]);
                $cached_snapshot = get_option('webcareproscan_caf_stack_snapshot', get_option('webcare_caf_stack_snapshot'));
                $inactive_themes = is_array($cached_snapshot) && !empty($cached_snapshot['inactive_themes']) ? array_keys($cached_snapshot['inactive_themes']) : [];

                if (in_array($target_theme, $inactive_themes, true)) {
                    $desc = self::translatable_string(
                        sprintf('Request targets inactive theme "%s". Direct requests to inactive themes are strictly blocked.', esc_html($target_theme))
                    );
                    return new WafVerdict(
                        'block',
                        'WAF-CAF-DORMANT-THEME',
                        $desc,
                        [
                            'category'    => 'Dormant Surface Shield',
                            'status_code' => 403,
                            'target_theme'=> $target_theme,
                        ]
                    );
                }
            }
        }

        // 6. Blank User-Agent / Referer POST Guard & Missing UA Shield
        $is_post = ($method === 'POST');
        $is_options = ($method === 'OPTIONS');

        // Check for verified payment gateway webhooks (Stripe / PayPal / Mollie / Square)
        $is_webhook = self::is_verified_payment_gateway_webhook_from_ctx($ctx);

        if (!empty($settings['waf_block_empty_post_ua_referer']) && $is_post && !$is_options && !$is_webhook) {
            $is_commerce_safe = !empty($settings['waf_ecommerce_safe_mode']) && CommerceSessionGuard::is_commerce_or_membership_request($request_uri);
            $is_form_safe = !empty($settings['waf_forms_safe_mode']) && CommerceSessionGuard::is_form_submission_request($request_uri);

            if (!$is_commerce_safe && !$is_form_safe) {
                $has_ua = trim($ctx->userAgent) !== '';
                $has_ref = trim($ctx->referer) !== '';

                if (!$has_ua && !$has_ref) {
                    $desc = self::translatable_string('Automated POST payload rejected: Both User-Agent and Referer headers were missing or empty.');
                    return new WafVerdict(
                        'block',
                        'WAF-EMPTY-POST-UA-REFERER',
                        $desc,
                        [
                            'category'    => 'Bot Defense',
                            'status_code' => 403,
                        ]
                    );
                }
            }
        }

        // Rule: Blank or Missing User-Agent Shield
        if (!empty($settings['waf_block_empty_user_agent'])) {
            $raw_ua = trim($ctx->userAgent);
            if ($raw_ua === '') {
                // Never break CORS preflight OPTIONS requests
                if (!$is_options && !$is_webhook) {
                    $is_loopback = in_array($client_ip, ['127.0.0.1', '::1'], true)
                        || ($client_ip === ($ctx->server['SERVER_ADDR'] ?? ''));
                    $is_cli_or_cron = (php_sapi_name() === 'cli' || (defined('DOING_CRON') && DOING_CRON) || isset($ctx->queryParams['doing_wp_cron']));
                    $is_wc_api = isset($ctx->queryParams['wc-api']);
                    $is_commerce_safe = !empty($settings['waf_ecommerce_safe_mode']) && CommerceSessionGuard::is_commerce_or_membership_request($request_uri);
                    $is_form_safe = !empty($settings['waf_forms_safe_mode']) && CommerceSessionGuard::is_form_submission_request($request_uri);

                    if (!$is_loopback && !$is_cli_or_cron && !$is_wc_api && !$is_commerce_safe && !$is_form_safe) {
                        $has_pow_submission = isset($ctx->formParams['webcare_pow_challenge'], $ctx->formParams['webcare_pow_nonce']);
                        $has_clearance = class_exists(BotReconDefense::class)
                            && (BotReconDefense::has_valid_clearance_cookie($client_ip, '') || BotReconDefense::verify_and_clear_pow_header($client_ip, ''));

                        $empty_ua_action = FirewallEngine::get_empty_user_agent_action($method, $has_clearance, $has_pow_submission);

                        if ($empty_ua_action === 'allow') {
                            // Clearance or valid flow permits the request
                        } elseif ($empty_ua_action === 'head_block') {
                            return new WafVerdict(
                                'block',
                                'WAF-EMPTY-USER-AGENT',
                                self::translatable_string('Automated HEAD request rejected: User-Agent header was missing or empty.'),
                                [
                                    'category'    => 'Bot Defense',
                                    'status_code' => 403,
                                ]
                            );
                        } elseif ($empty_ua_action === 'challenge') {
                            $is_json = wp_is_json_request()
                                || (defined('REST_REQUEST') && REST_REQUEST)
                                || (function_exists('wp_doing_ajax') && wp_doing_ajax())
                                || str_contains($request_uri, '/wp-json/')
                                || str_contains($request_uri, 'rest_route=')
                                || str_contains($request_uri, 'wc-ajax=');

                            if ($is_json) {
                                return WafVerdict::rate_limit(
                                    'WAF-EMPTY-UA-JSON-RATELIMIT',
                                    self::translatable_string('Blank User-Agent rejected on API surface. Please retry with standard client headers.'),
                                    [
                                        'category'    => 'Bot Defense',
                                        'status_code' => 429,
                                    ]
                                );
                            }

                            return WafVerdict::challenge(
                                'WAF-EMPTY-USER-AGENT',
                                self::translatable_string('Automated request without User-Agent header requires verification.'),
                                [
                                    'category'    => 'Bot Defense',
                                    'status_code' => 429,
                                ]
                            );
                        } else {
                            $desc = self::translatable_string('Automated request rejected: The HTTP User-Agent header was missing or blank.');
                            return new WafVerdict(
                                'block',
                                'WAF-EMPTY-USER-AGENT',
                                $desc,
                                [
                                    'category'    => 'Bot Defense',
                                    'status_code' => 403,
                                ]
                            );
                        }
                    }
                }
            }
        }

        // 7. Check Bot Recon Defense & AI Scraper Shield
        if (class_exists(BotReconDefense::class) && trim($ctx->userAgent) !== '') {
            $ua = $ctx->userAgent;
            $is_legit_search = BotReconDefense::is_genuine_search_engine($client_ip, $ua);
            if (!$is_legit_search) {
                $bot_rule = BotReconDefense::inspect_bot($client_ip, $ua, $settings);
                if ($bot_rule !== null && is_array($bot_rule)) {
                    $rule_id = (string) ($bot_rule['id'] ?? 'WAF-BOT-DEFENSE');
                    $rule_desc = (string) ($bot_rule['description'] ?? 'Malicious scraper or unverified bot rejected.');
                    return new WafVerdict(
                        'block',
                        $rule_id,
                        $rule_desc,
                        [
                            'category'    => $bot_rule['category'] ?? 'Bot Defense',
                            'status_code' => 403,
                            'bot_rule'    => $bot_rule,
                        ]
                    );
                }
            }
        }

        return null;
    }

    /**
     * Inspect HTTP/2 & HTTP/3 pseudo-header and client-hint anomalies from RequestContext.
     */
    private static function check_http2_pseudo_header_anomaly_from_ctx(RequestContext $ctx): ?array {
        $protocol = (string) ($ctx->server['SERVER_PROTOCOL'] ?? '');
        $is_h2 = (str_contains($protocol, 'HTTP/2') || str_contains($protocol, 'HTTP/3') || (!empty($ctx->server['HTTP2']) && $ctx->server['HTTP2'] === 'on'));

        if (!$is_h2) {
            return null;
        }

        // 1. Check for uppercase pseudo-headers (e.g. :Method, :Path, :Authority, :Scheme)
        // Inspect headers directly from RequestContext and raw server headers
        foreach ($ctx->headers as $header_name => $header_val) {
            if (is_string($header_name) && str_starts_with($header_name, ':')) {
                if ($header_name !== strtolower($header_name)) {
                    return [
                        'anomaly'     => 'uppercase_pseudo_header',
                        'description' => sprintf('Invalid uppercase HTTP/2 pseudo-header detected: %s', esc_html($header_name)),
                        'severity'    => 'high',
                    ];
                }
            }
        }

        // Check if raw headers can be inspected
        if (function_exists('getallheaders')) {
            $raw_headers = getallheaders();
            if (!empty($raw_headers) && is_array($raw_headers)) {
                foreach (array_keys($raw_headers) as $h_name) {
                    if (is_string($h_name) && str_starts_with($h_name, ':') && $h_name !== strtolower($h_name)) {
                        return [
                            'anomaly'     => 'uppercase_pseudo_header',
                            'description' => sprintf('Invalid uppercase HTTP/2 pseudo-header detected: %s', esc_html($h_name)),
                            'severity'    => 'high',
                        ];
                    }
                }
            }
        }

        return null;
    }

    /**
     * Detect verified payment gateway webhooks (Stripe / PayPal / Mollie / Square).
     */
    private static function is_verified_payment_gateway_webhook_from_ctx(RequestContext $ctx): bool {
        $client_ip = $ctx->ip;

        // 1. Stripe Webhook IPs
        if (in_array($client_ip, CommerceSessionGuard::STRIPE_WEBHOOK_IPS, true) || in_array($client_ip, ['54.241.31.102', '54.241.34.107'], true)) {
            return true;
        }

        // 2. PayPal Webhook subnets
        foreach (array_merge(CommerceSessionGuard::PAYPAL_WEBHOOK_CIDRS, ['185.177.189.0/24', '3.253.0.0/16', '52.212.0.0/15']) as $paypal_cidr) {
            if (\WebCareProScanner\Firewall\Core\ClientIpResolver::ip_in_range($client_ip, $paypal_cidr)) {
                return true;
            }
        }

        // 3. Webhook signature headers on designated webhook endpoints
        $parsed_path = strtolower(wp_parse_url($ctx->uri, PHP_URL_PATH) ?: $ctx->uri);
        $is_webhook_endpoint = (
            str_contains($parsed_path, '/wp-json/mollie')
            || str_contains($parsed_path, '/wp-json/square')
            || str_contains($parsed_path, '/wp-json/surecart')
            || str_contains($ctx->uri, 'wc-api=')
            || !empty($ctx->queryParams['wc-api'])
        );

        if ($is_webhook_endpoint) {
            $sig_headers = [
                'x-square-hmacsha256-signature',
                'x-wc-webhook-signature',
                'x-razorpay-signature',
                'x-shopify-hmac-sha256',
                'x-mollie-signature',
                'x-surecart-signature',
            ];
            foreach ($sig_headers as $sh) {
                if (!empty($ctx->headers[$sh]) || !empty($ctx->server['HTTP_' . strtoupper(str_replace('-', '_', $sh))])) {
                    return true;
                }
            }
        }

        return false;
    }
}
