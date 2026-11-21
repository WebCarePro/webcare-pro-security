<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall\Evaluators;

use WebCareProScanner\Contracts\EvaluatorFailurePolicy;
use WebCareProScanner\Contracts\RequestContext;
use WebCareProScanner\Contracts\RouteClass;
use WebCareProScanner\Contracts\WafAction;
use WebCareProScanner\Contracts\WafEvaluatorInterface;
use WebCareProScanner\Contracts\WafVerdict;
use WebCareProScanner\Firewall\Core\AffiliateSecurityEngine;
use WebCareProScanner\Firewall\Core\ClientIpResolver;
use WebCareProScanner\Firewall\Core\CommerceSessionGuard;
use WebCareProScanner\Firewall\Core\ExploitSignatureEngine;
use WebCareProScanner\Firewall\FirewallEngine;
use WebCareProScanner\System\SettingsManager;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * CommerceAndUploadEvaluator
 *
 * Route & capability-scoped evaluator for:
 * 1. Forged Payment Gateway Webhook Signature Spoofing Trap (Rule #52).
 * 2. Multi-Dimensional $ctx->files Upload Pre-Flight Inspection (Rule #8).
 * 3. Affiliate Ecosystem Shield & Click-Fraud Armor (Rule #43).
 *
 * Scoped strictly to:
 * - RouteClass::Commerce (Commerce checkout/cart)
 * - RouteClass::PublicMutation
 * - RouteClass::RestApi
 * - RouteClass::AdminAjax
 * - RouteClass::AdminUi
 * (Must NOT run on RouteClass::PublicGet plain blog requests — zero overhead).
 *
 * Author: Mir Alamin (WebCare Pro)
 * Senior Linux SysAdmin & WordPress Security Engineer
 */
final readonly class CommerceAndUploadEvaluator implements WafEvaluatorInterface {

    public function get_module_id(): string {
        return 'commerce-and-upload-evaluator';
    }

    public function is_required(): bool {
        return false;
    }

    /**
     * @return array<RouteClass>
     */
    public function get_route_classes(): array {
        return [
            RouteClass::Commerce,
            RouteClass::PublicMutation,
            RouteClass::RestApi,
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
            'id'        => 'WAF-COMMERCE-AND-UPLOAD-SURFACE',
            'category'  => 'Commerce & Upload Surface Defense',
            'evaluator' => self::class,
        ];
    }

    public function evaluate_runtime_request(RequestContext $ctx): ?WafVerdict {
        $settings = SettingsManager::get_settings();

        // 1. Forged Payment Gateway Webhook Signature Spoofing Trap (Smart Rule #52)
        $webhook_verdict = $this->evaluate_webhook_signatures($ctx, $settings);
        if ($webhook_verdict !== null) {
            return $webhook_verdict;
        }

        // 2. Multi-Dimensional $ctx->files Upload Pre-Flight Inspection (Rule #8)
        $upload_verdict = $this->evaluate_uploaded_files($ctx, $settings);
        if ($upload_verdict !== null) {
            return $upload_verdict;
        }

        // 3. Affiliate Ecosystem Shield & Click-Fraud Armor (Rule #43)
        $affiliate_verdict = $this->evaluate_affiliate_shield($ctx, $settings);
        if ($affiliate_verdict !== null) {
            return $affiliate_verdict;
        }

        return null;
    }

    /**
     * Evaluate Stripe & PayPal webhook signature headers against origin IPs.
     */
    private function evaluate_webhook_signatures(RequestContext $ctx, array $settings): ?WafVerdict {
        $raw_stripe_sig = (string) ($ctx->headers['stripe-signature'] ?? ($ctx->server['HTTP_STRIPE_SIGNATURE'] ?? ''));
        $raw_paypal_sig = (string) ($ctx->headers['paypal-transmission-sig'] ?? ($ctx->server['HTTP_PAYPAL_TRANSMISSION_SIG'] ?? ''));

        $has_stripe_sig = ($raw_stripe_sig !== '');
        $has_paypal_sig = ($raw_paypal_sig !== '');

        if (!$has_stripe_sig && !$has_paypal_sig) {
            return null;
        }

        $client_ip = $ctx->ip;

        if (
            ClientIpResolver::is_server_origin_or_loopback($client_ip) ||
            FirewallEngine::is_authenticated_administrator()
        ) {
            return null;
        }

        $is_genuine_webhook_origin = false;

        if ($has_stripe_sig) {
            $base_stripe_ips = class_exists(CommerceSessionGuard::class)
                ? CommerceSessionGuard::STRIPE_WEBHOOK_IPS
                : FirewallEngine::STRIPE_WEBHOOK_IPS;

            $default_stripe_cidrs = array_map(
                static function (string $ip): string {
                    return !str_contains($ip, '/') ? $ip . '/32' : $ip;
                },
                array_values(array_unique(array_merge($base_stripe_ips, [
                    '54.241.31.102',
                    '54.241.34.107',
                ])))
            );

            $stripe_cidrs = function_exists('apply_filters')
                ? apply_filters('webcareproscan_stripe_webhook_cidrs', $default_stripe_cidrs)
                : $default_stripe_cidrs;

            foreach ((array) $stripe_cidrs as $stripe_cidr) {
                if (ClientIpResolver::ip_in_range($client_ip, (string) $stripe_cidr)) {
                    $is_genuine_webhook_origin = true;
                    break;
                }
            }
        }

        if (!$is_genuine_webhook_origin && $has_paypal_sig) {
            $base_paypal_cidrs = class_exists(CommerceSessionGuard::class)
                ? CommerceSessionGuard::PAYPAL_WEBHOOK_CIDRS
                : FirewallEngine::PAYPAL_WEBHOOK_CIDRS;

            $default_paypal_cidrs = array_values(array_unique(array_merge($base_paypal_cidrs, [
                '185.177.189.0/24',
                '3.253.0.0/16',
                '52.212.0.0/15',
            ])));

            $paypal_cidrs = function_exists('apply_filters')
                ? apply_filters('webcareproscan_paypal_webhook_cidrs', $default_paypal_cidrs)
                : $default_paypal_cidrs;

            foreach ((array) $paypal_cidrs as $paypal_cidr) {
                if (ClientIpResolver::ip_in_range($client_ip, (string) $paypal_cidr)) {
                    $is_genuine_webhook_origin = true;
                    break;
                }
            }
        }

        if ($is_genuine_webhook_origin) {
            return null;
        }

        // Check if header format itself is a forged spoof or if the target URI is not a webhook endpoint
        $req_uri_lower = strtolower($ctx->uri);
        $is_dedicated_webhook_uri = (
            str_contains($req_uri_lower, 'wc-api=')
            || str_contains($req_uri_lower, '/wc-api/')
            || str_contains($req_uri_lower, '/wp-json/wc-stripe')
            || str_contains($req_uri_lower, '/wp-json/stripe')
            || str_contains($req_uri_lower, '/wp-json/paypal')
            || str_contains($req_uri_lower, '/wp-json/woocommerce')
            || str_contains($req_uri_lower, 'webhook')
        );

        $is_malformed_sig = false;
        if ($has_stripe_sig && !preg_match('/\bt=\d+\b.*?\bv1=[a-f0-9]{64}\b/i', $raw_stripe_sig)) {
            $is_malformed_sig = true;
        }
        if ($has_paypal_sig && strlen(trim($raw_paypal_sig)) < 32) {
            $is_malformed_sig = true;
        }

        $is_drill_request = !empty($ctx->headers['x-webcare-drill-secret']) || !empty($ctx->server['HTTP_X_WEBCARE_DRILL_SECRET']);

        // Block immediately if header is malformed, sent to a non-webhook URI, or during red-team drill
        if ($is_malformed_sig || !$is_dedicated_webhook_uri || $is_drill_request) {
            $sig_type = $has_stripe_sig ? 'Stripe-Signature' : 'PayPal-Transmission-Sig';

            $can_translate = function_exists('did_action') && did_action('init');
            $desc_fmt = $can_translate
                ? __('Forged %1$s webhook header presented by unauthorized non-gateway IP (%2$s).', 'webcare-pro-security')
                : 'Forged %1$s webhook header presented by unauthorized non-gateway IP (%2$s).';

            return new WafVerdict(
                WafAction::Block,
                'WAF-FORGED-WEBHOOK-TRAP',
                sprintf($desc_fmt, $sig_type, $client_ip),
                [
                    'category'    => 'Execution Armor',
                    'detector'    => 'CommerceAndUploadEvaluator',
                    'sig_id'      => 'sig:proto:forged_webhook_signature',
                    'match_type'  => 'Webhook Origin Spoofing',
                    'match_value' => $client_ip,
                    'payload'     => "Header: {$sig_type} URI: {$ctx->uri} Spoofed IP: {$client_ip}",
                    'status_code' => 403,
                ]
            );
        }

        return null;
    }

    /**
     * Multi-Dimensional $ctx->files Payload Pre-Flight Inspection (Rule #8).
     */
    private function evaluate_uploaded_files(RequestContext $ctx, array $settings): ?WafVerdict {
        if (empty($ctx->files) || empty($settings['waf_block_malicious_uploads'])) {
            return null;
        }

        $files_overflow = false;
        $all_uploaded_files = ExploitSignatureEngine::flatten_uploaded_files($ctx->files, 4, 50, $files_overflow);

        if ($files_overflow) {
            return new WafVerdict(
                WafAction::Block,
                'WAF-MULTIPART-FILE-COUNT-EXCEEDED',
                'Multipart request exceeds maximum allowed file count (50) or nesting depth (4); failing closed.',
                [
                    'category'    => 'Protocol Defense',
                    'match_type'  => 'Upload Array Overflow',
                    'match_value' => 'count > 50 or depth > 4',
                    'payload'     => 'Multipart $ctx->files overflow (>50 files or >4 nesting depth)',
                    'status_code' => 403,
                ]
            );
        }

        foreach ($all_uploaded_files as $uploaded_item) {
            // Pass log_and_ban = false to let RequestPipeline / ViolationResponder perform single authoritative log/ban
            $upload_check = ExploitSignatureEngine::inspect_uploaded_file($uploaded_item, false);
            if (!empty($upload_check['error'])) {
                $rule_id   = !empty($upload_check['rule_id']) ? (string) $upload_check['rule_id'] : 'WAF-POLYGLOT-UPLOAD-TRAP';
                $rule_name = !empty($upload_check['rule_name']) ? (string) $upload_check['rule_name'] : 'Malicious File Upload Shield (Rule 8)';
                $category  = !empty($upload_check['category']) ? (string) $upload_check['category'] : 'Malicious File Upload';
                $detector  = !empty($upload_check['detector']) ? (string) $upload_check['detector'] : 'ExploitSignatureEngine';
                $sig_id    = !empty($upload_check['sig_id']) ? (string) $upload_check['sig_id'] : 'sig:upload:polyglot_embedded_script';
                $file_name = (string) ($uploaded_item['name'] ?? '');

                return new WafVerdict(
                    WafAction::Block,
                    $rule_id,
                    (string) $upload_check['error'],
                    [
                        'name'        => $rule_name,
                        'category'    => $category,
                        'detector'    => $detector,
                        'sig_id'      => $sig_id,
                        'match_type'  => 'Malicious File Upload',
                        'match_value' => $file_name,
                        'payload'     => 'Uploaded: ' . substr($file_name, 0, 100) . ' IP: ' . $ctx->ip,
                        'status_code' => 403,
                    ]
                );
            }
        }

        return null;
    }

    /**
     * Affiliate Ecosystem Shield & Click-Fraud Armor (Rule #43).
     */
    private function evaluate_affiliate_shield(RequestContext $ctx, array $settings): ?WafVerdict {
        if (empty($settings['waf_affiliate_shield_enabled']) || !class_exists(AffiliateSecurityEngine::class)) {
            return null;
        }

        $ecosystem = AffiliateSecurityEngine::get_detected_ecosystem();
        if (empty($ecosystem['is_active'])) {
            return null;
        }

        // Collect referral parameters strictly from $ctx
        $found_params = AffiliateSecurityEngine::collect_referral_parameters(
            (array) $ctx->queryParams,
            (array) $ctx->formParams,
            (array) $ctx->jsonParams
        );

        if (empty($found_params)) {
            return null;
        }

        // 1. Anti-Injection Inspection
        if (!empty($settings['waf_affiliate_anti_injection'])) {
            $injection_violation = AffiliateSecurityEngine::find_referral_injection($found_params, $ctx->ip, $ctx->uri);
            if ($injection_violation !== null) {
                return new WafVerdict(
                    WafAction::Block,
                    $injection_violation['id'] ?? 'WAF-AFFILIATE-INJECTION',
                    $injection_violation['description'] ?? 'Malicious payload detected in referral parameter.',
                    array_merge($injection_violation, ['status_code' => 403])
                );
            }
        }

        // 2. Click-Fraud & High-Velocity Visit Rate Limiter
        $max_clicks  = max(3, min(300, (int) ($settings['waf_affiliate_max_clicks_min'] ?? 10)));
        $is_flooding = AffiliateSecurityEngine::track_referral_click_velocity($ctx->ip, $max_clicks);

        if (AffiliateSecurityEngine::suppress_visit_recording_if_flooding($is_flooding)) {
            $first_key = array_key_first($found_params);

            $can_translate = function_exists('did_action') && did_action('init');
            $desc_fmt = $can_translate
                ? __('High-velocity referral click flood from IP %1$s exceeded safety threshold (%2$d clicks/min). Suppressed database visit logging to prevent table bloat and click-fraud.', 'webcare-pro-security')
                : 'High-velocity referral click flood from IP %1$s exceeded safety threshold (%2$d clicks/min). Suppressed database visit logging to prevent table bloat and click-fraud.';

            $rule_triggered = [
                'id'          => 'WAF-AFFILIATE-CLICK-FLOOD',
                'name'        => 'Affiliate Referral Click-Flood & Database Bloat Shield (Rule #43)',
                'category'    => 'Affiliate Defense',
                'description' => sprintf($desc_fmt, $ctx->ip, $max_clicks),
                'match_type'  => 'Referral Velocity Limit',
                'match_value' => $ctx->ip,
                'payload'     => "IP: {$ctx->ip} Param: {$first_key} Clicks: >{$max_clicks}/min",
            ];

            FirewallEngine::log_incident($rule_triggered, 'throttled');
        }

        return null;
    }
}
