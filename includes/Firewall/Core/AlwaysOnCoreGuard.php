<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall\Core;

if (!defined('ABSPATH')) {
    exit;
}

use WebCareProScanner\Contracts\EvaluatorFailurePolicy;
use WebCareProScanner\Contracts\RequestContext;
use WebCareProScanner\Contracts\RouteClass;
use WebCareProScanner\Contracts\WafAction;
use WebCareProScanner\Contracts\WafEvaluatorInterface;
use WebCareProScanner\Contracts\WafVerdict;
use WebCareProScanner\Firewall\BotReconDefense;
use WebCareProScanner\Firewall\FirewallEngine;
use WebCareProScanner\Firewall\Modular\ModularFirewallSynthesizer;
use WebCareProScanner\Firewall\RescueAssistantManager;
use WebCareProScanner\Firewall\ThreatIntelNetwork;
use WebCareProScanner\Firewall\ThreatIntelService;
use WebCareProScanner\Firewall\VirtualPatchManager;
use WebCareProScanner\Security\EmergencyContainmentManager;
use WebCareProScanner\SupplyChain\UpdateGatekeeperEngine;
use WebCareProScanner\System\SettingsManager;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * AlwaysOnCoreGuard
 *
 * Mandatory Always-On Perimeter Firewall Evaluator.
 * Encapsulates fail-safe checks, environment pre-flight, deduplicated IP blocklist/allowlist,
 * custom modular firewall rules, emergency containment/upgrade lock, protocol & buffer armor,
 * 404 lockouts, Threat Intel IP reputation, and verified virtual patches.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
final class AlwaysOnCoreGuard implements WafEvaluatorInterface {

    public function get_module_id(): string {
        return 'always-on-core-guard';
    }

    public function is_required(): bool {
        return true;
    }

    public function get_route_classes(): array {
        return RouteClass::cases();
    }

    public function get_required_capabilities(): array {
        return [];
    }

    public function get_failure_policy(): EvaluatorFailurePolicy {
        return EvaluatorFailurePolicy::FailClosedRoute;
    }

    public function compile_preload_ast(): array {
        return [
            'id'        => 'WAF-ALWAYS-ON-CORE-GUARD',
            'category'  => 'Core Perimeter Defense',
            'evaluator' => self::class,
        ];
    }

    public function evaluate_runtime_request(RequestContext $ctx): ?WafVerdict {
        // 1. Fail-Safe & Environment Pre-Check
        if ((defined('WEBCAREPROSCAN_DISABLE_WAF') && WEBCAREPROSCAN_DISABLE_WAF)
            || (defined('WEBCAREPROSCAN_DISABLE_FIREWALL') && WEBCAREPROSCAN_DISABLE_FIREWALL)
            || (defined('WEBCARE_CAF_DISABLE_PRELOAD') && WEBCARE_CAF_DISABLE_PRELOAD)
        ) {
            return WafVerdict::allow();
        }

        // CAF Killswitch check
        $upload_dir = function_exists('wp_upload_dir') ? wp_upload_dir() : [];
        if (!empty($upload_dir['basedir'])) {
            $uploads_base = rtrim($upload_dir['basedir'], '/\\');
            if (file_exists($uploads_base . '/webcare-pro-security/.killswitch') || file_exists($uploads_base . '/webcare-vault/.killswitch')) {
                return WafVerdict::allow();
            }
        }

        // Skip CLI execution (unless running in synthetic test runner)
        if (php_sapi_name() === 'cli' || (defined('WP_CLI') && WP_CLI)) {
            if (!\WebCareProScanner\Firewall\DeclarativePatchVerifier::is_test_context()) {
                return WafVerdict::allow();
            }
        }

        // Internal DOING_CRON pre-check: skip unless this is an external HTTP trigger to wp-cron.php
        if (defined('DOING_CRON') && DOING_CRON) {
            $clean_cron_check = strtolower(wp_parse_url($ctx->uri, PHP_URL_PATH) ?: $ctx->uri);
            if (!str_contains($clean_cron_check, 'wp-cron.php')) {
                return WafVerdict::allow();
            }
        }

        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_enabled']) || ($settings['waf_mode'] ?? 'enabled') === 'disabled') {
            return WafVerdict::allow();
        }

        $client_ip = $ctx->ip;
        $request_uri = $ctx->uri;
        $method = $ctx->method;

        // 2. Single Deduplicated IP Blocklist + Allowlist Check
        // Tiered Context-Aware IP Whitelist Check
        $whitelist_ctx = AllowlistManager::check_ip_whitelist_context($client_ip, $settings);
        if ($whitelist_ctx['is_whitelisted'] && $whitelist_ctx['full_bypass']) {
            return WafVerdict::allow();
        }

        // Temporary 15-minute customer unblock pass (exempts IP blocklist & rate-limit blocks only)
        $is_temp_unblocked = (bool) get_transient('webcareproscan_temp_allow_' . md5($client_ip));

        // URL allowlists / support URL safe-pass / targeted allowlist rules
        $url_whitelisted = false;
        if (!empty($settings['waf_whitelisted_urls']) && AllowlistManager::is_url_whitelisted($request_uri, (string) $settings['waf_whitelisted_urls'])) {
            $url_whitelisted = true;
        }

        if (!$url_whitelisted && !empty($settings['waf_contact_support_url'])) {
            if (AllowlistManager::is_configured_support_path($request_uri, (string) $settings['waf_contact_support_url'])) {
                $url_whitelisted = true;
            }
        }

        $targeted_rules_raw = $settings['waf_targeted_allowlist_rules'] ?? '[]';
        $targeted_rules = is_array($targeted_rules_raw) ? $targeted_rules_raw : json_decode((string) $targeted_rules_raw, true);
        if (!$url_whitelisted && !empty($targeted_rules) && is_array($targeted_rules)) {
            $ua = $ctx->userAgent;
            $matched_rule = AllowlistManager::match_targeted_allowlist_rule($request_uri, $ua, $client_ip, $method, $targeted_rules);
            if ($matched_rule !== null) {
                if (class_exists(FirewallEngine::class)) {
                    FirewallEngine::log_targeted_allowlist_hit($matched_rule, $client_ip, $request_uri, $ua, $method);
                }
                $url_whitelisted = true;
            }
        }

        // Fast-path: Check custom user IP blocklist
        if (!empty($settings['waf_blocked_ips'])) {
            $matching_entry = BlocklistRepository::get_matching_blocked_entry($client_ip, $settings['waf_blocked_ips']);
            if ($matching_entry !== null) {
                // Immunity check: Ensure legitimate search engine crawlers are automatically pardoned
                $ua = $ctx->userAgent;
                $is_legit_crawler = class_exists(BotReconDefense::class) && BotReconDefense::is_genuine_search_engine($client_ip, $ua);

                if ($is_legit_crawler) {
                    BlocklistRepository::remove_blocked_ip($matching_entry);
                    BlocklistRepository::remove_blocked_ip($client_ip);
                } else {
                    $block_meta = FirewallEngine::get_ip_block_meta($matching_entry) ?: FirewallEngine::get_ip_block_meta($client_ip);
                    $expires_at = !empty($block_meta['expires_at']) ? (int) $block_meta['expires_at'] : 0;

                    // Auto-heal expired temporary ban
                    if ($expires_at > 0 && time() >= $expires_at) {
                        BlocklistRepository::remove_blocked_ip($matching_entry);
                        BlocklistRepository::remove_blocked_ip($client_ip);
                        $matching_entry = null;
                    }

                    if ($matching_entry !== null) {
                        $ban_reason = !empty($block_meta['reason']) ? trim((string) $block_meta['reason']) : '';
                        $ban_source = !empty($block_meta['source']) ? trim((string) $block_meta['source']) : 'custom_blocklist';
                        $ban_rule   = !empty($block_meta['rule_name']) ? trim((string) $block_meta['rule_name']) : '';

                        $is_manual_admin_ban = ($ban_source === 'manual_admin') || (!empty($block_meta['admin_user']));
                        $ban_rule_id = strtoupper((string) ($block_meta['rule_id'] ?? ''));
                        // Strictly operational/rate-limiting/crawler bans (Never includes exploits like XSS, AI killchains, or prompt injections)
                        $is_non_exploit_operational_ban = !$is_manual_admin_ban && (
                            str_contains($ban_rule_id, '404')
                            || str_contains($ban_rule_id, 'RATE-LIMIT')
                            || str_contains($ban_rule_id, 'SCRAPING')
                            || str_contains($ban_rule_id, 'BURST')
                            || str_contains($ban_rule_id, 'THREAT-SCORE')
                            || str_contains($ban_rule_id, 'BOT-')
                            || str_contains($ban_rule_id, 'HONEYTOKEN')
                            || str_contains($ban_rule_id, 'FORBIDDEN-USERNAME')
                        );

                        $is_verified_human_session = CommerceSessionGuard::is_exempt_from_operational_ban();
                        $is_auth_admin = FirewallEngine::is_authenticated_administrator();

                        if ($is_auth_admin) {
                            $matching_entry = null;
                        } elseif ($is_temp_unblocked && $is_non_exploit_operational_ban) {
                            // Temporary 15-minute unblock pass: exempt strictly from operational bans (never manual admin or exploit bans)
                            $matching_entry = null;
                        } elseif ($is_non_exploit_operational_ban && $is_verified_human_session) {
                            // Verified shopper/member operational-ban exemption
                            $matching_entry = null;
                        }

                        if ($matching_entry !== null) {
                            $description = 'Connection blocked by administrator-defined custom IP rule.';
                            if (!empty($ban_reason)) {
                                $description = sprintf('Connection blocked: %s', $ban_reason);
                            } elseif (!empty($ban_rule)) {
                                $description = sprintf('Connection blocked by automated rule: %s', $ban_rule);
                            }

                            return new WafVerdict(
                                'block',
                                'USER-CUSTOM-IP-BLOCK',
                                $description,
                                [
                                    'category'       => 'Custom IP Blocklist',
                                    'status_code'    => 403,
                                    'matching_entry' => $matching_entry,
                                    'ban_reason'     => $ban_reason,
                                    'ban_source'     => $ban_source,
                                    'expires_at'     => $expires_at,
                                ]
                            );
                        }
                    }
                }
            }
        }

        // Two-Tier Privilege & Builder session inspection
        $is_admin_operation = false;
        $is_builder_operation = false;
        $is_drill_request = !empty($ctx->queryParams['webcare_drill_token'])
            || !empty($ctx->formParams['webcare_drill_token'])
            || !empty($ctx->headers['x-webcare-drill-token'])
            || !empty($ctx->server['HTTP_X_WEBCARE_DRILL_TOKEN']);

        if (!$is_drill_request) {
            if (FirewallEngine::is_authenticated_administrator()) {
                $is_admin_operation = (function_exists('is_admin') && is_admin())
                    || str_contains($request_uri, '/wp-admin/')
                    || str_contains($request_uri, '/wp-json/webcare-pro-security/');
            } elseif (FirewallEngine::is_verified_editor_builder_request($request_uri) || FirewallEngine::is_authenticated_editor_or_builder()) {
                $is_builder_operation = true;
            }
        }

        $custom_allow_matched = false;
        // 3. Custom / Visual Firewall Rules
        if (class_exists(ModularFirewallSynthesizer::class)) {
            $modular_violation = ModularFirewallSynthesizer::evaluate_runtime_modular_rules();
            if ($modular_violation !== null) {
                $mod_action = (string) ($modular_violation['action_type'] ?? '');
                if ($mod_action === 'allow') {
                    $custom_allow_matched = true;
                } elseif ($mod_action === 'challenge_pow' && !empty($modular_violation['blocked']) && class_exists(BotReconDefense::class)) {
                    $ua_raw = $ctx->userAgent;
                    if (!BotReconDefense::has_valid_clearance_cookie($client_ip, $ua_raw)) {
                        return new WafVerdict(
                            'challenge_pow',
                            (string) ($modular_violation['rule_id'] ?? 'WAF-MODULAR-POW'),
                            (string) ($modular_violation['reason'] ?? 'Custom Firewall Rule PoW Challenge'),
                            [
                                'category' => 'Modular Behavioral WAF',
                            ]
                        );
                    }
                } elseif (!empty($modular_violation['blocked'])) {
                    $http_code = ($mod_action === 'rate_limit') ? 429 : 403;
                    return new WafVerdict(
                        $mod_action === 'rate_limit' ? 'rate_limit' : 'block',
                        (string) ($modular_violation['rule_id'] ?? 'WAF-MODULAR-BLOCK'),
                        (string) ($modular_violation['reason'] ?? 'Modular Intelligence Firewall Rule Violation'),
                        [
                            'category'        => !empty($modular_violation['category']) && $modular_violation['category'] === 'custom' ? 'Custom Modular Rule' : 'Modular Behavioral WAF',
                            'status_code'     => $http_code,
                            'sync_cloudflare' => !empty($modular_violation['sync_cloudflare']),
                            'ban_ttl'         => (int) ($modular_violation['ban_ttl'] ?? 0),
                        ]
                    );
                } else {
                    FirewallEngine::log_incident([
                        'id'          => $modular_violation['rule_id'],
                        'name'        => $modular_violation['title'] ?? 'Modular Intelligence Firewall Rule',
                        'category'    => 'Modular Behavioral WAF',
                        'description' => $modular_violation['reason'],
                        'match_type'  => $modular_violation['category'] ?? 'custom',
                        'match_value' => $modular_violation['rule_id'],
                        'payload'     => "Client IP: {$client_ip} URI: {$request_uri}",
                    ], 'detected');
                }
            }
            if (ModularFirewallSynthesizer::did_custom_allow_match()) {
                $custom_allow_matched = true;
            }
        }

        $skip_operational_heuristics = ($url_whitelisted || $custom_allow_matched || $is_admin_operation || $is_builder_operation || $is_temp_unblocked);

        // 4. Emergency Containment Mode & Atomic Upgrade Lock
        if (class_exists(EmergencyContainmentManager::class) && EmergencyContainmentManager::is_active()) {
            if (!FirewallEngine::is_authenticated_administrator()) {
                if (EmergencyContainmentManager::is_maintenance_enabled()) {
                    EmergencyContainmentManager::render_containment_screen();
                    exit;
                }

                $req_method = strtoupper($method);
                if (in_array($req_method, ['POST', 'PUT', 'DELETE', 'PATCH'], true)) {
                    return new WafVerdict(
                        'block',
                        'WAF-CONTAINMENT-LOCKDOWN',
                        'Write operations are strictly prohibited while site is in Emergency Containment Mode.',
                        [
                            'category'    => 'Incident Containment',
                            'status_code' => 403,
                        ]
                    );
                }

                if (str_contains($request_uri, 'xmlrpc.php') || str_contains($request_uri, '/wp/v2/users')) {
                    return new WafVerdict(
                        'block',
                        'WAF-CONTAINMENT-SURFACE-LOCK',
                        'Endpoint locked down by Emergency Containment Mode.',
                        [
                            'category'    => 'Incident Containment',
                            'status_code' => 403,
                        ]
                    );
                }
            }
        }

        if (class_exists(UpdateGatekeeperEngine::class)) {
            $active_lock = UpdateGatekeeperEngine::get_active_lock();
            if ($active_lock !== null) {
                $is_admin = FirewallEngine::is_authenticated_administrator();
                $lock_ip = (string) ($active_lock['ip'] ?? '');
                if (!$is_admin && !hash_equals($lock_ip, $client_ip)) {
                    $decoded_uri = rawurldecode($request_uri);
                    if (preg_match('#(?:/wp-admin/(?:upgrade|maint/repair)\.php|/wp-content/(?:plugins|themes|upgrade)/)#i', $decoded_uri)) {
                        return new WafVerdict(
                            'block',
                            'WAF-ATOMIC-UPGRADE-LOCK',
                            'Target resource is locked against unauthenticated access during an active software update.',
                            [
                                'category'    => 'Supply Chain Defense',
                                'status_code' => 423,
                            ]
                        );
                    }
                }
            }
        }

        // 5. Protocol & Request Surface Armor
        $is_builder_session = FirewallEngine::is_authenticated_editor_or_builder();

        // Rule #34: Oversized Request Buffer & DoS Guard
        if (!empty($settings['waf_block_oversized_requests'])) {
            $is_upload_endpoint = (
                str_contains($request_uri, 'async-upload.php') ||
                str_contains($request_uri, 'update.php') ||
                str_contains($request_uri, 'plugin-install.php') ||
                str_contains($request_uri, 'theme-install.php') ||
                str_contains($request_uri, '/wp-json/wp/v2/media')
            );
            $is_admin_area = (function_exists('is_admin') && is_admin()) || str_contains($request_uri, '/wp-admin/');
            $is_commerce_safe = !empty($settings['waf_ecommerce_safe_mode']) && CommerceSessionGuard::is_commerce_or_membership_request($request_uri);
            $is_exempt_endpoint = $is_upload_endpoint || $is_admin_area || $is_builder_session;

            $uri_length = strlen($request_uri);
            $raw_query = (string) ($ctx->server['QUERY_STRING'] ?? '');
            $query_length = strlen($raw_query);
            $post_count = !empty($ctx->formParams) ? count($ctx->formParams, COUNT_RECURSIVE) : 0;

            $max_uri_limit = ($is_commerce_safe || $is_admin_area) ? 8192 : 4096;
            if ($uri_length > $max_uri_limit && !$is_exempt_endpoint) {
                return new WafVerdict(
                    'block',
                    'WAF-OVERSIZED-URI',
                    sprintf('Request URI length of %d bytes exceeded security threshold (%d bytes).', $uri_length, $max_uri_limit),
                    [
                        'category'    => 'DoS & Resource Shield',
                        'status_code' => 414,
                    ]
                );
            }

            $max_query_limit = ($is_commerce_safe || $is_admin_area) ? 4096 : 2048;
            if ($query_length > $max_query_limit && !$is_exempt_endpoint) {
                return new WafVerdict(
                    'block',
                    'WAF-OVERSIZED-QUERY',
                    sprintf('Query string length of %d bytes exceeded security threshold (%d bytes).', $query_length, $max_query_limit),
                    [
                        'category'    => 'DoS & Resource Shield',
                        'status_code' => 403,
                    ]
                );
            }

            $is_param_exempt = $is_upload_endpoint || $is_builder_session;
            if ($post_count > 1000 && !$is_param_exempt) {
                return new WafVerdict(
                    'block',
                    'WAF-OVERSIZED-POST-VARS',
                    sprintf('POST payload contains %d recursive variables, exceeding security threshold (1000).', $post_count),
                    [
                        'category'    => 'DoS & Resource Shield',
                        'status_code' => 400,
                    ]
                );
            }
        }

        // Rule #32: Strict Host Header Allowlist Guard
        if (!empty($settings['waf_enforce_host_allowlist'])) {
            $is_valid_host = self::validate_host_headers_from_context($ctx, $settings);
            if (!$is_valid_host) {
                $presented_host = $ctx->headers['host'] ?? ($ctx->server['HTTP_HOST'] ?? 'unknown');
                $forwarded_host = $ctx->headers['x-forwarded-host'] ?? ($ctx->server['HTTP_X_FORWARDED_HOST'] ?? '');
                $msg = self::translatable_string(
                    sprintf('HTTP Host ("%s") or X-Forwarded-Host ("%s") does not match configured site domain allowlist.', esc_html($presented_host), esc_html($forwarded_host))
                );
                return new WafVerdict(
                    'block',
                    'WAF-HOST-HEADER-POISON',
                    $msg,
                    [
                        'category'    => 'Protocol Defense',
                        'status_code' => 403,
                    ]
                );
            }
        }

        // Check HTTP Request Method Whitelist / Block Unsafe Methods (TRACE, TRACK, CONNECT, DEBUG)
        if (!empty($settings['waf_block_unsafe_http_methods'])) {
            $http_method = strtoupper($method);
            $unsafe_methods = ['TRACE', 'TRACK', 'CONNECT', 'DEBUG'];
            if (in_array($http_method, $unsafe_methods, true)) {
                return new WafVerdict(
                    'block',
                    'WAF-UNSAFE-HTTP-METHOD',
                    sprintf('HTTP %s request blocked by administrator firewall policy.', $http_method),
                    [
                        'category'    => 'Protocol Defense',
                        'status_code' => 405,
                    ]
                );
            }
        }

        // HTTP PUT / Arbitrary Webshell Upload Hardening
        $raw_method = strtoupper($method);
        if ($raw_method === 'PUT') {
            $is_rest_put = (defined('REST_REQUEST') && REST_REQUEST) || str_contains($request_uri, '/wp-json/') || str_contains($request_uri, 'rest_route=');
            if (!$is_rest_put && !FirewallEngine::is_authenticated_administrator() && !FirewallEngine::is_authenticated_editor_or_builder()) {
                $desc = self::translatable_string(
                    sprintf('Unauthenticated HTTP PUT request rejected on non-REST endpoint "%s" to prevent arbitrary webshell upload.', esc_html($request_uri))
                );
                return new WafVerdict(
                    'block',
                    'WAF-UNAUTHORIZED-PUT-UPLOAD',
                    $desc,
                    [
                        'category'    => 'Protocol Defense',
                        'status_code' => 405,
                    ]
                );
            }
        }

        // Smart Rule #48: HTTP Method Override & REST Route Smuggling Guard
        $override_method = $ctx->formParams['_method']
            ?? $ctx->queryParams['_method']
            ?? $ctx->params['_method']
            ?? $ctx->headers['x-http-method-override']
            ?? $ctx->headers['x-method-override']
            ?? ($ctx->server['HTTP_X_HTTP_METHOD_OVERRIDE'] ?? '');

        if (!empty($override_method)) {
            $override_clean = strtoupper(is_string($override_method) ? sanitize_text_field(wp_unslash($override_method)) : 'ARRAY');
            if (in_array($override_clean, ['PUT', 'DELETE', 'PATCH', 'TRACE', 'CONNECT', 'ARRAY'], true)) {
                $is_logged_in = (function_exists('is_user_logged_in') && is_user_logged_in())
                    || FirewallEngine::is_authenticated_administrator()
                    || FirewallEngine::is_authenticated_editor_or_builder();
                if (!$is_logged_in) {
                    $desc = self::translatable_string(
                        sprintf('Unauthenticated client attempted to smuggle privileged HTTP method (%s) via override parameter/header.', esc_html($override_clean))
                    );
                    return new WafVerdict(
                        'block',
                        'WAF-REST-METHOD-SMUGGLE',
                        $desc,
                        [
                            'category'    => 'Execution Armor',
                            'status_code' => 403,
                        ]
                    );
                }
            }
        }

        // Rule 18 / Smart Rule #53: Sensitive Log, .env.* & Byte-Range Exfiltration Instant Ban
        if (!empty($settings['waf_block_sensitive_file_probes'])) {
            $sensitive_violation = ExploitSignatureEngine::check_sensitive_file_probe($request_uri, $settings, $skip_operational_heuristics);
            if ($sensitive_violation !== null) {
                return new WafVerdict(
                    'block',
                    (string) ($sensitive_violation['id'] ?? 'WAF-SENSITIVE-FILE-PROBE'),
                    (string) ($sensitive_violation['description'] ?? 'Sensitive file access probe blocked.'),
                    [
                        'category'    => (string) ($sensitive_violation['category'] ?? 'Information Disclosure'),
                        'status_code' => 403,
                    ]
                );
            }
        }

        // Rule 19: Direct Execution Deny for wp-content/uploads/ PHP Scripts
        if (!empty($settings['waf_block_uploads_php_exec'])) {
            $clean_path = strtolower(wp_parse_url($request_uri, PHP_URL_PATH) ?: $request_uri);
            if (preg_match('/\/wp-content\/uploads\/.*\.php([0-9]|s|tml)?(\/|\?|$)/i', $clean_path) || preg_match('/\/wp-content\/uploads\/.*\.php([0-9]|s|tml)?/i', $request_uri)) {
                return new WafVerdict(
                    'block',
                    'WAF-UPLOADS-PHP-DENY',
                    'Direct execution request to PHP script inside media uploads folder was blocked.',
                    [
                        'category'    => 'Execution Armor',
                        'status_code' => 403,
                    ]
                );
            }
        }

        // Rule 20: External wp-cron.php Abuse & Flooding Blocker
        if (!empty($settings['waf_block_external_cron'])) {
            $clean_path = strtolower(wp_parse_url($request_uri, PHP_URL_PATH) ?: $request_uri);
            if (str_contains($clean_path, 'wp-cron.php')) {
                $is_loopback = FirewallEngine::is_server_origin_or_loopback($client_ip);
                $is_admin = FirewallEngine::is_authenticated_administrator();
                $is_whitelisted = AllowlistManager::is_ip_whitelisted($client_ip, $settings['waf_whitelisted_ips'] ?? '');

                if (!$is_loopback && !$is_admin && !$is_whitelisted) {
                    return new WafVerdict(
                        'block',
                        'WAF-EXTERNAL-CRON-BLOCK',
                        'Direct external HTTP trigger to wp-cron.php rejected to prevent resource starvation.',
                        [
                            'category'    => 'DoS & Resource Shield',
                            'status_code' => 403,
                        ]
                    );
                }
            }
        }

        // Rule 23: Lockdown install.php & upgrade.php on Already Installed Sites
        if (!empty($settings['waf_block_install_php'])) {
            $clean_path = strtolower(wp_parse_url($request_uri, PHP_URL_PATH) ?: $request_uri);
            if (str_contains($clean_path, 'wp-admin/install.php') || str_contains($clean_path, 'wp-admin/upgrade.php')) {
                if (function_exists('is_blog_installed') && is_blog_installed()) {
                    $is_admin = FirewallEngine::is_authenticated_administrator();
                    if (!$is_admin) {
                        return new WafVerdict(
                            'block',
                            'WAF-INSTALL-LOCKDOWN',
                            'Public access to WordPress install.php/upgrade.php blocked on already established site.',
                            [
                                'category'    => 'Hardening Defense',
                                'status_code' => 403,
                            ]
                        );
                    }
                }
            }
        }

        // 6. 404 Lockout, Threat Intel Blacklist & Verified Virtual Patches
        $lockout_transient = 'webcareproscan_404_lock_' . md5($client_ip);
        $lockout_data = get_transient($lockout_transient);
        if (!$skip_operational_heuristics && !$is_temp_unblocked && $lockout_data !== false) {
            return new WafVerdict(
                'block',
                'RATE-LIMIT-404-LOCKOUT',
                sprintf(
                    'Temporary lockout enforced: IP generated excessive 404 errors (%d probes in %ds). Locked out for %d minutes.',
                    (int) ($lockout_data['count'] ?? 10),
                    (int) ($lockout_data['window'] ?? 60),
                    (int) ($lockout_data['duration'] ?? 30)
                ),
                [
                    'category'    => '404 Scanner Rate Limit',
                    'status_code' => 403,
                ]
            );
        }

        // Check Cloud Threat Intelligence Botnet / Malicious IP Blacklist (Degrades safely on external network/API failure)
        if (!empty($settings['threat_intel_enabled']) && !empty($settings['threat_intel_block_blacklisted_ips'])) {
            try {
                if (class_exists(ThreatIntelService::class) && ThreatIntelService::is_ip_blacklisted($client_ip)) {
                    return new WafVerdict(
                        'block',
                        'THREAT-INTEL-BOTNET',
                        'Connection blocked by Global Botnet / Malicious IP Blacklist reputation.',
                        [
                            'category'    => 'Threat Intelligence',
                            'status_code' => 403,
                        ]
                    );
                }
            } catch (\Throwable $ti_err) {
                if (class_exists(FirewallEngine::class)) {
                    FirewallEngine::log_incident([
                        'id'          => 'WAF-THREAT-INTEL-DEGRADED',
                        'name'        => 'Threat Intel Lookup Degraded',
                        'category'    => 'System Integrity',
                        'description' => 'Optional Threat Intelligence lookup failed; degraded safely without aborting request: ' . $ti_err->getMessage(),
                        'match_type'  => 'Degraded Log',
                        'match_value' => $client_ip,
                        'payload'     => $ti_err->getFile() . ':' . $ti_err->getLine(),
                    ], 'detected');
                }
            }
        }

        // Check Active Virtual Patches (Tier 1: In-Memory WAF Lite Shield)
        if (class_exists(VirtualPatchManager::class)) {
            $vpatch_rule = VirtualPatchManager::evaluate_request($client_ip, $request_uri);
            if ($vpatch_rule !== null) {
                if (class_exists(ThreatIntelNetwork::class)) {
                    ThreatIntelNetwork::record_consensus_beacon($client_ip, $vpatch_rule['name'] ?? 'Virtual Patch Violation', ['category' => 'Virtual Patch']);
                }

                $action_raw = (string) ($vpatch_rule['action'] ?? 'block');
                $status_code = (int) ($vpatch_rule['status_code'] ?? ($action_raw === 'rate_limit' ? 429 : 403));
                $waf_action = match ($action_raw) {
                    'challenge_pow', 'challenge' => WafAction::Challenge,
                    'rate_limit'                 => WafAction::RateLimit,
                    'log_only', 'log'            => WafAction::LogOnly,
                    default                      => WafAction::Block,
                };

                return new WafVerdict(
                    $waf_action,
                    (string) ($vpatch_rule['id'] ?? 'VPATCH-VIOLATION'),
                    (string) ($vpatch_rule['description'] ?? 'Virtual patch violation detected.'),
                    [
                        'category'    => (string) ($vpatch_rule['category'] ?? 'Virtual Patch (CVE Shield)'),
                        'status_code' => $status_code,
                    ]
                );
            }
        }

        return null;
    }

    /**
     * Helper to safely format translatable strings without warnings prior to init.
     */
    private static function translatable_string(string $fallback_str): string {
        return $fallback_str;
    }

    /**
     * Strict Host & Forwarded Host Header Allowlist Validator from RequestContext.
     */
    private static function validate_host_headers_from_context(RequestContext $ctx, array $settings): bool {
        $raw_host = $ctx->headers['host'] ?? ($ctx->server['HTTP_HOST'] ?? '');
        if (empty($raw_host)) {
            return false;
        }

        $clean_host = strtolower(trim(preg_replace('/:\d+$/', '', $raw_host)));

        $allowed = [];
        if (function_exists('site_url')) {
            $site_host = wp_parse_url(site_url(), PHP_URL_HOST);
            if ($site_host) {
                $allowed[] = strtolower($site_host);
            }
        }
        if (function_exists('home_url')) {
            $home_host = wp_parse_url(home_url(), PHP_URL_HOST);
            if ($home_host) {
                $allowed[] = strtolower($home_host);
            }
        }

        foreach ($allowed as $h) {
            if ($h) {
                if (str_starts_with($h, 'www.')) {
                    $allowed[] = substr($h, 4);
                } else {
                    $allowed[] = 'www.' . $h;
                }
            }
        }

        $custom_aliases = $settings['waf_allowed_host_aliases'] ?? '';
        if (!empty($custom_aliases)) {
            $lines = preg_split('/[\r\n,]+/', $custom_aliases);
            if (is_array($lines)) {
                foreach ($lines as $line) {
                    $alias = strtolower(trim($line));
                    if ($alias !== '') {
                        $alias = preg_replace('/:\d+$/', '', $alias);
                        $allowed[] = $alias;
                    }
                }
            }
        }

        $allowed = array_unique(array_filter($allowed));
        if (!in_array($clean_host, $allowed, true)) {
            return false;
        }

        $fwd_host_raw = $ctx->headers['x-forwarded-host'] ?? ($ctx->server['HTTP_X_FORWARDED_HOST'] ?? '');
        if (!empty($fwd_host_raw)) {
            $fwd_raw = explode(',', sanitize_text_field(wp_unslash($fwd_host_raw)));
            foreach ($fwd_raw as $raw_seg) {
                $fwd_host = strtolower(trim(preg_replace('/:\d+$/', '', $raw_seg)));
                if ($fwd_host === '' || str_contains($fwd_host, '@') || !in_array($fwd_host, $allowed, true)) {
                    return false;
                }
            }
        }

        return true;
    }
}
