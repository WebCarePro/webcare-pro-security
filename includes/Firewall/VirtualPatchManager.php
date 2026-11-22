<?php
namespace WebCareProScanner\Firewall;

use WebCareProScanner\System\SettingsManager;
use WebCareProScanner\System\AuditLogger;
use WebCareProScanner\Cloudflare\CloudflareService;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * VirtualPatchManager
 *
 * Automated Two-Tier Virtual Patching Engine (WAF Lite + Cloudflare Free Edge Rules):
 * - Intercepts and shields unpatched CVEs and zero-days before official vendor releases or updates can be applied.
 * - Tier 1: Local PHP WAF Lite Virtual Patch (<0.5ms in-memory inspection at plugins_loaded:0).
 * - Tier 2: Cloudflare Global Edge Custom WAF Expression (blocks exploit at edge before reaching server/PHP).
 * - 1-Click "Protect Now via Virtual Patch" action across vulnerabilities and scan issues.
 *
 * Author: Mir Alamin (WebCare Pro)
 * Senior Linux SysAdmin & WordPress Security Engineer
 */
class VirtualPatchManager {

    const OPTION_PATCHES = 'webcareproscan_virtual_patches';
    const CF_TAG = '[WebCare Virtual Patch]';

    /**
     * Get Curated Catalog of Pre-Built Virtual Patches for Common & High-Impact WordPress CVEs.
     *
     * @return array
     */
    public static function get_patch_catalog(): array {
        return [
            'CVE-2024-28000' => [
                'patch_id'     => 'CVE-2024-28000',
                'cve_id'       => 'CVE-2024-28000',
                'component'    => 'litespeed-cache',
                'title'        => 'LiteSpeed Cache <= 6.3.0.1 - Unauthenticated Privilege Escalation / Admin Takeover',
                'severity'     => 'critical',
                'description'  => 'Blocks brute-forced or spoofed hash authentication bypass targeting LiteSpeed REST API / admin simulation endpoints.',
                'php_rule'     => [
                    'target_uris' => ['/wp-json/litespeed/', 'action=async_litespeed'],
                    'headers'     => ['X-LSCACHE-VARY'],
                    'regex'       => '/(litespeed_role|litespeed_hash|user_id=1)/i',
                ],
                'cf_expression' => '(http.request.uri.path contains "wp-json/litespeed" or http.request.uri.query contains "async_litespeed") and (http.request.uri.query contains "user_id=1" or any(http.request.headers["x-lscache-vary"][*] contains "role"))',
            ],
            'CVE-2024-31210' => [
                'patch_id'     => 'CVE-2024-31210',
                'cve_id'       => 'CVE-2024-31210',
                'component'    => 'wordpress-core',
                'title'        => 'WordPress Core <= 6.5.2 - Path Traversal & Arbitrary File Deletion',
                'severity'     => 'critical',
                'description'  => 'Neutralizes path traversal attempts with dot-dot-slash sequence targeting media attachment cleanup and file deletion routines.',
                'php_rule'     => [
                    'target_uris' => ['/wp-admin/post.php', '/wp-admin/admin-ajax.php'],
                    'regex'       => '/(\.\.\/|\.\.\\\\|\%2e\%2e|\%252e)/i',
                ],
                'cf_expression' => '(http.request.uri.path contains "wp-admin/post.php" or http.request.uri.path contains "wp-admin/admin-ajax.php") and (http.request.uri.query contains ".." or http.request.body contains "..")',
            ],
            'CVE-2024-5654' => [
                'patch_id'     => 'CVE-2024-5654',
                'cve_id'       => 'CVE-2024-5654',
                'component'    => 'give',
                'title'        => 'GiveWP <= 3.14.1 - Unauthenticated PHP Object Injection & RCE',
                'severity'     => 'critical',
                'description'  => 'Blocks serialized PHP object payload injection through donation forms and donation receipt parameter handles.',
                'php_rule'     => [
                    'target_uris' => ['give_action', 'give-donation'],
                    'regex'       => '/(O:[0-9]+:"[a-zA-Z0-9_]+":|a:[0-9]+:\{|give_title)/i',
                ],
                'cf_expression' => '(http.request.uri.path contains "give" or http.request.uri.query contains "give") and (http.request.body contains "O:" or http.request.uri.query contains "O:")',
            ],
            'CVE-2023-38000' => [
                'patch_id'     => 'CVE-2023-38000',
                'cve_id'       => 'CVE-2023-38000',
                'component'    => 'royal-elementor-addons',
                'title'        => 'Royal Elementor Addons <= 1.3.78 - Unauthenticated Arbitrary File Upload',
                'severity'     => 'critical',
                'description'  => 'Prevents executable file uploads and PHP extensions bypassing file verification checks in Royal Elementor upload handlers.',
                'php_rule'     => [
                    'target_uris' => ['wpr_addons_upload_file', 'royal_elementor'],
                    'regex'       => '/(\.php|\.phtml|\.php5|\.sh|\.cgi)/i',
                ],
                'cf_expression' => '(http.request.uri.query contains "wpr_addons_upload_file" or http.request.body contains "wpr_addons_upload_file") and (http.request.body contains ".php" or http.request.uri.query contains ".php")',
            ],
            'CVE-2023-28121' => [
                'patch_id'     => 'CVE-2023-28121',
                'cve_id'       => 'CVE-2023-28121',
                'component'    => 'woocommerce-payments',
                'title'        => 'WooCommerce Payments <= 5.6.1 - Unauthenticated Admin Privilege Escalation',
                'severity'     => 'critical',
                'description'  => 'Blocks unauthorized user impersonation headers (X-WCPay-Platform-Checkout-User) from arbitrary remote clients.',
                'php_rule'     => [
                    'target_uris' => ['/'],
                    'headers'     => ['X-WCPay-Platform-Checkout-User'],
                    'regex'       => '/[0-9]+/i',
                ],
                'cf_expression' => 'any(http.request.headers["X-WCPay-Platform-Checkout-User"][*] != "")',
            ],
            'VPATCH-FILE-UPLOAD' => [
                'patch_id'     => 'VPATCH-FILE-UPLOAD',
                'cve_id'       => 'GENERIC-UPLOAD',
                'component'    => 'all-plugins',
                'title'        => 'Universal Zero-Day Arbitrary File Upload Shield',
                'severity'     => 'high',
                'description'  => 'Blocks unauthenticated POST requests uploading PHP, shell scripts, or executable code to admin-ajax or rest-api endpoints.',
                'php_rule'     => [
                    'target_uris' => ['/wp-admin/admin-ajax.php', '/wp-json/'],
                    'methods'     => ['POST'],
                    'regex'       => '/(filename=[\'"][^\'"]+\.(php[0-9]?|phtml|sh|bash|cgi|exe)[\'"]|application\/x-php)/i',
                ],
                'cf_expression' => '(http.request.uri.path contains "admin-ajax.php" or http.request.uri.path contains "wp-json") and http.request.method eq "POST" and (http.request.body contains ".php" or http.request.body contains "application/x-php")',
            ],
            'VPATCH-SQLI-DEEP' => [
                'patch_id'     => 'VPATCH-SQLI-DEEP',
                'cve_id'       => 'GENERIC-SQLI',
                'component'    => 'all-plugins',
                'title'        => 'High-Confidence Plugin SQL Injection Shield',
                'severity'     => 'high',
                'description'  => 'Blocks UNION SELECT, Boolean-based sleep(), and benchmark() injection payloads targeting plugin custom query parameters.',
                'php_rule'     => [
                    'target_uris' => ['/'],
                    'regex'       => '/(union\s+all\s+select|select\s+sleep\s*\(|waitfor\s+delay\s+|extractvalue\s*\(|updatexml\s*\()/i',
                ],
                'cf_expression' => 'http.request.uri.query contains "union select" or http.request.uri.query contains "sleep(" or http.request.body contains "union select"',
            ],
        ];
    }

    /**
     * Get All Active Virtual Patches.
     *
     * @return array
     */
    public static function get_active_patches(): array {
        $patches = get_option(self::OPTION_PATCHES, []);
        if (!is_array($patches)) {
            $patches = [];
        }

        // Merge active synthesized virtual hotpatches
        $synthesized = get_option(VirtualPatchSynthesizer::OPTION_SYNTHESIZED_PATCHES, []);
        if (is_array($synthesized) && !empty($synthesized)) {
            foreach ($synthesized as $s_id => $s_patch) {
                if (!empty($s_patch['enabled'])) {
                    $patches[$s_id] = $s_patch;
                }
            }
        }

        return $patches;
    }

    /**
     * Apply a Virtual Patch (Tier 1: PHP WAF Lite + Tier 2: Cloudflare Free Edge).
     * Enforces DeclarativePatchVerifier cryptographic signature and manifest check on all declarative patches.
     *
     * @param string $patch_id
     * @param array $custom_config
     * @return array
     */
    public static function apply_patch(string $patch_id, array $custom_config = []): array {
        // If applying an incoming declarative patch manifest (has signature/schema_version)
        $is_declarative_manifest = !empty($custom_config['schema_version']) || !empty($custom_config['signature']);

        if ($is_declarative_manifest) {
            $checkpoint = class_exists('\\WebCareProScanner\\Firewall\\CentralThreatControlPlane')
                ? CentralThreatControlPlane::get_checkpoint()
                : ['sequence' => 0];
            $min_seq = (int) ($checkpoint['sequence'] ?? 0);

            $verify_res = DeclarativePatchVerifier::verify_patch_manifest($custom_config, $min_seq);
            if (!$verify_res['valid']) {
                AuditLogger::log_event(
                    'VPATCH_REJECTED',
                    sprintf('Declarative patch %s rejected: %s', $patch_id, (string) $verify_res['error'])
                );
                return [
                    'success' => false,
                    /* translators: %s: Error message detail */
                    'message' => sprintf(__('Virtual patch validation failed: %s', 'webcare-pro-security'), (string) $verify_res['error']),
                ];
            }

            $patch = $verify_res['patch'];
            $settings = SettingsManager::get_settings();
            $owner_opt_in = !empty($settings['waf_auto_enforce_virtual_patches']);
            // If owner has NOT opted into auto-enforcement, force stage to SHADOW (preserving STAGE_REVOKED)
            if (!$owner_opt_in && ($patch['stage'] ?? '') !== DeclarativePatchVerifier::STAGE_REVOKED) {
                $patch['stage'] = DeclarativePatchVerifier::STAGE_SHADOW;
            } else {
                $declared_stage = (string) ($patch['stage'] ?? '');
                if ($declared_stage !== '') {
                    $patch['stage'] = $declared_stage;
                } else {
                    $patch['stage'] = DeclarativePatchVerifier::determine_initial_stage($patch, $owner_opt_in);
                }
            }
        } else {
            $catalog = self::get_patch_catalog();
            $patch = $catalog[$patch_id] ?? null;

            if (!$patch && !empty($custom_config['title'])) {
                // Remote/central custom patch without declarative signature must be rejected
                if (!empty($custom_config['is_remote'])) {
                    return [
                        'success' => false,
                        'message' => __('Unsigned remote virtual patches are prohibited. A valid Ed25519 signature is required.', 'webcare-pro-security'),
                    ];
                }

                $patch = [
                    'patch_id'      => $patch_id,
                    'cve_id'        => $custom_config['cve_id'] ?? $patch_id,
                    'component'     => $custom_config['component'] ?? 'custom',
                    'title'         => $custom_config['title'],
                    'severity'      => $custom_config['severity'] ?? 'high',
                    'description'   => $custom_config['description'] ?? 'Custom Virtual Patch shield deployed via WebCare.',
                    'php_rule'      => $custom_config['php_rule'] ?? ['target_uris' => ['/'], 'regex' => '/\.\.\//i'],
                    'cf_expression' => $custom_config['cf_expression'] ?? '',
                    'stage'         => $custom_config['stage'] ?? DeclarativePatchVerifier::STAGE_ACTIVE,
                    'action'        => $custom_config['action'] ?? 'block',
                ];
            }
        }

        if (!$patch) {
            /* translators: %s: patch ID */
            return ['success' => false, 'message' => sprintf(__('Unknown patch template: %s', 'webcare-pro-security'), $patch_id)];
        }

        $active = self::get_active_patches();
        $is_update = isset($active[$patch_id]);

        $patch['enabled'] = true;
        $patch['hits'] = $is_update ? ($active[$patch_id]['hits'] ?? 0) : 0;
        $patch['applied_at'] = current_time('mysql');
        $patch['deployed_to_cloudflare'] = false;
        $patch['cloudflare_rule_id'] = null;

        // Build & persist the post-update patch collection FIRST before Cloudflare reconciliation
        $active[$patch_id] = $patch;
        update_option(self::OPTION_PATCHES, $active, false);

        // Tier 2: Deploy to Cloudflare Global Edge if Cloudflare is configured
        $cf_deployed = false;
        $cf_msg = '';

        $patch_stage = (string) ($patch['stage'] ?? DeclarativePatchVerifier::STAGE_ACTIVE);
        $patch_action = strtolower((string) ($patch['action'] ?? 'block'));

        // Always reconcile Cloudflare edge rules with the full post-update patch collection
        $cf_res = self::deploy_to_cloudflare_edge($patch);
        if ($cf_res['success']) {
            $included_ids = (array) ($cf_res['included_patch_ids'] ?? []);
            $is_included = in_array($patch_id, $included_ids, true);

            if ($patch_stage === DeclarativePatchVerifier::STAGE_ACTIVE && $patch_action === 'block' && !empty($patch['cf_expression']) && $is_included) {
                $patch['deployed_to_cloudflare'] = true;
                $patch['cloudflare_rule_id'] = $cf_res['rule_id'] ?? null;
                $cf_deployed = true;
                $cf_msg = __(' (Active on Cloudflare Global Edge + PHP WAF Lite)', 'webcare-pro-security');
                $active[$patch_id] = $patch;
                update_option(self::OPTION_PATCHES, $active, false);
            } else {
                /* translators: 1: Virtual patch rollout stage, 2: Virtual patch action */
                $cf_msg = ' (' . sprintf(__('Local PHP WAF Lite [%1$s/%2$s]; Cloudflare Edge: Non-blocking, non-active, or omitted from Edge budget', 'webcare-pro-security'), $patch_stage, $patch_action) . ')';
            }
        } else {
            $cf_msg = ' (' . __('Local PHP WAF Lite Active; Cloudflare Edge: ', 'webcare-pro-security') . ($cf_res['message'] ?? 'Not connected') . ')';
        }

        // Record Audit Log with Rich Details
        if (class_exists('\\WebCareProScanner\\System\\WebCareActivityLogger')) {
            \WebCareProScanner\System\WebCareActivityLogger::notice('virtual_patch_applied', 'firewall', [
                'patch_id'   => $patch_id,
                'title'      => $patch['title'] ?? $patch_id,
                'cve_id'     => $patch['cve_id'] ?? $patch_id,
                'severity'   => $patch['severity'] ?? 'high',
                'target'     => $patch['target'] ?? 'core',
                'cloudflare' => $cf_deployed,
                'diff'       => [
                    $patch_id => [
                        'old' => null,
                        'new' => [
                            'status'     => 'active',
                            'title'      => $patch['title'] ?? $patch_id,
                            'cve_id'     => $patch['cve_id'] ?? $patch_id,
                            'cloudflare' => $cf_deployed,
                        ],
                    ],
                ],
                'description' => sprintf(
                    /* translators: 1: patch title, 2: patch ID, 3: deployment message */
                    __('Activated Virtual Shield "%1$s" (%2$s)%3$s', 'webcare-pro-security'),
                    $patch['title'] ?? $patch_id,
                    $patch_id,
                    $cf_msg
                ),
            ]);
        }

        AuditLogger::log_event(
            'virtual_patch_applied',
            sprintf(
                /* translators: 1: patch title, 2: patch ID, 3: deployment message */
                __('Applied Virtual Patch "%1$s" (%2$s)%3$s', 'webcare-pro-security'),
                $patch['title'] ?? $patch_id,
                $patch_id,
                $cf_msg
            )
        );

        return [
            'success'                => true,
            'message'                => sprintf(
                /* translators: 1: patch title, 2: deployment message */
                __('Virtual Patch "%1$s" applied successfully!%2$s', 'webcare-pro-security'),
                $patch['title'] ?? $patch_id,
                $cf_msg
            ),
            'patch'                  => $patch,
            'deployed_to_cloudflare' => $cf_deployed,
        ];
    }

    /**
     * Remove / Deactivate a Virtual Patch.
     *
     * @param string $patch_id
     * @return array
     */
    public static function remove_patch(string $patch_id): array {
        $active = self::get_active_patches();
        if (!isset($active[$patch_id])) {
            return ['success' => false, 'local_removed' => false, 'edge_reconciled' => false, 'message' => __('Virtual Patch is not active.', 'webcare-pro-security')];
        }

        $patch = $active[$patch_id];

        unset($active[$patch_id]);
        $main_updated = update_option(self::OPTION_PATCHES, $active, false);

        // If patch exists in synthesized hotpatches, revoke and disable it so it never reappears
        $synthesized_opt_key = class_exists('\\WebCareProScanner\\Firewall\\VirtualPatchSynthesizer')
            ? VirtualPatchSynthesizer::OPTION_SYNTHESIZED_PATCHES
            : 'webcareproscan_synthesized_virtual_patches';
        $synth_patches = get_option($synthesized_opt_key, []);
        $synth_updated = true;
        if (is_array($synth_patches) && isset($synth_patches[$patch_id])) {
            $synth_patches[$patch_id]['enabled'] = false;
            $synth_patches[$patch_id]['stage'] = DeclarativePatchVerifier::STAGE_REVOKED;
            $synth_patches[$patch_id]['updated_at'] = current_time('mysql');
            $synth_updated = update_option($synthesized_opt_key, $synth_patches, false);
            // Verify persistence: must be disabled and marked STAGE_REVOKED
            $persisted_synth = get_option($synthesized_opt_key, []);
            $persisted_entry = $persisted_synth[$patch_id] ?? null;
            if (!is_array($persisted_entry) || !empty($persisted_entry['enabled']) || ($persisted_entry['stage'] ?? '') !== DeclarativePatchVerifier::STAGE_REVOKED) {
                $synth_updated = false;
            }
        }

        // Verify active patches persistence
        $persisted_active = self::get_active_patches();
        $local_removed = !isset($persisted_active[$patch_id]) && $synth_updated;

        if (!$local_removed) {
            return [
                'success'         => false,
                'local_removed'   => false,
                'edge_reconciled' => false,
                'message'         => __('Failed to persist patch deactivation in local storage.', 'webcare-pro-security'),
            ];
        }

        // Always reconcile Cloudflare edge rules when a patch is removed / deactivated
        $edge_ok = true;
        if (!empty($patch['deployed_to_cloudflare']) || !empty($patch['cf_expression'])) {
            $edge_ok = self::remove_from_cloudflare_edge($patch_id);
            if (!$edge_ok) {
                update_option('webcareproscan_vpatch_pending_cf_sync', true, false);
                AuditLogger::log_event(
                    'VPATCH_EDGE_SYNC_PENDING',
                    sprintf('Deactivated patch %s from origin, but Cloudflare Edge cleanup failed. Flagged for cron retry.', $patch_id)
                );
            }
        }

        if (class_exists('\\WebCareProScanner\\System\\WebCareActivityLogger')) {
            \WebCareProScanner\System\WebCareActivityLogger::notice('virtual_patch_deactivated', 'firewall', [
                'patch_id'   => $patch_id,
                'title'      => $patch['title'] ?? $patch_id,
                'cve_id'     => $patch['cve_id'] ?? $patch_id,
                'diff'       => [
                    $patch_id => [
                        'old' => [
                            'status' => 'active',
                            'title'  => $patch['title'] ?? $patch_id,
                        ],
                        'new' => null,
                    ],
                ],
                'description' => sprintf(
                    /* translators: 1: patch title, 2: patch ID */
                    __('Deactivated Virtual Shield "%1$s" (%2$s)', 'webcare-pro-security'),
                    $patch['title'] ?? $patch_id,
                    $patch_id
                ),
            ]);
        }

        AuditLogger::log_event(
            'virtual_patch_removed',
            sprintf(
                /* translators: 1: patch title, 2: patch ID */
                __('Removed Virtual Patch "%1$s" (%2$s)', 'webcare-pro-security'),
                $patch['title'] ?? $patch_id,
                $patch_id
            )
        );

        return [
            'success'         => true,
            'local_removed'   => true,
            'edge_reconciled' => $edge_ok,
            /* translators: %s: patch title */
            'message'         => sprintf(__('Virtual Patch "%s" has been deactivated.', 'webcare-pro-security'), $patch['title'] ?? $patch_id),
        ];
    }

    /**
     * Check if current request originates from an authenticated WordPress administrator.
     *
     * @return bool
     */
    public static function is_authenticated_administrator(): bool {
        if (class_exists('\\WebCareProScanner\\Firewall\\FirewallEngine')) {
            return \WebCareProScanner\Firewall\FirewallEngine::is_authenticated_administrator();
        }

        if (function_exists('is_user_logged_in') && function_exists('current_user_can')) {
            if (is_user_logged_in() && (current_user_can('manage_options') || current_user_can('activate_plugins'))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Fast-Path Runtime Inspection: Evaluate Incoming Request against Active Virtual Patches.
     * Hooked directly into FirewallEngine before request processing.
     *
     * @param string $client_ip
     * @param string $request_uri
     * @return array|null Triggered rule array or null if clean
     */
    public static function evaluate_request(string $client_ip, string $request_uri): ?array {
        // Authenticated administrators managing the site must never be blocked by virtual patches
        if (self::is_authenticated_administrator()) {
            return null;
        }

        $active_patches = self::get_active_patches();
        if (empty($active_patches)) {
            return null;
        }

        $method = isset($_SERVER['REQUEST_METHOD']) ? strtoupper(sanitize_key(wp_unslash($_SERVER['REQUEST_METHOD']))) : 'GET';
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Inspecting raw query string for CVE virtual patch match criteria
        $raw_query = isset($_SERVER['QUERY_STRING']) ? (string) wp_unslash($_SERVER['QUERY_STRING']) : '';
        $query_string = rawurldecode($raw_query);
        $raw_body = '';

        if (in_array($method, ['POST', 'PUT', 'PATCH'], true)) {
            if (class_exists('\\WebCareProScanner\\Firewall\\Core\\RequestBodyReader')) {
                $raw_body = \WebCareProScanner\Firewall\Core\RequestBodyReader::get_bounded_body(65536);
            } else {
                $raw_input = @file_get_contents('php://input', false, null, 0, 65536);
                $raw_body = !empty($raw_input) ? wp_unslash($raw_input) : '';
            }
        }

        // Normalize request URI path to prevent query/fragment false positives and path traversal spoofing
        $parsed_path = (string) (wp_parse_url($request_uri, PHP_URL_PATH) ?? '/');
        $normalized_req_path = '/' . ltrim($parsed_path, '/');

        foreach ($active_patches as $patch_id => &$patch) {
            if (empty($patch['enabled'])) {
                continue;
            }

            // CAF 2.0: Component-Type-Aware Applicability for Core, Plugins, Themes & MU Plugins
            $comp_slug = is_array($patch['component'] ?? null) ? ($patch['component']['slug'] ?? '') : ($patch['component'] ?? '');
            $comp_type = is_array($patch['component'] ?? null) ? strtolower((string) ($patch['component']['type'] ?? 'plugin')) : 'plugin';
            $target_slug = strtolower((string) ($patch['target'] ?? $comp_slug));

            if (!empty($target_slug) && !in_array($target_slug, ['generic', 'server', 'php', 'all-plugins', 'custom', 'test-plugin'], true)) {
                $is_applicable = false;
                switch ($comp_type) {
                    case 'core':
                        // Core patches always applicable (subject to version checks)
                        $is_applicable = true;
                        break;
                    case 'theme':
                        $active_stylesheet = function_exists('get_stylesheet') ? strtolower((string) get_stylesheet()) : '';
                        $active_template   = function_exists('get_template') ? strtolower((string) get_template()) : '';
                        if ($target_slug === $active_stylesheet || $target_slug === $active_template) {
                            $is_applicable = true;
                        } elseif (function_exists('wp_get_themes')) {
                            $installed_themes = wp_get_themes();
                            $is_applicable = is_array($installed_themes) && isset($installed_themes[$target_slug]);
                        }
                        break;
                    case 'mu-plugin':
                        if (function_exists('get_mu_plugins')) {
                            $mu_plugins = get_mu_plugins();
                            if (is_array($mu_plugins)) {
                                foreach (array_keys($mu_plugins) as $mu_file) {
                                    $mu_slug = strtolower(basename((string) $mu_file, '.php'));
                                    if ($mu_slug === $target_slug || str_starts_with($mu_slug, $target_slug)) {
                                        $is_applicable = true;
                                        break;
                                    }
                                }
                            }
                        }
                        if (!$is_applicable && defined('WPMU_PLUGIN_DIR') && is_dir(WPMU_PLUGIN_DIR)) {
                            $is_applicable = file_exists(WPMU_PLUGIN_DIR . '/' . $target_slug . '.php')
                                || is_dir(WPMU_PLUGIN_DIR . '/' . $target_slug);
                        }
                        break;
                    case 'plugin':
                    default:
                        if (in_array($target_slug, ['core', 'wordpress-core'], true)) {
                            $is_applicable = true;
                        } elseif (class_exists('\\WebCareProScanner\\Firewall\\CAF\\AdaptiveFirewallAdvisor')) {
                            $is_applicable = \WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor::is_plugin_slug_active($target_slug);
                        } else {
                            $is_applicable = true;
                        }
                        break;
                }

                if (!$is_applicable) {
                    continue;
                }
            }

            $stage = (string) ($patch['stage'] ?? DeclarativePatchVerifier::STAGE_ACTIVE);
            if ($stage === DeclarativePatchVerifier::STAGE_REVOKED) {
                continue;
            }

            // Check Declarative Patch match logic (PR-K wiring: route + method + source + key + predicate)
            if (!empty($patch['match']) && is_array($patch['match'])) {
                $match = $patch['match'];
                $match_route = (string) ($match['route'] ?? '/');
                $match_method = strtoupper((string) ($match['method'] ?? '*'));

                if ($match_method !== '*' && $match_method !== $method) {
                    continue;
                }

                if ($match_route !== '/' && $match_route !== '') {
                    $route_matched = false;
                    if (str_ends_with($match_route, '/*')) {
                        // Wildcard prefix matching on directory boundary (e.g. /checkout/* matches /checkout/pay but not /checkout-admin)
                        $prefix = rtrim(substr($match_route, 0, -2), '/');
                        if ($normalized_req_path === $prefix || str_starts_with($normalized_req_path, $prefix . '/')) {
                            $route_matched = true;
                        }
                    } elseif (rtrim($normalized_req_path, '/') === rtrim($match_route, '/')) {
                        // Exact path equality
                        $route_matched = true;
                    } elseif (str_starts_with($normalized_req_path, rtrim($match_route, '/') . '/')) {
                        // Sub-path match
                        $route_matched = true;
                    }

                    if (!$route_matched) {
                        continue;
                    }
                }

                $predicate = (string) ($match['predicate'] ?? '');
                $matched_declarative = false;
                $evidence = 'Declarative match';

                $source = strtolower((string) ($match['source'] ?? ''));
                $key    = (string) ($match['key'] ?? '');

                // Check for read truncation or stream read failure on body predicates
                $body_read_failed = false;
                $body_is_truncated = false;
                if (in_array($source, ['body', 'raw_body', 'json', 'post', 'form'], true) || ($source === '' && $key === '')) {
                    if (class_exists('\\WebCareProScanner\\Firewall\\Core\\RequestBodyReader')) {
                        $body_read_failed = \WebCareProScanner\Firewall\Core\RequestBodyReader::has_read_failed();
                        $body_is_truncated = \WebCareProScanner\Firewall\Core\RequestBodyReader::is_truncated();

                        if ($body_read_failed) {
                            if ($stage === DeclarativePatchVerifier::STAGE_ACTIVE) {
                                AuditLogger::log_event(
                                    'VPATCH_BODY_INCOMPLETE_BLOCKED',
                                    sprintf('Virtual patch %s failed closed (HTTP 400): php://input stream unreadable.', $patch_id)
                                );
                                return [
                                    'id'          => 'WAF-VPATCH-BODY-INCOMPLETE',
                                    'name'        => '[Virtual Patch] Incomplete Body Read Fail-Closed',
                                    'category'    => 'Virtual Patch (CVE Shield)',
                                    'detector'    => 'VirtualPatchManager',
                                    'sig_id'      => 'cve:' . strtolower($patch_id),
                                    'action'      => 'block',
                                    'status_code' => 400,
                                    'match_type'  => 'Stream Read Failure',
                                    'match_value' => 'php://input read failure',
                                ];
                            }
                            AuditLogger::log_event(
                                'VPATCH_BODY_INCOMPLETE',
                                sprintf('Virtual patch %s body predicate evaluation skipped due to php://input stream read failure.', $patch_id)
                            );
                            continue;
                        }
                    }
                }

                // Resolve target source value if key/source is specified
                $target_value = null;
                if ($source !== '' || $key !== '') {
                    switch ($source) {
                        case 'query':
                        case 'get':
                            // phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
                            $target_value = $key !== '' ? (isset($_GET[$key]) ? (string) wp_unslash($_GET[$key]) : '') : $query_string;
                            break;
                        case 'post':
                        case 'form':
                            // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
                            $target_value = $key !== '' ? (isset($_POST[$key]) ? (string) wp_unslash($_POST[$key]) : '') : $raw_body;
                            break;
                        case 'header':
                            $hdr_k = 'HTTP_' . strtoupper(str_replace('-', '_', $key));
                            // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
                            $target_value = isset($_SERVER[$hdr_k]) ? (string) wp_unslash($_SERVER[$hdr_k]) : '';
                            break;
                        case 'cookie':
                            // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
                            $target_value = isset($_COOKIE[$key]) ? (string) wp_unslash($_COOKIE[$key]) : '';
                            break;
                        case 'uri':
                        case 'path':
                            $target_value = $request_uri;
                            break;
                        case 'body':
                        case 'raw_body':
                        case 'json':
                            if ($key !== '') {
                                $decoded = json_decode($raw_body, true);
                                $target_value = is_array($decoded) && isset($decoded[$key]) ? (string) $decoded[$key] : '';
                            } else {
                                $target_value = $raw_body;
                            }
                            break;
                        default:
                            if ($key !== '') {
                                $hdr_k_def = 'HTTP_' . strtoupper(str_replace('-', '_', $key));
                                // phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
                                $target_value = (string) (isset($_GET[$key]) ? wp_unslash($_GET[$key]) : (isset($_POST[$key]) ? wp_unslash($_POST[$key]) : (isset($_SERVER[$hdr_k_def]) ? wp_unslash($_SERVER[$hdr_k_def]) : '')));
                            }
                            break;
                    }
                }

                if ($predicate === 'true' || empty($predicate)) {
                    $matched_declarative = true;
                } elseif (str_starts_with($predicate, 'header.')) {
                    // Evaluate header predicate (e.g. header.x-wcpay != "")
                    if (preg_match('/header\.([a-zA-Z0-9_-]+)\s*(!=|==)\s*"?([^"]*)"?/', $predicate, $pm)) {
                        $hdr_name = 'HTTP_' . strtoupper(str_replace('-', '_', $pm[1]));
                        $hdr_op   = $pm[2];
                        $hdr_val  = $pm[3];
                        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
                        $actual   = isset($_SERVER[$hdr_name]) ? (string) wp_unslash($_SERVER[$hdr_name]) : '';
                        if ($hdr_op === '!=' && $actual !== $hdr_val) {
                            $matched_declarative = true;
                            $evidence = "Header {$pm[1]}: {$actual}";
                        } elseif ($hdr_op === '==' && $actual === $hdr_val) {
                            $matched_declarative = true;
                            $evidence = "Header {$pm[1]}: {$actual}";
                        }
                    }
                } elseif (str_starts_with($predicate, 'equals:')) {
                    $eq_val = substr($predicate, 7);
                    if ($target_value !== null && $target_value === $eq_val) {
                        $matched_declarative = true;
                        $evidence = "Value equals {$eq_val}";
                    }
                } elseif (str_starts_with($predicate, 'contains:')) {
                    $ct_val = substr($predicate, 9);
                    if ($target_value !== null && str_contains($target_value, $ct_val)) {
                        $matched_declarative = true;
                        $evidence = "Value contains {$ct_val}";
                    }
                } elseif (str_starts_with($predicate, 'regex:') || (str_starts_with($predicate, '/') && str_ends_with($predicate, '/'))) {
                    $pattern = str_starts_with($predicate, 'regex:') ? substr($predicate, 6) : $predicate;
                    $subject = $target_value ?? (!empty($query_string) ? $query_string : $raw_body);
                    if (!empty($subject) && @preg_match($pattern, $subject, $m)) {
                        $matched_declarative = true;
                        $evidence = substr((string) ($m[0] ?? ''), 0, 100);
                    }
                } elseif (!empty($match['regex'])) {
                    $pattern = (string) $match['regex'];
                    $subject = $target_value ?? (!empty($query_string) ? $query_string : $raw_body);
                    if (!empty($subject) && @preg_match($pattern, $subject, $m)) {
                        $matched_declarative = true;
                        $evidence = substr((string) ($m[0] ?? ''), 0, 100);
                    }
                }

                if ($matched_declarative) {
                    if ($stage === DeclarativePatchVerifier::STAGE_SHADOW || $stage === DeclarativePatchVerifier::STAGE_STAGED) {
                        // Shadow / Staged canary mode: record hit telemetry without blocking
                        $active = self::get_active_patches();
                        if (isset($active[$patch_id])) {
                            $active[$patch_id]['hits'] = ($active[$patch_id]['hits'] ?? 0) + 1;
                            $active[$patch_id]['last_hit'] = current_time('mysql');
                            update_option(self::OPTION_PATCHES, $active, false);
                        }
                        AuditLogger::log_event(
                            'VPATCH_' . strtoupper($stage) . '_OBSERVE',
                            sprintf('Virtual patch %s matched in %s mode (observe-only): %s', $patch_id, $stage, $evidence)
                        );
                        continue;
                    }

                    // STAGE_ACTIVE: Trigger block or declared action
                    return self::trigger_patch_block($patch_id, $patch, $evidence, 'Declarative Match');
                }

                // If body was truncated and prefix did NOT match, fail closed for STAGE_ACTIVE
                if ($body_is_truncated && (in_array($source, ['body', 'raw_body', 'json', 'post', 'form'], true) || ($source === '' && $key === ''))) {
                    if ($stage === DeclarativePatchVerifier::STAGE_ACTIVE) {
                        AuditLogger::log_event(
                            'VPATCH_BODY_TRUNCATED_BLOCKED',
                            sprintf('Virtual patch %s failed closed (HTTP 413): Payload exceeded bounded limit and prefix did not match.', $patch_id)
                        );
                        return [
                            'id'          => 'WAF-VPATCH-BODY-INCOMPLETE',
                            'name'        => '[Virtual Patch] Truncated Payload Fail-Closed',
                            'category'    => 'Virtual Patch (CVE Shield)',
                            'detector'    => 'VirtualPatchManager',
                            'sig_id'      => 'cve:' . strtolower($patch_id),
                            'action'      => 'block',
                            'status_code' => 413,
                            'match_type'  => 'Payload Truncation',
                            'match_value' => 'Body exceeded bounded stream limit',
                        ];
                    }
                    AuditLogger::log_event(
                        'VPATCH_BODY_INCOMPLETE',
                        sprintf('Virtual patch %s observe mode: payload exceeded bounded ceiling and prefix did not match.', $patch_id)
                    );
                }

                continue;
            }

            $rule = $patch['php_rule'] ?? [];
            if (empty($rule)) {
                continue;
            }

            // Check Method restriction
            if (!empty($rule['methods']) && is_array($rule['methods'])) {
                $allowed_methods = array_map('strtoupper', (array) $rule['methods']);
                if (!in_array('*', $allowed_methods, true) && !in_array($method, $allowed_methods, true)) {
                    continue;
                }
            }

            // Check URI match
            $uri_matches = false;
            if (!empty($rule['target_uris']) && is_array($rule['target_uris'])) {
                foreach ($rule['target_uris'] as $target_uri) {
                    if ($target_uri === '/' || stripos($request_uri, $target_uri) !== false) {
                        $uri_matches = true;
                        break;
                    }
                }
            } else {
                $uri_matches = true;
            }

            if (!$uri_matches) {
                continue;
            }

            // Check Headers
            if (!empty($rule['headers']) && is_array($rule['headers'])) {
                foreach ($rule['headers'] as $h_key) {
                    $norm_header = 'HTTP_' . strtoupper(str_replace('-', '_', $h_key));
                    if (!empty($_SERVER[$norm_header])) {
                        $h_val = sanitize_text_field(wp_unslash($_SERVER[$norm_header]));
                        if (!empty($rule['regex']) && preg_match($rule['regex'], $h_val)) {
                            return self::trigger_patch_block($patch_id, $patch, $h_val, 'HTTP Header: ' . $h_key);
                        }
                    }
                }
                // Header-targeted rules must not leak their header regex into query string or POST parameters
                continue;
            }

            // Check Query string and Body with Regex
            if (!empty($rule['regex'])) {
                $matched_evidence = '';

                if (!empty($query_string) && preg_match($rule['regex'], urldecode($query_string), $matches)) {
                    $matched_evidence = $matches[0];
                } elseif (!empty($raw_body) && preg_match($rule['regex'], $raw_body, $matches)) {
                    $matched_evidence = substr($matches[0], 0, 100);
                // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Early runtime virtual patch evaluation executes before nonces
                } elseif (!empty($_POST)) {
                    // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Early runtime virtual patch evaluation executes before nonces
                    $raw_post = is_array($_POST) ? wp_unslash($_POST) : [];
                    $flat_post = (string) wp_json_encode($raw_post);
                    if (preg_match($rule['regex'], $flat_post, $matches) || preg_match($rule['regex'], rawurldecode($flat_post), $matches)) {
                        $matched_evidence = substr($matches[0], 0, 100);
                    }
                }

                if (!empty($matched_evidence)) {
                    return self::trigger_patch_block($patch_id, $patch, $matched_evidence, 'Payload Parameter');
                }
            }
        }

        return null;
    }

    /**
     * Trigger Patch Block and Increment Counters.
     */
    private static function trigger_patch_block(string $patch_id, array &$patch, string $evidence, string $match_type): array {
        // Increment hit counter in options
        $active = self::get_active_patches();
        if (isset($active[$patch_id])) {
            $active[$patch_id]['hits'] = ($active[$patch_id]['hits'] ?? 0) + 1;
            $active[$patch_id]['last_hit'] = current_time('mysql');
            update_option(self::OPTION_PATCHES, $active, false);
        }

        $action_raw = strtolower((string) ($patch['action'] ?? 'block'));
        $vpatch_req_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash((string) $_SERVER['REQUEST_URI'])) : '';
        $status_code = match ($action_raw) {
            'rate_limit'                 => 429,
            'challenge_pow', 'challenge' => (str_contains($vpatch_req_uri, 'wp-json') || str_contains($vpatch_req_uri, 'admin-ajax.php')) ? 429 : 200,
            'log', 'log_only'            => 200,
            default                      => 403,
        };

        return [
            'id'          => 'VPATCH-' . $patch_id,
            'name'        => '[Virtual Patch] ' . ($patch['title'] ?? $patch_id),
            'category'    => 'Virtual Patch (CVE Shield)',
            'detector'    => 'VirtualPatchManager',
            'sig_id'      => 'cve:' . strtolower($patch_id),
            'action'      => $action_raw,
            'status_code' => $status_code,
            'match_type'  => $match_type,
            'match_value' => substr($evidence, 0, 120),
        ];
    }

    /**
     * Deploy Virtual Patch Expression to Cloudflare Global Edge.
     */
    public static function deploy_to_cloudflare_edge(array $patch): array {
        $settings = SettingsManager::get_settings();
        $zone_id = $settings['cloudflare_zone_id'] ?? '';
        $token = $settings['cloudflare_api_token'] ?? '';

        if (empty($zone_id) || empty($token)) {
            return ['success' => false, 'message' => __('Cloudflare API Token or Zone ID is not configured in Settings.', 'webcare-pro-security')];
        }

        if (!class_exists('\\WebCareProScanner\\Cloudflare\\CloudflareService')) {
            $cf_file = defined('WEBCAREPROSCAN_PATH') ? WEBCAREPROSCAN_PATH . 'includes/Cloudflare/CloudflareService.php' : dirname(__DIR__) . '/Cloudflare/CloudflareService.php';
            if (file_exists($cf_file)) {
                require_once $cf_file;
            }
        }

        if (!class_exists('\\WebCareProScanner\\Cloudflare\\CloudflareService')) {
            return ['success' => false, 'message' => __('Cloudflare integration service is unavailable.', 'webcare-pro-security')];
        }

        // Delegate synchronization cleanly through CloudflareSlotOptimizer as single authoritative fetch + deploy path
        if (class_exists('\\WebCareProScanner\\Firewall\\CAF\\CloudflareSlotOptimizer')) {
            $optimizer = new \WebCareProScanner\Firewall\CAF\CloudflareSlotOptimizer();
            $active_patches = self::get_active_patches();
            // Ensure incoming patch is reflected in active_patches collection
            $active_patches[$patch['patch_id']] = $patch;
            $scoped_patches = [];
            foreach ($active_patches as $p) {
                $p_stage = (string) ($p['stage'] ?? DeclarativePatchVerifier::STAGE_ACTIVE);
                $p_act = strtolower((string) ($p['action'] ?? 'block'));
                if (!empty($p['cf_expression']) && !empty($p['enabled']) && $p_stage === DeclarativePatchVerifier::STAGE_ACTIVE && $p_act === 'block') {
                    $scoped_patches[] = $p;
                }
            }
            return $optimizer->deploy_to_cloudflare($zone_id, null, $scoped_patches);
        }

        // Direct fallback when CloudflareSlotOptimizer is unavailable
        $fetch_safe = CloudflareService::request("zones/{$zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint");
        if (empty($fetch_safe['success'])) {
            $err = $fetch_safe['errors'][0]['message'] ?? __('Failed to verify existing Cloudflare ruleset. Aborting sync to prevent overwriting customer rules.', 'webcare-pro-security');
            return ['success' => false, 'message' => $err];
        }

        $rules = [];
        if (!empty($fetch_safe['result']['rules'])) {
            foreach ($fetch_safe['result']['rules'] as $r) {
                // Keep other rules
                $desc = $r['description'] ?? '';
                if (strpos($desc, self::CF_TAG . ' ' . $patch['patch_id']) === false) {
                    $rules[] = $r;
                }
            }
        }

        // Direct fallback parity: Only deploy when stage === STAGE_ACTIVE && action === 'block'
        $patch_stage = (string) ($patch['stage'] ?? DeclarativePatchVerifier::STAGE_ACTIVE);
        $patch_action = strtolower((string) ($patch['action'] ?? 'block'));
        $cf_expr = trim((string) ($patch['cf_expression'] ?? ''));

        if ($patch_stage === DeclarativePatchVerifier::STAGE_ACTIVE && $patch_action === 'block' && $cf_expr !== '') {
            $rule_desc = self::CF_TAG . ' ' . $patch['patch_id'] . ': ' . substr($patch['title'], 0, 60);
            $rules[] = [
                'action'      => 'block',
                'expression'  => $cf_expr,
                'description' => $rule_desc,
                'enabled'     => true,
            ];
        }

        // Cloudflare Free allows up to 5 custom rules. Check limit
        if (count($rules) > 10) {
            // Keep rules within limit
            $rules = array_slice($rules, -10);
        }

        $put_res = CloudflareService::request(
            "zones/{$zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint",
            'PUT',
            ['rules' => $rules]
        );

        if (!empty($put_res['success'])) {
            return [
                'success'            => true,
                'rule_id'            => $patch['patch_id'],
                'included_patch_ids' => ($patch_stage === DeclarativePatchVerifier::STAGE_ACTIVE && $patch_action === 'block' && $cf_expr !== '') ? [(string) $patch['patch_id']] : [],
                'message'            => __('Cloudflare Edge Rule synced successfully.', 'webcare-pro-security'),
            ];
        }

        $err = $put_res['errors'][0]['message'] ?? __('Cloudflare API rejected rule expression.', 'webcare-pro-security');
        return ['success' => false, 'message' => $err];
    }

    /**
     * Remove Virtual Patch Rule from Cloudflare Global Edge.
     */
    public static function remove_from_cloudflare_edge(string $patch_id): bool {
        $settings = SettingsManager::get_settings();
        $zone_id = $settings['cloudflare_zone_id'] ?? '';
        if (empty($zone_id)) {
            return false;
        }

        if (!class_exists('\\WebCareProScanner\\Cloudflare\\CloudflareService')) {
            $cf_file = defined('WEBCAREPROSCAN_PATH') ? WEBCAREPROSCAN_PATH . 'includes/Cloudflare/CloudflareService.php' : dirname(__DIR__) . '/Cloudflare/CloudflareService.php';
            if (file_exists($cf_file)) {
                require_once $cf_file;
            }
        }

        if (!class_exists('\\WebCareProScanner\\Cloudflare\\CloudflareService')) {
            return false;
        }

        // Delegate synchronization cleanly through CloudflareSlotOptimizer as single authoritative fetch + deploy path
        if (class_exists('\\WebCareProScanner\\Firewall\\CAF\\CloudflareSlotOptimizer')) {
            $optimizer = new \WebCareProScanner\Firewall\CAF\CloudflareSlotOptimizer();
            $active_patches = self::get_active_patches();
            $scoped_patches = [];
            foreach ($active_patches as $p) {
                $p_stage = (string) ($p['stage'] ?? DeclarativePatchVerifier::STAGE_ACTIVE);
                $p_act = strtolower((string) ($p['action'] ?? 'block'));
                if (!empty($p['cf_expression']) && !empty($p['enabled']) && $p_stage === DeclarativePatchVerifier::STAGE_ACTIVE && $p_act === 'block') {
                    $scoped_patches[] = $p;
                }
            }
            $opt_res = $optimizer->deploy_to_cloudflare($zone_id, null, $scoped_patches);
            return !empty($opt_res['success']);
        }

        $res = CloudflareService::request("zones/{$zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint");
        if (empty($res['success']) || empty($res['result']['rules'])) {
            return false;
        }

        $remaining_rules = [];
        foreach ($res['result']['rules'] as $r) {
            $desc = $r['description'] ?? '';
            if (strpos($desc, self::CF_TAG . ' ' . $patch_id) === false) {
                $remaining_rules[] = $r;
            }
        }

        $put_res = CloudflareService::request(
            "zones/{$zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint",
            'PUT',
            ['rules' => $remaining_rules]
        );

        return !empty($put_res['success']);
    }
}
