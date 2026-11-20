<?php
declare(strict_types=1);

namespace WebCareProScanner\Api\Controllers;

use WebCareProScanner\Api\ScannerRoutes;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * SystemController
 *
 * System, Settings, Backup & Telemetry REST Controller.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
final class SystemController extends AbstractApiController {

    /**
     * Register endpoints for this domain.
     *
     * @param string   $namespace REST API route namespace.
     * @param callable $permission Permission callback.
     */
    public static function register(string $namespace, callable $permission): void {
        register_rest_route($namespace, '/server-info', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_server_info'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/telemetry/snapshot', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_telemetry_snapshot'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/system/telemetry-snapshot', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_telemetry_snapshot'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/readiness', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_system_readiness'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/welcome/dismiss', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'dismiss_welcome_modal'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/backup/preflight', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_backup_preflight'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/backup/session/start', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'start_backup_session'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/backup/session/step', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'step_backup_session'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/backup/session/status', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_backup_session_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/backup/active', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_active_backup'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/backup/session/cancel', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'cancel_backup_session'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/backup/create', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'create_backup'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/backup/list', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'list_backups'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/backup/delete', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'delete_backup'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/backup/download', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'download_backup'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/settings', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/settings', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'save_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/settings/export', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'export_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/settings/import', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'import_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/settings/reset', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'reset_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/settings/trigger-cron', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'trigger_cron_now'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/hardening/audit', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_hardening_audit'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/hardening/apply-preset', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'apply_hardening_preset'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/site-advisor', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_site_advisor_evaluation'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/site-advisor/apply', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'apply_site_advisor_recommendations'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/site-advisor/rollback', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'rollback_site_advisor_snapshot'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/reports/incident-response', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_incident_report'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/comment/moderate', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'moderate_comment'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/notifications/test-webhook', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'test_chat_webhook'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/notifications/settings', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_notification_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/notifications/settings', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'save_notification_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/notifications/test-event', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'test_notification_event'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/vault/status', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_vault_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/vault/rotate-key', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'rotate_vault_key'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/vault/rollback-rotation', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'rollback_vault_rotation'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/vault/reset-rotation', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'reset_vault_rotation'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/security/run-drill', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'run_security_drill'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/security/drill-results', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_security_drill_results'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/containment/status', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_containment_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/containment/toggle', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'toggle_containment'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/correlation/hierarchy', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_correlation_hierarchy'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/activity-logs', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_activity_logs'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/activity-logs/verify', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'verify_activity_logs_integrity'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/activity-logs/export', [
            'methods'             => ['GET', 'POST'],
            'callback'            => [self::class, 'export_activity_logs'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/activity-logs/prune', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'prune_activity_logs'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/activity-logs/acknowledge-tamper', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'acknowledge_activity_tamper_alert'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/wizard/status', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_wizard_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/wizard/save', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'save_wizard_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/modules/ecosystem', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_modules_ecosystem'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/modules/toggle', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'toggle_ecosystem_module'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/system/doctor', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_system_doctor'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/system/diagnostic-export', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'export_diagnostic_bundle'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/system/safe-mode', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'toggle_safe_mode'],
            'permission_callback' => $permission,
        ]);

    }

    /**
     * Run doctor diagnostics and return health report.
     */
    public static function get_system_doctor(): \WP_REST_Response {
        $report = \WebCareProScanner\System\SystemDoctor::run_diagnostics();
        return new \WP_REST_Response(['success' => true, 'report' => $report], 200);
    }

    /**
     * Export DLP-redacted diagnostic bundle JSON.
     */
    public static function export_diagnostic_bundle(): \WP_REST_Response {
        $bundle = \WebCareProScanner\System\SystemDoctor::build_redacted_diagnostic_bundle();
        return new \WP_REST_Response(['success' => true, 'bundle' => $bundle], 200);
    }

    /**
     * Toggle 15-Minute Safe Mode (Observe-Only Pause or Immediate Resume).
     */
    public static function toggle_safe_mode(\WP_REST_Request $request): \WP_REST_Response {
        $action = sanitize_key((string) ($request->get_param('action') ?? 'pause'));
        if (!class_exists(\WebCareProScanner\Firewall\RescueAssistantManager::class)) {
            return new \WP_REST_Response(['success' => false, 'message' => __('Rescue assistant manager not available.', 'webcare-pro-security')], 500);
        }

        if ($action === 'resume') {
            $result = \WebCareProScanner\Firewall\RescueAssistantManager::resume_strict_firewall();
        } else {
            $result = \WebCareProScanner\Firewall\RescueAssistantManager::pause_strict_firewall_15m();
        }

        return new \WP_REST_Response($result, 200);
    }

    /**
     * Retrieve status and environmental signals for the Onboarding Protection Wizard.
     *
     * @param \WP_REST_Request $request
     * @return \WP_REST_Response
     */
    public static function get_wizard_status(\WP_REST_Request $request) {
        $client_ip = \WebCareProScanner\Firewall\FirewallEngine::get_client_ip();
        
        // Detect live Cloudflare edge proxy
        $is_cloudflare = !empty($_SERVER['HTTP_CF_RAY']) || !empty($_SERVER['HTTP_CF_CONNECTING_IP']);
        $cf_ray = !empty($_SERVER['HTTP_CF_RAY']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_CF_RAY'])) : '';

        // Detect archetype
        $archetype = 'business';
        $saved_archetype = get_option('webcareproscan_site_archetype');
        if (!empty($saved_archetype) && in_array($saved_archetype, ['ecommerce', 'membership', 'business', 'blog'], true)) {
            $archetype = $saved_archetype;
        } elseif (class_exists('WooCommerce')) {
            $archetype = 'ecommerce';
        } elseif (class_exists('MemberPress') || class_exists('LearnDash_Settings_Section') || class_exists('LifterLMS')) {
            $archetype = 'membership';
        }

        $waf_settings = get_option('webcareproscan_waf_settings', []);
        if (!is_array($waf_settings)) {
            $waf_settings = [];
        }

        $current_whitelist = (string) get_option('webcareproscan_waf_whitelisted_ips', '');
        $is_whitelisted = strpos($current_whitelist, $client_ip) !== false;

        $ip_whitelist_entries = get_option('webcareproscan_ip_whitelist', []);
        if (!is_array($ip_whitelist_entries)) {
            $ip_whitelist_entries = [];
        }
        if (empty($ip_whitelist_entries) && !empty($current_whitelist)) {
            $lines = array_filter(array_map('trim', explode("\n", $current_whitelist)));
            foreach ($lines as $line) {
                $ip_whitelist_entries[] = [
                    'ip'         => $line,
                    'label'      => __('Allowlisted Address', 'webcare-pro-security'),
                    'created_at' => current_time('mysql'),
                ];
            }
        }

        $uid = get_current_user_id();
        $support_code = '#WEBCARE-' . strtoupper(substr(md5((string) $uid . wp_salt('auth')), 0, 4));

        $site_host = wp_parse_url(home_url(), PHP_URL_HOST) ?: '';
        $root_domain = class_exists('\WebCareProScanner\Cloudflare\CloudflareService')
            ? \WebCareProScanner\Cloudflare\CloudflareService::extract_root_domain($site_host)
            : $site_host;

        $server_info = class_exists('\WebCareProScanner\System\ServerInfo')
            ? \WebCareProScanner\System\ServerInfo::get_info(false)
            : null;

        $global_settings = class_exists('\WebCareProScanner\System\SettingsManager')
            ? \WebCareProScanner\System\SettingsManager::get_settings()
            : [];

        $active_plugin_slugs = class_exists('\WebCareProScanner\Firewall\FirewallEngine')
            ? \WebCareProScanner\Firewall\FirewallEngine::get_active_plugin_slugs()
            : [];

        // Check if Cloudflare token is stored
        $cf_token_saved = !empty($global_settings['has_cloudflare_key']) || !empty($global_settings['cloudflare_api_token']);
        $cf_zone_id     = (string) ($global_settings['cloudflare_zone_id'] ?? get_option('webcareproscan_cf_zone_id', ''));
        $cloudflare_status = [
            'has_saved_token' => $cf_token_saved,
            'zone_id'         => $cf_zone_id,
            'is_active'       => $is_cloudflare,
        ];

        // Check Preload Micro-WAF status
        $preload_waf_status = [
            'is_active'        => defined('WEBCAREPRO_PRELOAD_WAF_ACTIVE') && WEBCAREPRO_PRELOAD_WAF_ACTIVE,
            'is_compiled'      => false,
            'auto_prepend_ini' => (string) ini_get('auto_prepend_file'),
            'target_info'      => null,
        ];
        if (class_exists('\\WebCareProScanner\\Firewall\\MicroWafCompiler')) {
            $mw_stat = \WebCareProScanner\Firewall\MicroWafCompiler::get_status();
            $preload_waf_status['is_compiled']      = !empty($mw_stat['is_compiled']);
            $preload_waf_status['is_active']        = !empty($mw_stat['is_active']) || $preload_waf_status['is_active'];
            $preload_waf_status['target_info']      = $mw_stat['target_info'] ?? null;
            $preload_waf_status['auto_prepend_ini'] = $mw_stat['auto_prepend_ini'] ?? $preload_waf_status['auto_prepend_ini'];
        }

        // Outbound Egress status
        $egress_status = [];
        if (class_exists('\\WebCareProScanner\\Firewall\\OutboundEgressFirewall')) {
            $egress_status = \WebCareProScanner\Firewall\OutboundEgressFirewall::get_status();
        }

        // Stack Profile & Capabilities
        $stack_snapshot = [];
        $caf_status = [
            'active_profile'      => 'balanced',
            'recommended_profile' => 'balanced',
        ];
        if (class_exists('\\WebCareProScanner\\Firewall\\CAF\\AdaptiveFirewallAdvisor')) {
            $advisor = new \WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor();
            $snapshot_obj = $advisor->get_stack_snapshot();
            if (method_exists($snapshot_obj, 'to_array')) {
                $stack_snapshot = $snapshot_obj->to_array();
            }
            $rec_matrix = $advisor->get_recommendations_matrix($snapshot_obj);
            $caf_status['active_profile']      = $rec_matrix['current_profile'] ?? 'balanced';
            $caf_status['recommended_profile'] = $rec_matrix['recommended_profile'] ?? 'balanced';
        }
        $capability_profile = [];
        if (class_exists('\\WebCareProScanner\\Advisor\\SiteCapabilityProfiler')) {
            $capability_profile = \WebCareProScanner\Advisor\SiteCapabilityProfiler::profile();
        }

        $notification_settings = get_option('webcareproscan_notification_settings', []);
        if (!is_array($notification_settings)) {
            $notification_settings = [];
        }

        // Strip raw secrets before sending settings dictionary to frontend
        $safe_settings = $global_settings;
        unset(
            $safe_settings['cloudflare_api_token'],
            $safe_settings['ai_api_key'],
            $safe_settings['openai_api_key'],
            $safe_settings['gemini_api_key'],
            $safe_settings['claude_api_key'],
            $safe_settings['virus_total_api_key'],
            $safe_settings['wpscan_api_key'],
            $safe_settings['mcp_token']
        );

        // PHP Extension & Server Requirement Gate
        $php_ver = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
        $extensions_checklist = [
            [
                'id'       => 'json',
                'name'     => 'JSON Serialization',
                'tier'     => 'critical',
                'loaded'   => extension_loaded('json'),
                'purpose'  => __('REST API & Vault manifest serialization', 'webcare-pro-security'),
                'pkg_deb'  => "php{$php_ver}-json",
                'pkg_rpm'  => 'php-json',
            ],
            [
                'id'       => 'mbstring',
                'name'     => 'Multibyte String (mbstring)',
                'tier'     => 'critical',
                'loaded'   => extension_loaded('mbstring'),
                'purpose'  => __('Multi-byte UTF-8 evasion normalization in WAF', 'webcare-pro-security'),
                'pkg_deb'  => "php{$php_ver}-mbstring",
                'pkg_rpm'  => 'php-mbstring',
            ],
            [
                'id'       => 'openssl',
                'name'     => 'OpenSSL Cryptography',
                'tier'     => 'critical',
                'loaded'   => extension_loaded('openssl'),
                'purpose'  => __('Cryptographic HMAC ledger signatures & TLS inspection', 'webcare-pro-security'),
                'pkg_deb'  => "php{$php_ver}-openssl",
                'pkg_rpm'  => 'php-openssl',
            ],
            [
                'id'       => 'curl',
                'name'     => 'Client URL Library (cURL)',
                'tier'     => 'critical',
                'loaded'   => extension_loaded('curl'),
                'purpose'  => __('Cloudflare API sync, webhook dispatch & CVE signature updates', 'webcare-pro-security'),
                'pkg_deb'  => "php{$php_ver}-curl",
                'pkg_rpm'  => 'php-curl',
            ],
            [
                'id'       => 'tokenizer',
                'name'     => 'PHP Tokenizer & AST',
                'tier'     => 'critical',
                'loaded'   => extension_loaded('tokenizer') || function_exists('token_get_all'),
                'purpose'  => __('Required for PHP AST behavioral code analysis', 'webcare-pro-security'),
                'pkg_deb'  => "php{$php_ver}-tokenizer",
                'pkg_rpm'  => 'php-tokenizer',
            ],
            [
                'id'       => 'sodium',
                'name'     => 'Libsodium (AEAD)',
                'tier'     => 'recommended',
                'loaded'   => extension_loaded('sodium'),
                'purpose'  => __('Hardware-accelerated AEAD encryption for Secret Vault', 'webcare-pro-security'),
                'pkg_deb'  => "php{$php_ver}-sodium",
                'pkg_rpm'  => 'php-sodium',
            ],
            [
                'id'       => 'zip',
                'name'     => 'ZipArchive Engine',
                'tier'     => 'recommended',
                'loaded'   => extension_loaded('zip'),
                'purpose'  => __('Safe quarantine packaging & core repair backups', 'webcare-pro-security'),
                'pkg_deb'  => "php{$php_ver}-zip",
                'pkg_rpm'  => 'php-zip',
            ],
            [
                'id'       => 'zlib',
                'name'     => 'Zlib Compression',
                'tier'     => 'recommended',
                'loaded'   => extension_loaded('zlib'),
                'purpose'  => __('Compressed .intel.gz and .manifest.gz vault shards', 'webcare-pro-security'),
                'pkg_deb'  => "php{$php_ver}-zlib",
                'pkg_rpm'  => 'php-zlib',
            ],
            [
                'id'       => 'intl',
                'name'     => 'Internationalization (intl)',
                'tier'     => 'recommended',
                'loaded'   => extension_loaded('intl'),
                'purpose'  => __('IDN Punycode homograph phishing detection', 'webcare-pro-security'),
                'pkg_deb'  => "php{$php_ver}-intl",
                'pkg_rpm'  => 'php-intl',
            ],
            [
                'id'       => 'image',
                'name'     => 'Image Processing (GD / Imagick)',
                'tier'     => 'recommended',
                'loaded'   => extension_loaded('gd') || extension_loaded('imagick'),
                'purpose'  => __('Polyglot image upload payload inspection', 'webcare-pro-security'),
                'pkg_deb'  => "php{$php_ver}-gd",
                'pkg_rpm'  => 'php-gd',
            ],
            [
                'id'       => 'opcache',
                'name'     => 'Zend OPcache',
                'tier'     => 'runtime',
                'loaded'   => extension_loaded('Zend OPcache'),
                'purpose'  => __('High-performance bytecode caching for 0ms Pre-Boot WAF', 'webcare-pro-security'),
                'pkg_deb'  => "php{$php_ver}-opcache",
                'pkg_rpm'  => 'php-opcache',
            ],
        ];

        $missing_deb = [];
        $missing_rpm = [];
        $missing_critical = [];
        $missing_recommended = [];

        foreach ($extensions_checklist as $ext) {
            if (!$ext['loaded']) {
                if ($ext['tier'] === 'critical') {
                    $missing_critical[] = $ext['name'];
                } elseif ($ext['tier'] === 'recommended') {
                    $missing_recommended[] = $ext['name'];
                }
                if (!empty($ext['pkg_deb'])) {
                    $missing_deb[] = $ext['pkg_deb'];
                }
                if (!empty($ext['pkg_rpm'])) {
                    $missing_rpm[] = $ext['pkg_rpm'];
                }
            }
        }

        $apt_cmd = !empty($missing_deb)
            ? "sudo apt update && sudo apt install -y " . implode(' ', array_unique($missing_deb)) . " && sudo systemctl restart php{$php_ver}-fpm"
            : "sudo apt update && sudo apt install -y php{$php_ver}-mbstring php{$php_ver}-curl php{$php_ver}-zip && sudo systemctl restart php{$php_ver}-fpm";

        $dnf_cmd = !empty($missing_rpm)
            ? "sudo dnf install -y " . implode(' ', array_unique($missing_rpm)) . " && sudo systemctl restart php-fpm"
            : "sudo dnf install -y php-mbstring php-curl php-zip && sudo systemctl restart php-fpm";

        $memory_limit_str = (string) ini_get('memory_limit');
        $memory_limit_bytes = wp_convert_hr_to_bytes($memory_limit_str);
        $is_memory_sufficient = ($memory_limit_str === '-1' || $memory_limit_bytes === -1 || $memory_limit_bytes >= 134217728); // >= 128MB or unlimited

        $upload_dir_info = wp_upload_dir();
        $upload_dir_writable = !empty($upload_dir_info['basedir']) && wp_is_writable($upload_dir_info['basedir']);

        $php_extension_gate = [
            'php_version'          => PHP_VERSION,
            'extensions'           => $extensions_checklist,
            'all_critical_met'     => empty($missing_critical),
            'missing_critical'     => $missing_critical,
            'missing_recommended'  => $missing_recommended,
            'memory_limit'         => $memory_limit_str,
            'is_memory_sufficient' => $is_memory_sufficient,
            'max_execution_time'   => (int) ini_get('max_execution_time'),
            'upload_dir_writable'  => $upload_dir_writable,
            'commands'             => [
                'apt'    => $apt_cmd,
                'dnf'    => $dnf_cmd,
                'cpanel' => __('cPanel → Software → Select PHP Version → Extensions', 'webcare-pro-security'),
                'plesk'  => __('Plesk → Tools & Settings → PHP Settings → Select Version → Extensions', 'webcare-pro-security'),
            ],
        ];

        // Behavioral Vault & Modular Rules Summary
        $modular_vault_summary = class_exists('\\WebCareProScanner\\Firewall\\Modular\\BehavioralVaultManager')
            ? \WebCareProScanner\Firewall\Modular\BehavioralVaultManager::get_vault_summary()
            : null;

        $modular_rules = class_exists('\\WebCareProScanner\\Firewall\\Modular\\ModularFirewallSynthesizer')
            ? \WebCareProScanner\Firewall\Modular\ModularFirewallSynthesizer::get_active_rules()
            : [];

        $modular_rules_summary = [
            'total'    => count($modular_rules),
            'enforced' => count(array_filter($modular_rules, fn($r) => ($r['current_mode'] ?? '') === 'enforce')),
            'monitor'  => count(array_filter($modular_rules, fn($r) => ($r['current_mode'] ?? '') === 'monitor')),
            'off'      => count(array_filter($modular_rules, fn($r) => ($r['current_mode'] ?? '') === 'off')),
        ];

        return new \WP_REST_Response([
            'success'               => true,
            'client_ip'             => $client_ip,
            'is_whitelisted'        => $is_whitelisted,
            'ip_whitelist'          => $ip_whitelist_entries,
            'is_cloudflare_active'  => $is_cloudflare,
            'cf_ray'                => $cf_ray,
            'admin_email'           => get_option('admin_email'),
            'site_name'             => get_bloginfo('name'),
            'site_domain'           => $site_host,
            'root_domain'           => $root_domain,
            'detected_archetype'    => $archetype,
            'wizard_completed'      => (bool) get_option('webcareproscan_wizard_completed', false),
            'wizard_current_step'   => (int) get_option('webcareproscan_wizard_current_step', 1),
            'wizard_mode'           => (string) get_option('webcareproscan_wizard_mode', 'developer'),
            'support_code'          => $support_code,
            'waf_settings'          => $waf_settings,
            'server_info'           => $server_info,
            'active_plugin_slugs'   => $active_plugin_slugs,
            'scan_schedule'         => !empty($global_settings['schedule_enabled'])
                ? ($global_settings['schedule_frequency'] ?? 'daily')
                : 'manual',
            'cloudflare_status'     => $cloudflare_status,
            'preload_waf'           => $preload_waf_status,
            'egress_status'         => $egress_status,
            'stack_snapshot'        => $stack_snapshot,
            'affiliate_telemetry'   => class_exists('\\WebCareProScanner\\Firewall\\Core\\AffiliateSecurityEngine')
                ? \WebCareProScanner\Firewall\Core\AffiliateSecurityEngine::get_detected_ecosystem()
                : ['is_active' => false, 'plugins' => [], 'themes' => [], 'summary' => ''],
            'caf_status'            => $caf_status,
            'capability_profile'    => $capability_profile,
            'notification_settings' => $notification_settings,
            'php_extension_gate'    => $php_extension_gate,
            'modular_vault_summary' => $modular_vault_summary,
            'modular_rules_summary' => $modular_rules_summary,
            'settings'              => $safe_settings,
        ], 200);
    }

    /**
     * Atomic save handler for Onboarding Quickstart settings.
     *
     * @param \WP_REST_Request $request
     * @return \WP_REST_Response
     */
    public static function save_wizard_settings(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];

        // Suppress fragmented option watcher entries so wizard produces 1 clean consolidated event
        if (class_exists('\\WebCareProScanner\\System\\WebCareActivityLogger')) {
            \WebCareProScanner\System\WebCareActivityLogger::$suppress_option_watcher = true;
        }

        try {
            // 1. Whitelist Owner IP & Multi-IP/CIDR Entries
            $whitelist_updated = false;
            $client_ip = \WebCareProScanner\Firewall\FirewallEngine::get_client_ip();
            $existing_ips = (string) get_option('webcareproscan_waf_whitelisted_ips', '');
            $ip_lines = array_filter(array_map('trim', explode("\n", $existing_ips)));

            if (!empty($params['whitelist_ip'])) {
                if (!in_array($client_ip, $ip_lines, true)) {
                    $ip_lines[] = $client_ip;
                    $whitelist_updated = true;
                }
            }

            $custom_whitelist = $request->get_param('ip_whitelist_entries');
            if (is_array($custom_whitelist)) {
                $sanitized_whitelist = [];
                foreach ($custom_whitelist as $entry) {
                    if (!is_array($entry) || empty($entry['ip'])) {
                        continue;
                    }
                    $cand = sanitize_text_field((string) $entry['ip']);
                    if (filter_var($cand, FILTER_VALIDATE_IP) || preg_match('/^[0-9a-fA-F:\.]+\/\d{1,3}$/', $cand)) {
                        $sanitized_whitelist[] = [
                            'ip'         => $cand,
                            'label'      => sanitize_text_field((string) ($entry['label'] ?? __('Setup Studio Whitelist', 'webcare-pro-security'))),
                            'created_at' => sanitize_text_field((string) ($entry['created_at'] ?? current_time('mysql'))),
                        ];
                        if (!in_array($cand, $ip_lines, true)) {
                            $ip_lines[] = $cand;
                            $whitelist_updated = true;
                        }
                    }
                }
                update_option('webcareproscan_ip_whitelist', $sanitized_whitelist, false);
            }

            if ($whitelist_updated) {
                update_option('webcareproscan_waf_whitelisted_ips', implode("\n", array_unique($ip_lines)), false);
            }

            // 2. Archetype & Profile
            $archetype = sanitize_key($params['archetype'] ?? 'business');
            update_option('webcareproscan_site_archetype', $archetype, false);

            // 3. Firewall Toggles & Archetype Smart Rules
            $waf_settings = get_option('webcareproscan_waf_settings', []);
            if (!is_array($waf_settings)) {
                $waf_settings = [];
            }
            $firewall_payload = [];

            if (isset($params['firewall_settings']) && is_array($params['firewall_settings'])) {
                $fs = $params['firewall_settings'];

                $bool_waf_keys = [
                    'waf_enabled', 'waf_learning_mode', 'waf_block_uploads_exec',
                    'waf_enable_brute_force_shield', 'waf_enable_virtual_patching',
                    'waf_block_bad_bots', 'waf_rasp_enabled', 'waf_allow_seo_bots',
                    'waf_caf_block_inactive_plugins', 'waf_caf_lock_dormant_rest',
                    'waf_caf_strict_guest_admin_ajax', 'waf_ecommerce_safe_mode',
                    'waf_woo_carding_protection', 'waf_woo_coupon_protection',
                    'waf_woo_registration_protection', 'waf_woo_cart_flood_protection',
                    'waf_woo_scraping_protection', 'cf_auto_ban_sync', 'cf_ddos_protection_enabled',
                    'waf_smart_rule_48', 'waf_smart_rule_49', 'waf_smart_rule_50',
                    'waf_smart_rule_51', 'waf_smart_rule_52', 'waf_smart_rule_53', 'waf_smart_rule_54',
                ];
                foreach ($bool_waf_keys as $k) {
                    if (isset($fs[$k])) {
                        $waf_settings[$k] = (bool) $fs[$k];
                    }
                }

                $int_waf_keys = [
                    'waf_max_404_per_minute'            => [5, 200],
                    'waf_lockout_duration_mins'         => [1, 10080],
                    'waf_woo_carding_max_attempts'      => [2, 50],
                    'waf_woo_carding_max_declines'      => [1, 25],
                    'waf_woo_coupon_max_failures'       => [3, 50],
                    'waf_woo_cart_max_adds_per_min'     => [5, 300],
                    'waf_woo_reg_max_per_hour'          => [1, 100],
                    'waf_woo_scraping_max_reqs_per_min' => [10, 600],
                    'cf_ddos_threshold'                 => [20, 5000],
                ];
                foreach ($int_waf_keys as $k => $bounds) {
                    if (isset($fs[$k])) {
                        $waf_settings[$k] = max($bounds[0], min($bounds[1], (int) $fs[$k]));
                    }
                }
                update_option('webcareproscan_waf_settings', $waf_settings, false);

                // Map high-level wizard switches to exact SettingsManager keys
                if (isset($fs['waf_block_uploads_exec'])) {
                    $firewall_payload['waf_block_malicious_uploads'] = (bool) $fs['waf_block_uploads_exec'];
                    $firewall_payload['waf_block_uploads_php_exec']  = (bool) $fs['waf_block_uploads_exec'];
                }
                if (isset($fs['waf_enable_brute_force_shield'])) {
                    $firewall_payload['login_hardening_enabled'] = (bool) $fs['waf_enable_brute_force_shield'];
                    $firewall_payload['waf_login_rate_limit']    = (bool) $fs['waf_enable_brute_force_shield'];
                    $firewall_payload['waf_disable_xmlrpc']      = (bool) $fs['waf_enable_brute_force_shield'];
                }
                if (isset($fs['waf_enable_virtual_patching'])) {
                    $firewall_payload['waf_block_sqli']          = (bool) $fs['waf_enable_virtual_patching'];
                    $firewall_payload['waf_block_xss']           = (bool) $fs['waf_enable_virtual_patching'];
                    $firewall_payload['waf_block_traversal']     = (bool) $fs['waf_enable_virtual_patching'];
                    $firewall_payload['waf_block_php_injection'] = (bool) $fs['waf_enable_virtual_patching'];
                }
                if (isset($fs['waf_block_bad_bots'])) {
                    $firewall_payload['waf_block_fake_bots']    = (bool) $fs['waf_block_bad_bots'];
                    $firewall_payload['waf_block_404_scanners'] = (bool) $fs['waf_block_bad_bots'];
                }

                // Passthrough any explicit settings keys passed
                foreach ($fs as $k => $v) {
                    $clean_k = sanitize_key($k);
                    if (str_starts_with($clean_k, 'waf_') || str_starts_with($clean_k, 'form_') || str_starts_with($clean_k, 'login_')) {
                        if (is_bool($v) || is_numeric($v)) {
                            $firewall_payload[$clean_k] = $v;
                        }
                    }
                }
            }

            // Apply Archetype & Hosting-specific Smart Rules & CAF Protection Profile
            $explicit_caf_profile = !empty($params['caf_profile']) ? sanitize_key($params['caf_profile']) : '';
            if (empty($explicit_caf_profile) && !empty($params['scan_memory_safety_envelope']) && $params['scan_memory_safety_envelope'] === 'strict') {
                $explicit_caf_profile = \WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor::PROFILE_CPANEL_SHARED;
            }

            if (!empty($explicit_caf_profile) && class_exists('\\WebCareProScanner\\Firewall\\CAF\\AdaptiveFirewallAdvisor')) {
                $advisor = new \WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor();
                $advisor->apply_profile($explicit_caf_profile);

                if (in_array($explicit_caf_profile, [\WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor::PROFILE_ECOMMERCE_HARDENED, \WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor::PROFILE_HYBRID_PORTAL], true)) {
                    $firewall_payload['waf_ecommerce_safe_mode']         = true;
                    $firewall_payload['waf_woo_carding_protection']      = true;
                    $firewall_payload['waf_woo_coupon_protection']       = true;
                    $firewall_payload['waf_woo_registration_protection'] = true;
                    $firewall_payload['waf_woo_cart_flood_protection']   = true;
                    $firewall_payload['waf_woo_scraping_protection']     = true;
                }
            } elseif ($archetype === 'ecommerce') {
                $firewall_payload['waf_ecommerce_safe_mode']         = true;
                $firewall_payload['waf_woo_carding_protection']      = true;
                $firewall_payload['waf_woo_coupon_protection']       = true;
                $firewall_payload['waf_woo_registration_protection'] = true;
                $firewall_payload['waf_woo_cart_flood_protection']   = true;
                $firewall_payload['waf_woo_scraping_protection']     = true;

                if (class_exists('\\WebCareProScanner\\Firewall\\CAF\\AdaptiveFirewallAdvisor')) {
                    $advisor = new \WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor();
                    $advisor->apply_profile(\WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor::PROFILE_ECOMMERCE_HARDENED);
                }
            } elseif ($archetype === 'membership') {
                $firewall_payload['waf_ecommerce_safe_mode'] = true;

                if (class_exists('\\WebCareProScanner\\Firewall\\CAF\\AdaptiveFirewallAdvisor')) {
                    $advisor = new \WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor();
                    $advisor->apply_profile(\WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor::PROFILE_MEMBERSHIP_LMS);
                }
            } elseif ($archetype === 'community' || $archetype === 'forum') {
                $firewall_payload['waf_ecommerce_safe_mode'] = true;

                if (class_exists('\\WebCareProScanner\\Firewall\\CAF\\AdaptiveFirewallAdvisor')) {
                    $advisor = new \WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor();
                    $advisor->apply_profile(\WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor::PROFILE_COMMUNITY_FORUM);
                }
            } elseif ($archetype === 'hybrid' || $archetype === 'portal') {
                $firewall_payload['waf_ecommerce_safe_mode']         = true;
                $firewall_payload['waf_woo_carding_protection']      = true;
                $firewall_payload['waf_woo_cart_flood_protection']   = true;

                if (class_exists('\\WebCareProScanner\\Firewall\\CAF\\AdaptiveFirewallAdvisor')) {
                    $advisor = new \WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor();
                    $advisor->apply_profile(\WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor::PROFILE_HYBRID_PORTAL);
                }
            } elseif ($archetype === 'business' || $archetype === 'blog') {
                if (class_exists('\\WebCareProScanner\\Firewall\\CAF\\AdaptiveFirewallAdvisor')) {
                    $advisor = new \WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor();
                    $advisor->apply_profile(\WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor::PROFILE_BALANCED);
                }
            }

            // 4. Outbound Egress Settings
            if (isset($params['egress_settings']) && is_array($params['egress_settings'])) {
                $es = $params['egress_settings'];
                if (class_exists('\\WebCareProScanner\\Firewall\\OutboundEgressFirewall')) {
                    $mode = sanitize_key($es['mode'] ?? 'monitor');
                    if (!in_array($mode, ['disabled', 'monitor', 'enforce'], true)) {
                        $mode = 'monitor';
                    }
                    $allowed_hosts = [];
                    if (!empty($es['allowed_hosts'])) {
                        $raw_hosts = is_array($es['allowed_hosts']) ? $es['allowed_hosts'] : explode("\n", (string) $es['allowed_hosts']);
                        foreach ($raw_hosts as $h) {
                            $cleaned = strtolower(trim(sanitize_text_field($h)));
                            if (!empty($cleaned)) {
                                $allowed_hosts[] = $cleaned;
                            }
                        }
                    }
                    \WebCareProScanner\Firewall\OutboundEgressFirewall::update_settings([
                        'mode'                 => $mode,
                        'block_ssrf_metadata'  => !empty($es['block_ssrf_metadata']),
                        'block_exfil_webhooks' => !empty($es['block_exfil_webhooks']),
                        'block_suspicious_tld' => !empty($es['block_suspicious_tld']),
                        'allowed_hosts'        => $allowed_hosts,
                    ]);
                }
            }

            // 5. Cloudflare Integration (if provided)
            if (!empty($params['cloudflare']['api_token'])) {
                $cf_token = sanitize_text_field($params['cloudflare']['api_token']);
                $cf_zone  = !empty($params['cloudflare']['zone_id']) ? sanitize_text_field($params['cloudflare']['zone_id']) : '';

                // If Zone ID is empty, attempt auto-detect via CloudflareService
                if (empty($cf_zone) && class_exists('\WebCareProScanner\Cloudflare\CloudflareService')) {
                    $verify = \WebCareProScanner\Cloudflare\CloudflareService::verify_zone(null, $cf_token);
                    if (!empty($verify['success']) && !empty($verify['zone_id'])) {
                        $cf_zone = $verify['zone_id'];
                    }
                }

                if (!empty($cf_zone)) {
                    $firewall_payload['cloudflare_enabled']        = true;
                    $firewall_payload['cloudflare_api_token']      = $cf_token;
                    $firewall_payload['cloudflare_zone_id']        = $cf_zone;
                    $firewall_payload['cloudflare_auto_sync_bans'] = true;
                }
            } elseif (!empty($params['cloudflare']['zone_id'])) {
                $firewall_payload['cloudflare_enabled']        = true;
                $firewall_payload['cloudflare_zone_id']        = sanitize_text_field($params['cloudflare']['zone_id']);
                $firewall_payload['cloudflare_auto_sync_bans'] = true;
            }

            // 6. Scheduled Scan Frequency & Advanced Engine Settings
            $advanced_payload = $firewall_payload;

            if (!empty($params['scan_schedule'])) {
                $freq = sanitize_key($params['scan_schedule']);
                if (in_array($freq, ['hourly', 'twicedaily', 'daily', 'weekly', 'manual'], true)) {
                    $is_enabled = ($freq !== 'manual');
                    $actual_freq = $is_enabled ? $freq : 'daily';
                    $advanced_payload['schedule_enabled']   = $is_enabled;
                    $advanced_payload['schedule_frequency'] = $actual_freq;
                }
            }

            if (isset($params['custom_scan_options']) && is_array($params['custom_scan_options'])) {
                $advanced_payload['custom_scan_options'] = $params['custom_scan_options'];
            }

            if (isset($params['scan_batch_size'])) {
                $advanced_payload['scan_batch_size'] = max(10, min(500, intval($params['scan_batch_size'])));
            }

            if (isset($params['scan_memory_safety_envelope'])) {
                $advanced_payload['scan_memory_safety_envelope'] = sanitize_key($params['scan_memory_safety_envelope']);
            }

            if (isset($params['scan_adaptive_throttling'])) {
                $advanced_payload['scan_adaptive_throttling'] = (bool) $params['scan_adaptive_throttling'];
            }

            if (isset($params['scan_batch_delay_ms'])) {
                $advanced_payload['scan_batch_delay_ms'] = max(0, min(2000, intval($params['scan_batch_delay_ms'])));
            }

            if (isset($params['delete_data_on_uninstall'])) {
                $advanced_payload['delete_data_on_uninstall'] = (bool) $params['delete_data_on_uninstall'];
            }

            if (isset($params['uninstall_drop_tables'])) {
                $advanced_payload['uninstall_drop_tables'] = (bool) $params['uninstall_drop_tables'];
            }

            if (isset($params['uninstall_delete_options'])) {
                $advanced_payload['uninstall_delete_options'] = (bool) $params['uninstall_delete_options'];
            }

            if (isset($params['activity_log_settings']) && is_array($params['activity_log_settings'])) {
                $advanced_payload['activity_log_settings'] = [
                    'retention_days'     => max(7, min(365, intval($params['activity_log_settings']['retention_days'] ?? 30))),
                    'tamper_webhook_url' => esc_url_raw($params['activity_log_settings']['tamper_webhook_url'] ?? ''),
                ];
            }

            if (isset($params['waf_targeted_allowlist_rules'])) {
                $advanced_payload['waf_targeted_allowlist_rules'] = is_string($params['waf_targeted_allowlist_rules'])
                    ? $params['waf_targeted_allowlist_rules']
                    : wp_json_encode($params['waf_targeted_allowlist_rules']);
            }

            // Advanced controls from Step 9, 10, 11, 13
            if (isset($params['advanced_settings']) && is_array($params['advanced_settings'])) {
                $adv = $params['advanced_settings'];
                
                // Login Hardening & 2FA
                if (isset($adv['login_max_retries'])) {
                    $advanced_payload['login_max_retries'] = max(2, min(50, intval($adv['login_max_retries'])));
                }
                if (isset($adv['login_lockout_duration'])) {
                    $advanced_payload['login_lockout_duration'] = max(1, min(10080, intval($adv['login_lockout_duration'])));
                }
                if (isset($adv['auth_2fa_enabled'])) {
                    $advanced_payload['auth_2fa_enabled'] = (bool) $adv['auth_2fa_enabled'];
                }
                if (isset($adv['auth_2fa_enforce_admins'])) {
                    $advanced_payload['auth_2fa_enforce_admins'] = (bool) $adv['auth_2fa_enforce_admins'];
                }
                if (isset($adv['auth_2fa_policy_mode']) && in_array($adv['auth_2fa_policy_mode'], ['immediate', 'grace_period', 'remind_login'], true)) {
                    $advanced_payload['auth_2fa_policy_mode'] = $adv['auth_2fa_policy_mode'];
                }
                if (isset($adv['auth_2fa_grace_days'])) {
                    $advanced_payload['auth_2fa_grace_days'] = max(1, min(90, intval($adv['auth_2fa_grace_days'])));
                }

                // Password security & hardening
                $direct_bools = [
                    'waf_enforce_strong_passwords', 'waf_check_pwned_passwords',
                    'disable_file_editing', 'hide_wp_version', 'block_user_enumeration',
                    'header_hsts', 'header_nosniff', 'header_x_frame_options',
                    'header_referrer_policy', 'header_permissions_policy',
                    'auto_quarantine_critical', 'self_defense_watchdog_enabled'
                ];
                foreach ($direct_bools as $db_key) {
                    if (isset($adv[$db_key])) {
                        $advanced_payload[$db_key] = (bool) $adv[$db_key];
                    }
                }

                // AI Copilot settings
                if (isset($adv['ai_enabled'])) {
                    $advanced_payload['ai_enabled'] = (bool) $adv['ai_enabled'];
                }
                if (!empty($adv['ai_provider']) && in_array($adv['ai_provider'], ['openai', 'gemini', 'claude', 'wp_ai_connect', 'deepseek', 'openrouter'], true)) {
                    $advanced_payload['ai_provider'] = $adv['ai_provider'];
                }
                if (!empty($adv['openai_api_key'])) {
                    $advanced_payload['openai_api_key'] = sanitize_text_field($adv['openai_api_key']);
                }
                if (!empty($adv['gemini_api_key'])) {
                    $advanced_payload['gemini_api_key'] = sanitize_text_field($adv['gemini_api_key']);
                }
                if (!empty($adv['claude_api_key'])) {
                    $advanced_payload['claude_api_key'] = sanitize_text_field($adv['claude_api_key']);
                }
                if (!empty($adv['deepseek_api_key'])) {
                    $advanced_payload['deepseek_api_key'] = sanitize_text_field($adv['deepseek_api_key']);
                }
                if (!empty($adv['openrouter_api_key'])) {
                    $advanced_payload['openrouter_api_key'] = sanitize_text_field($adv['openrouter_api_key']);
                }
                if (!empty($adv['openai_model'])) {
                    $advanced_payload['openai_model'] = sanitize_text_field($adv['openai_model']);
                }
                if (!empty($adv['gemini_model'])) {
                    $advanced_payload['gemini_model'] = sanitize_text_field($adv['gemini_model']);
                }
                if (!empty($adv['claude_model'])) {
                    $advanced_payload['claude_model'] = sanitize_text_field($adv['claude_model']);
                }
                if (!empty($adv['deepseek_model'])) {
                    $advanced_payload['deepseek_model'] = sanitize_text_field($adv['deepseek_model']);
                }
                if (!empty($adv['openrouter_model'])) {
                    $advanced_payload['openrouter_model'] = sanitize_text_field($adv['openrouter_model']);
                }

                // Trusted proxy IPs
                if (!empty($adv['trusted_proxy_ips'])) {
                    $advanced_payload['trusted_proxy_ips'] = sanitize_textarea_field($adv['trusted_proxy_ips']);
                }
                // Excluded paths & extensions
                if (!empty($adv['excluded_paths'])) {
                    $advanced_payload['excluded_paths'] = sanitize_textarea_field($adv['excluded_paths']);
                }
                if (!empty($adv['custom_extensions'])) {
                    $advanced_payload['custom_extensions'] = sanitize_text_field($adv['custom_extensions']);
                }
            }

            // Save via SettingsManager
            if (!empty($advanced_payload) && class_exists('\\WebCareProScanner\\System\\SettingsManager')) {
                \WebCareProScanner\System\SettingsManager::save_settings($advanced_payload);
            }

            // 7. Security Alert Notifications & Webhooks
            if (!empty($params['alerts'])) {
                $alert_email = sanitize_email($params['alerts']['email'] ?? get_option('admin_email'));
                $notif_settings = get_option('webcareproscan_notification_settings', []);
                if (!is_array($notif_settings)) {
                    $notif_settings = [];
                }
                $notif_settings['email_recipient'] = $alert_email;
                $notif_settings['notify_critical'] = !empty($params['alerts']['notify_critical']);
                $notif_settings['notify_logins']   = !empty($params['alerts']['notify_logins']);
                $notif_settings['notify_panic']    = !empty($params['alerts']['notify_panic']);
                update_option('webcareproscan_notification_settings', $notif_settings, false);

                // Also save to SettingsManager for webhook dispatch
                $webhook_updates = [
                    'email_alerts_enabled' => true,
                    'alert_emails'         => $alert_email,
                ];
                if (!empty($params['alerts']['slack_webhook_url'])) {
                    $webhook_updates['slack_enabled']     = true;
                    $webhook_updates['slack_webhook_url'] = esc_url_raw($params['alerts']['slack_webhook_url']);
                }
                if (!empty($params['alerts']['discord_webhook_url'])) {
                    $webhook_updates['discord_enabled']     = true;
                    $webhook_updates['discord_webhook_url'] = esc_url_raw($params['alerts']['discord_webhook_url']);
                }
                if (!empty($params['alerts']['generic_webhook_url'])) {
                    $webhook_updates['generic_webhook_enabled'] = true;
                    $webhook_updates['generic_webhook_url']     = esc_url_raw($params['alerts']['generic_webhook_url']);
                }
                if (class_exists('\\WebCareProScanner\\System\\SettingsManager')) {
                    \WebCareProScanner\System\SettingsManager::save_settings($webhook_updates);
                }
            }

            // 8. Recompile Pre-Boot Micro-WAF Snapshot with all updated exemptions & rules
            if (class_exists('\\WebCareProScanner\\Firewall\\MicroWafCompiler')) {
                \WebCareProScanner\Firewall\MicroWafCompiler::compile();
            }

            // 9. Save Step Progress & Completion Status
            if (!empty($params['current_step'])) {
                update_option('webcareproscan_wizard_current_step', max(1, min(14, intval($params['current_step']))), false);
            }
            if (!empty($params['wizard_mode'])) {
                update_option('webcareproscan_wizard_mode', sanitize_key($params['wizard_mode']), false);
            }
            if (empty($params['is_intermediate_step'])) {
                update_option('webcareproscan_wizard_completed', true, false);
            }
        } finally {
            if (class_exists('\\WebCareProScanner\\System\\WebCareActivityLogger')) {
                \WebCareProScanner\System\WebCareActivityLogger::$suppress_option_watcher = false;
            }
        }

        // Consolidated single master activity event for initial security onboarding (only upon full completion)
        if (empty($params['is_intermediate_step']) && class_exists('\\WebCareProScanner\\System\\WebCareActivityLogger')) {
            $client_ip = \WebCareProScanner\Firewall\FirewallEngine::get_client_ip();
            $alert_email = sanitize_email($params['alerts']['email'] ?? get_option('admin_email'));
            $arch_label = ucfirst($archetype ?? 'business');
            $event_desc = sprintf(
                /* translators: 1: Site archetype profile label, 2: Client IP address, 3: Notification email */
                __('Completed initial security onboarding setup with %1$s profile: enabled core firewall shields, whitelisted administrator IP (%2$s), and configured security alerts for %3$s.', 'webcare-pro-security'),
                $arch_label,
                $client_ip,
                $alert_email
            );
            \WebCareProScanner\System\WebCareActivityLogger::notice(
                'onboarding_wizard_completed',
                'settings',
                [
                    'archetype'       => $archetype ?? 'business',
                    'whitelisted_ip'  => !empty($params['whitelist_ip']) ? $client_ip : null,
                    'alert_email'     => $alert_email,
                    'firewall_active' => true,
                    'description'     => $event_desc,
                ]
            );
        }

        return new \WP_REST_Response([
            'success' => true,
            'message' => __('WebCare Protection Quickstart successfully configured.', 'webcare-pro-security'),
        ], 200);
    }

    /**
     * Retrieve registered Module Ecosystem & Next-Gen Engines status.
     */
    public static function get_modules_ecosystem(\WP_REST_Request $request) {
        $modules = class_exists('\\WebCareProScanner\\Core\\ModuleRegistry')
            ? \WebCareProScanner\Core\ModuleRegistry::get_ecosystem_status()
            : [];
        return new \WP_REST_Response([
            'success' => true,
            'modules' => $modules,
        ], 200);
    }

    /**
     * Toggle a pluggable module on/off via its declared SettingsManager enable_key.
     */
    public static function toggle_ecosystem_module(\WP_REST_Request $request) {
        $params  = $request->get_json_params() ?: [];
        $mod_id  = sanitize_key((string) ($params['module_id'] ?? ''));
        $enabled = !empty($params['enabled']);
        if ($mod_id === '' || !class_exists('\\WebCareProScanner\\Core\\ModuleRegistry')) {
            return new \WP_REST_Response(['success' => false, 'message' => __('Module ID is required.', 'webcare-pro-security')], 400);
        }
        $mod = \WebCareProScanner\Core\ModuleRegistry::get_module($mod_id);
        if (!$mod) {
            return new \WP_REST_Response(['success' => false, 'message' => __('Module not found.', 'webcare-pro-security')], 404);
        }
        $manifest   = $mod->get_manifest();
        $enable_key = (string) ($manifest['enable_key'] ?? '');
        if ($enable_key === '') {
            return new \WP_REST_Response(['success' => false, 'message' => __('Core module is permanently active.', 'webcare-pro-security')], 400);
        }
        \WebCareProScanner\System\SettingsManager::save_settings([$enable_key => $enabled]);
        return new \WP_REST_Response([
            'success' => true,
            'modules' => \WebCareProScanner\Core\ModuleRegistry::get_ecosystem_status(),
        ], 200);
    }

    public static function get_server_info(\WP_REST_Request $request) {
        $refresh = (bool) $request->get_param('refresh');
        if ($refresh && function_exists('delete_transient')) {
            delete_transient('webcareproscan_server_filesystem_metrics');
        }
        return rest_ensure_response([
            'success' => true,
            'info'    => ServerInfo::get_info(true),
        ]);
    }

    /**
     * Get diagnostic telemetry snapshot for log export & incident triage.
     */
    public static function get_telemetry_snapshot(\WP_REST_Request $request): \WP_REST_Response {
        $snapshot = class_exists('\\WebCareProScanner\\System\\TelemetrySnapshot')
            ? \WebCareProScanner\System\TelemetrySnapshot::get_snapshot()
            : [];

        return rest_ensure_response([
            'success'  => true,
            'snapshot' => $snapshot,
        ]);
    }

    /**
     * Get comprehensive system readiness & compatibility audit report.
     */
    public static function get_system_readiness(\WP_REST_Request $request): \WP_REST_Response {
        $report = \WebCareProScanner\System\SystemReadinessChecker::check_all();
        return rest_ensure_response([
            'success' => true,
            'report'  => $report,
        ]);
    }

    /**
     * Dismiss first-time welcome modal.
     */
    public static function dismiss_welcome_modal(\WP_REST_Request $request): \WP_REST_Response {
        \WebCareProScanner\System\SystemReadinessChecker::dismiss_welcome();
        return rest_ensure_response([
            'success' => true,
            'message' => __('Welcome dialog dismissed successfully.', 'webcare-pro-security'),
        ]);
    }

    public static function get_backup_preflight(\WP_REST_Request $request) {
        $db_backup = new DatabaseBackup();
        $info = $db_backup->get_preflight_info();
        return rest_ensure_response([
            'success' => true,
            'info'    => $info,
        ]);
    }

    public static function start_backup_session(\WP_REST_Request $request) {
        $throttle_ms = $request->get_param('throttle_ms');
        $batch_size = $request->get_param('batch_size');
        $db_backup = new DatabaseBackup();
        $options = [];
        if ($throttle_ms !== null) {
            $options['throttle_ms'] = (int) $throttle_ms;
        }
        if ($batch_size !== null) {
            $options['batch_size'] = (int) $batch_size;
        }
        $res = $db_backup->start_session($options);
        return rest_ensure_response($res);
    }

    public static function step_backup_session(\WP_REST_Request $request) {
        $session_id = sanitize_text_field($request->get_param('session_id'));
        $throttle_ms = $request->get_param('throttle_ms');
        $db_backup = new DatabaseBackup();
        $res = $db_backup->step_session($session_id, $throttle_ms !== null ? (int) $throttle_ms : null);
        return rest_ensure_response($res);
    }

    public static function get_backup_session_status(\WP_REST_Request $request) {
        $session_id = sanitize_text_field($request->get_param('session_id'));
        $db_backup = new DatabaseBackup();
        $state = $db_backup->get_session_state($session_id);
        if (!$state) {
            return new \WP_Error('session_not_found', 'Backup session not found.', ['status' => 404]);
        }
        return rest_ensure_response([
            'success'   => true,
            'status'    => $state['status'],
            'state'     => $state,
        ]);
    }

    public static function get_active_backup(\WP_REST_Request $request) {
        $db_backup = new DatabaseBackup();
        $active = $db_backup->get_active_session();
        return rest_ensure_response([
            'success'   => true,
            'is_running'=> !empty($active) && ($active['status'] ?? '') === 'running',
            'session'   => $active,
        ]);
    }

    public static function cancel_backup_session(\WP_REST_Request $request) {
        $session_id = sanitize_text_field($request->get_param('session_id'));
        $db_backup = new DatabaseBackup();
        $res = $db_backup->cancel_session($session_id);
        return rest_ensure_response($res);
    }

    public static function create_backup(\WP_REST_Request $request) {
        $db_backup = new DatabaseBackup();
        $res = $db_backup->create_backup();
        return rest_ensure_response($res);
    }

    public static function list_backups(\WP_REST_Request $request) {
        $db_backup = new DatabaseBackup();
        return rest_ensure_response([
            'success' => true,
            'backups' => $db_backup->list_backups(),
        ]);
    }

    public static function delete_backup(\WP_REST_Request $request) {
        $filename = sanitize_text_field($request->get_param('filename'));
        $db_backup = new DatabaseBackup();
        $deleted = $db_backup->delete_backup($filename);
        return rest_ensure_response([
            'success' => $deleted,
            'message' => $deleted ? 'Backup deleted successfully.' : 'Could not delete backup.',
        ]);
    }

    public static function download_backup(\WP_REST_Request $request) {
        $filename = sanitize_text_field($request->get_param('filename'));
        $db_backup = new DatabaseBackup();
        $path = $db_backup->get_backup_path($filename);

        if (!$path || !file_exists($path)) {
            return new \WP_Error('not_found', 'Backup file not found.', ['status' => 404]);
        }

        header('Content-Description: File Transfer');
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($path) . '"');
        header('Expires: 0');
        header('Cache-Control: must-revalidate');
        header('Pragma: public');
        header('Content-Length: ' . filesize($path));
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_readfile -- Streaming raw binary backup file to HTTP client
        readfile($path);
        exit;
    }

    /**
     * Get plugin settings
     */
    public static function get_settings(\WP_REST_Request $request) {
        $settings = \WebCareProScanner\System\SettingsManager::get_settings();
        $time_info = self::build_schedule_time_info();

        $uid = get_current_user_id();
        $is_support = false;
        $restrictions = [];

        return rest_ensure_response([
            'success'                        => true,
            'settings'                       => $settings,
            'ai_connect_status'              => \WebCareProScanner\System\AIService::get_ai_connect_status(),
            'next_scheduled'                 => $time_info['next_scheduled_wp'],
            'schedule_time'                  => $time_info,
            'current_time'                   => $time_info['current_wp_time'],
            'is_temporary_support'           => false,
            'temporary_support_restrictions' => [],
        ]);
    }

    /**
     * Save plugin settings
     */
    public static function save_settings(\WP_REST_Request $request) {
        $params = $request->get_json_params();
        if (!is_array($params)) {
            $params = $request->get_body_params();
        }

        $old_settings = \WebCareProScanner\System\SettingsManager::get_settings();
        $saved = \WebCareProScanner\System\SettingsManager::save_settings((array) $params);
        $time_info = self::build_schedule_time_info();

        // Check toggles for Webhooks, AI Forensics, and MCP Service
        if (class_exists('\\WebCareProScanner\\Notifications\\NotificationDispatcher')) {
            $old_webhook = !empty($old_settings['generic_webhook_enabled']) || !empty($old_settings['slack_enabled']) || !empty($old_settings['discord_enabled']);
            $new_webhook = !empty($saved['generic_webhook_enabled']) || !empty($saved['slack_enabled']) || !empty($saved['discord_enabled']);
            if ($old_webhook !== $new_webhook) {
                \WebCareProScanner\Notifications\NotificationDispatcher::trigger('webhook_status_toggled', [
                    'severity' => 'info',
                    /* translators: %s: status string */
                    'message'  => sprintf(__('DevSecOps Webhook channels were %s.', 'webcare-pro-security'), $new_webhook ? __('enabled', 'webcare-pro-security') : __('disabled', 'webcare-pro-security')),
                    'details'  => [
                        'State' => $new_webhook ? 'Enabled' : 'Disabled',
                    ],
                ]);
            }

            if (!empty($old_settings['ai_enabled']) !== !empty($saved['ai_enabled'])) {
                $ai_on = !empty($saved['ai_enabled']);
                \WebCareProScanner\Notifications\NotificationDispatcher::trigger('ai_forensics_toggled', [
                    'severity' => 'info',
                    /* translators: %s: status string */
                    'message'  => sprintf(__('AI Code Forensics engine was %s.', 'webcare-pro-security'), $ai_on ? __('enabled', 'webcare-pro-security') : __('disabled', 'webcare-pro-security')),
                    'details'  => [
                        'State'    => $ai_on ? 'Enabled' : 'Disabled',
                        'Provider' => $saved['ai_provider'] ?? 'gemini',
                    ],
                ]);
            }

            if (!empty($old_settings['mcp_enabled']) !== !empty($saved['mcp_enabled'])) {
                $mcp_on = !empty($saved['mcp_enabled']);
                \WebCareProScanner\Notifications\NotificationDispatcher::trigger('mcp_service_toggled', [
                    'severity' => 'info',
                    /* translators: %s: status string */
                    'message'  => sprintf(__('Model Context Protocol (MCP) Agent Service was %s.', 'webcare-pro-security'), $mcp_on ? __('enabled', 'webcare-pro-security') : __('disabled', 'webcare-pro-security')),
                    'details'  => [
                        'State' => $mcp_on ? 'Enabled' : 'Disabled',
                    ],
                ]);
            }
        }

        return rest_ensure_response([
            'success'           => true,
            'message'           => __('Settings successfully saved.', 'webcare-pro-security'),
            'settings'          => $saved,
            'ai_connect_status' => \WebCareProScanner\System\AIService::get_ai_connect_status(),
            'next_scheduled'    => $time_info['next_scheduled_wp'],
            'schedule_time'     => $time_info,
        ]);
    }

    /**
     * Export settings as downloadable JSON payload
     */
    public static function export_settings(\WP_REST_Request $request) {
        $data = \WebCareProScanner\System\SettingsManager::export_settings();
        return rest_ensure_response([
            'success' => true,
            'export'  => $data,
        ]);
    }

    /**
     * Import settings from uploaded JSON payload
     */
    public static function import_settings(\WP_REST_Request $request) {
        $payload = $request->get_json_params();
        if (empty($payload)) {
            $raw = $request->get_body();
            if (!empty($raw)) {
                $payload = json_decode($raw, true);
            }
            if (empty($payload)) {
                $payload = $request->get_body_params();
            }
        }
        if (empty($payload) || !is_array($payload)) {
            return new \WP_Error('invalid_import', __('Invalid JSON data.', 'webcare-pro-security'), ['status' => 400]);
        }

        try {
            $imported = \WebCareProScanner\System\SettingsManager::import_settings($payload);
            return rest_ensure_response([
                'success'  => true,
                'message'  => __('Settings successfully imported and applied.', 'webcare-pro-security'),
                'settings' => $imported,
            ]);
        } catch (\Exception $e) {
            return new \WP_Error('import_failed', $e->getMessage(), ['status' => 400]);
        }
    }

    /**
     * Reset settings to factory defaults
     */
    public static function reset_settings(\WP_REST_Request $request) {
        $defaults = \WebCareProScanner\System\SettingsManager::reset_defaults();
        return rest_ensure_response([
            'success'  => true,
            'message'  => __('Settings have been reset to factory defaults.', 'webcare-pro-security'),
            'settings' => $defaults,
        ]);
    }

    /**
     * Manually trigger the scheduled cron scan immediately (for test / on-demand cron execution)
     */
    public static function trigger_cron_now(\WP_REST_Request $request) {
        $locked_id = ScanLock::get_locked_scan_id();
        if ($locked_id) {
            return new \WP_Error(
                'scan_locked',
                sprintf(
                    /* translators: %d: active scan ID */
                    __('A scan is already actively running (ID: %d).', 'webcare-pro-security'),
                    $locked_id
                ),
                ['status' => 409]
            );
        }

        // Run scheduled scan synchronously or trigger the hook
        try {
            \WebCareProScanner\System\Scheduler::run_scheduled_scan();
            return rest_ensure_response([
                'success' => true,
                'message' => __('Scheduled security scan was triggered and executed successfully.', 'webcare-pro-security'),
            ]);
        } catch (\Throwable $e) {
            return new \WP_Error('cron_trigger_failed', $e->getMessage(), ['status' => 500]);
        }
    }

    /**
     * Audit HTTP security headers & site hardening status
     */
    public static function get_hardening_audit(\WP_REST_Request $request) {
        $audit = \WebCareProScanner\Hardening\SecurityHeadersEngine::audit_hardening_status();
        return rest_ensure_response([
            'success' => true,
            'audit'   => $audit,
        ]);
    }

    /**
     * Apply recommended A+ hardening preset
     */
    public static function apply_hardening_preset(\WP_REST_Request $request) {
        $current = \WebCareProScanner\System\SettingsManager::get_settings();
        
        $preset = [
            'header_hsts'                      => true,
            'header_hsts_preload'              => false,
            'header_x_frame_options'           => true,
            'header_x_frame_options_mode'      => 'SAMEORIGIN',
            'header_nosniff'                   => true,
            'header_referrer_policy'           => true,
            'header_referrer_policy_value'     => 'strict-origin-when-cross-origin',
            'header_permissions_policy'        => true,
            'header_permissions_policy_value'  => 'geolocation=(), camera=(), microphone=(), payment=()',
            'header_xss_protection'            => true,
            'disable_file_editing'             => true,
            'block_user_enumeration'           => true,
            'hide_wp_version'                  => true,
            'block_sensitive_files'            => true,
            'waf_disable_xmlrpc'               => true,
        ];

        $updated = array_merge($current, $preset);
        $saved = \WebCareProScanner\System\SettingsManager::save_settings($updated);
        $audit = \WebCareProScanner\Hardening\SecurityHeadersEngine::audit_hardening_status();

        return rest_ensure_response([
            'success'  => true,
            'message'  => __('Recommended A+ Security Hardening preset applied successfully.', 'webcare-pro-security'),
            'settings' => $saved,
            'audit'    => $audit,
        ]);
    }

    public static function get_incident_report(\WP_REST_Request $request) {
        $format = sanitize_text_field($request->get_param('format') ?: 'json');
        $client_name = sanitize_text_field($request->get_param('client_name') ?: '');
        $auditor_notes = sanitize_textarea_field($request->get_param('auditor_notes') ?: '');

        $options = [
            'client_name'   => $client_name,
            'auditor_notes' => $auditor_notes,
        ];

        $report = IncidentReportEngine::generate_report($options);

        if ($format === 'html') {
            $html = IncidentReportEngine::render_html($report);
            header('Content-Type: text/html; charset=UTF-8');
            // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
            echo $html;
            exit;
        }

        return rest_ensure_response($report);
    }

    /**
     * Moderate or delete a spam/malicious WordPress comment.
     */
    public static function moderate_comment(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $comment_id = !empty($params['comment_id']) ? (int) $params['comment_id'] : 0;
        $action = !empty($params['action']) ? sanitize_key($params['action']) : '';
        $issue_id = !empty($params['issue_id']) ? (int) $params['issue_id'] : null;

        if (!$comment_id) {
            return new \WP_Error('missing_comment_id', __('Valid comment ID is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $comment = get_comment($comment_id);
        if (!$comment && $action !== 'delete') {
            return new \WP_Error('comment_not_found', __('Comment not found or already deleted.', 'webcare-pro-security'), ['status' => 404]);
        }

        $success = false;
        $message = '';

        switch ($action) {
            case 'trash':
                $success = (bool) wp_trash_comment($comment_id);
                /* translators: %d: comment ID */
                $message = sprintf(__('Comment #%d has been moved to Trash (quarantined from public view).', 'webcare-pro-security'), $comment_id);
                break;

            case 'spam':
                $success = (bool) wp_spam_comment($comment_id);
                /* translators: %d: comment ID */
                $message = sprintf(__('Comment #%d has been marked as Spam and delisted.', 'webcare-pro-security'), $comment_id);
                break;

            case 'delete':
                $success = (bool) wp_delete_comment($comment_id, true);
                /* translators: %d: comment ID */
                $message = sprintf(__('Comment #%d has been permanently deleted from the database.', 'webcare-pro-security'), $comment_id);
                break;

            case 'approve':
                $success = (bool) wp_set_comment_status($comment_id, 'approve');
                /* translators: %d: comment ID */
                $message = sprintf(__('Comment #%d status updated to approved.', 'webcare-pro-security'), $comment_id);
                break;

            default:
                return new \WP_Error('invalid_action', __('Invalid moderation action. Supported: trash, spam, delete.', 'webcare-pro-security'), ['status' => 400]);
        }

        if ($success) {
            global $wpdb;
            $table = $wpdb->prefix . 'webcareproscan_scan_issues';
            if ($issue_id) {
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                $wpdb->update($table, ['status' => 'repaired'], ['id' => $issue_id]);
            }
            // Mark all open findings associated with this comment as solved/repaired
            $com_up_sql = "UPDATE {$table} SET status = 'repaired' WHERE (file_path LIKE %s OR file_path = %s) AND status = 'open'";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $wpdb->query(
                // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                $wpdb->prepare($com_up_sql, "comment:{$comment_id}%", "comment:{$comment_id}")
            );
        }

        return rest_ensure_response([
            'success'    => $success,
            'message'    => $message,
            'action'     => $action,
            'comment_id' => $comment_id,
        ]);
    }

    /**
     * Webhook Testing Endpoint
     */
    public static function test_chat_webhook(\WP_REST_Request $request) {
        $params   = $request->get_json_params() ?: [];
        $platform = sanitize_text_field($params['platform'] ?? 'slack');
        $url      = !empty($params['webhook_url']) ? esc_url_raw(trim($params['webhook_url'])) : null;

        $result = \WebCareProScanner\Notifications\WebhookService::send_test($platform, $url);
        return rest_ensure_response($result);
    }

    /**
     * Get granular notification settings & catalog
     */
    public static function get_notification_settings(\WP_REST_Request $request) {
        $settings = \WebCareProScanner\System\SettingsManager::get_settings();
        $catalog  = \WebCareProScanner\Notifications\NotificationDispatcher::get_event_catalog();

        return rest_ensure_response([
            'success'                     => true,
            'notification_master_enabled' => !empty($settings['notification_master_enabled']),
            'notification_events'         => $settings['notification_events'] ?? \WebCareProScanner\System\SettingsManager::get_default_notification_events(),
            'catalog'                     => $catalog,
            'alert_emails'                => $settings['alert_emails'] ?? get_option('admin_email'),
            'webhooks_configured'         => [
                'slack'   => !empty($settings['slack_enabled']) && !empty($settings['slack_webhook_url']),
                'discord' => !empty($settings['discord_enabled']) && !empty($settings['discord_webhook_url']),
                'clickup' => !empty($settings['clickup_enabled']) && !empty($settings['clickup_webhook_url']),
                'asana'   => !empty($settings['asana_enabled']) && !empty($settings['asana_webhook_url']),
                'generic' => !empty($settings['generic_webhook_enabled']) && !empty($settings['generic_webhook_url']),
            ],
        ]);
    }

    /**
     * Save granular notification settings
     */
    public static function save_notification_settings(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $current = \WebCareProScanner\System\SettingsManager::get_settings();

        if (isset($params['notification_master_enabled'])) {
            $current['notification_master_enabled'] = !empty($params['notification_master_enabled']);
        }
        if (isset($params['notification_events']) && is_array($params['notification_events'])) {
            $current['notification_events'] = \WebCareProScanner\System\SettingsManager::sanitize_notification_events($params['notification_events']);
        }
        if (isset($params['alert_emails'])) {
            $current['alert_emails'] = sanitize_text_field($params['alert_emails']);
        }

        $saved = \WebCareProScanner\System\SettingsManager::save_settings($current);

        return rest_ensure_response([
            'success'                     => true,
            'message'                     => __('Notification settings saved successfully.', 'webcare-pro-security'),
            'notification_master_enabled' => !empty($saved['notification_master_enabled']),
            'notification_events'         => $saved['notification_events'],
        ]);
    }

    /**
     * Test a specific notification event
     */
    public static function test_notification_event(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $event_key = sanitize_text_field($params['event_key'] ?? '');

        if (empty($event_key)) {
            return new \WP_Error('missing_event', __('Event key is required for notification testing.', 'webcare-pro-security'), ['status' => 400]);
        }

        $catalog = \WebCareProScanner\Notifications\NotificationDispatcher::get_event_catalog();
        if (!isset($catalog[$event_key])) {
            return new \WP_Error('invalid_event', __('Unknown security event identifier.', 'webcare-pro-security'), ['status' => 404]);
        }

        $result = \WebCareProScanner\Notifications\NotificationDispatcher::trigger($event_key, [
            /* translators: %s: event title */
            'title'   => sprintf(__('[TEST] %s', 'webcare-pro-security'), $catalog[$event_key]['title']),
            /* translators: %s: event title */
            'message' => sprintf(__('This is an instant verification alert triggered from the WebCare Notification Center for "%s".', 'webcare-pro-security'), $catalog[$event_key]['title']),
            'details' => [
                'triggered_by' => wp_get_current_user()->user_login ?: 'admin',
                'event_code'   => $event_key,
                'test_mode'    => 'manual_verification',
            ],
        ]);

        return rest_ensure_response([
            'success' => true,
            /* translators: %s: event title */
            'message' => sprintf(__('Test notification dispatched for event: %s', 'webcare-pro-security'), $catalog[$event_key]['title']),
            'result'  => $result,
        ]);
    }

    public static function run_security_drill(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $vectors = is_array($params['vectors'] ?? null) ? $params['vectors'] : [];
        $report = \WebCareProScanner\Security\AttackSimulationEngine::run_simulation($vectors);

        return rest_ensure_response([
            'success' => true,
            'report'  => $report,
        ]);
    }

    public static function get_security_drill_results(\WP_REST_Request $request) {
        $report = \WebCareProScanner\Security\AttackSimulationEngine::get_latest_results();
        return rest_ensure_response([
            'success' => true,
            'report'  => $report,
        ]);
    }

    public static function get_containment_status(\WP_REST_Request $request) {
        return rest_ensure_response([
            'success' => true,
            'status'  => \WebCareProScanner\Security\EmergencyContainmentManager::get_status(),
        ]);
    }

    public static function toggle_containment(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $action = sanitize_text_field($params['action'] ?? '');
        $reason = sanitize_text_field($params['reason'] ?? 'Administrator Security Incident Action');
        $maintenance = !empty($params['maintenance_enabled']);

        if ($action === 'activate') {
            $res = \WebCareProScanner\Security\EmergencyContainmentManager::activate([
                'reason'              => $reason,
                'maintenance_enabled' => $maintenance,
            ]);
        } elseif ($action === 'deactivate') {
            $res = \WebCareProScanner\Security\EmergencyContainmentManager::deactivate(get_current_user_id());
        } else {
            return new \WP_Error('invalid_action', __('Invalid containment action. Must be "activate" or "deactivate".', 'webcare-pro-security'), ['status' => 400]);
        }

        return rest_ensure_response($res);
    }

    public static function get_vault_status(\WP_REST_Request $request) {
        // 1. Quarantine stats
        $qm = new \WebCareProScanner\Quarantine\QuarantineManager();
        $quarantine_records = $qm->list_records();
        $q_active = 0;
        $q_restored = 0;
        foreach ($quarantine_records as $qr) {
            if (($qr['status'] ?? '') === 'quarantined') {
                $q_active++;
            } elseif (($qr['status'] ?? '') === 'restored') {
                $q_restored++;
            }
        }

        // 2. Database backup stats
        $db_backup = new \WebCareProScanner\Backup\DatabaseBackup();
        $db_backups = $db_backup->list_backups();
        $db_count = count($db_backups);
        $db_size_mb = 0;
        foreach ($db_backups as $b) {
            $db_size_mb += floatval($b['size_mb'] ?? 0);
        }

        // 3. Transactions & Missing Users stats
        $transactions = \WebCareProScanner\Remediation\TransactionalRemediation::list_transactions(50);
        $tx_count = count($transactions);
        $user_mgr = new \WebCareProScanner\WordPress\UserRemediationManager();
        $missing_users = $user_mgr->get_missing_user_backups();
        $missing_users_count = count($missing_users);

        // 4. Secret Vault & Key Rotator stats
        $key_source = 'wp_salt';
        $env_key = getenv('WEBCARE_VAULT_KEY');
        if (!empty($env_key)) {
            $key_source = 'env';
        } elseif (defined('WEBCARE_VAULT_KEY') && !empty(WEBCARE_VAULT_KEY)) {
            $key_source = 'constant';
        }

        $raw_key = \WebCareProScanner\Security\SecretVault::get_key();
        $key_fingerprint = substr(hash('sha256', $raw_key), 0, 16) . '...';
        $is_hex_key = defined('WEBCARE_VAULT_KEY') && strlen((string) WEBCARE_VAULT_KEY) === 64 && ctype_xdigit((string) WEBCARE_VAULT_KEY);

        $openssl_ok = function_exists('openssl_encrypt');
        $gcm_ok = $openssl_ok && in_array(\WebCareProScanner\Security\SecretVault::CIPHER_GCM, openssl_get_cipher_methods(), true);

        $settings = get_option(\WebCareProScanner\System\SettingsManager::OPTION_KEY, []);
        $secret_fields = [
            'gemini_api_key'       => 'Google Gemini AI Key',
            'openai_api_key'       => 'OpenAI API Key',
            'claude_api_key'       => 'Anthropic Claude Key',
            'cloudflare_api_token' => 'Cloudflare API Token',
            'cloudflare_zone_id'   => 'Cloudflare Zone ID',
            'slack_webhook_url'    => 'Slack Webhook URL',
            'discord_webhook_url'  => 'Discord Webhook URL',
            'clickup_webhook_url'  => 'ClickUp Webhook URL',
            'asana_webhook_url'    => 'Asana Webhook URL',
            'generic_webhook_url'  => 'Generic Automation Webhook',
        ];

        $secrets_status = [];
        $encrypted_count = 0;
        foreach ($secret_fields as $field_key => $label) {
            $val = (string) ($settings[$field_key] ?? '');
            $is_set = !empty($val);
            $is_enc = $is_set && \WebCareProScanner\Security\SecretVault::is_encrypted($val);
            if ($is_enc) {
                $encrypted_count++;
            }
            $secrets_status[] = [
                'key'          => $field_key,
                'label'        => $label,
                'is_configured'=> $is_set,
                'is_encrypted' => $is_enc,
            ];
        }

        $rot_state = get_option(\WebCareProScanner\Security\VaultRotator::STATE_OPTION, ['status' => 'idle']);

        return rest_ensure_response([
            'success' => true,
            'quarantine' => [
                'total_records'  => count($quarantine_records),
                'active_threats' => $q_active,
                'restored_files' => $q_restored,
            ],
            'database' => [
                'count'    => $db_count,
                'total_mb' => round($db_size_mb, 2),
            ],
            'rollback' => [
                'transactions_count'  => $tx_count,
                'missing_users_count' => $missing_users_count,
                'missing_users'       => array_map(fn($u) => [
                    'user_id'    => $u['user_id'],
                    'user_login' => $u['user_login'],
                    'user_email' => $u['user_email'],
                ], $missing_users),
            ],
            'secrets' => [
                'cipher'              => 'AES-256-GCM AEAD',
                'key_source'          => $key_source,
                'key_fingerprint'     => $key_fingerprint,
                'is_constant_defined' => defined('WEBCARE_VAULT_KEY') && !empty(WEBCARE_VAULT_KEY),
                'is_hex_256'          => $is_hex_key,
                'openssl_available'   => $openssl_ok,
                'gcm_available'       => $gcm_ok,
                'encrypted_count'     => $encrypted_count,
                'fields'              => $secrets_status,
                'rotation_state'      => $rot_state,
            ],
        ]);
    }

    public static function rotate_vault_key(\WP_REST_Request $request) {
        $params  = $request->get_json_params() ?: $request->get_params();
        $new_key = sanitize_text_field($params['new_key'] ?? '');
        $force   = !empty($params['force']);

        if (empty($new_key)) {
            $new_key = bin2hex(random_bytes(32));
        }

        $init = \WebCareProScanner\Security\VaultRotator::start_rotation($new_key, $force);
        if (is_wp_error($init)) {
            return $init;
        }

        $cont = \WebCareProScanner\Security\VaultRotator::continue_rotation(100);
        if (is_wp_error($cont)) {
            return $cont;
        }

        $commit = \WebCareProScanner\Security\VaultRotator::verify_and_commit();
        if (is_wp_error($commit)) {
            return $commit;
        }

        if (class_exists('\\WebCareProScanner\\Notifications\\NotificationDispatcher')) {
            \WebCareProScanner\Notifications\NotificationDispatcher::trigger('vault_secrets_rotated', [
                'severity' => 'high',
                'message'  => __('Secrets Vault Master Key / Cryptographic Salt was successfully rotated and re-encrypted.', 'webcare-pro-security'),
                'details'  => [
                    'Rotated At'     => current_time('mysql'),
                    'Rotated By'     => wp_get_current_user()->user_login ?: 'admin',
                    'Key Algorithm'  => 'AES-256-GCM',
                ],
            ]);
        }

        return rest_ensure_response([
            'success'          => true,
            'message'          => __('Vault encryption keys rotated and all credentials safely re-encrypted.', 'webcare-pro-security'),
            'new_key_material' => $new_key,
            'status'           => $commit,
        ]);
    }

    public static function rollback_vault_rotation(\WP_REST_Request $request) {
        $res = \WebCareProScanner\Security\VaultRotator::rollback();
        if (is_wp_error($res)) {
            return $res;
        }
        return rest_ensure_response([
            'success' => true,
            'message' => __('Vault key rotation rolled back to pre-rotation state.', 'webcare-pro-security'),
            'status'  => $res,
        ]);
    }

    public static function reset_vault_rotation(\WP_REST_Request $request) {
        \WebCareProScanner\Security\VaultRotator::reset_state();
        return rest_ensure_response([
            'success' => true,
            'message' => __('Vault rotation state and locks cleared successfully.', 'webcare-pro-security'),
            'status'  => \WebCareProScanner\Security\VaultRotator::get_status(),
        ]);
    }

    public static function get_correlation_hierarchy() {
        $engine = new \WebCareProScanner\Findings\CorrelationEngine();
        return rest_ensure_response($engine->generate_telemetry_hierarchy());
    }

    public static function get_activity_logs(\WP_REST_Request $request) {
        $limit      = max(1, min(100, intval($request->get_param('limit') ?: 50)));
        $page       = max(1, intval($request->get_param('page') ?: 1));
        $category   = sanitize_key($request->get_param('category') ?: '');
        $actor_type = sanitize_key($request->get_param('actor_type') ?: '');
        $severity   = sanitize_key($request->get_param('severity') ?: '');
        $search     = sanitize_text_field($request->get_param('search') ?: '');

        $result = \WebCareProScanner\System\WebCareActivityLogger::query_records([
            'actor_type' => $actor_type,
            'category'   => $category,
            'limit'      => $limit,
            'page'       => $page,
            'search'     => $search,
            'severity'   => $severity,
        ]);

        $settings = get_option('webcareproscan_activity_log_settings', []);
        $tamper_alert = get_option('webcareproscan_activity_tamper_active', null);

        return rest_ensure_response([
            'current_page'   => $result['current_page'] ?? $page,
            'has_next'       => $result['has_next'] ?? false,
            'has_prev'       => $result['has_prev'] ?? false,
            'per_page'       => $result['per_page'] ?? $limit,
            'records'        => $result['records'],
            'settings'       => [
                'retention_days'     => isset($settings['retention_days']) ? (int) $settings['retention_days'] : 30,
                'tamper_webhook_url' => $settings['tamper_webhook_url'] ?? '',
            ],
            'success'        => true,
            'tamper_alert'   => $tamper_alert,
            'total'          => $result['total'] ?? count($result['records']),
            'total_pages'    => $result['total_pages'] ?? 1,
            'total_read'     => $result['total_read'],
        ]);
    }

    public static function verify_activity_logs_integrity(\WP_REST_Request $request) {
        $report = \WebCareProScanner\System\WebCareActivityLogger::verify_integrity();
        return rest_ensure_response([
            'report'  => $report,
            'success' => true,
        ]);
    }

    public static function export_activity_logs(\WP_REST_Request $request) {
        $format              = sanitize_key($request->get_param('format') ?: 'csv');
        $category            = sanitize_key($request->get_param('category') ?: '');
        $actor_type          = sanitize_key($request->get_param('actor_type') ?: '');
        $severity            = sanitize_key($request->get_param('severity') ?: '');
        $search              = sanitize_text_field($request->get_param('search') ?: '');
        $date                = sanitize_text_field($request->get_param('date') ?: '');
        $include_system_info = !empty($request->get_param('include_system_info'));

        $result = \WebCareProScanner\System\WebCareActivityLogger::query_records([
            'actor_type' => $actor_type,
            'category'   => $category,
            'is_export'  => true,
            'limit'      => 10000,
            'search'     => $search,
            'severity'   => $severity,
            'date'       => $date,
        ]);

        $host_raw   = wp_parse_url(get_site_url(), PHP_URL_HOST) ?: 'site';
        $domain     = strtolower(preg_replace('/[^a-z0-9]/i', '-', preg_replace('/^www\./i', '', $host_raw)));
        $date_token = $date && preg_match('/^\d{4}-\d{2}-\d{2}$/', $date) ? $date : gmdate('Y-m-d');
        $time_token = gmdate('His');
        $rand_token = substr(wp_generate_password(8, false), 0, 5);
        $filename   = "activity-logs-{$date_token}-{$time_token}-{$domain}-{$rand_token}.{$format}";

        if ($format === 'json') {
            \WebCareProScanner\System\ActivityLogs\ActivityExporter::stream_json($result['records'], $filename, $include_system_info);
        } else {
            \WebCareProScanner\System\ActivityLogs\ActivityExporter::stream_csv($result['records'], $filename, $include_system_info);
        }
        exit;
    }

    public static function prune_activity_logs(\WP_REST_Request $request) {
        $results = \WebCareProScanner\System\ActivityLogs\ActivityRetention::prune_expired_partitions();

        // Audit Trail: Log manual partition prune execution
        \WebCareProScanner\System\WebCareActivityLogger::notice(
            'logs_pruned',
            'retention',
            [
                'description'  => sprintf('Pruned %d expired partition file(s) beyond 7-day minimum immutability.', $results['pruned_count']),
                'pruned_count' => (int) $results['pruned_count'],
                'pruned_files' => $results['files'],
            ]
        );

        /* translators: %d: Number of pruned partitions */
        $message = sprintf(__('Pruned %d expired partition(s).', 'webcare-pro-security'), $results['pruned_count']);

        return rest_ensure_response([
            'message'      => $message,
            'pruned_count' => $results['pruned_count'],
            'pruned_files' => $results['files'],
            'success'      => true,
        ]);
    }

    public static function acknowledge_activity_tamper_alert(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $incident_id = sanitize_key($params['incident_id'] ?? '');

        \WebCareProScanner\System\ActivityLogs\ActivityTamperNotifier::acknowledge_alert($incident_id);

        return rest_ensure_response([
            'message' => __('Tamper security incident acknowledged and dismissed.', 'webcare-pro-security'),
            'success' => true,
        ]);
    }

    /**
     * Get Site Archetype Intelligence evaluation & recommendation matrix.
     *
     * @param \WP_REST_Request $request
     * @return \WP_REST_Response
     */
    public static function get_site_advisor_evaluation(\WP_REST_Request $request) {
        $evaluation = \WebCareProScanner\Advisor\SiteAdvisorEngine::evaluate();
        return rest_ensure_response($evaluation);
    }

    /**
     * Atomically apply approved recommendations with a versioned snapshot.
     *
     * @param \WP_REST_Request $request
     * @return \WP_REST_Response
     */
    public static function apply_site_advisor_recommendations(\WP_REST_Request $request) {
        $params   = $request->get_json_params() ?: [];
        $approved = $params['approved'] ?? [];

        if (!is_array($approved)) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => __('Invalid approved recommendations payload.', 'webcare-pro-security'),
            ], 400);
        }

        $result = \WebCareProScanner\Advisor\SiteAdvisorEngine::apply_recommendations($approved);
        return rest_ensure_response($result);
    }

    /**
     * Rollback the last Site Advisor snapshot with conflict awareness.
     *
     * @param \WP_REST_Request $request
     * @return \WP_REST_Response
     */
    public static function rollback_site_advisor_snapshot(\WP_REST_Request $request) {
        $result = \WebCareProScanner\Advisor\SiteAdvisorEngine::rollback();
        return rest_ensure_response($result);
    }
}
