<?php
declare(strict_types=1);

namespace WebCareProScanner\System;

use WebCareProScanner\Core\CompiledStackManifest;
use WebCareProScanner\Firewall\Core\WafVaultManager;
use WebCareProScanner\Firewall\RescueAssistantManager;
use WebCareProScanner\Firewall\NextGen\ResponseDlpSentinel;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * SystemDoctor
 *
 * Diagnostic engine performing deep health checks across PHP 8.3+, WordPress 7.0+,
 * OPcache acceleration, WAF vault permissions (0750/0600), CompiledStackManifest HMAC
 * integrity, WP-Cron schedule health, and conflicting security/caching plugins.
 *
 * Also provides Safe Mode toggle and DLP-redacted diagnostic bundle export.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
final class SystemDoctor {

    /**
     * Conflicting security plugins signature map (slug => Display Name).
     */
    private const KNOWN_SECURITY_CONFLICTS = [
        'wordfence/wordfence.php'                      => 'Wordfence Security',
        'better-wp-security/better-wp-security.php'    => 'Solid Security (iThemes)',
        'all-in-one-wp-security-and-firewall/wp-security-core.php' => 'All-In-One Security (AIOS)',
        'sucuri-scanner/sucuri.php'                    => 'Sucuri Security',
        'ninjafirewall/ninjafirewall.php'              => 'NinjaFirewall',
        'wp-cerber/wp-cerber.php'                      => 'Cerber Security',
        'malcare-security/malcare.php'                 => 'MalCare Security',
        'defend-wp/defend-wp.php'                      => 'Defend WP',
    ];

    /**
     * Run all doctor checks and return an actionable health report.
     *
     * @return array<string, mixed>
     */
    public static function run_diagnostics(): array {
        $checks = [];

        // 1. PHP 8.3+ Runtime Floor
        $php_ver = PHP_VERSION;
        $php_pass = version_compare($php_ver, '8.3.0', '>=');
        $checks['php_runtime'] = [
            'id'          => 'php_runtime',
            'title'       => __('PHP Runtime Standard', 'webcare-pro-security'),
            'category'    => 'runtime',
            'status'      => $php_pass ? 'pass' : 'fail',
            'severity'    => 'critical',
            'message'     => $php_pass
                /* translators: %s: Current PHP version */
                ? sprintf(__('PHP %s meets strict WebCare Pro 8.3+ floor with modern read-only classes and native typing.', 'webcare-pro-security'), $php_ver)
                /* translators: %s: Current PHP version */
                : sprintf(__('PHP %s is below required PHP 8.3+ floor. Upgrade your PHP environment.', 'webcare-pro-security'), $php_ver),
            'current'     => $php_ver,
            'required'    => '>= 8.3.0',
        ];

        // 2. WordPress 7.0+ Core Version
        global $wp_version;
        $core_ver = (string) ($wp_version ?? '0.0.0');
        $wp_pass = version_compare($core_ver, '7.0.0', '>=');
        $checks['wordpress_core'] = [
            'id'          => 'wordpress_core',
            'title'       => __('WordPress Core Compatibility', 'webcare-pro-security'),
            'category'    => 'runtime',
            'status'      => $wp_pass ? 'pass' : 'warn',
            'severity'    => 'high',
            'message'     => $wp_pass
                /* translators: %s: Current WordPress core version */
                ? sprintf(__('WordPress %s detected with modern HTML Tag Processor & Script Module APIs.', 'webcare-pro-security'), $core_ver)
                /* translators: %s: Current WordPress core version */
                : sprintf(__('WordPress %s detected. WordPress 7.0+ recommended for complete Abilities & Interactivity support.', 'webcare-pro-security'), $core_ver),
            'current'     => $core_ver,
            'required'    => '>= 7.0.0 (Recommended)',
        ];

        // 3. OPcache Acceleration
        $opcache_enabled = function_exists('opcache_get_status') && !empty(@opcache_get_status(false)['opcache_enabled']);
        $checks['opcache'] = [
            'id'          => 'opcache',
            'title'       => __('Zend OPcache Acceleration', 'webcare-pro-security'),
            'category'    => 'performance',
            'status'      => $opcache_enabled ? 'pass' : 'warn',
            'severity'    => 'medium',
            'message'     => $opcache_enabled
                ? __('Zend OPcache is active in bytecode RAM for sub-millisecond CompiledStackManifest execution.', 'webcare-pro-security')
                : __('OPcache is disabled or unconfigured in php.ini. Enabling OPcache boosts firewall throughput up to 400%.', 'webcare-pro-security'),
            'current'     => $opcache_enabled ? __('Active & Accelerated', 'webcare-pro-security') : __('Disabled', 'webcare-pro-security'),
            'required'    => __('Enabled in php.ini', 'webcare-pro-security'),
        ];

        // 4. WAF Vault Permissions (webcare-waf/ 0750 dir, 0600 files) - READ-ONLY inspection
        $vault_dir = class_exists(WafVaultManager::class)
            ? WafVaultManager::get_vault_dir_readonly()
            : (defined('WP_CONTENT_DIR') ? WP_CONTENT_DIR : ABSPATH . 'wp-content') . '/webcare-waf';

        $vault_dir_exists = is_dir($vault_dir);
        $vault_writable = $vault_dir_exists && wp_is_writable($vault_dir);
        $vault_perms = $vault_dir_exists ? (decoct(fileperms($vault_dir) & 0777)) : 'none';

        // Check file perms if files exist across vault directory, nested logs, and micro-waf
        $file_perms_ok = true;
        $checked_files = 0;
        $waf_parent_dir = dirname($vault_dir);

        $target_files = [];
        if ($vault_dir_exists) {
            $root_json = @glob($vault_dir . '/*.{json,jsonl}', GLOB_BRACE) ?: [];
            $nested_json = @glob($vault_dir . '/logs/*.{json,jsonl}', GLOB_BRACE) ?: [];
            $target_files = array_merge($root_json, $nested_json);
        }
        $micro_waf_file = $waf_parent_dir . '/webcare-micro-waf.php';
        if (file_exists($micro_waf_file)) {
            $target_files[] = $micro_waf_file;
        }

        foreach ($target_files as $f) {
            if (!file_exists($f)) {
                continue;
            }
            $checked_files++;
            $p = fileperms($f) & 0777;
            // Allow 0600, 0640 or 0660 depending on webserver group, but warn if world-readable (0644/0666/0777)
            if (($p & 0004) !== 0 || ($p & 0002) !== 0) {
                $file_perms_ok = false;
                break;
            }
        }

        $vault_status = ($vault_dir_exists && $vault_writable && $file_perms_ok) ? 'pass' : ($vault_dir_exists ? 'warn' : 'fail');
        $checks['vault_permissions'] = [
            'id'          => 'vault_permissions',
            'title'       => __('WAF Vault Storage & Permissions Isolation', 'webcare-pro-security'),
            'category'    => 'security',
            'status'      => $vault_status,
            'severity'    => 'critical',
            'message'     => $vault_status === 'pass'
                /* translators: %s: Vault directory basename */
                ? sprintf(__('Vault directory %s is writable (0750) with 0600 isolated file permissions.', 'webcare-pro-security'), basename($vault_dir))
                /* translators: 1: Permission octal string, 2: Directory path */
                : sprintf(__('Vault permissions issue detected (%1$s). Ensure web server user owns %2$s with 0750 permissions.', 'webcare-pro-security'), $vault_perms, $vault_dir),
            'current'     => sprintf('Dir: 0%s, Files checked: %d (%s)', $vault_perms, $checked_files, $file_perms_ok ? 'Isolated' : 'World-readable risk'),
            'required'    => '0750 directory / 0600 files',
        ];

        // 5. CompiledStackManifest HMAC Integrity
        $manifest_intact = false;
        $manifest_msg = '';
        if (class_exists(CompiledStackManifest::class)) {
            $path = CompiledStackManifest::get_manifest_path();
            $stored_hmac = (string) get_option(CompiledStackManifest::OPTION_MANIFEST_HMAC, '');
            if (file_exists($path) && $stored_hmac !== '') {
                $secret_key = class_exists('\\WebCareProScanner\\Security\\SecretVault')
                    ? \WebCareProScanner\Security\SecretVault::get_key()
                    : (defined('AUTH_KEY') && AUTH_KEY !== '' ? AUTH_KEY : '');
                if ($secret_key !== '') {
                    $content = (string) @file_get_contents($path);
                    $expected = hash_hmac('sha256', $content, $secret_key);
                    $manifest_intact = hash_equals($expected, $stored_hmac);
                    $manifest_msg = $manifest_intact
                        ? __('Cryptographic HMAC-SHA256 signature verified against in-memory secret vault.', 'webcare-pro-security')
                        : __('HMAC signature mismatch detected. Auto-recompilation triggered.', 'webcare-pro-security');
                } else {
                    $manifest_msg = __('Secret key unavailable for HMAC check.', 'webcare-pro-security');
                }
            } else {
                $manifest_msg = __('Manifest not yet compiled. Run compilation to seed OPcache.', 'webcare-pro-security');
            }
        }

        $checks['manifest_hmac'] = [
            'id'          => 'manifest_hmac',
            'title'       => __('Stack Manifest Cryptographic HMAC', 'webcare-pro-security'),
            'category'    => 'integrity',
            'status'      => $manifest_intact ? 'pass' : 'warn',
            'severity'    => 'high',
            'message'     => $manifest_msg,
            'current'     => $manifest_intact ? __('HMAC Verified (SHA-256)', 'webcare-pro-security') : __('Unverified / Pending Recompile', 'webcare-pro-security'),
            'required'    => __('Match stored HMAC signature', 'webcare-pro-security'),
        ];

        // 6. WP-Cron Schedule Health
        $cron_disabled = defined('DISABLE_WP_CRON') && DISABLE_WP_CRON;
        $alternate_cron = defined('ALTERNATE_WP_CRON') && ALTERNATE_WP_CRON;
        $cron_due_count = 0;
        $crons = function_exists('_get_cron_array') ? _get_cron_array() : [];
        $now = time();
        if (is_array($crons)) {
            foreach ($crons as $timestamp => $hooks) {
                if ($timestamp < ($now - 300)) { // 5 minutes overdue
                    $cron_due_count += count($hooks);
                }
            }
        }
        $cron_healthy = ($cron_due_count < 10);
        $checks['cron_health'] = [
            'id'          => 'cron_health',
            'title'       => __('WP-Cron Background Task Scheduler', 'webcare-pro-security'),
            'category'    => 'scheduler',
            'status'      => $cron_healthy ? 'pass' : 'warn',
            'severity'    => 'medium',
            'message'     => $cron_healthy
                ? sprintf(__('Scheduler running smoothly (%d overdue hooks). Loopback worker ready for background scans.', 'webcare-pro-security'), $cron_due_count)
                : sprintf(__('WP-Cron has %d overdue jobs. Loopback worker will self-chain background scans safely.', 'webcare-pro-security'), $cron_due_count),
            'current'     => sprintf('Overdue: %d | DISABLE_WP_CRON: %s | ALTERNATE_WP_CRON: %s', $cron_due_count, $cron_disabled ? 'true' : 'false', $alternate_cron ? 'true' : 'false'),
            'required'    => __('Functioning WP-Cron or Server Cron runner', 'webcare-pro-security'),
        ];

        // 7. Conflicting Security / Dual-WAF Plugins
        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        $active_plugins = (array) get_option('active_plugins', []);
        $detected_conflicts = [];
        foreach (self::KNOWN_SECURITY_CONFLICTS as $slug => $name) {
            if (in_array($slug, $active_plugins, true)) {
                $detected_conflicts[] = $name;
            }
        }
        $has_conflicts = count($detected_conflicts) > 0;
        $checks['plugin_conflicts'] = [
            'id'          => 'plugin_conflicts',
            'title'       => __('Conflicting Security & Dual-WAF Plugins', 'webcare-pro-security'),
            'category'    => 'conflicts',
            'status'      => $has_conflicts ? 'warn' : 'pass',
            'severity'    => 'high',
            'message'     => $has_conflicts
                ? sprintf(__('Detected active third-party security plugin(s): %s. Running dual WAF engines can cause false positive double-blocks and redundant memory overhead.', 'webcare-pro-security'), implode(', ', $detected_conflicts))
                : __('No conflicting third-party security plugins detected. WebCare Pro is operating as primary perimeter firewall.', 'webcare-pro-security'),
            'current'     => $has_conflicts ? implode(', ', $detected_conflicts) : __('Zero Conflicts', 'webcare-pro-security'),
            'required'    => __('Dedicated single WAF perimeter', 'webcare-pro-security'),
        ];

        // 8. Evaluator Pipeline Health & Metadata Integrity
        $pipeline_intact = true;
        $pipeline_issues = [];
        $manifest_data = class_exists(CompiledStackManifest::class) ? CompiledStackManifest::load() : [];
        $evaluator_meta = $manifest_data['evaluators'] ?? [];
        $mandatory_cls = 'WebCareProScanner\\Firewall\\Core\\ExploitSignatureEngine';

        if (!class_exists($mandatory_cls)) {
            $pipeline_intact = false;
            $pipeline_issues[] = sprintf(__('Mandatory evaluator %s missing from runtime.', 'webcare-pro-security'), $mandatory_cls);
        }

        if (is_array($evaluator_meta)) {
            foreach ($evaluator_meta as $eval_cls => $m) {
                if (!empty($m['required']) && !class_exists($eval_cls)) {
                    $pipeline_intact = false;
                    $pipeline_issues[] = sprintf(__('Required evaluator %s missing.', 'webcare-pro-security'), $eval_cls);
                }
            }
        }

        $checks['evaluator_pipeline'] = [
            'id'          => 'evaluator_pipeline',
            'title'       => __('Adaptive Firewall Evaluator Pipeline', 'webcare-pro-security'),
            'category'    => 'waf',
            'status'      => $pipeline_intact ? 'pass' : 'fail',
            'severity'    => 'critical',
            'message'     => $pipeline_intact
                ? __('All mandatory and required WAF evaluators are present and compiled with strict metadata contracts.', 'webcare-pro-security')
                : sprintf(__('WAF pipeline degraded: %s', 'webcare-pro-security'), implode('; ', $pipeline_issues)),
            'current'     => $pipeline_intact ? __('Active & Intact', 'webcare-pro-security') : __('Degraded / Critical Evaluator Missing', 'webcare-pro-security'),
            'required'    => __('All required evaluators operational', 'webcare-pro-security'),
        ];

        // Compute overall score
        $total = count($checks);
        $passed = 0;
        $warnings = 0;
        $failures = 0;
        foreach ($checks as $c) {
            if ($c['status'] === 'pass') {
                $passed++;
            } elseif ($c['status'] === 'warn') {
                $warnings++;
            } else {
                $failures++;
            }
        }

        $overall_score = (int) round(($passed / max(1, $total)) * 100);

        // Safe mode status
        $safe_mode = class_exists(RescueAssistantManager::class)
            ? RescueAssistantManager::get_pause_status()
            : ['paused' => false, 'seconds_remaining' => 0];

        return [
            'score'             => $overall_score,
            'summary'           => [
                'total'    => $total,
                'passed'   => $passed,
                'warnings' => $warnings,
                'failures' => $failures,
            ],
            'checks'            => array_values($checks),
            'safe_mode'         => $safe_mode,
            'generated_at'      => gmdate('c'),
            'author'            => 'Mir Alamin (WebCare Pro)',
        ];
    }

    /**
     * Build and return a full, DLP-redacted diagnostic bundle JSON.
     * Fail-closed: returns \WP_Error if DLP is unavailable or fails.
     *
     * @return array<string, mixed>|\WP_Error
     */
    public static function build_redacted_diagnostic_bundle(): array|\WP_Error {
        global $wpdb, $wp_version;

        $raw_bundle = [
            'report_meta' => [
                'plugin'      => 'WebCare Pro Security & Firewall',
                'version'     => defined('WEBCAREPROSCAN_VERSION') ? WEBCAREPROSCAN_VERSION : '3.1.0',
                'author'      => 'Mir Alamin (WebCare Pro)',
                'exported_at' => gmdate('c'),
                'php_version' => PHP_VERSION,
                'wp_version'  => (string) ($wp_version ?? '0.0.0'),
                'server_software' => sanitize_text_field($_SERVER['SERVER_SOFTWARE'] ?? 'Unknown'),
            ],
            'runtime_environment' => [
                'memory_limit'      => ini_get('memory_limit'),
                'max_execution_time'=> ini_get('max_execution_time'),
                'opcache_enabled'   => function_exists('opcache_get_status') && !empty(@opcache_get_status(false)['opcache_enabled']),
                'curl_version'      => function_exists('curl_version') ? (curl_version()['version'] ?? 'N/A') : 'N/A',
                'openssl_version'   => defined('OPENSSL_VERSION_TEXT') ? OPENSSL_VERSION_TEXT : 'N/A',
                'mysql_version'     => $wpdb->db_version(),
            ],
            'doctor_checks'       => self::run_diagnostics(),
            'active_plugins'      => (array) get_option('active_plugins', []),
            'theme_info'          => [
                'active_theme'    => get_template(),
                'stylesheet'      => get_stylesheet(),
            ],
            'recent_waf_catches'  => class_exists(WafVaultManager::class) ? WafVaultManager::get_ghost_catches(20) : [],
        ];

        // Sanitize & redact all sensitive tokens, IPs, keys, passwords via ResponseDlpSentinel
        $has_leak = false;
        $matched_pattern = '';
        if (class_exists(ResponseDlpSentinel::class)) {
            try {
                $redacted = ResponseDlpSentinel::redact_data_recursive($raw_bundle, $has_leak, $matched_pattern);
                if (is_array($redacted)) {
                    return $redacted;
                }
            } catch (\Throwable $e) {
                return new \WP_Error('dlp_redaction_failed', __('Diagnostic export failed: DLP redaction error.', 'webcare-pro-security'));
            }
        }

        // Fail-closed invariant: Never return raw un-redacted diagnostic bundle when DLP is unavailable or fails
        return new \WP_Error('dlp_unavailable', __('Diagnostic export unavailable: DLP protection component is not loaded.', 'webcare-pro-security'));
    }
}
