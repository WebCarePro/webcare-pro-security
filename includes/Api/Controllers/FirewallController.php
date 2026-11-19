<?php
declare(strict_types=1);

namespace WebCareProScanner\Api\Controllers;

use WebCareProScanner\Api\ScannerRoutes;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * FirewallController
 *
 * Firewall & Server Security REST Controller.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
final class FirewallController extends AbstractApiController {

    /**
     * Register endpoints for this domain.
     *
     * @param string   $namespace REST API route namespace.
     * @param callable $permission Permission callback.
     */
    public static function register(string $namespace, callable $permission): void {
        register_rest_route($namespace, '/firewall/status', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_firewall_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/logs', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_firewall_logs'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/logs/stats', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_firewall_log_stats'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/logs/files', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_firewall_log_files'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/logs/retention', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'update_firewall_log_retention'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/logs/prune', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'prune_firewall_logs'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/logs/download', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'download_firewall_log_file'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/logs/delete', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'delete_firewall_log'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/logs/block-ip', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'add_firewall_blocked_ip'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/logs/unblock-ip', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'unblock_firewall_ip'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/customer/lookup-block', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'lookup_customer_lockout'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/customer/unblock', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'unblock_customer_lockout'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/blocklist', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_firewall_blocklist'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/blocklist/clear-expired', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'clear_expired_firewall_blocklist'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/allowlist-rule-target', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'allowlist_firewall_rule_target'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/logs/whitelist-ip', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'add_firewall_whitelisted_ip'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/whitelist', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_firewall_whitelist'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/whitelist/remove', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'remove_firewall_whitelisted_ip'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/clear-logs', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'clear_firewall_logs'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/toggle', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'toggle_firewall'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/save-rule', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'save_single_firewall_rule'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/roles', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_firewall_roles'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/server-security/config', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_server_security_config'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/server-security/save', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'save_server_security_config'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/server-security/deploy-htaccess', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'deploy_server_security_htaccess'],
            'permission_callback' => $permission,
        ]);

        foreach (['/firewall/redirect-shield', '/redirect-shield'] as $r_base) {
            register_rest_route($namespace, $r_base . '/status', [
                'methods'             => ['GET', 'POST'],
                'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_redirect_shield_status'],
                'permission_callback' => $permission,
            ]);

            register_rest_route($namespace, $r_base . '/probe', [
                'methods'             => 'POST',
                'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'run_redirect_canary_probe'],
                'permission_callback' => $permission,
            ]);

            register_rest_route($namespace, $r_base . '/restore', [
                'methods'             => 'POST',
                'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'restore_htaccess_vault_snapshot'],
                'permission_callback' => $permission,
            ]);

            register_rest_route($namespace, $r_base . '/lock', [
                'methods'             => 'POST',
                'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'toggle_htaccess_lock'],
                'permission_callback' => $permission,
            ]);

            register_rest_route($namespace, $r_base . '/heal-urls', [
                'methods'             => 'POST',
                'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'heal_database_core_urls'],
                'permission_callback' => $permission,
            ]);

            register_rest_route($namespace, $r_base . '/snapshot', [
                'methods'             => 'POST',
                'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'create_htaccess_vault_snapshot'],
                'permission_callback' => $permission,
            ]);
        }

        register_rest_route($namespace, '/caf/overview', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_caf_overview'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/caf/apply-profile', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'apply_caf_profile'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/caf/reprofile', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'reprofile_caf_stack'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/caf/killswitch', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'toggle_caf_killswitch'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/caf/cloudflare-status', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_caf_cloudflare_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/caf/sync-cloudflare', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'sync_caf_cloudflare'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/caf/toggle-circuit-breaker', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'toggle_origin_circuit_breaker'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/caf/behavioral-status', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_caf_behavioral_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/caf/create-exemption', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'create_caf_exemption'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/caf/toggle-pow-challenge', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'toggle_caf_pow_challenge'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/micro-waf/status', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_micro_waf_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/micro-waf/compile', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'compile_micro_waf'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/micro-waf/install', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'install_micro_waf_preload'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/micro-waf/uninstall', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'uninstall_micro_waf_preload'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/whitelist/rules', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_whitelist_rules'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/whitelist/add', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'add_whitelist_rule'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/whitelist/remove', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'remove_whitelist_rule'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/server-security/verify', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'verify_server_security_rules'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/server-security/caddy-config', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_caddy_server_config'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/rescue/status', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_rescue_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/rescue/trust-action', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'rescue_trust_action'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/rescue/pause-15m', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'rescue_pause_15m'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/rescue/resume', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'rescue_resume'],
            'permission_callback' => $permission,
        ]);

    }
}