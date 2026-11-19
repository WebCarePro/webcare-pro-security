<?php
declare(strict_types=1);

namespace WebCareProScanner\Api\Controllers;

use WebCareProScanner\Api\ScannerRoutes;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * RemediationController
 *
 * Remediation, Quarantine & Forensics REST Controller.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
final class RemediationController extends AbstractApiController {

    /**
     * Register endpoints for this domain.
     *
     * @param string   $namespace REST API route namespace.
     * @param callable $permission Permission callback.
     */
    public static function register(string $namespace, callable $permission): void {
        register_rest_route($namespace, '/quarantine', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'quarantine_file'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/quarantine/(?P<id>\d+)/restore', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'restore_quarantine'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/quarantine/restored', [
            'methods'             => 'DELETE',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'clear_restored_quarantine'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/quarantine/(?P<id>\d+)', [
            'methods'             => 'DELETE',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'delete_quarantine'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/quarantine/repair', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'repair_core_file'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/quarantine', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'list_quarantine'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/remediation/strip', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'remediate_strip_webshell'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/remediation/restore-plugin', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'remediate_restore_plugin'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/remediation/restore-theme', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'remediate_restore_theme'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/remediation/restore-core', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'remediate_restore_core'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/remediation/fix-permissions', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'remediate_fix_permissions'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/remediation/delete-file', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'remediate_delete_file'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/remediation/disable-wp-debug', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'remediate_disable_wp_debug'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/permissions/audit', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'permissions_audit'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/permissions/fix-all', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'permissions_fix_all'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/persistence/audit', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'persistence_audit'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/persistence/neutralize', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'persistence_neutralize'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/attack-chain/audit', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'attack_chain_audit'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/attack-chain/eradicate', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'attack_chain_eradicate'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/remediation/backups', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_remediation_backups'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/remediation/rollback', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'rollback_remediation'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/remediation/delete-cron-hook', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'remediate_delete_cron_hook'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/database/remediate', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'remediate_database_row'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/database/row', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_database_row'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/database/restore', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'restore_database_row'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/user/remediate', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'remediate_user'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/users/backups', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_user_backups'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/users/restore', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'restore_user_account'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/users/backups/dismiss', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'dismiss_user_backup'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/users/backups/delete', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'delete_user_backup'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/database/rogue-admin-audit', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_rogue_admin_audit'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/transactions/list', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_remediation_transactions'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/transactions/rollback', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'rollback_remediation_transaction'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/reinfection-watchdog/status', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_reinfection_watchdog_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/reinfection-watchdog/register', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'register_reinfection_watch'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/reinfection-watchdog/dismiss', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'dismiss_reinfection_watch'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/reinfection-watchdog/check-now', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'check_reinfection_watchdog_now'],
            'permission_callback' => $permission,
        ]);

    }
}