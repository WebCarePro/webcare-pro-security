<?php
declare(strict_types=1);

namespace WebCareProScanner\Api\Controllers;

use WebCareProScanner\Api\ScannerRoutes;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * IntegrityController
 *
 * Integrity, Supply Chain & Snapshots REST Controller.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
final class IntegrityController extends AbstractApiController {

    /**
     * Register endpoints for this domain.
     *
     * @param string   $namespace REST API route namespace.
     * @param callable $permission Permission callback.
     */
    public static function register(string $namespace, callable $permission): void {
        register_rest_route($namespace, '/integrity/recent-changes', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_integrity_recent_changes'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/integrity/vault-status', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_integrity_vault_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/integrity/calibrate-vault', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'calibrate_integrity_vault'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/integrity/recheck-drift', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'recheck_integrity_drift'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/integrity/diff', [
            'methods'             => ['GET', 'POST'],
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_integrity_file_diff'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/hooks/audit', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_hook_sentinel_audit'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/self-defense/status', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_self_defense_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/self-defense/verify', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'verify_plugin_self_defense'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/self-defense/audit-github', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'audit_self_defense_against_github'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/self-defense/restore-file', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'restore_self_defense_file'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/baseline/status', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_baseline_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/baseline/calibrate', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'calibrate_baseline'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/baseline/audit', [
            'methods'             => ['GET', 'POST'],
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'audit_baseline_deviations'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/supply-chain/sbom', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_supply_chain_sbom'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/supply-chain/sbom/calibrate', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'calibrate_supply_chain_sbom'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/supply-chain/sbom/isolate', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'isolate_supply_chain_anchor'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/supply-chain/gatekeeper', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_supply_chain_gatekeeper'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/supply-chain/gatekeeper/settings', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'update_supply_chain_gatekeeper_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/supply-chain/gatekeeper/rollback', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'rollback_supply_chain_gatekeeper'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/supply-chain/gatekeeper/clear', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'clear_supply_chain_gatekeeper_logs'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/supply-chain/analyze-plugin', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'analyze_supply_chain_plugin'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/supply-chain/scripts', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_script_inventory_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/supply-chain/scripts/calibrate', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'calibrate_script_inventory'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/supply-chain/scripts/dismiss', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'dismiss_script_drift_alert'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/supply-chain/lockfiles', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_supply_chain_lockfiles'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/supply-chain/lockfiles/scan', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'scan_supply_chain_lockfiles'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/snapshots/list', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_local_snapshots_list'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/snapshots/create', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'create_local_snapshot'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/snapshots/compare', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'compare_local_snapshot'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/snapshots/diff', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_local_snapshot_diff'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/snapshots/restore', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'restore_local_snapshot_file'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/snapshots/delete', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'delete_local_snapshot'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/integrity/object-cache/status', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_object_cache_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/integrity/object-cache/audit', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'run_object_cache_audit'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/integrity/object-cache/flush', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'flush_object_cache_resync'],
            'permission_callback' => $permission,
        ]);

    }
}