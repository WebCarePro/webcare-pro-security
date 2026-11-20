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
            'callback'            => [self::class, 'get_integrity_recent_changes'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/integrity/vault-status', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_integrity_vault_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/integrity/calibrate-vault', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'calibrate_integrity_vault'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/integrity/recheck-drift', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'recheck_integrity_drift'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/integrity/diff', [
            'methods'             => ['GET', 'POST'],
            'callback'            => [self::class, 'get_integrity_file_diff'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/hooks/audit', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_hook_sentinel_audit'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/self-defense/status', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_self_defense_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/self-defense/verify', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'verify_plugin_self_defense'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/self-defense/audit-github', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'audit_self_defense_against_github'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/self-defense/restore-file', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'restore_self_defense_file'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/baseline/status', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_baseline_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/baseline/calibrate', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'calibrate_baseline'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/baseline/audit', [
            'methods'             => ['GET', 'POST'],
            'callback'            => [self::class, 'audit_baseline_deviations'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/supply-chain/sbom', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_supply_chain_sbom'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/supply-chain/sbom/calibrate', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'calibrate_supply_chain_sbom'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/supply-chain/sbom/isolate', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'isolate_supply_chain_anchor'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/supply-chain/gatekeeper', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_supply_chain_gatekeeper'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/supply-chain/gatekeeper/settings', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'update_supply_chain_gatekeeper_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/supply-chain/gatekeeper/rollback', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'rollback_supply_chain_gatekeeper'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/supply-chain/gatekeeper/clear', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'clear_supply_chain_gatekeeper_logs'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/supply-chain/analyze-plugin', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'analyze_supply_chain_plugin'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/supply-chain/scripts', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_script_inventory_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/supply-chain/scripts/calibrate', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'calibrate_script_inventory'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/supply-chain/scripts/dismiss', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'dismiss_script_drift_alert'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/supply-chain/lockfiles', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_supply_chain_lockfiles'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/supply-chain/lockfiles/scan', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'scan_supply_chain_lockfiles'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/snapshots/list', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_local_snapshots_list'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/snapshots/create', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'create_local_snapshot'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/snapshots/compare', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'compare_local_snapshot'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/snapshots/diff', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_local_snapshot_diff'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/snapshots/restore', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'restore_local_snapshot_file'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/snapshots/delete', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'delete_local_snapshot'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/integrity/object-cache/status', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_object_cache_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/integrity/object-cache/audit', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'run_object_cache_audit'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/integrity/object-cache/flush', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'flush_object_cache_resync'],
            'permission_callback' => $permission,
        ]);

    }

    public static function get_integrity_recent_changes(\WP_REST_Request $request) {
        $hours = (int) ($request->get_param('hours') ?: 48);
        $category = sanitize_key($request->get_param('category') ?: 'all');
        $limit = (int) ($request->get_param('limit') ?: 150);

        $fim = new \WebCareProScanner\Integrity\FileIntegrityMonitor();
        $data = $fim->get_recent_changes($hours, $category, $limit);

        return rest_ensure_response($data);
    }

    public static function get_integrity_vault_status(\WP_REST_Request $request) {
        $status = \WebCareProScanner\Integrity\FimVaultManager::get_vault_status();
        return rest_ensure_response($status);
    }

    public static function calibrate_integrity_vault(\WP_REST_Request $request) {
        if (function_exists('set_time_limit')) {
            // phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged
            @set_time_limit(300);
        }
        if (function_exists('ini_set')) {
            // phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged
            @ini_set('memory_limit', '512M');
        }
        try {
            $result = \WebCareProScanner\Integrity\FimDriftDetector::calibrate_all();

            if (!empty($result['success']) && class_exists('\\WebCareProScanner\\Notifications\\NotificationDispatcher')) {
                \WebCareProScanner\Notifications\NotificationDispatcher::trigger('fim_baseline_refreshed', [
                    'severity' => 'info',
                    /* translators: %d: count of files indexed */
                    'message'  => sprintf(__('FIM Integrity Baseline snapshot refreshed (%d files indexed across all scopes).', 'webcare-pro-security'), (int) ($result['total_files'] ?? 0)),
                    'details'  => [
                        'Indexed Files'   => number_format((int) ($result['total_files'] ?? 0)),
                        'Duration'        => ($result['duration_sec'] ?? 0) . 's',
                        'Calibrated At'   => current_time('mysql'),
                    ],
                ]);
            }

            return rest_ensure_response($result);
        } catch (\Throwable $e) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
            error_log('[WEBCARE-FIM] Calibration Fatal Error: ' . $e->getMessage() . "\n" . $e->getTraceAsString());
            return new \WP_Error(
                'fim_calibration_failed',
                'FIM Vault Calibration Failed: ' . $e->getMessage(),
                ['status' => 500]
            );
        }
    }

    public static function recheck_integrity_drift(\WP_REST_Request $request) {
        if (function_exists('set_time_limit')) {
            // phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged
            @set_time_limit(180);
        }
        if (function_exists('ini_set')) {
            // phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged
            @ini_set('memory_limit', '512M');
        }
        try {
            $category = sanitize_key($request->get_param('category') ?: 'all');
            $limit = (int) ($request->get_param('limit') ?: 250);

            $result = \WebCareProScanner\Integrity\FimDriftDetector::audit_drift($category, $limit);
            return rest_ensure_response($result);
        } catch (\Throwable $e) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
            error_log('[WEBCARE-FIM] Drift Audit Fatal Error: ' . $e->getMessage() . "\n" . $e->getTraceAsString());
            return new \WP_Error(
                'fim_drift_audit_failed',
                'FIM Drift Audit Failed: ' . $e->getMessage(),
                ['status' => 500]
            );
        }
    }

    public static function get_integrity_file_diff(\WP_REST_Request $request) {
        $file_path = $request->get_param('file_path') ?: $request->get_param('path');
        if (empty($file_path)) {
            $json_params = $request->get_json_params();
            if (!empty($json_params['file_path'])) {
                $file_path = $json_params['file_path'];
            } elseif (!empty($json_params['path'])) {
                $file_path = $json_params['path'];
            }
        }

        if (empty($file_path)) {
            return new \WP_Error('missing_file_path', __('Missing required file_path parameter.', 'webcare-pro-security'), ['status' => 400]);
        }

        $file_path = sanitize_text_field(wp_unslash($file_path));

        // Support base64 encoded path to avoid WAF false positives on sensitive filenames in URL
        if (strpos($file_path, 'b64:') === 0) {
            $decoded = base64_decode(substr($file_path, 4), true);
            if ($decoded !== false && is_string($decoded)) {
                $file_path = $decoded;
            }
        } elseif (preg_match('/^[a-zA-Z0-9+\/]+=*$/', $file_path) && strlen($file_path) >= 8) {
            $decoded = base64_decode($file_path, true);
            if ($decoded !== false && is_string($decoded) && (strpos($decoded, '/') !== false || strpos($decoded, '\\') !== false || strpos($decoded, '.php') !== false)) {
                $file_path = $decoded;
            }
        }

        $fim = new \WebCareProScanner\Integrity\FileIntegrityMonitor();
        $diff_data = $fim->get_file_diff($file_path);

        return rest_ensure_response($diff_data);
    }

    /**
     * Living-off-the-Land (LotL) Hook Infiltration Audit
     */
    public static function get_hook_sentinel_audit(\WP_REST_Request $request) {
        $sentinel = new \WebCareProScanner\WordPress\HookInfiltrationSentinel();
        $findings = $sentinel->scan('manual_api_' . time());
        $results = [];
        foreach ($findings as $f) {
            $results[] = $f->to_array();
        }
        return rest_ensure_response([
            'success'  => true,
            'count'    => count($results),
            'findings' => $results,
        ]);
    }

    public static function get_baseline_status(\WP_REST_Request $request) {
        $baseline = \WebCareProScanner\Integrity\BehavioralBaselineEngine::get_baseline();
        return rest_ensure_response([
            'success'    => true,
            'calibrated' => ($baseline !== null),
            'baseline'   => $baseline,
        ]);
    }

    public static function calibrate_baseline(\WP_REST_Request $request) {
        $result = \WebCareProScanner\Integrity\BehavioralBaselineEngine::calibrate();
        return rest_ensure_response($result);
    }

    public static function audit_baseline_deviations(\WP_REST_Request $request) {
        $result = \WebCareProScanner\Integrity\BehavioralBaselineEngine::audit_baseline();
        return rest_ensure_response($result);
    }

    public static function get_supply_chain_sbom(\WP_REST_Request $request) {
        $report = \WebCareProScanner\SupplyChain\SbomSentinelEngine::check_drift();
        return rest_ensure_response([
            'success' => true,
            'report'  => $report,
        ]);
    }

    public static function calibrate_supply_chain_sbom(\WP_REST_Request $request) {
        $result = \WebCareProScanner\SupplyChain\SbomSentinelEngine::calibrate_baseline();
        return rest_ensure_response($result);
    }

    public static function isolate_supply_chain_anchor(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $item_id = sanitize_text_field($params['item_id'] ?? '');

        if (empty($item_id)) {
            return new \WP_Error('missing_item_id', __('Item ID is required for isolation.', 'webcare-pro-security'), ['status' => 400]);
        }

        $result = \WebCareProScanner\SupplyChain\SbomSentinelEngine::isolate_anchor($item_id);
        return rest_ensure_response($result);
    }

    public static function get_supply_chain_gatekeeper(\WP_REST_Request $request) {
        return rest_ensure_response([
            'success'   => true,
            'logs'      => \WebCareProScanner\SupplyChain\UpdateGatekeeperEngine::get_logs(30),
            'snapshots' => \WebCareProScanner\SupplyChain\UpdateGatekeeperEngine::get_snapshots(),
            'settings'  => \WebCareProScanner\SupplyChain\UpdateGatekeeperEngine::get_settings(),
        ]);
    }

    public static function update_supply_chain_gatekeeper_settings(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $updated = \WebCareProScanner\SupplyChain\UpdateGatekeeperEngine::update_settings($params);
        return rest_ensure_response([
            'success'  => true,
            'settings' => $updated,
            'message'  => __('Gatekeeper settings saved successfully.', 'webcare-pro-security'),
        ]);
    }

    public static function rollback_supply_chain_gatekeeper(\WP_REST_Request $request) {
        if (is_multisite() && !current_user_can('manage_network')) {
            return new \WP_Error('rest_forbidden', __('Multisite network administrator privileges required to rollback updates.', 'webcare-pro-security'), ['status' => 403]);
        }

        $params = $request->get_json_params() ?: [];
        $snapshot_id = sanitize_text_field($params['snapshot_id'] ?? '');

        if (empty($snapshot_id)) {
            return new \WP_Error('missing_snapshot_id', __('Snapshot ID is required for rollback.', 'webcare-pro-security'), ['status' => 400]);
        }

        $result = \WebCareProScanner\SupplyChain\UpdateGatekeeperEngine::rollback_snapshot($snapshot_id);
        return rest_ensure_response($result);
    }

    public static function clear_supply_chain_gatekeeper_logs(\WP_REST_Request $request) {
        \WebCareProScanner\SupplyChain\UpdateGatekeeperEngine::clear_logs();
        return rest_ensure_response([
            'success' => true,
            'message' => __('Gatekeeper intercepted logs cleared successfully.', 'webcare-pro-security'),
        ]);
    }

    public static function analyze_supply_chain_plugin(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $slug = sanitize_text_field($params['slug'] ?? '');

        if (empty($slug)) {
            return new \WP_Error('missing_slug', __('Plugin slug is required for risk analysis.', 'webcare-pro-security'), ['status' => 400]);
        }

        $analysis = \WebCareProScanner\SupplyChain\InstallRiskAdvisor::analyze_installed_plugin($slug);
        return rest_ensure_response([
            'success'  => true,
            'analysis' => $analysis,
        ]);
    }

    public static function get_script_inventory_status(\WP_REST_Request $request) {
        $data = \WebCareProScanner\Content\ScriptInventoryMonitor::get_status();
        return rest_ensure_response($data);
    }

    public static function calibrate_script_inventory(\WP_REST_Request $request) {
        $data = \WebCareProScanner\Content\ScriptInventoryMonitor::calibrate_baseline();
        return rest_ensure_response([
            'success' => true,
            'message' => __('Script inventory baseline calibrated successfully.', 'webcare-pro-security'),
            'status'  => $data,
        ]);
    }

    public static function dismiss_script_drift_alert(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $alert_id = sanitize_text_field($params['alert_id'] ?? '');

        if (empty($alert_id)) {
            return new \WP_Error('missing_alert_id', __('Alert ID is required to dismiss.', 'webcare-pro-security'), ['status' => 400]);
        }

        $res = \WebCareProScanner\Content\ScriptInventoryMonitor::dismiss_alert($alert_id);
        return rest_ensure_response([
            'success' => $res,
            'message' => __('Script drift alert dismissed.', 'webcare-pro-security'),
        ]);
    }

    public static function get_supply_chain_lockfiles(\WP_REST_Request $request) {
        $data = \WebCareProScanner\SupplyChain\LockfileAuditEngine::run_audit(false);
        return rest_ensure_response($data);
    }

    public static function scan_supply_chain_lockfiles(\WP_REST_Request $request) {
        $data = \WebCareProScanner\SupplyChain\LockfileAuditEngine::run_audit(true);
        return rest_ensure_response($data);
    }

    public static function get_self_defense_status(\WP_REST_Request $request) {
        if (!class_exists('\WebCareProScanner\Security\PluginSelfDefense')) {
            $file = WEBCAREPROSCAN_PATH . 'includes/Security/PluginSelfDefense.php';
            if (file_exists($file)) {
                require_once $file;
            }
        }

        $last_audit = get_option(\WebCareProScanner\Security\PluginSelfDefense::DB_LAST_AUDIT_OPTION, null);
        if (!$last_audit) {
            $last_audit = \WebCareProScanner\Security\PluginSelfDefense::run_audit(false);
        }

        $settings = \WebCareProScanner\System\SettingsManager::get_settings();

        return rest_ensure_response([
            'success'  => true,
            'audit'    => $last_audit,
            'settings' => [
                'watchdog_enabled' => !empty($settings['self_defense_watchdog_enabled']),
                'notify_email'     => !empty($settings['self_defense_notify_email']),
                'admin_email'      => get_option('admin_email', ''),
            ],
        ]);
    }

    public static function verify_plugin_self_defense(\WP_REST_Request $request) {
        if (!class_exists('\WebCareProScanner\Security\PluginSelfDefense')) {
            $file = WEBCAREPROSCAN_PATH . 'includes/Security/PluginSelfDefense.php';
            if (file_exists($file)) {
                require_once $file;
            }
        }

        $audit = \WebCareProScanner\Security\PluginSelfDefense::run_audit(true);

        return rest_ensure_response([
            'success' => true,
            'audit'   => $audit,
            'message' => !empty($audit['has_issues'])
                ? __('Self-defense verification completed: anomalies detected in plugin files.', 'webcare-pro-security')
                : __('All plugin core files are 100% authentic, intact, and verified against the official release signature.', 'webcare-pro-security'),
        ]);
    }

    public static function audit_self_defense_against_github(\WP_REST_Request $request) {
        if (!class_exists('\WebCareProScanner\Security\PluginSelfDefense')) {
            $file = WEBCAREPROSCAN_PATH . 'includes/Security/PluginSelfDefense.php';
            if (file_exists($file)) {
                require_once $file;
            }
        }

        $res = \WebCareProScanner\Security\PluginSelfDefense::audit_against_github(true);
        return rest_ensure_response($res);
    }

    public static function restore_self_defense_file(\WP_REST_Request $request) {
        if (is_multisite() && !current_user_can('manage_network')) {
            return new \WP_Error('rest_forbidden', __('Multisite network administrator privileges required.', 'webcare-pro-security'), ['status' => 403]);
        }
        if (!class_exists('\WebCareProScanner\Security\PluginSelfDefense')) {
            $file = WEBCAREPROSCAN_PATH . 'includes/Security/PluginSelfDefense.php';
            if (file_exists($file)) {
                require_once $file;
            }
        }

        $params = $request->get_json_params();
        $path = sanitize_text_field($params['path'] ?? '');

        if (empty($path)) {
            return rest_ensure_response([
                'success' => false,
                'message' => __('Path parameter is required for file restoration.', 'webcare-pro-security'),
            ]);
        }

        $res = \WebCareProScanner\Security\PluginSelfDefense::restore_file_from_github($path);
        return rest_ensure_response($res);
    }

    public static function get_local_snapshots_list() {
        return rest_ensure_response(\WebCareProScanner\Integrity\LocalSnapshotManager::list_snapshots());
    }

    public static function create_local_snapshot(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $target = sanitize_text_field($params['target_rel_path'] ?? '');
        $label = sanitize_text_field($params['label'] ?? '');

        if (empty($target)) {
            return new \WP_Error('missing_target', __('Target relative directory path is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $res = \WebCareProScanner\Integrity\LocalSnapshotManager::create_snapshot($target, $label);
        return rest_ensure_response($res);
    }

    public static function compare_local_snapshot(\WP_REST_Request $request) {
        $snap_id = sanitize_key($request->get_param('snapshot_id') ?: '');
        if (empty($snap_id)) {
            return new \WP_Error('missing_id', __('Snapshot ID required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $res = \WebCareProScanner\Integrity\LocalSnapshotManager::compare_snapshot($snap_id);
        return rest_ensure_response($res);
    }

    public static function get_local_snapshot_diff(\WP_REST_Request $request) {
        $snap_id = sanitize_key($request->get_param('snapshot_id') ?: '');
        $rel_path = sanitize_text_field($request->get_param('rel_path') ?: '');

        if (empty($snap_id) || empty($rel_path)) {
            return new \WP_Error('missing_params', __('Snapshot ID and rel_path are required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $res = \WebCareProScanner\Integrity\LocalSnapshotManager::get_file_diff($snap_id, $rel_path);
        return rest_ensure_response($res);
    }

    public static function restore_local_snapshot_file(\WP_REST_Request $request) {
        if (is_multisite() && !current_user_can('manage_network')) {
            return new \WP_Error('rest_forbidden', __('Multisite network administrator privileges required.', 'webcare-pro-security'), ['status' => 403]);
        }
        $params = $request->get_json_params() ?: [];
        $snap_id = sanitize_key($params['snapshot_id'] ?? '');
        $rel_path = sanitize_text_field($params['rel_path'] ?? '');

        if (empty($snap_id) || empty($rel_path)) {
            return new \WP_Error('missing_params', __('Snapshot ID and rel_path are required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $res = \WebCareProScanner\Integrity\LocalSnapshotManager::restore_file($snap_id, $rel_path);
        return rest_ensure_response($res);
    }

    public static function delete_local_snapshot(\WP_REST_Request $request) {
        if (is_multisite() && !current_user_can('manage_network')) {
            return new \WP_Error('rest_forbidden', __('Multisite network administrator privileges required.', 'webcare-pro-security'), ['status' => 403]);
        }
        $params = $request->get_json_params() ?: [];
        $snap_id = sanitize_key($params['snapshot_id'] ?? '');

        if (empty($snap_id)) {
            return new \WP_Error('missing_id', __('Snapshot ID is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $deleted = \WebCareProScanner\Integrity\LocalSnapshotManager::delete_snapshot($snap_id);
        return rest_ensure_response([
            'success'   => $deleted,
            'message'   => $deleted ? __('Snapshot deleted.', 'webcare-pro-security') : __('Snapshot not found.', 'webcare-pro-security'),
            'snapshots' => \WebCareProScanner\Integrity\LocalSnapshotManager::list_snapshots(),
        ]);
    }

    /**
     * Get In-Memory Object Cache Integrity status & environment.
     */
    public static function get_object_cache_status(\WP_REST_Request $request) {
        if (!class_exists(\WebCareProScanner\Integrity\ObjectCacheIntegritySentinel::class)) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => 'Object Cache Sentinel service not available.',
            ], 500);
        }

        $audit = \WebCareProScanner\Integrity\ObjectCacheIntegritySentinel::audit_ram_vs_disk();

        return rest_ensure_response([
            'success' => true,
            'report'  => $audit,
        ]);
    }

    /**
     * Run on-demand deep differential audit of RAM Object Cache vs MySQL disk.
     */
    public static function run_object_cache_audit(\WP_REST_Request $request) {
        if (!class_exists(\WebCareProScanner\Integrity\ObjectCacheIntegritySentinel::class)) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => 'Object Cache Sentinel service not available.',
            ], 500);
        }

        $audit = \WebCareProScanner\Integrity\ObjectCacheIntegritySentinel::audit_ram_vs_disk();

        return rest_ensure_response([
            'success' => true,
            'message' => __('Differential RAM vs Disk audit completed successfully.', 'webcare-pro-security'),
            'report'  => $audit,
        ]);
    }

    /**
     * 1-Click Surgical Flush & Resynchronization from MySQL Database Truth.
     */
    public static function flush_object_cache_resync(\WP_REST_Request $request) {
        if (!class_exists(\WebCareProScanner\Integrity\ObjectCacheIntegritySentinel::class)) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => 'Object Cache Sentinel service not available.',
            ], 500);
        }

        $result = \WebCareProScanner\Integrity\ObjectCacheIntegritySentinel::resynchronize_and_flush();

        return rest_ensure_response($result);
    }
}
