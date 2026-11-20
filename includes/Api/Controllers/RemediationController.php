<?php
declare(strict_types=1);

namespace WebCareProScanner\Api\Controllers;

use WebCareProScanner\Quarantine\CoreRepairManager;
use WebCareProScanner\Quarantine\QuarantineManager;
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
            'callback'            => [self::class, 'quarantine_file'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/quarantine/(?P<id>\d+)/restore', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'restore_quarantine'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/quarantine/restored', [
            'methods'             => 'DELETE',
            'callback'            => [self::class, 'clear_restored_quarantine'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/quarantine/(?P<id>\d+)', [
            'methods'             => 'DELETE',
            'callback'            => [self::class, 'delete_quarantine'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/quarantine/repair', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'repair_core_file'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/quarantine', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'list_quarantine'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/remediation/strip', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'remediate_strip_webshell'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/remediation/restore-plugin', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'remediate_restore_plugin'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/remediation/restore-theme', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'remediate_restore_theme'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/remediation/restore-core', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'remediate_restore_core'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/remediation/fix-permissions', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'remediate_fix_permissions'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/remediation/delete-file', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'remediate_delete_file'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/remediation/disable-wp-debug', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'remediate_disable_wp_debug'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/permissions/audit', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'permissions_audit'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/permissions/fix-all', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'permissions_fix_all'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/persistence/audit', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'persistence_audit'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/persistence/neutralize', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'persistence_neutralize'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/attack-chain/audit', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'attack_chain_audit'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/attack-chain/eradicate', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'attack_chain_eradicate'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/remediation/backups', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_remediation_backups'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/remediation/rollback', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'rollback_remediation'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/remediation/delete-cron-hook', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'remediate_delete_cron_hook'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/database/remediate', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'remediate_database_row'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/database/row', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_database_row'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/database/restore', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'restore_database_row'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/user/remediate', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'remediate_user'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/users/backups', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_user_backups'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/users/restore', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'restore_user_account'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/users/backups/dismiss', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'dismiss_user_backup'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/users/backups/delete', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'delete_user_backup'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/database/rogue-admin-audit', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_rogue_admin_audit'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/transactions/list', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_remediation_transactions'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/transactions/rollback', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'rollback_remediation_transaction'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/reinfection-watchdog/status', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_reinfection_watchdog_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/reinfection-watchdog/register', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'register_reinfection_watch'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/reinfection-watchdog/dismiss', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'dismiss_reinfection_watch'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/reinfection-watchdog/check-now', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'check_reinfection_watchdog_now'],
            'permission_callback' => $permission,
        ]);

    }

    public static function quarantine_file(\WP_REST_Request $request) {
        if (is_multisite() && !current_user_can('manage_network')) {
            return new \WP_Error('rest_forbidden', __('Multisite network administrator privileges required.', 'webcare-pro-security'), ['status' => 403]);
        }
        $file_path = sanitize_text_field($request->get_param('file_path'));
        $issue_id = $request->get_param('issue_id') ? (int) $request->get_param('issue_id') : null;
        $scan_id = $request->get_param('scan_id') ? (int) $request->get_param('scan_id') : null;

        $qm = new QuarantineManager();
        $result = $qm->quarantine_file($file_path, $scan_id, $issue_id);

        return rest_ensure_response($result);
    }

    public static function restore_quarantine(\WP_REST_Request $request) {
        if (is_multisite() && !current_user_can('manage_network')) {
            return new \WP_Error('rest_forbidden', __('Multisite network administrator privileges required.', 'webcare-pro-security'), ['status' => 403]);
        }
        $quarantine_id = (int) $request->get_param('id');
        $overwrite     = !empty($request->get_param('overwrite'));
        $allow_legacy  = !empty($request->get_param('allow_legacy'));

        $qm = new QuarantineManager();
        $result = $qm->restore_file($quarantine_id, $overwrite, $allow_legacy);

        return rest_ensure_response($result);
    }

    public static function delete_quarantine(\WP_REST_Request $request) {
        if (is_multisite() && !current_user_can('manage_network')) {
            return new \WP_Error('rest_forbidden', __('Multisite network administrator privileges required.', 'webcare-pro-security'), ['status' => 403]);
        }
        $quarantine_id = (int) $request->get_param('id');
        $qm = new QuarantineManager();
        $result = $qm->delete_record($quarantine_id);

        return rest_ensure_response($result);
    }

    public static function clear_restored_quarantine(\WP_REST_Request $request) {
        if (is_multisite() && !current_user_can('manage_network')) {
            return new \WP_Error('rest_forbidden', __('Multisite network administrator privileges required.', 'webcare-pro-security'), ['status' => 403]);
        }
        $qm = new QuarantineManager();
        $result = $qm->clear_restored_records();

        return rest_ensure_response($result);
    }

    public static function list_quarantine(\WP_REST_Request $request) {
        $qm = new QuarantineManager();
        $records = $qm->list_records();

        return rest_ensure_response([
            'success' => true,
            'records' => $records,
        ]);
    }

    /**
     * Safely repair an infected core file by pulling the pristine version from WP.org.
     */
    public static function repair_core_file(\WP_REST_Request $request) {
        if (is_multisite() && !current_user_can('manage_network')) {
            return new \WP_Error('rest_forbidden', __('Multisite network administrator privileges required.', 'webcare-pro-security'), ['status' => 403]);
        }
        $file_path = sanitize_text_field($request->get_param('file_path'));
        $issue_id = (int) $request->get_param('issue_id');

        if (empty($file_path)) {
            return new \WP_Error('missing_params', __('File path is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $repair_manager = new CoreRepairManager();
        $result = $repair_manager->repair_core_file($file_path);

        if ($result['success'] && $issue_id) {
            global $wpdb;
            $table_issues = $wpdb->prefix . 'webcareproscan_scan_issues';
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->update($table_issues, ['status' => 'repaired'], ['id' => $issue_id]);
        }

        return rest_ensure_response($result);
    }

    public static function remediate_strip_webshell(\WP_REST_Request $request) {
        if (is_multisite() && !current_user_can('manage_network')) {
            return new \WP_Error('rest_forbidden', __('Multisite network administrator privileges required to modify system files.', 'webcare-pro-security'), ['status' => 403]);
        }

        $params = $request->get_json_params() ?: [];
        $file_path = !empty($params['file_path']) ? sanitize_text_field(wp_unslash($params['file_path'])) : '';
        $issue_id = !empty($params['issue_id']) ? (int) $params['issue_id'] : null;

        if (empty($file_path)) {
            return new \WP_Error('missing_param', __('Missing file_path parameter.', 'webcare-pro-security'), ['status' => 400]);
        }

        $manager = new \WebCareProScanner\Remediation\RemediationManager();
        $result = $manager->strip_malware_injection($file_path, $issue_id);

        return rest_ensure_response($result);
    }

    public static function remediate_restore_plugin(\WP_REST_Request $request) {
        if (is_multisite() && !current_user_can('manage_network')) {
            return new \WP_Error('rest_forbidden', __('Multisite network administrator privileges required to restore plugin files.', 'webcare-pro-security'), ['status' => 403]);
        }

        $params = $request->get_json_params() ?: [];
        $file_path = !empty($params['file_path']) ? sanitize_text_field(wp_unslash($params['file_path'])) : '';
        $issue_id = !empty($params['issue_id']) ? (int) $params['issue_id'] : null;

        if (empty($file_path)) {
            return new \WP_Error('missing_param', __('Missing file_path parameter.', 'webcare-pro-security'), ['status' => 400]);
        }

        $manager = new \WebCareProScanner\Remediation\RemediationManager();
        $result = $manager->restore_official_plugin_file($file_path, $issue_id);

        return rest_ensure_response($result);
    }

    public static function remediate_restore_theme(\WP_REST_Request $request) {
        if (is_multisite() && !current_user_can('manage_network')) {
            return new \WP_Error('rest_forbidden', __('Multisite network administrator privileges required to restore theme files.', 'webcare-pro-security'), ['status' => 403]);
        }

        $params = $request->get_json_params() ?: [];
        $file_path = !empty($params['file_path']) ? sanitize_text_field(wp_unslash($params['file_path'])) : '';
        $issue_id = !empty($params['issue_id']) ? (int) $params['issue_id'] : null;

        if (empty($file_path)) {
            return new \WP_Error('missing_param', __('Missing file_path parameter.', 'webcare-pro-security'), ['status' => 400]);
        }

        $manager = new \WebCareProScanner\Remediation\RemediationManager();
        $result = $manager->restore_official_theme_file($file_path, $issue_id);

        return rest_ensure_response($result);
    }

    public static function remediate_restore_core(\WP_REST_Request $request) {
        if (is_multisite() && !current_user_can('manage_network')) {
            return new \WP_Error('rest_forbidden', __('Multisite network administrator privileges required to restore core files.', 'webcare-pro-security'), ['status' => 403]);
        }

        $params = $request->get_json_params() ?: [];
        $file_path = !empty($params['file_path']) ? sanitize_text_field(wp_unslash($params['file_path'])) : '';
        $issue_id = !empty($params['issue_id']) ? (int) $params['issue_id'] : null;

        if (empty($file_path)) {
            return new \WP_Error('missing_param', __('Missing file_path parameter.', 'webcare-pro-security'), ['status' => 400]);
        }

        $manager = new \WebCareProScanner\Remediation\RemediationManager();
        $result = $manager->restore_official_core_file($file_path, $issue_id);

        return rest_ensure_response($result);
    }

    public static function remediate_fix_permissions(\WP_REST_Request $request) {
        if (is_multisite() && !current_user_can('manage_network')) {
            return new \WP_Error('rest_forbidden', __('Multisite network administrator privileges required to modify filesystem permissions.', 'webcare-pro-security'), ['status' => 403]);
        }

        $params = $request->get_json_params() ?: [];
        $file_path = !empty($params['file_path']) ? sanitize_text_field(wp_unslash($params['file_path'])) : '';
        $issue_id = !empty($params['issue_id']) ? (int) $params['issue_id'] : null;
        $target_perm = !empty($params['target_perm']) ? sanitize_text_field(wp_unslash($params['target_perm'])) : null;

        if (empty($file_path)) {
            return new \WP_Error('missing_param', __('Missing file_path parameter.', 'webcare-pro-security'), ['status' => 400]);
        }

        $manager = new \WebCareProScanner\Remediation\RemediationManager();
        $result = $manager->fix_permissions($file_path, $target_perm, $issue_id);

        return rest_ensure_response($result);
    }

    public static function remediate_delete_file(\WP_REST_Request $request) {
        if (is_multisite() && !current_user_can('manage_network')) {
            return new \WP_Error('rest_forbidden', __('Multisite network administrator privileges required to delete system files.', 'webcare-pro-security'), ['status' => 403]);
        }

        $params = $request->get_json_params() ?: [];
        $file_path = !empty($params['file_path']) ? sanitize_text_field(wp_unslash($params['file_path'])) : '';
        $issue_id = !empty($params['issue_id']) ? (int) $params['issue_id'] : null;

        if (empty($file_path)) {
            return new \WP_Error('missing_param', __('Missing file_path parameter.', 'webcare-pro-security'), ['status' => 400]);
        }

        $manager = new \WebCareProScanner\Remediation\RemediationManager();
        $result = $manager->delete_file($file_path, $issue_id);

        return rest_ensure_response($result);
    }

    public static function remediate_disable_wp_debug(\WP_REST_Request $request) {
        if (is_multisite() && !current_user_can('manage_network')) {
            return new \WP_Error('rest_forbidden', __('Multisite network administrator privileges required to modify wp-config.php.', 'webcare-pro-security'), ['status' => 403]);
        }

        $params = $request->get_json_params() ?: [];
        $file_path = !empty($params['file_path']) ? sanitize_text_field(wp_unslash($params['file_path'])) : '';
        $issue_id = !empty($params['issue_id']) ? (int) $params['issue_id'] : null;

        $manager = new \WebCareProScanner\Remediation\RemediationManager();
        $result = $manager->disable_wp_debug($file_path, $issue_id);

        return rest_ensure_response($result);
    }

    public static function permissions_audit(\WP_REST_Request $request) {
        $manager = new \WebCareProScanner\Hardening\PermissionHardeningManager();
        $result = $manager->audit();
        return rest_ensure_response($result);
    }

    public static function permissions_fix_all(\WP_REST_Request $request) {
        if (is_multisite() && !current_user_can('manage_network')) {
            return new \WP_Error('rest_forbidden', __('Multisite network administrator privileges required to modify filesystem permissions.', 'webcare-pro-security'), ['status' => 403]);
        }

        $manager = new \WebCareProScanner\Hardening\PermissionHardeningManager();
        $result = $manager->fix_all();
        return rest_ensure_response($result);
    }

    public static function persistence_audit(\WP_REST_Request $request) {
        $scanner = new \WebCareProScanner\WordPress\PersistenceScanner();
        $result = $scanner->audit_full();
        return rest_ensure_response($result);
    }

    public static function persistence_neutralize(\WP_REST_Request $request) {
        if (is_multisite() && !current_user_can('manage_network')) {
            return new \WP_Error('rest_forbidden', __('Multisite network administrator privileges required to neutralize persistence mechanisms.', 'webcare-pro-security'), ['status' => 403]);
        }

        $params = $request->get_json_params() ?: [];
        $type = sanitize_key($params['type'] ?? '');
        $id = sanitize_text_field(wp_unslash($params['id'] ?? ''));
        $bulk = !empty($params['bulk']);

        $scanner = new \WebCareProScanner\WordPress\PersistenceScanner();

        if ($bulk) {
            $result = $scanner->neutralize_all();
            return rest_ensure_response($result);
        }

        if (empty($type) || empty($id)) {
            return new \WP_Error('missing_params', __('Type and identifier are required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $result = $scanner->neutralize_item($type, $id);
        if (!$result['success']) {
            return new \WP_Error('neutralize_failed', $result['message'], ['status' => 500]);
        }

        return rest_ensure_response($result);
    }

    public static function attack_chain_audit(\WP_REST_Request $request) {
        $engine = new \WebCareProScanner\Forensics\AttackChainEngine();
        $result = $engine->audit_attack_chains();
        return rest_ensure_response($result);
    }

    public static function attack_chain_eradicate(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $chain_id = sanitize_text_field(wp_unslash($params['chain_id'] ?? ''));
        $plan = is_array($params['plan'] ?? null) ? $params['plan'] : [];

        if (empty($chain_id)) {
            return new \WP_Error('missing_chain_id', __('Chain ID is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $engine = new \WebCareProScanner\Forensics\AttackChainEngine();
        $result = $engine->eradicate_chain($chain_id, $plan);
        return rest_ensure_response($result);
    }

    public static function get_remediation_backups() {
        $manager = new \WebCareProScanner\Remediation\RemediationManager();
        return rest_ensure_response([
            'backups' => $manager->get_backups(),
        ]);
    }

    public static function rollback_remediation(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $backup_id = !empty($params['backup_id']) ? sanitize_text_field(wp_unslash($params['backup_id'])) : '';

        if (empty($backup_id)) {
            return new \WP_Error('missing_param', __('Missing backup_id parameter.', 'webcare-pro-security'), ['status' => 400]);
        }

        $manager = new \WebCareProScanner\Remediation\RemediationManager();
        $result = $manager->rollback_remediation($backup_id);

        return rest_ensure_response($result);
    }

    public static function remediate_delete_cron_hook(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $hook_name = !empty($params['hook_name']) ? sanitize_text_field(wp_unslash($params['hook_name'])) : '';
        $issue_id = !empty($params['issue_id']) ? (int) $params['issue_id'] : null;

        if (empty($hook_name) && !empty($params['file_path'])) {
            $path = sanitize_text_field(wp_unslash($params['file_path']));
            if (strpos($path, 'cron:hook:') === 0) {
                $hook_name = substr($path, strlen('cron:hook:'));
            } else {
                $hook_name = $path;
            }
        }

        if (empty($hook_name)) {
            return new \WP_Error('missing_param', __('Missing hook_name parameter.', 'webcare-pro-security'), ['status' => 400]);
        }

        // Safety check: protect essential WordPress core cron hooks from being cleared
        $protected_core_crons = [
            'wp_version_check',
            'wp_update_plugins',
            'wp_update_themes',
            'recovery_mode_clean_expired_keys',
            'wp_scheduled_delete',
            'delete_expired_transients',
            'wp_privacy_delete_old_export_files',
        ];

        if (in_array($hook_name, $protected_core_crons, true)) {
            return new \WP_Error('protected_core_hook', __('Cannot delete essential WordPress core system cron hooks.', 'webcare-pro-security'), ['status' => 403]);
        }

        // Clear all scheduled instances of this cron hook
        $cleared = wp_clear_scheduled_hook($hook_name);

        if ($issue_id) {
            global $wpdb;
            $table = $wpdb->prefix . 'webcareproscan_scan_issues';
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->update($table, ['status' => 'repaired'], ['id' => $issue_id]);
        }

        return rest_ensure_response([
            'success' => true,
            /* translators: %s: cron hook name */
            'message' => sprintf(__('Scheduled cron hook "%s" was successfully removed from the WordPress database.', 'webcare-pro-security'), $hook_name),
            'cleared' => $cleared,
            'hook'    => $hook_name,
        ]);
    }

    /**
     * Database Row Remediation (Delete row or cleanse field with auto-backup snapshot)
     */
    public static function remediate_database_row(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $table = !empty($params['table']) ? sanitize_text_field($params['table']) : '';
        $column = !empty($params['column']) ? sanitize_text_field($params['column']) : '';
        $row_id = !empty($params['row_id']) ? sanitize_text_field($params['row_id']) : '';
        $action = !empty($params['action']) ? sanitize_key($params['action']) : 'delete_row';
        $issue_id = !empty($params['issue_id']) ? (int) $params['issue_id'] : null;

        if (empty($table) || empty($row_id)) {
            return new \WP_Error('missing_params', __('Table name and Row ID are required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $mgr = new \WebCareProScanner\Database\DatabaseRemediationManager();

        if ($action === 'delete_row') {
            $result = $mgr->delete_row_with_backup($table, $row_id, $column, $issue_id);
        } elseif ($action === 'cleanse_field') {
            if (empty($column)) {
                return new \WP_Error('missing_column', __('Column name is required for field cleansing.', 'webcare-pro-security'), ['status' => 400]);
            }
            $result = $mgr->cleanse_field_with_backup($table, $column, $row_id, $issue_id);
        } else {
            return new \WP_Error('invalid_action', __('Invalid database remediation action.', 'webcare-pro-security'), ['status' => 400]);
        }

        if (!$result['success']) {
            return new \WP_Error('db_remediation_failed', $result['message'], ['status' => 500]);
        }

        return rest_ensure_response($result);
    }

    /**
     * Get Database Row Data for Live Forensic Inspection
     */
    public static function get_database_row(\WP_REST_Request $request) {
        $table = sanitize_text_field($request->get_param('table') ?: '');
        $row_id = sanitize_text_field($request->get_param('row_id') ?: '');

        if (empty($table) || empty($row_id)) {
            return new \WP_Error('missing_params', __('Table and Row ID are required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $mgr = new \WebCareProScanner\Database\DatabaseRemediationManager();
        $pk = $mgr->get_primary_key($table);
        $row = $mgr->get_row($table, $row_id);

        if (!$row) {
            return new \WP_Error('row_not_found', __('Database record not found or already deleted.', 'webcare-pro-security'), ['status' => 404]);
        }

        $is_log_table = (bool) preg_match('/(log|logs|redirection|audit|history|stat|stats|traffic|404)/i', $table);

        return rest_ensure_response([
            'success'      => true,
            'table'        => $table,
            'row_id'       => $row_id,
            'primary_key'  => $pk,
            'is_log_table' => $is_log_table,
            'row'          => $row,
            'data'         => [
                'table'        => $table,
                'row_id'       => $row_id,
                'primary_key'  => $pk,
                'is_log_table' => $is_log_table,
                'row'          => $row,
            ],
        ]);
    }

    /**
     * Restore Database Row from Auto-Backup Snapshot
     */
    public static function restore_database_row(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $backup_id = !empty($params['backup_id']) ? sanitize_text_field($params['backup_id']) : '';

        if (empty($backup_id)) {
            return new \WP_Error('missing_backup_id', __('Backup ID is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $mgr = new \WebCareProScanner\Database\DatabaseRemediationManager();
        $result = $mgr->restore_backup($backup_id);

        if (!$result['success']) {
            return new \WP_Error('db_restore_failed', $result['message'], ['status' => 500]);
        }

        return rest_ensure_response($result);
    }

    /**
     * Remediate User Account / Capabilities Anomaly
     *
     * Actions:
     * - 'assign_default_role': Assigns default role (subscriber) to user missing capabilities.
     * - 'strip_capabilities': Strips unauthorized/trojan capabilities from non-admin accounts.
     * - 'delete_user': Safely deletes anomalous/ghost account with mandatory pre-action snapshot.
     */
    public static function remediate_user(\WP_REST_Request $request) {
        if (is_multisite() && !current_user_can('manage_network')) {
            return new \WP_Error('rest_forbidden', __('Multisite network administrator privileges required.', 'webcare-pro-security'), ['status' => 403]);
        }
        global $wpdb;

        $params = $request->get_json_params() ?: [];
        $user_id = !empty($params['user_id']) ? (int) $params['user_id'] : 0;
        $action = !empty($params['action']) ? sanitize_key($params['action']) : '';
        $role = !empty($params['role']) ? sanitize_key($params['role']) : null;
        $reassign_to = !empty($params['reassign_to']) ? (int) $params['reassign_to'] : null;
        $issue_id = !empty($params['issue_id']) ? (int) $params['issue_id'] : null;

        if ($user_id <= 0) {
            return new \WP_Error('invalid_user_id', __('Valid User ID is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $mgr = new \WebCareProScanner\WordPress\UserRemediationManager();

        if ($action === 'assign_default_role') {
            $result = $mgr->assign_default_role($user_id, $role);
        } elseif ($action === 'strip_capabilities') {
            $result = $mgr->strip_injected_capabilities($user_id);
        } elseif ($action === 'delete_user') {
            $result = $mgr->delete_user($user_id, $reassign_to);
        } elseif ($action === 'restore_user') {
            $result = $mgr->restore_user_by_id($user_id);
        } elseif ($action === 'reassign_orphaned_posts') {
            $result = $mgr->reassign_orphaned_posts($user_id, $reassign_to);
        } else {
            return new \WP_Error('invalid_action', __('Invalid user remediation action.', 'webcare-pro-security'), ['status' => 400]);
        }

        if (empty($result['success'])) {
            $error_code = $result['error_code'] ?? 'remediation_failed';
            $error_status = in_array($error_code, ['invalid_target_user_id', 'target_user_not_found', 'target_user_not_admin'], true)
                ? 400
                : 500;
            return new \WP_Error($error_code, $result['error'] ?? __('User remediation failed.', 'webcare-pro-security'), ['status' => $error_status]);
        }

        // Mark associated scan issue as repaired if issue_id is provided
        $table_issues = $wpdb->prefix . 'webcareproscan_scan_issues';
        if ($issue_id > 0) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->update($table_issues, ['status' => 'repaired'], ['id' => $issue_id]);
        }

        // Also mark open issues for this user account or author as repaired
        $repair_sql = "UPDATE `{$table_issues}` SET status = 'repaired' WHERE (file_path LIKE %s OR file_path LIKE %s OR file_path LIKE %s OR file_path = %s) AND status = 'open'";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $wpdb->query(
            $wpdb->prepare(
                // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                $repair_sql,
                "user:{$user_id}%",
                "%_users:user_id_{$user_id}%",
                "%users.ID = {$user_id}%",
                "author:{$user_id}"
            )
        );

        return rest_ensure_response($result);
    }

    /**
     * Get all quarantined or backed-up user accounts.
     */
    public static function get_user_backups(\WP_REST_Request $request) {
        $mgr = new \WebCareProScanner\WordPress\UserRemediationManager();
        $backups = $mgr->list_user_backups();
        return rest_ensure_response([
            'success' => true,
            'backups' => $backups,
            'count'   => count($backups),
        ]);
    }

    /**
     * 1-Click Restore a deleted or quarantined user account.
     */
    public static function restore_user_account(\WP_REST_Request $request) {
        if (is_multisite() && !current_user_can('manage_network')) {
            return new \WP_Error('rest_forbidden', __('Multisite network administrator privileges required.', 'webcare-pro-security'), ['status' => 403]);
        }
        $params = $request->get_json_params() ?: $request->get_params();
        $backup_file = !empty($params['backup_file']) ? sanitize_text_field($params['backup_file']) : '';
        $user_id = !empty($params['user_id']) ? (int) $params['user_id'] : 0;
        $restore_all = !empty($params['all']);

        $mgr = new \WebCareProScanner\WordPress\UserRemediationManager();

        if ($restore_all) {
            $result = $mgr->restore_all_user_backups();
            return rest_ensure_response($result);
        }

        if (!empty($backup_file)) {
            $result = $mgr->restore_user($backup_file);
        } elseif ($user_id > 0) {
            $result = $mgr->restore_user_by_id($user_id);
        } else {
            return new \WP_Error('missing_param', __('Specify backup_file or user_id or all.', 'webcare-pro-security'), ['status' => 400]);
        }

        if (empty($result['success'])) {
            return new \WP_Error('restore_failed', $result['error'] ?? __('Failed to restore user account.', 'webcare-pro-security'), ['status' => 500]);
        }

        return rest_ensure_response($result);
    }

    /**
     * Dismiss / Acknowledge user backup snapshot(s) so they no longer prompt restoration alerts.
     */
    public static function dismiss_user_backup(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: $request->get_params();
        $backup_file = !empty($params['backup_file']) ? sanitize_text_field($params['backup_file']) : '';
        $user_login = !empty($params['user_login']) ? sanitize_text_field($params['user_login']) : '';
        $user_id = !empty($params['user_id']) ? (int) $params['user_id'] : 0;
        $dismiss_all = !empty($params['all']);

        $mgr = new \WebCareProScanner\WordPress\UserRemediationManager();

        if ($dismiss_all) {
            $count = $mgr->dismiss_all_missing_backups();
            return rest_ensure_response([
                'success' => true,
                /* translators: %d: count */
                'message' => sprintf(__('Dismissed %d missing user backup notifications.', 'webcare-pro-security'), $count),
            ]);
        }

        if (!empty($backup_file)) {
            $mgr->dismiss_user_backup($backup_file);
        }
        if (!empty($user_login)) {
            $mgr->dismiss_user_backup($user_login);
        }
        if ($user_id > 0) {
            $mgr->dismiss_user_backups_for_id($user_id);
        }

        return rest_ensure_response([
            'success' => true,
            'message' => __('User backup alert dismissed successfully.', 'webcare-pro-security'),
        ]);
    }

    /**
     * Permanently delete a user backup snapshot file from disk.
     */
    public static function delete_user_backup(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: $request->get_params();
        $backup_file = !empty($params['backup_file']) ? sanitize_text_field($params['backup_file']) : '';

        if (empty($backup_file)) {
            return new \WP_Error('missing_param', __('Specify backup_file to delete.', 'webcare-pro-security'), ['status' => 400]);
        }

        $mgr = new \WebCareProScanner\WordPress\UserRemediationManager();
        $result = $mgr->delete_backup_file($backup_file);

        if (empty($result['success'])) {
            return new \WP_Error('delete_failed', $result['error'] ?? __('Failed to delete user backup file.', 'webcare-pro-security'), ['status' => 500]);
        }

        return rest_ensure_response($result);
    }

    /**
     * Database: Get Rogue Administrator & Micro-Anomaly Audit
     */
    public static function get_rogue_admin_audit(\WP_REST_Request $request) {
        $audit = \WebCareProScanner\Database\RogueAdminAnomalyDetector::audit_users_and_anomalies();
        return rest_ensure_response([
            'success' => true,
            'audit'   => $audit,
        ]);
    }

    public static function get_remediation_transactions(\WP_REST_Request $request) {
        $limit = max(1, min(100, intval($request->get_param('limit') ?: 30)));
        $list  = \WebCareProScanner\Remediation\TransactionalRemediation::list_transactions($limit);
        return rest_ensure_response([
            'success'      => true,
            'transactions' => $list,
        ]);
    }

    public static function rollback_remediation_transaction(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: $request->get_params();
        $tx_id  = sanitize_text_field($params['tx_id'] ?? '');

        if (empty($tx_id)) {
            return new \WP_Error('missing_param', __('Transaction ID (tx_id) is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $result = \WebCareProScanner\Remediation\TransactionalRemediation::rollback_transaction($tx_id);
        return rest_ensure_response($result);
    }

    public static function get_reinfection_watchdog_status() {
        return rest_ensure_response(\WebCareProScanner\Quarantine\ReinfectionWatchdog::get_status());
    }

    public static function register_reinfection_watch(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $file_path = sanitize_text_field($params['file_path'] ?? '');
        $status = sanitize_key($params['expected_status'] ?? 'deleted');
        $clean_hash = sanitize_text_field($params['clean_hash'] ?? '');
        $reason = sanitize_text_field($params['reason'] ?? '');

        if (empty($file_path)) {
            return new \WP_Error('missing_param', __('Missing file_path parameter.', 'webcare-pro-security'), ['status' => 400]);
        }

        $res = \WebCareProScanner\Quarantine\ReinfectionWatchdog::register_watch($file_path, $status, $clean_hash ?: null, $reason);
        return rest_ensure_response($res);
    }

    public static function dismiss_reinfection_watch(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $watch_id = sanitize_key($params['watch_id'] ?? '');
        if (empty($watch_id)) {
            return new \WP_Error('missing_param', __('Missing watch_id parameter.', 'webcare-pro-security'), ['status' => 400]);
        }

        $res = \WebCareProScanner\Quarantine\ReinfectionWatchdog::dismiss_watch($watch_id);
        return rest_ensure_response([
            'success' => $res,
            'message' => $res ? __('Watchdog monitor dismissed.', 'webcare-pro-security') : __('Watch not found.', 'webcare-pro-security'),
            'status'  => \WebCareProScanner\Quarantine\ReinfectionWatchdog::get_status(),
        ]);
    }

    public static function check_reinfection_watchdog_now() {
        $res = \WebCareProScanner\Quarantine\ReinfectionWatchdog::inspect_all_monitors();
        return rest_ensure_response(array_merge([
            'status' => \WebCareProScanner\Quarantine\ReinfectionWatchdog::get_status(),
        ], $res));
    }
}
