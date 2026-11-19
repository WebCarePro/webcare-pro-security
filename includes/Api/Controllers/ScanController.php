<?php
declare(strict_types=1);

namespace WebCareProScanner\Api\Controllers;

use WebCareProScanner\Api\ScannerRoutes;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * ScanController
 *
 * Scan & Vulnerability Management REST Controller.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
final class ScanController extends AbstractApiController {

    /**
     * Register endpoints for this domain.
     *
     * @param string   $namespace REST API route namespace.
     * @param callable $permission Permission callback.
     */
    public static function register(string $namespace, callable $permission): void {
        register_rest_route($namespace, '/scan/start', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'start_scan'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/scan/batch', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'process_batch'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/scan/deep-audit', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'run_deep_audit'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/scan/latest', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_latest_scan'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/scan/active', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_active_scan'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/scan/abort', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'abort_scan'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/scan/history', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_scan_history'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/scan/history/clear', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'clear_scan_history'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/scan/history/(?P<id>\d+)', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_scan_log_detail'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/scan/export', [
            'methods'             => ['GET', 'POST'],
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'export_scan_results'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/scan/manifest', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_scan_manifest'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/scan/manifest/download', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'download_scan_manifest'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/vulnerabilities/report', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_vulnerabilities_report'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/file/view', [
            'methods'             => ['GET', 'POST'],
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'view_file_content'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/post/view', [
            'methods'             => ['GET', 'POST'],
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'view_post_content'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/component/changelog', [
            'methods'             => ['GET', 'POST'],
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_component_changelog'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/issues/(?P<id>\d+)', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'update_issue'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/vulnerabilities/virtual-shield', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'activate_vulnerability_virtual_shield'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/vulnerabilities/safe-update', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'execute_safe_plugin_update'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/vulnerabilities/safe-rollback', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'execute_safe_plugin_rollback'],
            'permission_callback' => $permission,
        ]);

    }

    public static function get_scan_manifest(\WP_REST_Request $request) {
        if (is_multisite() && !current_user_can('manage_network')) {
            return new \WP_Error('rest_forbidden', __('Multisite network administrator privileges required.', 'webcare-pro-security'), ['status' => 403]);
        }

        $scan_id = (int) $request->get_param('scan_id');
        if ($scan_id <= 0) {
            global $wpdb;
            $table_scans = $wpdb->prefix . 'webcareproscan_scans';
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $scan_id = (int) $wpdb->get_var($wpdb->prepare('SELECT id FROM %i ORDER BY id DESC LIMIT 1', $table_scans));
        }

        if ($scan_id <= 0) {
            return new \WP_Error('no_scans', __('No scans found.', 'webcare-pro-security'), ['status' => 404]);
        }

        $page     = max(1, (int) $request->get_param('page'));
        $per_page = max(1, min(500, (int) ($request->get_param('per_page') ?: 50)));
        $search   = sanitize_text_field((string) $request->get_param('search'));
        $status   = sanitize_text_field((string) $request->get_param('status'));

        $summary = null;
        $result  = null;
        if (class_exists('\\WebCareProScanner\\Scan\\ScanVaultManager')) {
            $summary = \WebCareProScanner\Scan\ScanVaultManager::get_manifest_summary($scan_id);
            // Correct parameter order: ($scan_id, $page, $limit, $status, $search)
            $result  = \WebCareProScanner\Scan\ScanVaultManager::get_manifest_files($scan_id, $page, $per_page, $status, $search);
        }

        // Fallback for legacy scans stored in MySQL table only when no Vault manifest exists
        if (!$result || empty($result['success'])) {
            global $wpdb;
            $table_files = $wpdb->prefix . 'webcareproscan_scan_files';
            $where = ['scan_id = %d'];
            $params = [$scan_id];
            if ($status) {
                $where[] = 'status = %s';
                $params[] = $status;
            }
            if ($search) {
                $where[] = 'file_path LIKE %s';
                $params[] = '%' . $wpdb->esc_like($search) . '%';
            }
            $where_sql = implode(' AND ', $where);
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $total_legacy = (int) $wpdb->get_var(
                // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare -- $where_sql is assembled from fixed clauses and placeholders above; all request values are passed as prepared arguments.
                $wpdb->prepare("SELECT COUNT(*) FROM %i WHERE {$where_sql}", ...array_merge([$table_files], $params))
            );
            $offset = ($page - 1) * $per_page;
            $params_page = array_merge($params, [$per_page, $offset]);
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $legacy_files = $wpdb->get_results(
                // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber -- $where_sql is assembled from fixed clauses and placeholders above; table name and all request values are supplied as prepared arguments.
                $wpdb->prepare("SELECT * FROM %i WHERE {$where_sql} ORDER BY id ASC LIMIT %d OFFSET %d", ...array_merge([$table_files], $params_page)),
                ARRAY_A
            ) ?: [];

            $result = [
                'success'     => true,
                'files'       => $legacy_files,
                'total'       => $total_legacy,
                'total_count' => $total_legacy,
                'page'        => $page,
                'limit'       => $per_page,
                'per_page'    => $per_page,
                'total_pages' => (int) ceil($total_legacy / max(1, $per_page)),
                'source'      => 'legacy_database',
            ];
        }

        return rest_ensure_response([
            'success'   => true,
            'scan_id'   => $scan_id,
            'summary'   => $summary,
            'manifest'  => $result,
        ]);
    }
}