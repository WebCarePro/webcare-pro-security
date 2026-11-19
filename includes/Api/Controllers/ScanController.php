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
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_scan_manifest'],
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
}