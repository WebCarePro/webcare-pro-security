<?php
declare(strict_types=1);

namespace WebCareProScanner\Api\Controllers;

use WebCareProScanner\Api\ScannerRoutes;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * McpController
 *
 * Model Context Protocol (MCP) & AI REST Controller.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
final class McpController extends AbstractApiController {

    /**
     * Register endpoints for this domain.
     *
     * @param string   $namespace REST API route namespace.
     * @param callable $permission Permission callback.
     */
    public static function register(string $namespace, callable $permission): void {
        $mcp_permission = static function (\WP_REST_Request $request) {
            $mcp_enabled = (bool) \WebCareProScanner\System\SettingsManager::get('mcp_enabled', false);
            if (!$mcp_enabled) {
                return false;
            }
            if (current_user_can('manage_options')) {
                return true;
            }
            $client_ip    = \WebCareProScanner\Firewall\FirewallEngine::get_client_ip();
            $verification = \WebCareProScanner\Api\MCPAntiLockoutValidator::verify_mcp_bearer_request($request, $client_ip);
            if (!empty($verification['allowed'])) {
                return true;
            }

            if (($verification['reason'] ?? '') === 'expired') {
                return new \WP_Error('mcp_token_expired', __('MCP Bearer token has expired. Rotate the token in WP Admin.', 'webcare-pro-security'), ['status' => 401]);
            }

            if (in_array(($verification['reason'] ?? ''), ['cidr_denied', 'invalid_cidr_configuration'], true)) {
                return new \WP_Error('mcp_ip_denied', __('Client IP is not permitted by the MCP allowed CIDR configuration.', 'webcare-pro-security'), ['status' => 403]);
            }

            return false;
        };

        $mcp_admin_only = static function (\WP_REST_Request $request) use ($permission) {
            $auth_header = (string) $request->get_header('Authorization');
            if (stripos($auth_header, 'Bearer ') === 0) {
                return false;
            }
            return (bool) call_user_func($permission, $request);
        };

        register_rest_route($namespace, '/ai/test', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'test_ai_connection'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/ai/analyze', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'analyze_code_with_ai'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/ai/models', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_ai_models'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/ai/models/update', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'update_ai_models'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/mcp/rpc', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'handle_mcp_json_rpc'],
            'permission_callback' => $mcp_permission,
        ]);

        register_rest_route($namespace, '/mcp/tools', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_mcp_tools'],
            'permission_callback' => $mcp_permission,
        ]);

        register_rest_route($namespace, '/mcp/execute', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'execute_mcp_tool'],
            'permission_callback' => $mcp_permission,
        ]);

        register_rest_route($namespace, '/mcp/audit', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_mcp_audit'],
            'permission_callback' => $mcp_permission,
        ]);

        register_rest_route($namespace, '/mcp/audit/clear', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'clear_mcp_audit'],
            'permission_callback' => $mcp_admin_only,
        ]);

        register_rest_route($namespace, '/mcp/staged-actions', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_mcp_staged_actions'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/mcp/staged-actions/approve', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'approve_mcp_staged_action'],
            'permission_callback' => $mcp_admin_only,
        ]);

        register_rest_route($namespace, '/mcp/staged-actions/reject', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'reject_mcp_staged_action'],
            'permission_callback' => $mcp_admin_only,
        ]);

        register_rest_route($namespace, '/mcp/matrix', [
            'methods'             => ['GET', 'POST'],
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'handle_mcp_matrix'],
            'permission_callback' => $mcp_admin_only,
        ]);

        register_rest_route($namespace, '/mcp/persona', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'apply_mcp_persona'],
            'permission_callback' => $mcp_admin_only,
        ]);

        register_rest_route($namespace, '/mcp/token/reveal', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'reveal_mcp_token'],
            'permission_callback' => $mcp_admin_only,
        ]);

        register_rest_route($namespace, '/mcp/token/rotate', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'rotate_mcp_token'],
            'permission_callback' => $mcp_admin_only,
        ]);

        register_rest_route($namespace, '/mcp/snapshots', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_mcp_snapshots'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/mcp/snapshots/restore', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'restore_mcp_snapshot'],
            'permission_callback' => $mcp_admin_only,
        ]);

    }
}