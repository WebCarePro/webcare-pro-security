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
            'callback'            => [self::class, 'test_ai_connection'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/ai/analyze', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'analyze_code_with_ai'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/ai/models', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_ai_models'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/ai/models/update', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'update_ai_models'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/mcp/rpc', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'handle_mcp_json_rpc'],
            'permission_callback' => $mcp_permission,
        ]);

        register_rest_route($namespace, '/mcp/tools', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_mcp_tools'],
            'permission_callback' => $mcp_permission,
        ]);

        register_rest_route($namespace, '/mcp/execute', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'execute_mcp_tool'],
            'permission_callback' => $mcp_permission,
        ]);

        register_rest_route($namespace, '/mcp/audit', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_mcp_audit'],
            'permission_callback' => $mcp_permission,
        ]);

        register_rest_route($namespace, '/mcp/audit/clear', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'clear_mcp_audit'],
            'permission_callback' => $mcp_admin_only,
        ]);

        register_rest_route($namespace, '/mcp/staged-actions', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_mcp_staged_actions'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/mcp/staged-actions/approve', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'approve_mcp_staged_action'],
            'permission_callback' => $mcp_admin_only,
        ]);

        register_rest_route($namespace, '/mcp/staged-actions/reject', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'reject_mcp_staged_action'],
            'permission_callback' => $mcp_admin_only,
        ]);

        register_rest_route($namespace, '/mcp/matrix', [
            'methods'             => ['GET', 'POST'],
            'callback'            => [self::class, 'handle_mcp_matrix'],
            'permission_callback' => $mcp_admin_only,
        ]);

        register_rest_route($namespace, '/mcp/persona', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'apply_mcp_persona'],
            'permission_callback' => $mcp_admin_only,
        ]);

        register_rest_route($namespace, '/mcp/token/reveal', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'reveal_mcp_token'],
            'permission_callback' => $mcp_admin_only,
        ]);

        register_rest_route($namespace, '/mcp/token/rotate', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'rotate_mcp_token'],
            'permission_callback' => $mcp_admin_only,
        ]);

        register_rest_route($namespace, '/mcp/snapshots', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_mcp_snapshots'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/mcp/snapshots/restore', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'restore_mcp_snapshot'],
            'permission_callback' => $mcp_admin_only,
        ]);

    }

    /**
     * Test AI connection
     */
    public static function test_ai_connection(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $provider = sanitize_text_field($params['provider'] ?? 'openai');
        $api_key  = trim($params['api_key'] ?? '');
        $model    = sanitize_text_field($params['model'] ?? '');

        if ($provider === 'wp_ai_connect') {
            $result = \WebCareProScanner\System\AIService::test_connection($provider, '', $model);
            if (empty($result['success'])) {
                return new \WP_Error('ai_test_failed', $result['error'] ?? 'WordPress Native AI Connect Test Failed', ['status' => 400]);
            }
            return rest_ensure_response($result);
        }

        // If key is masked or empty, fall back to stored key
        if ($api_key === '' || $api_key === '••••••••') {
            $settings = \WebCareProScanner\System\SettingsManager::get_settings();
            if ($provider === 'gemini') {
                $api_key = $settings['gemini_api_key'] ?? '';
                if (!$model) $model = $settings['gemini_model'] ?? 'gemini-3.8-flash';
            } elseif ($provider === 'claude') {
                $api_key = $settings['claude_api_key'] ?? '';
                if (!$model) $model = $settings['claude_model'] ?? 'claude-sonnet-5-5';
            } else {
                $api_key = $settings['openai_api_key'] ?? '';
                if (!$model) $model = $settings['openai_model'] ?? 'gpt-6.1-sol';
            }
        }

        $result = \WebCareProScanner\System\AIService::test_connection($provider, $api_key, $model);
        if (empty($result['success'])) {
            return new \WP_Error('ai_test_failed', $result['error'] ?? 'AI Test Connection Failed', ['status' => 400]);
        }

        return rest_ensure_response($result);
    }

    /**
     * Run AI forensic analysis on code or suspicious finding
     */
    public static function analyze_code_with_ai(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        try {
            $analysis = \WebCareProScanner\System\AIService::analyze_code($params);
            return rest_ensure_response($analysis);
        } catch (\Exception $e) {
            return new \WP_Error('ai_analysis_error', $e->getMessage(), ['status' => 400]);
        }
    }

    /**
     * Get available AI model catalog
     */
    public static function get_ai_models(\WP_REST_Request $request) {
        $catalog = \WebCareProScanner\System\AIService::get_available_models();
        return rest_ensure_response([
            'success' => true,
            'catalog' => $catalog,
        ]);
    }

    /**
     * Check provider APIs for new agent releases and update catalog & settings
     */
    public static function update_ai_models(\WP_REST_Request $request) {
        try {
            $params = $request->get_json_params() ?: [];
            $auto_upgrade = !isset($params['auto_upgrade']) || !empty($params['auto_upgrade']);
            $result = \WebCareProScanner\System\AIService::check_and_update_models($auto_upgrade);
            $settings = \WebCareProScanner\System\SettingsManager::get_settings();
            $result['settings'] = $settings;
            return rest_ensure_response($result);
        } catch (\Exception $e) {
            return new \WP_Error('ai_models_update_error', $e->getMessage(), ['status' => 400]);
        }
    }

    public static function get_mcp_tools(\WP_REST_Request $request) {
        $catalog = \WebCareProScanner\Api\MCPAgentService::get_tools_catalog();
        return rest_ensure_response($catalog);
    }

    public static function execute_mcp_tool(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $tool   = sanitize_text_field($params['tool'] ?? $params['name'] ?? '');
        $args   = is_array($params['arguments'] ?? null) ? $params['arguments'] : (is_array($params['args'] ?? null) ? $params['args'] : []);

        if (empty($tool)) {
            return new \WP_Error('missing_tool', __('Tool name is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        // WordPress.org Security Directive: Remote MCP execution endpoints must remain strictly read-only.
        // Mutating actions cannot be executed remotely via MCP and are restricted to the local WP Admin console.
        $catalog_map = \WebCareProScanner\Api\MCPAgentService::get_registered_tool_map();
        if (isset($catalog_map[$tool]) && !empty($catalog_map[$tool]['isMutating'])) {
            return new \WP_Error(
                'mcp_mutating_action_prohibited',
                __('Mutating administrative actions cannot be executed remotely via MCP. Please execute this action directly from the local WordPress Admin dashboard.', 'webcare-pro-security'),
                ['status' => 403]
            );
        }

        $result = \WebCareProScanner\Api\MCPAgentService::execute_tool($tool, $args);
        return rest_ensure_response($result);
    }

    public static function get_mcp_audit(\WP_REST_Request $request) {
        $limit = max(10, min(150, intval($request->get_param('limit') ?? 50)));
        return rest_ensure_response([
            'success' => true,
            'entries' => \WebCareProScanner\Api\MCPAgentService::get_audit_log($limit),
        ]);
    }

    public static function clear_mcp_audit(\WP_REST_Request $request) {
        \WebCareProScanner\Api\MCPAgentService::clear_audit_log();
        return rest_ensure_response([
            'success' => true,
            'message' => __('MCP agent audit trail cleared.', 'webcare-pro-security'),
        ]);
    }

    public static function handle_mcp_json_rpc(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        if (($params['method'] ?? '') === 'tools/call') {
            $tool = sanitize_text_field($params['params']['name'] ?? '');
            $catalog_map = \WebCareProScanner\Api\MCPAgentService::get_registered_tool_map();
            if (isset($catalog_map[$tool]) && !empty($catalog_map[$tool]['isMutating'])) {
                return rest_ensure_response([
                    'jsonrpc' => '2.0',
                    'id'      => $params['id'] ?? null,
                    'error'   => [
                        'code'    => -32001,
                        'message' => __('Mutating administrative actions cannot be executed remotely via MCP. Please execute this action directly from the local WordPress Admin dashboard.', 'webcare-pro-security'),
                    ],
                ]);
            }
        }
        $rpc    = \WebCareProScanner\Api\MCPAgentService::handle_json_rpc($params);
        return rest_ensure_response($rpc);
    }

    public static function get_mcp_staged_actions(\WP_REST_Request $request) {
        $status = sanitize_text_field($request->get_param('status') ?? 'all');
        $list   = \WebCareProScanner\Api\MCPAgentService::get_staged_actions($status);
        return rest_ensure_response([
            'success'        => true,
            'actions'        => $list,
            'staged_actions' => $list,
        ]);
    }

    public static function approve_mcp_staged_action(\WP_REST_Request $request) {
        $params    = $request->get_json_params() ?: [];
        $staged_id = sanitize_text_field((string) ($params['staged_id'] ?? $params['action_id'] ?? $request->get_param('staged_id') ?? $request->get_param('action_id') ?? ''));
        $step_up   = (string) ($params['step_up_secret'] ?? $params['totp_code'] ?? $params['password'] ?? '');
        if ($staged_id === '') {
            return new \WP_Error('missing_param', __('Staged action ID is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $res = \WebCareProScanner\Api\MCPAgentService::approve_staged_action($staged_id, get_current_user_id(), $step_up);
        return rest_ensure_response($res);
    }

    public static function reject_mcp_staged_action(\WP_REST_Request $request) {
        $params    = $request->get_json_params() ?: [];
        $staged_id = sanitize_text_field((string) ($params['staged_id'] ?? $params['action_id'] ?? $request->get_param('staged_id') ?? $request->get_param('action_id') ?? ''));
        if ($staged_id === '') {
            return new \WP_Error('missing_param', __('Staged action ID is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $res = \WebCareProScanner\Api\MCPAgentService::reject_staged_action($staged_id, get_current_user_id());
        return rest_ensure_response($res);
    }

    public static function handle_mcp_matrix(\WP_REST_Request $request) {
        if ($request->get_method() === 'POST') {
            $params = $request->get_json_params() ?: [];
            $matrix = is_array($params['matrix'] ?? null) ? $params['matrix'] : [];
            $clean_matrix = \WebCareProScanner\System\SettingsManager::sanitize_mcp_tool_matrix($matrix);
            $settings = \WebCareProScanner\System\SettingsManager::get_settings();
            $settings['mcp_tool_matrix'] = $clean_matrix;
            \WebCareProScanner\System\SettingsManager::save_settings($settings);

            return rest_ensure_response([
                'success' => true,
                'matrix'  => $clean_matrix,
                'message' => __('MCP tool policy governance matrix saved.', 'webcare-pro-security'),
            ]);
        }

        $saved    = \WebCareProScanner\System\SettingsManager::get('mcp_tool_matrix', []);
        $defaults = \WebCareProScanner\System\SettingsManager::get_default_mcp_tool_matrix();
        $merged   = array_merge($defaults, is_array($saved) ? $saved : []);
        return rest_ensure_response([
            'success' => true,
            'matrix'  => \WebCareProScanner\System\SettingsManager::sanitize_mcp_tool_matrix($merged),
        ]);
    }

    public static function apply_mcp_persona(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $preset = sanitize_key((string) ($params['preset'] ?? 'guided'));
        $res    = \WebCareProScanner\Api\MCPAgentService::apply_persona_preset($preset);
        return rest_ensure_response($res);
    }

    public static function reveal_mcp_token(\WP_REST_Request $request) {
        unset($request);
        $token      = (string) \WebCareProScanner\System\SettingsManager::get('mcp_token', '');
        $created_at = (int) \WebCareProScanner\System\SettingsManager::get('mcp_token_created_at', 0);
        $ttl_days   = (int) \WebCareProScanner\System\SettingsManager::get('mcp_token_ttl_days', 0);
        $expires_at = ($ttl_days > 0 && $created_at > 0) ? ($created_at + ($ttl_days * 86400)) : 0;
        return rest_ensure_response([
            'success'    => $token !== '',
            'token'      => $token,
            'created_at' => $created_at,
            'ttl_days'   => $ttl_days,
            'expires_at' => $expires_at,
        ]);
    }

    public static function rotate_mcp_token(\WP_REST_Request $request) {
        unset($request);
        $new_plain = 'webcareproscan_mcp_' . bin2hex(random_bytes(16));
        \WebCareProScanner\System\SettingsManager::save_settings([
            'mcp_token'            => $new_plain,
            'mcp_token_created_at' => time(),
        ]);
        $ttl_days = (int) \WebCareProScanner\System\SettingsManager::get('mcp_token_ttl_days', 0);
        return rest_ensure_response([
            'success'    => true,
            'token'      => $new_plain,
            'created_at' => time(),
            'ttl_days'   => $ttl_days,
            'expires_at' => $ttl_days > 0 ? (time() + ($ttl_days * 86400)) : 0,
            'message'    => __('MCP Bearer token rotated cleanly.', 'webcare-pro-security'),
        ]);
    }

    public static function get_mcp_snapshots(\WP_REST_Request $request) {
        $limit = max(1, min(15, intval($request->get_param('limit') ?? 15)));
        return rest_ensure_response([
            'success'   => true,
            'snapshots' => \WebCareProScanner\Api\MCPSnapshotManager::list_snapshots($limit),
        ]);
    }

    public static function restore_mcp_snapshot(\WP_REST_Request $request) {
        $params      = $request->get_json_params() ?: [];
        $snapshot_id = sanitize_text_field((string) ($params['snapshot_id'] ?? ''));
        $res         = \WebCareProScanner\Api\MCPSnapshotManager::restore_snapshot($snapshot_id);
        return rest_ensure_response($res);
    }
}
