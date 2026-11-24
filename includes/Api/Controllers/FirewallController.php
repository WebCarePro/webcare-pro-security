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
            'callback'            => [self::class, 'get_firewall_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/logs', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_firewall_logs'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/logs/stats', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_firewall_log_stats'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/logs/files', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_firewall_log_files'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/logs/timeline', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_session_timeline'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/logs/trust-action', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'trust_log_action'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/logs/retention', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'update_firewall_log_retention'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/logs/prune', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'prune_firewall_logs'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/logs/download', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'download_firewall_log_file'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/logs/delete', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'delete_firewall_log'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/logs/block-ip', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'add_firewall_blocked_ip'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/logs/unblock-ip', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'unblock_firewall_ip'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/logs/unblock-all', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'unblock_all_firewall_ips'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/customer/lookup-block', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'lookup_customer_lockout'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/customer/unblock', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'unblock_customer_lockout'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/blocklist', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_firewall_blocklist'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/blocklist/clear-expired', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'clear_expired_firewall_blocklist'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/allowlist-rule-target', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'allowlist_firewall_rule_target'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/logs/whitelist-ip', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'add_firewall_whitelisted_ip'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/whitelist', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_firewall_whitelist'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/whitelist/remove', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'remove_firewall_whitelisted_ip'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/clear-logs', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'clear_firewall_logs'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/toggle', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'toggle_firewall'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/save-rule', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'save_single_firewall_rule'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/roles', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_firewall_roles'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/server-security/config', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_server_security_config'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/server-security/save', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'save_server_security_config'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/server-security/deploy-htaccess', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'deploy_server_security_htaccess'],
            'permission_callback' => $permission,
        ]);

        foreach (['/firewall/redirect-shield', '/redirect-shield'] as $r_base) {
            register_rest_route($namespace, $r_base . '/status', [
                'methods'             => ['GET', 'POST'],
                'callback'            => [self::class, 'get_redirect_shield_status'],
                'permission_callback' => $permission,
            ]);

            register_rest_route($namespace, $r_base . '/probe', [
                'methods'             => 'POST',
                'callback'            => [self::class, 'run_redirect_canary_probe'],
                'permission_callback' => $permission,
            ]);

            register_rest_route($namespace, $r_base . '/restore', [
                'methods'             => 'POST',
                'callback'            => [self::class, 'restore_htaccess_vault_snapshot'],
                'permission_callback' => $permission,
            ]);

            register_rest_route($namespace, $r_base . '/lock', [
                'methods'             => 'POST',
                'callback'            => [self::class, 'toggle_htaccess_lock'],
                'permission_callback' => $permission,
            ]);

            register_rest_route($namespace, $r_base . '/heal-urls', [
                'methods'             => 'POST',
                'callback'            => [self::class, 'heal_database_core_urls'],
                'permission_callback' => $permission,
            ]);

            register_rest_route($namespace, $r_base . '/snapshot', [
                'methods'             => 'POST',
                'callback'            => [self::class, 'create_htaccess_vault_snapshot'],
                'permission_callback' => $permission,
            ]);
        }

        register_rest_route($namespace, '/caf/overview', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_caf_overview'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/caf/apply-profile', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'apply_caf_profile'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/caf/reprofile', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'reprofile_caf_stack'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/caf/killswitch', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'toggle_caf_killswitch'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/caf/cloudflare-status', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_caf_cloudflare_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/caf/sync-cloudflare', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'sync_caf_cloudflare'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/caf/toggle-circuit-breaker', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'toggle_origin_circuit_breaker'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/caf/behavioral-status', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_caf_behavioral_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/caf/create-exemption', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'create_caf_exemption'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/caf/delete-exemption', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'delete_caf_exemption'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/caf/toggle-pow-challenge', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'toggle_caf_pow_challenge'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/micro-waf/status', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_micro_waf_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/micro-waf/compile', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'compile_micro_waf'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/micro-waf/install', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'install_micro_waf_preload'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/firewall/micro-waf/uninstall', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'uninstall_micro_waf_preload'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/whitelist/rules', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_whitelist_rules'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/whitelist/add', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'add_whitelist_rule'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/whitelist/remove', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'remove_whitelist_rule'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/server-security/verify', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'verify_server_security_rules'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/server-security/caddy-config', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_caddy_server_config'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/rescue/status', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_rescue_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/rescue/trust-action', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'rescue_trust_action'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/rescue/pause-15m', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'rescue_pause_15m'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/rescue/resume', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'rescue_resume'],
            'permission_callback' => $permission,
        ]);

    }

    public static function get_firewall_status(): \WP_REST_Response {
        return rest_ensure_response(\WebCareProScanner\Firewall\FirewallEngine::get_status());
    }

    public static function get_firewall_logs(\WP_REST_Request $request): \WP_REST_Response {
        $limit       = (int) ($request->get_param('limit') ?: 50);
        $offset      = (int) ($request->get_param('offset') ?: 0);
        $range       = sanitize_key((string) ($request->get_param('range') ?: 'today'));
        $date        = sanitize_text_field((string) ($request->get_param('date') ?: ''));
        $search      = sanitize_text_field((string) ($request->get_param('search') ?: ''));
        $category    = sanitize_text_field((string) ($request->get_param('category') ?: ''));
        $action      = sanitize_text_field((string) ($request->get_param('action') ?: ''));
        $method      = sanitize_text_field((string) ($request->get_param('method') ?: ''));
        $ip          = sanitize_text_field((string) ($request->get_param('ip') ?: ''));
        $status_code = sanitize_text_field((string) ($request->get_param('status_code') ?: ''));
        $sort_by     = sanitize_key((string) ($request->get_param('sort_by') ?: 'created_at'));
        $sort_order  = strtolower(sanitize_key((string) ($request->get_param('sort_order') ?: 'desc')));
        $is_export   = !empty($request->get_param('is_export'));
        $include_system_info = !empty($request->get_param('include_system_info'));

        $filters = array_filter([
            'range'       => $range,
            'date'        => $date,
            'search'      => $search,
            'category'    => $category,
            'action'      => $action,
            'method'      => $method,
            'ip'          => $ip,
            'status_code' => $status_code,
            'sort_by'     => $sort_by,
            'sort_order'  => $sort_order,
            'is_export'   => $is_export,
        ]);

        $res = \WebCareProScanner\Firewall\FirewallEngine::get_logs($limit, $offset, $filters);
        $res['current_client_ip'] = \WebCareProScanner\Firewall\FirewallEngine::get_client_ip();
        $res['retention_days']    = \WebCareProScanner\Firewall\WafFileLogger::get_retention_days();
        $res['active_range']      = $range;

        if ($include_system_info && class_exists('\\WebCareProScanner\\System\\TelemetrySnapshot')) {
            $res['environment_snapshot'] = \WebCareProScanner\System\TelemetrySnapshot::get_snapshot();
        }

        return rest_ensure_response($res);
    }

    public static function get_firewall_log_stats(\WP_REST_Request $request): \WP_REST_Response {
        $range = sanitize_key((string) ($request->get_param('range') ?: 'today'));
        return rest_ensure_response([
            'stats'          => \WebCareProScanner\Firewall\FirewallEngine::get_log_stats($range),
            'retention_days' => \WebCareProScanner\Firewall\WafFileLogger::get_retention_days(),
        ]);
    }

    public static function get_firewall_log_files(): \WP_REST_Response {
        return rest_ensure_response([
            'files'          => \WebCareProScanner\Firewall\WafFileLogger::get_available_files(),
            'storage_dir'    => \WebCareProScanner\Firewall\WafFileLogger::get_storage_dir(),
            'retention_days' => \WebCareProScanner\Firewall\WafFileLogger::get_retention_days(),
        ]);
    }

    /**
     * Retrieve chronological behavioral event timeline for a specific IP or session fingerprint.
     */
    public static function get_session_timeline(\WP_REST_Request $request): \WP_REST_Response {
        $ip = sanitize_text_field(trim((string) $request->get_param('ip')));
        $session = sanitize_text_field(trim((string) $request->get_param('session_hash')));

        if ($ip === '' && $session === '') {
            return new \WP_REST_Response(['error' => __('Either IP address or session fingerprint is required.', 'webcare-pro-security')], 400);
        }

        $filters = ['range' => '7days'];
        if ($ip !== '') {
            $filters['ip'] = $ip;
        }

        $result = \WebCareProScanner\Firewall\FirewallEngine::get_logs(100, 0, $filters);
        $logs   = $result['logs'] ?? [];

        if ($session !== '') {
            $logs = array_values(array_filter($logs, static function ($log) use ($session) {
                return ($log['session_hash'] ?? '') === $session;
            }));
        }

        // Ascending chronological order for timeline playback
        usort($logs, static function ($a, $b) {
            $ts_a = isset($a['timestamp']) ? (int) $a['timestamp'] : strtotime((string) ($a['created_at'] ?? 'now'));
            $ts_b = isset($b['timestamp']) ? (int) $b['timestamp'] : strtotime((string) ($b['created_at'] ?? 'now'));
            return $ts_a <=> $ts_b;
        });

        // Compute aggregate behavioral verdict
        $is_human_scores = array_filter(array_column($logs, 'is_human_score'));
        $avg_human_score = !empty($is_human_scores) ? intval(array_sum($is_human_scores) / count($is_human_scores)) : 50;
        $human_verdict   = ($avg_human_score >= 80) ? 'Likely Real Customer' : (($avg_human_score <= 20) ? 'Confirmed Bot / Automated Probe' : 'Uncertain / Mixed');

        return rest_ensure_response([
            'ip'              => $ip,
            'session_hash'    => $session,
            'total_events'    => count($logs),
            'human_verdict'   => $human_verdict,
            'human_score'     => $avg_human_score,
            'timeline'        => $logs,
        ]);
    }

    /**
     * 1-Click "Learn From This Log" / "Trust This Customer Action"
     * Create narrow (route_path + param_key + user_role) scoped allowlist rule from a log incident.
     */
    public static function trust_log_action(\WP_REST_Request $request): \WP_REST_Response {
        $params      = $request->get_json_params() ?: [];
        $rule_id     = sanitize_text_field(trim((string) ($params['rule_id'] ?? '')));
        $uri         = sanitize_text_field(trim((string) ($params['uri'] ?? '')));
        $ip          = sanitize_text_field(trim((string) ($params['ip'] ?? '')));
        $label       = sanitize_text_field(trim((string) ($params['label'] ?? '')));
        $param_key   = sanitize_text_field(trim((string) ($params['param_key'] ?? '')));
        $user_role   = sanitize_key(trim((string) ($params['user_role'] ?? '')));
        $method      = strtoupper(sanitize_key(trim((string) ($params['method'] ?? ''))));
        $incident_id = sanitize_text_field(trim((string) ($params['incident_id'] ?? '')));

        if ($incident_id === '') {
            return new \WP_REST_Response([
                'success' => false,
                'code'    => 'missing_incident_id',
                'message' => __('Authoritative incident ID is strictly required to establish verified method and parameter context.', 'webcare-pro-security'),
            ], 400);
        }

        if (!class_exists('\\WebCareProScanner\\Firewall\\WafFileLogger')) {
            return new \WP_REST_Response(['success' => false, 'message' => __('WAF file logger unavailable.', 'webcare-pro-security')], 500);
        }

        // Authoritatively query and resolve the exact incident across the entire retained WAF log store
        // Uses 'range' => 'all' so incident lookup spans all retained daily WAF partitions, independent of activity-log retention
        $recent_logs = \WebCareProScanner\Firewall\WafFileLogger::query_logs([
            'search' => $incident_id,
            'action' => 'all',
            'range'  => 'all',
        ], 50);

        $incident_record = null;
        foreach ($recent_logs['logs'] ?? [] as $log) {
            $log_inc_id = (string) ($log['incident_id'] ?? ($log['id'] ?? ''));
            if ($log_inc_id === $incident_id || (string) ($log['id'] ?? '') === $incident_id) {
                $incident_record = $log;
                break;
            }
        }

        if ($incident_record === null) {
            return new \WP_REST_Response([
                'success' => false,
                'code'    => 'incident_not_found',
                /* translators: %s: Incident identifier */
                'message' => sprintf(__('Incident record "%s" was not found in audit logs. Cannot establish verified trust context.', 'webcare-pro-security'), $incident_id),
            ], 404);
        }

        // Extract and verify server-authoritative incident values
        $authoritative_method = strtoupper(trim((string) ($incident_record['request_method'] ?? '')));
        $authoritative_rule   = trim((string) ($incident_record['rule_id'] ?? ''));
        $raw_inc_uri          = (string) ($incident_record['request_uri'] ?? '');
        $authoritative_path   = (string) wp_parse_url($raw_inc_uri, PHP_URL_PATH);
        if ($authoritative_path === '') {
            $authoritative_path = (string) strtok($raw_inc_uri, '?');
        }
        if ($authoritative_path === '') {
            $authoritative_path = '/';
        }

        // Authoritative parameter key resolution: use matched_param_key exclusively.
        // Never fall back to matched_param or payload match values for historical records.
        $authoritative_param_key = trim((string) ($incident_record['matched_param_key'] ?? ''));

        // Validate client parameters against authoritative incident record to prevent parameter/method forgery
        if ($method !== '' && $method !== $authoritative_method) {
            $err_msg = sprintf(
                /* translators: 1: Supplied HTTP method, 2: Authoritative incident HTTP method */
                __('Supplied method "%1$s" does not match authoritative incident method "%2$s".', 'webcare-pro-security'),
                $method,
                $authoritative_method
            );
            return new \WP_REST_Response([
                'success' => false,
                'code'    => 'method_mismatch',
                'message' => $err_msg,
            ], 400);
        }
        $method = $authoritative_method;

        if ($rule_id !== '' && $rule_id !== $authoritative_rule) {
            $err_msg = sprintf(
                /* translators: 1: Supplied rule ID, 2: Authoritative incident rule ID */
                __('Supplied rule ID "%1$s" does not match authoritative incident rule ID "%2$s".', 'webcare-pro-security'),
                $rule_id,
                $authoritative_rule
            );
            return new \WP_REST_Response([
                'success' => false,
                'code'    => 'rule_mismatch',
                'message' => $err_msg,
            ], 400);
        }
        $rule_id = $authoritative_rule;

        $client_clean_path = (string) wp_parse_url($uri, PHP_URL_PATH);
        if ($client_clean_path === '') {
            $client_clean_path = (string) strtok($uri, '?');
        }
        if ($client_clean_path !== '' && $client_clean_path !== $authoritative_path) {
            $err_msg = sprintf(
                /* translators: 1: Supplied URI path, 2: Authoritative incident path */
                __('Supplied URI path "%1$s" does not match authoritative incident path "%2$s".', 'webcare-pro-security'),
                $client_clean_path,
                $authoritative_path
            );
            return new \WP_REST_Response([
                'success' => false,
                'code'    => 'uri_mismatch',
                'message' => $err_msg,
            ], 400);
        }
        $target_uri = $authoritative_path;

        // If the client requested parameter-specific scoping, verify the parameter key against authoritative incident
        if ($param_key !== '') {
            if ($authoritative_param_key === '') {
                return new \WP_REST_Response([
                    'success' => false,
                    'code'    => 'param_key_unavailable',
                    'message' => __('Authoritative parameter key is unavailable for this incident record. Cannot create parameter-scoped exemption without verified parameter key.', 'webcare-pro-security'),
                ], 400);
            }
            if ($param_key !== $authoritative_param_key) {
                $err_msg = sprintf(
                    /* translators: 1: Supplied parameter key, 2: Authoritative incident parameter key */
                    __('Supplied parameter key "%1$s" does not match authoritative incident parameter key "%2$s".', 'webcare-pro-security'),
                    $param_key,
                    $authoritative_param_key
                );
                return new \WP_REST_Response([
                    'success' => false,
                    'code'    => 'param_key_mismatch',
                    'message' => $err_msg,
                ], 400);
            }
        } else {
            // Adopt authoritative parameter key if present on the incident
            $param_key = $authoritative_param_key;
        }

        // Mandatory method validation
        $valid_methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
        if ($method === '' || !in_array($method, $valid_methods, true)) {
            return new \WP_REST_Response([
                'success' => false,
                'code'    => 'invalid_method',
                'message' => __('Authoritative incident HTTP method is invalid or unrecorded. Cannot trust action without a verified method.', 'webcare-pro-security'),
            ], 400);
        }

        if ($target_uri === '' || $rule_id === '') {
            return new \WP_REST_Response(['success' => false, 'message' => __('Both Log URI and rule ID are required for scoped trust.', 'webcare-pro-security')], 400);
        }

        // PR 1.4 & v3.23.1: Zero-tolerance exploit invariant (SQLi, RCE, LFI, Object Injection are never exemptible)
        if (class_exists('\\WebCareProScanner\\Firewall\\RescueAssistantManager') && \WebCareProScanner\Firewall\RescueAssistantManager::is_zero_tolerance_rule($rule_id)) {
            return new \WP_REST_Response([
                'success' => false,
                'code'    => 'zero_tolerance_rule',
                'message' => __('Security Invariant: Confirmed SQLi/RCE/LFI zero-tolerance exploit rules cannot be exempted.', 'webcare-pro-security')
            ], 403);
        }

        if (class_exists('\\WebCareProScanner\\Firewall\\RescueAssistantManager')) {
            /* translators: %s: Rule identifier */
            $rule_label = sprintf(__('1-Click Trust from WAF Log (%s)', 'webcare-pro-security'), $rule_id);
            $trust_res = \WebCareProScanner\Firewall\RescueAssistantManager::trust_and_allow_action([
                'type'       => 'uri',
                'value'      => $target_uri,
                'rule_id'    => $rule_id,
                'method'     => $method,
                'label'      => $label ?: $rule_label,
                'ip'         => $ip ?: (string) ($incident_record['ip_address'] ?? ''),
                'param_key'  => $param_key,
                'user_role'  => $user_role ?: (string) ($incident_record['user_role'] ?? ''),
            ]);
            $status_code = !empty($trust_res['success']) ? 200 : ((isset($trust_res['code']) && $trust_res['code'] === 'zero_tolerance_rule') ? 403 : 400);
            return new \WP_REST_Response($trust_res, $status_code);
        }

        return new \WP_REST_Response(['success' => false, 'message' => __('Rescue assistant manager not available.', 'webcare-pro-security')], 500);
    }

    /**
     * Retrieve Rescue Assistant recent block diagnostics, 15m pause state, trusted actions, and Daily Security Story.
     */
    public static function get_rescue_status(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\RescueAssistantManager')) {
            return new \WP_REST_Response(['success' => false, 'message' => __('Rescue Assistant unavailable.', 'webcare-pro-security')], 500);
        }
        $minutes = max(5, min(60, intval($request->get_param('minutes') ?: 15)));
        return new \WP_REST_Response([
            'success'         => true,
            'pause_status'    => \WebCareProScanner\Firewall\RescueAssistantManager::get_pause_status(),
            'recent_blocks'   => \WebCareProScanner\Firewall\RescueAssistantManager::analyze_recent_blocks($minutes),
            'trusted_actions' => \WebCareProScanner\Firewall\RescueAssistantManager::get_trusted_actions(),
            'daily_story'     => \WebCareProScanner\Firewall\RescueAssistantManager::get_daily_security_story(),
        ], 200);
    }

    /**
     * Trust and permanently allow a blocked request or plugin action via Rescue Assistant.
     */
    public static function rescue_trust_action(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\RescueAssistantManager')) {
            return new \WP_REST_Response(['success' => false, 'message' => __('Rescue Assistant unavailable.', 'webcare-pro-security')], 500);
        }
        $params = $request->get_json_params() ?: [];
        $res    = \WebCareProScanner\Firewall\RescueAssistantManager::trust_and_allow_action($params);
        $status_code = !empty($res['success']) ? 200 : ((isset($res['code']) && $res['code'] === 'zero_tolerance_rule') ? 403 : 400);
        return new \WP_REST_Response($res, $status_code);
    }

    /**
     * Pause strict WAF enforcement for 15 minutes (Monitor-Only Test Mode with auto re-arm).
     */
    public static function rescue_pause_15m(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\RescueAssistantManager')) {
            return new \WP_REST_Response(['success' => false, 'message' => __('Rescue Assistant unavailable.', 'webcare-pro-security')], 500);
        }
        $res = \WebCareProScanner\Firewall\RescueAssistantManager::pause_strict_firewall_15m();
        if (is_wp_error($res)) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => $res->get_error_message(),
                'code'    => $res->get_error_code(),
            ], 403);
        }
        return new \WP_REST_Response($res, 200);
    }

    /**
     * Resume strict WAF enforcement immediately.
     */
    public static function rescue_resume(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\RescueAssistantManager')) {
            return new \WP_REST_Response(['success' => false, 'message' => __('Rescue Assistant unavailable.', 'webcare-pro-security')], 500);
        }
        return new \WP_REST_Response(\WebCareProScanner\Firewall\RescueAssistantManager::resume_strict_firewall(), 200);
    }

    public static function update_firewall_log_retention(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $days   = (int) ($params['retention_days'] ?? 30);
        $saved  = \WebCareProScanner\Firewall\WafFileLogger::set_retention_days($days);
        return rest_ensure_response([
            'success'        => $saved,
            'retention_days' => \WebCareProScanner\Firewall\WafFileLogger::get_retention_days(),
            'message'        => $saved ? __('WAF log retention period updated.', 'webcare-pro-security') : __('Failed to update retention period.', 'webcare-pro-security'),
        ]);
    }

    public static function prune_firewall_logs() {
        $pruned = \WebCareProScanner\Firewall\WafFileLogger::prune_expired_logs();
        return rest_ensure_response([
            'success'      => true,
            'pruned_count' => $pruned,
            'message'      => sprintf(
                /* translators: %d: number of pruned daily log files */
                _n('%d expired daily WAF log file pruned.', '%d expired daily WAF log files pruned.', $pruned, 'webcare-pro-security'),
                $pruned
            ),
        ]);
    }

    public static function download_firewall_log_file(\WP_REST_Request $request) {
        $filename = sanitize_file_name((string) $request->get_param('filename'));
        if (empty($filename) || !preg_match('/-waf-logs\.json$/', $filename)) {
            return new \WP_Error('invalid_file', 'Valid daily WAF log filename is required.', ['status' => 400]);
        }

        $dir      = \WebCareProScanner\Firewall\WafFileLogger::get_storage_dir();
        $filepath = $dir . '/' . $filename;
        if (!file_exists($filepath) || !is_readable($filepath)) {
            return new \WP_Error('not_found', 'Log file does not exist on disk.', ['status' => 404]);
        }

        $lines = @file($filepath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $records = [];
        if (is_array($lines)) {
            foreach ($lines as $line) {
                $decoded = json_decode($line, true);
                if (is_array($decoded)) {
                    $records[] = $decoded;
                }
            }
        }

        return rest_ensure_response([
            'filename' => $filename,
            'count'    => count($records),
            'records'  => $records,
        ]);
    }

    public static function delete_firewall_log(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $id = sanitize_text_field(trim((string) ($params['id'] ?? '')));
        if (empty($id)) {
            return new \WP_Error('invalid_id', 'Valid log ID is required', ['status' => 400]);
        }
        $deleted = \WebCareProScanner\Firewall\FirewallEngine::delete_log($id);
        return rest_ensure_response([
            'success' => $deleted,
            'message' => $deleted ? 'Log entry deleted successfully.' : 'Failed to delete log entry.',
        ]);
    }

    public static function add_firewall_blocked_ip(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $ip = sanitize_text_field(trim($params['ip'] ?? ''));
        if (empty($ip)) {
            return new \WP_Error('invalid_ip', 'Valid IP address is required', ['status' => 400]);
        }

        $current_client_ip = \WebCareProScanner\Firewall\FirewallEngine::get_client_ip();
        if ($ip === $current_client_ip && \WebCareProScanner\Firewall\FirewallEngine::is_authenticated_administrator()) {
            return new \WP_Error(
                'self_ban_prohibited',
                /* translators: %s: current IP address */
                sprintf(__('Safety Guard: IP %s is your active administrator connection. You cannot block your own IP to prevent site lockout.', 'webcare-pro-security'), $ip),
                ['status' => 400]
            );
        }

        $reason = isset($params['reason']) ? sanitize_text_field(trim($params['reason'])) : '';
        $duration_seconds = isset($params['duration_seconds']) ? max(0, (int) $params['duration_seconds']) : 0;
        $current_user = wp_get_current_user();
        $user_login = ($current_user && $current_user->exists()) ? $current_user->user_login : 'admin';

        $added = \WebCareProScanner\Firewall\FirewallEngine::add_blocked_ip(
            $ip,
            !empty($reason) ? $reason : sprintf('Blocked manually by administrator "%s"', $user_login),
            $duration_seconds,
            null,
            'Custom Administrator Block',
            'Manual Blocklist',
            null,
            $user_login
        );

        if ($added && class_exists('\WebCareProScanner\System\WebCareActivityLogger')) {
            $client_ip = \WebCareProScanner\Firewall\FirewallEngine::get_client_ip();

            \WebCareProScanner\System\WebCareActivityLogger::notice(
                'firewall_ip_blocked',
                'firewall',
                [
                    'ip'          => $ip,
                    'description' => sprintf('IP %s manually added to WAF blocklist by %s from IP %s (Reason: %s).', $ip, $user_login, $client_ip, $reason ?: 'Administrator policy'),
                ]
            );
        }

        return rest_ensure_response([
            'success' => $added,
            'message' => $added ? sprintf('IP %s added to custom WAF blocklist.', $ip) : 'Failed to add IP.',
            'locked_ips' => \WebCareProScanner\Firewall\FirewallEngine::get_all_locked_ips(),
        ]);
    }

    public static function unblock_firewall_ip(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $ip = sanitize_text_field(trim($params['ip'] ?? ''));
        $raw_duration = (int) ($params['duration'] ?? 0);
        // Server-side strict cap: minimum 60s, maximum 900s (15 minutes) if requested
        $duration = $raw_duration > 0 ? max(60, min(900, $raw_duration)) : 0;
        if (empty($ip)) {
            return new \WP_Error('invalid_ip', 'Valid IP address is required', ['status' => 400]);
        }

        $unblocked = \WebCareProScanner\Firewall\FirewallEngine::remove_blocked_ip($ip);

        // Optional temporary bypass immunity (capped strictly between 60s and 900s)
        if ($duration > 0) {
            set_transient('webcareproscan_temp_allow_' . md5($ip), 1, $duration);
        }

        if ($unblocked && class_exists('\WebCareProScanner\System\WebCareActivityLogger')) {
            $current_user = wp_get_current_user();
            $user_login = ($current_user && $current_user->exists()) ? $current_user->user_login : 'admin';
            $client_ip = \WebCareProScanner\Firewall\FirewallEngine::get_client_ip();

            \WebCareProScanner\System\WebCareActivityLogger::notice(
                'firewall_ip_unblocked',
                'firewall',
                [
                    'ip'          => $ip,
                    'duration'    => $duration > 0 ? sprintf('%d seconds', $duration) : 'immediate',
                    'description' => sprintf('IP %s unblocked from firewall by %s from IP %s%s.', $ip, $user_login, $client_ip, $duration > 0 ? sprintf(' (granted %d min temporary access)', (int) round($duration / 60)) : ''),
                ]
            );
        }

        $msg = $duration > 0
            /* translators: 1: unblocked IP address, 2: duration in minutes */
            ? sprintf(__('IP %1$s has been unblocked with a temporary %2$d-minute access pass. Standard WAF exploit protection remains active.', 'webcare-pro-security'), $ip, (int) round($duration / 60))
            /* translators: %s: unblocked IP address */
            : sprintf(__('IP %s has been unblocked. Standard WAF protection remains active.', 'webcare-pro-security'), $ip);

        return rest_ensure_response([
            'success' => $unblocked,
            'message' => $msg,
            'locked_ips' => \WebCareProScanner\Firewall\FirewallEngine::get_all_locked_ips(),
        ]);
    }

    /**
     * Unban all IP addresses across Local WAF, Login Hardening, Transients, and Cloudflare Edge.
     */
    public static function unblock_all_firewall_ips(\WP_REST_Request $request) {
        $result = \WebCareProScanner\Firewall\FirewallEngine::clear_all_blocked_ips();
        $cleared_count = (int) ($result['cleared_count'] ?? 0);
        $cf_unbanned = (int) ($result['cf_unbanned'] ?? 0);
        $locked_ips = \WebCareProScanner\Firewall\FirewallEngine::get_all_locked_ips();
        $settings = \WebCareProScanner\System\SettingsManager::get_settings();

        if (class_exists('\\WebCareProScanner\\System\\WebCareActivityLogger')) {
            $current_user = wp_get_current_user();
            $user_login = ($current_user && $current_user->exists()) ? $current_user->user_login : 'admin';
            $client_ip = \WebCareProScanner\Firewall\FirewallEngine::get_client_ip();

            \WebCareProScanner\System\WebCareActivityLogger::notice(
                'firewall_all_ips_unblocked',
                'firewall',
                [
                    'cleared_count' => $cleared_count,
                    'cf_unbanned'   => $cf_unbanned,
                    'description'   => sprintf(
                        /* translators: %1$s: user login, %2$s: client IP, %3$d: cleared count, %4$d: Cloudflare unbanned count */
                        __('All banned IPs (%3$d total, %4$d Cloudflare edge rules) unbanned by %1$s from IP %2$s.', 'webcare-pro-security'),
                        $user_login,
                        $client_ip,
                        $cleared_count,
                        $cf_unbanned
                    ),
                ]
            );
        }

        $msg = $cleared_count > 0
            /* translators: 1: total cleared count, 2: Cloudflare edge unbanned count */
            ? sprintf(__('Successfully unbanned all %1$d IPs from local firewall and Cloudflare Edge (%2$d edge rules cleared).', 'webcare-pro-security'), $cleared_count, $cf_unbanned)
            : __('All firewall ban lists and lockouts are clear. No active IP bans were found.', 'webcare-pro-security');

        return rest_ensure_response([
            'success'         => true,
            'cleared_count'   => $cleared_count,
            'cf_unbanned'     => $cf_unbanned,
            'message'         => $msg,
            'locked_ips'      => $locked_ips,
            'waf_blocked_ips' => $settings['waf_blocked_ips'] ?? '',
        ]);
    }

    /**
     * Customer Lockout Finder: Look up blocked customer by 6-digit Support Code (#WEBCARE-XXXX) or IP address
     */
    public static function lookup_customer_lockout(\WP_REST_Request $request) {
        $raw_param = preg_replace('/\s+/', '', trim((string) ($request->get_param('code') ?? '')));
        $query = strtoupper((string) $raw_param);
        if (empty($query)) {
            return new \WP_Error('missing_code', __('Support Code or IP address is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        // Clean code formatting: allow #WEBCARE-492A, WEBCARE-492A, 492A, or WEBCARE-2C912D79 / 2C912D79
        $clean_code = ltrim($query, '#');
        if (!str_starts_with($clean_code, 'WEBCARE-') && !filter_var($clean_code, FILTER_VALIDATE_IP)) {
            if (preg_match('/^[A-Z0-9]{4}$/', $clean_code) || preg_match('/^[A-F0-9]{8}$/', $clean_code)) {
                $clean_code = 'WEBCARE-' . $clean_code;
            }
        }

        // 1. Try finding by support reference code or indexed incident ID transient
        $data = get_transient('webcareproscan_lockout_' . $clean_code);

        // 2. Fallback: Try finding by IP address if user entered an IP
        if (!$data && filter_var($clean_code, FILTER_VALIDATE_IP)) {
            $data = get_transient('webcareproscan_lockout_ip_' . md5($clean_code));
        }

        // 3. Fallback: Search recent filesystem logs (last 30 days) using normalized clean code
        if (!$data && class_exists('\\WebCareProScanner\\Firewall\\WafFileLogger')) {
            $file_query = \WebCareProScanner\Firewall\WafFileLogger::query_logs([
                'search' => $clean_code,
                'action' => 'all',
                'range'  => '30days',
            ], 5);
            if (!empty($file_query['logs'])) {
                $top = $file_query['logs'][0];
                foreach ($file_query['logs'] as $candidate_log) {
                    if (($candidate_log['action_taken'] ?? '') === 'blocked') {
                        $top = $candidate_log;
                        break;
                    }
                }
                $data = [
                    'ref_code'       => !empty($top['ref_code']) ? $top['ref_code'] : $clean_code,
                    'incident_id'    => $top['incident_id'] ?? 'WEBCARE-LOG',
                    'client_ip'      => $top['ip_address'] ?? '',
                    'rule_id'        => $top['rule_id'] ?? 'WAF-BLOCK',
                    'rule_name'      => $top['rule_name'] ?? ($top['rule_category'] ?? 'Security Shield'),
                    'rule_category'  => $top['rule_category'] ?? 'Security Shield',
                    'description'    => $top['rule_description'] ?? 'Automated defense rule triggered.',
                    'request_uri'    => $top['request_uri'] ?? '/',
                    'timestamp'      => strtotime($top['created_at'] ?? ($top['timestamp'] ?? 'now')),
                    'formatted_time' => $top['created_at_gmt'] ?? ($top['created_at'] ?? gmdate('Y-m-d H:i:s \U\T\C')),
                ];
            }
        }

        // 4. Fallback: Search SQL firewall_logs table by incident_id or IP
        if (!$data) {
            global $wpdb;
            $fw_table = $wpdb->prefix . 'webcareproscan_firewall_logs';
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            if ($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($fw_table))) === $fw_table) {
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                $sql_row = $wpdb->get_row(
                    $wpdb->prepare(
                        'SELECT incident_id, ip_address, rule_category, rule_description, request_uri, created_at FROM %i WHERE incident_id = %s OR ip_address = %s ORDER BY id DESC LIMIT 1',
                        $fw_table,
                        $clean_code,
                        $clean_code
                    ),
                    ARRAY_A
                );
                if (is_array($sql_row) && !empty($sql_row['ip_address'])) {
                    $data = [
                        'ref_code'       => $clean_code,
                        'incident_id'    => $sql_row['incident_id'],
                        'client_ip'      => $sql_row['ip_address'],
                        'rule_category'  => $sql_row['rule_category'] ?? 'Security Shield',
                        'description'    => $sql_row['rule_description'] ?? '',
                        'request_uri'    => $sql_row['request_uri'] ?? '/',
                        'timestamp'      => strtotime((string) ($sql_row['created_at'] ?? 'now')),
                        'formatted_time' => $sql_row['created_at'] ?? gmdate('Y-m-d H:i:s'),
                    ];
                }
            }
        }

        if (!$data) {
            return rest_ensure_response([
                'found'   => false,
                'message' => __('No active lockout record found for this Support Reference Code or IP. The visitor may already be unblocked or the block event expired.', 'webcare-pro-security'),
            ]);
        }

        // Translate reason into customer-friendly plain English
        $friendly_reason = __('Security shield temporarily held the request due to suspicious request signatures.', 'webcare-pro-security');
        $cat = strtolower($data['rule_category'] ?? '');
        $desc = strtolower($data['description'] ?? '');

        if (strpos($cat, 'coupon') !== false || strpos($desc, 'coupon') !== false) {
            $friendly_reason = __('Customer was temporarily held because invalid discount coupon codes were attempted multiple times in a short window.', 'webcare-pro-security');
        } elseif (strpos($cat, 'checkout') !== false || strpos($desc, 'checkout') !== false) {
            $friendly_reason = __('Customer was rate-limited during checkout due to rapid order submissions or repeated card payment verification attempts.', 'webcare-pro-security');
        } elseif (strpos($cat, 'login') !== false || strpos($desc, 'login') !== false) {
            $friendly_reason = __('Customer was held because an account password was entered incorrectly multiple times.', 'webcare-pro-security');
        } elseif (strpos($cat, 'rate') !== false || strpos($desc, 'rate') !== false) {
            $friendly_reason = __('Customer refreshed or requested store pages faster than normal browsing velocity.', 'webcare-pro-security');
        }

        return rest_ensure_response([
            'found'           => true,
            'lockout'         => $data,
            'friendly_reason' => $friendly_reason,
            'client_ip'       => $data['client_ip'],
            'ref_code'        => $data['ref_code'],
            'incident_id'     => $data['incident_id'] ?? '',
            'formatted_time'  => $data['formatted_time'],
        ]);
    }

    /**
     * Unblock customer in 1 click and grant temporary 24-hour bypass immunity
     */
    public static function unblock_customer_lockout(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $ip = sanitize_text_field(trim($params['ip'] ?? ''));
        $code = sanitize_text_field(trim($params['code'] ?? ''));

        if (empty($ip) && !empty($code)) {
            $clean_code = ltrim(strtoupper((string) preg_replace('/\s+/', '', $code)), '#');
            if (!str_starts_with($clean_code, 'WEBCARE-') && !filter_var($clean_code, FILTER_VALIDATE_IP)) {
                if (preg_match('/^[A-Z0-9]{4}$/', $clean_code) || preg_match('/^[A-F0-9]{8}$/', $clean_code)) {
                    $clean_code = 'WEBCARE-' . $clean_code;
                }
            }
            $t = get_transient('webcareproscan_lockout_' . $clean_code);
            if (!empty($t['client_ip'])) {
                $ip = $t['client_ip'];
            } elseif (class_exists('\\WebCareProScanner\\Firewall\\WafFileLogger')) {
                $fq = \WebCareProScanner\Firewall\WafFileLogger::query_logs(['search' => $clean_code, 'action' => 'all', 'range' => '30days'], 1);
                if (!empty($fq['logs'][0]['ip_address'])) {
                    $ip = (string) $fq['logs'][0]['ip_address'];
                }
            }
            if (empty($ip)) {
                global $wpdb;
                $fw_table = $wpdb->prefix . 'webcareproscan_firewall_logs';
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                if ($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($fw_table))) === $fw_table) {
                    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                    $ip_hit = $wpdb->get_var(
                        $wpdb->prepare('SELECT ip_address FROM %i WHERE incident_id = %s ORDER BY id DESC LIMIT 1', $fw_table, $clean_code)
                    );
                    if (is_string($ip_hit) && $ip_hit !== '') {
                        $ip = $ip_hit;
                    }
                }
            }
        }

        if (empty($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return new \WP_Error('invalid_ip', __('Valid client IP is required to unblock.', 'webcare-pro-security'), ['status' => 400]);
        }

        // 1. Remove all active rate limiters and blocklists
        \WebCareProScanner\Firewall\FirewallEngine::remove_blocked_ip($ip);

        // 2. Grant temporary 24-hour bypass allowlist
        set_transient('webcareproscan_temp_allow_' . md5($ip), 1, 24 * HOUR_IN_SECONDS);

        // 3. Log audit event
        if (class_exists('\\WebCareProScanner\\System\\WebCareActivityLogger')) {
            $current_user = wp_get_current_user();
            $user_login = ($current_user && $current_user->exists()) ? $current_user->user_login : 'admin';
            \WebCareProScanner\System\WebCareActivityLogger::notice(
                'customer_lockout_unblocked',
                'firewall',
                [
                    'ip'          => $ip,
                    'code'        => $code,
                    'unblocked_by'=> $user_login,
                    'duration'    => '24 hours',
                    'description' => sprintf('Customer IP %s was unblocked and granted 24-hour store access by %s.', $ip, $user_login),
                ]
            );
        }

        return rest_ensure_response([
            'success' => true,
            /* translators: %s: customer IP address */
            'message' => sprintf(__('Customer IP %s has been successfully unblocked and granted 24-hour checkout access.', 'webcare-pro-security'), $ip),
            'client_ip' => $ip,
        ]);
    }

    public static function get_firewall_blocklist(\WP_REST_Request $request) {
        $locked_ips = \WebCareProScanner\Firewall\FirewallEngine::get_all_locked_ips();
        $settings = \WebCareProScanner\System\SettingsManager::get_settings();
        return rest_ensure_response([
            'success'          => true,
            'locked_ips'       => $locked_ips,
            'total_locked'     => count($locked_ips),
            'waf_blocked_ips'  => $settings['waf_blocked_ips'] ?? '',
        ]);
    }

    public static function clear_expired_firewall_blocklist(\WP_REST_Request $request) {
        $cleared = \WebCareProScanner\Firewall\FirewallEngine::clear_expired_blocked_ips();
        $locked_ips = \WebCareProScanner\Firewall\FirewallEngine::get_all_locked_ips();
        $settings = \WebCareProScanner\System\SettingsManager::get_settings();

        if ($cleared > 0 && class_exists('\\WebCareProScanner\\System\\WebCareActivityLogger')) {
            $current_user = wp_get_current_user();
            $user_login = ($current_user && $current_user->exists()) ? $current_user->user_login : 'admin';
            \WebCareProScanner\System\WebCareActivityLogger::notice(
                'firewall_expired_bans_cleared',
                'firewall',
                [
                    /* translators: %1$d: number of expired bans cleared, %2$s: admin user login */
                    'description' => sprintf(__('Cleared %1$d expired temporary ban records from firewall blocklist by %2$s.', 'webcare-pro-security'), $cleared, $user_login),
                ]
            );
        }

        return rest_ensure_response([
            'success'         => true,
            'cleared_count'   => $cleared,
            'locked_ips'      => $locked_ips,
            'total_locked'    => count($locked_ips),
            'waf_blocked_ips' => $settings['waf_blocked_ips'] ?? '',
            /* translators: %d: number of expired bans cleared */
            'message'         => sprintf(_n('Cleared %d expired ban record.', 'Cleared %d expired ban records.', $cleared, 'webcare-pro-security'), $cleared),
        ]);
    }

    public static function allowlist_firewall_rule_target(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $rule = (int) ($params['rule'] ?? 0);
        $target = trim((string) ($params['target'] ?? ''));

        if ($rule !== 36 && $rule !== 37) {
            return new \WP_Error('invalid_rule', __('Rule must be either 36 (AJAX Action) or 37 (REST Route).', 'webcare-pro-security'), ['status' => 400]);
        }

        if (empty($target)) {
            return new \WP_Error('empty_target', __('Allowlist target value is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $settings = \WebCareProScanner\System\SettingsManager::get_settings();
        $current_user = wp_get_current_user();
        $user_login = ($current_user && $current_user->exists()) ? $current_user->user_login : 'admin';

        if ($rule === 36) {
            $action = sanitize_key($target);
            if (empty($action) || strlen($action) > 100) {
                return new \WP_Error('invalid_action', __('Invalid AJAX action name format.', 'webcare-pro-security'), ['status' => 400]);
            }

            $current_raw = (string) ($settings['waf_guest_ajax_custom_allowlist'] ?? '');
            $lines = array_filter(array_map('trim', explode("\n", str_replace("\r", '', $current_raw))));
            if (!in_array($action, $lines, true)) {
                if (count($lines) >= 500) {
                    return new \WP_Error('allowlist_limit', __('Custom allowlist has reached maximum capacity (500 items).', 'webcare-pro-security'), ['status' => 400]);
                }
                $lines[] = $action;
                $settings['waf_guest_ajax_custom_allowlist'] = implode("\n", array_unique($lines));
                \WebCareProScanner\System\SettingsManager::save_settings($settings);

                if (class_exists('\\WebCareProScanner\\System\\WebCareActivityLogger')) {
                    \WebCareProScanner\System\WebCareActivityLogger::notice(
                        'firewall_rule36_allowlist_added',
                        'firewall',
                        [
                            /* translators: %1$s: action name, %2$s: admin user login */
                            'description' => sprintf(__('Added AJAX action "%1$s" to Rule #36 custom allowlist by %2$s.', 'webcare-pro-security'), $action, $user_login),
                        ]
                    );
                }
            }

            return rest_ensure_response([
                'success' => true,
                /* translators: %s: AJAX action name */
                'message' => sprintf(__('AJAX action "%s" successfully allowed in Rule #36.', 'webcare-pro-security'), $action),
            ]);
        }

        if ($rule === 37) {
            $method_input = array_key_exists('method', $params) ? $params['method'] : 'POST';
            if (!is_string($method_input)) {
                return new \WP_Error('invalid_method', __('Invalid HTTP method. Supported methods are POST, PUT, PATCH, DELETE, and GET.', 'webcare-pro-security'), ['status' => 400]);
            }

            $raw_method = strtoupper(trim(wp_unslash($method_input)));
            $valid_methods = ['POST', 'PUT', 'PATCH', 'DELETE', 'GET'];
            if (!in_array($raw_method, $valid_methods, true)) {
                return new \WP_Error('invalid_method', __('Invalid HTTP method. Supported methods are POST, PUT, PATCH, DELETE, and GET.', 'webcare-pro-security'), ['status' => 400]);
            }
            $method = $raw_method;

            $route = strtolower(sanitize_text_field(wp_unslash($target)));
            if (!str_starts_with($route, '/')) {
                $route = '/' . $route;
            }

            // Security Guards: prohibit wildcards and dangerous administrative/system paths
            if (str_contains($route, '*') || preg_match('#/(?:wp/v2/users|wp/v2/settings|webcare-pro-security/v1/auth)#i', $route)) {
                return new \WP_Error('dangerous_route', __('This REST route cannot be added to guest allowlist for security reasons.', 'webcare-pro-security'), ['status' => 400]);
            }

            $current_raw = (string) ($settings['waf_guest_rest_custom_allowlist'] ?? '');
            $lines = array_filter(array_map('trim', explode("\n", str_replace("\r", '', $current_raw))));
            $allowlist_update = self::build_method_scoped_rest_allowlist(array_values($lines), $route, $method);
            if (
                !empty($allowlist_update['added'])
                && empty($allowlist_update['legacy_route_replaced'])
                && count($lines) >= 500
            ) {
                return new \WP_Error('allowlist_limit', __('Custom allowlist has reached maximum capacity (500 items).', 'webcare-pro-security'), ['status' => 400]);
            }

            if (!empty($allowlist_update['changed'])) {
                $settings['waf_guest_rest_custom_allowlist'] = implode("\n", $allowlist_update['lines']);
                \WebCareProScanner\System\SettingsManager::save_settings($settings);

                if (class_exists('\\WebCareProScanner\\System\\WebCareActivityLogger')) {
                    if (!empty($allowlist_update['legacy_route_replaced'])) {
                        \WebCareProScanner\System\WebCareActivityLogger::notice(
                            'firewall_rule37_allowlist_narrowed',
                            'firewall',
                            [
                                /* translators: %1$s: HTTP method, %2$s: REST route, %3$s: admin user login */
                                'description' => sprintf(__('Replaced an unrestricted route-only Rule #37 entry with "%1$s %2$s" by %3$s.', 'webcare-pro-security'), $method, $route, $user_login),
                            ]
                        );
                    } else {
                        \WebCareProScanner\System\WebCareActivityLogger::notice(
                            'firewall_rule37_allowlist_added',
                            'firewall',
                            [
                                /* translators: %1$s: HTTP method, %2$s: REST route, %3$s: admin user login */
                                'description' => sprintf(__('Added REST route "%1$s %2$s" to Rule #37 custom allowlist by %3$s.', 'webcare-pro-security'), $method, $route, $user_login),
                            ]
                        );
                    }
                }
            }

            if (!empty($allowlist_update['changed']) && !empty($allowlist_update['legacy_route_replaced'])) {
                $message = sprintf(
                    /* translators: %1$s: HTTP method, %2$s: REST route */
                    __('Unrestricted route-only exception narrowed to "%1$s %2$s".', 'webcare-pro-security'),
                    $method,
                    $route
                );
            } elseif (!empty($allowlist_update['changed'])) {
                $message = sprintf(
                    /* translators: %1$s: HTTP method, %2$s: REST route */
                    __('REST route "%1$s %2$s" successfully allowed in Rule #37.', 'webcare-pro-security'),
                    $method,
                    $route
                );
            } else {
                $message = sprintf(
                    /* translators: %1$s: HTTP method, %2$s: REST route */
                    __('REST route "%1$s %2$s" is already allowed in Rule #37.', 'webcare-pro-security'),
                    $method,
                    $route
                );
            }

            return rest_ensure_response([
                'success' => true,
                'message' => $message,
            ]);
        }

        return new \WP_Error('invalid_request', __('Invalid allowlist request.', 'webcare-pro-security'), ['status' => 400]);
    }

    public static function add_firewall_whitelisted_ip(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $ip = sanitize_text_field(trim($params['ip'] ?? ''));
        $reason = sanitize_text_field(trim($params['reason'] ?? ''));
        if (empty($ip)) {
            return new \WP_Error('invalid_ip', 'Valid IP address or CIDR range is required', ['status' => 400]);
        }

        $current_user = wp_get_current_user();
        $user_login = ($current_user && $current_user->exists()) ? $current_user->user_login : 'admin';

        $scope_args = [
            'scope'         => sanitize_key($params['scope'] ?? 'global'),
            'allowed_rules' => !empty($params['allowed_rules']) && is_array($params['allowed_rules']) ? $params['allowed_rules'] : [],
            'allowed_cats'  => !empty($params['allowed_cats']) && is_array($params['allowed_cats']) ? $params['allowed_cats'] : [],
            'endpoint'      => sanitize_text_field($params['endpoint'] ?? ''),
            'expires_in'    => isset($params['expires_in']) ? intval($params['expires_in']) : 0,
        ];

        $added = \WebCareProScanner\Firewall\FirewallEngine::add_whitelisted_ip($ip, $reason, $user_login, $scope_args);
        if ($added && class_exists('\WebCareProScanner\System\WebCareActivityLogger')) {
            $client_ip = \WebCareProScanner\Firewall\FirewallEngine::get_client_ip();
            $scope_desc = $scope_args['scope'] === 'rule' 
                ? sprintf('Rule: %s', implode(', ', $scope_args['allowed_rules'])) 
                : ($scope_args['scope'] === 'category' ? sprintf('Category: %s', implode(', ', $scope_args['allowed_cats'])) : 'Global Bypass');

            \WebCareProScanner\System\WebCareActivityLogger::notice(
                'firewall_ip_whitelisted',
                'firewall',
                [
                    'ip'          => $ip,
                    'description' => sprintf('IP %s allowlisted (%s) by %s from IP %s (Reason: %s).', $ip, $scope_desc, $user_login, $client_ip, $reason ?: 'Administrator policy'),
                ]
            );
        }

        $success_msg = sprintf('IP %s added to allowlist.', $ip);
        if ($scope_args['scope'] === 'rule' && !empty($scope_args['allowed_rules'])) {
            $success_msg = sprintf('IP %s successfully allowed strictly for rule %s.', $ip, implode(', ', $scope_args['allowed_rules']));
        } elseif ($scope_args['scope'] === 'category' && !empty($scope_args['allowed_cats'])) {
            $success_msg = sprintf('IP %s successfully allowed for category %s.', $ip, implode(', ', $scope_args['allowed_cats']));
        }

        return rest_ensure_response([
            'success'         => $added,
            'message'         => $added ? $success_msg : 'Failed to whitelist IP.',
            'whitelisted_ips' => \WebCareProScanner\Firewall\FirewallEngine::get_all_whitelisted_ips(),
        ]);
    }

    public static function remove_firewall_whitelisted_ip(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $ip = sanitize_text_field(trim($params['ip'] ?? ''));
        if (empty($ip)) {
            return new \WP_Error('invalid_ip', 'Valid IP address is required', ['status' => 400]);
        }

        $removed = \WebCareProScanner\Firewall\FirewallEngine::remove_whitelisted_ip($ip);
        if ($removed && class_exists('\WebCareProScanner\System\WebCareActivityLogger')) {
            $current_user = wp_get_current_user();
            $user_login = ($current_user && $current_user->exists()) ? $current_user->user_login : 'admin';
            $client_ip = \WebCareProScanner\Firewall\FirewallEngine::get_client_ip();

            \WebCareProScanner\System\WebCareActivityLogger::notice(
                'firewall_ip_whitelist_removed',
                'firewall',
                [
                    'ip'          => $ip,
                    'description' => sprintf('IP %s removed from trusted WAF allowlist by %s from IP %s.', $ip, $user_login, $client_ip),
                ]
            );
        }

        return rest_ensure_response([
            'success' => $removed,
            'message' => sprintf('IP %s removed from trusted WAF allowlist.', $ip),
            'whitelisted_ips' => \WebCareProScanner\Firewall\FirewallEngine::get_all_whitelisted_ips(),
        ]);
    }

    public static function get_firewall_whitelist(\WP_REST_Request $request) {
        $whitelisted_ips = \WebCareProScanner\Firewall\FirewallEngine::get_all_whitelisted_ips();
        $settings = \WebCareProScanner\System\SettingsManager::get_settings();
        $rules_catalog = \WebCareProScanner\Firewall\FirewallEngine::get_firewall_rules_catalog();
        return rest_ensure_response([
            'success'             => true,
            'whitelisted_ips'     => $whitelisted_ips,
            'total_whitelisted'   => count($whitelisted_ips),
            'waf_whitelisted_ips' => $settings['waf_whitelisted_ips'] ?? '',
            'rules_catalog'       => $rules_catalog,
        ]);
    }

    public static function clear_firewall_logs() {
        $cleared = \WebCareProScanner\Firewall\FirewallEngine::clear_logs();
        if ($cleared && class_exists('\WebCareProScanner\System\WebCareActivityLogger')) {
            $current_user = wp_get_current_user();
            $user_login = ($current_user && $current_user->exists()) ? $current_user->user_login : 'admin';
            $client_ip = class_exists('\WebCareProScanner\Firewall\FirewallEngine')
                ? \WebCareProScanner\Firewall\FirewallEngine::get_client_ip()
                : (isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '127.0.0.1');

            \WebCareProScanner\System\WebCareActivityLogger::notice(
                'firewall_logs_cleared',
                'firewall',
                [
                    'description' => sprintf('Firewall incident logs purged by %s from IP %s.', $user_login, $client_ip),
                ]
            );
        }

        $status = \WebCareProScanner\Firewall\FirewallEngine::get_status();

        return rest_ensure_response([
            'success' => $cleared,
            'message' => 'Firewall incident logs cleared successfully.',
            'status'  => $status,
        ]);
    }

    public static function toggle_firewall(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $enabled = !empty($params['enabled']);
        $settings = \WebCareProScanner\System\SettingsManager::get_settings();
        $settings['waf_enabled'] = $enabled;
        if ($enabled && ($settings['waf_mode'] ?? '') === 'disabled') {
            $settings['waf_mode'] = 'enabled';
        } elseif (!$enabled) {
            $settings['waf_mode'] = 'disabled';
        }
        \WebCareProScanner\System\SettingsManager::save_settings($settings);

        return rest_ensure_response([
            'success' => true,
            'enabled' => $enabled,
            'status'  => \WebCareProScanner\Firewall\FirewallEngine::get_status(),
        ]);
    }

    /**
     * Save an individual firewall rule or setting immediately
     */
    public static function save_single_firewall_rule(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $key = sanitize_key($params['key'] ?? '');
        if (empty($key)) {
            return new \WP_Error('invalid_key', 'Setting key is required.', ['status' => 400]);
        }

        $val = $params['value'] ?? null;
        $saved = \WebCareProScanner\System\SettingsManager::save_settings([$key => $val]);
        if ($saved === false || !is_array($saved)) {
            return new \WP_Error(
                'firewall_rule_save_failed',
                __('Failed to save firewall rule or persist webhook secret in SecretVault.', 'webcare-pro-security'),
                ['status' => 500]
            );
        }
        $ui_settings = \WebCareProScanner\System\SettingsManager::get_settings_for_ui($saved);
        return rest_ensure_response([
            'success'  => true,
            'message'  => sprintf('Rule "%s" successfully saved.', $key),
            'key'      => $key,
            'value'    => $ui_settings[$key] ?? (in_array($key, \WebCareProScanner\System\SettingsManager::SECRET_KEYS, true) ? (!empty($val) ? '••••••••' : '') : $val),
            'settings' => $ui_settings,
        ]);
    }

    /**
     * Get available WordPress user roles for firewall role-enforcement rules
     */
    public static function get_firewall_roles() {
        return rest_ensure_response([
            'success' => true,
            'roles'   => \WebCareProScanner\Firewall\FirewallEngine::get_available_roles(),
        ]);
    }

    public static function get_server_security_config() {
        if (!class_exists('\\WebCareProScanner\\Firewall\\ServerSecurityEngine')) {
            $f = WEBCAREPROSCAN_PATH . 'includes/Firewall/ServerSecurityEngine.php';
            if (file_exists($f)) {
                require_once $f;
            }
        }
        $options = \WebCareProScanner\Firewall\ServerSecurityEngine::get_options();
        $file_info = \WebCareProScanner\Firewall\ServerSecurityEngine::get_file_info();
        $nginx_content = \WebCareProScanner\Firewall\ServerSecurityEngine::generate_nginx_config($options);
        $apache_content = \WebCareProScanner\Firewall\ServerSecurityEngine::generate_apache_config($options);

        return rest_ensure_response([
            'options'        => $options,
            'file_info'      => $file_info,
            'nginx_content'  => $nginx_content,
            'apache_content' => $apache_content,
        ]);
    }

    public static function save_server_security_config(\WP_REST_Request $request) {
        if (is_multisite() && !current_user_can('manage_network')) {
            return new \WP_Error('rest_forbidden', __('Multisite network administrator privileges required.', 'webcare-pro-security'), ['status' => 403]);
        }
        if (!class_exists('\\WebCareProScanner\\Firewall\\ServerSecurityEngine')) {
            $f = WEBCAREPROSCAN_PATH . 'includes/Firewall/ServerSecurityEngine.php';
            if (file_exists($f)) {
                require_once $f;
            }
        }
        $params = $request->get_json_params() ?: [];
        $server_type = !empty($params['server_type']) ? sanitize_key($params['server_type']) : 'nginx';
        $options = !empty($params['options']) && is_array($params['options']) ? $params['options'] : [];

        $result = \WebCareProScanner\Firewall\ServerSecurityEngine::save_config_file($server_type, $options);

        if (!empty($result['success']) && class_exists('\WebCareProScanner\System\WebCareActivityLogger')) {
            $current_user = wp_get_current_user();
            $user_login = ($current_user && $current_user->exists()) ? $current_user->user_login : 'admin';
            $client_ip = class_exists('\WebCareProScanner\Firewall\FirewallEngine')
                ? \WebCareProScanner\Firewall\FirewallEngine::get_client_ip()
                : (isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '127.0.0.1');

            \WebCareProScanner\System\WebCareActivityLogger::notice(
                'server_security_saved',
                'firewall',
                [
                    'server_type' => $server_type,
                    'description' => sprintf('Web server armor configuration for %s updated by %s from IP %s.', strtoupper($server_type), $user_login, $client_ip),
                ]
            );
        }

        return rest_ensure_response($result);
    }

    public static function deploy_server_security_htaccess(\WP_REST_Request $request) {
        if (is_multisite() && !current_user_can('manage_network')) {
            return new \WP_Error('rest_forbidden', __('Multisite network administrator privileges required.', 'webcare-pro-security'), ['status' => 403]);
        }
        if (!class_exists('\\WebCareProScanner\\Firewall\\ServerSecurityEngine')) {
            $f = WEBCAREPROSCAN_PATH . 'includes/Firewall/ServerSecurityEngine.php';
            if (file_exists($f)) {
                require_once $f;
            }
        }
        $params = $request->get_json_params() ?: [];
        $options = !empty($params['options']) && is_array($params['options']) ? $params['options'] : [];

        $result = \WebCareProScanner\Firewall\ServerSecurityEngine::deploy_to_htaccess($options);

        if (!empty($result['success']) && class_exists('\WebCareProScanner\System\WebCareActivityLogger')) {
            $current_user = wp_get_current_user();
            $user_login = ($current_user && $current_user->exists()) ? $current_user->user_login : 'admin';
            $client_ip = class_exists('\WebCareProScanner\Firewall\FirewallEngine')
                ? \WebCareProScanner\Firewall\FirewallEngine::get_client_ip()
                : (isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '127.0.0.1');

            \WebCareProScanner\System\WebCareActivityLogger::notice(
                'server_security_htaccess_deployed',
                'firewall',
                [
                    'description' => sprintf('Web server armor rules deployed directly to root .htaccess by %s from IP %s.', $user_login, $client_ip),
                ]
            );
        }

        return rest_ensure_response($result);
    }

    public static function get_redirect_shield_status() {
        $htaccess_path = ABSPATH . '.htaccess';
        $htaccess_exists = file_exists($htaccess_path);
        $htaccess_content = $htaccess_exists ? (@file_get_contents($htaccess_path) ?: '') : '';
        $htaccess_writable = $htaccess_exists ? wp_is_writable($htaccess_path) : wp_is_writable(ABSPATH);

        $analysis = class_exists('\\WebCareProScanner\\Firewall\\HtaccessShield')
            ? \WebCareProScanner\Firewall\HtaccessShield::analyze_htaccess_content($htaccess_content)
            : ['score' => 0, 'hostile_count' => 0, 'findings' => [], 'summary' => ''];

        $snapshots = class_exists('\\WebCareProScanner\\Firewall\\HtaccessVaultManager')
            ? \WebCareProScanner\Firewall\HtaccessVaultManager::list_snapshots()
            : [];

        $canary_state = get_option(\WebCareProScanner\Firewall\RedirectCanaryEngine::STATE_OPTION, []);

        $db_urls = class_exists('\\WebCareProScanner\\Firewall\\RedirectCanaryEngine')
            ? \WebCareProScanner\Firewall\RedirectCanaryEngine::verify_database_core_urls()
            : ['clean' => true, 'siteurl' => get_option('siteurl'), 'home' => get_option('home')];

        $auto_heal = (bool) \WebCareProScanner\System\SettingsManager::get('htaccess_auto_heal_enabled', false);
        $next_canary = wp_next_scheduled('webcareproscan_redirect_canary_event');

        return rest_ensure_response([
            'success'             => true,
            'is_htaccess_active'  => $htaccess_exists,
            'is_read_only_locked' => !$htaccess_writable,
            'auto_heal_enabled'   => $auto_heal,
            'file_size'           => strlen($htaccess_content),
            'mtime'               => $htaccess_exists ? (int) @filemtime($htaccess_path) : 0,
            'mtime_human'         => $htaccess_exists ? human_time_diff((int) @filemtime($htaccess_path), time()) . ' ago' : 'N/A',
            'analysis'            => $analysis,
            'snapshots'           => $snapshots,
            'canary_state'        => $canary_state,
            'database_urls'       => $db_urls,
            'server_software'     => isset($_SERVER['SERVER_SOFTWARE']) ? sanitize_text_field(wp_unslash($_SERVER['SERVER_SOFTWARE'])) : 'Unknown',
            'next_canary_ts'      => $next_canary ?: 0,
            'next_canary_human'   => $next_canary ? human_time_diff(time(), $next_canary) . ' from now' : 'Not scheduled',
        ]);
    }

    public static function run_redirect_canary_probe() {
        if (!class_exists('\\WebCareProScanner\\Firewall\\RedirectCanaryEngine')) {
            return rest_ensure_response([
                'success' => false,
                'message' => __('RedirectCanaryEngine not loaded.', 'webcare-pro-security'),
            ]);
        }

        $report = \WebCareProScanner\Firewall\RedirectCanaryEngine::execute_probes();
        $auto_heal_res = \WebCareProScanner\Firewall\RedirectCanaryEngine::evaluate_and_auto_heal($report);

        return rest_ensure_response([
            'success'   => true,
            'report'    => $report,
            'auto_heal' => $auto_heal_res,
        ]);
    }

    public static function restore_htaccess_vault_snapshot(\WP_REST_Request $request) {
        if (is_multisite() && !current_user_can('manage_network')) {
            return new \WP_Error('rest_forbidden', __('Multisite network administrator privileges required.', 'webcare-pro-security'), ['status' => 403]);
        }
        if (!class_exists('\\WebCareProScanner\\Firewall\\HtaccessVaultManager')) {
            return rest_ensure_response([
                'success' => false,
                'message' => __('HtaccessVaultManager not loaded.', 'webcare-pro-security'),
            ]);
        }

        $params = $request->get_json_params() ?: [];
        $version = isset($params['version']) ? max(1, min(5, (int) $params['version'])) : 1;

        $res = \WebCareProScanner\Firewall\HtaccessVaultManager::restore_snapshot($version);
        return rest_ensure_response($res);
    }

    public static function toggle_htaccess_lock(\WP_REST_Request $request) {
        if (is_multisite() && !current_user_can('manage_network')) {
            return new \WP_Error('rest_forbidden', __('Multisite network administrator privileges required.', 'webcare-pro-security'), ['status' => 403]);
        }
        if (!class_exists('\\WebCareProScanner\\Firewall\\HtaccessVaultManager')) {
            return rest_ensure_response([
                'success' => false,
                'message' => __('HtaccessVaultManager not loaded.', 'webcare-pro-security'),
            ]);
        }

        $params = $request->get_json_params() ?: [];
        $locked = !empty($params['locked']);

        $res = \WebCareProScanner\Firewall\HtaccessVaultManager::set_readonly_lock($locked);

        if (isset($params['auto_heal'])) {
            \WebCareProScanner\System\SettingsManager::set('htaccess_auto_heal_enabled', !empty($params['auto_heal']));
        }

        return rest_ensure_response([
            'success'   => $res,
            'is_locked' => $locked,
            'auto_heal' => (bool) \WebCareProScanner\System\SettingsManager::get('htaccess_auto_heal_enabled', false),
            'message'   => $locked
                ? __('Root .htaccess locked to read-only (0444). Direct modification by processes is disabled.', 'webcare-pro-security')
                : __('Root .htaccess unlocked (0644). Caching and SEO plugins can write configuration updates.', 'webcare-pro-security'),
        ]);
    }

    public static function heal_database_core_urls() {
        if (is_multisite() && !current_user_can('manage_network')) {
            return new \WP_Error('rest_forbidden', __('Multisite network administrator privileges required.', 'webcare-pro-security'), ['status' => 403]);
        }
        if (!class_exists('\\WebCareProScanner\\Firewall\\RedirectCanaryEngine')) {
            return rest_ensure_response([
                'success' => false,
                'message' => __('RedirectCanaryEngine not loaded.', 'webcare-pro-security'),
            ]);
        }

        $res = \WebCareProScanner\Firewall\RedirectCanaryEngine::restore_database_core_urls();
        return rest_ensure_response($res);
    }

    public static function create_htaccess_vault_snapshot() {
        if (is_multisite() && !current_user_can('manage_network')) {
            return new \WP_Error('rest_forbidden', __('Multisite network administrator privileges required.', 'webcare-pro-security'), ['status' => 403]);
        }
        if (!class_exists('\\WebCareProScanner\\Firewall\\HtaccessVaultManager')) {
            return rest_ensure_response([
                'success' => false,
                'message' => __('HtaccessVaultManager not loaded.', 'webcare-pro-security'),
            ]);
        }

        $res = \WebCareProScanner\Firewall\HtaccessVaultManager::snapshot_current_if_clean('manual_admin_cockpit');
        return rest_ensure_response($res);
    }

    public static function get_micro_waf_status(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\MicroWafCompiler')) {
            $f = WEBCAREPROSCAN_PATH . 'includes/Firewall/MicroWafCompiler.php';
            if (file_exists($f)) {
                require_once $f;
            }
        }
        $status = \WebCareProScanner\Firewall\MicroWafCompiler::get_status();
        return rest_ensure_response($status);
    }

    public static function compile_micro_waf(\WP_REST_Request $request) {
        if (is_multisite() && !current_user_can('manage_network')) {
            return new \WP_Error('rest_forbidden', __('Multisite network administrator privileges required.', 'webcare-pro-security'), ['status' => 403]);
        }
        if (!class_exists('\\WebCareProScanner\\Firewall\\MicroWafCompiler')) {
            $f = WEBCAREPROSCAN_PATH . 'includes/Firewall/MicroWafCompiler.php';
            if (file_exists($f)) {
                require_once $f;
            }
        }
        $result = \WebCareProScanner\Firewall\MicroWafCompiler::compile();
        return rest_ensure_response($result);
    }

    public static function install_micro_waf_preload(\WP_REST_Request $request) {
        if (is_multisite() && !current_user_can('manage_network')) {
            return new \WP_Error('rest_forbidden', __('Multisite network administrator privileges required.', 'webcare-pro-security'), ['status' => 403]);
        }
        if (!class_exists('\\WebCareProScanner\\Firewall\\MicroWafCompiler')) {
            $f = WEBCAREPROSCAN_PATH . 'includes/Firewall/MicroWafCompiler.php';
            if (file_exists($f)) {
                require_once $f;
            }
        }
        $result = \WebCareProScanner\Firewall\MicroWafCompiler::install_preload();
        return rest_ensure_response($result);
    }

    public static function uninstall_micro_waf_preload(\WP_REST_Request $request) {
        if (is_multisite() && !current_user_can('manage_network')) {
            return new \WP_Error('rest_forbidden', __('Multisite network administrator privileges required.', 'webcare-pro-security'), ['status' => 403]);
        }
        if (!class_exists('\\WebCareProScanner\\Firewall\\MicroWafCompiler')) {
            $f = WEBCAREPROSCAN_PATH . 'includes/Firewall/MicroWafCompiler.php';
            if (file_exists($f)) {
                require_once $f;
            }
        }
        $result = \WebCareProScanner\Firewall\MicroWafCompiler::uninstall_preload();
        return rest_ensure_response($result);
    }

    public static function get_whitelist_rules(\WP_REST_Request $request) {
        $rules = \WebCareProScanner\Findings\WhitelistManager::get_whitelist_rules(false);
        return rest_ensure_response([
            'success' => true,
            'rules'   => $rules,
            'active_count' => count(array_filter($rules, fn($r) => ($r['status'] ?? '') === 'active')),
        ]);
    }

    public static function add_whitelist_rule(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: $request->get_params();
        $result = \WebCareProScanner\Findings\WhitelistManager::add_rule($params);
        return rest_ensure_response($result);
    }

    public static function remove_whitelist_rule(\WP_REST_Request $request) {
        $params  = $request->get_json_params() ?: $request->get_params();
        $rule_id = sanitize_text_field($params['id'] ?? $params['rule_id'] ?? '');

        if (empty($rule_id)) {
            return new \WP_Error('missing_param', __('Rule ID is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $removed = \WebCareProScanner\Findings\WhitelistManager::remove_rule($rule_id);
        return rest_ensure_response([
            'success' => $removed,
            'rule_id' => $rule_id,
            'message' => $removed ? __('Whitelist rule revoked successfully.', 'webcare-pro-security') : __('Rule not found or could not be revoked.', 'webcare-pro-security'),
        ]);
    }

    public static function verify_server_security_rules() {
        return rest_ensure_response(\WebCareProScanner\Firewall\ServerSecurityEngine::verify_rule_enforcement());
    }

    public static function get_caddy_server_config() {
        $options = \WebCareProScanner\Firewall\ServerSecurityEngine::get_options();
        $config = \WebCareProScanner\Firewall\ServerSecurityEngine::generate_caddy_config($options);
        return rest_ensure_response([
            'success'   => true,
            'config'    => $config,
            'file_info' => \WebCareProScanner\Firewall\ServerSecurityEngine::get_file_info(),
        ]);
    }

    /**
     * Get complete CAF overview including stack snapshot and recommendations matrix.
     */
    public static function get_caf_overview(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\CAF\\AdaptiveFirewallAdvisor')) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => 'CAF module is not initialized.',
            ], 500);
        }

        $advisor = new \WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor();
        $snapshot = $advisor->get_stack_snapshot();
        $matrix   = $advisor->get_recommendations_matrix($snapshot);

        // Preload status
        $upload_dir = function_exists('wp_upload_dir') ? wp_upload_dir() : [];
        $killswitch_file = !empty($upload_dir['basedir']) ? (rtrim($upload_dir['basedir'], '/\\') . '/webcare-pro-security/.killswitch') : '';
        $is_killed = (defined('WEBCARE_CAF_DISABLE_PRELOAD') && WEBCARE_CAF_DISABLE_PRELOAD) || ($killswitch_file && file_exists($killswitch_file));

        return rest_ensure_response([
            'success'              => true,
            'snapshot'             => $snapshot->to_array(),
            'recommendations'      => $matrix,
            'is_killswitch_active' => $is_killed,
            'active_profile'       => $matrix['current_profile'],
            'residual_risk_score'  => $matrix['residual_risk_score'],
        ]);
    }

    /**
     * Apply a CAF Protection Profile.
     */
    public static function apply_caf_profile(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $profile_id   = sanitize_key($params['profile_id'] ?? 'balanced');
        $lock_dormant = isset($params['lock_dormant_surface']) ? (bool) $params['lock_dormant_surface'] : true;

        if (!class_exists('\\WebCareProScanner\\Firewall\\CAF\\AdaptiveFirewallAdvisor')) {
            return new \WP_REST_Response(['success' => false, 'message' => 'CAF module missing.'], 500);
        }

        $advisor = new \WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor();
        $result  = $advisor->apply_profile($profile_id, $lock_dormant);

        $auto_enabled = $result['auto_enabled'] ?? [];

        /* translators: %s: CAF profile identifier (e.g. ecommerce_hardened) */
        $base_msg = sprintf( __( 'CAF Profile "%s" applied and Micro-WAF recompiled.', 'webcare-pro-security' ), esc_html( $profile_id ) );

        return rest_ensure_response([
            'success'      => true,
            'message'      => $base_msg,
            'auto_enabled' => $auto_enabled,
            'result'       => $result,
        ]);
    }

    /**
     * Force immediate stack re-profiling and re-compilation.
     */
    public static function reprofile_caf_stack(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\CAF\\AdaptiveFirewallAdvisor')) {
            return new \WP_REST_Response(['success' => false, 'message' => 'CAF module missing.'], 500);
        }

        $advisor = new \WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor();
        $snapshot = $advisor->capture_stack_snapshot();

        if (class_exists('\\WebCareProScanner\\Firewall\\MicroWafCompiler')) {
            \WebCareProScanner\Firewall\MicroWafCompiler::compile_script();
        }

        return rest_ensure_response([
            'success'         => true,
            'message'         => 'Stack snapshot refreshed and CAF Micro-WAF recompiled.',
            'snapshot'        => $snapshot->to_array(),
            'recommendations' => $advisor->get_recommendations_matrix($snapshot),
        ]);
    }

    /**
     * Toggle the emergency preload killswitch.
     */
    public static function toggle_caf_killswitch(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $enable_killswitch = !empty($params['killswitch']);

        $upload_dir = function_exists('wp_upload_dir') ? wp_upload_dir() : [];
        if (empty($upload_dir['basedir'])) {
            return new \WP_REST_Response(['success' => false, 'message' => __('Uploads directory unavailable.', 'webcare-pro-security')], 500);
        }
        $vault_dir = rtrim($upload_dir['basedir'], '/\\') . '/webcare-pro-security';
        if (!is_dir($vault_dir)) {
            wp_mkdir_p($vault_dir);
        }

        $killswitch_file = $vault_dir . '/.killswitch';

        if ($enable_killswitch) {
            file_put_contents($killswitch_file, '1');
            $active = true;
        } else {
            if (file_exists($killswitch_file)) {
                wp_delete_file($killswitch_file);
            }
            $active = false;
        }

        return rest_ensure_response([
            'success'              => true,
            'is_killswitch_active' => $active,
            'message'              => $active ? 'Emergency Killswitch activated. Preload WAF bypassed.' : 'Emergency Killswitch deactivated. Preload WAF active.',
        ]);
    }

    /**
     * Get Cloudflare CAF Status (Phase 2): Slots, Token Capability, Ban Queue, Origin Circuit Breaker
     */
    public static function get_caf_cloudflare_status(\WP_REST_Request $request) {
        $settings = \WebCareProScanner\System\SettingsManager::get_settings();
        $zone_id = $settings['cloudflare_zone_id'] ?? '';
        $configured = !empty($settings['cloudflare_api_token']) && !empty($zone_id);

        $optimizer = class_exists('\\WebCareProScanner\\Firewall\\CAF\\CloudflareSlotOptimizer') ? new \WebCareProScanner\Firewall\CAF\CloudflareSlotOptimizer() : null;
        $synchronizer = class_exists('\\WebCareProScanner\\Firewall\\CAF\\CloudflareIpListSynchronizer') ? new \WebCareProScanner\Firewall\CAF\CloudflareIpListSynchronizer() : null;
        $breaker = class_exists('\\WebCareProScanner\\Firewall\\CAF\\OriginLoadCircuitBreaker') ? new \WebCareProScanner\Firewall\CAF\OriginLoadCircuitBreaker() : null;

        $existing_rules = [];
        $slot_budget = 4;
        $user_rules_count = 0;
        $webcare_rules_count = 0;

        if ($configured && $optimizer) {
            $existing_rules = $optimizer->get_zone_rules($zone_id);
            $slot_budget = $optimizer->calculate_webcare_slot_budget($existing_rules);

            foreach ($existing_rules as $r) {
                $desc = (string) ($r['description'] ?? '');
                if ($optimizer->is_webcare_rule($desc)) {
                    $webcare_rules_count++;
                } else {
                    $user_rules_count++;
                }
            }
        }

        $token_scope = $synchronizer ? $synchronizer->detect_api_scope() : 'none';
        $pending_queue = get_option(\WebCareProScanner\Firewall\CAF\CloudflareIpListSynchronizer::OPTION_BAN_QUEUE, []);
        $pending_count = is_array($pending_queue) ? count($pending_queue) : 0;

        $circuit_breaker_state = $breaker ? $breaker->get_state() : [];

        return rest_ensure_response([
            'success'               => true,
            'configured'            => $configured,
            'zone_id'               => $zone_id,
            'token_scope'           => $token_scope,
            'slot_usage'            => [
                'total_quota'      => 5,
                'user_rules'       => $user_rules_count,
                'webcare_rules'    => $webcare_rules_count,
                'available_slots'  => $slot_budget,
                'free_unallocated' => max(0, 5 - ($user_rules_count + $webcare_rules_count)),
                'reserved_owner_slot' => 1,
            ],
            'existing_rules'        => array_map(function ($r) use ($optimizer) {
                $desc = (string) ($r['description'] ?? '');
                return [
                    'id'          => $r['id'] ?? '',
                    'description' => $desc,
                    'action'      => $r['action'] ?? '',
                    'enabled'     => !empty($r['enabled']),
                    'bytes'       => strlen((string) ($r['expression'] ?? '')),
                    'is_webcare'  => $optimizer ? $optimizer->is_webcare_rule($desc) : (strpos($desc, '[WebCare Pro]') !== false),
                ];
            }, $existing_rules),
            'pending_ban_queue_size'=> $pending_count,
            'circuit_breaker'       => $circuit_breaker_state,
        ]);
    }

    /**
     * Trigger immediate on-demand synchronization of Cloudflare Edge slots and IP lists.
     */
    public static function sync_caf_cloudflare(\WP_REST_Request $request) {
        $settings = \WebCareProScanner\System\SettingsManager::get_settings();
        $zone_id = $settings['cloudflare_zone_id'] ?? '';

        if (empty($zone_id) || empty($settings['cloudflare_api_token'])) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => 'Cloudflare API token and Zone ID must be configured in Settings first.',
            ], 400);
        }

        $optimizer = new \WebCareProScanner\Firewall\CAF\CloudflareSlotOptimizer();
        $synchronizer = new \WebCareProScanner\Firewall\CAF\CloudflareIpListSynchronizer();
        $breaker = new \WebCareProScanner\Firewall\CAF\OriginLoadCircuitBreaker();

        // 1. Sync IP ban queue
        $synced_ips = $synchronizer->process_sync_queue();

        // 2. Sync 3-slot ruleset
        $origin_survival = $breaker->is_survival_mode_active();
        $slot_result = $optimizer->deploy_to_cloudflare($zone_id, null, [], $origin_survival);

        return rest_ensure_response([
            'success'     => $slot_result['success'] ?? false,
            'message'     => $slot_result['message'] ?? 'Cloudflare Edge synchronized.',
            'synced_ips'  => $synced_ips,
            'slot_result' => $slot_result,
        ]);
    }

    /**
     * Manual toggle for Origin Survival Mode (Circuit Breaker).
     */
    public static function toggle_origin_circuit_breaker(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $enable = !empty($params['enable']);

        $settings = \WebCareProScanner\System\SettingsManager::get_settings();
        $zone_id = $settings['cloudflare_zone_id'] ?? '';

        $breaker = new \WebCareProScanner\Firewall\CAF\OriginLoadCircuitBreaker();

        if ($enable) {
            $reason = !empty($params['reason']) ? sanitize_text_field($params['reason']) : 'Administrator Manual Trigger';
            $success = $breaker->escalate_edge_defense($zone_id, $reason, false);
            $msg = $success ? 'Origin Survival Mode engaged. Cloudflare Edge defense escalated.' : 'Failed to escalate Cloudflare Edge defense.';
        } else {
            $success = $breaker->deescalate_edge_defense($zone_id);
            $msg = $success ? 'Origin Survival Mode disengaged. Cloudflare Edge returned to standard baseline.' : 'Failed to deescalate Cloudflare Edge defense.';
        }

        return rest_ensure_response([
            'success'               => $success,
            'message'               => $msg,
            'circuit_breaker_state' => $breaker->get_state(),
        ]);
    }

    /**
     * Get CAF Phase 3 Behavioral Status: Multi-Bucket Velocity, PoW Counters, Learning Observations, Threat Scores
     */
    public static function get_caf_behavioral_status(\WP_REST_Request $request) {
        $rate_limiter_stats = class_exists('\\WebCareProScanner\\Firewall\\AdaptiveRateLimiter')
            ? \WebCareProScanner\Firewall\AdaptiveRateLimiter::get_telemetry()
            : [];

        $threat_score_stats = class_exists('\\WebCareProScanner\\Firewall\\CAF\\ThreatScoreTracker')
            ? \WebCareProScanner\Firewall\CAF\ThreatScoreTracker::get_telemetry()
            : [];

        $learning_observations = get_option(\WebCareProScanner\Firewall\CAF\LearningModeEngine::OPTION_OBSERVATIONS, []);
        $synthesized_exemptions = get_option(\WebCareProScanner\Firewall\CAF\LearningModeEngine::OPTION_SYNTHESIZED, []);

        $pow_enforced_ips = get_option('webcare_pow_enforced_ips', []);

        return rest_ensure_response([
            'success'                => true,
            'rate_limiter'           => $rate_limiter_stats,
            'threat_scorer'          => $threat_score_stats,
            'learning_observations'  => is_array($learning_observations) ? array_values(array_slice($learning_observations, 0, 50)) : [],
            'observation_count'      => is_array($learning_observations) ? count($learning_observations) : 0,
            'synthesized_exemptions' => is_array($synthesized_exemptions) ? array_values($synthesized_exemptions) : [],
            'exemption_count'        => is_array($synthesized_exemptions) ? count($synthesized_exemptions) : 0,
            'pow_enforced_ips'       => is_array($pow_enforced_ips) ? array_values($pow_enforced_ips) : [],
        ]);
    }

    /**
     * Synthesize 1-click targeted safe-pass exemption from incident or observation ID.
     */
    public static function create_caf_exemption(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $finding_id = !empty($params['finding_id']) ? sanitize_text_field($params['finding_id']) : '';

        if (empty($finding_id)) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => 'Finding or Incident ID is required.',
            ], 400);
        }

        if (!class_exists('\\WebCareProScanner\\Firewall\\CAF\\LearningModeEngine')) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => 'Learning Mode Engine is not loaded.',
            ], 500);
        }

        $result = \WebCareProScanner\Firewall\CAF\LearningModeEngine::synthesize_exemption($finding_id);
        return rest_ensure_response($result);
    }

    /**
     * Revoke / undo a synthesized exemption.
     */
    public static function delete_caf_exemption(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $target = !empty($params['target']) ? sanitize_text_field($params['target']) : (!empty($params['finding_id']) ? sanitize_text_field($params['finding_id']) : (!empty($params['exemption_id']) ? sanitize_text_field($params['exemption_id']) : ''));

        if (empty($target)) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => 'Target exemption ID or finding ID is required.',
            ], 400);
        }

        if (!class_exists('\\WebCareProScanner\\Firewall\\CAF\\LearningModeEngine')) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => 'Learning Mode Engine is not loaded.',
            ], 500);
        }

        $result = \WebCareProScanner\Firewall\CAF\LearningModeEngine::revoke_exemption($target);
        return rest_ensure_response($result);
    }

    /**
     * Toggle manual WebCrypto PoW challenge for suspicious IP.
     */
    public static function toggle_caf_pow_challenge(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $ip = !empty($params['ip']) ? sanitize_text_field($params['ip']) : '';
        $enable = !empty($params['enable']);

        if (empty($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => 'Valid IP address is required.',
            ], 400);
        }

        $enforced = get_option('webcare_pow_enforced_ips', []);
        if (!is_array($enforced)) {
            $enforced = [];
        }

        if ($enable) {
            $enforced[$ip] = [
                'ip'         => $ip,
                'enforced_at'=> time(),
                'reason'     => sanitize_text_field($params['reason'] ?? 'Administrator Suspicious Traffic Flag'),
            ];
        } else {
            unset($enforced[$ip]);
        }

        update_option('webcare_pow_enforced_ips', $enforced, false);

        return rest_ensure_response([
            'success' => true,
            'message' => $enable ? sprintf('WebCrypto PoW challenge enforced for IP %s.', $ip) : sprintf('WebCrypto PoW challenge lifted for IP %s.', $ip),
            'enforced'=> array_values($enforced),
        ]);
    }

    public static function build_method_scoped_rest_allowlist(array $lines, string $route, string $method): array {
        $entry = strtoupper($method) . ' ' . $route;
        $route_key = rtrim('/' . ltrim(strtolower(trim($route)), '/'), '/');
        $result_lines = [];
        $exact_exists = false;
        $legacy_route_replaced = false;

        foreach ($lines as $line) {
            $line = trim((string) $line);
            if ($line === '') {
                continue;
            }

            if (strcasecmp($line, $entry) === 0) {
                $exact_exists = true;
                $result_lines[] = $line;
                continue;
            }

            // Methodless exact routes are legacy all-method grants. A one-click
            // method-specific action replaces them so the broader grant does not remain active.
            $has_method_prefix = (bool) preg_match('/^[A-Za-z]+(?:[,|][A-Za-z]+)*\s+/', $line);
            if (!$has_method_prefix && !str_starts_with($line, '#') && !str_contains($line, '*')) {
                $legacy_key = rtrim('/' . ltrim(strtolower($line), '/'), '/');
                if ($legacy_key === $route_key) {
                    $legacy_route_replaced = true;
                    continue;
                }
            }

            $result_lines[] = $line;
        }

        if (!$exact_exists) {
            $result_lines[] = $entry;
        }

        $result_lines = array_values(array_unique($result_lines));
        return [
            'lines'                 => $result_lines,
            'changed'               => !$exact_exists || $legacy_route_replaced,
            'added'                 => !$exact_exists,
            'legacy_route_replaced' => $legacy_route_replaced,
        ];
    }
}
