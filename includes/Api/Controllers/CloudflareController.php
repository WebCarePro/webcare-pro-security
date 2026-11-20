<?php
declare(strict_types=1);

namespace WebCareProScanner\Api\Controllers;

use WebCareProScanner\Firewall\ThreatIntelNetwork;
use WebCareProScanner\Api\ScannerRoutes;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * CloudflareController
 *
 * Cloudflare & Threat Intel REST Controller.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
final class CloudflareController extends AbstractApiController {

    /**
     * Register endpoints for this domain.
     *
     * @param string   $namespace REST API route namespace.
     * @param callable $permission Permission callback.
     */
    public static function register(string $namespace, callable $permission): void {
        register_rest_route($namespace, '/threat-intel/status', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_threat_intel_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/threat-intel/sync', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'sync_threat_intel'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/threat-intel/cves', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_threat_intel_cves'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/cloudflare/status', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_cloudflare_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/cloudflare/verify', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'verify_cloudflare_credentials'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/cloudflare/deploy-rules', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'deploy_cloudflare_rules'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/cloudflare/deploy-single-rule', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'deploy_single_cloudflare_rule'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/cloudflare/rate-limiting', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'toggle_cloudflare_rate_limiting'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/cloudflare/sync-ip', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'block_cloudflare_ip'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/cloudflare/sync-all-blocked-ips', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'sync_all_blocked_ips_to_cloudflare'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/cloudflare/banned-ips', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_cloudflare_banned_ips'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/cloudflare/unblock-ip', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'unblock_cloudflare_ip'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/cloudflare/purge-cache', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'purge_cloudflare_cache'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/cloudflare/inspect-rules', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'inspect_cloudflare_rules'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/cloudflare/whitelist-ip', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'whitelist_cloudflare_ip'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/cloudflare/whitelisted-ips', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_cloudflare_whitelisted_ips'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/cloudflare/remove-whitelisted-ip', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'remove_cloudflare_whitelisted_ip'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/cloudflare/disconnect', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'disconnect_cloudflare'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/cloudflare/firewall-events', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_cloudflare_firewall_events'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/cloudflare/fetch-firewall-events', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'fetch_cloudflare_firewall_events'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/cloudflare/clear-firewall-events', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'clear_cloudflare_firewall_events'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/threat-intel/network', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_threat_intel_network'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/threat-intel/sync', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'sync_threat_intel_network'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/threat-intel/reputation-check', [
            'methods'             => ['GET', 'POST'],
            'callback'            => [self::class, 'check_threat_intel_reputation'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/domain-reputation/status', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_domain_reputation_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/domain-reputation/check', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'check_domain_reputation_now'],
            'permission_callback' => $permission,
        ]);

    }

    /**
     * Threat Intelligence: Get Status
     */
    public static function get_threat_intel_status() {
        return rest_ensure_response(\WebCareProScanner\Firewall\ThreatIntelService::get_status());
    }

    /**
     * Threat Intelligence: Sync live data
     */
    public static function sync_threat_intel() {
        $result = \WebCareProScanner\Firewall\ThreatIntelService::sync_threat_data();
        return rest_ensure_response($result);
    }

    /**
     * Threat Intelligence: Get CVE catalog
     */
    public static function get_threat_intel_cves() {
        return rest_ensure_response([
            'cves' => \WebCareProScanner\Firewall\ThreatIntelService::get_cve_catalog(),
        ]);
    }

    /**
     * Cloudflare Edge Defense Handlers
     */
    public static function get_cloudflare_status(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing on this installation.', 'webcare-pro-security'), ['status' => 500]);
        }
        $status = \WebCareProScanner\Cloudflare\CloudflareService::get_status();
        $definitions = \WebCareProScanner\Cloudflare\CloudflareService::get_rule_definitions();
        $compound_rules = \WebCareProScanner\Cloudflare\CloudflareService::get_compound_rule_definitions();
        $edge_advisor = \WebCareProScanner\Cloudflare\CloudflareService::get_edge_advisor();
        return rest_ensure_response([
            'success'        => true,
            'status'         => $status,
            'definitions'    => $definitions,
            'compound_rules' => $compound_rules,
            'edge_advisor'   => $edge_advisor,
        ]);
    }

    public static function verify_cloudflare_credentials(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing on this installation. Please reinstall or update the plugin zip.', 'webcare-pro-security'), ['status' => 500]);
        }
        $params  = $request->get_json_params() ?: [];
        $token   = !empty($params['token']) ? trim(sanitize_text_field($params['token'])) : null;
        $zone_id = !empty($params['zone_id']) ? trim(sanitize_text_field($params['zone_id'])) : null;

        $result = \WebCareProScanner\Cloudflare\CloudflareService::verify_zone($zone_id, $token);
        return rest_ensure_response($result);
    }

    public static function deploy_cloudflare_rules(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'webcare-pro-security'), ['status' => 500]);
        }
        $params = $request->get_json_params() ?: [];
        $rules  = is_array($params['rules'] ?? null) ? $params['rules'] : [];

        $result = \WebCareProScanner\Cloudflare\CloudflareService::deploy_custom_rules($rules);

        if (!empty($result['success']) && class_exists('\WebCareProScanner\System\WebCareActivityLogger')) {
            $current_user = wp_get_current_user();
            $user_login = ($current_user && $current_user->exists()) ? $current_user->user_login : 'admin';
            $client_ip = class_exists('\WebCareProScanner\Firewall\FirewallEngine')
                ? \WebCareProScanner\Firewall\FirewallEngine::get_client_ip()
                : (isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '127.0.0.1');

            \WebCareProScanner\System\WebCareActivityLogger::notice(
                'cloudflare_rules_deployed',
                'firewall',
                [
                    'rules_count' => count($rules),
                    'description' => sprintf('Cloudflare Edge WAF rules deployed (%d rules configured) by %s from IP %s.', count($rules), $user_login, $client_ip),
                ]
            );
        }

        return rest_ensure_response($result);
    }

    public static function deploy_single_cloudflare_rule(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'webcare-pro-security'), ['status' => 500]);
        }
        $params   = $request->get_json_params() ?: [];
        $rule_key = sanitize_key($params['rule_key'] ?? '');
        $config   = is_array($params['config'] ?? null) ? $params['config'] : [];
        $enable   = !isset($params['enabled']) || !empty($params['enabled']);

        $result = \WebCareProScanner\Cloudflare\CloudflareService::deploy_single_rule($rule_key, $config, $enable);

        if (!empty($result['success']) && class_exists('\WebCareProScanner\System\WebCareActivityLogger')) {
            $current_user = wp_get_current_user();
            $user_login = ($current_user && $current_user->exists()) ? $current_user->user_login : 'admin';
            $client_ip = class_exists('\WebCareProScanner\Firewall\FirewallEngine')
                ? \WebCareProScanner\Firewall\FirewallEngine::get_client_ip()
                : (isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '127.0.0.1');

            $action_state = $enable ? 'enabled' : 'disabled';
            \WebCareProScanner\System\WebCareActivityLogger::notice(
                'cloudflare_rule_modified',
                'firewall',
                [
                    'rule_key'    => $rule_key,
                    'enabled'     => $enable,
                    'description' => sprintf('Cloudflare Edge rule "%s" was %s by %s from IP %s.', $rule_key, $action_state, $user_login, $client_ip),
                ]
            );
        }

        return rest_ensure_response($result);
    }

    public static function toggle_cloudflare_rate_limiting(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'webcare-pro-security'), ['status' => 500]);
        }
        $params  = $request->get_json_params() ?: [];
        $enable  = !empty($params['enabled']);
        $options = is_array($params['options'] ?? null) ? $params['options'] : [];

        $result = \WebCareProScanner\Cloudflare\CloudflareService::toggle_rate_limiting($enable, $options);

        if (!empty($result['success']) && class_exists('\WebCareProScanner\System\WebCareActivityLogger')) {
            $current_user = wp_get_current_user();
            $user_login = ($current_user && $current_user->exists()) ? $current_user->user_login : 'admin';
            $client_ip = class_exists('\WebCareProScanner\Firewall\FirewallEngine')
                ? \WebCareProScanner\Firewall\FirewallEngine::get_client_ip()
                : (isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '127.0.0.1');

            $state_text = $enable ? 'activated' : 'paused';
            \WebCareProScanner\System\WebCareActivityLogger::notice(
                'cloudflare_rate_limiting_toggled',
                'firewall',
                [
                    'enabled'     => $enable,
                    'description' => sprintf('Cloudflare Edge rate limiting was %s by %s from IP %s.', $state_text, $user_login, $client_ip),
                ]
            );
        }

        return rest_ensure_response($result);
    }

    public static function block_cloudflare_ip(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'webcare-pro-security'), ['status' => 500]);
        }
        $params = $request->get_json_params() ?: [];
        $ip     = sanitize_text_field($params['ip'] ?? '');
        $reason = sanitize_text_field($params['reason'] ?? 'Manual block via Security Scanner');

        $result = \WebCareProScanner\Cloudflare\CloudflareService::block_ip($ip, $reason);

        if (!empty($result['success']) && class_exists('\WebCareProScanner\System\WebCareActivityLogger')) {
            $current_user = wp_get_current_user();
            $user_login = ($current_user && $current_user->exists()) ? $current_user->user_login : 'admin';
            $client_ip = class_exists('\WebCareProScanner\Firewall\FirewallEngine')
                ? \WebCareProScanner\Firewall\FirewallEngine::get_client_ip()
                : (isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '127.0.0.1');

            \WebCareProScanner\System\WebCareActivityLogger::notice(
                'cloudflare_ip_blocked',
                'firewall',
                [
                    'ip'          => $ip,
                    'reason'      => $reason,
                    'rule_id'     => $result['rule_id'] ?? '',
                    'description' => sprintf('IP %s manually blocked at Cloudflare Edge by %s from IP %s. Reason: %s', $ip, $user_login, $client_ip, $reason),
                ]
            );
        }

        return rest_ensure_response($result);
    }

    /**
     * Batch synchronize all active locally blocked IP addresses and CIDR subnets to Cloudflare Edge.
     *
     * @param \WP_REST_Request $request
     * @return \WP_REST_Response|\WP_Error
     */
    public static function sync_all_blocked_ips_to_cloudflare(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'webcare-pro-security'), ['status' => 500]);
        }

        $settings = \WebCareProScanner\System\SettingsManager::get_settings();
        $zone_id  = $settings['cloudflare_zone_id'] ?? '';
        if (empty($zone_id) || empty($settings['cloudflare_api_token'])) {
            return new \WP_Error('cloudflare_not_configured', __('Cloudflare credentials not configured. Please connect your Cloudflare API Token and Zone ID first.', 'webcare-pro-security'), ['status' => 400]);
        }

        // 1. Gather all locally blocked IPs and subnets
        $waf_settings = get_option('webcareproscan_waf_settings', []);
        $raw_blocked  = is_array($waf_settings) ? (string) ($waf_settings['waf_blocked_ips'] ?? '') : '';
        $lines        = array_filter(array_map('trim', explode("\n", $raw_blocked)));
        $unique_ips   = array_values(array_unique($lines));

        // Also check metadata ledger for reasons
        $all_block_meta = class_exists('\WebCareProScanner\Firewall\FirewallEngine')
            ? \WebCareProScanner\Firewall\FirewallEngine::get_all_block_meta()
            : [];

        // 2. Fetch active edge bans ledger
        $active_edge_bans = get_option('webcareproscan_cf_active_edge_bans', []);
        if (!is_array($active_edge_bans)) {
            $active_edge_bans = [];
        }

        $synced_count         = 0;
        $already_synced_count = 0;
        $failed_count         = 0;
        $errors               = [];

        foreach ($unique_ips as $entry) {
            if ($entry === '') {
                continue;
            }

            // Already synced according to ledger
            if (isset($active_edge_bans[$entry])) {
                $already_synced_count++;
                continue;
            }

            $reason = !empty($all_block_meta[$entry]['reason'])
                ? (string) $all_block_meta[$entry]['reason']
                : __('Local WAF blocked IP synchronized to Cloudflare Edge', 'webcare-pro-security');

            $res = \WebCareProScanner\Cloudflare\CloudflareService::block_ip($entry, $reason);
            if (!empty($res['success'])) {
                $synced_count++;
            } else {
                $failed_count++;
                $errors[] = sprintf('%s: %s', $entry, $res['message'] ?? 'Failed');
            }
        }

        if ($synced_count > 0 && class_exists('\WebCareProScanner\System\WebCareActivityLogger')) {
            $current_user = wp_get_current_user();
            $user_login   = ($current_user && $current_user->exists()) ? $current_user->user_login : 'admin';
            \WebCareProScanner\System\WebCareActivityLogger::notice(
                'cloudflare_batch_sync_completed',
                'firewall',
                [
                    'synced_count'         => $synced_count,
                    'already_synced_count' => $already_synced_count,
                    'total_blocked'        => count($unique_ips),
                    'failed_count'         => $failed_count,
                    'description'          => sprintf('Admin %s batch synchronized %d local blocked IPs to Cloudflare Edge (%d were already active at edge).', $user_login, $synced_count, $already_synced_count),
                ]
            );
        }

        return rest_ensure_response([
            'success'              => true,
            'synced_count'         => $synced_count,
            'already_synced_count' => $already_synced_count,
            'total_blocked'        => count($unique_ips),
            'failed_count'         => $failed_count,
            'errors'               => $errors,
            'message'              => sprintf(
                /* translators: 1: synced count, 2: already synced count */
                __('Successfully pushed %1$d IPs to Cloudflare Edge (%2$d already active at Edge).', 'webcare-pro-security'),
                $synced_count,
                $already_synced_count
            ),
        ]);
    }

    public static function get_cloudflare_banned_ips(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'webcare-pro-security'), ['status' => 500]);
        }
        $page     = max(1, (int) $request->get_param('page'));
        $per_page = max(1, min(100, (int) ($request->get_param('per_page') ?: 50)));

        $result = \WebCareProScanner\Cloudflare\CloudflareService::get_banned_ips($page, $per_page);
        return rest_ensure_response($result);
    }

    public static function unblock_cloudflare_ip(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'webcare-pro-security'), ['status' => 500]);
        }
        $params  = $request->get_json_params() ?: [];
        $rule_id = sanitize_text_field($params['rule_id'] ?? '');
        $target_ip = sanitize_text_field(trim($params['ip'] ?? ''));

        if (!empty($rule_id)) {
            $result = \WebCareProScanner\Cloudflare\CloudflareService::unblock_ip($rule_id);
        } elseif (!empty($target_ip)) {
            $result = \WebCareProScanner\Cloudflare\CloudflareService::unblock_ip_by_address($target_ip);
        } else {
            return new \WP_Error('invalid_param', __('Either rule_id or ip is required to unblock.', 'webcare-pro-security'), ['status' => 400]);
        }

        if (!empty($result['success']) && class_exists('\WebCareProScanner\System\WebCareActivityLogger')) {
            $current_user = wp_get_current_user();
            $user_login = ($current_user && $current_user->exists()) ? $current_user->user_login : 'admin';
            $client_ip = class_exists('\WebCareProScanner\Firewall\FirewallEngine')
                ? \WebCareProScanner\Firewall\FirewallEngine::get_client_ip()
                : (isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '127.0.0.1');

            $ip_text = !empty($target_ip) ? sprintf('IP %s', $target_ip) : sprintf('Rule %s', $rule_id);
            $desc = !empty($target_ip)
                ? sprintf('Cloudflare Edge block rule for IP %s removed by %s from IP %s (Rule ID: %s).', $target_ip, $user_login, $client_ip, $rule_id)
                : sprintf('Cloudflare Edge block rule %s removed by %s from IP %s.', $rule_id, $user_login, $client_ip);

            \WebCareProScanner\System\WebCareActivityLogger::notice(
                'cloudflare_ip_unblocked',
                'firewall',
                [
                    'ip'          => $target_ip,
                    'rule_id'     => $rule_id,
                    'description' => $desc,
                ]
            );
        }

        return rest_ensure_response($result);
    }

    public static function purge_cloudflare_cache(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'webcare-pro-security'), ['status' => 500]);
        }
        $params = $request->get_json_params() ?: [];
        $files  = !empty($params['files']) && is_array($params['files']) ? array_map('esc_url_raw', $params['files']) : null;

        $result = \WebCareProScanner\Cloudflare\CloudflareService::purge_cache($files);

        if (!empty($result['success']) && class_exists('\WebCareProScanner\System\WebCareActivityLogger')) {
            $current_user = wp_get_current_user();
            $user_login = ($current_user && $current_user->exists()) ? $current_user->user_login : 'admin';
            $client_ip = class_exists('\WebCareProScanner\Firewall\FirewallEngine')
                ? \WebCareProScanner\Firewall\FirewallEngine::get_client_ip()
                : (isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '127.0.0.1');

            $target_desc = !empty($files) ? sprintf('%d specific file(s)', count($files)) : 'all cached assets (Everything)';
            \WebCareProScanner\System\WebCareActivityLogger::notice(
                'cloudflare_cache_purged',
                'firewall',
                [
                    'target'      => $target_desc,
                    'description' => sprintf('Cloudflare Edge cache purged (%s) by %s from IP %s.', $target_desc, $user_login, $client_ip),
                ]
            );
        }

        return rest_ensure_response($result);
    }

    public static function inspect_cloudflare_rules(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'webcare-pro-security'), ['status' => 500]);
        }
        $settings = \WebCareProScanner\System\SettingsManager::get_settings();
        $zone_id = $settings['cloudflare_zone_id'] ?? '';
        $result = \WebCareProScanner\Cloudflare\CloudflareService::inspect_edge_rules($zone_id);
        return rest_ensure_response($result);
    }

    public static function get_cloudflare_whitelisted_ips(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'webcare-pro-security'), ['status' => 500]);
        }
        $page     = max(1, (int) $request->get_param('page'));
        $per_page = max(1, min(100, (int) ($request->get_param('per_page') ?: 50)));

        $result = \WebCareProScanner\Cloudflare\CloudflareService::get_whitelisted_ips($page, $per_page);
        return rest_ensure_response($result);
    }

    public static function remove_cloudflare_whitelisted_ip(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'webcare-pro-security'), ['status' => 500]);
        }
        $params  = $request->get_json_params() ?: [];
        $rule_id = sanitize_text_field($params['rule_id'] ?? '');
        $target_ip = sanitize_text_field(trim($params['ip'] ?? ''));

        $result = \WebCareProScanner\Cloudflare\CloudflareService::unblock_ip($rule_id);
        if (!empty($result['success'])) {
            $result['message'] = __('Whitelisted IP rule successfully removed from Cloudflare Edge.', 'webcare-pro-security');

            if (class_exists('\WebCareProScanner\System\WebCareActivityLogger')) {
                $current_user = wp_get_current_user();
                $user_login = ($current_user && $current_user->exists()) ? $current_user->user_login : 'admin';
                $client_ip = class_exists('\WebCareProScanner\Firewall\FirewallEngine')
                    ? \WebCareProScanner\Firewall\FirewallEngine::get_client_ip()
                    : (isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '127.0.0.1');

                $desc = !empty($target_ip)
                    ? sprintf('Cloudflare Edge allowlist rule for IP %s removed by %s from IP %s (Rule ID: %s).', $target_ip, $user_login, $client_ip, $rule_id)
                    : sprintf('Cloudflare Edge allowlist rule %s removed by %s from IP %s.', $rule_id, $user_login, $client_ip);

                \WebCareProScanner\System\WebCareActivityLogger::notice(
                    'cloudflare_whitelist_removed',
                    'firewall',
                    [
                        'ip'          => $target_ip,
                        'rule_id'     => $rule_id,
                        'description' => $desc,
                    ]
                );
            }
        }
        return rest_ensure_response($result);
    }

    public static function whitelist_cloudflare_ip(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'webcare-pro-security'), ['status' => 500]);
        }
        $params = $request->get_json_params() ?: [];
        $ip     = sanitize_text_field($params['ip'] ?? '');
        $notes  = sanitize_text_field($params['notes'] ?? 'Administrator / Developer Whitelist via WebCare');

        $result = \WebCareProScanner\Cloudflare\CloudflareService::whitelist_ip($ip, $notes);

        if (!empty($result['success']) && class_exists('\WebCareProScanner\System\WebCareActivityLogger')) {
            $current_user = wp_get_current_user();
            $user_login = ($current_user && $current_user->exists()) ? $current_user->user_login : 'admin';
            $client_ip = class_exists('\WebCareProScanner\Firewall\FirewallEngine')
                ? \WebCareProScanner\Firewall\FirewallEngine::get_client_ip()
                : (isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '127.0.0.1');

            \WebCareProScanner\System\WebCareActivityLogger::notice(
                'cloudflare_ip_whitelisted',
                'firewall',
                [
                    'ip'          => $ip,
                    'notes'       => $notes,
                    'rule_id'     => $result['rule_id'] ?? '',
                    'description' => sprintf('IP %s added to Cloudflare Edge Allowlist by %s from IP %s. Notes: %s', $ip, $user_login, $client_ip, $notes),
                ]
            );
        }

        return rest_ensure_response($result);
    }

    public static function disconnect_cloudflare(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'webcare-pro-security'), ['status' => 500]);
        }
        $result = \WebCareProScanner\Cloudflare\CloudflareService::disconnect();
        return rest_ensure_response($result);
    }

    public static function get_cloudflare_firewall_events(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'webcare-pro-security'), ['status' => 500]);
        }
        $result = \WebCareProScanner\Cloudflare\CloudflareService::get_stored_firewall_events();
        return rest_ensure_response($result);
    }

    public static function fetch_cloudflare_firewall_events(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'webcare-pro-security'), ['status' => 500]);
        }
        $params = $request->get_json_params() ?: [];
        $limit  = isset($params['limit']) ? intval($params['limit']) : 100;

        $result = \WebCareProScanner\Cloudflare\CloudflareService::fetch_and_store_firewall_events($limit);
        return rest_ensure_response($result);
    }

    public static function clear_cloudflare_firewall_events(\WP_REST_Request $request) {
        if (!self::ensure_cloudflare_service()) {
            return new \WP_Error('service_unavailable', __('Cloudflare service file is missing.', 'webcare-pro-security'), ['status' => 500]);
        }
        $result = \WebCareProScanner\Cloudflare\CloudflareService::clear_stored_firewall_events();
        return rest_ensure_response($result);
    }

    public static function get_threat_intel_network(\WP_REST_Request $request) {
        $telemetry = ThreatIntelNetwork::get_network_telemetry();
        return rest_ensure_response([
            'success'   => true,
            'telemetry' => $telemetry,
        ]);
    }

    public static function sync_threat_intel_network(\WP_REST_Request $request) {
        $res = ThreatIntelNetwork::sync_all_feeds();
        $telemetry = ThreatIntelNetwork::get_network_telemetry();
        return rest_ensure_response([
            'success'   => true,
            'sync'      => $res,
            'telemetry' => $telemetry,
            'message'   => sprintf(
                /* translators: 1: total active threat IPs, 2: total Tor nodes */
                __('Threat intelligence feeds synchronized! Active pool: %1$d botnet IPs, %2$d Tor exit nodes.', 'webcare-pro-security'),
                $res['total_active_ips'] ?? 0,
                $res['tor_exit_nodes_count'] ?? 0
            ),
        ]);
    }

    public static function check_threat_intel_reputation(\WP_REST_Request $request) {
        $ip = sanitize_text_field($request->get_param('ip') ?: '');
        if (empty($ip)) {
            $ip = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '127.0.0.1';
        }

        $assessment = ThreatIntelNetwork::calculate_reputation_score($ip);
        return rest_ensure_response([
            'success'    => true,
            'assessment' => $assessment,
        ]);
    }

    public static function get_domain_reputation_status() {
        return rest_ensure_response(\WebCareProScanner\Firewall\DomainReputationMonitor::run_reputation_audit(false));
    }

    public static function check_domain_reputation_now() {
        return rest_ensure_response(\WebCareProScanner\Firewall\DomainReputationMonitor::run_reputation_audit(true));
    }

    /**
     * Helper to load CloudflareService reliably
     */
    public static function ensure_cloudflare_service(): bool {
        if (!class_exists('\WebCareProScanner\Cloudflare\CloudflareService')) {
            $candidates = [
                WEBCAREPROSCAN_PATH . 'includes/Cloudflare/CloudflareService.php',
                WEBCAREPROSCAN_PATH . 'includes/cloudflare/CloudflareService.php',
                WEBCAREPROSCAN_PATH . 'includes/Firewall/CloudflareService.php',
            ];
            foreach ($candidates as $file) {
                if (file_exists($file)) {
                    require_once $file;
                    break;
                }
            }
        }
        return class_exists('\WebCareProScanner\Cloudflare\CloudflareService');
    }
}
