<?php
declare(strict_types=1);

namespace WebCareProScanner\Api\Controllers;

use WebCareProScanner\Firewall\VirtualPatchSynthesizer;
use WebCareProScanner\Api\ScannerRoutes;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * ModularWafController
 *
 * Modular WAF & Behavioral Defense REST Controller.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
final class ModularWafController extends AbstractApiController {

    /**
     * Register endpoints for this domain.
     *
     * @param string   $namespace REST API route namespace.
     * @param callable $permission Permission callback.
     */
    public static function register(string $namespace, callable $permission): void {
        register_rest_route($namespace, '/virtual-patch/list', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'virtual_patch_list'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/virtual-patch/apply', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'virtual_patch_apply'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/virtual-patch/remove', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'virtual_patch_remove'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/behavioral/status', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_behavioral_waf_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/behavioral/route-status', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'set_behavioral_route_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/behavioral/learning-settings', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'update_behavioral_learning_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/behavioral/honeytoken/settings', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'update_honeytoken_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/behavioral/honeytoken/unban', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'unban_honeytoken_ip'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/behavioral/honeytoken/reseed-db-canaries', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'reseed_db_canaries'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/behavioral/rate-limiter/settings', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'update_rate_limiter_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/distributed-shield/status', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_distributed_shield_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/distributed-shield/settings', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'update_distributed_shield_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/distributed-shield/toggle-under-attack', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'toggle_under_attack_mode'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/distributed-shield/simulate', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'simulate_distributed_attack'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/taint-engine/status', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_taint_engine_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/taint-engine/analyze', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'analyze_code_taint_flow'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/geo-shield/status', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_geo_shield_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/geo-shield/save-baseline', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'save_geo_llms_baseline'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/geo-shield/audit-content', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'audit_geo_content'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/block-security/status', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_block_security_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/block-security/audit', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'audit_block_directives'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/virtual-patch/synthesized', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_synthesized_virtual_patches'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/virtual-patch/synthesize', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'synthesize_virtual_patch'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/virtual-patch/test-simulation', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'test_virtual_patch_simulation'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/virtual-patch/deploy-synthesized', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'deploy_synthesized_virtual_patch'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/virtual-patch/toggle-synthesized', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'toggle_synthesized_virtual_patch'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/virtual-patch/delete-synthesized', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'delete_synthesized_virtual_patch'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/virtual-patch/cve-lookup', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'virtual_patch_cve_lookup'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/virtual-patch/deactivate-component', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'virtual_patch_deactivate_component'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/ai-status', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_ai_defense_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/ghost-routes', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_ghost_routes_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/ghost-routes/settings', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'update_ghost_routes_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/egress', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_egress_firewall_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/egress/settings', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'update_egress_firewall_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/credentials', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_credential_exposure_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/credentials/scan', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'scan_credential_exposure'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/prompt-guard', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_prompt_guard_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/prompt-guard/settings', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'update_prompt_guard_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/prompt-guard/test', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'test_prompt_injection'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/attack-surface', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_attack_surface_inventory'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/attack-surface/settings', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'update_attack_surface_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/attack-surface/export', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'export_attack_surface_bundle'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/custom-rules/scan/start', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'start_modular_scan'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/custom-rules/scan/batch', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'process_modular_scan_batch'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/custom-rules/scan/pause', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'pause_modular_scan'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/custom-rules/scan/resume', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'resume_modular_scan'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/custom-rules/scan/cancel', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'cancel_modular_scan'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/custom-rules/status', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_custom_rules_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/custom-rules/rule/toggle', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'toggle_modular_rule'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/custom-rules/rule/bulk-apply', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'bulk_apply_modular_rules'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/custom-rules/rule/custom', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'save_custom_modular_rule'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/custom-rules/code-preview', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_modular_code_preview'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/custom-rules/export', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'export_custom_rules_bundle'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/custom-rules/autopilot', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'toggle_modular_autopilot'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/custom-rules/fields', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_modular_visual_fields'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/custom-rules/rule/simulate', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'simulate_custom_modular_rule'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/custom-rules/rule/custom/delete', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'delete_custom_modular_rule'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/custom-rules/rule/custom/reorder', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'reorder_custom_modular_rules'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/custom-rules/rule/cloudflare-push', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'push_custom_rule_to_cloudflare'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/custom-rules/rule/parse-wirefilter', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'parse_wirefilter_expression'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/custom-rules/rule/parse-ai', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'parse_ai_rule_payload'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/custom-rules/rule/ai-generate', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'ai_generate_visual_rule'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/cve/nist-status', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_nist_cve_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/cve/nist-sync-start', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'start_nist_cve_sync'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/cve/nist-fetch-component', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'fetch_nist_cve_component'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/cve/nist-api-key', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'save_nist_api_key'],
            'permission_callback' => $permission,
        ]);

    }

    /**
     * Initialize a new behavioral intelligence scan session.
     *
     * @param \WP_REST_Request $request
     * @return \WP_REST_Response
     */
    public static function start_modular_scan(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\CustomRules\\SiteBehavioralAnalyzer')) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => __('Behavioral analyzer engine unavailable.', 'webcare-pro-security'),
            ], 500);
        }

        $params = $request->get_json_params() ?: [];
        $result = \WebCareProScanner\Firewall\CustomRules\SiteBehavioralAnalyzer::start_scan($params);
        return new \WP_REST_Response($result, 200);
    }

    /**
     * Process a chunked batch of files in the active behavioral scan session.
     *
     * @param \WP_REST_Request $request
     * @return \WP_REST_Response
     */
    public static function process_modular_scan_batch(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\CustomRules\\SiteBehavioralAnalyzer')) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => __('Behavioral analyzer engine unavailable.', 'webcare-pro-security'),
            ], 500);
        }

        $params = $request->get_json_params() ?: [];
        $batch_size = max(10, min(500, intval($params['batch_size'] ?? 400)));
        $result = \WebCareProScanner\Firewall\CustomRules\SiteBehavioralAnalyzer::process_batch($batch_size);
        return new \WP_REST_Response($result, 200);
    }

    /**
     * Pause an active behavioral AST scan session cleanly.
     *
     * @param \WP_REST_Request $request
     * @return \WP_REST_Response
     */
    public static function pause_modular_scan(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\CustomRules\\SiteBehavioralAnalyzer')) {
            return new \WP_REST_Response(['success' => false, 'message' => __('Behavioral analyzer engine unavailable.', 'webcare-pro-security')], 500);
        }
        return new \WP_REST_Response(\WebCareProScanner\Firewall\CustomRules\SiteBehavioralAnalyzer::pause_scan(), 200);
    }

    /**
     * Resume a paused or stale behavioral AST scan session.
     *
     * @param \WP_REST_Request $request
     * @return \WP_REST_Response
     */
    public static function resume_modular_scan(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\CustomRules\\SiteBehavioralAnalyzer')) {
            return new \WP_REST_Response(['success' => false, 'message' => __('Behavioral analyzer engine unavailable.', 'webcare-pro-security')], 500);
        }
        return new \WP_REST_Response(\WebCareProScanner\Firewall\CustomRules\SiteBehavioralAnalyzer::resume_scan(), 200);
    }

    /**
     * Cancel and discard an in-progress behavioral AST scan session while preserving previously sealed Vault rules.
     *
     * @param \WP_REST_Request $request
     * @return \WP_REST_Response
     */
    public static function cancel_modular_scan(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\CustomRules\\SiteBehavioralAnalyzer')) {
            return new \WP_REST_Response(['success' => false, 'message' => __('Behavioral analyzer engine unavailable.', 'webcare-pro-security')], 500);
        }
        return new \WP_REST_Response(\WebCareProScanner\Firewall\CustomRules\SiteBehavioralAnalyzer::cancel_scan(), 200);
    }

    /**
     * Retrieve behavioral intelligence vault summary, component dossiers, and synthesized modular rules.
     *
     * @param \WP_REST_Request $request
     * @return \WP_REST_Response
     */
    public static function get_custom_rules_status(\WP_REST_Request $request) {
        $ctx            = self::build_modular_dossier_context(false);
        $preload_active = defined('WEBCAREPRO_PRELOAD_WAF_ACTIVE') && WEBCAREPRO_PRELOAD_WAF_ACTIVE;
        $autopilot      = class_exists('\\WebCareProScanner\\Firewall\\CustomRules\\ModularFirewallSynthesizer')
            && \WebCareProScanner\Firewall\CustomRules\ModularFirewallSynthesizer::is_autopilot_enabled();

        return new \WP_REST_Response([
            'success'           => true,
            'vault_summary'     => $ctx['vault_summary'],
            'rules'             => $ctx['rules'],
            'inventory'         => $ctx['inventory'],
            'trust_summary'     => $ctx['trust_summary'],
            'endpoint_map'      => $ctx['endpoint_map'],
            'findings'          => $ctx['findings'],
            'scan_progress'     => $ctx['scan_progress'],
            'preload_active'    => $preload_active,
            'autopilot_enabled' => $autopilot,
        ], 200);
    }

    /**
     * Toggle Smart 48-Hour Auto-Pilot for Modular Firewall rules.
     */
    public static function toggle_modular_autopilot(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\CustomRules\\ModularFirewallSynthesizer')) {
            return new \WP_REST_Response(['success' => false, 'message' => __('Modular firewall synthesizer unavailable.', 'webcare-pro-security')], 500);
        }
        $params  = $request->get_json_params() ?: [];
        $enabled = !empty($params['enabled']);
        $res     = \WebCareProScanner\Firewall\CustomRules\ModularFirewallSynthesizer::set_autopilot_enabled($enabled);
        return new \WP_REST_Response($res, 200);
    }

    /**
     * Toggle a modular firewall rule mode (enforce, monitor, off) or update parameters.
     *
     * @param \WP_REST_Request $request
     * @return \WP_REST_Response
     */
    public static function toggle_modular_rule(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\CustomRules\\ModularFirewallSynthesizer')) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => __('Modular firewall synthesizer unavailable.', 'webcare-pro-security'),
            ], 500);
        }

        $params  = $request->get_json_params() ?: [];
        $rule_id = isset($params['rule_id']) ? sanitize_text_field(wp_unslash($params['rule_id'])) : '';
        $mode    = isset($params['mode']) ? sanitize_key($params['mode']) : 'enforce';

        if (empty($rule_id)) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => __('Rule ID is required.', 'webcare-pro-security'),
            ], 400);
        }

        $result = \WebCareProScanner\Firewall\CustomRules\ModularFirewallSynthesizer::toggle_rule($rule_id, $mode, $params);
        return new \WP_REST_Response($result, 200);
    }

    /**
     * Bulk activate/enforce all recommended modular firewall rules.
     *
     * @param \WP_REST_Request $request
     * @return \WP_REST_Response
     */
    public static function bulk_apply_modular_rules(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\CustomRules\\ModularFirewallSynthesizer')) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => __('Modular firewall synthesizer unavailable.', 'webcare-pro-security'),
            ], 500);
        }

        $result = \WebCareProScanner\Firewall\CustomRules\ModularFirewallSynthesizer::bulk_apply_recommendations();
        return new \WP_REST_Response($result, 200);
    }

    /**
     * Create or save a developer-defined custom modular rule.
     *
     * @param \WP_REST_Request $request
     * @return \WP_REST_Response
     */
    public static function save_custom_modular_rule(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\CustomRules\\ModularFirewallSynthesizer')) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => __('Modular firewall synthesizer unavailable.', 'webcare-pro-security'),
            ], 500);
        }

        $params = $request->get_json_params() ?: [];
        $result = \WebCareProScanner\Firewall\CustomRules\ModularFirewallSynthesizer::create_custom_rule($params);
        return new \WP_REST_Response($result, 200);
    }

    /**
     * Return Custom Firewall Rules field catalog plus live installed plugins/themes, roles, endpoints, AI & MCP status.
     */
    public static function get_modular_visual_fields(\WP_REST_Request $request) {
        $ctx = class_exists('\\WebCareProScanner\\Firewall\\CustomRules\\VisualRuleExpressionEngine')
            ? \WebCareProScanner\Firewall\CustomRules\VisualRuleExpressionEngine::get_site_context_data()
            : [
                'fields'                => [],
                'installed_components'  => [],
                'roles'                 => [],
                'current_ip'            => '',
                'discovered_endpoints'  => ['ajax_actions' => [], 'rest_routes' => []],
                'custom_rules_count'    => 0,
                'existing_custom_rules' => [],
                'cloudflare_status'     => ['enabled' => false, 'configured' => false, 'connected' => false, 'proxied' => false, 'zone_name' => ''],
            ];

        $ai_creds = class_exists('\\WebCareProScanner\\System\\AIService')
            ? \WebCareProScanner\System\AIService::resolve_active_credentials()
            : ['configured' => false, 'provider' => 'gemini', 'model' => ''];

        $mcp_settings = class_exists('\\WebCareProScanner\\System\\SettingsManager')
            ? \WebCareProScanner\System\SettingsManager::get_settings()
            : [];
        $mcp_tools_count = 0;
        if (class_exists('\\WebCareProScanner\\Core\\Modules\\ModularWafModule')) {
            $mod_instance    = new \WebCareProScanner\Core\Modules\ModularWafModule();
            $mcp_tools_count = count($mod_instance->get_mcp_tools());
        }

        $ctx['success']   = true;
        $ctx['ai_status'] = [
            'configured' => !empty($ai_creds['configured']),
            'provider'   => (string) ($ai_creds['provider'] ?? 'gemini'),
            'model'      => (string) ($ai_creds['model'] ?? ''),
        ];
        $ctx['mcp_status'] = [
            'enabled'         => !empty($mcp_settings['mcp_enabled']),
            'scope'           => (string) ($mcp_settings['mcp_permission_scope'] ?? 'read_only'),
            'modular_tools'   => $mcp_tools_count,
        ];

        return new \WP_REST_Response($ctx, 200);
    }

    /**
     * Dry-run simulate a Visual/Custom rule against recent WafFileLogger history.
     */
    public static function simulate_custom_modular_rule(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\CustomRules\\VisualRuleExpressionEngine')) {
            return new \WP_REST_Response(['success' => false, 'message' => __('Visual expression engine unavailable.', 'webcare-pro-security')], 500);
        }
        $params = $request->get_json_params() ?: [];
        $limit  = isset($params['limit']) ? intval($params['limit']) : 500;
        $res    = \WebCareProScanner\Firewall\CustomRules\VisualRuleExpressionEngine::simulate_against_recent_logs($params, $limit);
        return new \WP_REST_Response($res, 200);
    }

    /**
     * Delete a developer-defined custom rule.
     */
    public static function delete_custom_modular_rule(\WP_REST_Request $request) {
        $params  = $request->get_json_params() ?: [];
        $rule_id = sanitize_text_field((string) ($params['rule_id'] ?? ''));
        if ($rule_id === '') {
            return new \WP_REST_Response(['success' => false, 'message' => __('Rule ID is required.', 'webcare-pro-security')], 400);
        }
        $res = \WebCareProScanner\Firewall\CustomRules\ModularFirewallSynthesizer::delete_custom_rule($rule_id);
        return new \WP_REST_Response($res, 200);
    }

    /**
     * Push a Custom Firewall Rule's HTTP/Network Wirefilter expression directly to Cloudflare Edge Custom Ruleset.
     */
    public static function push_custom_rule_to_cloudflare(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\CustomRules\\VisualRuleExpressionEngine')) {
            return new \WP_REST_Response(['success' => false, 'message' => __('Visual expression engine unavailable.', 'webcare-pro-security')], 500);
        }
        $params = $request->get_json_params() ?: [];
        $res    = \WebCareProScanner\Firewall\CustomRules\VisualRuleExpressionEngine::push_rule_to_cloudflare_edge($params);
        return new \WP_REST_Response($res, 200);
    }

    /**
     * Reorder custom modular firewall rules in priority sequence.
     */
    public static function reorder_custom_modular_rules(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\CustomRules\\ModularFirewallSynthesizer')) {
            return new \WP_REST_Response(['success' => false, 'message' => __('Modular firewall synthesizer unavailable.', 'webcare-pro-security')], 500);
        }
        $params      = $request->get_json_params() ?: [];
        $ordered_ids = is_array($params['ordered_ids'] ?? null) ? $params['ordered_ids'] : [];
        if (empty($ordered_ids)) {
            return new \WP_REST_Response(['success' => false, 'message' => __('ordered_ids array is required.', 'webcare-pro-security')], 400);
        }
        $res = \WebCareProScanner\Firewall\CustomRules\ModularFirewallSynthesizer::reorder_custom_rules($ordered_ids);
        return new \WP_REST_Response($res, 200);
    }

    /**
     * Parse an edited Wirefilter expression into structured visual condition groups.
     */
    public static function parse_wirefilter_expression(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\CustomRules\\VisualRuleExpressionEngine')) {
            return new \WP_REST_Response(['success' => false, 'conditions' => [], 'group_logic' => 'OR'], 200);
        }
        $params      = $request->get_json_params() ?: [];
        $expr        = (string) ($params['wirefilter_expr'] ?? '');
        $tree        = \WebCareProScanner\Firewall\CustomRules\VisualRuleExpressionEngine::parse_wirefilter_tree($expr);
        $conditions  = $tree['conditions'];
        $group_logic = $tree['group_logic'];
        $unparsed    = $tree['unparsed_clauses'] ?? [];
        $wf          = \WebCareProScanner\Firewall\CustomRules\VisualRuleExpressionEngine::to_wirefilter($conditions, $group_logic);
        $warnings    = \WebCareProScanner\Firewall\CustomRules\VisualRuleExpressionEngine::lint_rule_safety($conditions, $wf, $unparsed);
        return new \WP_REST_Response([
            'success'          => !empty($conditions),
            'conditions'       => $conditions,
            'group_logic'      => $group_logic,
            'wirefilter'       => $wf,
            'cf_edge'          => \WebCareProScanner\Firewall\CustomRules\VisualRuleExpressionEngine::to_cloudflare_edge_wirefilter($conditions, $group_logic),
            'warnings'         => $warnings,
            'unparsed_clauses' => $unparsed,
        ], 200);
    }

    /**
     * Parse pasted AI rule output (JSON rule bundle, fenced Wirefilter block, or raw Wirefilter)
     * into Visual Builder fields with safety diagnostics.
     */
    public static function parse_ai_rule_payload(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\CustomRules\\VisualRuleExpressionEngine')) {
            return new \WP_REST_Response(['success' => false, 'message' => __('Visual expression engine unavailable.', 'webcare-pro-security')], 500);
        }
        $params    = $request->get_json_params() ?: [];
        $raw_input = (string) ($params['raw_input'] ?? ($params['wirefilter_expr'] ?? ''));
        $parsed    = \WebCareProScanner\Firewall\CustomRules\VisualRuleExpressionEngine::parse_ai_rule_payload($raw_input);
        return new \WP_REST_Response($parsed, 200);
    }

    /**
     * Generate a Visual Firewall Rule using the configured AIService provider and site context.
     */
    public static function ai_generate_visual_rule(\WP_REST_Request $request) {
        if (
            !class_exists('\\WebCareProScanner\\Firewall\\CustomRules\\VisualRuleExpressionEngine')
            || !class_exists('\\WebCareProScanner\\System\\AIService')
        ) {
            return new \WP_REST_Response(['success' => false, 'message' => __('AI generator subsystem unavailable.', 'webcare-pro-security')], 500);
        }

        $params = $request->get_json_params() ?: [];
        $goal   = sanitize_textarea_field(wp_unslash((string) ($params['goal'] ?? '')));
        if (trim($goal) === '') {
            return new \WP_REST_Response(['success' => false, 'message' => __('Please describe what firewall rule you want AI to create.', 'webcare-pro-security')], 400);
        }

        $prompt = \WebCareProScanner\Firewall\CustomRules\VisualRuleExpressionEngine::build_ai_markdown_prompt($goal);
        $system = 'You are a WordPress WAF Rule Architect. Output ONLY a single valid JSON object inside ```json ... ``` matching the requested schema (title, description, expression, action_type, ban_ttl, block_uploads, placement) using strictly the provided field IDs and operators.';
        $res    = \WebCareProScanner\System\AIService::generate_text_completion($system, $prompt, 0.15, 900, 45);
        if (empty($res['success'])) {
            return new \WP_REST_Response($res, 200);
        }

        $parsed             = \WebCareProScanner\Firewall\CustomRules\VisualRuleExpressionEngine::parse_ai_rule_payload((string) ($res['text'] ?? ''));
        $parsed['provider'] = $res['provider'] ?? '';
        $parsed['model']    = $res['model'] ?? '';
        $parsed['raw_ai']   = (string) ($res['text'] ?? '');
        return new \WP_REST_Response($parsed, 200);
    }

    /**
     * Read a safe 15-line preview snippet of the code that triggered a modular rule.
     *
     * @param \WP_REST_Request $request
     * @return \WP_REST_Response
     */
    public static function get_modular_code_preview(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\CustomRules\\ModularFirewallSynthesizer')) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => __('Modular firewall synthesizer unavailable.', 'webcare-pro-security'),
            ], 500);
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $file = isset($_GET['file']) ? sanitize_text_field(wp_unslash($_GET['file'])) : '';
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $line = isset($_GET['line']) ? max(1, intval($_GET['line'])) : 1;

        if (empty($file)) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => __('File parameter is required.', 'webcare-pro-security'),
            ], 400);
        }

        $result = \WebCareProScanner\Firewall\CustomRules\ModularFirewallSynthesizer::get_code_preview($file, $line);
        return new \WP_REST_Response($result, 200);
    }

    /**
     * Export complete Modular Intelligence Firewall forensic bundle as JSON.
     *
     * Provides complete visibility into synthesized rules, component inventory,
     * behavioral endpoint maps, AST taint findings, recent modular triggers,
     * and scan telemetry so false positives can be rapidly investigated.
     *
     * @param \WP_REST_Request $request
     * @return \WP_REST_Response
     */
    public static function export_custom_rules_bundle(\WP_REST_Request $request) {
        $synth = '\\WebCareProScanner\\Firewall\\CustomRules\\ModularFirewallSynthesizer';

        $ctx        = self::build_modular_dossier_context(true);
        $rules_list = $ctx['rules'];
        $inventory  = $ctx['inventory'];
        $findings   = $ctx['findings'];
        $endpoints  = $ctx['endpoint_map'];

        $enforced_count = 0;
        $monitor_count  = 0;
        $off_count      = 0;
        $custom_count   = 0;
        $by_category    = [];

        foreach ($rules_list as $rl) {
            $mode = $rl['current_mode'] ?? 'off';
            if ($mode === 'enforce') {
                $enforced_count++;
            } elseif ($mode === 'monitor') {
                $monitor_count++;
            } else {
                $off_count++;
            }
            if (!empty($rl['is_custom'])) {
                $custom_count++;
            }
            $cat = $rl['category'] ?? 'unknown';
            $by_category[$cat] = ($by_category[$cat] ?? 0) + 1;
        }

        // Assemble deduplicated file cryptographic hash index & log correlation context
        $file_hash_index      = self::build_file_hash_index($rules_list, $findings);
        $log_analysis_context = self::build_modular_log_analysis_context();

        // Collect compiled 0ms Pre-Boot Micro-WAF snapshot
        $preload_active = defined('WEBCAREPRO_PRELOAD_WAF_ACTIVE') && WEBCAREPRO_PRELOAD_WAF_ACTIVE;
        $compiled_file  = class_exists('\\WebCareProScanner\\Firewall\\MicroWafCompiler')
            ? \WebCareProScanner\Firewall\MicroWafCompiler::get_compiled_file_path()
            : '';
        $compiled_preload_waf = [
            'preload_waf_active'  => $preload_active,
            'compiled_file_exists'=> ($compiled_file && file_exists($compiled_file)),
            'compiled_file_sha256'=> ($compiled_file && file_exists($compiled_file)) ? (@hash_file('sha256', $compiled_file) ?: null) : null,
            'compiled_file_mtime' => ($compiled_file && file_exists($compiled_file)) ? gmdate('c', (int) @filemtime($compiled_file)) : null,
            'compiled_rules'      => class_exists($synth) ? $synth::get_compiled_preload_rules() : [],
        ];

        $active_theme = wp_get_theme();
        $site_host    = wp_parse_url(get_site_url(), PHP_URL_HOST) ?: 'localhost';

        $payload = [
            'success'                     => true,
            'webcare_export_type'         => 'custom_rules_forensic_dossier',
            'format_version'              => defined('WEBCAREPROSCAN_VERSION') ? WEBCAREPROSCAN_VERSION : '2.11.0',
            'exported_at'                 => gmdate('c'),
            'exported_timestamp'          => time(),
            'author'                      => 'Mir Alamin (WebCare Pro)',
            'environment'                 => [
                'site_url'           => get_site_url(),
                'home_url'           => get_home_url(),
                'wordpress_version'  => $GLOBALS['wp_version'] ?? 'Unknown',
                'php_version'        => PHP_VERSION,
                'server_software'    => isset($_SERVER['SERVER_SOFTWARE']) ? sanitize_text_field(wp_unslash($_SERVER['SERVER_SOFTWARE'])) : 'Unknown',
                'webcare_version'    => defined('WEBCAREPROSCAN_VERSION') ? WEBCAREPROSCAN_VERSION : '2.11.0',
                'preload_waf_active' => $preload_active,
                'site_archetype'     => get_option('webcareproscan_site_archetype', 'business'),
                'active_theme'       => [
                    'name'       => $active_theme ? $active_theme->get('Name') : '',
                    'version'    => $active_theme ? $active_theme->get('Version') : '',
                    'template'   => $active_theme ? $active_theme->get_template() : '',
                    'stylesheet' => $active_theme ? $active_theme->get_stylesheet() : '',
                ],
            ],
            'summary'                     => [
                'total_rules'          => count($rules_list),
                'enforced_rules'       => $enforced_count,
                'monitored_rules'      => $monitor_count,
                'disabled_rules'       => $off_count,
                'custom_rules'         => $custom_count,
                'rules_by_category'    => $by_category,
                'components_profiled'  => count($inventory),
                'endpoints_mapped'     => count($endpoints),
                'ast_findings_count'   => count($findings),
                'unique_files_hashed'  => count($file_hash_index),
                'recent_modular_hits'  => $log_analysis_context['total_events_analyzed'],
                'vault_sealed'         => !empty($ctx['vault_summary']),
            ],
            'trust_and_integrity_summary' => $ctx['trust_summary'],
            'rules'                       => $rules_list,
            'component_inventory'         => $inventory,
            'file_hash_index'             => $file_hash_index,
            'compiled_preload_waf'        => $compiled_preload_waf,
            'log_analysis_context'        => $log_analysis_context,
            'endpoint_behavior_map'       => $endpoints,
            'ast_taint_findings'          => $findings,
            'recent_modular_hits'         => $log_analysis_context['recent_log_records'],
            'vault_summary'               => $ctx['vault_summary'],
            'scan_progress'               => $ctx['scan_progress'],
        ];

        $is_download = !empty($request->get_param('download'));
        if ($is_download) {
            $filename = 'webcare-custom-rules-' . sanitize_file_name($site_host) . '-' . gmdate('Y-m-d') . '.json';
            header('Content-Type: application/json; charset=utf-8');
            header('Content-Disposition: attachment; filename="' . $filename . '"');
            header('X-Content-Type-Options: nosniff');
            echo wp_json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
            exit;
        }

        return new \WP_REST_Response($payload, 200);
    }

    public static function virtual_patch_list(\WP_REST_Request $request) {
        $catalog = \WebCareProScanner\Firewall\VirtualPatchManager::get_patch_catalog();
        $active = \WebCareProScanner\Firewall\VirtualPatchManager::get_active_patches();
        
        $settings = \WebCareProScanner\System\SettingsManager::get_settings();
        $cf_ready = !empty($settings['cloudflare_api_token']) && !empty($settings['cloudflare_zone_id']);

        return rest_ensure_response([
            'success'           => true,
            'catalog'           => array_values($catalog),
            'active_patches'    => array_values($active),
            'cloudflare_ready'  => $cf_ready,
        ]);
    }

    public static function virtual_patch_apply(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $patch_id = sanitize_text_field(wp_unslash($params['patch_id'] ?? ''));
        $custom_config = is_array($params['custom_config'] ?? null) ? $params['custom_config'] : [];

        if (empty($patch_id)) {
            return new \WP_Error('missing_patch_id', __('Patch ID is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $result = \WebCareProScanner\Firewall\VirtualPatchManager::apply_patch($patch_id, $custom_config);
        if (!$result['success']) {
            return new \WP_Error('patch_failed', $result['message'], ['status' => 500]);
        }

        return rest_ensure_response($result);
    }

    public static function virtual_patch_remove(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $patch_id = sanitize_text_field(wp_unslash($params['patch_id'] ?? ''));

        if (empty($patch_id)) {
            return new \WP_Error('missing_patch_id', __('Patch ID is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $result = \WebCareProScanner\Firewall\VirtualPatchManager::remove_patch($patch_id);
        if (!$result['success']) {
            return new \WP_Error('remove_failed', $result['message'], ['status' => 500]);
        }

        return rest_ensure_response($result);
    }

    public static function get_behavioral_waf_status(\WP_REST_Request $request) {
        $learning_stats    = class_exists('\WebCareProScanner\Firewall\LearningModeEngine') ? \WebCareProScanner\Firewall\LearningModeEngine::get_summary_stats() : [];
        $route_profiles    = class_exists('\WebCareProScanner\Firewall\LearningModeEngine') ? \WebCareProScanner\Firewall\LearningModeEngine::get_route_profiles() : [];
        $learning_settings = class_exists('\WebCareProScanner\Firewall\LearningModeEngine') ? \WebCareProScanner\Firewall\LearningModeEngine::get_settings() : [];
        $honeytoken        = class_exists('\WebCareProScanner\Firewall\HoneyTokenEngine') ? \WebCareProScanner\Firewall\HoneyTokenEngine::get_summary() : [];
        $rate_limiter      = class_exists('\WebCareProScanner\Firewall\AdaptiveRateLimiter') ? \WebCareProScanner\Firewall\AdaptiveRateLimiter::get_telemetry() : [];

        return rest_ensure_response([
            'success'           => true,
            'learning_stats'    => $learning_stats,
            'route_profiles'    => $route_profiles,
            'learning_settings' => $learning_settings,
            'honeytoken'        => $honeytoken,
            'rate_limiter'      => $rate_limiter,
        ]);
    }

    public static function set_behavioral_route_status(\WP_REST_Request $request) {
        $params    = $request->get_json_params() ?: [];
        $route_key = sanitize_text_field($params['route_key'] ?? '');
        $action    = sanitize_key($params['action'] ?? '');

        if (empty($route_key) || empty($action)) {
            return new \WP_Error('missing_params', __('Route key and action are required.', 'webcare-pro-security'), ['status' => 400]);
        }

        if (!class_exists('\WebCareProScanner\Firewall\LearningModeEngine')) {
            return new \WP_Error('missing_engine', __('LearningModeEngine not available.', 'webcare-pro-security'), ['status' => 500]);
        }

        $result = \WebCareProScanner\Firewall\LearningModeEngine::set_route_status($route_key, $action);
        return rest_ensure_response($result);
    }

    public static function update_behavioral_learning_settings(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        if (!class_exists('\WebCareProScanner\Firewall\LearningModeEngine')) {
            return new \WP_Error('missing_engine', __('LearningModeEngine not available.', 'webcare-pro-security'), ['status' => 500]);
        }
        $updated = \WebCareProScanner\Firewall\LearningModeEngine::update_settings($params);
        return rest_ensure_response([
            'success'  => true,
            'settings' => $updated,
            'message'  => __('Learning Mode 2.0 settings updated successfully.', 'webcare-pro-security'),
        ]);
    }

    public static function update_honeytoken_settings(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        if (!class_exists('\WebCareProScanner\Firewall\HoneyTokenEngine')) {
            return new \WP_Error('missing_engine', __('HoneyTokenEngine not available.', 'webcare-pro-security'), ['status' => 500]);
        }
        $updated = \WebCareProScanner\Firewall\HoneyTokenEngine::update_settings($params);
        return rest_ensure_response([
            'success'  => true,
            'settings' => $updated,
            'message'  => __('Honey-Token Bot Trap settings updated successfully.', 'webcare-pro-security'),
        ]);
    }

    public static function unban_honeytoken_ip(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $ip = sanitize_text_field($params['ip'] ?? '');
        if (empty($ip)) {
            return new \WP_Error('missing_ip', __('IP address is required.', 'webcare-pro-security'), ['status' => 400]);
        }
        if (!class_exists('\WebCareProScanner\Firewall\HoneyTokenEngine')) {
            return new \WP_Error('missing_engine', __('HoneyTokenEngine not available.', 'webcare-pro-security'), ['status' => 500]);
        }
        $result = \WebCareProScanner\Firewall\HoneyTokenEngine::unban_bot_ip($ip);
        return rest_ensure_response($result);
    }

    public static function reseed_db_canaries(\WP_REST_Request $request) {
        if (!class_exists('\WebCareProScanner\Firewall\HoneyTokenEngine')) {
            return new \WP_Error('missing_engine', __('HoneyTokenEngine not available.', 'webcare-pro-security'), ['status' => 500]);
        }
        $result = \WebCareProScanner\Firewall\HoneyTokenEngine::reseed_db_canaries();
        return rest_ensure_response($result);
    }

    public static function update_rate_limiter_settings(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        if (!class_exists('\WebCareProScanner\Firewall\AdaptiveRateLimiter')) {
            return new \WP_Error('missing_engine', __('AdaptiveRateLimiter not available.', 'webcare-pro-security'), ['status' => 500]);
        }
        $updated = \WebCareProScanner\Firewall\AdaptiveRateLimiter::update_settings($params);
        return rest_ensure_response([
            'success'  => true,
            'settings' => $updated,
            'message'  => __('Adaptive Rate Limiter thresholds updated successfully.', 'webcare-pro-security'),
        ]);
    }

    public static function get_distributed_shield_status(\WP_REST_Request $request) {
        if (!class_exists('\WebCareProScanner\Firewall\DistributedVelocityShield')) {
            return new \WP_Error('missing_module', __('DistributedVelocityShield module not found.', 'webcare-pro-security'), ['status' => 500]);
        }
        return rest_ensure_response(array_merge([
            'success' => true,
        ], \WebCareProScanner\Firewall\DistributedVelocityShield::get_telemetry()));
    }

    public static function update_distributed_shield_settings(\WP_REST_Request $request) {
        if (!class_exists('\WebCareProScanner\Firewall\DistributedVelocityShield')) {
            return new \WP_Error('missing_module', __('DistributedVelocityShield module not found.', 'webcare-pro-security'), ['status' => 500]);
        }
        $params  = $request->get_json_params() ?: [];
        $updated = \WebCareProScanner\Firewall\DistributedVelocityShield::update_settings($params);
        return rest_ensure_response([
            'success'  => true,
            'message'  => __('Distributed velocity shield settings saved successfully.', 'webcare-pro-security'),
            'settings' => $updated,
            'status'   => \WebCareProScanner\Firewall\DistributedVelocityShield::get_telemetry(),
        ]);
    }

    public static function toggle_under_attack_mode(\WP_REST_Request $request) {
        if (!class_exists('\WebCareProScanner\Firewall\DistributedVelocityShield')) {
            return new \WP_Error('missing_module', __('DistributedVelocityShield module not found.', 'webcare-pro-security'), ['status' => 500]);
        }
        $params   = $request->get_json_params() ?: [];
        $active   = !empty($params['active']);
        $duration = max(60, min(86400, intval($params['duration'] ?? 900)));
        $action   = !empty($params['action']) ? sanitize_key($params['action']) : 'pow';
        $reason   = !empty($params['reason']) ? sanitize_text_field($params['reason']) : __('Manual administrator activation', 'webcare-pro-security');

        if ($active) {
            \WebCareProScanner\Firewall\DistributedVelocityShield::activate_under_attack(
                'manual_lockdown',
                $duration,
                $action,
                'manual',
                [
                    'failures'   => 0,
                    'unique_ips' => 0,
                    'surface'    => 'admin_manual',
                    'reason'     => $reason,
                ]
            );
            $msg = __('Under-Attack Mode manually activated.', 'webcare-pro-security');
        } else {
            \WebCareProScanner\Firewall\DistributedVelocityShield::deactivate_under_attack();
            $msg = __('Under-Attack Mode deactivated.', 'webcare-pro-security');
        }

        return rest_ensure_response([
            'success'      => true,
            'message'      => $msg,
            'under_attack' => \WebCareProScanner\Firewall\DistributedVelocityShield::get_under_attack_status(),
        ]);
    }

    public static function simulate_distributed_attack(\WP_REST_Request $request) {
        if (!class_exists('\WebCareProScanner\Firewall\DistributedVelocityShield')) {
            return new \WP_Error('missing_module', __('DistributedVelocityShield module not found.', 'webcare-pro-security'), ['status' => 500]);
        }
        $params = $request->get_json_params() ?: [];
        $type   = !empty($params['type']) ? sanitize_key($params['type']) : 'carding';

        $res = \WebCareProScanner\Firewall\DistributedVelocityShield::simulate_attack_swarm($type);

        return rest_ensure_response(array_merge([
            'success' => true,
            'message' => sprintf(
                /* translators: %s: simulated swarm type */
                __('Simulated distributed %s attack generated. Check Under-Attack status.', 'webcare-pro-security'),
                esc_html($type)
            ),
        ], $res));
    }

    /**
     * Retrieve status and capabilities of the AST Taint Analysis Engine.
     */
    public static function get_taint_engine_status(\WP_REST_Request $request) {
        if (!class_exists('\WebCareProScanner\Malware\TaintAnalysisEngine')) {
            return new \WP_Error('missing_module', __('TaintAnalysisEngine module not found.', 'webcare-pro-security'), ['status' => 500]);
        }

        $engine = new \WebCareProScanner\Malware\TaintAnalysisEngine();
        return rest_ensure_response(array_merge([
            'success' => true,
        ], $engine->get_telemetry()));
    }

    /**
     * Run on-demand AST Source-to-Sink Taint Flow Analysis on PHP code or file.
     */
    public static function analyze_code_taint_flow(\WP_REST_Request $request) {
        if (!class_exists('\WebCareProScanner\Malware\TaintAnalysisEngine')) {
            return new \WP_Error('missing_module', __('TaintAnalysisEngine module not found.', 'webcare-pro-security'), ['status' => 500]);
        }

        $code = $request->get_param('code');
        $file_path = $request->get_param('file_path');

        $engine = new \WebCareProScanner\Malware\TaintAnalysisEngine();

        if (!empty($file_path)) {
            $sanitized_path = sanitize_text_field(wp_unslash($file_path));
            $finding = $engine->analyze_file($sanitized_path);
        } elseif (!empty($code)) {
            $raw_code = (string) $request->get_param('code');
            $finding = $engine->analyze_content($raw_code, 'sandbox_evaluation.php');
        } else {
            return new \WP_Error('missing_params', __('Please provide either "code" or "file_path" to analyze.', 'webcare-pro-security'), ['status' => 400]);
        }

        if ($finding !== null) {
            return rest_ensure_response([
                'success'     => true,
                'has_taint'   => true,
                'finding'     => $finding->to_array(),
                'taint_chain' => $finding->taint_chain,
                'message'     => __('Polymorphic taint flow detected into execution sink!', 'webcare-pro-security')
            ]);
        }

        return rest_ensure_response([
            'success'     => true,
            'has_taint'   => false,
            'finding'     => null,
            'taint_chain' => [],
            'message'     => __('Clean: No untrusted taint flow reached an execution sink.', 'webcare-pro-security')
        ]);
    }

    /**
     * Retrieve telemetry and status of the AI SEO & GEO Shield.
     */
    public static function get_geo_shield_status(\WP_REST_Request $request) {
        if (!class_exists('\WebCareProScanner\Content\GeoShieldService')) {
            return new \WP_Error('missing_module', __('GeoShieldService module not found.', 'webcare-pro-security'), ['status' => 500]);
        }

        return rest_ensure_response(\WebCareProScanner\Content\GeoShieldService::get_telemetry());
    }

    /**
     * Save the pristine cryptographic baseline for /llms.txt and /llms-full.txt.
     */
    public static function save_geo_llms_baseline(\WP_REST_Request $request) {
        if (!class_exists('\WebCareProScanner\Content\GeoShieldService')) {
            return new \WP_Error('missing_module', __('GeoShieldService module not found.', 'webcare-pro-security'), ['status' => 500]);
        }

        $res = \WebCareProScanner\Content\GeoShieldService::save_llms_baseline();
        return rest_ensure_response($res);
    }

    /**
     * On-demand audit of HTML or content for GEO invisible cloaking and JSON-LD poisoning.
     */
    public static function audit_geo_content(\WP_REST_Request $request) {
        if (!class_exists('\WebCareProScanner\Content\GeoShieldService')) {
            return new \WP_Error('missing_module', __('GeoShieldService module not found.', 'webcare-pro-security'), ['status' => 500]);
        }

        $raw_html = (string) $request->get_param('html');
        if (empty($raw_html)) {
            return new \WP_Error('missing_param', __('Please provide "html" content to audit.', 'webcare-pro-security'), ['status' => 400]);
        }

        $jsonld_hits = \WebCareProScanner\Content\GeoShieldService::audit_jsonld_schemas($raw_html);
        $cloak_hits  = \WebCareProScanner\Content\GeoShieldService::audit_geo_cloaking($raw_html);
        $all_hits    = array_merge($jsonld_hits, $cloak_hits);

        return rest_ensure_response([
            'success'     => true,
            'has_threats' => !empty($all_hits),
            'detections'  => $all_hits,
            'jsonld_hits' => count($jsonld_hits),
            'cloak_hits'  => count($cloak_hits),
            'message'     => !empty($all_hits)
                ? sprintf(
                    /* translators: %d: threat count */
                    __('GEO Audit: %d deceptive elements or poisoned schema attributes detected.', 'webcare-pro-security'),
                    count($all_hits)
                )
                : __('GEO Audit: Content verified clean. No cloaking or schema poisoning detected.', 'webcare-pro-security'),
        ]);
    }

    /**
     * Retrieve telemetry status for Gutenberg Interactivity API & Block Directives defense.
     */
    public static function get_block_security_status(\WP_REST_Request $request) {
        if (!class_exists('\WebCareProScanner\Content\BlockDirectiveSanitizer')) {
            return new \WP_Error('missing_module', __('BlockDirectiveSanitizer module not found.', 'webcare-pro-security'), ['status' => 500]);
        }

        return rest_ensure_response(\WebCareProScanner\Content\BlockDirectiveSanitizer::get_telemetry());
    }

    /**
     * On-demand audit or sanitization of Gutenberg block markup or HTML content.
     */
    public static function audit_block_directives(\WP_REST_Request $request) {
        if (!class_exists('\WebCareProScanner\Content\BlockDirectiveSanitizer')) {
            return new \WP_Error('missing_module', __('BlockDirectiveSanitizer module not found.', 'webcare-pro-security'), ['status' => 500]);
        }

        $content = (string) $request->get_param('content');
        if (empty($content)) {
            return new \WP_Error('missing_param', __('Please provide "content" to audit.', 'webcare-pro-security'), ['status' => 400]);
        }

        $audit_hits = \WebCareProScanner\Content\BlockDirectiveSanitizer::audit_content($content);
        $sanitized  = \WebCareProScanner\Content\BlockDirectiveSanitizer::sanitize_content($content);

        return rest_ensure_response([
            'success'           => true,
            'has_threats'       => !empty($audit_hits),
            'detections'        => $audit_hits,
            'threat_count'      => count($audit_hits),
            'sanitized_content' => $sanitized['content'],
            'is_modified'       => $sanitized['modified'],
            'message'           => !empty($audit_hits)
                ? sprintf(
                    /* translators: %d: threat count */
                    __('Block Security: %d hostile directive(s) or sensitive bindings detected.', 'webcare-pro-security'),
                    count($audit_hits)
                )
                : __('Block Security: Block directives verified clean and valid.', 'webcare-pro-security'),
        ]);
    }

    public static function get_synthesized_virtual_patches(\WP_REST_Request $request) {
        $patches = VirtualPatchSynthesizer::get_synthesized_patches();
        $settings = \WebCareProScanner\System\SettingsManager::get_settings();
        $cf_ready = !empty($settings['cloudflare_api_token']) && !empty($settings['cloudflare_zone_id']);

        return rest_ensure_response([
            'success'          => true,
            'patches'          => array_values($patches),
            'total'            => count($patches),
            'cloudflare_ready' => $cf_ready,
        ]);
    }

    public static function synthesize_virtual_patch(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $result = VirtualPatchSynthesizer::synthesize_patch($params);

        if (!$result['success']) {
            return new \WP_Error('synthesis_failed', $result['message'], ['status' => 400]);
        }

        return rest_ensure_response($result);
    }

    public static function test_virtual_patch_simulation(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $patch = $params['patch'] ?? [];
        $custom_payloads = $params['custom_payloads'] ?? null;

        if (empty($patch) || empty($patch['php_rule']['regex'])) {
            return new \WP_Error('missing_patch_rule', __('Virtual patch definition and regex pattern are required for simulation.', 'webcare-pro-security'), ['status' => 400]);
        }

        $simulation = VirtualPatchSynthesizer::run_dryrun_simulation($patch, $custom_payloads);
        return rest_ensure_response([
            'success'    => true,
            'simulation' => $simulation,
        ]);
    }

    public static function deploy_synthesized_virtual_patch(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $patch = $params['patch'] ?? [];
        $deploy_cf = !empty($params['deploy_to_cloudflare']);

        if (empty($patch['patch_id'])) {
            return new \WP_Error('missing_patch_id', __('Valid patch definition with patch_id is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $result = VirtualPatchSynthesizer::save_synthesized_patch($patch, $deploy_cf);
        return rest_ensure_response($result);
    }

    public static function toggle_synthesized_virtual_patch(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $patch_id = sanitize_text_field($params['patch_id'] ?? '');
        $enable = !empty($params['enable']);

        if (empty($patch_id)) {
            return new \WP_Error('missing_patch_id', __('Patch ID is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $result = VirtualPatchSynthesizer::toggle_synthesized_patch($patch_id, $enable);
        return rest_ensure_response($result);
    }

    public static function delete_synthesized_virtual_patch(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $patch_id = sanitize_text_field($params['patch_id'] ?? '');

        if (empty($patch_id)) {
            return new \WP_Error('missing_patch_id', __('Patch ID is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $result = VirtualPatchSynthesizer::delete_synthesized_patch($patch_id);
        return rest_ensure_response($result);
    }

    public static function virtual_patch_cve_lookup(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $cve_id = sanitize_text_field(wp_unslash($params['cve_id'] ?? ''));

        if (empty($cve_id)) {
            return new \WP_Error('missing_cve_id', __('CVE ID is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $result = \WebCareProScanner\Firewall\CVEIntelligenceService::lookup_and_correlate($cve_id);
        if (!$result['success']) {
            return new \WP_Error('cve_lookup_failed', $result['message'], ['status' => 404]);
        }

        return rest_ensure_response($result);
    }

    public static function virtual_patch_deactivate_component(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $plugin_file = sanitize_text_field(wp_unslash($params['plugin_file'] ?? ''));

        if (empty($plugin_file)) {
            return new \WP_Error('missing_plugin_file', __('Target plugin file is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $result = \WebCareProScanner\Firewall\CVEIntelligenceService::deactivate_vulnerable_plugin($plugin_file);
        if (!$result['success']) {
            return new \WP_Error('deactivation_failed', $result['message'], ['status' => 400]);
        }

        return rest_ensure_response($result);
    }

    public static function get_ai_defense_status() {
        return rest_ensure_response([
            'success'        => true,
            'ghost_routes'   => \WebCareProScanner\Firewall\GhostRouteTrap::get_status(),
            'egress'         => \WebCareProScanner\Firewall\OutboundEgressFirewall::get_status(),
            'prompt_guard'   => \WebCareProScanner\Security\PromptInjectionGuard::get_status(),
            'credentials'    => \WebCareProScanner\Security\CredentialExposureScanner::get_status(),
            'attack_surface' => \WebCareProScanner\WordPress\RestApiInventory::get_inventory(),
        ]);
    }

    public static function get_ghost_routes_status() {
        return rest_ensure_response(array_merge([
            'success' => true,
        ], \WebCareProScanner\Firewall\GhostRouteTrap::get_status()));
    }

    public static function update_ghost_routes_settings(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $res = \WebCareProScanner\Firewall\GhostRouteTrap::update_settings($params);
        return rest_ensure_response([
            'success' => $res,
            'message' => __('Ghost route trap settings updated.', 'webcare-pro-security'),
            'status'  => \WebCareProScanner\Firewall\GhostRouteTrap::get_status(),
        ]);
    }

    public static function get_egress_firewall_status() {
        return rest_ensure_response(array_merge([
            'success' => true,
        ], \WebCareProScanner\Firewall\OutboundEgressFirewall::get_status()));
    }

    public static function update_egress_firewall_settings(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $res = \WebCareProScanner\Firewall\OutboundEgressFirewall::update_settings($params);
        return rest_ensure_response([
            'success' => $res,
            'message' => __('Outbound egress firewall settings updated.', 'webcare-pro-security'),
            'status'  => \WebCareProScanner\Firewall\OutboundEgressFirewall::get_status(),
        ]);
    }

    public static function get_credential_exposure_status() {
        return rest_ensure_response(array_merge([
            'success' => true,
        ], \WebCareProScanner\Security\CredentialExposureScanner::get_status()));
    }

    public static function scan_credential_exposure() {
        $report = \WebCareProScanner\Security\CredentialExposureScanner::run_scan(true);
        return rest_ensure_response(array_merge([
            'success' => true,
        ], $report));
    }

    public static function get_prompt_guard_status() {
        return rest_ensure_response(array_merge([
            'success' => true,
        ], \WebCareProScanner\Security\PromptInjectionGuard::get_status()));
    }

    public static function update_prompt_guard_settings(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $res = \WebCareProScanner\Security\PromptInjectionGuard::update_settings($params);
        return rest_ensure_response([
            'success' => $res,
            'message' => __('Prompt injection guard settings updated.', 'webcare-pro-security'),
            'status'  => \WebCareProScanner\Security\PromptInjectionGuard::get_status(),
        ]);
    }

    public static function test_prompt_injection(\WP_REST_Request $request) {
        $params  = $request->get_json_params() ?: [];
        $text    = !empty($params['text']) ? (string) $params['text'] : '';
        $context = !empty($params['context']) ? sanitize_key($params['context']) : 'generic';

        if (trim($text) === '') {
            return new \WP_REST_Response([
                'success' => false,
                'message' => __('Prompt text is required for analysis.', 'webcare-pro-security'),
            ], 400);
        }

        $analysis = \WebCareProScanner\Security\PromptInjectionGuard::inspect_prompt($text, $context);

        return rest_ensure_response([
            'success'  => true,
            'analysis' => $analysis,
        ]);
    }

    public static function get_attack_surface_inventory() {
        return rest_ensure_response(array_merge([
            'success' => true,
        ], \WebCareProScanner\WordPress\RestApiInventory::get_inventory()));
    }

    public static function update_attack_surface_settings(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $res = \WebCareProScanner\WordPress\RestApiInventory::update_settings($params);
        return rest_ensure_response([
            'success' => $res,
            'message' => __('Attack surface defense settings updated.', 'webcare-pro-security'),
            'data'    => \WebCareProScanner\WordPress\RestApiInventory::get_inventory(),
        ]);
    }

    /**
     * Export complete REST API & wp_ajax_nopriv attack surface inventory, PHP Reflection handler provenance,
     * deduplicated cryptographic file hash index, active shields, and correlated WAF incident logs as JSON.
     *
     * @param \WP_REST_Request $request
     * @return \WP_REST_Response|void
     */
    public static function export_attack_surface_bundle(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\WordPress\\RestApiInventory')) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => __('REST API & AJAX Attack Surface inventory engine is unavailable.', 'webcare-pro-security'),
            ], 500);
        }

        $inventory = \WebCareProScanner\WordPress\RestApiInventory::get_inventory(true);
        $routes    = is_array($inventory['routes'] ?? null) ? $inventory['routes'] : [];
        $ajax_list = is_array($inventory['ajax_nopriv'] ?? null) ? $inventory['ajax_nopriv'] : [];

        // 1. Build deduplicated cryptographic file hash index across REST & AJAX handler files
        $handler_file_index = [];
        $index_handler_file = static function (array $handler, string $kind) use (&$handler_file_index) {
            $rel = isset($handler['file']) ? (string) $handler['file'] : '';
            if ($rel === '') {
                return;
            }
            if (!isset($handler_file_index[$rel])) {
                $handler_file_index[$rel] = [
                    'file'            => $rel,
                    'owner_component' => $handler['owner_component'] ?? 'Unknown',
                    'owner_type'      => $handler['owner_type'] ?? 'unknown',
                    'origin_type'     => $handler['origin_type'] ?? 'custom_unmanaged',
                    'vendor_name'     => $handler['vendor_name'] ?? null,
                    'is_official'     => !empty($handler['is_official']),
                    'is_known_vendor' => !empty($handler['is_known_vendor']),
                    'checksum_status' => $handler['checksum_status'] ?? 'not_available',
                    'file_sha256'     => $handler['file_sha256'] ?? null,
                    'file_md5'        => $handler['file_md5'] ?? null,
                    'rest_routes_cnt' => 0,
                    'ajax_hooks_cnt'  => 0,
                ];
                if (!empty($handler['known_vendor_lib'])) {
                    $handler_file_index[$rel]['known_vendor_lib'] = $handler['known_vendor_lib'];
                }
            }
            if ($kind === 'rest') {
                $handler_file_index[$rel]['rest_routes_cnt']++;
            } else {
                $handler_file_index[$rel]['ajax_hooks_cnt']++;
            }
        };

        foreach ($routes as $r) {
            if (!empty($r['handler']) && is_array($r['handler'])) {
                $index_handler_file($r['handler'], 'rest');
            }
        }
        foreach ($ajax_list as $ax) {
            if (!empty($ax['handler']) && is_array($ax['handler'])) {
                $index_handler_file($ax['handler'], 'ajax');
            }
        }

        // 2. Collect WAF logs & cross-reference hits against registered REST routes and nopriv AJAX actions
        $log_ctx          = self::build_modular_log_analysis_context();
        $all_log_records  = is_array($log_ctx['recent_log_records'] ?? null) ? $log_ctx['recent_log_records'] : [];
        $surface_logs     = [];
        $hits_by_route    = [];
        $hits_by_ajax_act = [];

        foreach ($all_log_records as $rec) {
            $uri     = (string) ($rec['request_uri'] ?? '');
            $payload = (string) ($rec['payload_sample'] ?? '');
            $rid     = (string) ($rec['rule_id'] ?? '');
            $is_rest = str_contains($uri, '/wp-json/') || str_contains($uri, 'rest_route=');
            $is_ajax = str_contains($uri, 'admin-ajax.php');
            $is_mod  = str_starts_with($rid, 'MOD-REST-') || str_starts_with($rid, 'MOD-AJAX-');

            if (!$is_rest && !$is_ajax && !$is_mod) {
                continue;
            }

            $surface_logs[] = $rec;

            if ($is_rest) {
                $matched_route = '';
                $parsed_q = wp_parse_url($uri, PHP_URL_QUERY);
                $q_params = [];
                if (is_string($parsed_q) && $parsed_q !== '') {
                    parse_str($parsed_q, $q_params);
                }
                if (!empty($q_params['rest_route']) && is_string($q_params['rest_route'])) {
                    $matched_route = '/' . ltrim($q_params['rest_route'], '/');
                } else {
                    $parsed_path = (string) (wp_parse_url($uri, PHP_URL_PATH) ?: '');
                    $pos         = strpos($parsed_path, '/wp-json');
                    if ($pos !== false) {
                        $matched_route = '/' . ltrim(substr($parsed_path, $pos + strlen('/wp-json')), '/');
                    }
                }
                if ($matched_route !== '') {
                    $rkey = strtolower(rtrim($matched_route, '/') ?: '/');
                    if (!isset($hits_by_route[$rkey])) {
                        $hits_by_route[$rkey] = [
                            'route_sample'  => $matched_route,
                            'hits'          => 0,
                            'actions_taken' => [],
                            'rule_ids'      => [],
                            'last_seen'     => $rec['created_at'] ?? '',
                        ];
                    }
                    $hits_by_route[$rkey]['hits']++;
                    if (!empty($rec['action_taken']) && !in_array($rec['action_taken'], $hits_by_route[$rkey]['actions_taken'], true)) {
                        $hits_by_route[$rkey]['actions_taken'][] = $rec['action_taken'];
                    }
                    if ($rid !== '' && !in_array($rid, $hits_by_route[$rkey]['rule_ids'], true)) {
                        $hits_by_route[$rkey]['rule_ids'][] = $rid;
                    }
                }
            }

            if ($is_ajax) {
                $ajax_act = '';
                $parsed_q = wp_parse_url($uri, PHP_URL_QUERY);
                $q_params = [];
                if (is_string($parsed_q) && $parsed_q !== '') {
                    parse_str($parsed_q, $q_params);
                }
                if (!empty($q_params['action']) && is_string($q_params['action'])) {
                    $ajax_act = sanitize_key($q_params['action']);
                } elseif (preg_match('/(?:^|[&\s,;=\'"(])action\s*[:=]\s*[\'"]?([a-zA-Z0-9_-]+)/', $payload, $m)) {
                    $ajax_act = sanitize_key($m[1]);
                }
                if ($ajax_act !== '') {
                    $akey = strtolower($ajax_act);
                    if (!isset($hits_by_ajax_act[$akey])) {
                        $hits_by_ajax_act[$akey] = [
                            'action'        => $ajax_act,
                            'hits'          => 0,
                            'actions_taken' => [],
                            'rule_ids'      => [],
                            'last_seen'     => $rec['created_at'] ?? '',
                        ];
                    }
                    $hits_by_ajax_act[$akey]['hits']++;
                    if (!empty($rec['action_taken']) && !in_array($rec['action_taken'], $hits_by_ajax_act[$akey]['actions_taken'], true)) {
                        $hits_by_ajax_act[$akey]['actions_taken'][] = $rec['action_taken'];
                    }
                    if ($rid !== '' && !in_array($rid, $hits_by_ajax_act[$akey]['rule_ids'], true)) {
                        $hits_by_ajax_act[$akey]['rule_ids'][] = $rid;
                    }
                }
            }
        }

        // Annotate route & AJAX items with matching log telemetry counts
        foreach ($routes as &$rt) {
            $rkey = strtolower(rtrim((string) ($rt['route'] ?? ''), '/') ?: '/');
            if (isset($hits_by_route[$rkey])) {
                $rt['recent_waf_hits'] = $hits_by_route[$rkey];
            }
        }
        unset($rt);

        foreach ($ajax_list as &$ax) {
            $akey = strtolower((string) ($ax['action'] ?? ''));
            if ($akey !== '' && isset($hits_by_ajax_act[$akey])) {
                $ax['recent_waf_hits'] = $hits_by_ajax_act[$akey];
            }
        }
        unset($ax);

        // 3. Gather active Modular WAF rules protecting REST / AJAX surfaces
        $active_surface_rules = [];
        if (class_exists('\\WebCareProScanner\\Firewall\\CustomRules\\ModularFirewallSynthesizer')) {
            $all_rules = \WebCareProScanner\Firewall\CustomRules\ModularFirewallSynthesizer::get_active_rules();
            foreach ($all_rules as $rule) {
                $cat = $rule['category'] ?? '';
                if ($cat === 'rest_guard' || $cat === 'ajax_shield' || str_contains((string) ($rule['target_uri'] ?? ''), 'wp-json') || str_contains((string) ($rule['target_uri'] ?? ''), 'admin-ajax.php')) {
                    $active_surface_rules[] = $rule;
                }
            }
        }

        // 4. Environment & breakdown statistics
        $origin_breakdown = [];
        $flag_stats = [
            'public_routes'               => (int) ($inventory['public_routes_count'] ?? 0),
            'discovery_index_routes'      => (int) ($inventory['discovery_index_routes_count'] ?? 0),
            'storefront_guarded_routes'   => (int) ($inventory['storefront_guarded_routes_count'] ?? 0),
            'unauth_write_routes'         => (int) ($inventory['unauth_post_routes'] ?? 0),
            'mixed_auth_protected_routes' => (int) ($inventory['mixed_auth_protected_routes'] ?? 0),
            'locked_routes'               => 0,
            'shielded_routes'             => 0,
            'unguarded_nopriv_ajax'       => (int) ($inventory['unguarded_nopriv_ajax_count'] ?? 0),
            'protected_nopriv_ajax'       => (int) ($inventory['protected_nopriv_ajax_count'] ?? 0),
            'shielded_ajax_nopriv'        => 0,
        ];
        foreach ($routes as $rt) {
            if (!empty($rt['is_locked'])) {
                $flag_stats['locked_routes']++;
            }
            if (!empty($rt['shielded_by'])) {
                $flag_stats['shielded_routes']++;
            }
            $orig = $rt['handler']['origin_type'] ?? 'unknown';
            $origin_breakdown[$orig] = ($origin_breakdown[$orig] ?? 0) + 1;
        }
        foreach ($ajax_list as $ax) {
            if (!empty($ax['shielded_by'])) {
                $flag_stats['shielded_ajax_nopriv']++;
            }
        }

        $active_theme   = wp_get_theme();
        $site_host      = wp_parse_url(get_site_url(), PHP_URL_HOST) ?: 'localhost';
        $preload_active = defined('WEBCAREPRO_PRELOAD_WAF_ACTIVE') && WEBCAREPRO_PRELOAD_WAF_ACTIVE;

        $payload = [
            'success'               => true,
            'webcare_export_type'   => 'attack_surface_forensic_bundle',
            'format_version'        => defined('WEBCAREPROSCAN_VERSION') ? WEBCAREPROSCAN_VERSION : '2.11.0',
            'exported_at'           => gmdate('c'),
            'exported_timestamp'    => time(),
            'author'                => 'Mir Alamin (WebCare Pro)',
            'environment'           => [
                'site_url'           => get_site_url(),
                'home_url'           => get_home_url(),
                'wordpress_version'  => $GLOBALS['wp_version'] ?? 'Unknown',
                'php_version'        => PHP_VERSION,
                'server_software'    => isset($_SERVER['SERVER_SOFTWARE']) ? sanitize_text_field(wp_unslash($_SERVER['SERVER_SOFTWARE'])) : 'Unknown',
                'webcare_version'    => defined('WEBCAREPROSCAN_VERSION') ? WEBCAREPROSCAN_VERSION : '2.11.0',
                'preload_waf_active' => $preload_active,
                'active_theme'       => [
                    'name'       => $active_theme ? $active_theme->get('Name') : '',
                    'version'    => $active_theme ? $active_theme->get('Version') : '',
                    'template'   => $active_theme ? $active_theme->get_template() : '',
                    'stylesheet' => $active_theme ? $active_theme->get_stylesheet() : '',
                ],
            ],
            'summary'               => array_merge([
                'total_routes'               => count($routes),
                'total_namespaces'           => (int) ($inventory['total_namespaces'] ?? 0),
                'total_nopriv_ajax'          => count($ajax_list),
                'unique_handler_files_hashed'=> count($handler_file_index),
                'active_surface_rules_count' => count($active_surface_rules),
                'surface_waf_events_count'   => count($surface_logs),
                'total_modular_events_30d'   => (int) ($log_ctx['total_events_analyzed'] ?? 0),
                'routes_by_origin_type'      => $origin_breakdown,
            ], $flag_stats),
            'settings'              => $inventory['settings'] ?? [],
            'namespaces'            => $inventory['namespaces'] ?? [],
            'routes'                => $routes,
            'ajax_nopriv'           => $ajax_list,
            'active_surface_rules'  => $active_surface_rules,
            'handler_file_hash_index'=> array_values($handler_file_index),
            'log_analysis_context'  => [
                'surface_events_matched'   => count($surface_logs),
                'hits_by_rest_route'       => $hits_by_route,
                'hits_by_ajax_action'      => $hits_by_ajax_act,
                'hits_by_rule'             => $log_ctx['hits_by_rule'] ?? [],
                'hits_by_action'           => $log_ctx['hits_by_action'] ?? [],
                'top_target_uris'          => $log_ctx['top_target_uris'] ?? [],
                'top_user_agents'          => $log_ctx['top_user_agents'] ?? [],
                'preboot_fail2ban_lines'   => $log_ctx['preboot_fail2ban_lines'] ?? [],
                'recent_surface_waf_logs'  => array_slice($surface_logs, 0, 200),
            ],
        ];

        $is_download = !empty($request->get_param('download'));
        if ($is_download) {
            $filename = 'webcare-attack-surface-' . sanitize_file_name($site_host) . '-' . gmdate('Y-m-d') . '.json';
            header('Content-Type: application/json; charset=utf-8');
            header('Content-Disposition: attachment; filename="' . $filename . '"');
            header('X-Content-Type-Options: nosniff');
            echo wp_json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
            exit;
        }

        return new \WP_REST_Response($payload, 200);
    }

    /**
     * Shared helper assembling enriched modular rules, component provenance/checksum dossiers,
     * and trust summary telemetry without duplicating logic across status and export routes.
     *
     * @param bool $deep_verify Whether to execute full disk & WP.org checksum verification.
     * @return array
     */
    public static function build_modular_dossier_context(bool $deep_verify = false): array {
        $vault_mgr = '\\WebCareProScanner\\Firewall\\CustomRules\\BehavioralVaultManager';
        $synth     = '\\WebCareProScanner\\Firewall\\CustomRules\\ModularFirewallSynthesizer';
        $analyzer  = '\\WebCareProScanner\\Firewall\\CustomRules\\SiteBehavioralAnalyzer';
        $verifier  = '\\WebCareProScanner\\Firewall\\CustomRules\\ComponentIntegrityVerifier';

        $vault_summary = class_exists($vault_mgr) ? $vault_mgr::get_vault_summary() : null;
        $rules         = class_exists($synth) ? $synth::get_active_rules() : [];
        $raw_inv       = class_exists($vault_mgr) ? ($vault_mgr::read_shard($vault_mgr::SHARD_INVENTORY) ?: []) : [];

        if (empty($raw_inv) && class_exists($analyzer) && method_exists($analyzer, 'discover_all_components')) {
            $raw_inv = $analyzer::discover_all_components($deep_verify);
        }

        $endpoint_map  = class_exists($vault_mgr) ? ($vault_mgr::read_shard($vault_mgr::SHARD_ENDPOINTS) ?: []) : [];
        $findings      = class_exists($vault_mgr) ? ($vault_mgr::read_shard($vault_mgr::SHARD_FINDINGS) ?: []) : [];
        $scan_progress = class_exists($analyzer) ? $analyzer::get_scan_progress() : null;

        $endpoint_counts = [];
        if (is_array($endpoint_map)) {
            foreach ($endpoint_map as $ep) {
                $comp_name = $ep['component'] ?? '';
                if ($comp_name !== '') {
                    $endpoint_counts[$comp_name] = ($endpoint_counts[$comp_name] ?? 0) + 1;
                }
            }
        }

        $finding_counts = [];
        if (is_array($findings)) {
            foreach ($findings as $fd) {
                $comp_name = $fd['component'] ?? '';
                if ($comp_name !== '') {
                    $finding_counts[$comp_name] = ($finding_counts[$comp_name] ?? 0) + 1;
                }
            }
        }

        $rules_list  = is_array($rules) ? array_values($rules) : [];
        $rule_counts = [];
        foreach ($rules_list as $rl) {
            $comp_name = $rl['origin_component'] ?? ($rl['target_component'] ?? '');
            if ($comp_name !== '' && ($rl['current_mode'] ?? 'off') !== 'off') {
                $rule_counts[$comp_name] = ($rule_counts[$comp_name] ?? 0) + 1;
            }
        }

        $inventory        = [];
        $comp_by_name     = [];
        $trust_summary    = [
            'official_wporg_count'    => 0,
            'known_vendor_count'      => 0,
            'custom_unmanaged_count'  => 0,
            'checksum_verified_count' => 0,
            'tamper_alert_count'      => 0,
            'outdated_count'          => 0,
        ];

        if (is_array($raw_inv)) {
            foreach ($raw_inv as $comp) {
                if (!is_array($comp)) {
                    continue;
                }
                // Always attach/refresh provenance & checksum status when missing or during deep verification
                if (class_exists($verifier) && ($deep_verify || !isset($comp['origin_type']))) {
                    $comp = array_merge($comp, $verifier::verify_component($comp, $deep_verify));
                }

                $name = $comp['name'] ?? ($comp['slug'] ?? '');
                $comp['endpoints_count'] = $endpoint_counts[$name] ?? 0;
                $comp['findings_count']  = $finding_counts[$name] ?? 0;
                $comp['rules_count']     = $rule_counts[$name] ?? 0;

                if (!empty($comp['is_official_wporg'])) {
                    $trust_summary['official_wporg_count']++;
                } elseif (!empty($comp['is_known_vendor'])) {
                    $trust_summary['known_vendor_count']++;
                } else {
                    $trust_summary['custom_unmanaged_count']++;
                }

                if (!empty($comp['checksum_verified'])) {
                    $trust_summary['checksum_verified_count']++;
                }
                if (($comp['trust_tier'] ?? '') === 'tamper_alert') {
                    $trust_summary['tamper_alert_count']++;
                }
                if (!empty($comp['update_available'])) {
                    $trust_summary['outdated_count']++;
                }

                $inventory[] = $comp;
                if ($name !== '') {
                    $comp_by_name[$name] = $comp;
                }
            }
        }

        // Enrich rules that are missing provenance/hash metadata (e.g. from pre-upgrade scans or custom rules)
        $findings_by_file = [];
        if (is_array($findings)) {
            foreach ($findings as $idx => $fd) {
                if (!empty($fd['file'])) {
                    $findings_by_file[$fd['file']] = $fd;
                }
            }
        }

        foreach ($rules_list as &$rl) {
            if (!isset($rl['file_sha256']) || !isset($rl['checksum_status']) || $deep_verify) {
                $matched_finding = !empty($rl['file']) ? ($findings_by_file[$rl['file']] ?? []) : [];
                if (class_exists($synth) && method_exists($synth, 'enrich_synthesized_rule')) {
                    $rl = $synth::enrich_synthesized_rule($rl, $matched_finding, $comp_by_name);
                }
            }
        }
        unset($rl);

        return [
            'vault_summary' => $vault_summary,
            'rules'         => $rules_list,
            'inventory'     => $inventory,
            'comp_by_name'  => $comp_by_name,
            'trust_summary' => $trust_summary,
            'endpoint_map'  => is_array($endpoint_map) ? array_values($endpoint_map) : [],
            'findings'      => is_array($findings) ? array_values($findings) : [],
            'scan_progress' => $scan_progress,
        ];
    }

    /**
     * Build a deduplicated cryptographic hash index for all PHP files referenced by rules and findings.
     */
    public static function build_file_hash_index(array $rules, array $findings): array {
        $verifier = '\\WebCareProScanner\\Firewall\\CustomRules\\ComponentIntegrityVerifier';
        $index    = [];

        foreach ($findings as $fd) {
            $rel = $fd['file'] ?? '';
            if ($rel === '') {
                continue;
            }
            if (!isset($index[$rel])) {
                $forensics = (!empty($fd['file_sha256']) && !empty($fd['file_md5']))
                    ? [
                        'file_sha256'       => $fd['file_sha256'],
                        'file_md5'          => $fd['file_md5'],
                        'file_size'         => $fd['file_size'] ?? 0,
                        'file_mtime'        => $fd['file_mtime'] ?? null,
                        'checksum_status'   => $fd['checksum_status'] ?? 'unmanaged_custom',
                        'expected_checksum' => $fd['expected_checksum'] ?? null,
                        'known_vendor_lib'  => $fd['known_vendor_lib'] ?? null,
                    ]
                    : (class_exists($verifier) ? $verifier::verify_file_forensics($rel) : []);

                $index[$rel] = array_merge([
                    'file'                => $rel,
                    'component'           => $fd['component'] ?? '',
                    'origin_type'         => $fd['origin_type'] ?? 'custom_unmanaged',
                    'finding_types'       => [],
                    'referenced_by_rules' => [],
                ], $forensics);
            }
            if (!empty($fd['type']) && !in_array($fd['type'], $index[$rel]['finding_types'], true)) {
                $index[$rel]['finding_types'][] = $fd['type'];
            }
        }

        foreach ($rules as $rl) {
            $rel = $rl['file'] ?? '';
            if ($rel === '') {
                continue;
            }
            if (!isset($index[$rel])) {
                $forensics = class_exists($verifier) ? $verifier::verify_file_forensics($rel) : [];
                $index[$rel] = array_merge([
                    'file'                => $rel,
                    'component'           => $rl['origin_component'] ?? '',
                    'origin_type'         => $rl['component_origin_type'] ?? 'custom_unmanaged',
                    'finding_types'       => [],
                    'referenced_by_rules' => [],
                ], $forensics);
            }
            if (!empty($rl['id']) && !in_array($rl['id'], $index[$rel]['referenced_by_rules'], true)) {
                $index[$rel]['referenced_by_rules'][] = $rl['id'];
            }
        }

        return $index;
    }

    /**
     * Collect firewall & pre-boot log correlation telemetry for false-positive analysis.
     * Pseudonymizes client IPs via keyed SHA-256 prefix so exported dossiers stay privacy-safe.
     */
    public static function build_modular_log_analysis_context(): array {
        global $wpdb;

        $salt        = function_exists('wp_salt') ? wp_salt('auth') : 'webcare_log_salt';
        $hash_ip     = static fn(string $ip): string => $ip !== '' ? substr(hash('sha256', $salt . $ip), 0, 12) : '';
        $records     = [];
        $seen_ids    = [];
        $hits_by_rule = [];
        $hits_by_uri  = [];
        $hits_by_act  = [];
        $top_uas      = [];

        $record_event = static function (array $row) use (&$records, &$seen_ids, &$hits_by_rule, &$hits_by_uri, &$hits_by_act, &$top_uas) {
            $dedup_key = ($row['incident_id'] ?? '') . '|' . ($row['created_at'] ?? '') . '|' . ($row['request_uri'] ?? '');
            if (isset($seen_ids[$dedup_key])) {
                return;
            }
            $seen_ids[$dedup_key] = true;
            $records[] = $row;

            $rid = $row['rule_id'] ?: ($row['rule_category'] ?: 'UNKNOWN');
            if (!isset($hits_by_rule[$rid])) {
                $hits_by_rule[$rid] = [
                    'count'          => 0,
                    'last_seen'      => $row['created_at'] ?? '',
                    'sample_uris'    => [],
                    'methods'        => [],
                    'actions'        => [],
                ];
            }
            $hits_by_rule[$rid]['count']++;
            $uri_clean = strtok((string) ($row['request_uri'] ?? '/'), '?') ?: '/';
            if (count($hits_by_rule[$rid]['sample_uris']) < 5 && !in_array($row['request_uri'] ?? '', $hits_by_rule[$rid]['sample_uris'], true)) {
                $hits_by_rule[$rid]['sample_uris'][] = $row['request_uri'] ?? '';
            }
            if (!empty($row['request_method']) && !in_array($row['request_method'], $hits_by_rule[$rid]['methods'], true)) {
                $hits_by_rule[$rid]['methods'][] = $row['request_method'];
            }
            if (!empty($row['action_taken']) && !in_array($row['action_taken'], $hits_by_rule[$rid]['actions'], true)) {
                $hits_by_rule[$rid]['actions'][] = $row['action_taken'];
            }

            $hits_by_uri[$uri_clean] = ($hits_by_uri[$uri_clean] ?? 0) + 1;
            $act = $row['action_taken'] ?? 'unknown';
            $hits_by_act[$act] = ($hits_by_act[$act] ?? 0) + 1;
            if (!empty($row['user_agent'])) {
                $ua = substr((string) $row['user_agent'], 0, 120);
                $top_uas[$ua] = ($top_uas[$ua] ?? 0) + 1;
            }
        };

        // 1. Query JSON WafFileLogger (last 30 days, modular & endpoint-relevant incidents)
        if (class_exists('\\WebCareProScanner\\Firewall\\WafFileLogger')) {
            $json_res = \WebCareProScanner\Firewall\WafFileLogger::query_logs(['range' => '30d'], 150, 0);
            $items    = is_array($json_res['logs'] ?? null) ? $json_res['logs'] : [];
            foreach ($items as $item) {
                $rid   = (string) ($item['rule_id'] ?? '');
                $rcat  = (string) ($item['rule_category'] ?? '');
                $rdesc = (string) ($item['rule_description'] ?? '');
                $ruri  = (string) ($item['request_uri'] ?? '');
                $is_relevant = str_starts_with($rid, 'MOD-')
                    || stripos($rcat, 'modular') !== false
                    || str_contains($rdesc, 'MOD-')
                    || str_contains($ruri, 'admin-ajax.php')
                    || str_contains($ruri, '/wp-json/');

                if ($is_relevant) {
                    $record_event([
                        'source'           => 'waf_file_logger',
                        'incident_id'      => $item['incident_id'] ?? ($item['id'] ?? ''),
                        'ip_hash'          => $hash_ip((string) ($item['ip_address'] ?? '')),
                        'rule_id'          => $rid,
                        'rule_name'        => $item['rule_name'] ?? '',
                        'rule_category'    => $rcat,
                        'rule_description' => $rdesc,
                        'request_method'   => $item['request_method'] ?? 'GET',
                        'request_uri'      => $ruri,
                        'http_status_code' => $item['http_status_code'] ?? 403,
                        'http_referer'     => $item['http_referer'] ?? null,
                        'payload_sample'   => $item['payload_sample'] ?? '',
                        'user_agent'       => $item['user_agent'] ?? '',
                        'action_taken'     => $item['action_taken'] ?? '',
                        'is_authenticated' => !empty($item['is_authenticated']),
                        'user_role'        => $item['user_role'] ?? '',
                        'created_at'       => $item['created_at_gmt'] ?? ($item['created_at'] ?? ''),
                    ]);
                }
            }
        }

        // 2. Query SQL webcareproscan_firewall_logs table for modular & endpoint events
        $firewall_logs_table = $wpdb->prefix . 'webcareproscan_firewall_logs';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $table_exists = $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($firewall_logs_table)));
        if ($table_exists === $firewall_logs_table) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $rows = $wpdb->get_results(
                $wpdb->prepare(
                    'SELECT id, incident_id, ip_address, request_uri, request_method, http_status_code, http_referer, rule_category, rule_description, payload_sample, user_agent, action_taken, created_at
                     FROM %i
                     WHERE rule_category = %s OR rule_description LIKE %s OR request_uri LIKE %s OR request_uri LIKE %s
                     ORDER BY id DESC
                     LIMIT 100',
                    $firewall_logs_table,
                    'Modular Behavioral WAF',
                    '%MOD-%',
                    '%admin-ajax.php%',
                    '%/wp-json/%'
                ),
                ARRAY_A
            );
            if (is_array($rows)) {
                foreach ($rows as $r) {
                    $extracted_id = '';
                    if (preg_match('/\[(MOD-[A-Z0-9-]+)\]/', (string) ($r['rule_description'] ?? ''), $m)) {
                        $extracted_id = $m[1];
                    }
                    $record_event([
                        'source'           => 'sql_firewall_logs',
                        'incident_id'      => $r['incident_id'] ?? ('sql_' . $r['id']),
                        'ip_hash'          => $hash_ip((string) ($r['ip_address'] ?? '')),
                        'rule_id'          => $extracted_id,
                        'rule_name'        => '',
                        'rule_category'    => $r['rule_category'] ?? '',
                        'rule_description' => $r['rule_description'] ?? '',
                        'request_method'   => $r['request_method'] ?? 'GET',
                        'request_uri'      => $r['request_uri'] ?? '',
                        'http_status_code' => intval($r['http_status_code'] ?? 403),
                        'http_referer'     => $r['http_referer'] ?? null,
                        'payload_sample'   => $r['payload_sample'] ?? '',
                        'user_agent'       => $r['user_agent'] ?? '',
                        'action_taken'     => $r['action_taken'] ?? '',
                        'is_authenticated' => false,
                        'user_role'        => '',
                        'created_at'       => $r['created_at'] ?? '',
                    ]);
                }
            }
        }

        // 3. Parse Pre-Boot Micro-WAF Fail2ban log tail for MOD-* events (masking raw IPs)
        $preboot_mod_lines = [];
        if (class_exists('\\WebCareProScanner\\Firewall\\MicroWafCompiler')) {
            $f2b_path = \WebCareProScanner\Firewall\MicroWafCompiler::get_fail2ban_log_path();
            if ($f2b_path && file_exists($f2b_path) && is_readable($f2b_path)) {
                $lines = @file($f2b_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                if (is_array($lines)) {
                    $tail = array_slice($lines, -200);
                    foreach (array_reverse($tail) as $line) {
                        if (str_contains($line, 'MOD-')) {
                            $masked = preg_replace_callback('/\b(?:\d{1,3}\.){3}\d{1,3}\b|[0-9a-fA-F:]{6,39}/', static function ($m) use ($hash_ip) {
                                return 'iphash:' . $hash_ip($m[0]);
                            }, $line);
                            $preboot_mod_lines[] = $masked;
                            if (count($preboot_mod_lines) >= 50) {
                                break;
                            }
                        }
                    }
                }
            }
        }

        arsort($hits_by_uri);
        arsort($top_uas);

        return [
            'total_events_analyzed' => count($records),
            'hits_by_rule'          => $hits_by_rule,
            'hits_by_action'        => $hits_by_act,
            'top_target_uris'       => array_slice($hits_by_uri, 0, 30, true),
            'top_user_agents'       => array_slice($top_uas, 0, 15, true),
            'preboot_fail2ban_lines'=> $preboot_mod_lines,
            'recent_log_records'    => array_slice($records, 0, 200),
        ];
    }

    public static function get_nist_cve_status(\WP_REST_Request $request) {
        return rest_ensure_response([
            'success' => true,
            'status'  => \WebCareProScanner\Firewall\NistCveVaultSync::get_status(),
        ]);
    }

    public static function start_nist_cve_sync(\WP_REST_Request $request) {
        $status = \WebCareProScanner\Firewall\NistCveVaultSync::start_background_sync();
        return rest_ensure_response([
            'success' => true,
            'message' => __('Background NIST NVD CVE sync started.', 'webcare-pro-security'),
            'status'  => $status,
        ]);
    }

    public static function fetch_nist_cve_component(\WP_REST_Request $request) {
        $params  = $request->get_json_params() ?: [];
        $slug    = sanitize_text_field((string) ($params['slug'] ?? ''));
        $name    = sanitize_text_field((string) ($params['name'] ?? $slug));
        $version = sanitize_text_field((string) ($params['version'] ?? '0.0.0'));
        if ($slug === '') {
            return new \WP_Error('missing_slug', __('Component slug is required.', 'webcare-pro-security'), ['status' => 400]);
        }
        return rest_ensure_response(\WebCareProScanner\Firewall\NistCveVaultSync::fetch_single_component($slug, $name, $version));
    }

    public static function save_nist_api_key(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $key    = (string) ($params['api_key'] ?? '');
        $ok     = \WebCareProScanner\Firewall\NistCveVaultSync::save_api_key($key);
        return rest_ensure_response([
            'success' => $ok,
            'status'  => \WebCareProScanner\Firewall\NistCveVaultSync::get_status(),
        ]);
    }
}
