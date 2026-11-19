<?php
declare(strict_types=1);

namespace WebCareProScanner\Api\Controllers;

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
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'virtual_patch_list'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/virtual-patch/apply', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'virtual_patch_apply'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/virtual-patch/remove', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'virtual_patch_remove'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/behavioral/status', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_behavioral_waf_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/behavioral/route-status', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'set_behavioral_route_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/behavioral/learning-settings', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'update_behavioral_learning_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/behavioral/honeytoken/settings', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'update_honeytoken_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/behavioral/honeytoken/unban', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'unban_honeytoken_ip'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/behavioral/honeytoken/reseed-db-canaries', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'reseed_db_canaries'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/behavioral/rate-limiter/settings', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'update_rate_limiter_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/distributed-shield/status', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_distributed_shield_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/distributed-shield/settings', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'update_distributed_shield_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/distributed-shield/toggle-under-attack', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'toggle_under_attack_mode'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/distributed-shield/simulate', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'simulate_distributed_attack'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/taint-engine/status', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_taint_engine_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/taint-engine/analyze', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'analyze_code_taint_flow'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/geo-shield/status', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_geo_shield_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/geo-shield/save-baseline', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'save_geo_llms_baseline'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/geo-shield/audit-content', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'audit_geo_content'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/block-security/status', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_block_security_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/block-security/audit', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'audit_block_directives'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/virtual-patch/synthesized', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_synthesized_virtual_patches'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/virtual-patch/synthesize', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'synthesize_virtual_patch'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/virtual-patch/test-simulation', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'test_virtual_patch_simulation'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/virtual-patch/deploy-synthesized', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'deploy_synthesized_virtual_patch'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/virtual-patch/toggle-synthesized', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'toggle_synthesized_virtual_patch'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/virtual-patch/delete-synthesized', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'delete_synthesized_virtual_patch'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/virtual-patch/cve-lookup', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'virtual_patch_cve_lookup'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/virtual-patch/deactivate-component', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'virtual_patch_deactivate_component'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/ai-status', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_ai_defense_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/ghost-routes', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_ghost_routes_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/ghost-routes/settings', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'update_ghost_routes_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/egress', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_egress_firewall_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/egress/settings', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'update_egress_firewall_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/credentials', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_credential_exposure_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/credentials/scan', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'scan_credential_exposure'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/prompt-guard', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_prompt_guard_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/prompt-guard/settings', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'update_prompt_guard_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/prompt-guard/test', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'test_prompt_injection'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/attack-surface', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_attack_surface_inventory'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/attack-surface/settings', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'update_attack_surface_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/defense/attack-surface/export', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'export_attack_surface_bundle'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/modular-waf/scan/start', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'start_modular_scan'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/modular-waf/scan/batch', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'process_modular_scan_batch'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/modular-waf/scan/pause', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'pause_modular_scan'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/modular-waf/scan/resume', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'resume_modular_scan'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/modular-waf/scan/cancel', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'cancel_modular_scan'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/modular-waf/status', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_modular_waf_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/modular-waf/rule/toggle', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'toggle_modular_rule'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/modular-waf/rule/bulk-apply', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'bulk_apply_modular_rules'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/modular-waf/rule/custom', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'save_custom_modular_rule'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/modular-waf/code-preview', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_modular_code_preview'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/modular-waf/export', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'export_modular_waf_bundle'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/modular-waf/autopilot', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'toggle_modular_autopilot'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/modular-waf/fields', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_modular_visual_fields'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/modular-waf/rule/simulate', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'simulate_custom_modular_rule'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/modular-waf/rule/custom/delete', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'delete_custom_modular_rule'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/modular-waf/rule/custom/reorder', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'reorder_custom_modular_rules'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/modular-waf/rule/cloudflare-push', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'push_custom_rule_to_cloudflare'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/modular-waf/rule/parse-wirefilter', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'parse_wirefilter_expression'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/modular-waf/rule/parse-ai', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'parse_ai_rule_payload'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/modular-waf/rule/ai-generate', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'ai_generate_visual_rule'],
            'permission_callback' => $permission,
        ]);

    }
}