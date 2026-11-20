<?php
declare(strict_types=1);

namespace WebCareProScanner\Api\Controllers;

use WebCareProScanner\Api\ScannerRoutes;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * SystemController
 *
 * System, Settings, Backup & Telemetry REST Controller.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
final class SystemController extends AbstractApiController {

    /**
     * Register endpoints for this domain.
     *
     * @param string   $namespace REST API route namespace.
     * @param callable $permission Permission callback.
     */
    public static function register(string $namespace, callable $permission): void {
        register_rest_route($namespace, '/server-info', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_server_info'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/telemetry/snapshot', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_telemetry_snapshot'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/system/telemetry-snapshot', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_telemetry_snapshot'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/readiness', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_system_readiness'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/welcome/dismiss', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'dismiss_welcome_modal'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/backup/preflight', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_backup_preflight'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/backup/session/start', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'start_backup_session'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/backup/session/step', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'step_backup_session'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/backup/session/status', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_backup_session_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/backup/active', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_active_backup'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/backup/session/cancel', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'cancel_backup_session'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/backup/create', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'create_backup'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/backup/list', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'list_backups'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/backup/delete', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'delete_backup'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/backup/download', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'download_backup'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/settings', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/settings', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'save_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/settings/export', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'export_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/settings/import', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'import_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/settings/reset', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'reset_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/settings/trigger-cron', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'trigger_cron_now'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/hardening/audit', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_hardening_audit'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/hardening/apply-preset', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'apply_hardening_preset'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/site-advisor', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_site_advisor_evaluation'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/site-advisor/apply', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'apply_site_advisor_recommendations'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/site-advisor/rollback', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'rollback_site_advisor_snapshot'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/reports/incident-response', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_incident_report'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/comment/moderate', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'moderate_comment'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/notifications/test-webhook', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'test_chat_webhook'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/notifications/settings', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_notification_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/notifications/settings', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'save_notification_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/notifications/test-event', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'test_notification_event'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/vault/status', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_vault_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/vault/rotate-key', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'rotate_vault_key'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/vault/rollback-rotation', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'rollback_vault_rotation'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/vault/reset-rotation', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'reset_vault_rotation'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/security/run-drill', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'run_security_drill'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/security/drill-results', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_security_drill_results'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/containment/status', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_containment_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/containment/toggle', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'toggle_containment'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/correlation/hierarchy', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_correlation_hierarchy'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/activity-logs', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_activity_logs'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/activity-logs/verify', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'verify_activity_logs_integrity'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/activity-logs/export', [
            'methods'             => ['GET', 'POST'],
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'export_activity_logs'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/activity-logs/prune', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'prune_activity_logs'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/activity-logs/acknowledge-tamper', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'acknowledge_activity_tamper_alert'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/wizard/status', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_wizard_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/wizard/save', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'save_wizard_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/modules/ecosystem', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_modules_ecosystem'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/modules/toggle', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'toggle_ecosystem_module'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/system/doctor', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_system_doctor'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/system/diagnostic-export', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'export_diagnostic_bundle'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/system/safe-mode', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'toggle_safe_mode'],
            'permission_callback' => $permission,
        ]);

    }

    /**
     * Run doctor diagnostics and return health report.
     */
    public static function get_system_doctor(): \WP_REST_Response {
        $report = \WebCareProScanner\System\SystemDoctor::run_diagnostics();
        return new \WP_REST_Response(['success' => true, 'report' => $report], 200);
    }

    /**
     * Export DLP-redacted diagnostic bundle JSON.
     */
    public static function export_diagnostic_bundle(): \WP_REST_Response {
        $bundle = \WebCareProScanner\System\SystemDoctor::build_redacted_diagnostic_bundle();
        return new \WP_REST_Response(['success' => true, 'bundle' => $bundle], 200);
    }

    /**
     * Toggle 15-Minute Safe Mode (Observe-Only Pause or Immediate Resume).
     */
    public static function toggle_safe_mode(\WP_REST_Request $request): \WP_REST_Response {
        $action = sanitize_key((string) ($request->get_param('action') ?? 'pause'));
        if (!class_exists(\WebCareProScanner\Firewall\RescueAssistantManager::class)) {
            return new \WP_REST_Response(['success' => false, 'message' => __('Rescue assistant manager not available.', 'webcare-pro-security')], 500);
        }

        if ($action === 'resume') {
            $result = \WebCareProScanner\Firewall\RescueAssistantManager::resume_strict_firewall();
        } else {
            $result = \WebCareProScanner\Firewall\RescueAssistantManager::pause_strict_firewall_15m();
        }

        return new \WP_REST_Response($result, 200);
    }
}