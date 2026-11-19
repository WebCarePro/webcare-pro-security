<?php
declare(strict_types=1);

namespace WebCareProScanner\Api\Controllers;

use WebCareProScanner\Api\ScannerRoutes;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * AuthController
 *
 * Authentication, 2FA & Identity REST Controller.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
final class AuthController extends AbstractApiController {

    /**
     * Register endpoints for this domain.
     *
     * @param string   $namespace REST API route namespace.
     * @param callable $permission Permission callback.
     */
    public static function register(string $namespace, callable $permission): void {
        register_rest_route($namespace, '/auth/status', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_auth_security_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/2fa/setup', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'setup_2fa_for_user'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/2fa/verify-setup', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'verify_and_enable_2fa'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/2fa/disable', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'disable_2fa_for_user'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/2fa/revoke-trusted-devices', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'revoke_2fa_trusted_devices'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/2fa/regenerate-backup-codes', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'regenerate_user_backup_codes'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/unlock-ip', [

            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'unlock_locked_ip'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/clear-lockouts', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'clear_all_lockouts'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/admins', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_admin_directory_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/admin-2fa/disable', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'admin_disable_user_2fa'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/admin-2fa/reset', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'admin_reset_user_2fa'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/admin-2fa/regenerate-backup-codes', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'admin_regenerate_user_backup_codes'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/admin-lockout/clear', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'admin_clear_user_lockout'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/policy/save', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'save_auth_security_policy'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/sessions/list', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_active_sessions_list'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/sessions/revoke', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'revoke_active_session'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/user-history', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_user_login_history'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/telemetry', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'record_client_telemetry'],
            'permission_callback' => function () {
                return is_user_logged_in() && current_user_can('read');
            },
        ]);

        register_rest_route($namespace, '/identity/status', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_identity_forensics_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/identity/revoke-session', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'revoke_identity_session'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/identity/revoke-all-sessions', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'revoke_all_identity_sessions'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/identity/audit-users', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'audit_identity_privileged_users'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/identity/force-reset', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'force_identity_password_reset'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/identity/settings', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'update_identity_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/identity/dismiss-travel-alert', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'dismiss_impossible_travel_alert'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/webauthn/register-options', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'webauthn_register_options'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/webauthn/register-verify', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'webauthn_register_verify'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/webauthn/credentials', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'webauthn_get_credentials'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/webauthn/delete-credential', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'webauthn_delete_credential'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/webauthn/login-options', [
            'methods'             => ['GET', 'POST'],
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'webauthn_login_options'],
            'permission_callback' => [\WebCareProScanner\Api\ScannerRoutes::class, 'check_webauthn_public_rate_limit'],
        ]);

        register_rest_route($namespace, '/auth/webauthn/login-verify', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'webauthn_login_verify'],
            'permission_callback' => [\WebCareProScanner\Api\ScannerRoutes::class, 'check_webauthn_public_rate_limit'],
        ]);

        register_rest_route($namespace, '/auth/app-passwords', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_app_passwords'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/app-passwords/settings', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_app_passwords_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/app-passwords/settings', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'update_app_passwords_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/app-passwords/revoke', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'revoke_app_password'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/app-passwords/revoke-all', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'revoke_all_app_passwords'],
            'permission_callback' => $permission,
        ]);

    }
}