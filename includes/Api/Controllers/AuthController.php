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
            'callback'            => [self::class, 'get_auth_security_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/2fa/setup', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'setup_2fa_for_user'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/2fa/verify-setup', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'verify_and_enable_2fa'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/2fa/disable', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'disable_2fa_for_user'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/2fa/revoke-trusted-devices', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'revoke_2fa_trusted_devices'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/2fa/regenerate-backup-codes', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'regenerate_user_backup_codes'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/unlock-ip', [

            'methods'             => 'POST',
            'callback'            => [self::class, 'unlock_locked_ip'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/clear-lockouts', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'clear_all_lockouts'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/admins', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_admin_directory_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/admin-2fa/disable', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'admin_disable_user_2fa'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/admin-2fa/reset', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'admin_reset_user_2fa'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/admin-2fa/regenerate-backup-codes', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'admin_regenerate_user_backup_codes'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/admin-lockout/clear', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'admin_clear_user_lockout'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/policy/save', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'save_auth_security_policy'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/sessions/list', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_active_sessions_list'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/sessions/revoke', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'revoke_active_session'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/user-history', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_user_login_history'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/telemetry', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'record_client_telemetry'],
            'permission_callback' => function () {
                return is_user_logged_in() && current_user_can('read');
            },
        ]);

        register_rest_route($namespace, '/identity/status', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_identity_forensics_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/identity/revoke-session', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'revoke_identity_session'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/identity/revoke-all-sessions', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'revoke_all_identity_sessions'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/identity/audit-users', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'audit_identity_privileged_users'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/identity/force-reset', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'force_identity_password_reset'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/identity/settings', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'update_identity_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/identity/dismiss-travel-alert', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'dismiss_impossible_travel_alert'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/webauthn/register-options', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'webauthn_register_options'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/webauthn/register-verify', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'webauthn_register_verify'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/webauthn/credentials', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'webauthn_get_credentials'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/webauthn/delete-credential', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'webauthn_delete_credential'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/webauthn/login-options', [
            'methods'             => ['GET', 'POST'],
            'callback'            => [self::class, 'webauthn_login_options'],
            'permission_callback' => [self::class, 'check_webauthn_public_rate_limit'],
        ]);

        register_rest_route($namespace, '/auth/webauthn/login-verify', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'webauthn_login_verify'],
            'permission_callback' => [self::class, 'check_webauthn_public_rate_limit'],
        ]);

        register_rest_route($namespace, '/auth/app-passwords', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_app_passwords'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/app-passwords/settings', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_app_passwords_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/app-passwords/settings', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'update_app_passwords_settings'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/app-passwords/revoke', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'revoke_app_password'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/auth/app-passwords/revoke-all', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'revoke_all_app_passwords'],
            'permission_callback' => $permission,
        ]);

    }

    /**
     * Auth Security: Get Status & Lockouts
     */
    public static function get_auth_security_status() {
        $settings = \WebCareProScanner\System\SettingsManager::get_settings();
        $user_id  = get_current_user_id();
        $user     = wp_get_current_user();

        return rest_ensure_response([
            'auth_2fa_enabled'          => !empty($settings['auth_2fa_enabled']),
            'auth_2fa_algorithm'        => !empty($settings['auth_2fa_algorithm']) ? $settings['auth_2fa_algorithm'] : 'sha1',
            'auth_2fa_digits'           => (!empty($settings['auth_2fa_digits']) && (int) $settings['auth_2fa_digits'] === 8) ? 8 : 6,
            'auth_2fa_remember_device'  => !empty($settings['auth_2fa_remember_device']),
            'auth_2fa_remember_days'    => (int) ($settings['auth_2fa_remember_days'] ?? 7),
            'auth_2fa_enforce_admins'   => !empty($settings['auth_2fa_enforce_admins']),
            'auth_2fa_policy_mode'      => $settings['auth_2fa_policy_mode'] ?? 'immediate',
            'auth_2fa_grace_days'       => (int) ($settings['auth_2fa_grace_days'] ?? 0),
            'auth_2fa_enforce_since'    => (int) ($settings['auth_2fa_enforce_since'] ?? 0),
            'login_hardening_enabled'   => !empty($settings['login_hardening_enabled']),
            'login_max_retries'         => (int) ($settings['login_max_retries'] ?? 5),
            'login_lockout_duration'    => (int) ($settings['login_lockout_duration'] ?? 15),
            'session_sentinel_enabled'  => !empty($settings['session_sentinel_enabled']),
            'session_block_concurrent'  => !empty($settings['session_block_concurrent']),
            'user_2fa_enabled'          => \WebCareProScanner\Auth\TwoFactorAuth::is_user_enabled($user_id),
            'user_2fa_algorithm'        => \WebCareProScanner\Auth\TwoFactorAuth::get_user_algorithm($user_id),
            'user_2fa_digits'           => \WebCareProScanner\Auth\TwoFactorAuth::get_user_digits($user_id),
            'user_compliance'           => \WebCareProScanner\Auth\TwoFactorAuth::get_user_compliance_status($user_id),
            'user_login'                => $user ? $user->user_login : '',
            'user_email'                => $user ? $user->user_email : '',
            'trusted_devices_count'     => count(\WebCareProScanner\Auth\TwoFactorAuth::get_trusted_devices($user_id)),
            'trusted_devices'           => \WebCareProScanner\Auth\TwoFactorAuth::get_trusted_devices($user_id),
            'lockouts'                  => array_values(\WebCareProScanner\Auth\LoginHardening::get_locked_ips()),
            'stats'                     => \WebCareProScanner\Auth\LoginHardening::get_stats(),
            'active_sessions'           => \WebCareProScanner\Auth\SessionSentinel::get_active_sessions(),
            'backup_codes_count'        => \WebCareProScanner\Auth\TwoFactorAuth::get_remaining_backup_codes_count($user_id),
            'current_ip'                => \WebCareProScanner\Firewall\FirewallEngine::get_client_ip(),
        ]);
    }

    /**
     * Auth Security: Generate 2FA Setup Package
     */
    public static function setup_2fa_for_user() {
        $user_id = get_current_user_id();
        $user    = wp_get_current_user();

        $settings = \WebCareProScanner\System\SettingsManager::get_settings();
        $algo     = !empty($settings['auth_2fa_algorithm']) ? (string) $settings['auth_2fa_algorithm'] : 'sha1';
        $digits   = (!empty($settings['auth_2fa_digits']) && (int) $settings['auth_2fa_digits'] === 8 || $algo === 'sha512') ? 8 : 6;
        $secretLen = ($algo === 'sha512') ? 64 : 16;

        $secret           = \WebCareProScanner\Auth\TwoFactorAuth::generate_secret($secretLen);
        $provisioning_uri = \WebCareProScanner\Auth\TwoFactorAuth::get_provisioning_uri($secret, $user->user_login, $algo, $digits);
        $qr_data_uri      = \WebCareProScanner\Auth\TwoFactorAuth::get_qr_data_uri($provisioning_uri);
        $backup_bundle    = \WebCareProScanner\Auth\TwoFactorAuth::generate_backup_codes(8);

        // Store setup state in transient for 10 minutes
        set_transient('webcareproscan_2fa_setup_' . $user_id, [
            'secret'       => $secret,
            'algorithm'    => $algo,
            'digits'       => $digits,
            'hashed_codes' => $backup_bundle['hashed'],
        ], 600);

        return rest_ensure_response([
            'secret'           => $secret,
            'algorithm'        => $algo,
            'digits'           => $digits,
            'provisioning_uri' => $provisioning_uri,
            'qr_code_url'      => $qr_data_uri,
            'backup_codes'     => $backup_bundle['plain'],
        ]);
    }

    /**
     * Auth Security: Verify and Enable 2FA
     */
    public static function verify_and_enable_2fa(\WP_REST_Request $request) {
        $user_id = get_current_user_id();
        $params  = $request->get_json_params() ?: [];
        $code    = sanitize_text_field($params['code'] ?? '');

        $setup_state = get_transient('webcareproscan_2fa_setup_' . $user_id);
        if (!$setup_state || empty($setup_state['secret'])) {
            return new \WP_Error('session_expired', __('2FA setup session expired. Please click "Setup 2FA" again.', 'webcare-pro-security'), ['status' => 400]);
        }

        // Always read the pending secret strictly from server storage; never trust client-supplied secret overrides
        $active_secret = $setup_state['secret'];
        $algo          = $setup_state['algorithm'] ?? 'sha1';
        $digits        = (int) ($setup_state['digits'] ?? 6);

        if (!\WebCareProScanner\Auth\TwoFactorAuth::verify_code($active_secret, $code, 1, $algo, $digits)) {
            return new \WP_Error('invalid_code', sprintf(
                /* translators: %d: count of digits expected */
                __('The %d-digit verification code you entered is invalid. Please check your authenticator clock and try again.', 'webcare-pro-security'),
                $digits
            ), ['status' => 400]);
        }

        \WebCareProScanner\Auth\TwoFactorAuth::enable_user($user_id, $active_secret, $setup_state['hashed_codes'], $algo, $digits);
        delete_transient('webcareproscan_2fa_setup_' . $user_id);

        return rest_ensure_response([
            'success' => true,
            'message' => __('Two-Factor Authentication (2FA) is now active on your account!', 'webcare-pro-security'),
        ]);
    }

    /**
     * Auth Security: Disable 2FA
     */
    public static function disable_2fa_for_user() {
        $user_id = get_current_user_id();
        \WebCareProScanner\Auth\TwoFactorAuth::disable_user($user_id);
        return rest_ensure_response([
            'success' => true,
            'message' => __('Two-Factor Authentication (2FA) has been disabled.', 'webcare-pro-security'),
        ]);
    }

    /**
     * Auth Security: Revoke All Trusted Devices
     */
    public static function revoke_2fa_trusted_devices() {
        $user_id = get_current_user_id();
        \WebCareProScanner\Auth\TwoFactorAuth::revoke_all_trusted_devices($user_id);
        return rest_ensure_response([
            'success' => true,
            'message' => __('All remembered/trusted devices have been revoked. 2FA verification will be required on all browsers.', 'webcare-pro-security'),
        ]);
    }

    /**
     * Auth Security: Regenerate Backup Codes for Current User
     */
    public static function regenerate_user_backup_codes() {
        $user_id = get_current_user_id();
        $user    = wp_get_current_user();

        if (!\WebCareProScanner\Auth\TwoFactorAuth::is_user_enabled($user_id)) {
            return new \WP_Error('2fa_not_enabled', __('Two-Factor Authentication is not enabled for your account.', 'webcare-pro-security'), ['status' => 400]);
        }

        try {
            $bundle = \WebCareProScanner\Auth\TwoFactorAuth::regenerate_backup_codes($user_id, 8);

            if (class_exists('\\WebCareProScanner\\System\\AuditLogger')) {
                \WebCareProScanner\System\AuditLogger::log_event(
                    '2fa_backup_codes_regenerated',
                    /* translators: %s: username */
                    sprintf(__('Administrator %s regenerated 2FA emergency backup codes.', 'webcare-pro-security'), $user->user_login)
                );
            }

            return rest_ensure_response([
                'success'            => true,
                'message'            => __('New 2FA emergency backup codes generated successfully.', 'webcare-pro-security'),
                'backup_codes'       => $bundle['backup_codes'],
                'backup_codes_count' => $bundle['count'],
            ]);
        } catch (\Throwable $e) {
            return new \WP_Error('regen_failed', $e->getMessage(), ['status' => 500]);
        }
    }

    /**
     * Auth Security: Unlock IP
     */
    public static function unlock_locked_ip(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $ip = sanitize_text_field($params['ip'] ?? '');
        if (empty($ip)) {
            return new \WP_Error('missing_ip', __('Missing IP parameter.', 'webcare-pro-security'), ['status' => 400]);
        }
        \WebCareProScanner\Auth\LoginHardening::unlock_ip($ip);
        return rest_ensure_response([
            'success' => true,
            'message' => sprintf(
                /* translators: %s: IP address */
                __('IP %s has been unlocked.', 'webcare-pro-security'),
                $ip
            ),
        ]);
    }

    /**
     * Auth Security: Clear all lockouts
     */
    public static function clear_all_lockouts() {
        \WebCareProScanner\Auth\LoginHardening::clear_all_lockouts();
        return rest_ensure_response([
            'success' => true,
            'message' => __('All temporary IP lockouts have been cleared.', 'webcare-pro-security'),
        ]);
    }

    /**
     * Auth Security: Get Administrator Directory & 2FA Compliance Status
     */
    public static function get_admin_directory_status() {
        $admins = \WebCareProScanner\Auth\TwoFactorAuth::get_administrators_status();
        $settings = \WebCareProScanner\System\SettingsManager::get_settings();

        return rest_ensure_response([
            'success'            => true,
            'admins'             => $admins,
            'total_admins'       => count($admins),
            'enforce_admins'     => !empty($settings['auth_2fa_enforce_admins']),
            'policy_mode'        => $settings['auth_2fa_policy_mode'] ?? 'immediate',
            'grace_days'         => (int) ($settings['auth_2fa_grace_days'] ?? 0),
            'enforce_since'      => (int) ($settings['auth_2fa_enforce_since'] ?? 0),
            'global_2fa_enabled' => !empty($settings['auth_2fa_enabled']),
        ]);
    }

    /**
     * Auth Security: Admin Disable 2FA for target user (Emergency recovery / lockout unlock)
     */
    public static function admin_disable_user_2fa(\WP_REST_Request $request) {
        $params  = $request->get_json_params() ?: [];
        $user_id = (int) ($params['user_id'] ?? 0);

        if (!$user_id) {
            return new \WP_Error('invalid_user', __('Valid user ID is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $user = get_user_by('id', $user_id);
        if (!$user) {
            return new \WP_Error('user_not_found', __('User does not exist.', 'webcare-pro-security'), ['status' => 404]);
        }

        \WebCareProScanner\Auth\TwoFactorAuth::disable_user($user_id);

        if (class_exists('\\WebCareProScanner\\System\\AuditLogger')) {
            \WebCareProScanner\System\AuditLogger::log_event(
                'admin_2fa_disabled',
                sprintf(
                    /* translators: 1: admin username, 2: target username, 3: user ID */
                    __('Administrator %1$s disabled 2FA for user "%2$s" (ID: %3$d).', 'webcare-pro-security'),
                    wp_get_current_user()->user_login,
                    $user->user_login,
                    $user_id
                )
            );
        }

        return rest_ensure_response([
            'success' => true,
            'message' => sprintf(
                /* translators: %s: username */
                __('2FA has been disabled and unlocked for administrator %s.', 'webcare-pro-security'),
                $user->user_login
            ),
            'admins'  => \WebCareProScanner\Auth\TwoFactorAuth::get_administrators_status(),
        ]);
    }

    /**
     * Auth Security: Admin Reset 2FA & Generate New Setup Package for target user
     */
    public static function admin_reset_user_2fa(\WP_REST_Request $request) {
        $params  = $request->get_json_params() ?: [];
        $user_id = (int) ($params['user_id'] ?? 0);

        if (!$user_id) {
            return new \WP_Error('invalid_user', __('Valid user ID is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $user = get_user_by('id', $user_id);
        if (!$user) {
            return new \WP_Error('user_not_found', __('User does not exist.', 'webcare-pro-security'), ['status' => 404]);
        }

        $current_uid = get_current_user_id();
        // If resetting another administrator, reset their 2FA and require self-enrollment on next login
        // to prevent immediate lockout and cross-admin secret exposure
        if ($user_id !== $current_uid) {
            \WebCareProScanner\Auth\TwoFactorAuth::disable_user($user_id);
            update_user_meta($user_id, 'webcareproscan_force_2fa_setup', 1);
            delete_user_meta($user_id, 'webcareproscan_2fa_secret');
            delete_user_meta($user_id, 'webcareproscan_2fa_backup_codes');

            if (class_exists('\\WebCareProScanner\\System\\AuditLogger')) {
                \WebCareProScanner\System\AuditLogger::log_event(
                    'admin_2fa_reset',
                    sprintf(
                        /* translators: 1: admin username, 2: target username, 3: user ID */
                        __('Administrator %1$s reset 2FA policy for user "%2$s" (ID: %3$d), requiring re-enrollment on next login.', 'webcare-pro-security'),
                        wp_get_current_user()->user_login,
                        $user->user_login,
                        $user_id
                    )
                );
            }

            return rest_ensure_response([
                'success'       => true,
                'message'       => sprintf(
                    /* translators: %s: username */
                    __('2FA has been reset for administrator %s. They will be prompted to safely enroll their own authenticator upon next login.', 'webcare-pro-security'),
                    $user->user_login
                ),
                'setup_package' => null,
                'admins'        => \WebCareProScanner\Auth\TwoFactorAuth::get_administrators_status(),
            ]);
        }

        try {
            $setup_pkg = \WebCareProScanner\Auth\TwoFactorAuth::reset_user_2fa($user_id);

            if (class_exists('\\WebCareProScanner\\System\\AuditLogger')) {
                \WebCareProScanner\System\AuditLogger::log_event(
                    'admin_2fa_reset',
                    sprintf(
                        /* translators: 1: admin username, 2: target username, 3: user ID */
                        __('Administrator %1$s regenerated 2FA credentials for user "%2$s" (ID: %3$d).', 'webcare-pro-security'),
                        wp_get_current_user()->user_login,
                        $user->user_login,
                        $user_id
                    )
                );
            }

            return rest_ensure_response([
                'success'       => true,
                'message'       => sprintf(
                    /* translators: %s: username */
                    __('New 2FA credentials generated for %s.', 'webcare-pro-security'),
                    $user->user_login
                ),
                'setup_package' => $setup_pkg,
                'admins'        => \WebCareProScanner\Auth\TwoFactorAuth::get_administrators_status(),
            ]);
        } catch (\Throwable $e) {
            return new \WP_Error('reset_failed', $e->getMessage(), ['status' => 500]);
        }
    }

    /**
     * Auth Security: Admin Regenerate Backup Codes for Target Administrator
     */
    public static function admin_regenerate_user_backup_codes(\WP_REST_Request $request) {
        $params  = $request->get_json_params() ?: [];
        $user_id = (int) ($params['user_id'] ?? 0);

        if (!$user_id) {
            return new \WP_Error('invalid_user', __('Valid user ID is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $user = get_user_by('id', $user_id);
        if (!$user) {
            return new \WP_Error('user_not_found', __('User does not exist.', 'webcare-pro-security'), ['status' => 404]);
        }

        if (!\WebCareProScanner\Auth\TwoFactorAuth::is_user_enabled($user_id)) {
            return new \WP_Error(
                '2fa_not_enabled',
                sprintf(
                    /* translators: %s: username */
                    __('2FA is not enabled for user %s.', 'webcare-pro-security'),
                    $user->user_login
                ),
                ['status' => 400]
            );
        }

        try {
            $bundle = \WebCareProScanner\Auth\TwoFactorAuth::regenerate_backup_codes($user_id, 8);

            if (class_exists('\\WebCareProScanner\\System\\AuditLogger')) {
                \WebCareProScanner\System\AuditLogger::log_event(
                    'admin_2fa_backup_codes_regenerated',
                    sprintf(
                        /* translators: 1: admin username, 2: target username, 3: user ID */
                        __('Administrator %1$s regenerated backup codes for user "%2$s" (ID: %3$d).', 'webcare-pro-security'),
                        wp_get_current_user()->user_login,
                        $user->user_login,
                        $user_id
                    )
                );
            }

            return rest_ensure_response([
                'success'            => true,
                'message'            => sprintf(
                    /* translators: %s: username */
                    __('New backup codes generated for administrator %s.', 'webcare-pro-security'),
                    $user->user_login
                ),
                'user_login'         => $user->user_login,
                'backup_codes'       => $bundle['backup_codes'],
                'backup_codes_count' => $bundle['count'],
                'admins'             => \WebCareProScanner\Auth\TwoFactorAuth::get_administrators_status(),
            ]);
        } catch (\Throwable $e) {
            return new \WP_Error('regen_failed', $e->getMessage(), ['status' => 500]);
        }
    }

    /**
     * Auth Security: Clear Login Hardening Lockouts for Target Administrator
     */
    public static function admin_clear_user_lockout(\WP_REST_Request $request) {
        $params  = $request->get_json_params() ?: [];
        $user_id = (int) ($params['user_id'] ?? 0);

        if (!$user_id) {
            return new \WP_Error('invalid_user', __('Valid user ID is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $user = get_user_by('id', $user_id);
        if (!$user) {
            return new \WP_Error('user_not_found', __('User does not exist.', 'webcare-pro-security'), ['status' => 404]);
        }

        $res = \WebCareProScanner\Auth\TwoFactorAuth::unlock_user_lockouts($user_id);

        return rest_ensure_response([
            'success'          => true,
            'message'          => sprintf(
                /* translators: %s: username */
                __('Login lockouts and rate-limiting blocks cleared for user %s.', 'webcare-pro-security'),
                $user->user_login
            ),
            'unlocked_ips'     => $res['unlocked_ips'],
            'admins'           => \WebCareProScanner\Auth\TwoFactorAuth::get_administrators_status(),
            'lockouts'         => array_values(\WebCareProScanner\Auth\LoginHardening::get_locked_ips()),
        ]);
    }

    /**
     * Auth Security: Save 2FA Policy & Enforce Settings
     */
    public static function save_auth_security_policy(\WP_REST_Request $request) {
        $params   = $request->get_json_params();
        if (empty($params)) {
            $params = $request->get_params();
        }
        $settings = \WebCareProScanner\System\SettingsManager::get_settings();

        $enforce_admins = !empty($params['auth_2fa_enforce_admins']);
        $raw_mode       = sanitize_key($params['auth_2fa_policy_mode'] ?? 'remind_login');
        $policy_mode    = in_array($raw_mode, ['immediate', 'grace_period', 'remind_login'], true) ? $raw_mode : 'remind_login';
        $grace_days     = max(0, min(90, (int) ($params['auth_2fa_grace_days'] ?? ($policy_mode === 'immediate' ? 0 : 30))));

        $settings['auth_2fa_enforce_admins'] = $enforce_admins;
        $settings['auth_2fa_policy_mode']    = $policy_mode;
        $settings['auth_2fa_grace_days']     = $grace_days;

        if ($enforce_admins && empty($settings['auth_2fa_enforce_since'])) {
            $settings['auth_2fa_enforce_since'] = time();
        } elseif (!$enforce_admins) {
            $settings['auth_2fa_enforce_since'] = 0;
        }

        \WebCareProScanner\System\SettingsManager::save_settings($settings);

        if (class_exists('\\WebCareProScanner\\System\\AuditLogger')) {
            \WebCareProScanner\System\AuditLogger::log_event(
                'auth_policy_updated',
                sprintf(
                    /* translators: 1: enforce status, 2: policy mode, 3: grace days */
                    __('Administrator 2FA policy updated: Enforce=%1$s, Mode=%2$s, Grace Days=%3$d.', 'webcare-pro-security'),
                    $enforce_admins ? 'YES' : 'NO',
                    strtoupper($policy_mode),
                    $grace_days
                )
            );
        }

        return rest_ensure_response([
            'success' => true,
            'message' => __('2FA enforcement policy updated successfully.', 'webcare-pro-security'),
            'policy'  => [
                'enforce_admins' => $enforce_admins,
                'policy_mode'    => $policy_mode,
                'grace_days'     => $grace_days,
                'enforce_since'  => $settings['auth_2fa_enforce_since'],
            ],
            'admins'  => \WebCareProScanner\Auth\TwoFactorAuth::get_administrators_status(),
        ]);
    }

    /**
     * Session Sentinel: Get active sessions list
     */
    public static function get_active_sessions_list() {
        return rest_ensure_response([
            'success'    => true,
            'sessions'   => \WebCareProScanner\Auth\SessionSentinel::get_active_sessions(),
            'current_ip' => \WebCareProScanner\Firewall\FirewallEngine::get_client_ip(),
        ]);
    }

    /**
     * Session Sentinel: Revoke session
     */
    public static function revoke_active_session(\WP_REST_Request $request) {
        try {
            $params  = $request->get_json_params() ?: [];
            $token   = sanitize_text_field($params['token'] ?? '');
            $user_id = (int) ($params['user_id'] ?? 0);
            $revoke_others = !empty($params['revoke_others']);
            $delete_record = !empty($params['delete_record']);

            // Permanent removal of device record from audit history (enforcing 30-day retention invariant)
            if ($delete_record) {
                if (empty($token) || empty($user_id)) {
                    return new \WP_Error('missing_params', __('Session token and user ID are required to remove a record.', 'webcare-pro-security'), ['status' => 400]);
                }
                try {
                    $result = \WebCareProScanner\Auth\SessionSentinel::delete_session_record($user_id, $token);
                    if (!$result) {
                        return new \WP_Error('delete_failed', __('Failed to remove device record. It may not exist or has already been removed.', 'webcare-pro-security'), ['status' => 404]);
                    }
                    return rest_ensure_response([
                        'success'  => true,
                        'message'  => __('Device record permanently removed from history and security vault.', 'webcare-pro-security'),
                        'sessions' => \WebCareProScanner\Auth\SessionSentinel::get_active_sessions(),
                    ]);
                } catch (\Throwable $e) {
                    return new \WP_Error('retention_lock', $e->getMessage(), ['status' => 403]);
                }
            }

            if ($revoke_others) {
                $target_user_id = $user_id ?: 0;
                $all_admins = !empty($params['all_admins']) || empty($user_id);
                \WebCareProScanner\Auth\SessionSentinel::terminate_all_other_sessions($target_user_id, $all_admins);
                return rest_ensure_response([
                    'success' => true,
                    'message' => __('All other sessions have been logged out.', 'webcare-pro-security'),
                    'sessions' => \WebCareProScanner\Auth\SessionSentinel::get_active_sessions(),
                ]);
            }

            if (empty($token) || empty($user_id)) {
                return new \WP_Error('missing_params', __('Session token and user ID are required.', 'webcare-pro-security'), ['status' => 400]);
            }

            \WebCareProScanner\Auth\SessionSentinel::terminate_session($user_id, $token, 'Logged out by administrator via Session Sentinel.');

            return rest_ensure_response([
                'success'  => true,
                'message'  => __('Session successfully logged out.', 'webcare-pro-security'),
                'sessions' => \WebCareProScanner\Auth\SessionSentinel::get_active_sessions(),
            ]);
        } catch (\Throwable $e) {
            return new \WP_Error('session_revoke_error', $e->getMessage(), ['status' => 500]);
        }
    }

    /**
     * Auth Security: Get User Login History & Device Forensics (Encrypted Telemetry Decrypted for Admin)
     */
    public static function get_user_login_history(\WP_REST_Request $request) {
        $user_id = (int) $request->get_param('user_id');
        if (empty($user_id)) {
            $user_id = get_current_user_id();
        }

        $raw_limit = $request->get_param('limit');
        if ($raw_limit === '0' || $raw_limit === 0 || $raw_limit === 'all' || $raw_limit === 'unlimited') {
            $limit = 0; // Retrieve full historical audit log
        } elseif (!empty($raw_limit)) {
            $limit = max(1, (int) $raw_limit);
        } else {
            $limit = 10;
        }

        $result = \WebCareProScanner\Auth\LoginHistoryManager::get_user_history($user_id, $limit);

        return rest_ensure_response($result);
    }

    /**
     * Auth Security: Record Dynamic Client Telemetry (Screen Resolution, Viewport, Timezone)
     */
    public static function record_client_telemetry(\WP_REST_Request $request) {
        $user_id = get_current_user_id();
        if (!$user_id) {
            return new \WP_Error('unauthorized', __('Unauthorized', 'webcare-pro-security'), ['status' => 401]);
        }

        // Rate-limiting: Max 5 submissions per user per 60 seconds to prevent telemetry flooding
        $transient_key = 'webcareproscan_telemetry_rate_' . $user_id;
        $hit_count = (int) get_transient($transient_key);
        if ($hit_count >= 5) {
            return new \WP_Error('too_many_requests', __('Telemetry submission rate limit exceeded. Please wait a minute.', 'webcare-pro-security'), ['status' => 429]);
        }
        set_transient($transient_key, $hit_count + 1, 60);

        $params = $request->get_json_params();
        if (!is_array($params)) {
            return new \WP_Error('invalid_payload', __('Invalid JSON payload structure.', 'webcare-pro-security'), ['status' => 400]);
        }

        // Strict input sanitization and length bounds
        $raw_res = sanitize_text_field(substr((string) ($params['screen_resolution'] ?? ''), 0, 32));
        $raw_vp  = sanitize_text_field(substr((string) ($params['viewport'] ?? ''), 0, 20));
        $raw_tz  = sanitize_text_field(substr((string) ($params['timezone'] ?? ''), 0, 64));

        // Format validation (screen and viewport should follow WxH format e.g. 1920x1080 or 1920x1080@1.25)
        $clean_res = preg_match('/^\d{2,5}x\d{2,5}(@[0-9.]+)?$/', $raw_res) ? $raw_res : '';
        $clean_vp  = preg_match('/^\d{2,5}x\d{2,5}$/', $raw_vp) ? $raw_vp : '';
        $clean_tz  = preg_match('/^[a-zA-Z0-9_\-\/\+\:\. ]{1,64}$/', $raw_tz) ? $raw_tz : '';

        $telemetry = [
            'screen_resolution' => $clean_res,
            'viewport'          => $clean_vp,
            'timezone'          => $clean_tz,
        ];

        \WebCareProScanner\Auth\LoginHistoryManager::update_session_telemetry($user_id, $telemetry);

        return rest_ensure_response([
            'success' => true,
        ]);
    }

    public static function get_identity_forensics_status(\WP_REST_Request $request) {
        $sessions_report = class_exists('\WebCareProScanner\Identity\SessionForensicsEngine')
            ? \WebCareProScanner\Identity\SessionForensicsEngine::get_active_sessions_report()
            : [];
        $hibp_summary = class_exists('\WebCareProScanner\Identity\HIBPBreachAuditor')
            ? \WebCareProScanner\Identity\HIBPBreachAuditor::get_summary()
            : [];

        return rest_ensure_response([
            'success'           => true,
            'sessions_report'   => $sessions_report,
            'active_elevations' => [],
            'elevation_history' => [],
            'hibp_summary'      => $hibp_summary,
            'candidate_users'   => [],
        ]);
    }

    public static function revoke_identity_session(\WP_REST_Request $request) {
        $params   = $request->get_json_params() ?: [];
        $user_id  = intval($params['user_id'] ?? 0);
        $verifier = sanitize_text_field($params['verifier'] ?? '');

        if (!$user_id || empty($verifier)) {
            return new \WP_Error('missing_params', __('User ID and session verifier are required.', 'webcare-pro-security'), ['status' => 400]);
        }

        if (!class_exists('\WebCareProScanner\Identity\SessionForensicsEngine')) {
            return new \WP_Error('missing_engine', __('SessionForensicsEngine not available.', 'webcare-pro-security'), ['status' => 500]);
        }

        $res = \WebCareProScanner\Identity\SessionForensicsEngine::revoke_session($user_id, $verifier);
        return rest_ensure_response($res);
    }

    public static function revoke_all_identity_sessions(\WP_REST_Request $request) {
        $params  = $request->get_json_params() ?: [];
        $user_id = intval($params['user_id'] ?? 0);

        if (!$user_id) {
            return new \WP_Error('missing_user_id', __('User ID is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        if (!class_exists('\WebCareProScanner\Identity\SessionForensicsEngine')) {
            return new \WP_Error('missing_engine', __('SessionForensicsEngine not available.', 'webcare-pro-security'), ['status' => 500]);
        }

        $res = \WebCareProScanner\Identity\SessionForensicsEngine::revoke_all_sessions($user_id);
        return rest_ensure_response($res);
    }

    public static function audit_identity_privileged_users(\WP_REST_Request $request) {
        if (!class_exists('\WebCareProScanner\Identity\HIBPBreachAuditor')) {
            return new \WP_Error('missing_engine', __('HIBPBreachAuditor not available.', 'webcare-pro-security'), ['status' => 500]);
        }

        $report = \WebCareProScanner\Identity\HIBPBreachAuditor::audit_privileged_users();
        return rest_ensure_response([
            'success' => true,
            'report'  => $report,
        ]);
    }

    public static function force_identity_password_reset(\WP_REST_Request $request) {
        $params  = $request->get_json_params() ?: [];
        $user_id = intval($params['user_id'] ?? 0);

        if (!$user_id) {
            return new \WP_Error('missing_user_id', __('User ID is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        if (!class_exists('\WebCareProScanner\Identity\HIBPBreachAuditor')) {
            return new \WP_Error('missing_engine', __('HIBPBreachAuditor not available.', 'webcare-pro-security'), ['status' => 500]);
        }

        $res = \WebCareProScanner\Identity\HIBPBreachAuditor::force_password_reset($user_id);
        return rest_ensure_response($res);
    }

    public static function update_identity_settings(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        if (!class_exists('\WebCareProScanner\Identity\SessionForensicsEngine')) {
            return new \WP_Error('missing_engine', __('SessionForensicsEngine not available.', 'webcare-pro-security'), ['status' => 500]);
        }

        $updated = \WebCareProScanner\Identity\SessionForensicsEngine::update_settings($params);
        return rest_ensure_response([
            'success'  => true,
            'settings' => $updated,
            'message'  => __('Identity forensics settings updated successfully.', 'webcare-pro-security'),
        ]);
    }

    public static function dismiss_impossible_travel_alert(\WP_REST_Request $request) {
        $params   = $request->get_json_params() ?: [];
        $alert_id = sanitize_text_field($params['alert_id'] ?? '');

        if (empty($alert_id)) {
            return new \WP_Error('missing_alert_id', __('Alert ID is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        if (!class_exists('\WebCareProScanner\Identity\SessionForensicsEngine')) {
            return new \WP_Error('missing_engine', __('SessionForensicsEngine not available.', 'webcare-pro-security'), ['status' => 500]);
        }

        $res = \WebCareProScanner\Identity\SessionForensicsEngine::dismiss_travel_alert($alert_id);
        return rest_ensure_response($res);
    }

    public static function webauthn_register_options(\WP_REST_Request $request) {
        $user_id = get_current_user_id();
        if (!$user_id) {
            return new \WP_Error('unauthorized', __('Authentication required.', 'webcare-pro-security'), ['status' => 401]);
        }
        return rest_ensure_response(\WebCareProScanner\Auth\WebAuthnManager::generate_registration_options($user_id));
    }

    public static function webauthn_register_verify(\WP_REST_Request $request) {
        $user_id = get_current_user_id();
        if (!$user_id) {
            return new \WP_Error('unauthorized', __('Authentication required.', 'webcare-pro-security'), ['status' => 401]);
        }
        $params = $request->get_json_params() ?: [];
        $payload = is_array($params['payload'] ?? null) ? $params['payload'] : [];
        $label = sanitize_text_field(wp_unslash($params['label'] ?? ''));

        $res = \WebCareProScanner\Auth\WebAuthnManager::verify_registration($user_id, $payload, $label);
        if (empty($res['success'])) {
            return new \WP_Error('verification_failed', $res['message'] ?? __('Passkey registration failed.', 'webcare-pro-security'), ['status' => 400]);
        }
        return rest_ensure_response($res);
    }

    public static function webauthn_get_credentials(\WP_REST_Request $request) {
        $user_id = get_current_user_id();
        return rest_ensure_response([
            'success'     => true,
            'credentials' => \WebCareProScanner\Auth\WebAuthnManager::get_user_credentials($user_id),
            'rp_id'       => \WebCareProScanner\Auth\WebAuthnManager::get_rp_id(),
        ]);
    }

    public static function webauthn_delete_credential(\WP_REST_Request $request) {
        $user_id = get_current_user_id();
        $params = $request->get_json_params() ?: [];
        $credential_id = sanitize_text_field(wp_unslash($params['credential_id'] ?? ''));

        if (empty($credential_id)) {
            return new \WP_Error('missing_id', __('Credential ID required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $deleted = \WebCareProScanner\Auth\WebAuthnManager::delete_credential($user_id, $credential_id);
        return rest_ensure_response([
            'success'     => $deleted,
            'message'     => $deleted ? __('Passkey removed successfully.', 'webcare-pro-security') : __('Passkey not found.', 'webcare-pro-security'),
            'credentials' => \WebCareProScanner\Auth\WebAuthnManager::get_user_credentials($user_id),
        ]);
    }

    public static function webauthn_login_options(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $username = sanitize_text_field(wp_unslash($params['username'] ?? ''));
        $options = \WebCareProScanner\Auth\WebAuthnManager::generate_login_options($username);
        if (empty($options['success'])) {
            return new \WP_Error(
                'options_rate_limited',
                $options['message'] ?? __('Too many passkey requests. Please wait a few minutes.', 'webcare-pro-security'),
                ['status' => 429]
            );
        }
        return rest_ensure_response($options);
    }

    public static function webauthn_login_verify(\WP_REST_Request $request) {
        $params = $request->get_json_params() ?: [];
        $session_id = sanitize_key($params['session_id'] ?? '');
        $payload = is_array($params['payload'] ?? null) ? $params['payload'] : [];

        if (empty($session_id) || empty($payload)) {
            return new \WP_Error('missing_params', __('Authentication session and payload required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $res = \WebCareProScanner\Auth\WebAuthnManager::verify_login($session_id, $payload);
        if (empty($res['success'])) {
            return new \WP_Error('login_failed', $res['message'] ?? __('Biometric login failed.', 'webcare-pro-security'), ['status' => 401]);
        }
        return rest_ensure_response($res);
    }

    /**
     * Get all active Application Passwords across all user accounts.
     */
    public static function get_app_passwords(\WP_REST_Request $request) {
        if (!class_exists(\WebCareProScanner\Auth\ApplicationPasswordSentinel::class)) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => 'Application Password Sentinel service not available.',
            ], 500);
        }

        $passwords = \WebCareProScanner\Auth\ApplicationPasswordSentinel::get_all_passwords();
        $settings  = \WebCareProScanner\Auth\ApplicationPasswordSentinel::get_settings();

        return rest_ensure_response([
            'success'   => true,
            'passwords' => $passwords,
            'settings'  => $settings,
        ]);
    }

    /**
     * Get Application Password Sentinel settings.
     */
    public static function get_app_passwords_settings(\WP_REST_Request $request) {
        if (!class_exists(\WebCareProScanner\Auth\ApplicationPasswordSentinel::class)) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => 'Application Password Sentinel service not available.',
            ], 500);
        }

        $settings = \WebCareProScanner\Auth\ApplicationPasswordSentinel::get_settings();

        return rest_ensure_response([
            'success'  => true,
            'settings' => $settings,
        ]);
    }

    /**
     * Update Application Password Sentinel policy settings.
     */
    public static function update_app_passwords_settings(\WP_REST_Request $request) {
        if (!class_exists(\WebCareProScanner\Auth\ApplicationPasswordSentinel::class)) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => 'Application Password Sentinel service not available.',
            ], 500);
        }

        $params = $request->get_json_params() ?: [];
        $result = \WebCareProScanner\Auth\ApplicationPasswordSentinel::update_settings($params);
        $settings = \WebCareProScanner\Auth\ApplicationPasswordSentinel::get_settings();

        return rest_ensure_response([
            'success'  => $result,
            'message'  => __('Application Password policy settings updated successfully.', 'webcare-pro-security'),
            'settings' => $settings,
        ]);
    }

    /**
     * Revoke a single Application Password.
     */
    public static function revoke_app_password(\WP_REST_Request $request) {
        if (!class_exists(\WebCareProScanner\Auth\ApplicationPasswordSentinel::class)) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => 'Application Password Sentinel service not available.',
            ], 500);
        }

        $params  = $request->get_json_params() ?: [];
        $user_id = isset($params['user_id']) ? (int) $params['user_id'] : 0;
        $uuid    = !empty($params['uuid']) ? sanitize_text_field($params['uuid']) : '';

        if ($user_id <= 0 || empty($uuid)) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => __('User ID and Application Password UUID are required.', 'webcare-pro-security'),
            ], 400);
        }

        $result = \WebCareProScanner\Auth\ApplicationPasswordSentinel::revoke_password($user_id, $uuid);

        if (!$result) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => __('Failed to revoke Application Password or password not found.', 'webcare-pro-security'),
            ], 400);
        }

        $passwords = \WebCareProScanner\Auth\ApplicationPasswordSentinel::get_all_passwords();
        $settings  = \WebCareProScanner\Auth\ApplicationPasswordSentinel::get_settings();

        return rest_ensure_response([
            'success'   => true,
            'message'   => __('Application Password revoked successfully.', 'webcare-pro-security'),
            'passwords' => $passwords,
            'settings'  => $settings,
        ]);
    }

    /**
     * Revoke all Application Passwords for a user.
     */
    public static function revoke_all_app_passwords(\WP_REST_Request $request) {
        if (!class_exists(\WebCareProScanner\Auth\ApplicationPasswordSentinel::class)) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => 'Application Password Sentinel service not available.',
            ], 500);
        }

        $params  = $request->get_json_params() ?: [];
        $user_id = isset($params['user_id']) ? (int) $params['user_id'] : 0;

        if ($user_id <= 0) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => __('Valid User ID is required.', 'webcare-pro-security'),
            ], 400);
        }

        $result = \WebCareProScanner\Auth\ApplicationPasswordSentinel::revoke_all_for_user($user_id);

        $passwords = \WebCareProScanner\Auth\ApplicationPasswordSentinel::get_all_passwords();
        $settings  = \WebCareProScanner\Auth\ApplicationPasswordSentinel::get_settings();

        return rest_ensure_response([
            'success'   => true,
            'message'   => __('All Application Passwords for the user were revoked successfully.', 'webcare-pro-security'),
            'passwords' => $passwords,
            'settings'  => $settings,
        ]);
    }

    /**
     * Rate-limiting and anti-enumeration permission check for public WebAuthn routes.
     * Enforces proxy-aware sliding window rate limits per IP and per account.
     *
     * @param \WP_REST_Request $request
     * @return true|\WP_Error
     */
    public static function check_webauthn_public_rate_limit(\WP_REST_Request $request) {
        $client_ip = class_exists('\\WebCareProScanner\\Firewall\\FirewallEngine')
            ? \WebCareProScanner\Firewall\FirewallEngine::get_client_ip()
            : (isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '127.0.0.1');

        $route = (string) $request->get_route();
        $is_verify = strpos($route, 'login-verify') !== false;
        // In verify requests, WebAuthnManager::verify_login() enforces the authoritative attempt rate limit
        if (!$is_verify && class_exists('\\WebCareProScanner\\Auth\\WebAuthnManager')) {
            $max_ip_attempts = 25; // 25 options requests / 5 min
            $window = 300;
            if (!\WebCareProScanner\Auth\WebAuthnManager::check_ip_rate_limit('options', $max_ip_attempts, $window)) {
                return new \WP_Error(
                    'rest_rate_limited',
                    __('Too many authentication requests from this IP. Please wait a few minutes.', 'webcare-pro-security'),
                    ['status' => 429]
                );
            }
        }

        // Per-account + IP composite rate limiting to prevent remote admin lockout DoS
        $params = $request->get_json_params() ?: [];
        $username = !empty($params['username']) ? sanitize_text_field(wp_unslash($params['username'])) : '';
        if (!empty($username)) {
            $client_ip = class_exists('\\WebCareProScanner\\Firewall\\FirewallEngine')
                ? \WebCareProScanner\Firewall\FirewallEngine::get_client_ip()
                : (isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '127.0.0.1');
            $acc_key = 'webcareproscan_wa_acc_' . md5(strtolower($username) . '|' . $client_ip);
            $acc_attempts = (int) get_transient($acc_key);
            if ($acc_attempts >= 15) {
                return new \WP_Error(
                    'rest_account_rate_limited',
                    __('Too many authentication attempts for this account. Please wait a few minutes.', 'webcare-pro-security'),
                    ['status' => 429]
                );
            }
            set_transient($acc_key, $acc_attempts + 1, $window);
        }

        return true;
    }
}
