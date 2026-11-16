<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall\Core;

use WebCareProScanner\Firewall\FirewallEngine;
use WebCareProScanner\System\SettingsManager;

/**
 * Runtime Application Self-Protection (RASP) Privilege Guard.
 *
 * Traps in-memory option mutations, user role escalations, unauthorized admin registrations,
 * and usermeta injection payloads in real time.
 *
 * @package WebCareProScanner\Firewall\Core
 */
class RaspPrivilegeGuard {

    private static array $role_rollback_in_progress = [];

    /**
     * Record a RASP violation as a behavioral signal without creating an automated IP ban.
     *
     * @param string $client_ip
     * @return void
     */
    private static function record_rasp_behavioral_signal(string $client_ip): void {
        if (class_exists('\WebCareProScanner\Firewall\CAF\ThreatScoreTracker')) {
            \WebCareProScanner\Firewall\CAF\ThreatScoreTracker::record_event($client_ip, 'behavioral_anomaly', 25.0);
        }
    }

    /**
     * Rule #44: In-Memory RASP Hook Firewall - Prevent guest or unprivileged option tampering.
     *
     * @param mixed  $value
     * @param string $option
     * @param mixed  $old_value
     * @return mixed
     */
    public static function rasp_guard_critical_options($value, $option, $old_value) {
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_enabled']) || empty($settings['waf_runtime_rasp_privilege_guard'])) {
            return $value;
        }

        $guarded_options = [
            'users_can_register',
            'default_role',
            'siteurl',
            'home',
            'active_plugins',
            'admin_email',
        ];

        // Fast-path: Only inspect targeted critical privilege options
        if (!in_array($option, $guarded_options, true)) {
            return $value;
        }

        // Only allow trusted server-side runtimes or verified admins
        if (FirewallEngine::is_trusted_plugin_check_or_cli_runtime()) {
            return $value;
        }
        if (FirewallEngine::is_authenticated_administrator()) {
            return $value;
        }
        if (function_exists('is_user_logged_in') && is_user_logged_in() && function_exists('current_user_can') && current_user_can('manage_options')) {
            return $value;
        }

        $client_ip = ClientIpResolver::get_client_ip();
        $incident_id = 'WEBCARE-' . strtoupper(substr(md5($client_ip . $option . microtime(true)), 0, 8));
        FirewallEngine::log_incident([
            'id'          => 'WAF-RASP-OPTION-TAMPER',
            'name'        => 'Runtime Privilege Escalation Guard (Rule #44)',
            'category'    => 'Runtime RASP Hook Defense',
            'description' => sprintf(
                /* translators: 1: Option name, 2: Client IP */
                __('Unauthenticated request from %2$s attempted unauthorized runtime tampering with core option "%1$s".', 'webcare-pro-security'),
                $option,
                $client_ip
            ),
            'match_type'  => 'Unauthorized Option Mutation',
            'match_value' => $option,
            'payload'     => "Option: {$option} Attempted Value: " . substr(wp_json_encode($value), 0, 100),
        ], 'blocked', $incident_id);

        if (!FirewallEngine::is_authenticated_administrator() && !ClientIpResolver::is_server_origin_or_loopback($client_ip)) {
            self::record_rasp_behavioral_signal($client_ip);
        }

        // Hard Inviolable Revert: return the old value immediately
        return $old_value;
    }

    /**
     * Determines whether a capability name belongs to an administrative or elevated permission namespace.
     *
     * @param string $cap
     * @return bool
     */
    public static function is_privileged_capability(string $cap): bool {
        $c = strtolower(trim($cap));
        if ($c === '') {
            return false;
        }

        // 1. Explicit Core & Major Plugin administrative capabilities
        $known_privileged = [
            'manage_options',
            'edit_users',
            'promote_users',
            'create_users',
            'delete_users',
            'list_users',
            'remove_users',
            'edit_plugins',
            'activate_plugins',
            'delete_plugins',
            'install_plugins',
            'update_plugins',
            'edit_themes',
            'switch_themes',
            'delete_themes',
            'install_themes',
            'update_themes',
            'edit_files',
            'unfiltered_html',
            'unfiltered_upload',
            'export',
            'import',
            'manage_network',
            'manage_network_users',
            'manage_network_plugins',
            'manage_network_themes',
            'manage_network_options',
            'manage_woocommerce',
            'view_woocommerce_reports',
            'edit_shop_orders',
            'edit_others_shop_orders',
            'delete_shop_orders',
            'delete_others_shop_orders',
            'edit_others_products',
            'delete_others_products',
            'edit_others_posts',
            'edit_others_pages',
            'edit_private_posts',
            'edit_private_pages',
            'edit_published_posts',
            'edit_published_pages',
            'publish_pages',
            'publish_posts',
            'administrator',
        ];

        if (in_array($c, $known_privileged, true)) {
            return true;
        }

        // 2. Dynamic prefix evaluation for privileged administrative namespaces
        $privileged_prefixes = [
            'manage_network_',
            'manage_options',
            'manage_sites',
            'manage_woocommerce',
            'manage_security',
            'manage_webcare',
            'edit_users',
            'edit_plugins',
            'edit_themes',
            'edit_files',
            'edit_others_',
            'delete_users',
            'delete_plugins',
            'delete_themes',
            'delete_others_',
            'activate_',
            'install_',
            'update_',
            'unfiltered_',
            'publish_',
        ];

        foreach ($privileged_prefixes as $p) {
            if (str_starts_with($c, $p)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Deep-inspect a role name or role object to determine if it grants elevated/privileged capabilities.
     *
     * @param string $role
     * @return bool
     */
    public static function is_privileged_role(string $role): bool {
        $r = strtolower(trim($role));
        if ($r === '') {
            return false;
        }

        // 1. Known inherently elevated administrative / publishing roles
        if (in_array($r, ['administrator', 'editor', 'author', 'shop_manager', 'super_admin'], true)) {
            return true;
        }

        // 2. If the identifier itself is a privileged capability
        if (self::is_privileged_capability($r)) {
            return true;
        }

        // Elevated legacy user levels (level_2 = Author, level_7 = Editor, level_10 = Admin)
        $elevated_levels = ['level_2', 'level_3', 'level_4', 'level_5', 'level_6', 'level_7', 'level_8', 'level_9', 'level_10'];
        if (in_array($r, $elevated_levels, true)) {
            return true;
        }

        // 3. Always inspect actual registered role capabilities if get_role() is available
        if (function_exists('get_role')) {
            $role_obj = get_role($role);
            if ($role_obj instanceof \WP_Role && is_array($role_obj->capabilities)) {
                foreach ($role_obj->capabilities as $cap => $granted) {
                    if (!$granted) {
                        continue;
                    }
                    $cap_lower = strtolower((string) $cap);
                    if (self::is_privileged_capability($cap_lower) || in_array($cap_lower, $elevated_levels, true)) {
                        return true;
                    }
                }

                return false;
            }
        }

        return false;
    }

    /**
     * Determine if a WP_User instance holds any elevated or privileged roles or capabilities.
     *
     * @param \WP_User $user
     * @return bool
     */
    public static function is_user_privileged(\WP_User $user): bool {
        // 1. Direct core administrative capabilities check
        $core_priv_caps = [
            'manage_options',
            'administrator',
            'edit_users',
            'promote_users',
            'delete_users',
            'manage_woocommerce',
            'edit_plugins',
            'activate_plugins',
            'install_plugins',
            'edit_themes',
            'switch_themes',
        ];
        foreach ($core_priv_caps as $pcap) {
            if ($user->has_cap($pcap)) {
                return true;
            }
        }

        // 2. Inspect all assigned roles
        if (!empty($user->roles) && is_array($user->roles)) {
            foreach ($user->roles as $role) {
                if (self::is_privileged_role((string) $role)) {
                    return true;
                }
            }
        }

        // 3. Inspect effective capabilities across all roles and user-specific caps
        if (!empty($user->allcaps) && is_array($user->allcaps)) {
            foreach ($user->allcaps as $cap => $granted) {
                if ($granted && self::is_privileged_capability((string) $cap)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Verify whether a target user was authentically registered within the allowed registration window.
     *
     * @param \WP_User $user
     * @param int      $max_age_seconds Default 120 seconds
     * @return bool
     */
    public static function is_within_registration_window(\WP_User $user, int $max_age_seconds = 120): bool {
        $raw_reg = (string) $user->user_registered;

        if (
            $raw_reg === ''
            || $raw_reg === '0000-00-00 00:00:00'
            || str_contains($raw_reg, "\0")
            || $raw_reg !== trim($raw_reg)
        ) {
            return false;
        }

        try {
            $dt = \DateTimeImmutable::createFromFormat('!Y-m-d H:i:s', $raw_reg, new \DateTimeZone('UTC'));
            $errors = \DateTimeImmutable::getLastErrors();
            if (
                $dt === false
                || ($errors !== false && ($errors['warning_count'] > 0 || $errors['error_count'] > 0))
                || $dt->format('Y-m-d H:i:s') !== $raw_reg
            ) {
                return false;
            }
        } catch (\Throwable $e) {
            return false;
        }

        $reg_ts = $dt->getTimestamp();
        if ($reg_ts <= 0) {
            return false;
        }

        $now = time();
        $age = $now - $reg_ts;

        if ($age < -5) {
            return false;
        }

        if ($age > $max_age_seconds) {
            return false;
        }

        return true;
    }

    /**
     * Defense-in-depth for direct WP_User::add_role() and remove_role() calls.
     * The set_role() API has a richer post-change hook and is handled by its existing snapshot guard.
     *
     * @param int    $user_id User ID
     * @param string $role    Role being added or removed
     * @param string $action  Either 'add' or 'remove'
     * @return void
     */
    public static function rasp_guard_user_role_api_mutation(int $user_id, string $role, string $action): void {
        if (!in_array($action, ['add', 'remove'], true) || !empty(self::$role_rollback_in_progress[$user_id])) {
            return;
        }

        // WP_User::set_role() triggers these action hooks as an implementation detail; its
        // set_user_role hook below validates the complete old-role snapshot and performs rollback.
        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_debug_backtrace -- Distinguish direct role API calls from the separately guarded set_role operation.
        $frames = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 12);
        foreach ($frames as $frame) {
            if (($frame['class'] ?? '') === 'WP_User' && ($frame['function'] ?? '') === 'set_role') {
                return;
            }
        }

        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_enabled']) || empty($settings['waf_runtime_rasp_privilege_guard'])) {
            return;
        }
        if (!self::is_privileged_role($role) || FirewallEngine::is_trusted_plugin_check_or_cli_runtime()) {
            return;
        }
        if (FirewallEngine::is_authenticated_administrator()) {
            return;
        }
        if (function_exists('is_user_logged_in') && is_user_logged_in() && function_exists('current_user_can') && current_user_can('manage_options')) {
            return;
        }

        $user = function_exists('get_userdata') ? get_userdata($user_id) : null;
        if (!($user instanceof \WP_User)) {
            return;
        }

        self::$role_rollback_in_progress[$user_id] = true;
        try {
            if ($action === 'add') {
                $user->remove_role($role);
            } else {
                $user->add_role($role);
            }
        } finally {
            unset(self::$role_rollback_in_progress[$user_id]);
        }

        $client_ip = ClientIpResolver::get_client_ip();
        $incident_id = 'WEBCARE-' . strtoupper(substr(md5($client_ip . $role . $user_id . $action . microtime(true)), 0, 8));
        FirewallEngine::log_incident([
            'id'          => 'WAF-RASP-ROLE-API-' . strtoupper($action),
            'name'        => 'Runtime Privilege Role API Guard (Rule #44)',
            'category'    => 'Runtime RASP Hook Defense',
            'description' => sprintf(
                /* translators: 1: action, 2: role, 3: user ID, 4: client IP */
                __('Unauthorized session from %4$s attempted to %1$s privileged role "%2$s" for user #%3$d.', 'webcare-pro-security'),
                $action,
                $role,
                $user_id,
                $client_ip
            ),
            'match_type'  => 'Privileged Role API Mutation',
            'match_value' => $role,
            'payload'     => "Action: {$action} User ID: {$user_id} Role: {$role}",
        ], 'blocked', $incident_id);

        if (!ClientIpResolver::is_server_origin_or_loopback($client_ip)) {
            self::record_rasp_behavioral_signal($client_ip);
        }

        wp_die(
            esc_html__('Security Violation: Unauthorized role modification intercepted by WebCare Runtime RASP.', 'webcare-pro-security'),
            esc_html__('Forbidden', 'webcare-pro-security'),
            ['response' => 403]
        );
    }

    /**
     * Rule #44: In-Memory RASP Hook Firewall - Abort guest or unprivileged role escalation.
     *
     * @param int    $user_id   User ID
     * @param string $role      Assigned role
     * @param array  $old_roles Previous roles
     * @return void
     */
    public static function rasp_guard_user_role_assignment(int $user_id, string $role, array $old_roles): void {
        if (!empty(self::$role_rollback_in_progress[$user_id])) {
            return;
        }

        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_enabled']) || empty($settings['waf_runtime_rasp_privilege_guard'])) {
            return;
        }

        if (FirewallEngine::is_trusted_plugin_check_or_cli_runtime()) {
            return;
        }

        // Evaluate full effective capability set of the requested role.
        // Ordinary customer/subscriber/member/LMS roles return false here and execute unhindered
        // across storefront, Shop Manager, and DOING_CRON (WooCommerce Subscriptions) workflows.
        $is_elevated_role = self::is_privileged_role($role);

        // Also check if previous roles were privileged to protect administrators from unauthorized demotion
        $previous_roles = [];
        $was_privileged = false;
        $prev_privileged_role = null;
        if (!empty($old_roles) && is_array($old_roles)) {
            foreach ($old_roles as $old_role) {
                if (!is_string($old_role) || $old_role === '' || in_array($old_role, $previous_roles, true)) {
                    continue;
                }
                $previous_roles[] = $old_role;
                if (self::is_privileged_role($old_role)) {
                    $was_privileged = true;
                    $prev_privileged_role = $prev_privileged_role ?? $old_role;
                }
            }
        }

        // Also check if the target user currently holds privileged capabilities (protect admins from non-admin demotion/tampering)
        $target_user = function_exists('get_userdata') ? get_userdata($user_id) : null;
        $target_is_privileged = ($target_user instanceof \WP_User) && self::is_user_privileged($target_user);

        if ($is_elevated_role || $target_is_privileged || $was_privileged) {
            if (FirewallEngine::is_authenticated_administrator()) {
                return;
            }
            if (function_exists('is_user_logged_in') && is_user_logged_in() && function_exists('current_user_can') && current_user_can('manage_options')) {
                return;
            }

            // Note: Neither DOING_CRON nor Shop Managers (manage_woocommerce without manage_options)
            // are ever permitted to assign a privileged role ($is_elevated_role === true) or mutate/demote an existing privileged account.
            $client_ip = ClientIpResolver::get_client_ip();
            $incident_id = 'WEBCARE-' . strtoupper(substr(md5($client_ip . $role . $user_id . microtime(true)), 0, 8));

            if ($was_privileged && !$is_elevated_role) {
                // Restore every role from the pre-change snapshot while the actual FirewallEngine callback is detached.
                if ($target_user instanceof \WP_User && !empty($previous_roles)) {
                    self::$role_rollback_in_progress[$user_id] = true;
                    $role_callback = [FirewallEngine::class, 'rasp_guard_user_role_assignment'];
                    $role_callback_priority = false;
                    $role_callback_removed = false;

                    try {
                        if (function_exists('has_action')) {
                            $role_callback_priority = has_action('set_user_role', $role_callback);
                            $role_callback_removed = $role_callback_priority !== false && remove_action('set_user_role', $role_callback, (int) $role_callback_priority);
                        }
                        $target_user->set_role($previous_roles[0]);
                        foreach (array_slice($previous_roles, 1) as $previous_role) {
                            $target_user->add_role($previous_role);
                        }
                    } finally {
                        if ($role_callback_removed) {
                            add_action('set_user_role', $role_callback, (int) $role_callback_priority, 3);
                        }
                        unset(self::$role_rollback_in_progress[$user_id]);
                    }
                }

                FirewallEngine::log_incident([
                    'id'          => 'WAF-RASP-ROLE-DEMOTION',
                    'name'        => 'Runtime Privilege Demotion Guard (Rule #44)',
                    'category'    => 'Runtime RASP Hook Defense',
                    'description' => sprintf(
                        /* translators: 1: Previous role, 2: User ID, 3: Client IP, 4: Target role */
                        __('Unauthorized session from %3$s attempted to demote privileged user #%2$d (previous role: "%1$s") to "%4$s" without manage_options capability.', 'webcare-pro-security'),
                        $prev_privileged_role,
                        $user_id,
                        $client_ip,
                        $role
                    ),
                    'match_type'  => 'Privilege Demotion Intercept',
                    'match_value' => $role,
                    'payload'     => "User ID: {$user_id} Target Role: {$role} Previous Role: {$prev_privileged_role} Caller: Guest / Non-Admin",
                ], 'blocked', $incident_id);
            } else {
                FirewallEngine::log_incident([
                    'id'          => 'WAF-RASP-ROLE-ESCALATION',
                    'name'        => 'Runtime Privilege Escalation Guard (Rule #44)',
                    'category'    => 'Runtime RASP Hook Defense',
                    'description' => sprintf(
                        /* translators: 1: Role, 2: User ID, 3: Client IP */
                        __('Unauthorized session from %3$s attempted to assign "%1$s" role to user #%2$d without manage_options capability.', 'webcare-pro-security'),
                        $role,
                        $user_id,
                        $client_ip
                    ),
                    'match_type'  => 'Privilege Escalation Intercept',
                    'match_value' => $role,
                    'payload'     => "User ID: {$user_id} Target Role: {$role} Caller: Guest / Non-Admin",
                ], 'blocked', $incident_id);
            }

            if (!FirewallEngine::is_authenticated_administrator() && !ClientIpResolver::is_server_origin_or_loopback($client_ip)) {
                self::record_rasp_behavioral_signal($client_ip);
            }

            wp_die(
                esc_html__('Security Violation: Unauthorized role modification intercepted by WebCare Runtime RASP.', 'webcare-pro-security'),
                esc_html__('Forbidden', 'webcare-pro-security'),
                ['response' => 403]
            );
        }
    }

    /**
     * Rule #44: In-Memory RASP Hook Firewall - Abort guest or cron registration creating privileged users.
     *
     * @param int $user_id
     * @return void
     */
    public static function rasp_guard_user_registration(int $user_id): void {
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_enabled']) || empty($settings['waf_runtime_rasp_privilege_guard'])) {
            return;
        }

        if (FirewallEngine::is_trusted_plugin_check_or_cli_runtime()) {
            return;
        }

        if (FirewallEngine::is_authenticated_administrator()) {
            return;
        }
        if (function_exists('is_user_logged_in') && is_user_logged_in() && function_exists('current_user_can') && current_user_can('manage_options')) {
            return;
        }

        $user = function_exists('get_userdata') ? get_userdata($user_id) : null;
        $has_elevated_priv = ($user instanceof \WP_User) && self::is_user_privileged($user);

        if ($user && $has_elevated_priv) {
            $user->set_role('subscriber');

            $client_ip = ClientIpResolver::get_client_ip();
            $incident_id = 'WEBCARE-' . strtoupper(substr(md5($client_ip . $user->user_login . $user_id . microtime(true)), 0, 8));
            FirewallEngine::log_incident([
                'id'          => 'WAF-RASP-ADMIN-REG-BLOCKED',
                'name'        => 'Runtime Privilege Escalation Guard (Rule #44)',
                'category'    => 'Runtime RASP Hook Defense',
                'description' => sprintf(
                    /* translators: 1: User ID, 2: Client IP */
                    __('Unauthenticated session from %2$s registered new account (#%1$d) with elevated privileges. Account was demoted to subscriber.', 'webcare-pro-security'),
                    $user_id,
                    $client_ip
                ),
                'match_type'  => 'Guest Admin Registration',
                'match_value' => (string) $user_id,
                'payload'     => "User: {$user->user_login} ID: {$user_id}",
            ], 'blocked', $incident_id);

            if (!FirewallEngine::is_authenticated_administrator() && !ClientIpResolver::is_server_origin_or_loopback($client_ip)) {
                self::record_rasp_behavioral_signal($client_ip);
            }
        }
    }

    /**
     * Rule #44: In-Memory RASP Hook Firewall - Abort guest or unprivileged metadata injection into critical usermeta.
     *
     * @param null|bool $check      Whether to allow updating/adding metadata
     * @param int       $object_id  User ID
     * @param string    $meta_key   Metadata key
     * @param mixed     $meta_value Metadata value
     * @param mixed     $prev_value Previous value
     * @return null|bool null to proceed with core update, false to abort
     */
    public static function rasp_guard_user_metadata_injection($check, int $object_id, string $meta_key, $meta_value, $prev_value = '') {
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_enabled']) || empty($settings['waf_runtime_rasp_privilege_guard'])) {
            return $check;
        }

        $orig_prefix   = FirewallEngine::get_original_table_prefix();
        global $wpdb;
        $active_prefix = isset($wpdb->base_prefix) ? $wpdb->base_prefix : (isset($wpdb->prefix) ? $wpdb->prefix : 'wp_');
        $prefix        = $orig_prefix;

        $cap_keys = [$orig_prefix . 'capabilities'];
        $lvl_keys = [$orig_prefix . 'user_level'];
        if ($active_prefix !== $orig_prefix) {
            $cap_keys[] = $active_prefix . 'capabilities';
            $lvl_keys[] = $active_prefix . 'user_level';
        }

        $guarded_keys = array_merge(['_application_passwords'], $cap_keys, $lvl_keys);

        // Ordinary customer metadata (billing_*, shipping_*, paying_customer, etc.) is never in $guarded_keys
        // and returns immediately here with zero friction for Shop Managers, customers, and cron jobs.
        if (!in_array($meta_key, $guarded_keys, true)) {
            return $check;
        }

        // A guarded role demotion rollback must be able to restore its own capabilities and user level.
        // Keep this bypass limited to those role metadata keys for the same user being rolled back.
        if (
            !empty(self::$role_rollback_in_progress[$object_id])
            && (in_array($meta_key, $cap_keys, true) || in_array($meta_key, $lvl_keys, true))
        ) {
            return $check;
        }

        if (FirewallEngine::is_trusted_plugin_check_or_cli_runtime() || FirewallEngine::is_authenticated_administrator()) {
            return $check;
        }

        if (function_exists('is_user_logged_in') && is_user_logged_in() && function_exists('current_user_can')) {
            if (current_user_can('manage_options')) {
                return $check;
            }
        }

        $target_user          = function_exists('get_userdata') ? get_userdata($object_id) : null;
        $target_is_privileged = ($target_user instanceof \WP_User) && self::is_user_privileged($target_user);

        // Evaluate whether the requested capabilities or user_level payload is strictly unprivileged
        $payload_is_unprivileged = false;
        if (in_array($meta_key, $cap_keys, true) && is_array($meta_value)) {
            $requested_roles = array_keys(array_filter($meta_value));
            $has_elevated_cap = false;
            foreach ($requested_roles as $role_or_cap) {
                if (self::is_privileged_role((string) $role_or_cap)) {
                    $has_elevated_cap = true;
                    break;
                }
            }
            $payload_is_unprivileged = !$has_elevated_cap;
        } elseif (in_array($meta_key, $lvl_keys, true)) {
            $payload_is_unprivileged = ((int) $meta_value <= 1);
        }

        // Narrowly Scoped Shop Manager & Cron Allowance:
        // 1. NEVER allow non-admin or cron to mutate _application_passwords (handled solely by the verified Core REST usage-ping check below).
        // 2. NEVER allow non-admin or cron to mutate an existing privileged user ($target_is_privileged === true).
        // 3. NEVER allow non-admin or cron to write any privileged capability or user_level > 1 ($payload_is_unprivileged must be true).
        if ($meta_key !== '_application_passwords' && !$target_is_privileged && $payload_is_unprivileged) {
            // Case A: Authenticated Shop Manager (manage_woocommerce) updating a non-privileged customer's role/capabilities to another non-privileged role
            if (function_exists('is_user_logged_in') && is_user_logged_in() && function_exists('current_user_can') && current_user_can('manage_woocommerce')) {
                return $check;
            }

            // Case B: Background Cron (DOING_CRON) updating a non-privileged subscriber/customer to another non-privileged role
            // (e.g. WooCommerce Subscriptions renewal, MemberPress/LearnDash/LifterLMS expiration) when no untrusted HTTP role parameters exist
            if (defined('DOING_CRON') && DOING_CRON) {
                // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended
                if (empty($_POST['role']) && empty($_GET['role']) && empty($_POST['new_role']) && empty($_POST['wp_capabilities'])) {
                    return $check;
                }
            }
        }

        if (in_array($meta_key, $cap_keys, true) || in_array($meta_key, $lvl_keys, true)) {
            $is_safe_registration_mutation = false;

            if (in_array($meta_key, $cap_keys, true) && is_array($meta_value)) {
                $requested_roles = array_keys(array_filter($meta_value));
                $has_admin_privilege = false;
                foreach ($requested_roles as $role_or_cap) {
                    if (self::is_privileged_role((string) $role_or_cap)) {
                        $has_admin_privilege = true;
                        break;
                    }
                }

                if (!$has_admin_privilege) {
                    $user_obj = function_exists('get_userdata') ? get_userdata($object_id) : null;
                    if ($user_obj instanceof \WP_User && self::is_within_registration_window($user_obj, 120)) {
                        $is_safe_registration_mutation = true;
                    }
                }
            } elseif (in_array($meta_key, $lvl_keys, true)) {
                $level = (int) $meta_value;
                if ($level <= 1) {
                    $user_obj = function_exists('get_userdata') ? get_userdata($object_id) : null;
                    if ($user_obj instanceof \WP_User && self::is_within_registration_window($user_obj, 120)) {
                        $is_safe_registration_mutation = true;
                    }
                }
            }

            if (!$is_safe_registration_mutation && function_exists('debug_backtrace')) {
                $user_obj = function_exists('get_userdata') ? get_userdata($object_id) : null;
                $is_new_account = ($user_obj instanceof \WP_User && self::is_within_registration_window($user_obj, 120));

                if ($is_new_account) {
                    // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_debug_backtrace -- Context inspection required to distinguish legitimate WordPress core registration from raw unauthenticated SQL/HTTP privilege injections.
                    $trace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 40);
                    foreach ($trace as $frame) {
                        $fn  = $frame['function'] ?? '';
                        $cls = $frame['class'] ?? '';
                        if (
                            $fn === 'wp_insert_user' ||
                            $fn === 'wp_create_user' ||
                            $fn === 'register_new_user' ||
                            ($cls === 'WP_User' && $fn === 'set_role')
                        ) {
                            if (in_array($meta_key, $cap_keys, true) && is_array($meta_value) && empty($has_admin_privilege)) {
                                $is_safe_registration_mutation = true;
                                break;
                            } elseif (in_array($meta_key, $lvl_keys, true) && (int) $meta_value < 7) {
                                $is_safe_registration_mutation = true;
                                break;
                            }
                        }
                    }
                }
            }

            if ($is_safe_registration_mutation) {
                return $check;
            }
        }

        if ($meta_key === '_application_passwords') {
            $existing = !empty($prev_value) && is_array($prev_value) ? $prev_value : get_user_meta($object_id, '_application_passwords', true);
            if (is_array($existing) && is_array($meta_value) && count($existing) === count($meta_value)) {
                $existing_map = [];
                $existing_uuid_set_valid = true;
                foreach ($existing as $item) {
                    if (!is_array($item) || !isset($item['uuid']) || !is_string($item['uuid']) || $item['uuid'] === '' || isset($existing_map[$item['uuid']])) {
                        $existing_uuid_set_valid = false;
                        break;
                    }
                    $existing_map[$item['uuid']] = $item;
                }

                $is_only_usage_ping = $existing_uuid_set_valid;
                $updated_uuid_set = [];
                if ($is_only_usage_ping) {
                    foreach ($meta_value as $new_item) {
                        if (!is_array($new_item) || !isset($new_item['uuid']) || !is_string($new_item['uuid']) || $new_item['uuid'] === '' || isset($updated_uuid_set[$new_item['uuid']])) {
                            $is_only_usage_ping = false;
                            break;
                        }

                        $uuid = $new_item['uuid'];
                        if (!isset($existing_map[$uuid])) {
                            $is_only_usage_ping = false;
                            break;
                        }
                        $updated_uuid_set[$uuid] = true;
                        $old_item = $existing_map[$uuid];

                        // WordPress application-password usage recording may update only last_used and last_ip.
                        // Preserve the exact field set and every other value, including app_id and the password hash.
                        if (
                            count($new_item) !== count($old_item) ||
                            count(array_diff_key($new_item, $old_item)) > 0 ||
                            count(array_diff_key($old_item, $new_item)) > 0
                        ) {
                            $is_only_usage_ping = false;
                            break;
                        }

                        foreach ($old_item as $field => $old_value) {
                            if ($field === 'last_used' || $field === 'last_ip') {
                                continue;
                            }
                            if (!array_key_exists($field, $new_item)) {
                                $is_only_usage_ping = false;
                                break 2;
                            }
                            if ($field === 'password') {
                                if (!is_string($old_value) || !is_string($new_item[$field]) || !hash_equals($old_value, $new_item[$field])) {
                                    $is_only_usage_ping = false;
                                    break 2;
                                }
                            } elseif ($new_item[$field] !== $old_value) {
                                $is_only_usage_ping = false;
                                break 2;
                            }
                        }

                        if (array_key_exists('last_used', $new_item) && $new_item['last_used'] !== ($old_item['last_used'] ?? null)) {
                            if ($new_item['last_used'] !== null && (!is_int($new_item['last_used']) || $new_item['last_used'] < 0)) {
                                $is_only_usage_ping = false;
                                break;
                            }
                            if (is_int($old_item['last_used'] ?? null) && is_int($new_item['last_used']) && $new_item['last_used'] < $old_item['last_used']) {
                                $is_only_usage_ping = false;
                                break;
                            }
                        }

                        if (array_key_exists('last_ip', $new_item) && $new_item['last_ip'] !== ($old_item['last_ip'] ?? null)) {
                            $new_last_ip = $new_item['last_ip'];
                            if ($new_last_ip !== null && (!is_string($new_last_ip) || filter_var($new_last_ip, FILTER_VALIDATE_IP) === false)) {
                                $is_only_usage_ping = false;
                                break;
                            }
                        }
                    }
                }

                if ($is_only_usage_ping && count($updated_uuid_set) === count($existing_map)) {
                    return $check;
                }
            }
        }

        $client_ip = ClientIpResolver::get_client_ip();
        $incident_id = 'WEBCARE-' . strtoupper(substr(md5($client_ip . $meta_key . $object_id . microtime(true)), 0, 8));
        FirewallEngine::log_incident([
            'id'          => 'WAF-RASP-META-INJECTION',
            'name'        => 'Runtime Privilege Escalation Guard (Rule #44)',
            'category'    => 'Runtime RASP Hook Defense',
            'description' => sprintf(
                /* translators: 1: Meta key, 2: User ID, 3: Client IP */
                __('Unauthenticated request from %3$s attempted unauthorized runtime usermeta injection into "%1$s" for user #%2$d.', 'webcare-pro-security'),
                $meta_key,
                $object_id,
                $client_ip
            ),
            'match_type'  => 'Unauthorized Usermeta Mutation',
            'match_value' => $meta_key,
            'payload'     => "User: {$object_id} Meta: {$meta_key}",
        ], 'blocked', $incident_id);

        if (!FirewallEngine::is_authenticated_administrator() && !ClientIpResolver::is_server_origin_or_loopback($client_ip)) {
            self::record_rasp_behavioral_signal($client_ip);
        }

        return false;
    }

    /**
     * Block unauthorized deletion of role capability, user-level, and application-password metadata.
     *
     * @param null|bool $check       Whether to allow deletion
     * @param int       $object_id   User ID
     * @param string    $meta_key    Metadata key
     * @param mixed     $meta_value Value to match
     * @param bool      $delete_all Whether all matching metadata is being deleted
     * @return null|bool null to proceed with core deletion, false to abort
     */
    public static function rasp_guard_user_metadata_deletion($check, int $object_id, string $meta_key, $meta_value, bool $delete_all = false) {
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_enabled']) || empty($settings['waf_runtime_rasp_privilege_guard'])) {
            return $check;
        }

        $original_prefix = FirewallEngine::get_original_table_prefix();
        global $wpdb;
        $active_prefix = isset($wpdb->base_prefix) ? $wpdb->base_prefix : (isset($wpdb->prefix) ? $wpdb->prefix : 'wp_');
        $capability_keys = [$original_prefix . 'capabilities'];
        $user_level_keys = [$original_prefix . 'user_level'];
        if ($active_prefix !== $original_prefix) {
            $capability_keys[] = $active_prefix . 'capabilities';
            $user_level_keys[] = $active_prefix . 'user_level';
        }

        $guarded_keys = array_merge(['_application_passwords'], $capability_keys, $user_level_keys);
        if (!in_array($meta_key, $guarded_keys, true)) {
            return $check;
        }
        if (
            !empty(self::$role_rollback_in_progress[$object_id])
            && (in_array($meta_key, $capability_keys, true) || in_array($meta_key, $user_level_keys, true))
        ) {
            return $check;
        }
        if (FirewallEngine::is_trusted_plugin_check_or_cli_runtime() || FirewallEngine::is_authenticated_administrator()) {
            return $check;
        }
        if (function_exists('is_user_logged_in') && is_user_logged_in() && function_exists('current_user_can') && current_user_can('manage_options')) {
            return $check;
        }

        $client_ip = ClientIpResolver::get_client_ip();
        $incident_id = 'WEBCARE-' . strtoupper(substr(md5($client_ip . $meta_key . $object_id . 'delete' . microtime(true)), 0, 8));
        FirewallEngine::log_incident([
            'id'          => 'WAF-RASP-META-DELETION',
            'name'        => 'Runtime Critical Usermeta Deletion Guard (Rule #44)',
            'category'    => 'Runtime RASP Hook Defense',
            'description' => sprintf(
                /* translators: 1: meta key, 2: user ID, 3: client IP */
                __('Unauthorized request from %3$s attempted to delete protected usermeta "%1$s" for user #%2$d.', 'webcare-pro-security'),
                $meta_key,
                $object_id,
                $client_ip
            ),
            'match_type'  => 'Unauthorized Usermeta Deletion',
            'match_value' => $meta_key,
            'payload'     => sprintf('User ID: %d Meta: %s Delete all: %s', $object_id, $meta_key, $delete_all ? 'yes' : 'no'),
        ], 'blocked', $incident_id);

        if (!ClientIpResolver::is_server_origin_or_loopback($client_ip)) {
            self::record_rasp_behavioral_signal($client_ip);
        }

        return false;
    }
}
