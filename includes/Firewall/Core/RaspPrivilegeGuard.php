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
        $reason = sprintf('Unauthenticated RASP tamper attempt on core option "%s"', $option);

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
            FirewallEngine::add_blocked_ip(
                $client_ip,
                $reason,
                86400,
                'WAF-RASP-OPTION-TAMPER',
                'Runtime Option Tamper Trap',
                'Runtime RASP Hook Defense',
                $incident_id
            );
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
     * Rule #44: In-Memory RASP Hook Firewall - Abort guest or unprivileged role escalation to administrator.
     *
     * @param int    $user_id   User ID
     * @param string $role      Assigned role
     * @param array  $old_roles Previous roles
     * @return void
     */
    public static function rasp_guard_user_role_assignment(int $user_id, string $role, array $old_roles): void {
        $settings = SettingsManager::get_settings();
        if (empty($settings['waf_enabled']) || empty($settings['waf_runtime_rasp_privilege_guard'])) {
            return;
        }

        if (FirewallEngine::is_trusted_plugin_check_or_cli_runtime()) {
            return;
        }

        $is_elevated_role = self::is_privileged_role($role);

        if ($is_elevated_role) {
            if (FirewallEngine::is_authenticated_administrator()) {
                return;
            }
            if (function_exists('is_user_logged_in') && is_user_logged_in() && function_exists('current_user_can') && current_user_can('manage_options')) {
                return;
            }

            $client_ip = ClientIpResolver::get_client_ip();
            $incident_id = 'WEBCARE-' . strtoupper(substr(md5($client_ip . $role . $user_id . microtime(true)), 0, 8));
            $reason = sprintf('Unauthorized role escalation to "%s" on user #%d', $role, $user_id);

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

            if (!FirewallEngine::is_authenticated_administrator() && !ClientIpResolver::is_server_origin_or_loopback($client_ip)) {
                FirewallEngine::add_blocked_ip(
                    $client_ip,
                    $reason,
                    86400,
                    'WAF-RASP-ROLE-ESCALATION',
                    'Runtime Role Escalation Trap',
                    'Runtime RASP Hook Defense',
                    $incident_id
                );
            }

            wp_die(
                esc_html__('Security Violation: Unauthorized role escalation intercepted by WebCare Runtime RASP.', 'webcare-pro-security'),
                esc_html__('Forbidden', 'webcare-pro-security'),
                ['response' => 403]
            );
        }
    }

    /**
     * Rule #44: In-Memory RASP Hook Firewall - Abort guest registration creating administrator or editor users.
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
        $has_elevated_priv = false;
        if ($user) {
            if (array_intersect(['administrator', 'editor'], array_map('strtolower', (array) $user->roles))) {
                $has_elevated_priv = true;
            } elseif ($user->has_cap('manage_options') || $user->has_cap('edit_users')) {
                $has_elevated_priv = true;
            }
        }
        if ($user && $has_elevated_priv) {
            $user->set_role('subscriber');

            $client_ip = ClientIpResolver::get_client_ip();
            $incident_id = 'WEBCARE-' . strtoupper(substr(md5($client_ip . $user->user_login . $user_id . microtime(true)), 0, 8));
            $reason = sprintf('Unauthenticated registration of elevated account "%s" (#%d)', $user->user_login, $user_id);

            FirewallEngine::log_incident([
                'id'          => 'WAF-RASP-ADMIN-REG-BLOCKED',
                'name'        => 'Runtime Privilege Escalation Guard (Rule #44)',
                'category'    => 'Runtime RASP Hook Defense',
                'description' => sprintf(
                    /* translators: 1: User ID, 2: Client IP */
                    __('Unauthenticated guest from %2$s registered new account (#%1$d) with elevated administrator privileges. Account was demoted to subscriber.', 'webcare-pro-security'),
                    $user_id,
                    $client_ip
                ),
                'match_type'  => 'Guest Admin Registration',
                'match_value' => (string) $user_id,
                'payload'     => "User: {$user->user_login} ID: {$user_id}",
            ], 'blocked', $incident_id);

            if (!FirewallEngine::is_authenticated_administrator() && !ClientIpResolver::is_server_origin_or_loopback($client_ip)) {
                FirewallEngine::add_blocked_ip(
                    $client_ip,
                    $reason,
                    86400,
                    'WAF-RASP-ADMIN-REG-BLOCKED',
                    'Unauthorized Admin Registration Trap',
                    'Runtime RASP Hook Defense',
                    $incident_id
                );
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

        $guarded_keys = [
            '_application_passwords',
            $orig_prefix . 'capabilities',
            $orig_prefix . 'user_level',
        ];
        if ($active_prefix !== $orig_prefix) {
            $guarded_keys[] = $active_prefix . 'capabilities';
            $guarded_keys[] = $active_prefix . 'user_level';
        }

        if (!in_array($meta_key, $guarded_keys, true)) {
            return $check;
        }

        if (FirewallEngine::is_trusted_plugin_check_or_cli_runtime() || FirewallEngine::is_authenticated_administrator()) {
            return $check;
        }

        if (function_exists('is_user_logged_in') && is_user_logged_in()) {
            if (FirewallEngine::is_authenticated_administrator()) {
                return $check;
            }
            if (function_exists('current_user_can') && (current_user_can('manage_options') || current_user_can('edit_user', $object_id))) {
                return $check;
            }
        }

        if ($meta_key === $prefix . 'capabilities' || $meta_key === $prefix . 'user_level') {
            $is_safe_registration_mutation = false;

            if ($meta_key === $prefix . 'capabilities' && is_array($meta_value)) {
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
            } elseif ($meta_key === $prefix . 'user_level') {
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
                            if ($meta_key === $prefix . 'capabilities' && is_array($meta_value) && empty($has_admin_privilege)) {
                                $is_safe_registration_mutation = true;
                                break;
                            } elseif ($meta_key === $prefix . 'user_level' && (int) $meta_value < 7) {
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
            $existing = get_user_meta($object_id, '_application_passwords', true);
            if (is_array($existing) && is_array($meta_value) && count($existing) === count($meta_value)) {
                $existing_map = [];
                foreach ($existing as $item) {
                    if (isset($item['uuid'], $item['password'])) {
                        $existing_map[$item['uuid']] = $item['password'];
                    }
                }

                $is_only_usage_ping = true;
                foreach ($meta_value as $new_item) {
                    $uuid = $new_item['uuid'] ?? '';
                    $pass = $new_item['password'] ?? '';
                    if (!isset($existing_map[$uuid]) || !hash_equals((string) $existing_map[$uuid], (string) $pass)) {
                        $is_only_usage_ping = false;
                        break;
                    }
                }

                if ($is_only_usage_ping) {
                    return $check;
                }
            }
        }

        $client_ip = ClientIpResolver::get_client_ip();
        $incident_id = 'WEBCARE-' . strtoupper(substr(md5($client_ip . $meta_key . $object_id . microtime(true)), 0, 8));
        $reason = sprintf('Unauthenticated usermeta injection on "%s" for user #%d', $meta_key, $object_id);

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
            FirewallEngine::add_blocked_ip(
                $client_ip,
                $reason,
                86400,
                'WAF-RASP-META-INJECTION',
                'Runtime Usermeta Privilege Trap',
                'Runtime RASP Hook Defense',
                $incident_id
            );
        }

        return false;
    }
}
