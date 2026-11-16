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
     * Rule #44: In-Memory RASP Hook Firewall - Abort guest or unprivileged role escalation.
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

        // Evaluate full effective capability set of the requested role.
        // Ordinary customer/subscriber/member/LMS roles return false here and execute unhindered
        // across storefront, Shop Manager, and DOING_CRON (WooCommerce Subscriptions) workflows.
        $is_elevated_role = self::is_privileged_role($role);

        // Also check if previous roles were privileged to protect administrators from unauthorized demotion
        $was_privileged = false;
        $prev_privileged_role = null;
        if (!empty($old_roles) && is_array($old_roles)) {
            foreach ($old_roles as $old_r) {
                if (self::is_privileged_role((string) $old_r)) {
                    $was_privileged = true;
                    $prev_privileged_role = (string) $old_r;
                    break;
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
                // Unauthorized Demotion: revert user role back to previous privileged role in DB
                if ($target_user instanceof \WP_User && !empty($prev_privileged_role)) {
                    remove_action('set_user_role', [__CLASS__, 'rasp_guard_user_role_assignment'], 9999);
                    $target_user->set_role($prev_privileged_role);
                    add_action('set_user_role', [__CLASS__, 'rasp_guard_user_role_assignment'], 9999, 3);
                }

                $reason = sprintf('Unauthorized role demotion of "%s" (user #%d) to "%s"', $prev_privileged_role, $user_id, $role);

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
            }

            if (!FirewallEngine::is_authenticated_administrator() && !ClientIpResolver::is_server_origin_or_loopback($client_ip)) {
                FirewallEngine::add_blocked_ip(
                    $client_ip,
                    $reason,
                    86400,
                    $was_privileged && !$is_elevated_role ? 'WAF-RASP-ROLE-DEMOTION' : 'WAF-RASP-ROLE-ESCALATION',
                    'Runtime Role Modification Trap',
                    'Runtime RASP Hook Defense',
                    $incident_id
                );
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
            $reason = sprintf('Unauthenticated registration of elevated account "%s" (#%d)', $user->user_login, $user_id);

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
                foreach ($existing as $item) {
                    if (is_array($item) && isset($item['uuid'])) {
                        $existing_map[$item['uuid']] = $item;
                    }
                }

                $is_only_usage_ping = true;
                foreach ($meta_value as $new_item) {
                    if (!is_array($new_item)) {
                        $is_only_usage_ping = false;
                        break;
                    }
                    $uuid = $new_item['uuid'] ?? '';
                    if (!isset($existing_map[$uuid])) {
                        $is_only_usage_ping = false;
                        break;
                    }
                    $old_item = $existing_map[$uuid];
                    // Core usage-ping (WP_Application_Passwords::record_application_password_usage)
                    // strictly and exclusively mutates 'last_used' and/or 'last_ip'.
                    // Password hash, name, created timestamp, and uuid must remain strictly identical.
                    if (
                        !hash_equals((string) ($old_item['password'] ?? ''), (string) ($new_item['password'] ?? '')) ||
                        (string) ($old_item['name'] ?? '') !== (string) ($new_item['name'] ?? '') ||
                        (int) ($old_item['created'] ?? 0) !== (int) ($new_item['created'] ?? 0)
                    ) {
                        $is_only_usage_ping = false;
                        break;
                    }
                    // Verify no unauthorized extra metadata keys were injected into the entry
                    $diff_keys = array_diff(array_keys($new_item), array_keys($old_item));
                    if (!empty($diff_keys)) {
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
