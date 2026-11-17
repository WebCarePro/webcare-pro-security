<?php
/**
 * Fired when the plugin is deleted via the WordPress Admin Plugins screen.
 *
 * @package WebCare_Pro_Security
 */

if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

// Register autoloader for WebCareProScanner namespace during uninstallation
spl_autoload_register(function ($class) {
    $prefix = 'WebCareProScanner\\';
    $base_dir = dirname(__FILE__) . '/includes/';

    $len = strlen($prefix);
    if (strncmp($prefix, $class, $len) !== 0) {
        return;
    }

    $relative_class = substr($class, $len);
    $rel_path = str_replace('\\', '/', $relative_class);
    $file = $base_dir . $rel_path . '.php';

    if (file_exists($file)) {
        require_once $file;
        return;
    }

    $dir = dirname($rel_path);
    $base = basename($rel_path);
    if ($dir !== '.' && $dir !== '') {
        $lower_dir_file = $base_dir . strtolower($dir) . '/' . $base . '.php';
        if (file_exists($lower_dir_file)) {
            require_once $lower_dir_file;
            return;
        }
    }

    $all_lower_file = $base_dir . strtolower($rel_path) . '.php';
    if (file_exists($all_lower_file)) {
        require_once $all_lower_file;
        return;
    }
});

// Dispatch plugin uninstallation security event notification before purging configuration
$webcareproscan_dispatcher_file = dirname(__FILE__) . '/includes/Notifications/NotificationDispatcher.php';
$webcareproscan_settings_mgr_file = dirname(__FILE__) . '/includes/System/SettingsManager.php';
if (file_exists($webcareproscan_dispatcher_file) && file_exists($webcareproscan_settings_mgr_file)) {
    require_once $webcareproscan_settings_mgr_file;
    require_once $webcareproscan_dispatcher_file;
    if (class_exists('\\WebCareProScanner\\Notifications\\NotificationDispatcher')) {
        try {
            \WebCareProScanner\Notifications\NotificationDispatcher::trigger('plugin_uninstall', [
                'severity' => 'high',
                'message'  => __('WebCare Pro Security & Firewall is being uninstalled and deleted from WordPress plugins manager.', 'webcare-pro-security'),
                'details'  => [
                    'Event'        => 'Plugin Uninstallation',
                    'Triggered By' => function_exists('wp_get_current_user') && wp_get_current_user()->exists() ? wp_get_current_user()->user_login : 'admin',
                    'Timestamp'    => current_time('mysql'),
                ],
            ]);
        } catch (\Throwable $e) {
            // Fail safely during uninstall without blocking deletion
        }
    }
}

// Always clean up Micro-WAF preloads and server security rules regardless of delete_data_on_uninstall
$webcareproscan_microwaf_file = dirname(__FILE__) . '/includes/Firewall/MicroWafCompiler.php';
if (file_exists($webcareproscan_microwaf_file)) {
    require_once $webcareproscan_microwaf_file;
    if (class_exists('\\WebCareProScanner\\Firewall\\MicroWafCompiler')) {
        try {
            \WebCareProScanner\Firewall\MicroWafCompiler::uninstall_preload();
        } catch (\Throwable $e) {
            // Fail safely
        }
    }
}
$webcareproscan_server_sec_file = dirname(__FILE__) . '/includes/Firewall/ServerSecurityEngine.php';
if (file_exists($webcareproscan_server_sec_file)) {
    require_once $webcareproscan_server_sec_file;
    if (class_exists('\\WebCareProScanner\\Firewall\\ServerSecurityEngine')) {
        try {
            \WebCareProScanner\Firewall\ServerSecurityEngine::remove_rules();
        } catch (\Throwable $e) {
            // Fail safely
        }
    }
}

// Clean up database canaries and ghost admin users before options deletion
$webcareproscan_honeytoken_file = dirname(__FILE__) . '/includes/Firewall/HoneyTokenEngine.php';
if (file_exists($webcareproscan_honeytoken_file)) {
    require_once $webcareproscan_honeytoken_file;
    if (class_exists('\\WebCareProScanner\\Firewall\\HoneyTokenEngine') && method_exists('\\WebCareProScanner\\Firewall\\HoneyTokenEngine', 'purge_canaries')) {
        try {
            \WebCareProScanner\Firewall\HoneyTokenEngine::purge_canaries();
        } catch (\Throwable $e) {
            // Fail safely
        }
    }
}

// Unconditionally purge ghost admin canary and canary tokens from database
global $wpdb;
if (isset($wpdb) && $wpdb instanceof \wpdb) {
    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
    $wpdb->query("DELETE FROM `{$wpdb->users}` WHERE `user_login` = 'webcare_canary_admin'");
    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
    $wpdb->query("DELETE FROM `{$wpdb->options}` WHERE `option_name` LIKE '%canary%' AND `option_name` LIKE '%webcare%'");
}

$webcareproscan_settings = get_option('webcareproscan_settings', []);
$webcareproscan_delete_data = true; // Default to true for clean fresh uninstallation; can be configured in settings

if (is_array($webcareproscan_settings) && array_key_exists('delete_data_on_uninstall', $webcareproscan_settings)) {
    $webcareproscan_delete_data = (bool) $webcareproscan_settings['delete_data_on_uninstall'];
}

if ($webcareproscan_delete_data) {
    global $wpdb;

    $webcareproscan_drop_tables    = !isset($webcareproscan_settings['uninstall_drop_tables']) || !empty($webcareproscan_settings['uninstall_drop_tables']);
    $webcareproscan_delete_options = !isset($webcareproscan_settings['uninstall_delete_options']) || !empty($webcareproscan_settings['uninstall_delete_options']);
    $webcareproscan_delete_crons   = !isset($webcareproscan_settings['uninstall_delete_crons']) || !empty($webcareproscan_settings['uninstall_delete_crons']);
    $webcareproscan_delete_uploads = !isset($webcareproscan_settings['uninstall_delete_uploads']) || !empty($webcareproscan_settings['uninstall_delete_uploads']);

    // Helper closure to drop custom tables and delete all WebCare options for a given prefix/blog
    $webcareproscan_clean_blog_tables_and_options = static function ($prefix) use ($wpdb, $webcareproscan_drop_tables, $webcareproscan_delete_options) {
        // 1. Drop all custom plugin tables
        if ($webcareproscan_drop_tables) {
            $webcareproscan_tables = [
                $prefix . 'webcareproscan_scans',
                $prefix . 'webcareproscan_scan_issues',
                $prefix . 'webcareproscan_scan_files',
                $prefix . 'webcareproscan_quarantine',
                $prefix . 'webcareproscan_firewall_logs',
                $prefix . 'webcareproscan_login_history',
                $prefix . 'webcareproscan_cron_logs',
            ];

            foreach ($webcareproscan_tables as $webcareproscan_table) {
                // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
                $wpdb->query("DROP TABLE IF EXISTS `{$webcareproscan_table}`");
            }

            // Drop any dynamic tables created under this prefix
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $dynamic_tables = $wpdb->get_col($wpdb->prepare("SHOW TABLES LIKE %s", $wpdb->esc_like($prefix . 'webcareproscan_') . '%'));
            if (!empty($dynamic_tables)) {
                foreach ($dynamic_tables as $dyn_table) {
                    // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
                    $wpdb->query("DROP TABLE IF EXISTS `{$dyn_table}`");
                }
            }
        }

        // 2. Delete all plugin options, CAF settings, Cloudflare edge states, canaries, and transients
        if ($webcareproscan_delete_options) {
            $options_table = $prefix . 'options';
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->query(
                $wpdb->prepare(
                    'DELETE FROM %i WHERE option_name LIKE %s',
                    $options_table,
                    '%webcare%'
                )
            );
        }
    };

    // Clean active blog
    $webcareproscan_clean_blog_tables_and_options($wpdb->prefix);

    // Multisite cleanup: iterate all blogs and clean their respective tables and options
    if (is_multisite()) {
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->query("DELETE FROM `{$wpdb->sitemeta}` WHERE `meta_key` LIKE '%webcare%'");

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $webcareproscan_blogs = $wpdb->get_col("SELECT blog_id FROM {$wpdb->blogs}");
        if (!empty($webcareproscan_blogs)) {
            $webcareproscan_current_blog_id = (int) get_current_blog_id();
            foreach ($webcareproscan_blogs as $webcareproscan_b_id) {
                if ((int) $webcareproscan_b_id === $webcareproscan_current_blog_id) {
                    continue;
                }
                switch_to_blog((int) $webcareproscan_b_id);
                $webcareproscan_clean_blog_tables_and_options($wpdb->prefix);
                restore_current_blog();
            }
        }
    }

    // 3. Purge plugin user meta (2FA tokens, backup codes, trusted devices, session meta)
    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
    $wpdb->query("DELETE FROM `{$wpdb->usermeta}` WHERE `meta_key` LIKE '%webcare%'");

    // 4. Purge Ghost Admin canary user and any canary tripwire accounts
    if (function_exists('get_user_by')) {
        $webcare_canary_user = get_user_by('login', 'webcare_canary_admin');
        if ($webcare_canary_user instanceof \WP_User) {
            if (!function_exists('wp_delete_user')) {
                require_once ABSPATH . 'wp-admin/includes/user.php';
            }
            if (function_exists('wp_delete_user')) {
                wp_delete_user($webcare_canary_user->ID);
            }
        }
    }
    // Fail-safe direct delete for canary user from wp_users
    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
    $wpdb->query("DELETE FROM {$wpdb->users} WHERE user_login = 'webcare_canary_admin'");

    // 5. Clear scheduled cron jobs
    if ($webcareproscan_delete_crons) {
        $webcareproscan_cron_hooks = [
            'webcareproscan_scheduled_scan_cron',
            'webcareproscan_scheduled_scan_event',
            'webcareproscan_weekly_digest_event',
            'webcareproscan_redirect_canary_event',
            'webcareproscan_modular_ast_step',
            'webcareproscan_backup_step_worker',
            'webcareproscan_threat_intel_cron_sync',
            'webcareproscan_self_defense_watchdog_event',
            'webcareproscan_waf_log_retention_prune',
            'webcareproscan_domain_reputation_daily_check',
            'webcareproscan_reinfection_hourly_check',
            'webcareproscan_modular_autopilot_cron',
            'webcareproscan_auto_rearm_waf',
            'webcareproscan_ephemeral_admin_expire',
            'webcare_cloudflare_ip_sync_cron',
            'webcare_cf_auto_sync_edge_cron',
        ];
        foreach ($webcareproscan_cron_hooks as $webcareproscan_hook) {
            wp_clear_scheduled_hook($webcareproscan_hook);
        }

        // Dynamically clear any remaining scheduled cron jobs starting with webcareproscan_ or webcare_
        if (function_exists('_get_cron_array')) {
            $webcareproscan_all_crons = _get_cron_array();
            if (is_array($webcareproscan_all_crons)) {
                foreach ($webcareproscan_all_crons as $webcareproscan_cron_time => $webcareproscan_cron_hooks) {
                    if (is_array($webcareproscan_cron_hooks)) {
                        foreach ($webcareproscan_cron_hooks as $webcareproscan_cron_hook_name => $webcareproscan_cron_args) {
                            if (str_starts_with($webcareproscan_cron_hook_name, 'webcareproscan_') || str_starts_with($webcareproscan_cron_hook_name, 'webcare_')) {
                                wp_clear_scheduled_hook($webcareproscan_cron_hook_name);
                            }
                        }
                    }
                }
            }
        }
    }

    // 6. Remove all plugin-created files in uploads (logs, quarantine, backups, compiled binaries)
    if ($webcareproscan_delete_uploads) {
        $webcareproscan_upload_dir = wp_upload_dir();
        if (!empty($webcareproscan_upload_dir['basedir'])) {
            $webcareproscan_storage_dir = untrailingslashit($webcareproscan_upload_dir['basedir']) . '/webcare-pro-security';
            if (is_dir($webcareproscan_storage_dir)) {
                global $wp_filesystem;
                if (!$wp_filesystem) {
                    require_once ABSPATH . 'wp-admin/includes/file.php';
                    WP_Filesystem();
                }
                $webcareproscan_deleted = false;
                if ($wp_filesystem && is_object($wp_filesystem) && method_exists($wp_filesystem, 'delete')) {
                    try {
                        $webcareproscan_deleted = (bool) $wp_filesystem->delete($webcareproscan_storage_dir, true);
                    } catch (\Throwable $e) {
                        $webcareproscan_deleted = false;
                    }
                }
                // Fallback recursive delete using standard WordPress functions if wp_filesystem failed
                if (!$webcareproscan_deleted && is_dir($webcareproscan_storage_dir)) {
                    $webcare_del_recursive = static function ($dir, $del_fn) {
                        if (!is_dir($dir)) {
                            return;
                        }
                        $items = @scandir($dir);
                        if (!is_array($items)) {
                            return;
                        }
                        foreach ($items as $item) {
                            if ($item === '.' || $item === '..') {
                                continue;
                            }
                            $path = $dir . DIRECTORY_SEPARATOR . $item;
                            if (is_dir($path)) {
                                $del_fn($path, $del_fn);
                            } else {
                                wp_delete_file($path);
                            }
                        }
                        global $wp_filesystem;
                        if ($wp_filesystem && is_object($wp_filesystem) && method_exists($wp_filesystem, 'rmdir')) {
                            $wp_filesystem->rmdir($dir);
                        } else {
                            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_rmdir -- Fallback directory purge during plugin uninstallation.
                            @rmdir($dir);
                        }
                    };
                    $webcare_del_recursive($webcareproscan_storage_dir, $webcare_del_recursive);
                }
            }
        }
    }
}
