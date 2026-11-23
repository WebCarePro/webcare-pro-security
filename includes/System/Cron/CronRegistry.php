<?php
namespace WebCareProScanner\System\Cron;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Canonical catalog and recurrence metadata for all WebCare Pro Security & Firewall
 * WP-Cron hooks and background continuation workers.
 */
class CronRegistry {

    /**
     * All custom recurrence intervals registered by WebCare Pro.
     *
     * @return array<string, array{interval: int, display: string}>
     */
    public static function get_custom_intervals(): array {
        return [
            'weekly' => [
                'interval' => 7 * DAY_IN_SECONDS,
                'display'  => did_action('init') ? __('Once Weekly', 'webcare-pro-security') : 'Once Weekly',
            ],
            'webcare_every_five_minutes' => [
                'interval' => 300,
                'display'  => did_action('init') ? __('Every 5 Minutes (WebCare Pro Security)', 'webcare-pro-security') : 'Every 5 Minutes (WebCare Pro Security)',
            ],
            'webcare_15min' => [
                'interval' => 900,
                'display'  => did_action('init') ? __('Every 15 Minutes (WebCare Pro Security)', 'webcare-pro-security') : 'Every 15 Minutes (WebCare Pro Security)',
            ],
            'webcare_30min' => [
                'interval' => 1800,
                'display'  => did_action('init') ? __('Every 30 Minutes (WebCare Pro Security)', 'webcare-pro-security') : 'Every 30 Minutes (WebCare Pro Security)',
            ],
        ];
    }

    /**
     * Recurrence options exposed to the UI schedule selector.
     *
     * @return array<string, array{label: string, interval: int}>
     */
    public static function get_recurrence_catalog(): array {
        return [
            'webcare_every_five_minutes' => [
                'label'    => did_action('init') ? __('Every 5 Minutes', 'webcare-pro-security') : 'Every 5 Minutes',
                'interval' => 300,
            ],
            'webcare_15min' => [
                'label'    => did_action('init') ? __('Every 15 Minutes', 'webcare-pro-security') : 'Every 15 Minutes',
                'interval' => 900,
            ],
            'webcare_30min' => [
                'label'    => did_action('init') ? __('Every 30 Minutes', 'webcare-pro-security') : 'Every 30 Minutes',
                'interval' => 1800,
            ],
            'hourly' => [
                'label'    => did_action('init') ? __('Every Hour', 'webcare-pro-security') : 'Every Hour',
                'interval' => HOUR_IN_SECONDS,
            ],
            'twicedaily' => [
                'label'    => did_action('init') ? __('Twice Daily (12h)', 'webcare-pro-security') : 'Twice Daily (12h)',
                'interval' => 12 * HOUR_IN_SECONDS,
            ],
            'daily' => [
                'label'    => did_action('init') ? __('Once Daily', 'webcare-pro-security') : 'Once Daily',
                'interval' => DAY_IN_SECONDS,
            ],
            'weekly' => [
                'label'    => did_action('init') ? __('Once Weekly', 'webcare-pro-security') : 'Once Weekly',
                'interval' => WEEK_IN_SECONDS,
            ],
        ];
    }

    /**
     * Category metadata for grouping tasks in the Control Center.
     *
     * @return array<string, string>
     */
    public static function get_categories(): array {
        return [
            'scanning'                  => did_action('init') ? __('Scanning & AST', 'webcare-pro-security') : 'Scanning & AST',
            'firewall_edge'             => did_action('init') ? __('Firewall & Cloudflare Edge', 'webcare-pro-security') : 'Firewall & Cloudflare Edge',
            'integrity_quarantine'      => did_action('init') ? __('Integrity & Watchdogs', 'webcare-pro-security') : 'Integrity & Watchdogs',
            'notifications_maintenance' => did_action('init') ? __('Reports & Maintenance', 'webcare-pro-security') : 'Reports & Maintenance',
            'background_workers'        => did_action('init') ? __('Background Workers & Safeguards', 'webcare-pro-security') : 'Background Workers & Safeguards',
        ];
    }

    /**
     * Master registry of all 15 plugin cron hooks & background workers.
     *
     * @return array<string, array<string, mixed>>
     */
    public static function get_tasks(): array {
        $tasks = [
            'webcareproscan_scheduled_scan_event' => [
                'id'                  => 'scheduled_scan',
                'hook'                => 'webcareproscan_scheduled_scan_event',
                'title'               => did_action('init') ? __('Automated Malware & Integrity Scan', 'webcare-pro-security') : 'Automated Malware & Integrity Scan',
                'description'         => did_action('init') ? __('Executes the configured full, plugin/theme, core integrity, or upload malware audit on schedule.', 'webcare-pro-security') : 'Executes the configured full, plugin/theme, core integrity, or upload malware audit on schedule.',
                'category'            => 'scanning',
                'kind'                => 'recurring',
                'default_recurrence'  => 'daily',
                'allowed_recurrences' => ['hourly', 'twicedaily', 'daily', 'weekly'],
                'can_disable'         => true,
                'setting_key'         => 'schedule_enabled',
                'setting_type'        => 'settings_manager',
                'setting_location'    => did_action('init') ? __('Settings -> Schedule & Automation', 'webcare-pro-security') : 'Settings -> Schedule & Automation',
                'deep_link'           => 'admin.php?page=webcare-pro-settings&tab=schedules',
                'default_delay'       => 0,
            ],
            'webcareproscan_custom_rules_ast_step' => [
                'id'                  => 'custom_rules_ast_worker',
                'hook'                => 'webcareproscan_custom_rules_ast_step',
                'title'               => did_action('init') ? __('Custom Rules AST Scan Continuation', 'webcare-pro-security') : 'Custom Rules AST Scan Continuation',
                'description'         => did_action('init') ? __('Resumes and finishes in-progress Custom Rules PHP AST scans via WP-Cron if the browser tab is closed.', 'webcare-pro-security') : 'Resumes and finishes in-progress Custom Rules PHP AST scans via WP-Cron if the browser tab is closed.',
                'category'            => 'scanning',
                'kind'                => 'on_demand_worker',
                'default_recurrence'  => 'on_demand',
                'allowed_recurrences' => [],
                'can_disable'         => true,
                'setting_key'         => 'cron_custom_rules_ast_bg_enabled',
                'setting_type'        => 'settings_manager',
                'setting_location'    => did_action('init') ? __('Custom Rules -> Live AST Telemetry', 'webcare-pro-security') : 'Custom Rules -> Live AST Telemetry',
                'deep_link'           => 'admin.php?page=webcare-pro-firewall&tab=custom-waf-rules',
                'default_delay'       => 15,
            ],
            'webcareproscan_scan_step_worker' => [
                'id'                  => 'scan_step_worker',
                'hook'                => 'webcareproscan_scan_step_worker',
                'title'               => did_action('init') ? __('Security Scan Background Continuation Worker', 'webcare-pro-security') : 'Security Scan Background Continuation Worker',
                'description'         => did_action('init') ? __('Resumes and executes active security scanner file batches in background WP-Cron ticks when the admin navigates away from the page.', 'webcare-pro-security') : 'Resumes and executes active security scanner file batches in background WP-Cron ticks when the admin navigates away from the page.',
                'category'            => 'scanning',
                'kind'                => 'on_demand_worker',
                'default_recurrence'  => 'on_demand',
                'allowed_recurrences' => [],
                'can_disable'         => true,
                'setting_key'         => 'cron_scan_bg_enabled',
                'setting_type'        => 'settings_manager',
                'setting_location'    => did_action('init') ? __('Scanner -> Scan Options', 'webcare-pro-security') : 'Scanner -> Scan Options',
                'deep_link'           => 'admin.php?page=webcare-pro-scanner',
                'default_delay'       => 5,
            ],
            'webcareproscan_threat_intel_cron_sync' => [
                'id'                  => 'threat_intel_sync',
                'hook'                => 'webcareproscan_threat_intel_cron_sync',
                'title'               => did_action('init') ? __('Threat Intelligence & CVE Feed Sync', 'webcare-pro-security') : 'Threat Intelligence & CVE Feed Sync',
                'description'         => did_action('init') ? __('Refreshes community malicious IP blocklists and known WordPress CVE advisories.', 'webcare-pro-security') : 'Refreshes community malicious IP blocklists and known WordPress CVE advisories.',
                'category'            => 'firewall_edge',
                'kind'                => 'recurring',
                'default_recurrence'  => 'twicedaily',
                'allowed_recurrences' => ['hourly', 'twicedaily', 'daily'],
                'can_disable'         => true,
                'setting_key'         => 'threat_intel_enabled',
                'setting_type'        => 'settings_manager',
                'setting_location'    => did_action('init') ? __('Firewall -> Threat Intelligence', 'webcare-pro-security') : 'Firewall -> Threat Intelligence',
                'deep_link'           => 'admin.php?page=webcare-pro-firewall',
                'default_delay'       => HOUR_IN_SECONDS,
            ],
            'webcareproscan_redirect_canary_event' => [
                'id'                  => 'redirect_canary_watchdog',
                'hook'                => 'webcareproscan_redirect_canary_event',
                'title'               => did_action('init') ? __('Redirect Canary & Cloaking Watchdog', 'webcare-pro-security') : 'Redirect Canary & Cloaking Watchdog',
                'description'         => did_action('init') ? __('Runs synthetic search-bot, mobile, AI crawler, and DB URL probes to detect and auto-heal hidden redirects.', 'webcare-pro-security') : 'Runs synthetic search-bot, mobile, AI crawler, and DB URL probes to detect and auto-heal hidden redirects.',
                'category'            => 'firewall_edge',
                'kind'                => 'recurring',
                'default_recurrence'  => 'webcare_15min',
                'allowed_recurrences' => ['webcare_15min', 'webcare_30min', 'hourly', 'twicedaily', 'daily'],
                'can_disable'         => true,
                'setting_key'         => 'cron_redirect_canary_enabled',
                'setting_type'        => 'settings_manager',
                'setting_location'    => did_action('init') ? __('Firewall -> Redirect Shield', 'webcare-pro-security') : 'Firewall -> Redirect Shield',
                'deep_link'           => 'admin.php?page=webcare-pro-firewall',
                'default_delay'       => 60,
            ],
            'webcareproscan_custom_rules_autopilot_cron' => [
                'id'                  => 'custom_rules_autopilot_promo',
                'hook'                => 'webcareproscan_custom_rules_autopilot_cron',
                'title'               => did_action('init') ? __('Custom Rules 48h Auto-Pilot Promotion', 'webcare-pro-security') : 'Custom Rules 48h Auto-Pilot Promotion',
                'description'         => did_action('init') ? __('Evaluates monitored Custom Rules after the 48-hour false-positive soak period for safe promotion.', 'webcare-pro-security') : 'Evaluates monitored Custom Rules after the 48-hour false-positive soak period for safe promotion.',
                'category'            => 'firewall_edge',
                'kind'                => 'recurring',
                'default_recurrence'  => 'hourly',
                'allowed_recurrences' => ['hourly', 'twicedaily', 'daily'],
                'can_disable'         => true,
                'setting_key'         => 'cron_custom_rules_autopilot_enabled',
                'setting_type'        => 'settings_manager',
                'setting_location'    => did_action('init') ? __('Custom Rules -> Smart Auto-Pilot', 'webcare-pro-security') : 'Custom Rules -> Smart Auto-Pilot',
                'deep_link'           => 'admin.php?page=webcare-pro-firewall&tab=custom-waf-rules',
                'default_delay'       => HOUR_IN_SECONDS,
            ],
            'webcare_cloudflare_ip_sync_cron' => [
                'id'                  => 'cloudflare_ip_sync',
                'hook'                => 'webcare_cloudflare_ip_sync_cron',
                'title'               => did_action('init') ? __('Cloudflare Edge IP Ban Queue Sync', 'webcare-pro-security') : 'Cloudflare Edge IP Ban Queue Sync',
                'description'         => did_action('init') ? __('Flushes queued origin WAF attacker IPs to your Cloudflare IP Access Rules & Edge lists.', 'webcare-pro-security') : 'Flushes queued origin WAF attacker IPs to your Cloudflare IP Access Rules & Edge lists.',
                'category'            => 'firewall_edge',
                'kind'                => 'recurring',
                'default_recurrence'  => 'webcare_every_five_minutes',
                'allowed_recurrences' => ['webcare_every_five_minutes', 'webcare_15min', 'webcare_30min', 'hourly'],
                'can_disable'         => true,
                'setting_key'         => 'cloudflare_auto_sync_bans',
                'setting_type'        => 'settings_manager',
                'setting_location'    => did_action('init') ? __('Settings -> Cloudflare Edge', 'webcare-pro-security') : 'Settings -> Cloudflare Edge',
                'deep_link'           => 'admin.php?page=webcare-pro-firewall&tab=cloudflare',
                'default_delay'       => 300,
            ],
            'webcare_cf_auto_sync_edge_cron' => [
                'id'                  => 'cloudflare_edge_auto_sync',
                'hook'                => 'webcare_cf_auto_sync_edge_cron',
                'title'               => did_action('init') ? __('Cloudflare Edge Rule Auto-Deploy Worker', 'webcare-pro-security') : 'Cloudflare Edge Rule Auto-Deploy Worker',
                'description'         => did_action('init') ? __('Automatically deploys optimized Cloudflare Edge WAF slot rules 5 seconds after stack or settings updates.', 'webcare-pro-security') : 'Automatically deploys optimized Cloudflare Edge WAF slot rules 5 seconds after stack or settings updates.',
                'category'            => 'firewall_edge',
                'kind'                => 'on_demand_worker',
                'default_recurrence'  => 'on_demand',
                'allowed_recurrences' => [],
                'can_disable'         => true,
                'setting_key'         => 'webcare_cf_auto_sync_edge',
                'setting_type'        => 'wp_option',
                'setting_location'    => did_action('init') ? __('Firewall -> Context-Adaptive (CAF)', 'webcare-pro-security') : 'Firewall -> Context-Adaptive (CAF)',
                'deep_link'           => 'admin.php?page=webcare-pro-firewall&tab=adaptive',
                'default_delay'       => 5,
            ],
            'webcareproscan_self_defense_watchdog_event' => [
                'id'                  => 'self_defense_watchdog',
                'hook'                => 'webcareproscan_self_defense_watchdog_event',
                'title'               => did_action('init') ? __('Plugin Self-Defense Integrity Watchdog', 'webcare-pro-security') : 'Plugin Self-Defense Integrity Watchdog',
                'description'         => did_action('init') ? __('Verifies SHA-256 checksums across WebCare Pro files to detect host deletions or malicious tampering.', 'webcare-pro-security') : 'Verifies SHA-256 checksums across WebCare Pro files to detect host deletions or malicious tampering.',
                'category'            => 'integrity_quarantine',
                'kind'                => 'recurring',
                'default_recurrence'  => 'twicedaily',
                'allowed_recurrences' => ['hourly', 'twicedaily', 'daily'],
                'can_disable'         => true,
                'setting_key'         => 'self_defense_watchdog_enabled',
                'setting_type'        => 'settings_manager',
                'setting_location'    => did_action('init') ? __('Forensics -> Plugin Self-Defense', 'webcare-pro-security') : 'Forensics -> Plugin Self-Defense',
                'deep_link'           => 'admin.php?page=webcare-pro-backups&tab=forensics',
                'default_delay'       => 300,
            ],
            'webcareproscan_reinfection_hourly_check' => [
                'id'                  => 'reinfection_watchdog',
                'hook'                => 'webcareproscan_reinfection_hourly_check',
                'title'               => did_action('init') ? __('72-Hour Post-Remediation Watchdog', 'webcare-pro-security') : '72-Hour Post-Remediation Watchdog',
                'description'         => did_action('init') ? __('Inspects recently quarantined or cleaned file paths to intercept malware resurrection loops.', 'webcare-pro-security') : 'Inspects recently quarantined or cleaned file paths to intercept malware resurrection loops.',
                'category'            => 'integrity_quarantine',
                'kind'                => 'recurring',
                'default_recurrence'  => 'hourly',
                'allowed_recurrences' => ['webcare_15min', 'webcare_30min', 'hourly', 'twicedaily', 'daily'],
                'can_disable'         => true,
                'setting_key'         => 'cron_reinfection_watchdog_enabled',
                'setting_type'        => 'settings_manager',
                'setting_location'    => did_action('init') ? __('Forensics -> 72h Watchdog', 'webcare-pro-security') : 'Forensics -> 72h Watchdog',
                'deep_link'           => 'admin.php?page=webcare-pro-backups&tab=forensics',
                'default_delay'       => HOUR_IN_SECONDS,
            ],
            'webcareproscan_domain_reputation_daily_check' => [
                'id'                  => 'domain_reputation_check',
                'hook'                => 'webcareproscan_domain_reputation_daily_check',
                'title'               => did_action('init') ? __('Domain Reputation, SSL & DNSBL Audit', 'webcare-pro-security') : 'Domain Reputation, SSL & DNSBL Audit',
                'description'         => did_action('init') ? __('Checks SSL expiration, SPF/DMARC records, and major DNSBL blacklists for site reputation health.', 'webcare-pro-security') : 'Checks SSL expiration, SPF/DMARC records, and major DNSBL blacklists for site reputation health.',
                'category'            => 'integrity_quarantine',
                'kind'                => 'recurring',
                'default_recurrence'  => 'daily',
                'allowed_recurrences' => ['twicedaily', 'daily', 'weekly'],
                'can_disable'         => true,
                'setting_key'         => 'cron_domain_reputation_enabled',
                'setting_type'        => 'settings_manager',
                'setting_location'    => did_action('init') ? __('Forensics -> Domain Reputation', 'webcare-pro-security') : 'Forensics -> Domain Reputation',
                'deep_link'           => 'admin.php?page=webcare-pro-backups&tab=forensics',
                'default_delay'       => DAY_IN_SECONDS,
            ],
            'webcareproscan_waf_log_retention_prune' => [
                'id'                  => 'waf_log_retention_prune',
                'hook'                => 'webcareproscan_waf_log_retention_prune',
                'title'               => did_action('init') ? __('WAF Incident Log Retention Pruner', 'webcare-pro-security') : 'WAF Incident Log Retention Pruner',
                'description'         => did_action('init') ? __('Deletes daily WAF JSON log shards older than the configured retention period.', 'webcare-pro-security') : 'Deletes daily WAF JSON log shards older than the configured retention period.',
                'category'            => 'notifications_maintenance',
                'kind'                => 'recurring',
                'default_recurrence'  => 'daily',
                'allowed_recurrences' => ['twicedaily', 'daily', 'weekly'],
                'can_disable'         => true,
                'setting_key'         => 'cron_waf_log_prune_enabled',
                'setting_type'        => 'settings_manager',
                'setting_location'    => did_action('init') ? __('WAF Logs -> Retention Policy', 'webcare-pro-security') : 'WAF Logs -> Retention Policy',
                'deep_link'           => 'admin.php?page=webcare-pro-logs&tab=firewall',
                'default_delay'       => HOUR_IN_SECONDS,
            ],
            'webcareproscan_daily_cve_audit' => [
                'id'                  => 'daily_cve_audit',
                'hook'                => 'webcareproscan_daily_cve_audit',
                'title'               => did_action('init') ? __('Daily CVE & Component Vulnerability Audit', 'webcare-pro-security') : 'Daily CVE & Component Vulnerability Audit',
                'description'         => did_action('init') ? __('Audits installed WordPress Core, plugins, and themes against known CVE vulnerabilities and dispatches smart diff alerts.', 'webcare-pro-security') : 'Audits installed WordPress Core, plugins, and themes against known CVE vulnerabilities and dispatches smart diff alerts.',
                'category'            => 'notifications_maintenance',
                'kind'                => 'recurring',
                'default_recurrence'  => 'daily',
                'allowed_recurrences' => ['twicedaily', 'daily', 'weekly'],
                'can_disable'         => true,
                'setting_key'         => 'cron_cve_audit_enabled',
                'setting_type'        => 'settings_manager',
                'setting_location'    => did_action('init') ? __('Scanner -> Daily CVE Watch', 'webcare-pro-security') : 'Scanner -> Daily CVE Watch',
                'deep_link'           => 'admin.php?page=webcare-pro-scanner&tab=vulnerabilities',
                'default_delay'       => HOUR_IN_SECONDS,
            ],
            'webcareproscan_weekly_digest_event' => [
                'id'                  => 'weekly_digest_report',
                'hook'                => 'webcareproscan_weekly_digest_event',
                'title'               => did_action('init') ? __('Weekly Security Digest Report', 'webcare-pro-security') : 'Weekly Security Digest Report',
                'description'         => did_action('init') ? __('Compiles and dispatches Monday morning peace-of-mind email and webhook security summaries.', 'webcare-pro-security') : 'Compiles and dispatches Monday morning peace-of-mind email and webhook security summaries.',
                'category'            => 'notifications_maintenance',
                'kind'                => 'recurring',
                'default_recurrence'  => 'weekly',
                'allowed_recurrences' => ['daily', 'weekly'],
                'can_disable'         => true,
                'setting_key'         => 'email_digest_enabled',
                'setting_type'        => 'settings_digest',
                'setting_location'    => did_action('init') ? __('Notifications -> Weekly Digest', 'webcare-pro-security') : 'Notifications -> Weekly Digest',
                'deep_link'           => 'admin.php?page=webcare-pro-settings&tab=alerts',
                'default_delay'       => 0,
            ],
            'webcareproscan_backup_step_worker' => [
                'id'                  => 'database_backup_worker',
                'hook'                => 'webcareproscan_backup_step_worker',
                'title'               => did_action('init') ? __('Database Backup Vault Step Worker', 'webcare-pro-security') : 'Database Backup Vault Step Worker',
                'description'         => did_action('init') ? __('Streams active Database Backup Vault table exports sequentially in background WP-Cron ticks.', 'webcare-pro-security') : 'Streams active Database Backup Vault table exports sequentially in background WP-Cron ticks.',
                'category'            => 'background_workers',
                'kind'                => 'on_demand_worker',
                'default_recurrence'  => 'on_demand',
                'allowed_recurrences' => [],
                'can_disable'         => true,
                'setting_key'         => 'cron_backup_bg_enabled',
                'setting_type'        => 'settings_manager',
                'setting_location'    => did_action('init') ? __('Vault -> Database Backup', 'webcare-pro-security') : 'Vault -> Database Backup',
                'deep_link'           => 'admin.php?page=webcare-pro-backups&tab=database',
                'default_delay'       => 1,
            ],
            'webcareproscan_auto_rearm_waf' => [
                'id'                  => 'waf_rescue_auto_rearm',
                'hook'                => 'webcareproscan_auto_rearm_waf',
                'title'               => did_action('init') ? __('WAF Rescue Mode Auto Re-Arm Timer', 'webcare-pro-security') : 'WAF Rescue Mode Auto Re-Arm Timer',
                'description'         => did_action('init') ? __('Automatically restores strict WAF blocking 15 minutes after Rescue Assistant Monitor-Only test mode starts.', 'webcare-pro-security') : 'Automatically restores strict WAF blocking 15 minutes after Rescue Assistant Monitor-Only test mode starts.',
                'category'            => 'background_workers',
                'kind'                => 'security_safeguard',
                'default_recurrence'  => 'on_demand',
                'allowed_recurrences' => [],
                'can_disable'         => false,
                'setting_key'         => null,
                'setting_location'    => did_action('init') ? __('Rescue Assistant -> 15m Test Pause', 'webcare-pro-security') : 'Rescue Assistant -> 15m Test Pause',
                'deep_link'           => 'admin.php?page=webcare-pro-firewall',
                'default_delay'       => 900,
            ],
        ];

        if (class_exists('\\WebCareProScanner\\Core\\ModuleRegistry')) {
            $mod_tasks = \WebCareProScanner\Core\ModuleRegistry::get_cron_tasks();
            if (!empty($mod_tasks)) {
                $tasks = array_merge($tasks, $mod_tasks);
            }
        }

        return $tasks;
    }

    /**
     * Alias for get_tasks() to provide backward and test-suite compatibility.
     *
     * @return array<string, array<string, mixed>>
     */
    public static function get_registered_tasks(): array {
        return self::get_tasks();
    }

    /**
     * Get metadata definition for a single hook name.
     *
     * @param string $hook
     * @return array<string, mixed>|null
     */
    public static function get_task(string $hook): ?array {
        $tasks = self::get_tasks();
        return $tasks[$hook] ?? null;
    }

    /**
     * All plugin hook names including historical aliases to ensure clean deactivation & uninstall cleanup.
     *
     * @return string[]
     */
    public static function get_all_hook_names(): array {
        return array_values(
            array_unique(
                array_merge(
                    array_keys(self::get_tasks()),
                    [
                        'webcareproscan_scheduled_scan_cron',
                        'webcareproscan_scan_vault_temp_prune',
                    ]
                )
            )
        );
    }
}
