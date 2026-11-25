<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall\Core;

use WebCareProScanner\Firewall\BotReconDefense;
use WebCareProScanner\Firewall\MicroWafCompiler;
use WebCareProScanner\System\SettingsManager;
use WebCareProScanner\Firewall\WafFileLogger;
use WebCareProScanner\Firewall\FirewallEngine;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * BlocklistRepository
 *
 * Repository for IP blocklists, temporary/permanent bans, duration calculations,
 * and block metadata persistence.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
final class BlocklistRepository {

    /**
     * Check if an IP is in the user-defined blocklist
     *
     * @param string $ip
     * @param string|null $blocklist_str Optional blocklist string. If null, loads from SettingsManager.
     * @return bool
     */
    public static function is_ip_blocked(string $ip, ?string $blocklist_str = null): bool {
        if ($blocklist_str === null) {
            $settings = SettingsManager::get_settings();
            $blocklist_str = (string) ($settings['waf_blocked_ips'] ?? '');
        }
        return self::get_matching_blocked_entry($ip, $blocklist_str) !== null;
    }

    /**
     * Find the exact blocklist entry (IP or CIDR subnet) matching a client IP.
     *
     * @param string $ip
     * @param string $blocklist_str
     * @return string|null Matching line string or null if not blocked
     */
    public static function get_matching_blocked_entry(string $ip, string $blocklist_str): ?string {
        if (empty($blocklist_str)) {
            return null;
        }

        // Hard Guard: Local loopback can NEVER be blocked
        if (in_array($ip, ['127.0.0.1', '::1'], true)) {
            return null;
        }

        $lines = explode("\n", str_replace("\r", "", $blocklist_str));
        foreach ($lines as $line) {
            $clean = trim($line);
            if ($clean === '') {
                continue;
            }
            if ($clean === $ip) {
                return $clean;
            }
            // Simple CIDR / subnet support
            if (strpos($clean, '/') !== false && FirewallEngine::ip_in_range($ip, $clean)) {
                return $clean;
            }
        }

        return null;
    }

    /**
     * Add IP to custom blocklist with rich metadata
     *
     * @param string $ip IP address or CIDR subnet
     * @param string $reason Human-readable explanation or rule violation note
     * @param int $duration_seconds Ban duration in seconds (0 = permanent)
     * @param string|null $rule_id Unique rule identifier (e.g. 'WAF-FORBIDDEN-USERNAME')
     * @param string|null $rule_name Rule title
     * @param string|null $rule_category Rule category
     * @param string|null $incident_id Incident tracking ID (e.g. 'WEBCARE-80458BF3')
     * @param string|null $admin_user Username of administrator who added manual block
     * @return bool
     */
    public static function add_blocked_ip(
        string $ip,
        string $reason = '',
        int $duration_seconds = 0,
        ?string $rule_id = null,
        ?string $rule_name = null,
        ?string $rule_category = null,
        ?string $incident_id = null,
        ?string $admin_user = null,
        bool $sync_cloudflare = true
    ): bool {
        $ip = trim($ip);
        if (!filter_var($ip, FILTER_VALIDATE_IP) && strpos($ip, '/') === false) {
            return false;
        }

        // Safety Guard 1: Never block local loopback IPs or server origin / Docker dev gateways
        if (in_array($ip, ['127.0.0.1', '::1'], true) || FirewallEngine::is_server_origin_or_loopback($ip)) {
            return false;
        }

        // Safety Guard 1b: Never ban an official Cloudflare Anycast Edge IP or overlapping CIDR subnet locally
        // (prevents proxy self-DoS when real visitor IP trust is unconfigured or a broad CIDR is added)
        if (class_exists(ClientIpResolver::class)) {
            if (str_contains($ip, '/')) {
                if (ClientIpResolver::cidr_overlaps_cloudflare($ip)) {
                    return false;
                }
            } elseif (ClientIpResolver::is_cloudflare_ip($ip)) {
                return false;
            }
        }

        // Safety Guard 2: Refuse to add current administrator's active IP or whitelisted IP to custom blocklist
        $current_client_ip = FirewallEngine::get_client_ip();
        if ($ip === $current_client_ip && (FirewallEngine::is_authenticated_administrator() || FirewallEngine::is_authenticated_editor_or_builder())) {
            return false;
        }

        // Safety Guard 2b: Never ban an IP during a verified server-side Plugin Check / WP-CLI sandbox run
        if ($ip === $current_client_ip && FirewallEngine::is_trusted_plugin_check_or_cli_runtime()) {
            return false;
        }

        // Safety Guard 3: Immutable immunity for genuine search crawlers & uptime monitors.
        // Never allow automated honeypots or rules to inadvertently ban Googlebot, Bingbot, or verified monitors.
        if (class_exists('\\WebCareProScanner\\Firewall\\BotReconDefense')) {
            $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';
            if (BotReconDefense::is_genuine_search_engine($ip, $user_agent)) {
                return false;
            }
        }

        // Safety Guard 4: Automated Ban Immunity for Whitelisted IPs & Active Shoppers.
        // Refuse automated bans (empty $admin_user) if IP is explicitly whitelisted or belongs to an active shopper.
        if (empty($admin_user)) {
            if (AllowlistManager::is_ip_whitelisted($ip)) {
                return false;
            }
            if (class_exists('\\WebCareProScanner\\Firewall\\Core\\CommerceSessionGuard') && \WebCareProScanner\Firewall\Core\CommerceSessionGuard::has_active_shopper_session()) {
                return false;
            }
        }

        $settings = SettingsManager::get_settings();
        $current = trim($settings['waf_blocked_ips'] ?? '');
        $lines = array_filter(array_map('trim', explode("\n", str_replace("\r", "", $current))));

        if (!in_array($ip, $lines, true)) {
            $lines[] = $ip;
            $settings['waf_blocked_ips'] = implode("\n", $lines);
            SettingsManager::$suppress_firewall_ruleset_log = true;
            SettingsManager::save_settings($settings);
            SettingsManager::$suppress_firewall_ruleset_log = false;
        }

        // Persist structured metadata (enforce non-zero 24h default TTL on rule auto-bans)
        $now = time();
        $source = !empty($admin_user) ? 'manual_admin' : (!empty($rule_id) ? 'rule_auto_ban' : 'custom_blocklist');
        $effective_duration = ($source === 'rule_auto_ban' && $duration_seconds <= 0) ? 86400 : $duration_seconds;
        $expires_at = $effective_duration > 0 ? ($now + $effective_duration) : 0;

        FirewallEngine::set_ip_block_meta($ip, [
            'ip'               => $ip,
            'source'           => $source,
            'reason'           => !empty($reason) ? $reason : 'Blocked by security firewall policy',
            'duration_seconds' => $effective_duration,
            'blocked_at'       => $now,
            'expires_at'       => $expires_at,
            'rule_id'          => $rule_id,
            'rule_name'        => $rule_name,
            'rule_category'    => $rule_category,
            'incident_id'      => $incident_id,
            'admin_user'       => $admin_user,
        ]);

        // Context-Adaptive Firewall (CAF Phase 2): Queue IP ban for Cloudflare Edge synchronization
        $cf_res = ['cf_sync_state' => 'disabled', 'operation_id' => null];
        if ($sync_cloudflare && class_exists('\\WebCareProScanner\\Firewall\\CAF\\CloudflareIpListSynchronizer')) {
            $forensic_note = FirewallEngine::build_forensic_cf_note(
                !empty($reason) ? $reason : 'Blocked by security firewall policy',
                $rule_id,
                $rule_category,
                $incident_id,
                $effective_duration,
                $admin_user
            );
            $cf_res = \WebCareProScanner\Firewall\CAF\CloudflareIpListSynchronizer::queue_ip_ban(
                $ip,
                $forensic_note,
                $effective_duration > 0 ? $effective_duration : 86400
            );
        }

        self::$last_ban_cf_result = $cf_res;
        return true;
    }

    /**
     * Last Cloudflare enqueue result from add_blocked_ip().
     *
     * @var array{cf_sync_state: string, operation_id: ?string}
     */
    public static array $last_ban_cf_result = ['cf_sync_state' => 'disabled', 'operation_id' => null];

    /**
     * Compatibility alias for blocking an IP address (used by GhostRouteTrap / Bot Traps)
     *
     * @param string $ip
     * @param string $reason
     * @param int $duration_seconds
     * @param bool $sync_cloudflare
     * @return bool
     */
    public static function block_ip(string $ip, string $reason = '', int $duration_seconds = 0, bool $sync_cloudflare = true): bool {
        return self::add_blocked_ip($ip, $reason, $duration_seconds, null, null, null, null, null, $sync_cloudflare);
    }

    /**
     * Remove an IP or CIDR subnet from custom blocklist and clear any active temporary lockouts.
     * Restores normal visitor access with full WAF inspection protection active.
     *
     * @param string $ip
     * @return bool
     */
    public static function remove_blocked_ip(string $ip): bool {
        $ip = trim($ip);
        if (empty($ip)) {
            return false;
        }

        // 1. Remove from settings waf_blocked_ips
        $settings = SettingsManager::get_settings();
        $current = trim($settings['waf_blocked_ips'] ?? '');
        $lines = array_filter(array_map('trim', explode("\n", str_replace("\r", "", $current))));
        $changed = false;

        $new_lines = [];
        foreach ($lines as $line) {
            $entry_ip = trim(preg_split('/[\s#]+/', $line)[0] ?? '');
            if ($entry_ip === $ip) {
                $changed = true;
                continue;
            }
            $new_lines[] = $line;
        }

        if ($changed) {
            $settings['waf_blocked_ips'] = implode("\n", $new_lines);
            SettingsManager::$suppress_firewall_ruleset_log = true;
            SettingsManager::save_settings($settings);
            SettingsManager::$suppress_firewall_ruleset_log = false;
        }

        // 2. Unlock from Login Hardening if locked
        if (class_exists('\\WebCareProScanner\\Auth\\LoginHardening')) {
            \WebCareProScanner\Auth\LoginHardening::unlock_ip($ip);
        }

        // 3. Clear any active 404 lockout transients and WooCommerce checkout/coupon rate locks
        delete_transient('webcareproscan_404_lock_' . md5($ip));
        delete_transient('webcareproscan_404_cnt_' . md5($ip));
        delete_transient('webcareproscan_cpn_lock_' . md5($ip));
        delete_transient('webcareproscan_cpn_fail_' . md5($ip));
        delete_transient('webcareproscan_chk_lock_' . md5($ip));
        delete_transient('webcareproscan_chk_fail_' . md5($ip));
        delete_transient('webcareproscan_scrape_lock_' . md5($ip));
        delete_transient('webcareproscan_scrape_vel_' . md5($ip));
        delete_transient('webcareproscan_bot_ban_' . md5($ip));

        // 4. Clean up block metadata & lockout references
        FirewallEngine::delete_ip_block_meta($ip);
        delete_transient('webcareproscan_lockout_ip_' . md5($ip));

        // 5. Bi-Directional Cloudflare Unban Sync: Remove from Cloudflare Edge and queue
        if (class_exists('\\WebCareProScanner\\Firewall\\CAF\\CloudflareIpListSynchronizer')) {
            \WebCareProScanner\Firewall\CAF\CloudflareIpListSynchronizer::unban_ip_immediately($ip);
        }

        return true;
    }

    /**
     * Clear all expired temporary bans from the firewall blocklist in one operation.
     *
     * @return int Number of expired IP bans cleared.
     */
    public static function clear_expired_blocked_ips(): int {
        $settings = SettingsManager::get_settings();
        $blocked_raw = trim($settings['waf_blocked_ips'] ?? '');
        if (empty($blocked_raw)) {
            return 0;
        }

        $all_meta = self::get_all_block_meta();
        $now = time();
        $lines = array_filter(array_map('trim', explode("\n", str_replace("\r", "", $blocked_raw))));
        $new_lines = [];
        $cleared_count = 0;
        $cleared_ips = [];

        foreach ($lines as $line) {
            $entry_ip = trim(preg_split('/[\s#]+/', $line)[0] ?? '');
            if (empty($entry_ip)) {
                continue;
            }
            $meta = $all_meta[$entry_ip] ?? null;
            $expires_at = !empty($meta['expires_at']) ? (int) $meta['expires_at'] : 0;
            // Clear if temporary ban duration has elapsed
            if ($expires_at > 0 && $now >= $expires_at) {
                $cleared_count++;
                $cleared_ips[] = $entry_ip;
                FirewallEngine::delete_ip_block_meta($entry_ip);
                delete_transient('webcareproscan_lockout_ip_' . md5($entry_ip));
                continue;
            }
            $new_lines[] = $line;
        }

        if ($cleared_count > 0) {
            $settings['waf_blocked_ips'] = implode("\n", $new_lines);
            SettingsManager::$suppress_firewall_ruleset_log = true;
            SettingsManager::save_settings($settings);
            SettingsManager::$suppress_firewall_ruleset_log = false;
            if (class_exists(__NAMESPACE__ . '\MicroWafCompiler')) {
                MicroWafCompiler::compile_script();
            }

            // Bi-Directional Cloudflare Edge Reconciliation:
            // Prune expired edge items in bulk and purge local ledgers for cleared IPs
            if (class_exists('\\WebCareProScanner\\Firewall\\CAF\\CloudflareIpListSynchronizer')) {
                try {
                    $cf_sync = new \WebCareProScanner\Firewall\CAF\CloudflareIpListSynchronizer();
                    $cf_sync->prune_expired_bans();
                    foreach ($cleared_ips as $cip) {
                        \WebCareProScanner\Firewall\CAF\CloudflareIpListSynchronizer::unban_ip_immediately($cip);
                    }
                } catch (\Throwable $e) {
                    // Fail-safe: prevent Cloudflare API or connectivity exceptions from failing local unban
                }
            }
        }

        return $cleared_count;
    }

    /**
     * Unban and clear all blocked and locked IPs across all engines (Local WAF, Login Hardening,
     * Transients, and Cloudflare Edge) in a single atomic operation.
     *
     * @return array Structure containing cleared count, cleared IPs, and Cloudflare unban statistics.
     */
    public static function clear_all_blocked_ips(): array {
        $settings = SettingsManager::get_settings();
        $blocked_raw = trim($settings['waf_blocked_ips'] ?? '');
        $cleared_ips = [];

        // 1. Gather all custom blocklist IPs
        if (!empty($blocked_raw)) {
            $lines = array_filter(array_map('trim', explode("\n", str_replace("\r", "", $blocked_raw))));
            foreach ($lines as $line) {
                $entry_ip = trim(preg_split('/[\s#]+/', $line)[0] ?? '');
                if (!empty($entry_ip)) {
                    $cleared_ips[$entry_ip] = true;
                }
            }
        }

        // 2. Gather all login hardening locked IPs
        if (class_exists('\\WebCareProScanner\\Auth\\LoginHardening')) {
            $lockouts = \WebCareProScanner\Auth\LoginHardening::get_locked_ips();
            foreach (array_keys($lockouts) as $l_ip) {
                if (!empty($l_ip)) {
                    $cleared_ips[(string) $l_ip] = true;
                }
            }
            \WebCareProScanner\Auth\LoginHardening::clear_all_lockouts();
        }

        // 3. Gather all IPs from block metadata ledger
        $all_meta = self::get_all_block_meta();
        foreach (array_keys($all_meta) as $m_ip) {
            if (!empty($m_ip)) {
                $cleared_ips[(string) $m_ip] = true;
            }
        }

        // 4. Gather active Cloudflare edge bans ledger if present
        $cf_edge_bans = get_option('webcare_cf_active_edge_bans', []);
        if (is_array($cf_edge_bans)) {
            foreach (array_keys($cf_edge_bans) as $cf_ip) {
                if (!empty($cf_ip)) {
                    $cleared_ips[(string) $cf_ip] = true;
                }
            }
        }

        $unique_cleared_ips = array_keys($cleared_ips);

        // 5. Clear per-IP lockout transients and individual transients
        foreach ($unique_cleared_ips as $cip) {
            delete_transient('webcareproscan_404_lock_' . md5($cip));
            delete_transient('webcareproscan_404_cnt_' . md5($cip));
            delete_transient('webcareproscan_cpn_lock_' . md5($cip));
            delete_transient('webcareproscan_cpn_fail_' . md5($cip));
            delete_transient('webcareproscan_chk_lock_' . md5($cip));
            delete_transient('webcareproscan_chk_fail_' . md5($cip));
            delete_transient('webcareproscan_scrape_lock_' . md5($cip));
            delete_transient('webcareproscan_scrape_vel_' . md5($cip));
            delete_transient('webcareproscan_bot_ban_' . md5($cip));
            delete_transient('webcareproscan_lockout_ip_' . md5($cip));
            delete_transient('webcareproscan_temp_allow_' . md5($cip));
        }

        // 6. Empty custom WAF blocklist in settings
        $settings['waf_blocked_ips'] = '';
        SettingsManager::$suppress_firewall_ruleset_log = true;
        SettingsManager::save_settings($settings);
        SettingsManager::$suppress_firewall_ruleset_log = false;

        // 7. Purge entire block metadata option
        update_option(FirewallEngine::OPTION_BLOCKED_IPS_META, [], false);

        // 8. Recompile Micro-WAF script so preload drops all bans immediately
        if (class_exists(__NAMESPACE__ . '\MicroWafCompiler')) {
            MicroWafCompiler::compile_script();
        }

        // 9. Bi-Directional Cloudflare Edge Unban for all cleared IPs
        $cf_unbanned_count = 0;
        if (class_exists('\\WebCareProScanner\\Firewall\\CAF\\CloudflareIpListSynchronizer')) {
            try {
                foreach ($unique_cleared_ips as $cip) {
                    if (\WebCareProScanner\Firewall\CAF\CloudflareIpListSynchronizer::unban_ip_immediately($cip)) {
                        $cf_unbanned_count++;
                    }
                }
            } catch (\Throwable $e) {
                // Fail-safe: prevent network/API exceptions from interrupting local unban flow
            }
        }

        // Also purge any Cloudflare access rules matching this plugin's tag if configured
        if (class_exists('\\WebCareProScanner\\Cloudflare\\CloudflareService')) {
            try {
                $cf_banned = \WebCareProScanner\Cloudflare\CloudflareService::get_banned_ips(1, 100);
                if (!empty($cf_banned['success']) && !empty($cf_banned['rules']) && is_array($cf_banned['rules'])) {
                    foreach ($cf_banned['rules'] as $rule) {
                        $r_id = $rule['id'] ?? '';
                        if (!empty($r_id)) {
                            \WebCareProScanner\Cloudflare\CloudflareService::unblock_ip($r_id);
                            $cf_unbanned_count++;
                        }
                    }
                }
            } catch (\Throwable $e) {
                // Fail-safe
            }
        }

        return [
            'cleared_count' => count($unique_cleared_ips),
            'cleared_ips'   => $unique_cleared_ips,
            'cf_unbanned'   => $cf_unbanned_count,
        ];
    }

    /**
     * Retrieve aggregated list of all currently locked or custom-blocked IPs across engines with rich forensics.
     *
     * @return array
     */
    public static function get_all_locked_ips(): array {
        $results = [];
        $settings = SettingsManager::get_settings();
        $all_meta = self::get_all_block_meta();
        $now = time();

        // 1. Custom WAF Blocklisted IPs
        $blocked_raw = trim($settings['waf_blocked_ips'] ?? '');
        $seen_ips = [];

        if (!empty($blocked_raw)) {
            $lines = array_filter(array_map('trim', explode("\n", str_replace("\r", "", $blocked_raw))));
            foreach ($lines as $line) {
                $parts = preg_split('/[\s#]+/', $line);
                $ip = trim($parts[0] ?? '');
                if (empty($ip)) {
                    continue;
                }
                $inline_comment = strpos($line, '#') !== false ? trim(substr($line, strpos($line, '#') + 1)) : '';
                $seen_ips[$ip] = true;
                $meta = $all_meta[$ip] ?? null;

                // Correlate with recent WAF logs if incident ID or detailed reason is missing
                $recent_logs = [];
                $last_incident_id = $meta['incident_id'] ?? null;
                $detected_rule = $meta['rule_name'] ?? null;
                $detected_cat = $meta['rule_category'] ?? null;
                $detected_desc = null;
                $log_first_seen = null;
                $log_last_seen = null;

                if (class_exists('\\WebCareProScanner\\Firewall\\WafFileLogger')) {
                    $log_query = WafFileLogger::query_logs(['ip' => $ip], 3);
                    if (!empty($log_query['logs'])) {
                        $recent_logs = array_map(function($l) {
                            return [
                                'incident_id' => $l['incident_id'] ?? null,
                                'created_at'  => $l['created_at'] ?? null,
                                'category'    => $l['rule_category'] ?? null,
                                'description' => $l['rule_description'] ?? null,
                                'uri'         => $l['request_uri'] ?? null,
                                'method'      => $l['request_method'] ?? 'GET',
                                'status'      => $l['http_status_code'] ?? 403,
                                'user_agent'  => $l['user_agent'] ?? null,
                                'payload'     => $l['payload_sample'] ?? null,
                            ];
                        }, $log_query['logs']);

                        $top_log = $log_query['logs'][0];
                        if (empty($last_incident_id)) {
                            $last_incident_id = $top_log['incident_id'] ?? null;
                        }
                        if (empty($detected_rule)) {
                            $detected_rule = $top_log['rule_description'] ?? 'Malicious Request';
                        }
                        if (empty($detected_cat)) {
                            $detected_cat = $top_log['rule_category'] ?? 'Security Firewall';
                        }
                        $detected_desc = $top_log['rule_description'] ?? null;
                        $log_last_seen = $top_log['created_at'] ?? null;
                    }
                }

                $blocked_ts = !empty($meta['blocked_at']) ? (int) $meta['blocked_at'] : null;
                $expires_ts = !empty($meta['expires_at']) ? (int) $meta['expires_at'] : 0;
                $duration_secs = !empty($meta['duration_seconds']) ? (int) $meta['duration_seconds'] : 0;
                $admin_user = $meta['admin_user'] ?? null;
                $source = $meta['source'] ?? (!empty($admin_user) ? 'manual_admin' : 'custom_blocklist');

                // Determine Badge & Human-Readable Reason
                if ($source === 'manual_admin') {
                    $badge = 'Custom Admin Block';
                    $reason = !empty($meta['reason']) ? $meta['reason'] : sprintf('Blocked manually by administrator "%s"', $admin_user ?: 'admin');
                } elseif (!empty($detected_rule)) {
                    $badge = !empty($meta['rule_name']) ? $meta['rule_name'] : 'Firewall Violation';
                    $reason = !empty($meta['reason']) ? $meta['reason'] : ($detected_desc ?: 'Malicious activity blocked by security firewall policy');
                } else {
                    $badge = 'Custom Blocklist';
                    $reason = !empty($meta['reason']) ? $meta['reason'] : (!empty($inline_comment) ? $inline_comment : 'Permanently blocked by administrator policy');
                }

                // Timing & Duration Breakdown
                $timing = self::calculate_ban_timing($blocked_ts, $expires_ts, $duration_secs, $log_last_seen);

                $results[] = [
                    'ip'               => $ip,
                    'incident_id'      => $last_incident_id,
                    'type'             => $source,
                    'badge'            => $badge,
                    'rule_id'          => $meta['rule_id'] ?? null,
                    'rule_name'        => $detected_rule,
                    'rule_category'    => $detected_cat,
                    'reason'           => $reason,
                    'admin_user'       => $admin_user,
                    'admin_note'       => $meta['admin_note'] ?? null,
                    'blocked_at'       => $timing['ban_time'],
                    'blocked_at_raw'   => $timing['effective_ts'],
                    'ban_ago'          => $timing['ban_ago'],
                    'duration'         => $timing['duration'],
                    'duration_seconds' => $duration_secs,
                    'expires_at'       => $timing['unban_time'],
                    'expires_at_raw'   => $expires_ts,
                    'time_remaining'   => $timing['time_remaining'],
                    'countdown'        => $timing['countdown'],
                    'is_expired'       => $timing['is_expired'],
                    'is_permanent'     => $timing['is_permanent'],
                    'recent_history'   => $recent_logs,
                ];
            }
        }

        // 2. Brute-Force Login Hardening Lockouts
        if (class_exists('\\WebCareProScanner\\Auth\\LoginHardening')) {
            $lockouts = \WebCareProScanner\Auth\LoginHardening::get_locked_ips();
            foreach ($lockouts as $ip => $data) {
                $expires_ts = $data['expires_at'] ?? 0;
                $blocked_raw = $data['blocked_at'] ?? null;
                $blocked_ts = !empty($blocked_raw) ? strtotime($blocked_raw) : null;
                $duration_secs = ($expires_ts > $blocked_ts && $blocked_ts > 0) ? ($expires_ts - $blocked_ts) : 900;

                // Correlate recent log history for brute-force IP
                $recent_logs = [];
                $last_incident_id = null;
                if (class_exists('\\WebCareProScanner\\Firewall\\WafFileLogger')) {
                    $log_query = WafFileLogger::query_logs(['ip' => $ip], 3);
                    if (!empty($log_query['logs'])) {
                        $recent_logs = array_map(function($l) {
                            return [
                                'incident_id' => $l['incident_id'] ?? null,
                                'created_at'  => $l['created_at'] ?? null,
                                'category'    => $l['rule_category'] ?? null,
                                'description' => $l['rule_description'] ?? null,
                                'uri'         => $l['request_uri'] ?? null,
                                'method'      => $l['request_method'] ?? 'POST',
                                'status'      => $l['http_status_code'] ?? 403,
                                'user_agent'  => $l['user_agent'] ?? null,
                                'payload'     => $l['payload_sample'] ?? null,
                            ];
                        }, $log_query['logs']);
                        $last_incident_id = $log_query['logs'][0]['incident_id'] ?? null;
                    }
                }

                $timing = self::calculate_ban_timing($blocked_ts, $expires_ts, $duration_secs);

                // If already listed under custom blocklist, merge brute-force details
                $exists_idx = null;
                foreach ($results as $idx => $r) {
                    if ($r['ip'] === $ip) {
                        $exists_idx = $idx;
                        break;
                    }
                }

                $bf_item = [
                    'ip'               => $ip,
                    'incident_id'      => $last_incident_id,
                    'type'             => 'login_bruteforce',
                    'badge'            => 'Login Hardening',
                    'rule_id'          => 'WAF-LOGIN-BRUTEFORCE',
                    'rule_name'        => 'Login Brute-Force Rate Limiter',
                    'rule_category'    => 'Authentication Defense',
                    'reason'           => sprintf('Failed %d password attempts (user: "%s")', $data['attempts'] ?? 0, esc_html($data['username'] ?? 'unknown')),
                    'admin_user'       => null,
                    'admin_note'       => null,
                    'blocked_at'       => $timing['ban_time'],
                    'blocked_at_raw'   => $timing['effective_ts'],
                    'ban_ago'          => $timing['ban_ago'],
                    'duration'         => $timing['duration'],
                    'duration_seconds' => $duration_secs,
                    'expires_at'       => $timing['unban_time'],
                    'expires_at_raw'   => $expires_ts,
                    'time_remaining'   => $timing['time_remaining'],
                    'countdown'        => $timing['countdown'],
                    'is_expired'       => $timing['is_expired'],
                    'is_permanent'     => $timing['is_permanent'],
                    'recent_history'   => $recent_logs,
                ];

                if ($exists_idx !== null) {
                    // Update the custom blocklist card with incident details & brute-force note if higher severity
                    if (!empty($last_incident_id) && empty($results[$exists_idx]['incident_id'])) {
                        $results[$exists_idx]['incident_id'] = $last_incident_id;
                    }
                    if (!empty($recent_logs) && empty($results[$exists_idx]['recent_history'])) {
                        $results[$exists_idx]['recent_history'] = $recent_logs;
                    }
                } else {
                    $results[] = $bf_item;
                }
            }
        }

        // 3. Sort all blocked & locked IPs descending by latest ban timestamp so the latest banned IP appears first
        usort($results, function($a, $b) {
            $ts_a = isset($a['blocked_at_raw']) && is_numeric($a['blocked_at_raw']) ? (int) $a['blocked_at_raw'] : 0;
            $ts_b = isset($b['blocked_at_raw']) && is_numeric($b['blocked_at_raw']) ? (int) $b['blocked_at_raw'] : 0;
            return $ts_b <=> $ts_a;
        });

        return $results;
    }

    /**
     * Retrieve all persistent block metadata for IPs
     */
    public static function get_all_block_meta(): array {
        $meta = get_option(FirewallEngine::OPTION_BLOCKED_IPS_META, []);
        return is_array($meta) ? $meta : [];
    }

    /**
     * Compute comprehensive human-readable ban timing, countdown, and duration breakdown.
     *
     * @param int|null $blocked_ts
     * @param int $expires_ts
     * @param int $duration_secs
     * @param string|null $fallback_last_seen
     * @return array
     */
    public static function calculate_ban_timing(?int $blocked_ts, int $expires_ts, int $duration_secs, ?string $fallback_last_seen = null): array {
        $now = time();

        $effective_ts = 0;
        if ($blocked_ts && $blocked_ts > 0) {
            $effective_ts = $blocked_ts;
            $ban_time = gmdate('M j, Y, g:i a \U\T\C', $blocked_ts);
            $seconds_ago = max(0, $now - $blocked_ts);
            $ban_ago = FirewallEngine::format_seconds_human($seconds_ago) . ' ago';
        } elseif ($fallback_last_seen) {
            $ts = strtotime($fallback_last_seen);
            $effective_ts = $ts ?: 0;
            $ban_time = gmdate('M j, Y, g:i a \U\T\C', $ts);
            $ban_ago = FirewallEngine::format_seconds_human(max(0, $now - $ts)) . ' ago';
        } else {
            $effective_ts = 0;
            $ban_time = 'Unknown (Active Policy)';
            $ban_ago = 'Previously Recorded';
        }

        // 2. Duration & Expiration
        $is_permanent = ($expires_ts <= 0 || $duration_secs === 0);
        if ($is_permanent) {
            $duration = 'Permanent';
            $unban_time = 'Never (Permanent)';
            $time_remaining = 'Permanent Policy';
            $is_expired = false;
            $countdown = [
                'years'   => 0,
                'months'  => 0,
                'days'    => 0,
                'hours'   => 0,
                'minutes' => 0,
                'seconds' => 0,
            ];
        } else {
            $duration = FirewallEngine::format_duration_label($duration_secs);
            $unban_time = gmdate('M j, Y, g:i a \U\T\C', $expires_ts);
            $diff = $expires_ts - $now;

            if ($diff <= 0) {
                $is_expired = true;
                $time_remaining = 'Expired';
                $countdown = [
                    'years'   => 0,
                    'months'  => 0,
                    'days'    => 0,
                    'hours'   => 0,
                    'minutes' => 0,
                    'seconds' => 0,
                ];
            } else {
                $is_expired = false;
                $countdown = FirewallEngine::breakdown_seconds($diff);
                $time_remaining = FirewallEngine::format_countdown_human($countdown);
            }
        }

        return [
            'effective_ts'   => $effective_ts,
            'ban_time'       => $ban_time,
            'ban_ago'        => $ban_ago,
            'duration'       => $duration,
            'unban_time'     => $unban_time,
            'time_remaining' => $time_remaining,
            'countdown'      => $countdown,
            'is_expired'     => $is_expired,
            'is_permanent'   => $is_permanent,
        ];
    }
}
