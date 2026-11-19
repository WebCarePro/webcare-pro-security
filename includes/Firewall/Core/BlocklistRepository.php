<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall\Core;

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
     * Check if an IP is blocked against the active blocklist string.
     */
    public static function is_ip_blocked(string $ip, string $blocklist_str): bool {
        return FirewallEngine::is_ip_blocked($ip, $blocklist_str);
    }

    /**
     * Get the matching entry that blocked the given IP.
     */
    public static function get_matching_blocked_entry(string $ip, string $blocklist_str): ?string {
        return FirewallEngine::get_matching_blocked_entry($ip, $blocklist_str);
    }

    /**
     * Add an IP to the active blocked list with metadata.
     */
    public static function add_blocked_ip(
        string $ip,
        string $reason = '',
        string $threat_level = 'high',
        string $rule_id = '',
        string $cf_rule_id = '',
        int $duration_seconds = 0
    ): bool {
        return FirewallEngine::add_blocked_ip($ip, $reason, $threat_level, $rule_id, $cf_rule_id, $duration_seconds);
    }

    /**
     * Block an IP.
     */
    public static function block_ip(string $ip, string $reason = '', int $duration_seconds = 0): bool {
        return FirewallEngine::block_ip($ip, $reason, $duration_seconds);
    }

    /**
     * Remove an IP from the blocklist.
     */
    public static function remove_blocked_ip(string $ip): bool {
        return FirewallEngine::remove_blocked_ip($ip);
    }

    /**
     * Clear all expired temporary IP blocks.
     */
    public static function clear_expired_blocked_ips(): int {
        return FirewallEngine::clear_expired_blocked_ips();
    }

    /**
     * Get all currently locked IPs.
     *
     * @return array<int, array<string, mixed>>
     */
    public static function get_all_locked_ips(): array {
        return FirewallEngine::get_all_locked_ips();
    }

    /**
     * Get all block metadata entries.
     *
     * @return array<string, array<string, mixed>>
     */
    public static function get_all_block_meta(): array {
        return FirewallEngine::get_all_block_meta();
    }

    /**
     * Calculate human and machine-readable ban timing.
     *
     * @return array<string, mixed>
     */
    public static function calculate_ban_timing(?int $blocked_ts, int $expires_ts, int $duration_secs, ?string $fallback_last_seen = null): array {
        return FirewallEngine::calculate_ban_timing($blocked_ts, $expires_ts, $duration_secs, $fallback_last_seen);
    }
}
