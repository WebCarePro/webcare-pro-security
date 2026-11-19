<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall\Core;

use WebCareProScanner\Firewall\FirewallEngine;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * AllowlistManager
 *
 * Manages IP, URL, and targeted allowlist rules, rDNS validations, ASN lookups,
 * and enforces confirmed-exploit precedence.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
final class AllowlistManager {

    /**
     * Check if an IP is allowlisted.
     */
    public static function is_ip_whitelisted(string $ip, ?string $whitelist_str = null): bool {
        return FirewallEngine::is_ip_whitelisted($ip, $whitelist_str);
    }

    /**
     * Check if a request URI matches the URL allowlist text.
     */
    public static function is_url_whitelisted(string $uri, string $whitelist_text): bool {
        return FirewallEngine::is_url_whitelisted($uri, $whitelist_text);
    }

    /**
     * Check if request matches configured contact/support URL boundaries.
     */
    public static function is_configured_support_path(string $request_uri, string $configured_contact_url): bool {
        return FirewallEngine::is_configured_support_path($request_uri, $configured_contact_url);
    }

    /**
     * Match targeted allowlist rule (endpoint, user-agent, IP).
     *
     * @param array<int, array<string, mixed>> $rules
     * @return array<string, mixed>|null
     */
    public static function match_targeted_allowlist_rule(string $uri, string $user_agent, string $ip, string $method, array $rules): ?array {
        return FirewallEngine::match_targeted_allowlist_rule($uri, $user_agent, $ip, $method, $rules);
    }

    /**
     * Verify rDNS hostname against target domain.
     */
    public static function verify_rdns_domain(string $ip, string $target_domain): bool {
        return FirewallEngine::verify_rdns_domain($ip, $target_domain);
    }

    /**
     * Get client ASN string.
     */
    public static function get_client_asn(string $ip): string {
        return FirewallEngine::get_client_asn($ip);
    }

    /**
     * Check allowlist context flags for an IP.
     *
     * @param array<string, mixed> $settings
     * @param array<string, mixed>|null $rule
     * @return array{is_whitelisted: bool, full_bypass: bool, rule_bypass: bool, is_admin: bool}
     */
    public static function check_ip_whitelist_context(string $client_ip, array $settings, ?array $rule = null): array {
        return FirewallEngine::check_ip_whitelist_context($client_ip, $settings, $rule);
    }

    /**
     * Enforces the allowlist decision truth-table: confirmed exploits and critical categories
     * can NEVER be bypassed by unauthenticated allowlisted traffic.
     */
    public static function can_ip_whitelist_bypass_rule(bool $is_admin, bool $full_bypass, bool $rule_bypass, bool $is_critical_exploit): bool {
        return FirewallEngine::can_ip_whitelist_bypass_rule($is_admin, $full_bypass, $rule_bypass, $is_critical_exploit);
    }
}
