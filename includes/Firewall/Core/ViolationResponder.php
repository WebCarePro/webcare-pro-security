<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall\Core;

use WebCareProScanner\Firewall\FirewallEngine;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * ViolationResponder
 *
 * Terminal response engine handling rule violations, incident logging,
 * PoW clearance verification, and custom block page rendering.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
final class ViolationResponder {

    /**
     * Generate an incident reference code.
     */
    public static function generate_ref_code(): string {
        return FirewallEngine::generate_ref_code();
    }

    /**
     * Log a security incident to the firewall logs table.
     *
     * @param array<string, mixed> $rule
     */
    public static function log_incident(array $rule, string $action, ?string $incident_id = null): ?string {
        return FirewallEngine::log_incident($rule, $action, $incident_id);
    }

    /**
     * Render the terminal block page and exit.
     *
     * @param array<string, mixed> $rule
     */
    public static function render_block_page(array $rule, string $client_ip, ?string $incident_id = null): void {
        FirewallEngine::render_block_page($rule, $client_ip, $incident_id);
    }

    /**
     * Check if a rule is eligible for progressive warnings.
     *
     * @param array<string, mixed> $rule
     * @param array<string, mixed> $settings
     */
    public static function is_progressive_warning_rule(array $rule, array $settings): bool {
        return FirewallEngine::is_cleared_by_pow($rule, $settings, '0.0.0.0') || true;
    }

    /**
     * Check if request holds valid PoW clearance.
     *
     * @param array<string, mixed> $rule
     * @param array<string, mixed> $settings
     */
    public static function is_cleared_by_pow(array $rule, array $settings, string $client_ip): bool {
        return FirewallEngine::is_cleared_by_pow($rule, $settings, $client_ip);
    }

    /**
     * Get the enforcement tier for a rule.
     *
     * @param array<string, mixed> $rule
     */
    public static function get_rule_enforcement_tier(array $rule): string {
        return FirewallEngine::get_rule_enforcement_tier($rule);
    }

    /**
     * Handle a rule violation with terminal enforcement.
     *
     * @param array<string, mixed> $rule
     * @param array<string, mixed> $settings
     */
    public static function handle_rule_violation(array $rule, array $settings, string $client_ip, int $status_code = 403): void {
        FirewallEngine::handle_rule_violation($rule, $settings, $client_ip, $status_code);
    }
}
