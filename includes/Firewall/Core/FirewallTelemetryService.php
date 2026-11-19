<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall\Core;

use WebCareProScanner\Firewall\FirewallEngine;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * FirewallTelemetryService
 *
 * Dedicated service providing telemetry, engine status, rule catalogs, and log management.
 * Loaded strictly in administrative, REST, and WP-CLI contexts.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
final class FirewallTelemetryService {

    /**
     * Get complete status of the firewall engine.
     *
     * @return array<string, mixed>
     */
    public static function get_status(): array {
        return FirewallEngine::get_status();
    }

    /**
     * Get server and PHP runtime telemetry.
     *
     * @return array<string, mixed>
     */
    public static function get_server_telemetry(): array {
        return FirewallEngine::get_server_telemetry();
    }

    /**
     * Get the active firewall rules catalog.
     *
     * @return array<int, array<string, mixed>>
     */
    public static function get_firewall_rules_catalog(): array {
        return FirewallEngine::get_firewall_rules_catalog();
    }

    /**
     * Query firewall logs with pagination and filters.
     *
     * @param array<string, mixed> $filters
     * @return array<string, mixed>
     */
    public static function get_logs(int $limit = 50, int $offset = 0, array $filters = []): array {
        return FirewallEngine::get_logs($limit, $offset, $filters);
    }

    /**
     * Get aggregated log statistics.
     *
     * @return array<string, mixed>
     */
    public static function get_log_stats(string $range = 'today'): array {
        return FirewallEngine::get_log_stats($range);
    }

    /**
     * Delete a single firewall log record.
     */
    public static function delete_log(int|string $id): bool {
        return FirewallEngine::delete_log($id);
    }

    /**
     * Clear all firewall logs.
     */
    public static function clear_logs(): bool {
        return FirewallEngine::clear_logs();
    }
}
