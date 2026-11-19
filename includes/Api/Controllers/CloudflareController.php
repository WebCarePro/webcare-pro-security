<?php
declare(strict_types=1);

namespace WebCareProScanner\Api\Controllers;

use WebCareProScanner\Api\ScannerRoutes;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * CloudflareController
 *
 * Cloudflare & Threat Intel REST Controller.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
final class CloudflareController extends AbstractApiController {

    /**
     * Register endpoints for this domain.
     *
     * @param string   $namespace REST API route namespace.
     * @param callable $permission Permission callback.
     */
    public static function register(string $namespace, callable $permission): void {
        register_rest_route($namespace, '/threat-intel/status', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_threat_intel_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/threat-intel/sync', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'sync_threat_intel'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/threat-intel/cves', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_threat_intel_cves'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/cloudflare/status', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_cloudflare_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/cloudflare/verify', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'verify_cloudflare_credentials'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/cloudflare/deploy-rules', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'deploy_cloudflare_rules'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/cloudflare/deploy-single-rule', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'deploy_single_cloudflare_rule'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/cloudflare/rate-limiting', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'toggle_cloudflare_rate_limiting'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/cloudflare/sync-ip', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'block_cloudflare_ip'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/cloudflare/sync-all-blocked-ips', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'sync_all_blocked_ips_to_cloudflare'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/cloudflare/banned-ips', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_cloudflare_banned_ips'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/cloudflare/unblock-ip', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'unblock_cloudflare_ip'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/cloudflare/purge-cache', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'purge_cloudflare_cache'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/cloudflare/inspect-rules', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'inspect_cloudflare_rules'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/cloudflare/whitelist-ip', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'whitelist_cloudflare_ip'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/cloudflare/whitelisted-ips', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_cloudflare_whitelisted_ips'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/cloudflare/remove-whitelisted-ip', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'remove_cloudflare_whitelisted_ip'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/cloudflare/disconnect', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'disconnect_cloudflare'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/cloudflare/firewall-events', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_cloudflare_firewall_events'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/cloudflare/fetch-firewall-events', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'fetch_cloudflare_firewall_events'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/cloudflare/clear-firewall-events', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'clear_cloudflare_firewall_events'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/threat-intel/network', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_threat_intel_network'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/threat-intel/sync', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'sync_threat_intel_network'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/threat-intel/reputation-check', [
            'methods'             => ['GET', 'POST'],
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'check_threat_intel_reputation'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/domain-reputation/status', [
            'methods'             => 'GET',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'get_domain_reputation_status'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/domain-reputation/check', [
            'methods'             => 'POST',
            'callback'            => [\WebCareProScanner\Api\ScannerRoutes::class, 'check_domain_reputation_now'],
            'permission_callback' => $permission,
        ]);

    }
}