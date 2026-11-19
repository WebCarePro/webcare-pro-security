<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall\Evaluators;

use WebCareProScanner\Firewall\FirewallEngine;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * RestAndAjaxEvaluator
 *
 * Enforces policies for WordPress REST API and Admin AJAX routes.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
final class RestAndAjaxEvaluator {

    /**
     * Check user enumeration via REST API.
     *
     * @param mixed $access
     * @return mixed
     */
    public static function check_rest_user_enumeration(mixed $access): mixed {
        return FirewallEngine::check_rest_user_enumeration($access);
    }

    /**
     * Enforce guest AJAX policy.
     *
     * @param array<string, mixed> $settings
     */
    public static function check_guest_ajax_policy(string $request_uri, array $settings, string $client_ip): void {
        FirewallEngine::check_guest_ajax_policy($request_uri, $settings, $client_ip);
    }

    /**
     * Verify if request is a verified MCP bearer token request.
     *
     * @param mixed $request
     */
    public static function is_verified_mcp_bearer_request(mixed $request, string $client_ip): bool {
        return FirewallEngine::is_verified_mcp_bearer_request($request, $client_ip);
    }

    /**
     * Check if a custom REST route is allowed for guests.
     *
     * @param array<int, string> $custom_lines
     */
    public static function is_custom_rest_route_allowed(string $route, string $method, array $custom_lines): bool {
        return FirewallEngine::is_custom_rest_route_allowed($route, $method, $custom_lines);
    }

    /**
     * Inspect guest REST API dispatch.
     *
     * @param mixed $result
     * @param mixed $server
     * @param mixed $request
     * @return mixed
     */
    public static function inspect_guest_rest_dispatch(mixed $result, mixed $server, mixed $request): mixed {
        return FirewallEngine::inspect_guest_rest_dispatch($result, $server, $request);
    }
}
