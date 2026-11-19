<?php
declare(strict_types=1);

namespace WebCareProScanner\Core;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * CanonicalRouteParser
 *
 * Single authoritative normalizer and parser for request URIs and REST API routes.
 * Ensures consistent route evaluation across RouteClassifier, RestRouter, and MicroWaf.
 *
 * Handles:
 * - Percent-encoded traversal and path segments (e.g. /%77p-json/ -> /wp-json/)
 * - Redundant slashes and directory normalizations
 * - Query-based REST parameters (?rest_route=/...)
 * - Subdirectory installations via rest_get_url_prefix()
 *
 * Author: Mir Alamin (WebCare Pro)
 */
final class CanonicalRouteParser {

    /**
     * Parse and normalize the incoming request path from server environment.
     *
     * @param array<string, mixed> $server Reference to $_SERVER or array.
     * @return string Normalized leading-and-trailing slash path (e.g. '/wp-json/wp/v2/posts/').
     */
    public static function get_normalized_path(array $server = []): string {
        $uri = (string) ($server['REQUEST_URI'] ?? ($_SERVER['REQUEST_URI'] ?? '/'));

        // Strip query string and fragment
        $path = (string) strtok($uri, '?#');

        // URL-decode until fully decoded to neutralize multi-layer encoding attacks
        $decoded = $path;
        for ($i = 0; $i < 3; $i++) {
            $prev = $decoded;
            $decoded = rawurldecode($decoded);
            if ($decoded === $prev) {
                break;
            }
        }

        // Collapse multiple slashes and backslashes
        $clean = preg_replace('#[\\\\/]+#', '/', $decoded);
        if (!is_string($clean) || $clean === '') {
            $clean = '/';
        }

        // Return path with standard leading slash
        return '/' . ltrim($clean, '/');
    }

    /**
     * Resolve the canonical REST API route string if the request is a REST call.
     *
     * @param array<string, mixed> $server Reference to $_SERVER.
     * @return string Normalized route with leading slash (e.g. '/webcare-pro-security/v1/scan/status') or empty string.
     */
    public static function resolve_rest_route(array $server = []): string {
        // 1. Check ?rest_route= query parameter
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        if (isset($_GET['rest_route']) && is_string($_GET['rest_route']) && $_GET['rest_route'] !== '') {
            $query_route = rawurldecode(wp_unslash($_GET['rest_route']));
            return '/' . ltrim(preg_replace('#[\\\\/]+#', '/', $query_route) ?? '', '/');
        }

        // 2. Check path-based REST route
        $path = self::get_normalized_path($server);
        $prefix = function_exists('rest_get_url_prefix') ? rest_get_url_prefix() : 'wp-json';
        $prefix_segment = '/' . trim($prefix, '/') . '/';

        $pos = strpos($path, $prefix_segment);
        if ($pos !== false) {
            $route_part = substr($path, $pos + strlen($prefix_segment) - 1);
            return '/' . ltrim(preg_replace('#[\\\\/]+#', '/', $route_part) ?? '', '/');
        }

        // Fallback check for /wp-json/ if custom prefix was empty or different
        if (str_contains($path, '/wp-json/')) {
            $pos = strpos($path, '/wp-json/');
            $route_part = substr($path, $pos + 8);
            return '/' . ltrim(preg_replace('#[\\\\/]+#', '/', $route_part) ?? '', '/');
        }

        return '';
    }

    /**
     * Check if the current request is an internal or external REST API request.
     *
     * @param array<string, mixed> $server
     */
    public static function is_rest_request(array $server = []): bool {
        return self::resolve_rest_route($server) !== '';
    }
}
