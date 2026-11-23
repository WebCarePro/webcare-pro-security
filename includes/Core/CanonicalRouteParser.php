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
     * Normalize a raw URI or path into a canonical path:
     * 1. Strips control characters (NUL, CR, LF).
     * 2. Strips query string and fragment.
     * 3. Runs up to 3 passes of rawurldecode() until stable.
     * 4. Collapses repeated slashes and backslashes.
     * 5. Resolves '.' and '..' dot-segments via a path-segment stack, preserving leading '/' and trailing '/'.
     *
     * @param string $raw_uri Raw URI or path string.
     * @return string Canonical normalized path.
     */
    public static function normalize_path(string $raw_uri): string {
        $clean = str_replace(["\0", "\r", "\n"], '', $raw_uri);
        $path = (string) strtok($clean, '?#');

        for ($i = 0; $i < 3; $i++) {
            $prev = $path;
            $path = rawurldecode($path);
            $path = str_replace(["\0", "\r", "\n"], '', $path);
            if ($path === $prev) {
                break;
            }
        }

        $collapsed = preg_replace('#[\\\\/]+#', '/', $path);
        if (!is_string($collapsed) || $collapsed === '') {
            return '/';
        }

        $has_trailing_slash = str_ends_with($collapsed, '/') && strlen($collapsed) > 1;
        $segments = explode('/', trim($collapsed, '/'));
        $stack = [];
        foreach ($segments as $seg) {
            if ($seg === '' || $seg === '.') {
                continue;
            }
            if ($seg === '..') {
                array_pop($stack);
            } else {
                $stack[] = $seg;
            }
        }

        if (empty($stack)) {
            return '/';
        }

        $result = '/' . implode('/', $stack);
        if ($has_trailing_slash) {
            $result .= '/';
        }

        return $result;
    }

    /**
     * Parse and normalize the incoming request path from server environment.
     *
     * Note: If a caller passes $server['REQUEST_URI'], it must already be unslashed once.
     * When falling back to $_SERVER['REQUEST_URI'], wp_unslash() is called automatically.
     *
     * @param array<string, mixed> $server Reference to $_SERVER or array.
     * @return string Normalized leading-and-trailing slash path (e.g. '/wp-json/wp/v2/posts/').
     */
    public static function get_normalized_path(array $server = []): string {
        $has_explicit_uri = array_key_exists('REQUEST_URI', $server);
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- WAF route canonicalization must retain percent-encoded octets prior to rawurldecode() / parse_str()
        $uri_raw = (string) ($server['REQUEST_URI'] ?? (isset($_SERVER['REQUEST_URI']) ? wp_unslash($_SERVER['REQUEST_URI']) : '/'));
        return self::normalize_path($uri_raw);
    }

    /**
     * Resolve the canonical REST API route string if the request is a REST call.
     *
     * Note: If a caller passes $server['REQUEST_URI'], it must already be unslashed once.
     * When falling back to $_SERVER['REQUEST_URI'], wp_unslash() is called automatically.
     *
     * @param array<string, mixed> $server Reference to $_SERVER.
     * @return string Normalized route with leading slash (e.g. '/webcare-pro-security/v1/scan/status') or empty string.
     */
    public static function resolve_rest_route(array $server = []): string {
        $has_explicit_uri = array_key_exists('REQUEST_URI', $server);
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- WAF route canonicalization must retain percent-encoded octets prior to rawurldecode() / parse_str()
        $uri_raw = (string) ($server['REQUEST_URI'] ?? (isset($_SERVER['REQUEST_URI']) ? wp_unslash($_SERVER['REQUEST_URI']) : '/'));
        $uri = str_replace(["\0", "\r", "\n"], '', $uri_raw);
        $query_str = (string) (wp_parse_url($uri, PHP_URL_QUERY) ?? '');
        $query_params = [];
        if ($query_str !== '') {
            parse_str($query_str, $query_params);
        }

        // 1. Check ?rest_route= query parameter (from server URI first, falling back to $_GET only when $server lacks REQUEST_URI)
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- WAF route canonicalization must retain percent-encoded octets prior to rawurldecode()
        $rest_route_param = $query_params['rest_route'] ?? (!$has_explicit_uri ? (isset($_GET['rest_route']) ? str_replace(["\0", "\r", "\n"], '', (string) wp_unslash($_GET['rest_route'])) : null) : null);
        if (is_string($rest_route_param) && $rest_route_param !== '') {
            $query_route = str_replace(["\0", "\r", "\n"], '', $rest_route_param);
            for ($i = 0; $i < 3; $i++) {
                $prev = $query_route;
                $query_route = rawurldecode($query_route);
                if ($query_route === $prev) {
                    break;
                }
            }
            return '/' . ltrim(preg_replace('#[\\\\/]+#', '/', $query_route) ?? '', '/');
        }

        // 2. Check path-based REST route
        $path = self::get_normalized_path($server);
        $path_lower = strtolower($path);
        $prefix = function_exists('rest_get_url_prefix') ? rest_get_url_prefix() : 'wp-json';
        $prefix_segment = '/' . strtolower(trim($prefix, '/')) . '/';

        $pos = strpos($path_lower, $prefix_segment);
        if ($pos !== false) {
            $route_part = substr($path, $pos + strlen($prefix_segment) - 1);
            return '/' . ltrim(preg_replace('#[\\\\/]+#', '/', $route_part) ?? '', '/');
        }

        // Fallback check for /wp-json/ if custom prefix was empty or different
        if (str_contains($path_lower, '/wp-json/')) {
            $pos = strpos($path_lower, '/wp-json/');
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
