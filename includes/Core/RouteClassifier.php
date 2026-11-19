<?php
declare(strict_types=1);

namespace WebCareProScanner\Core;

use WebCareProScanner\Contracts\RouteClass;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * RouteClassifier
 *
 * Ultra-fast (<0.02ms) deterministic route classification based purely on request URI and environment.
 * Maps incoming HTTP requests to their corresponding RouteClass enum without executing database queries.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
final class RouteClassifier {

    /**
     * Classify incoming request into a deterministic RouteClass.
     *
     * @param array<string, mixed> $server Usually $_SERVER
     * @return RouteClass
     */
    public static function classify(array $server): RouteClass {
        $uri = (string) ($server['REQUEST_URI'] ?? '/');
        $path = strtolower((string) (wp_parse_url($uri, PHP_URL_PATH) ?? $uri));
        $method = strtoupper((string) ($server['REQUEST_METHOD'] ?? 'GET'));

        // 1. Admin UI
        if (str_contains($path, '/wp-admin/') && !str_contains($path, 'admin-ajax.php') && !str_contains($path, 'admin-post.php')) {
            return RouteClass::AdminUi;
        }

        // 2. Admin AJAX / Post
        if (str_contains($path, 'admin-ajax.php') || str_contains($path, 'admin-post.php')) {
            return RouteClass::AdminAjax;
        }

        // 3. REST API
        if (str_contains($path, '/wp-json/')) {
            return RouteClass::RestApi;
        }

        // 4. GraphQL
        if (str_contains($path, '/graphql')) {
            return RouteClass::GraphQL;
        }

        // 5. Auth / Login Entrypoints
        if (str_contains($path, 'wp-login.php') || str_contains($path, 'wp-signup.php')) {
            return RouteClass::AuthLogin;
        }

        // 6. Commerce Routes (WooCommerce checkout, cart, API webhooks)
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        if (
            str_contains($path, '/checkout')
            || str_contains($path, '/cart')
            || isset($_GET['wc-ajax'])
            || isset($_GET['wc-api'])
            || str_contains($path, 'wc-api')
        ) {
            return RouteClass::Commerce;
        }

        // 7. Membership / Account Routes
        if (
            str_contains($path, '/my-account')
            || str_contains($path, '/account')
            || str_contains($path, '/portal')
            || str_contains($path, '/membership')
        ) {
            return RouteClass::Membership;
        }

        // 8. Public Standard Requests
        return RouteClass::PublicGet;
    }
}
