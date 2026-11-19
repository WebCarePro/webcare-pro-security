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
        $method = strtoupper((string) ($server['REQUEST_METHOD'] ?? 'GET'));
        $path = strtolower(CanonicalRouteParser::get_normalized_path($server));
        $has_rest_query = CanonicalRouteParser::is_rest_request($server);

        // 1. Admin UI
        if (str_contains($path, '/wp-admin/') && !str_contains($path, 'admin-ajax.php') && !str_contains($path, 'admin-post.php')) {
            return RouteClass::AdminUi;
        }

        // 2. Admin AJAX / Post
        if (str_contains($path, 'admin-ajax.php') || str_contains($path, 'admin-post.php')) {
            return RouteClass::AdminAjax;
        }

        // 3. REST API (both /wp-json/ rewrite and ?rest_route= query forms)
        if (str_contains($path, '/wp-json/') || $has_rest_query) {
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

        // 6. Commerce Routes (WooCommerce checkout, cart, API webhooks, dynamic slugs)
        $commerce_matched = false;
        $path_trailing = rtrim($path, '/') . '/';

        $uri = (string) ($server['REQUEST_URI'] ?? ($_SERVER['REQUEST_URI'] ?? '/'));
        $query_str = (string) (wp_parse_url($uri, PHP_URL_QUERY) ?? '');
        $query_params = [];
        if ($query_str !== '') {
            parse_str($query_str, $query_params);
        }
        $has_explicit_uri = array_key_exists('REQUEST_URI', $server);
        $has_wc_ajax = isset($query_params['wc-ajax']) || (!$has_explicit_uri && isset($_GET['wc-ajax']));
        $has_wc_api  = isset($query_params['wc-api']) || (!$has_explicit_uri && isset($_GET['wc-api']));

        if (
            str_contains($path, '/checkout')
            || str_contains($path, '/cart')
            || $has_wc_ajax
            || $has_wc_api
            || str_contains($path, 'wc-api')
        ) {
            $commerce_matched = true;
        }

        // Match against compiled localized slugs if manifest exists
        if (!$commerce_matched && class_exists(CompiledStackManifest::class)) {
            $manifest = CompiledStackManifest::load();
            if (!empty($manifest['commerce_slugs']) && is_array($manifest['commerce_slugs'])) {
                foreach ($manifest['commerce_slugs'] as $c_slug) {
                    if ($c_slug !== '' && str_contains($path_trailing, '/' . trim($c_slug, '/') . '/')) {
                        $commerce_matched = true;
                        break;
                    }
                }
            }
        }

        if ($commerce_matched) {
            return RouteClass::Commerce;
        }

        // 7. Membership / Account Routes
        $membership_matched = false;
        if (
            str_contains($path, '/my-account')
            || str_contains($path, '/account')
            || str_contains($path, '/portal')
            || str_contains($path, '/membership')
        ) {
            $membership_matched = true;
        }

        // Match against compiled localized membership slugs if manifest exists
        if (!$membership_matched && class_exists(CompiledStackManifest::class)) {
            $manifest = CompiledStackManifest::load();
            if (!empty($manifest['membership_slugs']) && is_array($manifest['membership_slugs'])) {
                foreach ($manifest['membership_slugs'] as $m_slug) {
                    if ($m_slug !== '' && str_contains($path_trailing, '/' . trim($m_slug, '/') . '/')) {
                        $membership_matched = true;
                        break;
                    }
                }
            }
        }

        if ($membership_matched) {
            return RouteClass::Membership;
        }

        // 8. Public Standard Requests (Differentiate GET vs Mutation)
        if (!in_array($method, ['GET', 'HEAD', 'OPTIONS'], true)) {
            return RouteClass::PublicMutation;
        }

        return RouteClass::PublicGet;
    }
}
