<?php
declare(strict_types=1);

namespace WebCareProScanner\Api;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * RestRouter
 *
 * Micro-router for WebCare Pro REST API.
 * Orchestrates registration across the 9 domain controllers and CronRoutes.
 *
 * In PR 2, delegates to all 9 domain controllers to maintain 100% route catalog parity.
 * In PR 4, enables canonical 5-case lazy loading based on request prefix.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
final class RestRouter {

    public const NAMESPACE = 'webcare-pro-security/v1';

    /**
     * Map of top-level route prefixes to domain controllers.
     *
     * @var array<string, class-string>
     */
    public const PREFIX_MAP = [
        // 1. ScanController
        'scan'                 => Controllers\ScanController::class,
        'vulnerabilities'      => Controllers\ScanController::class,
        'file'                 => Controllers\ScanController::class,
        'post'                 => Controllers\ScanController::class,
        'issues'               => Controllers\ScanController::class,
        'component'            => Controllers\ScanController::class,

        // 2. FirewallController
        'firewall'             => Controllers\FirewallController::class,
        'caf'                  => Controllers\FirewallController::class,
        'rescue'               => Controllers\FirewallController::class,
        'whitelist'            => Controllers\FirewallController::class,
        'server-security'      => Controllers\FirewallController::class,
        'redirect-shield'      => Controllers\FirewallController::class,

        // 3. ModularWafController
        'modular-waf'          => Controllers\ModularWafController::class,
        'virtual-patch'        => Controllers\ModularWafController::class,
        'behavioral'           => Controllers\ModularWafController::class,
        'defense'              => Controllers\ModularWafController::class,

        // 4. AuthController
        'auth'                 => Controllers\AuthController::class,
        'identity'             => Controllers\AuthController::class,

        // 5. McpController
        'mcp'                  => Controllers\McpController::class,
        'ai'                   => Controllers\McpController::class,

        // 6. CloudflareController
        'cloudflare'           => Controllers\CloudflareController::class,
        'threat-intel'         => Controllers\CloudflareController::class,
        'domain-reputation'    => Controllers\CloudflareController::class,

        // 7. RemediationController
        'quarantine'           => Controllers\RemediationController::class,
        'remediation'          => Controllers\RemediationController::class,
        'database'             => Controllers\RemediationController::class,
        'user'                 => Controllers\RemediationController::class,
        'users'                => Controllers\RemediationController::class,
        'reinfection-watchdog' => Controllers\RemediationController::class,
        'persistence'          => Controllers\RemediationController::class,
        'attack-chain'         => Controllers\RemediationController::class,
        'permissions'          => Controllers\RemediationController::class,
        'transactions'         => Controllers\RemediationController::class,

        // 8. IntegrityController
        'supply-chain'         => Controllers\IntegrityController::class,
        'integrity'            => Controllers\IntegrityController::class,
        'snapshots'            => Controllers\IntegrityController::class,
        'baseline'             => Controllers\IntegrityController::class,
        'self-defense'         => Controllers\IntegrityController::class,
        'hooks'                => Controllers\IntegrityController::class,

        // 9. SystemController
        'backup'               => Controllers\SystemController::class,
        'settings'             => Controllers\SystemController::class,
        'activity-logs'        => Controllers\SystemController::class,
        'notifications'        => Controllers\SystemController::class,
        'vault'                => Controllers\SystemController::class,
        'wizard'               => Controllers\SystemController::class,
        'site-advisor'         => Controllers\SystemController::class,
        'hardening'            => Controllers\SystemController::class,
        'containment'          => Controllers\SystemController::class,
        'security'             => Controllers\SystemController::class,
        'modules'              => Controllers\SystemController::class,
        'server-info'          => Controllers\SystemController::class,
        'telemetry'            => Controllers\SystemController::class,
        'system'               => Controllers\SystemController::class,
        'readiness'            => Controllers\SystemController::class,
        'welcome'              => Controllers\SystemController::class,
        'reports'              => Controllers\SystemController::class,
        'comment'              => Controllers\SystemController::class,
        'correlation'          => Controllers\SystemController::class,

        // Cron management
        'cron-manager'         => CronRoutes::class,
    ];

    /**
     * Register REST API routes using canonical 5-case lazy loading.
     *
     * 1. Discovery/Index (/wp-json/ or /wp-json/webcare-pro-security/v1): registers all controllers.
     * 2. Known WebCare prefix: registers ONLY matching controller(s).
     * 3. NextGen module prefix ('nextgen'): registers ModuleRegistry nextgen routes.
     * 4. Unknown WebCare prefix: registers 0 controllers (WP 404 fallback).
     * 5. Non-WebCare route (/wp/v2/..., etc.): registers 0 controllers (zero memory overhead).
     */
    public static function register(): void {
        // Resolve canonical route using unslashed URI snapshot; CanonicalRouteParser handles single-unslash boundary automatically when no args are passed.
        $resolved_route = \WebCareProScanner\Core\CanonicalRouteParser::resolve_rest_route();

        // Case 1: REST Discovery / Index query
        // E.g. GET /wp-json/, GET /wp-json/webcare-pro-security/v1, or empty route
        $is_discovery = (
            $resolved_route === ''
            || $resolved_route === '/'
            || $resolved_route === '/' . self::NAMESPACE
            || $resolved_route === '/' . self::NAMESPACE . '/'
        );

        if ($is_discovery) {
            self::register_all();
            return;
        }

        // Case 5: Non-WebCare route (e.g. /wp/v2/posts, /wc/v3/orders)
        $ns_prefix = '/' . self::NAMESPACE . '/';
        if (!str_starts_with(strtolower($resolved_route), strtolower($ns_prefix))) {
            // Zero WebCare controllers registered on foreign REST requests
            return;
        }

        // Extract relative route segment after namespace prefix: e.g. 'firewall/status'
        $relative_route = substr($resolved_route, strlen($ns_prefix));
        $prefix = strtolower((string) strtok($relative_route, '/'));

        // Case 3: NextGen module routes (/webcare-pro-security/v1/nextgen/...)
        if ($prefix === 'nextgen') {
            if (class_exists('\\WebCareProScanner\\Core\\ModuleRegistry')) {
                \WebCareProScanner\Core\ModuleRegistry::register_rest_routes(self::NAMESPACE);
            }
            return;
        }

        // Case 2: Known WebCare route prefix
        if (isset(self::PREFIX_MAP[$prefix])) {
            $controller = self::PREFIX_MAP[$prefix];
            $permission = static function (): bool {
                return current_user_can('manage_options');
            };

            if ($controller === CronRoutes::class) {
                if (class_exists(CronRoutes::class)) {
                    CronRoutes::register($permission);
                }
            } elseif (class_exists($controller) && method_exists($controller, 'register')) {
                $controller::register(self::NAMESPACE, $permission);
            }
            return;
        }

        // Case 4: Unknown WebCare prefix: register 0 controllers (WP core returns 404 rest_no_route)
    }

    /**
     * Register all domain controllers, cron routes, and nextgen modules.
     * Invoked during REST index discovery or schema reflection.
     */
    public static function register_all(): void {
        $permission = static function (): bool {
            return current_user_can('manage_options');
        };

        if (class_exists(CronRoutes::class)) {
            CronRoutes::register($permission);
        }

        // Register all domain controllers
        Controllers\ScanController::register(self::NAMESPACE, $permission);
        Controllers\FirewallController::register(self::NAMESPACE, $permission);
        Controllers\ModularWafController::register(self::NAMESPACE, $permission);
        Controllers\AuthController::register(self::NAMESPACE, $permission);
        Controllers\McpController::register(self::NAMESPACE, $permission);
        Controllers\CloudflareController::register(self::NAMESPACE, $permission);
        Controllers\RemediationController::register(self::NAMESPACE, $permission);
        Controllers\IntegrityController::register(self::NAMESPACE, $permission);
        Controllers\SystemController::register(self::NAMESPACE, $permission);

        // Core nextgen module routes
        if (class_exists('\\WebCareProScanner\\Core\\ModuleRegistry')) {
            \WebCareProScanner\Core\ModuleRegistry::register_rest_routes(self::NAMESPACE);
        }
    }
}
