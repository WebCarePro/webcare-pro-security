<?php
declare(strict_types=1);

namespace WebCareProScanner\Core;

use WebCareProScanner\Contracts\RouteClass;
use WebCareProScanner\Contracts\SiteArchetype;
use WebCareProScanner\Firewall\MicroWafCompiler;
use WebCareProScanner\Security\SecretVault;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * CompiledStackManifest
 *
 * Compiles site tech-stack profile and route-to-evaluator mappings into an
 * OPcache-resident PHP array at WP_CONTENT_DIR . '/webcare-waf/site-manifest.php'.
 *
 * Executes strictly on lifecycle hooks (activated_plugin, deactivated_plugin, switch_theme,
 * upgrader_process_complete, wp webcare waf compile). Never executes on live visitor requests.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
final class CompiledStackManifest {

    public const MANIFEST_FILENAME = 'site-manifest.php';
    public const OPTION_MANIFEST_HMAC = 'webcareproscan_manifest_hmac';

    /**
     * Get the absolute path to the compiled site manifest.
     */
    public static function get_manifest_path(): string {
        $storage_dir = class_exists(MicroWafCompiler::class)
            ? MicroWafCompiler::get_compiled_dir()
            : (defined('WP_CONTENT_DIR') ? WP_CONTENT_DIR . '/webcare-waf' : ABSPATH . 'wp-content/webcare-waf');

        return wp_normalize_path(trailingslashit($storage_dir) . self::MANIFEST_FILENAME);
    }

    /**
     * Compile and write the OPcache-resident site manifest.
     *
     * @return array{success: bool, path: string, message: string}
     */
    public static function compile(): array {
        $storage_dir = class_exists(MicroWafCompiler::class)
            ? MicroWafCompiler::get_compiled_dir()
            : (defined('WP_CONTENT_DIR') ? WP_CONTENT_DIR . '/webcare-waf' : ABSPATH . 'wp-content/webcare-waf');

        if (!is_dir($storage_dir)) {
            wp_mkdir_p($storage_dir);
            // Protect directory
            @file_put_contents(trailingslashit($storage_dir) . 'index.php', "<?php\n// Silence is golden.\n");
            @chmod(trailingslashit($storage_dir) . 'index.php', 0600);
            @file_put_contents(trailingslashit($storage_dir) . '.htaccess', "Order Deny,Allow\nDeny from all\n<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n");
            @chmod(trailingslashit($storage_dir) . '.htaccess', 0600);
        }

        $active_plugins = (array) get_option('active_plugins', []);
        $active_str = implode(' ', $active_plugins);

        // Detect ecosystems
        $has_woo = str_contains($active_str, 'woocommerce');
        $has_edd = (bool) preg_match('/(?:easy-digital-downloads|surecart|fluent-cart|wp-easycart)/i', $active_str);
        $has_commerce = $has_woo || $has_edd;
        $has_lms = (bool) preg_match('/(?:learndash|sfwd-lms|memberpress|lifterlms|simple-membership|ultimate-member)/i', $active_str);
        $has_graphql = str_contains($active_str, 'wp-graphql');

        // Determine Site Archetype
        $archetype = SiteArchetype::Editorial;
        if ($has_commerce && $has_lms) {
            $archetype = SiteArchetype::Hybrid;
        } elseif ($has_commerce) {
            $archetype = SiteArchetype::Commerce;
        } elseif ($has_lms) {
            $archetype = SiteArchetype::Membership;
        } elseif ($has_graphql) {
            $archetype = SiteArchetype::HeadlessApi;
        }

        // Build route-to-evaluator mappings
        $routes = [
            RouteClass::PublicGet->value => [
                'WebCareProScanner\\Firewall\\Core\\ExploitSignatureEngine',
                'WebCareProScanner\\Firewall\\BotReconDefense',
            ],
            RouteClass::Commerce->value => [
                'WebCareProScanner\\Firewall\\Core\\ExploitSignatureEngine',
                'WebCareProScanner\\Firewall\\Core\\CommerceSessionGuard',
                'WebCareProScanner\\Firewall\\Core\\CommerceVelocityGuard',
            ],
            RouteClass::AuthLogin->value => [
                'WebCareProScanner\\Firewall\\Core\\ExploitSignatureEngine',
                'WebCareProScanner\\Auth\\WebAuthnManager',
            ],
            RouteClass::RestApi->value => [
                'WebCareProScanner\\Firewall\\Core\\ExploitSignatureEngine',
                'WebCareProScanner\\Firewall\\NextGen\\RuntimeSqlRaspEngine',
                'WebCareProScanner\\Firewall\\NextGen\\ResponseDlpSentinel',
            ],
            RouteClass::AdminAjax->value => [
                'WebCareProScanner\\Firewall\\Core\\ExploitSignatureEngine',
                'WebCareProScanner\\Firewall\\NextGen\\RuntimeSqlRaspEngine',
            ],
            RouteClass::AdminUi->value => [
                'WebCareProScanner\\Firewall\\Core\\ExploitSignatureEngine',
            ],
        ];

        // Custom evaluator registration hook for developers via policy
        if (function_exists('apply_filters')) {
            $routes = apply_filters('webcare/waf/manifest_routes', $routes, $archetype);
        }

        $manifest_data = [
            'compiled_at' => time(),
            'compiled_at_gmt' => gmdate('Y-m-d H:i:s'),
            'archetype'   => $archetype->value,
            'ecosystems'  => [
                'woocommerce' => $has_woo,
                'commerce'    => $has_commerce,
                'lms'         => $has_lms,
                'graphql'     => $has_graphql,
            ],
            'routes'      => $routes,
        ];

        // Format into OPcache-executable standalone array
        $export = var_export($manifest_data, true);
        $php_content = "<?php\n" .
            "/**\n" .
            " * WebCare Pro Compiled Stack Manifest\n" .
            " * Auto-generated by WebCare Pro v3.0 - Mir Alamin\n" .
            " * OPcache-resident route matrix for zero-waste loading.\n" .
            " */\n" .
            "defined('ABSPATH') || exit;\n\n" .
            "return " . $export . ";\n";

        $target_file = self::get_manifest_path();
        $temp_file = $target_file . '.tmp.' . wp_rand();

        if (file_put_contents($temp_file, $php_content, LOCK_EX) === false) {
            return [
                'success' => false,
                'path'    => $target_file,
                'message' => 'Failed to write temporary site manifest file.',
            ];
        }

        if (!rename($temp_file, $target_file)) {
            wp_delete_file($temp_file);
            return [
                'success' => false,
                'path'    => $target_file,
                'message' => 'Failed to atomically deploy site manifest file.',
            ];
        }

        @chmod($target_file, 0600);

        // Store HMAC signature
        $secret_key = class_exists(SecretVault::class) ? SecretVault::get_key() : (defined('AUTH_KEY') ? AUTH_KEY : 'webcare-manifest-salt');
        $hmac = hash_hmac('sha256', $php_content, $secret_key);
        update_option(self::OPTION_MANIFEST_HMAC, $hmac, false);

        if (function_exists('opcache_invalidate')) {
            opcache_invalidate($target_file, true);
        }

        return [
            'success' => true,
            'path'    => $target_file,
            'message' => 'WebCare Compiled Stack Manifest successfully compiled.',
        ];
    }

    /**
     * Load the compiled manifest array with OPcache and HMAC verification.
     *
     * @return array<string, mixed>
     */
    public static function load(): array {
        $path = self::get_manifest_path();
        if (!file_exists($path)) {
            // Lazy compile once if missing
            self::compile();
        }

        if (!file_exists($path)) {
            return [];
        }

        $content = (string) @file_get_contents($path);
        if ($content === '') {
            return [];
        }

        $stored_hmac = (string) get_option(self::OPTION_MANIFEST_HMAC, '');
        if ($stored_hmac !== '') {
            $secret_key = class_exists(SecretVault::class) ? SecretVault::get_key() : (defined('AUTH_KEY') ? AUTH_KEY : 'webcare-manifest-salt');
            $expected = hash_hmac('sha256', $content, $secret_key);
            if (!hash_equals($expected, $stored_hmac)) {
                // Recompile if tampered or key rotated
                self::compile();
            }
        }

        $data = @include $path;
        return is_array($data) ? $data : [];
    }

    /**
     * Register lifecycle hooks to trigger re-compilation strictly on plugin/theme modifications.
     */
    public static function register_lifecycle_hooks(): void {
        add_action('activated_plugin', [__CLASS__, 'compile']);
        add_action('deactivated_plugin', [__CLASS__, 'compile']);
        add_action('switch_theme', [__CLASS__, 'compile']);
        add_action('upgrader_process_complete', [__CLASS__, 'compile']);
    }
}
