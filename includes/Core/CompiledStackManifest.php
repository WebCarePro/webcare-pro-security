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
     * In-memory request cache to avoid duplicate file I/O and HMAC checks within the same request.
     *
     * @var array<string, mixed>|null
     */
    private static ?array $request_cache = null;

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
        self::$request_cache = null;
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
        if (function_exists('is_multisite') && is_multisite()) {
            $sitewide_plugins = array_keys((array) get_site_option('active_sitewide_plugins', []));
            $active_plugins = array_values(array_unique(array_merge($active_plugins, $sitewide_plugins)));
        }
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

        // Dynamic localized commerce paths detection
        $commerce_slugs = ['checkout', 'cart'];
        $membership_slugs = ['my-account', 'account', 'portal', 'membership'];
        if ($has_woo && function_exists('wc_get_page_id')) {
            $checkout_id = wc_get_page_id('checkout');
            if ($checkout_id > 0 && function_exists('get_post_field')) {
                $checkout_slug = (string) get_post_field('post_name', $checkout_id);
                if ($checkout_slug !== '') {
                    $commerce_slugs[] = $checkout_slug;
                }
            }
            $cart_id = wc_get_page_id('cart');
            if ($cart_id > 0 && function_exists('get_post_field')) {
                $cart_slug = (string) get_post_field('post_name', $cart_id);
                if ($cart_slug !== '') {
                    $commerce_slugs[] = $cart_slug;
                }
            }
            $myaccount_id = wc_get_page_id('myaccount');
            if ($myaccount_id > 0 && function_exists('get_post_field')) {
                $myaccount_slug = (string) get_post_field('post_name', $myaccount_id);
                if ($myaccount_slug !== '') {
                    $membership_slugs[] = $myaccount_slug;
                }
            }
        }
        $commerce_slugs = array_values(array_unique($commerce_slugs));
        $membership_slugs = array_values(array_unique($membership_slugs));

        // Build route-to-evaluator mappings
        $routes = [
            RouteClass::PublicGet->value => [
                'WebCareProScanner\\Firewall\\Core\\ExploitSignatureEngine',
                'WebCareProScanner\\Firewall\\BotReconDefense',
                'WebCareProScanner\\Firewall\\Evaluators\\AiAgentBehaviorEvaluator',
            ],
            RouteClass::PublicMutation->value => [
                'WebCareProScanner\\Firewall\\Core\\ExploitSignatureEngine',
                'WebCareProScanner\\Firewall\\BotReconDefense',
                'WebCareProScanner\\Firewall\\Evaluators\\AiAgentBehaviorEvaluator',
                'WebCareProScanner\\Firewall\\NextGen\\RuntimeSqlRaspEngine',
            ],
            RouteClass::Commerce->value => [
                'WebCareProScanner\\Firewall\\Core\\ExploitSignatureEngine',
                'WebCareProScanner\\Firewall\\Evaluators\\AiAgentBehaviorEvaluator',
                'WebCareProScanner\\Firewall\\Core\\CommerceSessionGuard',
                'WebCareProScanner\\Firewall\\Core\\CommerceVelocityGuard',
            ],
            RouteClass::Membership->value => [
                'WebCareProScanner\\Firewall\\Core\\ExploitSignatureEngine',
                'WebCareProScanner\\Auth\\SessionSentinel',
                'WebCareProScanner\\Firewall\\NextGen\\RuntimeSqlRaspEngine',
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
            RouteClass::GraphQL->value => [
                'WebCareProScanner\\Firewall\\Core\\ExploitSignatureEngine',
                'WebCareProScanner\\Firewall\\NextGen\\ModernApiShield',
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
            $filtered_routes = apply_filters('webcare/waf/manifest_routes', $routes, $archetype);
            if (is_array($filtered_routes)) {
                // Sanitize route mappings: ensure only valid class names are accepted
                foreach ($filtered_routes as $r_key => $evaluators) {
                    if (is_array($evaluators)) {
                        $sanitized_evals = [];
                        foreach ($evaluators as $eval_cls) {
                            if (is_string($eval_cls) && preg_match('/^[a-zA-Z0-9_\\\\]+$/', $eval_cls)) {
                                $sanitized_evals[] = $eval_cls;
                            }
                        }
                        // Non-negotiable invariant: Always preserve ExploitSignatureEngine in every route stack
                        $core_exploit_engine = 'WebCareProScanner\\Firewall\\Core\\ExploitSignatureEngine';
                        if (!in_array($core_exploit_engine, $sanitized_evals, true)) {
                            array_unshift($sanitized_evals, $core_exploit_engine);
                        }
                        $routes[$r_key] = $sanitized_evals;
                    }
                }
            }
        }

        $manifest_data = [
            'compiled_at'     => time(),
            'compiled_at_gmt' => gmdate('Y-m-d H:i:s'),
            'archetype'       => $archetype->value,
            'ecosystems'      => [
                'woocommerce' => $has_woo,
                'commerce'    => $has_commerce,
                'lms'         => $has_lms,
                'graphql'     => $has_graphql,
            ],
            'commerce_slugs'   => $commerce_slugs,
            'membership_slugs' => $membership_slugs,
            'routes'           => $routes,
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

        // Validate strictly data array tokens before writing to disk
        if (class_exists(MicroWafCompiler::class) && !MicroWafCompiler::assert_strictly_data_tokens($php_content)) {
            return [
                'success' => false,
                'path'    => self::get_manifest_path(),
                'message' => 'AST Token validation failed: manifest code contains forbidden executable constructs.',
            ];
        }

        $target_file = self::get_manifest_path();
        $temp_file = $target_file . '.tmp.' . bin2hex(random_bytes(8));

        if (file_put_contents($temp_file, $php_content, LOCK_EX) === false) {
            return [
                'success' => false,
                'path'    => $target_file,
                'message' => 'Failed to write temporary site manifest file.',
            ];
        }

        if (!rename($temp_file, $target_file)) {
            if (function_exists('wp_delete_file')) {
                wp_delete_file($temp_file);
            } else {
                @unlink($temp_file);
            }
            return [
                'success' => false,
                'path'    => $target_file,
                'message' => 'Failed to atomically deploy site manifest file.',
            ];
        }

        @chmod($target_file, 0600);

        // Store HMAC signature with fail-closed key derivation
        $secret_key = class_exists(SecretVault::class) ? SecretVault::get_key() : (defined('AUTH_KEY') && AUTH_KEY !== '' ? AUTH_KEY : '');
        if ($secret_key === '') {
            return [
                'success' => false,
                'path'    => $target_file,
                'message' => 'Cryptographic secret key unavailable for manifest signing.',
            ];
        }

        $hmac = hash_hmac('sha256', $php_content, $secret_key);
        if (!update_option(self::OPTION_MANIFEST_HMAC, $hmac, false)) {
            // Check if option was already set to this exact value
            if (get_option(self::OPTION_MANIFEST_HMAC) !== $hmac) {
                return [
                    'success' => false,
                    'path'    => $target_file,
                    'message' => 'Failed to persist cryptographic HMAC option.',
                ];
            }
        }

        // Verification check: ensure generated file can be loaded safely
        $test_load = @include $target_file;
        if (!is_array($test_load) || empty($test_load['archetype'])) {
            return [
                'success' => false,
                'path'    => $target_file,
                'message' => 'Compiled manifest self-verification test read failed.',
            ];
        }

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
     * Enforces strict fail-closed security: requires non-empty HMAC and rejects tampered files.
     *
     * @return array<string, mixed>
     */
    public static function load(): array {
        if (self::$request_cache !== null) {
            return self::$request_cache;
        }

        $path = self::get_manifest_path();
        if (!file_exists($path)) {
            // Lazy compile once if missing
            $compile_res = self::compile();
            if (empty($compile_res['success'])) {
                self::$request_cache = [];
                return [];
            }
        }

        if (!file_exists($path)) {
            self::$request_cache = [];
            return [];
        }

        $content = (string) @file_get_contents($path);
        if ($content === '') {
            self::$request_cache = [];
            return [];
        }

        $stored_hmac = (string) get_option(self::OPTION_MANIFEST_HMAC, '');
        $secret_key = class_exists(SecretVault::class) ? SecretVault::get_key() : (defined('AUTH_KEY') && AUTH_KEY !== '' ? AUTH_KEY : '');
        if ($secret_key === '') {
            self::$request_cache = [];
            return [];
        }

        // Fail-closed 1: Missing stored HMAC indicates corruption or tampering
        if ($stored_hmac === '') {
            $compile_res = self::compile();
            if (empty($compile_res['success'])) {
                self::$request_cache = [];
                return [];
            }
            $stored_hmac = (string) get_option(self::OPTION_MANIFEST_HMAC, '');
            $content = (string) @file_get_contents($path);
        }

        $expected = hash_hmac('sha256', $content, $secret_key);
        if (!hash_equals($expected, $stored_hmac)) {
            // Tampering detected: attempt recompilation
            $compile_res = self::compile();
            if (empty($compile_res['success'])) {
                // Fail closed immediately; never execute tampered PHP artifact
                self::$request_cache = [];
                return [];
            }
            $content = (string) @file_get_contents($path);
            $stored_hmac = (string) get_option(self::OPTION_MANIFEST_HMAC, '');
            if (!hash_equals(hash_hmac('sha256', $content, $secret_key), $stored_hmac)) {
                self::$request_cache = [];
                return [];
            }
        }

        $data = @include $path;
        $result = is_array($data) ? $data : [];
        self::$request_cache = $result;
        return $result;
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
