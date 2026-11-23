<?php
declare(strict_types=1);

namespace WebCareProScanner\Core;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * PolicyManager
 *
 * Developer & Agency Code-First Policy Loader.
 * Inspects and loads WP_CONTENT_DIR . '/webcare-policy.php' (Git-trackable declarative policy file).
 * Allows overriding database settings, registering custom evaluators, and defining route exemptions.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
final class PolicyManager {

    public const POLICY_FILE_NAME = 'webcare-policy.php';

    /**
     * Get the absolute path to the declarative policy file.
     */
    public static function get_policy_file_path(): string {
        $content_dir = defined('WP_CONTENT_DIR') ? WP_CONTENT_DIR : ABSPATH . 'wp-content';
        return wp_normalize_path(trailingslashit($content_dir) . self::POLICY_FILE_NAME);
    }

    public const PROTECTED_SETTINGS_DENYLIST = [
        'waf_enabled',
        'waf_block_sqli',
        'waf_block_xss',
        'waf_block_ssrf_metadata',
        'waf_runtime_rasp_privilege_guard',
        'waf_enforce_host_allowlist',
        'auth_2fa_enabled',
        'auth_2fa_enforce_admins',
        'self_defense_watchdog_enabled',
    ];

    /**
     * Check if a developer-defined policy file exists.
     */
    public static function has_policy_file(): bool {
        return file_exists(self::get_policy_file_path());
    }

    /**
     * Load developer policy configuration and register custom hooks.
     * Enforces strict protection: strips core security keys from settings overrides.
     *
     * @return array<string, mixed>
     */
    public static function load_policy(): array {
        $path = self::get_policy_file_path();
        if (!file_exists($path)) {
            return [];
        }

        try {
            $policy = @include $path;
            if (is_array($policy)) {
                // If policy declares settings overrides, sanitize against denylist and apply via filter
                if (!empty($policy['settings_overrides']) && is_array($policy['settings_overrides'])) {
                    $sanitized_overrides = array_diff_key(
                        $policy['settings_overrides'],
                        array_flip(self::PROTECTED_SETTINGS_DENYLIST)
                    );

                    add_filter('webcareproscan_settings', static function (array $settings) use ($sanitized_overrides): array {
                        return array_merge($settings, $sanitized_overrides);
                    }, 999);
                }

                return $policy;
            }
        } catch (\Throwable $e) {
            if (defined('WP_DEBUG') && WP_DEBUG) {
                // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
                @error_log('[WebCare Pro Policy Error] Failed loading webcare-policy.php: ' . $e->getMessage());
            }
        }

        return [];
    }
}
