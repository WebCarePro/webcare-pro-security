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

    /**
     * Check if a developer-defined policy file exists.
     */
    public static function has_policy_file(): bool {
        return file_exists(self::get_policy_file_path());
    }

    /**
     * Load developer policy configuration and register custom hooks.
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
                // If policy declares settings overrides, apply them via filter
                if (!empty($policy['settings_overrides']) && is_array($policy['settings_overrides'])) {
                    add_filter('webcareproscan_settings', static function (array $settings) use ($policy): array {
                        return array_merge($settings, $policy['settings_overrides']);
                    }, 999);
                }

                return $policy;
            }
        } catch (\Throwable $e) {
            if (defined('WP_DEBUG') && WP_DEBUG) {
                @error_log('[WebCare Pro Policy Error] Failed loading webcare-policy.php: ' . $e->getMessage());
            }
        }

        return [];
    }
}
