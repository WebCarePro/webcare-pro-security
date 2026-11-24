<?php

declare(strict_types=1);

namespace WebCareProScanner\System;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * PluginConflictChecker
 *
 * Read-only, memory-safe compatibility analyzer that inspects active plugins,
 * preload directives, and WebCare Pro settings to surface potential overlaps
 * in plain, calm, non-technical language. Never modifies third-party settings.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
final readonly class PluginConflictChecker {

    /**
     * Run a full compatibility and conflict check against active plugins.
     *
     * @return array<string, mixed>
     */
    public static function run_check(): array {
        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $all_plugins    = function_exists('get_plugins') ? get_plugins() : [];
        $active_plugins = (array) get_option('active_plugins', []);

        if (function_exists('is_multisite') && is_multisite()) {
            $network_active = array_keys((array) get_site_option('active_sitewide_plugins', []));
            $active_plugins = array_values(array_unique(array_merge($active_plugins, $network_active)));
        }

        $settings  = class_exists(SettingsManager::class) ? SettingsManager::get_settings() : [];
        $conflicts = [];

        foreach ($active_plugins as $plugin_file) {
            if (!is_string($plugin_file) || str_starts_with($plugin_file, 'webcare-pro-security/')) {
                continue;
            }

            $meta        = $all_plugins[$plugin_file] ?? [];
            $plugin_name = !empty($meta['Name']) ? (string) $meta['Name'] : $plugin_file;
            $slug_lower  = strtolower($plugin_file . ' ' . $plugin_name);

            // 1. Overlapping Security / WAF / 2FA plugins
            if (preg_match('/\b(wordfence|ithemes|better-wp-security|solid-security|sucuri|all-in-one-wp-security|aiowps|malcare|ninjafirewall|wp-cerber|shield-security|wp-simple-firewall|bulletproof-security)\b/i', $slug_lower)) {
                $conflicts[] = [
                    'id'                 => 'overlap_waf_' . sanitize_key($plugin_file),
                    'severity'           => 'attention',
                    'plugin_name'        => $plugin_name,
                    'plugin_file'        => $plugin_file,
                    'category'           => __('Security & Firewall Overlap', 'webcare-pro-security'),
                    'plain_title'        => sprintf(
                        /* translators: %s: active plugin name */
                        __('%s is also running firewall or login protection', 'webcare-pro-security'),
                        $plugin_name
                    ),
                    'extended_details'   => __('Running two full security firewalls at the same time can occasionally cause duplicate login lockouts, double 2FA prompts, or slower page loads because every visitor request is inspected twice.', 'webcare-pro-security'),
                    'recommended_action' => __('You do not need to remove anything immediately. If you notice duplicate login prompts or slowdowns, keep WebCare Pro Security & Firewall as your primary shield and turn off overlapping firewall/2FA modules in one of the plugins.', 'webcare-pro-security'),
                    'target_page'        => 'webcare-pro-firewall',
                    'target_tab'         => 'rules',
                ];
            }

            // 2. Standalone 2FA plugins when WebCare 2FA is active
            if (!empty($settings['auth_2fa_enabled']) && preg_match('/\b(two-factor|wp-2fa|google-authenticator|miniorange-2-factor)\b/i', $slug_lower)) {
                $conflicts[] = [
                    'id'                 => 'overlap_2fa_' . sanitize_key($plugin_file),
                    'severity'           => 'attention',
                    'plugin_name'        => $plugin_name,
                    'plugin_file'        => $plugin_file,
                    'category'           => __('Two-Factor Authentication (2FA)', 'webcare-pro-security'),
                    'plain_title'        => sprintf(
                        /* translators: %s: active plugin name */
                        __('%s may ask for a second 2FA code at login', 'webcare-pro-security'),
                        $plugin_name
                    ),
                    'extended_details'   => __('WebCare Pro already includes built-in 2FA and Passkeys. Having a second 2FA plugin active at the same time can ask administrators to enter two different verification codes when signing in.', 'webcare-pro-security'),
                    'recommended_action' => __('Use either WebCare Pro 2FA or your standalone 2FA plugin—not both—so logging in stays smooth.', 'webcare-pro-security'),
                    'target_page'        => 'webcare-pro-login',
                    'target_tab'         => '2fa',
                ];
            }

            // 3. Login URL customizers vs Login Hardening
            if (preg_match('/\b(wps-hide-login|rename-wp-login|hide-my-wp|perfmatters)\b/i', $slug_lower)) {
                $conflicts[] = [
                    'id'                 => 'overlap_login_url_' . sanitize_key($plugin_file),
                    'severity'           => 'info',
                    'plugin_name'        => $plugin_name,
                    'plugin_file'        => $plugin_file,
                    'category'           => __('Login Page Compatibility', 'webcare-pro-security'),
                    'plain_title'        => sprintf(
                        /* translators: %s: active plugin name */
                        __('%s customizes your WordPress login URL', 'webcare-pro-security'),
                        $plugin_name
                    ),
                    'extended_details'   => __('Plugins that rename /wp-login.php work fine alongside WebCare Pro, as long as you do not enable a second custom login slug at the same time.', 'webcare-pro-security'),
                    'recommended_action' => __('Everything is safe as-is. If you ever get a 404 on your login page, check that only one plugin is changing the login URL.', 'webcare-pro-security'),
                    'target_page'        => 'webcare-pro-login',
                    'target_tab'         => 'hardening',
                ];
            }

            // 4. Full-page caching plugins
            if (preg_match('/\b(wp-rocket|litespeed-cache|w3-total-cache|wp-super-cache|wp-fastest-cache|flying-press|breeze|sg-cachepress|autoptimize)\b/i', $slug_lower)) {
                $conflicts[] = [
                    'id'                 => 'compat_cache_' . sanitize_key($plugin_file),
                    'severity'           => 'info',
                    'plugin_name'        => $plugin_name,
                    'plugin_file'        => $plugin_file,
                    'category'           => __('Page Caching Compatibility', 'webcare-pro-security'),
                    'plain_title'        => sprintf(
                        /* translators: %s: active plugin name */
                        __('%s page caching is active and compatible', 'webcare-pro-security'),
                        $plugin_name
                    ),
                    'extended_details'   => __('WebCare Pro is built to work smoothly with full-page caches. Its form protection and firewall headers automatically adapt so cached pages never block real visitors.', 'webcare-pro-security'),
                    'recommended_action' => __('No action needed. If you ever update firewall rules, clearing your page cache once ensures visitors see the latest protection.', 'webcare-pro-security'),
                    'target_page'        => 'webcare-pro-settings',
                    'target_tab'         => 'general',
                ];
            }
        }

        // 5. Check PHP auto_prepend_file ownership for Preload Micro-WAF
        $auto_prepend = (string) ini_get('auto_prepend_file');
        if ($auto_prepend !== '' && !str_contains($auto_prepend, 'micro-waf-compiled.php')) {
            $conflicts[] = [
                'id'                 => 'env_auto_prepend_other',
                'severity'           => 'attention',
                'plugin_name'        => basename($auto_prepend),
                'plugin_file'        => $auto_prepend,
                'category'           => __('Server Preload File (auto_prepend_file)', 'webcare-pro-security'),
                'plain_title'        => __('Another preload security script is currently active on your server', 'webcare-pro-security'),
                'extended_details'   => sprintf(
                    /* translators: %s: existing auto_prepend_file path */
                    __('Your PHP configuration currently loads "%s" before WordPress starts. WebCare Pro can chain alongside it or replace it safely so both do not fight over .user.ini.', 'webcare-pro-security'),
                    $auto_prepend
                ),
                'recommended_action' => __('Open Firewall -> Preload Micro-WAF if you want WebCare Pro to manage or chain this preload file automatically.', 'webcare-pro-security'),
                'target_page'        => 'webcare-pro-firewall',
                'target_tab'         => 'rules',
            ];
        }

        $attention_count = count(array_filter($conflicts, static fn (array $c): bool => ($c['severity'] ?? '') === 'attention'));
        $status          = $attention_count > 0 ? 'attention' : 'clean';
        $headline        = $attention_count > 0
            ? sprintf(
                /* translators: %d: number of items needing attention */
                _n(
                    'Found %d compatibility item worth a quick look',
                    'Found %d compatibility items worth a quick look',
                    $attention_count,
                    'webcare-pro-security'
                ),
                $attention_count
            )
            : __('Everything looks harmonious — no conflicts detected', 'webcare-pro-security');

        $summary = $attention_count > 0
            ? __('Your site is still protected. Review the plain-English notes below whenever you have a moment.', 'webcare-pro-security')
            : sprintf(
                /* translators: %d: number of active plugins scanned */
                __('Scanned %d active plugins and your server preload configuration. WebCare Pro Security & Firewall is running smoothly alongside your existing setup.', 'webcare-pro-security'),
                count($active_plugins)
            );

        return [
            'success'               => true,
            'status'                => $status,
            'headline'              => $headline,
            'summary'               => $summary,
            'checked_plugins_count' => count($active_plugins),
            'attention_count'       => $attention_count,
            'conflicts'             => $conflicts,
            'checked_at_gmt'        => gmdate('Y-m-d H:i:s'),
        ];
    }
}
