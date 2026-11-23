<?php
declare(strict_types=1);

namespace WebCareProScanner\Admin;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Single-source navigation metadata registry for WebCare Pro Security & Firewall.
 *
 * Provides schema validation, duplicate slug rejection, allowlisted bundle mapping,
 * per-request in-memory caching, fail-safe fallbacks, and canonical URL generation.
 *
 * Strictly scoped to navigation metadata: authorization and capabilities (e.g. manage_options)
 * remain independently enforced by AdminMenu, REST controllers, and admin routes.
 */
final class RouteRegistry {
    /**
     * Explicit allowlist of permissible JS bundle identifiers.
     * Prevents arbitrary script execution or traversal via JSON modification.
     */
    private const ALLOWED_BUNDLES = [
        'index',
        'firewall',
        'waf-logs',
        'scan',
        'auth',
        'vault',
        'settings',
        'wizard',
        'fim',
        'activity-logs',
        'cron-manager',
        'notifications',
        'custom-rules',
    ];

    /**
     * In-memory cached schema data to prevent repeated JSON parses per request.
     *
     * @var array<string, mixed>|null
     */
    private static ?array $cached_schema = null;

    /**
     * In-memory index of pillars by pillar ID.
     *
     * @var array<string, array<string, mixed>>|null
     */
    private static ?array $pillar_index = null;

    /**
     * Load, validate, and return the navigation registry schema.
     *
     * @return array<string, mixed>
     */
    public static function get_schema(): array {
        if (self::$cached_schema !== null) {
            return self::$cached_schema;
        }

        $json_file = __DIR__ . '/routes.json';
        if (!file_exists($json_file)) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
            error_log('WebCare Pro RouteRegistry: routes.json file not found at ' . $json_file);
            return self::$cached_schema = self::get_fallback_schema();
        }

        $raw_content = @file_get_contents($json_file);
        if ($raw_content === false || !json_validate($raw_content)) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
            error_log('WebCare Pro RouteRegistry: routes.json is empty or contains invalid JSON.');
            return self::$cached_schema = self::get_fallback_schema();
        }

        $decoded = json_decode($raw_content, true);
        if (!is_array($decoded) || empty($decoded['pillars']) || !is_array($decoded['pillars'])) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
            error_log('WebCare Pro RouteRegistry: routes.json missing required "pillars" array.');
            return self::$cached_schema = self::get_fallback_schema();
        }

        $validated_pillars = [];
        $pillar_index = [];
        $seen_pillars = [];

        foreach ($decoded['pillars'] as $pillar) {
            if (!is_array($pillar) || empty($pillar['id']) || !is_string($pillar['id'])) {
                continue;
            }

            $pillar_id = sanitize_key($pillar['id']);
            if (isset($seen_pillars[$pillar_id])) {
                // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
                error_log("WebCare Pro RouteRegistry: Duplicate pillar ID rejected: {$pillar_id}");
                continue;
            }
            $seen_pillars[$pillar_id] = true;

            $bundle = isset($pillar['bundle']) && is_string($pillar['bundle']) ? $pillar['bundle'] : 'index';
            if (!in_array($bundle, self::ALLOWED_BUNDLES, true)) {
                // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
                error_log("WebCare Pro RouteRegistry: Disallowed bundle '{$bundle}' for pillar '{$pillar_id}'. Defaulting to 'index'.");
                $bundle = 'index';
            }

            $validated_tabs = [];
            $seen_tabs = [];
            if (!empty($pillar['tabs']) && is_array($pillar['tabs'])) {
                foreach ($pillar['tabs'] as $tab) {
                    if (!is_array($tab) || empty($tab['id']) || !is_string($tab['id'])) {
                        continue;
                    }
                    $tab_id = sanitize_key($tab['id']);
                    if (isset($seen_tabs[$tab_id])) {
                        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
                        error_log("WebCare Pro RouteRegistry: Duplicate tab ID '{$tab_id}' in pillar '{$pillar_id}' rejected.");
                        continue;
                    }
                    $seen_tabs[$tab_id] = true;

                    $validated_sections = [];
                    $seen_sections = [];
                    if (!empty($tab['sections']) && is_array($tab['sections'])) {
                        foreach ($tab['sections'] as $sec) {
                            if (!is_array($sec) || empty($sec['id']) || !is_string($sec['id'])) {
                                continue;
                            }
                            $sec_id = sanitize_key($sec['id']);
                            if (isset($seen_sections[$sec_id])) {
                                continue;
                            }
                            $seen_sections[$sec_id] = true;
                            $validated_sections[] = [
                                'id'    => $sec_id,
                                'label' => sanitize_text_field($sec['label'] ?? $sec_id),
                                'mode'  => ($sec['mode'] ?? 'all') === 'developer' ? 'developer' : 'all',
                            ];
                        }
                    }

                    $validated_tabs[] = [
                        'id'              => $tab_id,
                        'label'           => sanitize_text_field($tab['label'] ?? $tab_id),
                        'mode'            => ($tab['mode'] ?? 'all') === 'developer' ? 'developer' : 'all',
                        'group'           => sanitize_text_field($tab['group'] ?? ''),
                        'description'     => sanitize_text_field($tab['description'] ?? ''),
                        'default_section' => sanitize_key($tab['default_section'] ?? ''),
                        'sections'        => $validated_sections,
                    ];
                }
            }

            $default_tab = sanitize_key($pillar['default_tab'] ?? '');
            if ($default_tab !== '' && !empty($validated_tabs) && !in_array($default_tab, $seen_tabs, true)) {
                // If declared default_tab does not exist in validated tabs, discard it or default to first tab
                if (!isset($seen_tabs[$default_tab])) {
                    $default_tab = $validated_tabs[0]['id'] ?? '';
                }
            }

            $clean_pillar = [
                'id'          => $pillar_id,
                'title'       => sanitize_text_field($pillar['title'] ?? $pillar_id),
                'menu_title'  => sanitize_text_field($pillar['menu_title'] ?? $pillar_id),
                'page_title'  => sanitize_text_field($pillar['page_title'] ?? $pillar_id),
                'description' => sanitize_text_field($pillar['description'] ?? ''),
                'bundle'      => $bundle,
                'icon'        => sanitize_key($pillar['icon'] ?? 'shield'),
                'default_tab' => $default_tab,
                'mode'        => ($pillar['mode'] ?? 'all') === 'developer' ? 'developer' : 'all',
                'hidden'      => !empty($pillar['hidden']),
                'tabs'        => $validated_tabs,
            ];

            $validated_pillars[] = $clean_pillar;
            $pillar_index[$pillar_id] = $clean_pillar;
        }

        self::$pillar_index = $pillar_index;
        return self::$cached_schema = [
            'version' => sanitize_text_field($decoded['version'] ?? '3.26.0'),
            'pillars' => $validated_pillars,
        ];
    }

    /**
     * Get all registered pillars.
     *
     * @return array<int, array<string, mixed>>
     */
    public static function get_pillars(): array {
        $schema = self::get_schema();
        return $schema['pillars'] ?? [];
    }

    /**
     * Find a pillar by slug/ID.
     *
     * @param string $pillar_id
     * @return array<string, mixed>|null
     */
    public static function get_pillar(string $pillar_id): ?array {
        if (self::$pillar_index === null) {
            self::get_schema();
        }
        return self::$pillar_index[$pillar_id] ?? null;
    }

    /**
     * Validate whether a given pillar, tab, and optional section exist.
     *
     * @param string $pillar_id
     * @param string $tab_id
     * @param string $section_id
     * @return bool
     */
    public static function is_valid_route(string $pillar_id, string $tab_id = '', string $section_id = ''): bool {
        // Strict Schema Rule: Cannot specify a section without a valid tab
        if ($section_id !== '' && $tab_id === '') {
            return false;
        }

        $pillar = self::get_pillar($pillar_id);
        if ($pillar === null) {
            return false;
        }

        if ($tab_id === '') {
            return true;
        }

        $matched_tab = null;
        foreach ($pillar['tabs'] as $tab) {
            if ($tab['id'] === $tab_id) {
                $matched_tab = $tab;
                break;
            }
        }

        if ($matched_tab === null) {
            return false;
        }

        if ($section_id === '') {
            return true;
        }

        foreach ($matched_tab['sections'] as $sec) {
            if ($sec['id'] === $section_id) {
                return true;
            }
        }

        return false;
    }

    /**
     * Resolve the active bundle name for a given page and tab request.
     *
     * @param string $pillar_id
     * @param string $tab_id
     * @return string Allowlisted bundle identifier (e.g. 'firewall', 'scan', 'index')
     */
    public static function resolve_bundle(string $pillar_id, string $tab_id = ''): string {
        $pillar = self::get_pillar($pillar_id);
        if ($pillar !== null && !empty($pillar['bundle']) && in_array($pillar['bundle'], self::ALLOWED_BUNDLES, true)) {
            return $pillar['bundle'];
        }

        return 'index';
    }

    /**
     * Generate a canonical admin URL using admin_url() and add_query_arg().
     *
     * @param string $pillar_id Pillar slug (e.g. 'webcare-pro-firewall')
     * @param string $tab_id Optional tab slug (e.g. 'cloudflare')
     * @param string $section_id Optional section slug (e.g. 'server-rules')
     * @param array<string, mixed> $extra_args Any extra query parameters (e.g. ['rescue' => 1])
     * @return string Safe canonical admin URL
     */
    public static function url(string $pillar_id, string $tab_id = '', string $section_id = '', array $extra_args = []): string {
        $pillar = self::get_pillar($pillar_id);
        $canonical_page = $pillar !== null ? $pillar['id'] : $pillar_id;

        $query = ['page' => $canonical_page];

        // Strict Schema Rule: &section= can only exist when a valid &tab= is present
        if ($tab_id === '') {
            $section_id = '';
        } else {
            // Validate (pillar, tab, section) against schema
            if (!self::is_valid_route($canonical_page, $tab_id, '')) {
                // Discard invalid tab
                $tab_id = '';
                $section_id = '';
            } elseif ($section_id !== '' && !self::is_valid_route($canonical_page, $tab_id, $section_id)) {
                // Discard invalid section
                $section_id = '';
            }
        }

        // Only include tab if non-empty and not the default tab (unless section or extra_args is present)
        $default_tab = $pillar['default_tab'] ?? '';
        if ($tab_id !== '' && ($tab_id !== $default_tab || $section_id !== '' || !empty($extra_args))) {
            $query['tab'] = $tab_id;
        }

        if ($section_id !== '') {
            $query['section'] = $section_id;
        }

        if (!empty($extra_args)) {
            $reserved_keys = ['page', 'tab', 'section'];
            foreach ($extra_args as $k => $v) {
                $k_clean = sanitize_key((string)$k);
                if (in_array($k_clean, $reserved_keys, true) || $k_clean === '') {
                    continue;
                }
                $query[$k_clean] = sanitize_text_field((string)$v);
            }
        }

        return add_query_arg($query, admin_url('admin.php'));
    }

    /**
     * Fallback minimal schema in case routes.json cannot be read or is corrupted.
     * Guarantees wp-admin never crashes (WSOD prevention).
     *
     * @return array<string, mixed>
     */
    private static function get_fallback_schema(): array {
        return [
            'version' => '3.26.0',
            'pillars' => [
                [
                    'id'          => 'webcare-pro-security',
                    'title'       => 'Overview',
                    'menu_title'  => 'Overview',
                    'page_title'  => 'WebCare Pro Security — Overview',
                    'description' => 'Site protection status, recent blocks, and quick actions.',
                    'bundle'      => 'index',
                    'icon'        => 'shield',
                    'default_tab' => '',
                    'mode'        => 'all',
                    'hidden'      => false,
                    'tabs'        => [],
                ],
                [
                    'id'          => 'webcare-pro-firewall',
                    'title'       => 'Firewall',
                    'menu_title'  => 'Firewall',
                    'page_title'  => 'Firewall & Traffic Defense',
                    'description' => 'Block attacks, manage rules, bots, AI crawlers, and Cloudflare.',
                    'bundle'      => 'firewall',
                    'icon'        => 'firewall',
                    'default_tab' => 'protection',
                    'mode'        => 'all',
                    'hidden'      => false,
                    'tabs'        => [],
                ],
                [
                    'id'          => 'webcare-pro-settings',
                    'title'       => 'Settings',
                    'menu_title'  => 'Settings',
                    'page_title'  => 'Settings & Security Governance',
                    'description' => 'Health check, alerts, schedules, hardening, AI, and support.',
                    'bundle'      => 'settings',
                    'icon'        => 'settings',
                    'default_tab' => 'health',
                    'mode'        => 'all',
                    'hidden'      => false,
                    'tabs'        => [],
                ],
            ],
        ];
    }

    /**
     * Clear cached schema (for tests).
     */
    public static function reset_cache(): void {
        self::$cached_schema = null;
        self::$pillar_index = null;
    }
}
