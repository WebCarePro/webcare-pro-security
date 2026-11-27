<?php

declare(strict_types=1);

namespace WebCareProScanner\Firewall;

use WebCareProScanner\Security\SecretVault;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * NistCveVaultSync
 *
 * Rate-limited background batch worker and encrypted Vault store for NIST NVD CVE 2.0
 * advisories across all installed WordPress plugins, themes, and core.
 */
class NistCveVaultSync {

    public const OPTION_SYNC_STATE  = 'webcareproscan_nist_sync_state';
    public const OPTION_API_KEY_ENC = 'webcareproscan_nist_api_key_enc';
    public const CRON_HOOK          = 'webcareproscan_nist_cve_batch_tick';
    public const DAILY_CRON_HOOK    = 'webcareproscan_nist_daily_sync';
    public const VAULT_FILE                = 'nist_cve_catalog.vault.json';
    public const BATCH_SIZE                = 4;
    public const BATCH_INTERVAL_SEC        = 30;
    public const DAILY_COOLDOWN_SEC        = 86400;
    public const RESULTS_PER_PAGE          = 100;
    public const MAX_RESULTS_PER_COMPONENT = 500;
    public const FREE_TIER_REQUEST_BUDGET  = 4;
    public const API_KEY_REQUEST_BUDGET    = 12;
    public const RATE_WINDOW_TRANSIENT     = 'webcareproscan_nist_rate_window';

    /**
     * Optional test seam for mocking NIST HTTP responses in unit tests.
     *
     * @var callable|null
     */
    public static $http_get_callback = null;

    public static function init(): void {
        add_action(self::CRON_HOOK, [__CLASS__, 'process_next_batch']);
        add_action(self::DAILY_CRON_HOOK, [__CLASS__, 'maybe_run_daily_sync']);
        if (function_exists('wp_next_scheduled') && function_exists('wp_schedule_event') && !wp_next_scheduled(self::DAILY_CRON_HOOK)) {
            wp_schedule_event(time() + 60, 'daily', self::DAILY_CRON_HOOK);
        }
    }

    /**
     * Daily WP-Cron entrypoint: runs once every 24h to check all installed plugins, themes & core.
     */
    public static function maybe_run_daily_sync(): void {
        $state = get_option(self::OPTION_SYNC_STATE, []);
        if (!is_array($state)) {
            $state = [];
        }
        if (!empty($state['is_running'])) {
            return;
        }
        $last_completed = (int) ($state['last_completed_at'] ?? 0);
        if ($last_completed > 0 && (time() - $last_completed) < self::DAILY_COOLDOWN_SEC) {
            return;
        }
        self::start_background_sync();
    }

    /**
     * Check whether a candidate NIST NVD 2.0 API key matches official UUID/hex format.
     */
    public static function is_valid_api_key_format(string $key): bool {
        $trimmed = trim($key);
        return $trimmed !== '' && preg_match('/^[a-f0-9]{8}-?[a-f0-9]{4}-?[a-f0-9]{4}-?[a-f0-9]{4}-?[a-f0-9]{12}$/i', $trimmed) === 1;
    }

    /**
     * Save or clear the optional NIST NVD API key (encrypted via SecretVault).
     */
    public static function save_api_key(string $raw_key): bool {
        $clean = trim(sanitize_text_field($raw_key));
        if ($clean === '') {
            delete_option(self::OPTION_API_KEY_ENC);
            return true;
        }
        if (!self::is_valid_api_key_format($clean)) {
            return false;
        }
        if (!class_exists(SecretVault::class)) {
            return false;
        }
        $enc = SecretVault::encrypt($clean);
        if (!is_string($enc) || $enc === '') {
            return false;
        }
        update_option(self::OPTION_API_KEY_ENC, $enc, false);
        return true;
    }

    /**
     * Retrieve decrypted NIST NVD API key if configured and valid.
     */
    public static function get_api_key(): string {
        $enc = get_option(self::OPTION_API_KEY_ENC, '');
        if (!is_string($enc) || $enc === '' || !class_exists(SecretVault::class)) {
            return '';
        }
        $dec = SecretVault::decrypt($enc);
        $trimmed = is_string($dec) ? trim($dec) : '';
        if ($trimmed === '' || !self::is_valid_api_key_format($trimmed)) {
            return '';
        }
        return $trimmed;
    }

    /**
     * Batch size per 30-second window (strictly 4 components / 30s for safe NIST NVD compliance).
     */
    public static function get_batch_size(): int {
        return self::BATCH_SIZE;
    }

    private static function get_vault_file_path(): string {
        $upload_dir = wp_upload_dir();
        $base = !empty($upload_dir['basedir']) ? $upload_dir['basedir'] : WP_CONTENT_DIR . '/uploads';
        $dir = wp_normalize_path(rtrim($base, '/\\') . '/webcare-vault');
        if (!is_dir($dir)) {
            wp_mkdir_p($dir);
        }
        return $dir . '/' . self::VAULT_FILE;
    }

    /**
     * Read and decrypt the NIST CVE catalog from the Vault.
     *
     * @return array<string, array>
     */
    public static function read_vault_catalog(): array {
        $file = self::get_vault_file_path();
        if (!is_file($file) || !is_readable($file)) {
            return [];
        }
        $raw = @file_get_contents($file);
        if (!is_string($raw) || $raw === '') {
            return [];
        }
        $container = json_decode($raw, true);
        if (!is_array($container) || empty($container['encrypted_payload']) || !class_exists(SecretVault::class)) {
            return [];
        }
        if (!empty($container['hmac_sha256'])) {
            $expected = hash_hmac('sha256', (string) $container['encrypted_payload'], SecretVault::get_key());
            if (!hash_equals($expected, (string) $container['hmac_sha256'])) {
                return [];
            }
        }
        $dec = SecretVault::decrypt((string) $container['encrypted_payload']);
        if (!is_string($dec) || $dec === '') {
            return [];
        }
        $data = json_decode($dec, true);
        return is_array($data) ? $data : [];
    }

    /**
     * Encrypt and atomically persist the NIST CVE catalog to the Vault.
     */
    public static function write_vault_catalog(array $catalog): bool {
        if (!class_exists(SecretVault::class)) {
            return false;
        }
        $file = self::get_vault_file_path();
        $json = (string) wp_json_encode($catalog);
        $enc  = SecretVault::encrypt($json);
        if (!is_string($enc) || $enc === '') {
            return false;
        }
        $container = [
            'vault_format'      => 'V2_NIST_CVE_AEAD',
            'updated_at'        => time(),
            'hmac_sha256'       => hash_hmac('sha256', $enc, SecretVault::get_key()),
            'encrypted_payload' => $enc,
        ];
        $tmp = $file . '.' . bin2hex(random_bytes(4)) . '.tmp';
        if (@file_put_contents($tmp, (string) wp_json_encode($container), LOCK_EX) !== false) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- Restrict encrypted CVE vault to owner read/write.
            @chmod($tmp, 0600);
            // phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename -- Atomic vault replacement.
            @rename($tmp, $file);
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod
            @chmod($file, 0600);
            return true;
        }
        return false;
    }

    /**
     * Return current sync progress and Vault summary.
     */
    public static function get_status(): array {
        $state = get_option(self::OPTION_SYNC_STATE, []);
        if (!is_array($state)) {
            $state = [];
        }
        $catalog = self::read_vault_catalog();
        $last_ts = (int) ($state['last_fetch_at'] ?? 0);
        $now     = time();

        $checked_components = [];
        foreach ($catalog as $slug => $entry) {
            if (!is_array($entry)) {
                continue;
            }
            $checked_ts = (int) ($entry['checked_at'] ?? 0);
            $cves       = is_array($entry['cves'] ?? null) ? $entry['cves'] : [];
            $checked_components[$slug] = [
                'slug'            => (string) ($entry['slug'] ?? $slug),
                'name'            => (string) ($entry['name'] ?? $slug),
                'type'            => (string) ($entry['type'] ?? 'plugin'),
                'version'         => (string) ($entry['version'] ?? '0.0.0'),
                'checked_at'      => $checked_ts,
                'checked_human'   => $checked_ts > 0 ? (function_exists('human_time_diff') ? human_time_diff($checked_ts, $now) . ' ago' : gmdate('Y-m-d H:i:s', $checked_ts)) : 'Never',
                'query_keyword'   => (string) ($entry['query_keyword'] ?? ''),
                'http_status'     => (int) ($entry['http_status'] ?? 200),
                'raw_total'       => (int) ($entry['raw_total'] ?? 0),
                'scanned_records' => (int) ($entry['scanned_records'] ?? ($entry['raw_total'] ?? 0)),
                'pages_fetched'   => (int) ($entry['pages_fetched'] ?? 1),
                'truncated'       => !empty($entry['truncated']),
                'matched_count'   => count($cves),
                'error'           => (string) ($entry['error'] ?? ''),
                'cves'            => $cves,
            ];
        }

        $raw_logs = is_array($state['logs'] ?? null) ? $state['logs'] : [];
        $logs     = [];
        foreach ($raw_logs as $log) {
            if (!is_array($log)) {
                continue;
            }
            $ts = (int) ($log['ts'] ?? 0);
            $log['ts_human'] = $ts > 0 ? (function_exists('human_time_diff') ? human_time_diff($ts, $now) . ' ago' : gmdate('Y-m-d H:i:s', $ts)) : '';
            $logs[] = $log;
        }

        return [
            'is_running'         => !empty($state['is_running']),
            'total_components'   => (int) ($state['total_components'] ?? count(self::collect_installed_components())),
            'checked_count'      => (int) ($state['checked_count'] ?? count($catalog)),
            'last_fetch_at'      => $last_ts,
            'last_fetch_human'   => $last_ts > 0 ? (function_exists('human_time_diff') ? human_time_diff($last_ts, $now) . ' ago' : gmdate('Y-m-d H:i:s', $last_ts)) : 'Never',
            'has_api_key'        => self::get_api_key() !== '',
            'batch_size'         => self::get_batch_size(),
            'vault_entries'      => count($catalog),
            'checked_components' => $checked_components,
            'logs'               => $logs,
        ];
    }

    /**
     * Collect all installed plugins & themes for background NIST sync (with vendor/author hints).
     *
     * @return list<array{slug: string, name: string, version: string, type: string, author?: string, vendor_hints?: list<string>}>
     */
    public static function collect_installed_components(): array {
        $items = [
            [
                'slug'         => 'wordpress',
                'name'         => 'WordPress Core',
                'version'      => function_exists('get_bloginfo') ? (string) get_bloginfo('version') : '0.0.0',
                'type'         => 'core',
                'author'       => 'WordPress',
                'vendor_hints' => ['wordpress'],
            ],
        ];
        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        foreach (get_plugins() as $file => $data) {
            $slug = dirname($file);
            if ($slug === '.' || $slug === '') {
                $slug = pathinfo($file, PATHINFO_FILENAME);
            }
            $author = function_exists('wp_strip_all_tags')
                ? wp_strip_all_tags((string) ($data['Author'] ?? ($data['AuthorName'] ?? '')))
                : trim(strip_tags((string) ($data['Author'] ?? ($data['AuthorName'] ?? ''))));
            $items[] = [
                'slug'         => strtolower($slug),
                'name'         => (string) ($data['Name'] ?? $slug),
                'version'      => (string) ($data['Version'] ?? '0.0.0'),
                'type'         => 'plugin',
                'author'       => $author,
                'vendor_hints' => self::extract_vendor_hints($author, (string) ($data['AuthorURI'] ?? ''), (string) ($data['PluginURI'] ?? '')),
            ];
        }
        if (function_exists('wp_get_themes')) {
            foreach (wp_get_themes() as $slug => $theme) {
                $author = function_exists('wp_strip_all_tags')
                    ? wp_strip_all_tags((string) $theme->get('Author'))
                    : trim(strip_tags((string) $theme->get('Author')));
                $items[] = [
                    'slug'         => strtolower((string) $slug),
                    'name'         => (string) $theme->get('Name'),
                    'version'      => (string) $theme->get('Version'),
                    'type'         => 'theme',
                    'author'       => $author,
                    'vendor_hints' => self::extract_vendor_hints($author, (string) $theme->get('AuthorURI'), (string) $theme->get('ThemeURI')),
                ];
            }
        }
        return $items;
    }

    /**
     * Extract normalized vendor hint tokens from plugin/theme Author and URI headers.
     *
     * @return list<string>
     */
    private static function extract_vendor_hints(string $author, string $author_uri = '', string $project_uri = ''): array {
        $hints = [];
        $push_token = static function (string $raw) use (&$hints): void {
            $raw = strtolower(trim($raw));
            if ($raw === '') {
                return;
            }
            $under = (string) preg_replace('/[^a-z0-9]+/', '_', $raw);
            $under = trim($under, '_');
            $compact = str_replace('_', '', $under);
            if (strlen($under) >= 3) {
                $hints[$under] = true;
            }
            if (strlen($compact) >= 3) {
                $hints[$compact] = true;
            }
        };

        if ($author !== '') {
            $push_token($author);
            foreach (preg_split('/[\s,&\/|]+/', $author) ?: [] as $part) {
                $clean = trim($part);
                if (strlen($clean) >= 3 && !in_array(strtolower($clean), ['inc', 'llc', 'ltd', 'gmbh', 'team', 'the', 'and', 'for', 'com', 'org', 'dev'], true)) {
                    $push_token($clean);
                }
            }
        }

        $generic_hosts = ['wordpress.org', 'www.wordpress.org', 'profiles.wordpress.org', 'github.com', 'gitlab.com', 'bitbucket.org', 'example.com'];
        foreach ([$author_uri, $project_uri] as $uri) {
            if ($uri === '') {
                continue;
            }
            $host = strtolower((string) (wp_parse_url($uri, PHP_URL_HOST) ?: ''));
            $host = (string) preg_replace('/^www\./', '', $host);
            if ($host !== '' && !in_array($host, $generic_hosts, true)) {
                $host_parts = explode('.', $host);
                if (!empty($host_parts[0]) && strlen($host_parts[0]) >= 3) {
                    $push_token($host_parts[0]);
                }
            }
        }

        return array_keys($hints);
    }

    /**
     * Resolve vendor/author context for a component slug from installed components if not explicitly provided.
     */
    private static function resolve_component_context(string $slug, string $type = '', array $extra = []): array {
        if (!empty($extra['author']) || !empty($extra['vendor_hints']) || !empty($extra['vendor'])) {
            return $extra;
        }
        $norm_slug = strtolower(trim($slug));
        if ($norm_slug === 'wordpress' || $type === 'core') {
            return ['author' => 'WordPress', 'vendor_hints' => ['wordpress']];
        }
        foreach (self::collect_installed_components() as $comp) {
            if (($comp['slug'] ?? '') === $norm_slug && ($type === '' || $type === 'component' || ($comp['type'] ?? '') === $type)) {
                return [
                    'author'       => (string) ($comp['author'] ?? ''),
                    'vendor_hints' => is_array($comp['vendor_hints'] ?? null) ? $comp['vendor_hints'] : [],
                ];
            }
        }
        return [];
    }

    /**
     * Start a background rate-limited NIST NVD sync across all installed components.
     */
    public static function start_background_sync(): array {
        $components = self::collect_installed_components();
        $state = [
            'is_running'       => true,
            'total_components' => count($components),
            'checked_count'    => 0,
            'last_fetch_at'    => time(),
            'queue'            => $components,
        ];
        update_option(self::OPTION_SYNC_STATE, $state, false);

        // Process first batch immediately, then schedule remaining batches every 30s
        self::process_next_batch();
        return self::get_status();
    }

    /**
     * Process one rate-limited batch of components/pages from the queue.
     */
    public static function process_next_batch(): void {
        $state = get_option(self::OPTION_SYNC_STATE, []);
        if (!is_array($state) || empty($state['queue']) || !is_array($state['queue'])) {
            if (is_array($state) && !empty($state['is_running'])) {
                $state['is_running'] = false;
                update_option(self::OPTION_SYNC_STATE, $state, false);
            }
            return;
        }

        self::execute_queue_batch($state, false);
        update_option(self::OPTION_SYNC_STATE, $state, false);

        if (!empty($state['is_running']) && !wp_next_scheduled(self::CRON_HOOK)) {
            wp_schedule_single_event(time() + self::BATCH_INTERVAL_SEC, self::CRON_HOOK);
        }
    }

    /**
     * Process a single real-time Complete/Custom Scan batch without exceeding NIST rate limits.
     */
    public static function process_scan_batch(bool $start = false, int $scan_id = 0): array {
        if ($start) {
            $components = self::collect_installed_components();
            $state      = get_option(self::OPTION_SYNC_STATE, []);
            if (!is_array($state)) {
                $state = [];
            }
            $state['is_running']       = true;
            $state['total_components'] = count($components);
            $state['checked_count']    = 0;
            $state['last_fetch_at']    = time();
            $state['queue']            = $components;
            update_option(self::OPTION_SYNC_STATE, $state, false);
        }

        $state = get_option(self::OPTION_SYNC_STATE, []);
        if (!is_array($state) || empty($state['queue']) || !is_array($state['queue'])) {
            if (is_array($state)) {
                $state['is_running']        = false;
                $state['last_completed_at'] = time();
                update_option(self::OPTION_SYNC_STATE, $state, false);
            }
            if ($scan_id > 0) {
                self::sync_vault_findings_to_scan($scan_id);
            }
            return [
                'success'   => true,
                'has_more'  => false,
                'remaining' => 0,
                'status'    => self::get_status(),
            ];
        }

        $batch_summary = self::execute_queue_batch($state, true);
        $remaining     = count($state['queue']);
        if ($remaining === 0 && $scan_id > 0) {
            self::sync_vault_findings_to_scan($scan_id);
        }
        update_option(self::OPTION_SYNC_STATE, $state, false);

        return [
            'success'       => true,
            'has_more'      => $remaining > 0,
            'remaining'     => $remaining,
            'requests_used' => $batch_summary['requests_used'],
            'status'        => self::get_status(),
        ];
    }

    /**
     * Execute one rate-budgeted batch of component NVD queries, continuing multi-page
     * components seamlessly across subsequent 30-second batches when needed.
     *
     * @return array{requests_used: int}
     */
    private static function execute_queue_batch(array &$state, bool $from_scan_batch): array {
        $catalog        = self::read_vault_catalog();
        $logs           = is_array($state['logs'] ?? null) ? $state['logs'] : [];
        $has_api_key    = self::get_api_key() !== '';
        $request_budget = $has_api_key ? self::API_KEY_REQUEST_BUDGET : self::FREE_TIER_REQUEST_BUDGET;
        $requests_used  = 0;

        while (!empty($state['queue']) && $requests_used < $request_budget) {
            $comp = array_shift($state['queue']);
            if (!is_array($comp)) {
                continue;
            }
            $slug            = strtolower(trim((string) ($comp['slug'] ?? '')));
            $name            = (string) ($comp['name'] ?? $slug);
            $version         = (string) ($comp['version'] ?? '0.0.0');
            $type            = (string) ($comp['type'] ?? 'plugin');
            $start_index     = max(0, (int) ($comp['start_index'] ?? 0));
            $partial_cves    = is_array($comp['partial_cves'] ?? null) ? $comp['partial_cves'] : [];
            $scanned_records = max(0, (int) ($comp['scanned_records'] ?? 0));
            $pages_fetched   = max(0, (int) ($comp['pages_fetched'] ?? 0));
            $context         = [
                'author'       => (string) ($comp['author'] ?? ''),
                'vendor_hints' => is_array($comp['vendor_hints'] ?? null) ? $comp['vendor_hints'] : [],
            ];
            if ($slug === '') {
                continue;
            }

            $final_page = null;
            $rate_limited = false;
            while ($requests_used < $request_budget) {
                if ($pages_fetched > 0) {
                    self::pace_nist_request($has_api_key);
                }
                $page = self::query_nist_page($slug, $name, $version, $type, $start_index, self::RESULTS_PER_PAGE, $context);
                $requests_used += max(1, (int) ($page['requests_made'] ?? 1));
                $pages_fetched++;
                $scanned_records += (int) ($page['page_count'] ?? 0);
                $partial_cves = self::merge_unique_cves($partial_cves, $page['cves'] ?? []);
                $final_page = $page;

                if ($page['error'] !== '') {
                    // If rate-limited (429/503) mid-pagination, preserve progress and stop this batch gracefully
                    if (in_array((int) ($page['http_status'] ?? 0), [429, 503], true)) {
                        $rate_limited = true;
                        $comp['start_index']     = $start_index;
                        $comp['partial_cves']    = $partial_cves;
                        $comp['scanned_records'] = $scanned_records;
                        $comp['pages_fetched']   = max(0, $pages_fetched - 1);
                        array_unshift($state['queue'], $comp);
                    }
                    break;
                }

                if (empty($page['has_more'])) {
                    break;
                }

                $start_index = (int) $page['next_index'];
                if ($requests_used >= $request_budget) {
                    // Budget reached: push continuation back to queue front for next 30s tick
                    $comp['start_index']     = $start_index;
                    $comp['partial_cves']    = $partial_cves;
                    $comp['scanned_records'] = $scanned_records;
                    $comp['pages_fetched']   = $pages_fetched;
                    array_unshift($state['queue'], $comp);
                    break 2;
                }
            }

            if ($rate_limited || $final_page === null) {
                if ($rate_limited) {
                    array_unshift($logs, [
                        'ts'          => time(),
                        'slug'        => $slug,
                        'name'        => $name,
                        'type'        => $type,
                        'version'     => $version,
                        'http_status' => (int) ($final_page['http_status'] ?? 429),
                        'raw_total'   => (int) ($final_page['raw_total'] ?? 0),
                        'matched'     => count($partial_cves),
                        'message'     => sprintf('%s (v%s): NIST rate limit hit (%s); resuming remaining pages in next batch.', $name, $version, (string) ($final_page['error'] ?? 'HTTP 429')),
                    ]);
                }
                break;
            }

            $now = time();
            $existing_cves = (isset($catalog[$slug]['cves']) && is_array($catalog[$slug]['cves'])) ? $catalog[$slug]['cves'] : [];
            // Preserve prior cached CVEs on transient HTTP error so a network blip does not erase known alerts
            $stored_cves = ($final_page['error'] !== '' && !empty($existing_cves)) ? $existing_cves : $partial_cves;

            $catalog[$slug] = [
                'slug'            => $slug,
                'name'            => $name,
                'type'            => $type,
                'version'         => $version,
                'checked_at'      => $now,
                'query_keyword'   => $final_page['query_keyword'],
                'http_status'     => $final_page['http_status'],
                'raw_total'       => $final_page['raw_total'],
                'scanned_records' => $scanned_records,
                'pages_fetched'   => $pages_fetched,
                'truncated'       => !empty($final_page['truncated']),
                'error'           => $final_page['error'],
                'cves'            => $stored_cves,
            ];
            $state['checked_count'] = (int) ($state['checked_count'] ?? 0) + 1;

            $trunc_note = !empty($final_page['truncated']) ? ' [capped at max page limit]' : '';
            array_unshift($logs, [
                'ts'          => $now,
                'slug'        => $slug,
                'name'        => $name,
                'type'        => $type,
                'version'     => $version,
                'http_status' => $final_page['http_status'],
                'raw_total'   => $final_page['raw_total'],
                'matched'     => count($stored_cves),
                'message'     => $final_page['error'] !== ''
                    ? sprintf('%s (v%s): %s', $name, $version, $final_page['error'])
                    : sprintf('%s (v%s): Scanned %d of %d NVD records (%d page%s), %d matched CVEs%s', $name, $version, $scanned_records, $final_page['raw_total'], $pages_fetched, $pages_fetched === 1 ? '' : 's', count($stored_cves), $trunc_note),
            ]);

            if ($type === 'core' || $slug === 'wordpress') {
                delete_transient('webcareproscan_cve_core_' . sanitize_key($version));
            } else {
                delete_transient('webcareproscan_cve_plugin_' . sanitize_key($slug . '_' . $version));
                delete_transient('webcareproscan_cve_theme_' . sanitize_key($slug . '_' . $version));
            }
        }

        $state['logs']          = array_slice($logs, 0, 50);
        self::write_vault_catalog($catalog);
        $state['last_fetch_at'] = time();
        $has_more               = !empty($state['queue']);
        $state['is_running']    = $has_more;
        if (!$has_more) {
            $state['last_completed_at'] = time();
            if (!$from_scan_batch && function_exists('wp_clear_scheduled_hook')) {
                wp_clear_scheduled_hook(self::CRON_HOOK);
            }
        }

        return ['requests_used' => $requests_used];
    }

    /**
     * Merge CVE advisory lists uniquely by CVE ID.
     *
     * @param array $base
     * @param array $incoming
     * @return array
     */
    private static function merge_unique_cves(array $base, array $incoming): array {
        $by_id = [];
        foreach ([$base, $incoming] as $list) {
            foreach ($list as $item) {
                if (!is_array($item)) {
                    continue;
                }
                $id = strtoupper((string) ($item['cve_id'] ?? ''));
                if ($id === '') {
                    continue;
                }
                $by_id[$id] = $item;
            }
        }
        return array_values($by_id);
    }

    /**
     * Build Finding objects from all active NIST CVE advisories stored in the Vault for currently installed components.
     *
     * @return list<\WebCareProScanner\Findings\Finding>
     */
    public static function collect_vault_findings(string $scan_id = ''): array {
        if (!class_exists('\\WebCareProScanner\\Findings\\Finding')) {
            return [];
        }
        $findings   = [];
        $components = self::collect_installed_components();
        foreach ($components as $comp) {
            $slug    = (string) ($comp['slug'] ?? '');
            $name    = (string) ($comp['name'] ?? $slug);
            $version = (string) ($comp['version'] ?? '0.0.0');
            $type    = (string) ($comp['type'] ?? 'plugin');
            if ($slug === '') {
                continue;
            }
            $cves = self::get_component_cves($slug, $version);
            if (empty($cves)) {
                continue;
            }
            $cve_ids  = array_values(array_filter(array_map(static fn($c) => (string) ($c['cve_id'] ?? ''), $cves)));
            $max_cvss = 0.0;
            foreach ($cves as $c) {
                $max_cvss = max($max_cvss, (float) ($c['cvss'] ?? 7.5));
            }
            $sev = $max_cvss >= 9.0 ? 'critical' : ($max_cvss >= 7.0 ? 'high' : ($max_cvss >= 4.0 ? 'medium' : 'low'));
            $findings[] = new \WebCareProScanner\Findings\Finding([
                'engine'       => 'nist-cve',
                'type'         => $type === 'core' ? 'vulnerable_core' : ($type === 'theme' ? 'vulnerable_theme' : 'vulnerable_plugin'),
                'severity'     => $sev,
                'confidence'   => 98,
                'file_path'    => "cve:{$type}:{$slug}",
                'description'  => sprintf(
                    'NIST NVD Vulnerability Alert: %s (v%s) matches %d active CVE advisory(s) (%s, max CVSS %.1f).',
                    $name,
                    $version,
                    count($cves),
                    implode(', ', array_slice($cve_ids, 0, 5)),
                    $max_cvss
                ),
                'code_snippet' => 'CVE References: ' . implode(', ', $cve_ids),
                'evidence'     => wp_json_encode([
                    'type'      => $type,
                    'slug'      => $slug,
                    'name'      => $name,
                    'installed' => $version,
                    'has_cve'   => true,
                    'cves'      => $cves,
                ]),
            ]);
        }
        return $findings;
    }

    /**
     * Persist newly discovered NIST Vault CVE findings into a completed/running scan record and recalculate risk score.
     */
    public static function sync_vault_findings_to_scan(int $scan_id): void {
        if ($scan_id <= 0) {
            return;
        }
        global $wpdb;
        $findings = self::collect_vault_findings((string) $scan_id);
        if (empty($findings)) {
            return;
        }
        $table_issues = $wpdb->prefix . 'webcareproscan_scan_issues';
        $table_scans  = $wpdb->prefix . 'webcareproscan_scans';

        foreach ($findings as $f) {
            $item = $f->to_array();
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $exists = $wpdb->get_var(
                $wpdb->prepare(
                    'SELECT id FROM %i WHERE scan_id = %d AND file_path = %s LIMIT 1',
                    $table_issues,
                    $scan_id,
                    $item['file_path']
                )
            );
            if ($exists) {
                continue;
            }
            $matched_rule = class_exists('\\WebCareProScanner\\Findings\\WhitelistManager')
                ? \WebCareProScanner\Findings\WhitelistManager::match_finding($item)
                : null;
            $status = ($matched_rule !== null) ? 'ignored' : 'open';
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->insert($table_issues, [
                'scan_id'        => $scan_id,
                'engine'         => $item['engine'],
                'type'           => $item['type'],
                'severity'       => $item['severity'],
                'confidence'     => $item['confidence'],
                'file_path'      => $item['file_path'],
                'line_number'    => null,
                'code_snippet'   => $item['code_snippet'] ?? null,
                'evidence'       => $item['evidence'] ?? null,
                'description'    => $item['description'],
                'status'         => $status,
                'created_at'     => current_time('mysql'),
                'created_at_gmt' => gmdate('Y-m-d H:i:s'),
            ]);
        }

        // Recount open issues and update scan summary
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $open_count = (int) $wpdb->get_var(
            $wpdb->prepare("SELECT COUNT(*) FROM %i WHERE scan_id = %d AND status = 'open'", $table_issues, $scan_id)
        );
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->update($table_scans, ['issues_found' => $open_count], ['id' => $scan_id]);
    }

    /**
     * Live-fetch NIST NVD CVEs for a single plugin/theme/core component and store in the encrypted Vault.
     */
    public static function fetch_single_component(string $slug, string $name, string $version, string $type = ''): array {
        $norm_slug = strtolower(trim($slug));
        $comp_type = $type !== '' ? $type : ($norm_slug === 'wordpress' ? 'core' : 'component');
        $result    = self::query_nist_for_component($norm_slug, $name, $version, $comp_type);
        $cves      = $result['cves'];
        $now       = time();

        $catalog = self::read_vault_catalog();
        $existing_cves = (isset($catalog[$norm_slug]['cves']) && is_array($catalog[$norm_slug]['cves'])) ? $catalog[$norm_slug]['cves'] : [];
        $stored_cves = ($result['error'] !== '' && !empty($existing_cves)) ? $existing_cves : $cves;

        $catalog[$norm_slug] = [
            'slug'            => $norm_slug,
            'name'            => $name !== '' ? $name : $norm_slug,
            'type'            => $comp_type,
            'version'         => $version,
            'checked_at'      => $now,
            'query_keyword'   => $result['query_keyword'],
            'http_status'     => $result['http_status'],
            'raw_total'       => $result['raw_total'],
            'scanned_records' => (int) ($result['scanned_records'] ?? 0),
            'pages_fetched'   => (int) ($result['pages_fetched'] ?? 1),
            'truncated'       => !empty($result['truncated']),
            'error'           => $result['error'],
            'cves'            => $stored_cves,
        ];
        self::write_vault_catalog($catalog);

        $state = get_option(self::OPTION_SYNC_STATE, []);
        if (!is_array($state)) {
            $state = [];
        }
        $logs = is_array($state['logs'] ?? null) ? $state['logs'] : [];
        $pages_fetched   = max(1, (int) ($result['pages_fetched'] ?? 1));
        $scanned_records = (int) ($result['scanned_records'] ?? 0);
        $trunc_note      = !empty($result['truncated']) ? ' [capped at max page limit]' : '';
        array_unshift($logs, [
            'ts'          => $now,
            'slug'        => $norm_slug,
            'name'        => $name !== '' ? $name : $norm_slug,
            'type'        => $comp_type,
            'version'     => $version,
            'http_status' => $result['http_status'],
            'raw_total'   => $result['raw_total'],
            'matched'     => count($stored_cves),
            'message'     => $result['error'] !== ''
                ? sprintf('%s (v%s): %s', $name !== '' ? $name : $norm_slug, $version, $result['error'])
                : sprintf('%s (v%s): Live-fetched %d of %d NVD records (%d page%s), %d matched CVEs%s', $name !== '' ? $name : $norm_slug, $version, $scanned_records, $result['raw_total'], $pages_fetched, $pages_fetched === 1 ? '' : 's', count($stored_cves), $trunc_note),
        ]);
        $state['logs']          = array_slice($logs, 0, 50);
        $state['last_fetch_at'] = $now;
        $state['checked_count'] = count($catalog);
        update_option(self::OPTION_SYNC_STATE, $state, false);

        // Clear UpdateScanner transient cache for this component so UI refreshes immediately
        if ($comp_type === 'core' || $norm_slug === 'wordpress') {
            delete_transient('webcareproscan_cve_core_' . sanitize_key($version));
        } else {
            delete_transient('webcareproscan_cve_plugin_' . sanitize_key($norm_slug . '_' . $version));
            delete_transient('webcareproscan_cve_theme_' . sanitize_key($norm_slug . '_' . $version));
        }

        return [
            'success' => $result['error'] === '' || $result['http_status'] === 200,
            'slug'    => $norm_slug,
            'cves'    => $cves,
            'error'   => $result['error'],
            'status'  => self::get_status(),
        ];
    }

    /**
     * Retrieve cached NIST CVEs for a component from the encrypted Vault.
     */
    public static function get_component_cves(string $slug, string $version): array {
        $catalog = self::read_vault_catalog();
        $norm_slug = strtolower(trim($slug));
        if (empty($catalog[$norm_slug]['cves']) || !is_array($catalog[$norm_slug]['cves'])) {
            return [];
        }
        $cves = [];
        foreach ($catalog[$norm_slug]['cves'] as $item) {
            if (!is_array($item)) {
                continue;
            }
            $fixed_in = (string) ($item['fixed_in'] ?? '');
            if ($fixed_in !== '' && $fixed_in !== 'Latest' && !str_starts_with($fixed_in, '<=')) {
                if (version_compare($version, $fixed_in, '>=')) {
                    continue;
                }
            } elseif (str_starts_with($fixed_in, '<=')) {
                $max_inc = trim(substr($fixed_in, 2));
                if ($max_inc !== '' && version_compare($version, $max_inc, '>')) {
                    continue;
                }
            }
            $cves[] = $item;
        }
        return $cves;
    }

    /**
     * Build a clean, concise NIST NVD keywordSearch string without marketing subtitles or parentheticals.
     */
    public static function build_nist_query_keyword(string $slug, string $name, string $type = 'plugin'): string {
        $norm_slug = strtolower(trim($slug));
        if ($type === 'core' || $norm_slug === 'wordpress') {
            return 'WordPress';
        }
        $base = trim($name !== '' ? $name : str_replace(['-', '_'], ' ', $norm_slug));
        // Strip parentheticals like "(PCP)" and taglines after ":", " - ", " – ", " — ", "|"
        $base = (string) preg_replace('/\s*\([^)]*\)\s*/', ' ', $base);
        $parts = preg_split('/\s*(?::|\s[-–—|]\s)\s*/u', $base);
        if (is_array($parts) && !empty($parts[0])) {
            $base = trim($parts[0]);
        }
        $base = trim((string) preg_replace('/\s+/', ' ', $base));
        if ($base === '') {
            $base = str_replace(['-', '_'], ' ', $norm_slug);
        }
        // If slug is a clean single brand word matching the leading word (e.g. "akismet" -> "Akismet Anti-spam"), prefer the concise brand token
        $words = explode(' ', $base);
        if (count($words) > 1 && strtolower((string) preg_replace('/[^a-z0-9]/i', '', $words[0])) === (string) preg_replace('/[^a-z0-9]/i', '', $norm_slug)) {
            $base = $words[0];
        }
        if (stripos($base, 'wordpress') !== false) {
            return $base;
        }
        return 'WordPress ' . $base;
    }

    /**
     * Evaluate a single NIST NVD 2.0 CVE object against a specific WordPress component & version.
     *
     * Enforces recursive NVD configuration tree traversal (nested nodes/children, AND/OR/negate),
     * bounded and open-ended version range evaluation, and defensible CPE vendor/product policy
     * (exact WordPress Core vendor/product, strict vendor/author or WP.org slug verification when
     * target_sw is wildcard, and WordPress target_sw verification for company-vendor plugin CPEs).
     */
    public static function evaluate_nvd_cve_for_component(
        array $cve,
        string $slug,
        string $name,
        string $version,
        string $type = 'plugin',
        array $context = []
    ): ?array {
        $cve_id = strtoupper((string) ($cve['id'] ?? ''));
        if ($cve_id === '') {
            return null;
        }
        $vuln_status = strtolower((string) ($cve['vulnStatus'] ?? ''));
        if ($vuln_status === 'rejected') {
            return null;
        }

        $desc = '';
        foreach (($cve['descriptions'] ?? []) as $d) {
            if (($d['lang'] ?? '') === 'en') {
                $desc = (string) ($d['value'] ?? '');
                break;
            }
        }
        if ($desc === '' || str_starts_with($desc, '** REJECT **')) {
            return null;
        }

        $norm_slug  = strtolower(trim($slug));
        $slug_under = str_replace('-', '_', $norm_slug);
        $is_core    = ($type === 'core' || $norm_slug === 'wordpress');

        // Clean component title without marketing subtitle
        $clean_name = trim((string) preg_replace('/\s*\([^)]*\)\s*/', ' ', $name));
        $name_parts = preg_split('/\s*(?::|\s[-–—|]\s)\s*/u', $clean_name);
        $short_name = is_array($name_parts) && !empty($name_parts[0]) ? trim($name_parts[0]) : $clean_name;

        if (!$is_core) {
            $matches_text = ($short_name !== '' && stripos($desc, $short_name) !== false)
                || ($norm_slug !== '' && stripos($desc, $norm_slug) !== false)
                || ($slug_under !== '' && stripos($desc, $slug_under) !== false);
            if (!$matches_text) {
                return null;
            }
        }

        $context = self::resolve_component_context($norm_slug, $type, $context);
        $cve_signals = self::extract_cve_ecosystem_signals($cve, $desc, $norm_slug);
        $expected_vendors = self::build_expected_vendor_set($norm_slug, $short_name, $context);

        $has_any_cpe         = false;
        $fixed_in            = 'Latest';
        $is_version_affected = false;

        $configurations = is_array($cve['configurations'] ?? null) ? $cve['configurations'] : [];
        if (!empty($configurations)) {
            $eval = self::evaluate_nvd_configurations(
                $configurations,
                $norm_slug,
                $short_name,
                $version,
                $is_core,
                $context,
                $expected_vendors,
                $cve_signals,
                $has_any_cpe
            );
            if ($eval['state'] === 'matched') {
                $is_version_affected = true;
                if ($eval['fixed_in'] !== '') {
                    $fixed_in = $eval['fixed_in'];
                }
            }
        }

        if ($has_any_cpe) {
            if (!$is_version_affected) {
                return null;
            }
        } else {
            // No CPEs yet ("Awaiting Analysis") — never guess on Core; for plugins/themes require explicit CNA version range in description
            if ($is_core || str_contains($desc, '** DISPUTED **') || $version === '' || $version === '0.0.0') {
                return null;
            }
            if (preg_match('/\b(?:versions?\s+)?(?:up\s+to,?\s+and\s+including,?|through|<=)\s*v?(\d+\.\d+(?:\.\d+)*)/i', $desc, $m)) {
                $max_inc = $m[1];
                if (version_compare($version, $max_inc, '<=')) {
                    $is_version_affected = true;
                    $fixed_in            = '<= ' . $max_inc;
                }
            } elseif (preg_match('/\b(?:versions?\s+)?(?:before|prior\s+to|<)\s*v?(\d+\.\d+(?:\.\d+)*)/i', $desc, $m)) {
                $end_exc = $m[1];
                if (version_compare($version, $end_exc, '<')) {
                    $is_version_affected = true;
                    $fixed_in            = $end_exc;
                }
            }
        }

        if (!$is_version_affected) {
            return null;
        }

        $cvss        = 7.5;
        $cvss_vector = '';
        $metrics     = $cve['metrics']['cvssMetricV31'][0]['cvssData'] ?? ($cve['metrics']['cvssMetricV30'][0]['cvssData'] ?? null);
        if (is_array($metrics) && isset($metrics['baseScore'])) {
            $cvss        = (float) $metrics['baseScore'];
            $cvss_vector = (string) ($metrics['vectorString'] ?? '');
        }
        $cwe = '';
        if (!empty($cve['weaknesses'][0]['description'][0]['value'])) {
            $cwe = (string) $cve['weaknesses'][0]['description'][0]['value'];
        }
        $severity = $cvss >= 9.0 ? 'critical' : ($cvss >= 7.0 ? 'high' : ($cvss >= 4.0 ? 'medium' : 'low'));

        return [
            'cve_id'        => $cve_id,
            'title'         => substr($desc, 0, 120),
            'severity'      => $severity,
            'cvss'          => $cvss,
            'cvss_vector'   => $cvss_vector,
            'cwe'           => $cwe,
            'published'     => (string) ($cve['published'] ?? ''),
            'last_modified' => (string) ($cve['lastModified'] ?? ''),
            'fixed_in'      => $fixed_in,
            'reference'     => "https://nvd.nist.gov/vuln/detail/{$cve_id}",
            'cve_details'   => $desc,
        ];
    }

    /**
     * Extract WordPress ecosystem and slug reference signals from a CVE record.
     *
     * @return array{mentions_wp: bool, has_slug_wp_ref: bool}
     */
    private static function extract_cve_ecosystem_signals(array $cve, string $desc, string $norm_slug): array {
        $mentions_wp = (bool) preg_match('/\b(?:wordpress|wp-content|wp-admin|wp-includes|woocommerce|gutenberg)\b/i', $desc);
        $has_slug_wp_ref = false;

        foreach (($cve['references'] ?? []) as $ref) {
            if (!is_array($ref) || empty($ref['url'])) {
                continue;
            }
            $url = strtolower((string) $ref['url']);
            if (
                str_contains($url, 'wordpress.org')
                || str_contains($url, 'wordfence.com')
                || str_contains($url, 'patchstack.com')
                || str_contains($url, 'wpscan.com')
            ) {
                $mentions_wp = true;
            }
            if ($norm_slug !== '' && preg_match('#(?:wordpress\.org/(?:plugins|themes)|(?:plugins|themes)\.trac\.wordpress\.org/(?:browser|changeset|log))/' . preg_quote($norm_slug, '#') . '(?:[/?#]|$)#i', $url)) {
                $has_slug_wp_ref = true;
            }
        }

        return [
            'mentions_wp'     => $mentions_wp,
            'has_slug_wp_ref' => $has_slug_wp_ref,
        ];
    }

    /**
     * Build the set of normalized vendor tokens accepted as direct vendor matches for a component.
     *
     * @return array{all: array<string, bool>, explicit_author: array<string, bool>}
     */
    private static function build_expected_vendor_set(string $norm_slug, string $short_name, array $context): array {
        $all = [];
        $explicit_author = [];
        $add = static function (string $val, bool $is_explicit = false) use (&$all, &$explicit_author): void {
            $clean = strtolower(trim($val));
            if ($clean === '') {
                return;
            }
            $under = trim((string) preg_replace('/[^a-z0-9]+/', '_', $clean), '_');
            $compact = str_replace('_', '', $under);
            foreach (array_unique(array_filter([$clean, $under, $compact])) as $tok) {
                $all[$tok] = true;
                if ($is_explicit) {
                    $explicit_author[$tok] = true;
                }
            }
        };

        $slug_under = str_replace('-', '_', $norm_slug);
        if ($norm_slug !== '') {
            $add($norm_slug);
            $add($slug_under);
            $add($slug_under . '_project');
            $add($norm_slug . '_project');
        }
        if ($short_name !== '') {
            $sname_under = trim((string) preg_replace('/[^a-z0-9]+/i', '_', strtolower($short_name)), '_');
            if (strlen($sname_under) >= 3) {
                $add($sname_under);
                $add($sname_under . '_project');
            }
        }
        if (!empty($context['vendor'])) {
            $add((string) $context['vendor'], true);
        }
        if (!empty($context['author'])) {
            $add((string) $context['author'], true);
            foreach (self::extract_vendor_hints((string) $context['author']) as $hint) {
                $add($hint, true);
            }
        }
        if (!empty($context['vendor_hints']) && is_array($context['vendor_hints'])) {
            foreach ($context['vendor_hints'] as $hint) {
                $add((string) $hint, true);
            }
        }

        return [
            'all'             => $all,
            'explicit_author' => $explicit_author,
        ];
    }

    /**
     * Recursively evaluate top-level NVD configuration blocks (OR across blocks).
     *
     * @return array{state: 'matched'|'not_matched'|'neutral', fixed_in: string}
     */
    private static function evaluate_nvd_configurations(
        array $configurations,
        string $norm_slug,
        string $short_name,
        string $version,
        bool $is_core,
        array $context,
        array $expected_vendors,
        array $cve_signals,
        bool &$has_any_cpe
    ): array {
        $best_fixed_in = '';
        $saw_not_matched = false;

        foreach ($configurations as $cfg) {
            if (!is_array($cfg)) {
                continue;
            }
            $res = self::evaluate_cpe_node(
                $cfg,
                $norm_slug,
                $short_name,
                $version,
                $is_core,
                $context,
                $expected_vendors,
                $cve_signals,
                $has_any_cpe,
                0
            );
            if ($res['state'] === 'matched') {
                return $res;
            }
            if ($res['state'] === 'not_matched') {
                $saw_not_matched = true;
            }
        }

        return [
            'state'    => $saw_not_matched ? 'not_matched' : 'neutral',
            'fixed_in' => $best_fixed_in,
        ];
    }

    /**
     * Recursively evaluate a single NVD configuration node (supporting nested nodes/children, AND/OR, negate).
     *
     * @return array{state: 'matched'|'not_matched'|'neutral', fixed_in: string}
     */
    private static function evaluate_cpe_node(
        array $node,
        string $norm_slug,
        string $short_name,
        string $version,
        bool $is_core,
        array $context,
        array $expected_vendors,
        array $cve_signals,
        bool &$has_any_cpe,
        int $depth
    ): array {
        if ($depth > 16) {
            return ['state' => 'neutral', 'fixed_in' => ''];
        }

        $operator = strtoupper((string) ($node['operator'] ?? 'OR'));
        $negate   = !empty($node['negate']);
        $outcomes = [];

        // 1. Recurse into child nodes ('nodes' and/or 'children' keys in NVD 2.0)
        foreach (['nodes', 'children'] as $child_key) {
            if (!empty($node[$child_key]) && is_array($node[$child_key])) {
                foreach ($node[$child_key] as $child) {
                    if (is_array($child)) {
                        $outcomes[] = self::evaluate_cpe_node(
                            $child,
                            $norm_slug,
                            $short_name,
                            $version,
                            $is_core,
                            $context,
                            $expected_vendors,
                            $cve_signals,
                            $has_any_cpe,
                            $depth + 1
                        );
                    }
                }
            }
        }

        // 2. Evaluate direct cpeMatch leaves at this node
        if (!empty($node['cpeMatch']) && is_array($node['cpeMatch'])) {
            foreach ($node['cpeMatch'] as $match) {
                if (!is_array($match)) {
                    continue;
                }
                $criteria = strtolower((string) ($match['criteria'] ?? ''));
                if ($criteria === '') {
                    continue;
                }
                $is_vuln = !isset($match['vulnerable']) || !empty($match['vulnerable']);
                if ($is_vuln) {
                    $has_any_cpe = true;
                }

                $cpe_parts = explode(':', $criteria);
                // cpe:2.3:<part>:<vendor>:<product>:<version>:...:<target_sw>:...
                $part      = $cpe_parts[2] ?? '';
                $vendor    = $cpe_parts[3] ?? '';
                $product   = $cpe_parts[4] ?? '';
                $cpe_ver   = $cpe_parts[5] ?? '*';
                $target_sw = $cpe_parts[10] ?? '*';

                if (self::does_cpe_match_component($part, $vendor, $product, $target_sw, $norm_slug, $short_name, $is_core, $context, $expected_vendors, $cve_signals)) {
                    if (!$is_vuln) {
                        $outcomes[] = ['state' => 'not_matched', 'fixed_in' => ''];
                    } else {
                        $ver_eval = self::evaluate_cpe_version_match($match, $cpe_ver, $version);
                        $outcomes[] = [
                            'state'    => $ver_eval['matched'] ? 'matched' : 'not_matched',
                            'fixed_in' => $ver_eval['fixed_in'],
                        ];
                    }
                } elseif (!$is_vuln && !$is_core && $part === 'a' && $vendor === 'wordpress' && $product === 'wordpress') {
                    // Platform "running on WordPress" prerequisite inside an AND configuration
                    $wp_ver = (string) ($context['wp_version'] ?? (function_exists('get_bloginfo') ? (string) get_bloginfo('version') : ''));
                    $has_wp_bounds = !empty($match['versionStartIncluding']) || !empty($match['versionStartExcluding'])
                        || !empty($match['versionEndIncluding']) || !empty($match['versionEndExcluding'])
                        || ($cpe_ver !== '*' && $cpe_ver !== '-' && $cpe_ver !== '');
                    if (!$has_wp_bounds) {
                        $outcomes[] = ['state' => 'matched', 'fixed_in' => ''];
                    } elseif ($wp_ver !== '' && $wp_ver !== '0.0.0') {
                        $wp_eval = self::evaluate_cpe_version_match($match, $cpe_ver, $wp_ver);
                        $outcomes[] = ['state' => $wp_eval['matched'] ? 'matched' : 'not_matched', 'fixed_in' => ''];
                    }
                }
            }
        }

        $relevant = array_values(array_filter($outcomes, static fn(array $o): bool => $o['state'] !== 'neutral'));
        if (empty($relevant)) {
            return ['state' => 'neutral', 'fixed_in' => ''];
        }

        $node_state    = 'not_matched';
        $node_fixed_in = '';

        if ($operator === 'AND') {
            $all_matched = true;
            foreach ($relevant as $o) {
                if ($o['state'] !== 'matched') {
                    $all_matched = false;
                    break;
                }
                if ($node_fixed_in === '' && $o['fixed_in'] !== '') {
                    $node_fixed_in = $o['fixed_in'];
                }
            }
            $node_state = $all_matched ? 'matched' : 'not_matched';
        } else {
            foreach ($relevant as $o) {
                if ($o['state'] === 'matched') {
                    $node_state    = 'matched';
                    $node_fixed_in = $o['fixed_in'];
                    break;
                }
            }
        }

        if ($negate) {
            if ($node_state === 'matched') {
                $node_state    = 'not_matched';
                $node_fixed_in = '';
            } elseif ($node_state === 'not_matched') {
                $node_state = 'matched';
            }
        }

        return [
            'state'    => $node_state,
            'fixed_in' => $node_fixed_in,
        ];
    }

    /**
     * Validate CPE part, vendor, product, and target_sw against the target WordPress component.
     */
    private static function does_cpe_match_component(
        string $part,
        string $vendor,
        string $product,
        string $target_sw,
        string $norm_slug,
        string $short_name,
        bool $is_core,
        array $context,
        array $expected_vendors,
        array $cve_signals
    ): bool {
        if ($part !== 'a' || $product === '' || $product === '*') {
            return false;
        }

        if ($is_core) {
            return $vendor === 'wordpress'
                && $product === 'wordpress'
                && ($target_sw === '*' || $target_sw === '-' || $target_sw === '');
        }

        if ($product === 'wordpress') {
            return false;
        }

        $slug_under = str_replace('-', '_', $norm_slug);
        $norm_prod  = str_replace(['-', '_'], '', $product);
        $norm_s     = str_replace(['-', '_'], '', $norm_slug);
        $norm_sname = strtolower((string) preg_replace('/[^a-z0-9]/i', '', $short_name));

        $product_matches = (
            $product === $norm_slug
            || $product === $slug_under
            || ($norm_s !== '' && $norm_prod === $norm_s)
            || ($norm_sname !== '' && strlen($norm_sname) >= 4 && $norm_prod === $norm_sname)
        );
        if (!$product_matches) {
            return false;
        }

        // Reject CPEs explicitly scoped to non-WordPress ecosystems (e.g. drupal, joomla, magento, npm)
        if (!in_array($target_sw, ['wordpress', '*', '-', ''], true)) {
            return false;
        }

        if ($vendor === '' || $vendor === '*' || $vendor === '-') {
            return false;
        }

        $norm_vendor_under   = trim((string) preg_replace('/[^a-z0-9]+/', '_', $vendor), '_');
        $norm_vendor_compact = str_replace('_', '', $norm_vendor_under);
        $vendor_base         = preg_replace('/_project$/', '', $norm_vendor_under) ?? $norm_vendor_under;

        $vendor_in_expected = isset($expected_vendors['all'][$vendor])
            || isset($expected_vendors['all'][$norm_vendor_under])
            || isset($expected_vendors['all'][$norm_vendor_compact])
            || isset($expected_vendors['all'][$vendor_base]);

        $vendor_in_explicit_author = isset($expected_vendors['explicit_author'][$vendor])
            || isset($expected_vendors['explicit_author'][$norm_vendor_under])
            || isset($expected_vendors['explicit_author'][$norm_vendor_compact]);

        // Reject well-known non-WordPress OS/infrastructure vendors unless explicitly matching component author
        $non_wp_vendors = [
            'adobe', 'apache', 'apple', 'canonical', 'cisco', 'debian', 'drupal',
            'fedoraproject', 'freebsd', 'google', 'ibm', 'intel', 'joomla',
            'linux', 'magento', 'microsoft', 'mozilla', 'netbsd', 'nginx',
            'nodejs', 'openbsd', 'oracle', 'php', 'python', 'redhat',
            'ruby', 'sap', 'solarwinds', 'suse', 'ubuntu', 'vmware',
        ];
        if (in_array($norm_vendor_compact, $non_wp_vendors, true) && !$vendor_in_explicit_author) {
            return false;
        }

        // Optional strict-vendor override for callers/tests requiring exact vendor token match
        if (!empty($context['strict_vendor'])) {
            return $vendor_in_expected;
        }

        // If NVD explicitly scoped target_sw=wordpress and vendor is non-blocklisted, accept
        if ($target_sw === 'wordpress') {
            return true;
        }

        // When target_sw is wildcard (* or -), require BOTH WordPress ecosystem evidence AND
        // either a matching expected vendor (author/slug/*_project) or a WordPress.org slug reference URL
        return !empty($cve_signals['mentions_wp'])
            && ($vendor_in_expected || !empty($cve_signals['has_slug_wp_ref']));
    }

    /**
     * Evaluate bounded, exact, and open-ended lower-bound CPE version ranges.
     *
     * @return array{matched: bool, fixed_in: string}
     */
    private static function evaluate_cpe_version_match(array $match, string $cpe_ver, string $version): array {
        $start_inc = trim((string) ($match['versionStartIncluding'] ?? ''));
        $start_exc = trim((string) ($match['versionStartExcluding'] ?? ''));
        $end_exc   = trim((string) ($match['versionEndExcluding'] ?? ''));
        $end_inc   = trim((string) ($match['versionEndIncluding'] ?? ''));

        $has_exact = ($cpe_ver !== '*' && $cpe_ver !== '-' && $cpe_ver !== '');
        $has_bound = ($start_inc !== '' || $start_exc !== '' || $end_exc !== '' || $end_inc !== '' || $has_exact);
        if (!$has_bound || $version === '' || $version === '0.0.0') {
            return ['matched' => false, 'fixed_in' => ''];
        }

        if ($has_exact && $start_inc === '' && $start_exc === '' && $end_exc === '' && $end_inc === '') {
            if (version_compare($version, $cpe_ver, '==')) {
                return ['matched' => true, 'fixed_in' => '<= ' . $cpe_ver];
            }
            return ['matched' => false, 'fixed_in' => ''];
        }

        if ($start_inc !== '' && version_compare($version, $start_inc, '<')) {
            return ['matched' => false, 'fixed_in' => ''];
        }
        if ($start_exc !== '' && version_compare($version, $start_exc, '<=')) {
            return ['matched' => false, 'fixed_in' => ''];
        }
        if ($end_exc !== '') {
            if (version_compare($version, $end_exc, '>=')) {
                return ['matched' => false, 'fixed_in' => ''];
            }
            return ['matched' => true, 'fixed_in' => $end_exc];
        }
        if ($end_inc !== '') {
            if (version_compare($version, $end_inc, '>')) {
                return ['matched' => false, 'fixed_in' => ''];
            }
            return ['matched' => true, 'fixed_in' => '<= ' . $end_inc];
        }

        // Open-ended range with lower bound (versionStartIncluding / versionStartExcluding) and no upper bound
        if ($start_inc !== '' || $start_exc !== '') {
            return ['matched' => true, 'fixed_in' => 'Latest'];
        }

        return ['matched' => false, 'fixed_in' => ''];
    }

    /**
     * Pace sequential NIST HTTP requests to honor public (5 req/30s) and API-key (50 req/30s) limits.
     */
    private static function pace_nist_request(bool $has_api_key): void {
        if (self::$http_get_callback !== null || !empty($GLOBALS['wp_mock_http_callback'])) {
            return;
        }
        if (defined('WEBCAREPROSCAN_TESTING') && WEBCAREPROSCAN_TESTING) {
            return;
        }
        usleep($has_api_key ? 650000 : 1200000);
    }

    /**
     * Execute a single HTTP GET request against the NIST NVD 2.0 API (using wp_safe_remote_get or test mock).
     *
     * @return array|\WP_Error
     */
    private static function perform_nist_http_get(string $url, array $args): array|\WP_Error {
        if (self::$http_get_callback !== null && is_callable(self::$http_get_callback)) {
            return call_user_func(self::$http_get_callback, $url, $args);
        }
        if (!empty($GLOBALS['wp_mock_http_callback']) && is_callable($GLOBALS['wp_mock_http_callback'])) {
            return call_user_func($GLOBALS['wp_mock_http_callback'], $url, $args);
        }
        if (function_exists('wp_safe_remote_get')) {
            return wp_safe_remote_get($url, $args);
        }
        return wp_remote_get($url, $args);
    }

    /**
     * Query a single page from the NIST NVD 2.0 API for a WordPress component.
     *
     * @return array{cves: array, http_status: int, raw_total: int, page_count: int, next_index: int, has_more: bool, truncated: bool, query_keyword: string, error: string, requests_made: int}
     */
    private static function query_nist_page(
        string $slug,
        string $name,
        string $version,
        string $type = 'plugin',
        int $start_index = 0,
        int $results_per_page = self::RESULTS_PER_PAGE,
        array $context = []
    ): array {
        $norm_slug        = strtolower(trim($slug));
        $is_core          = ($type === 'core' || $norm_slug === 'wordpress');
        $query_keyword    = self::build_nist_query_keyword($norm_slug, $name, $type);
        $has_mock_http    = (self::$http_get_callback !== null || !empty($GLOBALS['wp_mock_http_callback']));
        $results_per_page = max(1, min(2000, $results_per_page));
        $start_index      = max(0, $start_index);
        $max_results      = (int) apply_filters('webcareproscan_nist_max_results_per_component', self::MAX_RESULTS_PER_COMPONENT, $norm_slug, $type);
        $max_results      = max($results_per_page, $max_results);

        if ((defined('WEBCAREPROSCAN_TESTING') && WEBCAREPROSCAN_TESTING && !$has_mock_http) || (!function_exists('wp_safe_remote_get') && !function_exists('wp_remote_get') && !$has_mock_http)) {
            return [
                'cves'          => [],
                'http_status'   => 0,
                'raw_total'     => 0,
                'page_count'    => 0,
                'next_index'    => $start_index,
                'has_more'      => false,
                'truncated'     => false,
                'query_keyword' => $query_keyword,
                'error'         => 'Testing mode',
                'requests_made' => 0,
            ];
        }

        $query_params = [
            'resultsPerPage' => $results_per_page,
            'startIndex'     => $start_index,
        ];
        if ($is_core && $version !== '' && $version !== '0.0.0') {
            $cpe_query              = 'cpe:2.3:a:wordpress:wordpress:' . $version . ':*:*:*:*:*:*:*';
            $query_keyword          = $cpe_query;
            $query_params['cpeName'] = $cpe_query;
        } else {
            $query_params['keywordSearch'] = $query_keyword;
        }
        $url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?' . http_build_query($query_params, '', '&', PHP_QUERY_RFC3986);

        $headers = ['Accept' => 'application/json'];
        $api_key = self::get_api_key();
        if ($api_key !== '') {
            $headers['apiKey'] = $api_key;
        }

        $req_args = [
            'timeout'    => 10,
            'headers'    => $headers,
            'user-agent' => 'WEBCARE-NIST-Vault/' . (defined('WEBCAREPROSCAN_VERSION') ? WEBCAREPROSCAN_VERSION : '1.0'),
        ];

        $requests_made = 1;
        $res = self::perform_nist_http_get($url, $req_args);
        if (is_wp_error($res)) {
            return [
                'cves'          => [],
                'http_status'   => 0,
                'raw_total'     => 0,
                'page_count'    => 0,
                'next_index'    => $start_index,
                'has_more'      => false,
                'truncated'     => false,
                'query_keyword' => $query_keyword,
                'error'         => $res->get_error_message(),
                'requests_made' => $requests_made,
            ];
        }
        $code = (int) wp_remote_retrieve_response_code($res);
        // If NIST rejects an unactivated/revoked API key (403/404), clear invalid key and retry once on Free Tier
        if (($code === 403 || $code === 404) && $api_key !== '') {
            $nist_hdr = strtolower((string) wp_remote_retrieve_header($res, 'message'));
            if (str_contains($nist_hdr, 'apikey') || $code === 403 || $code === 404) {
                delete_option(self::OPTION_API_KEY_ENC);
            }
            unset($req_args['headers']['apiKey']);
            $requests_made++;
            $res = self::perform_nist_http_get($url, $req_args);
            if (!is_wp_error($res)) {
                $code = (int) wp_remote_retrieve_response_code($res);
            }
        }
        if ($code !== 200) {
            $nist_msg = (string) wp_remote_retrieve_header($res, 'message');
            $err      = $nist_msg !== '' ? "NIST HTTP {$code}: {$nist_msg}" : "NIST HTTP {$code}";
            return [
                'cves'          => [],
                'http_status'   => $code,
                'raw_total'     => 0,
                'page_count'    => 0,
                'next_index'    => $start_index,
                'has_more'      => false,
                'truncated'     => false,
                'query_keyword' => $query_keyword,
                'error'         => $err,
                'requests_made' => $requests_made,
            ];
        }

        $body      = json_decode(wp_remote_retrieve_body($res), true);
        $raw_total = (int) ($body['totalResults'] ?? 0);
        $vulns     = $body['vulnerabilities'] ?? [];
        if (!is_array($vulns)) {
            return [
                'cves'          => [],
                'http_status'   => $code,
                'raw_total'     => $raw_total,
                'page_count'    => 0,
                'next_index'    => $start_index,
                'has_more'      => false,
                'truncated'     => false,
                'query_keyword' => $query_keyword,
                'error'         => '',
                'requests_made' => $requests_made,
            ];
        }

        $results = [];
        foreach ($vulns as $entry) {
            $cve = $entry['cve'] ?? [];
            if (!is_array($cve)) {
                continue;
            }
            $evaluated = self::evaluate_nvd_cve_for_component($cve, $norm_slug, $name, $version, $type, $context);
            if ($evaluated !== null) {
                $results[] = $evaluated;
            }
        }

        $page_count = count($vulns);
        $next_index = $start_index + $page_count;
        $has_more   = ($page_count > 0 && $next_index < $raw_total && $next_index < $max_results);
        $truncated  = ($raw_total > $max_results && $next_index >= $max_results);

        return [
            'cves'          => $results,
            'http_status'   => $code,
            'raw_total'     => $raw_total,
            'page_count'    => $page_count,
            'next_index'    => $next_index,
            'has_more'      => $has_more,
            'truncated'     => $truncated,
            'query_keyword' => $query_keyword,
            'error'         => '',
            'requests_made' => $requests_made,
        ];
    }

    /**
     * Query NIST NVD 2.0 API for a WordPress component with bounded, rate-limited pagination.
     *
     * @return array{cves: array, http_status: int, raw_total: int, scanned_records: int, pages_fetched: int, truncated: bool, query_keyword: string, error: string}
     */
    private static function query_nist_for_component(string $slug, string $name, string $version, string $type = 'plugin', array $context = []): array {
        $norm_slug       = strtolower(trim($slug));
        $context         = self::resolve_component_context($norm_slug, $type, $context);
        $has_api_key     = self::get_api_key() !== '';
        $max_sync_pages  = $has_api_key
            ? (int) ceil(self::MAX_RESULTS_PER_COMPONENT / self::RESULTS_PER_PAGE)
            : self::FREE_TIER_REQUEST_BUDGET;
        $start_index     = 0;
        $pages_fetched   = 0;
        $scanned_records = 0;
        $raw_total       = 0;
        $http_status     = 200;
        $query_keyword   = self::build_nist_query_keyword($norm_slug, $name, $type);
        $error           = '';
        $truncated       = false;
        $all_cves        = [];

        while ($pages_fetched < $max_sync_pages) {
            if ($pages_fetched > 0) {
                self::pace_nist_request($has_api_key);
            }

            $page = self::query_nist_page($norm_slug, $name, $version, $type, $start_index, self::RESULTS_PER_PAGE, $context);
            $pages_fetched++;
            $query_keyword = $page['query_keyword'];
            $http_status   = $page['http_status'];
            $raw_total     = max($raw_total, (int) $page['raw_total']);
            $scanned_records += (int) $page['page_count'];
            $all_cves      = self::merge_unique_cves($all_cves, $page['cves']);

            if ($page['error'] !== '') {
                $error = $page['error'];
                break;
            }
            if (!empty($page['truncated'])) {
                $truncated = true;
            }
            if (empty($page['has_more'])) {
                break;
            }

            $start_index = (int) $page['next_index'];
            if ($pages_fetched >= $max_sync_pages && $start_index < $raw_total) {
                $truncated = true;
            }
        }

        return [
            'cves'            => $all_cves,
            'http_status'     => $http_status,
            'raw_total'       => $raw_total,
            'scanned_records' => $scanned_records,
            'pages_fetched'   => $pages_fetched,
            'truncated'       => $truncated,
            'query_keyword'   => $query_keyword,
            'error'           => $error,
        ];
    }
}
