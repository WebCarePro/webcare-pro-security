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
    public const VAULT_FILE         = 'nist_cve_catalog.vault.json';
    public const BATCH_SIZE         = 4;
    public const BATCH_INTERVAL_SEC = 30;
    public const DAILY_COOLDOWN_SEC = 86400;

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
                'slug'           => (string) ($entry['slug'] ?? $slug),
                'name'           => (string) ($entry['name'] ?? $slug),
                'type'           => (string) ($entry['type'] ?? 'plugin'),
                'version'        => (string) ($entry['version'] ?? '0.0.0'),
                'checked_at'     => $checked_ts,
                'checked_human'  => $checked_ts > 0 ? human_time_diff($checked_ts, $now) . ' ago' : 'Never',
                'query_keyword'  => (string) ($entry['query_keyword'] ?? ''),
                'http_status'    => (int) ($entry['http_status'] ?? 200),
                'raw_total'      => (int) ($entry['raw_total'] ?? 0),
                'matched_count'  => count($cves),
                'error'          => (string) ($entry['error'] ?? ''),
                'cves'           => $cves,
            ];
        }

        $raw_logs = is_array($state['logs'] ?? null) ? $state['logs'] : [];
        $logs     = [];
        foreach ($raw_logs as $log) {
            if (!is_array($log)) {
                continue;
            }
            $ts = (int) ($log['ts'] ?? 0);
            $log['ts_human'] = $ts > 0 ? human_time_diff($ts, $now) . ' ago' : '';
            $logs[] = $log;
        }

        return [
            'is_running'         => !empty($state['is_running']),
            'total_components'   => (int) ($state['total_components'] ?? count(self::collect_installed_components())),
            'checked_count'      => (int) ($state['checked_count'] ?? count($catalog)),
            'last_fetch_at'      => $last_ts,
            'last_fetch_human'   => $last_ts > 0 ? human_time_diff($last_ts, $now) . ' ago' : 'Never',
            'has_api_key'        => self::get_api_key() !== '',
            'batch_size'         => self::get_batch_size(),
            'vault_entries'      => count($catalog),
            'checked_components' => $checked_components,
            'logs'               => $logs,
        ];
    }

    /**
     * Collect all installed plugins & themes for background NIST sync.
     *
     * @return list<array{slug: string, name: string, version: string, type: string}>
     */
    public static function collect_installed_components(): array {
        $items = [
            [
                'slug'    => 'wordpress',
                'name'    => 'WordPress Core',
                'version' => function_exists('get_bloginfo') ? (string) get_bloginfo('version') : '0.0.0',
                'type'    => 'core',
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
            $items[] = [
                'slug'    => strtolower($slug),
                'name'    => (string) ($data['Name'] ?? $slug),
                'version' => (string) ($data['Version'] ?? '0.0.0'),
                'type'    => 'plugin',
            ];
        }
        if (function_exists('wp_get_themes')) {
            foreach (wp_get_themes() as $slug => $theme) {
                $items[] = [
                    'slug'    => strtolower((string) $slug),
                    'name'    => (string) $theme->get('Name'),
                    'version' => (string) $theme->get('Version'),
                    'type'    => 'theme',
                ];
            }
        }
        return $items;
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

        // Process first batch immediately, then schedule remaining batches every 35s
        self::process_next_batch();
        return self::get_status();
    }

    /**
     * Process one rate-limited batch of components from the queue.
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

        $batch_size = self::get_batch_size();
        $batch = array_splice($state['queue'], 0, $batch_size);
        $catalog = self::read_vault_catalog();

        $logs = is_array($state['logs'] ?? null) ? $state['logs'] : [];

        foreach ($batch as $comp) {
            $slug    = (string) ($comp['slug'] ?? '');
            $name    = (string) ($comp['name'] ?? $slug);
            $version = (string) ($comp['version'] ?? '0.0.0');
            $type    = (string) ($comp['type'] ?? 'plugin');
            if ($slug === '') {
                continue;
            }
            $result = self::query_nist_for_component($slug, $name, $version, $type);
            $cves   = $result['cves'];
            $now    = time();

            $catalog[$slug] = [
                'slug'          => $slug,
                'name'          => $name,
                'type'          => $type,
                'version'       => $version,
                'checked_at'    => $now,
                'query_keyword' => $result['query_keyword'],
                'http_status'   => $result['http_status'],
                'raw_total'     => $result['raw_total'],
                'error'         => $result['error'],
                'cves'          => $cves,
            ];
            $state['checked_count'] = (int) ($state['checked_count'] ?? 0) + 1;

            array_unshift($logs, [
                'ts'          => $now,
                'slug'        => $slug,
                'name'        => $name,
                'type'        => $type,
                'version'     => $version,
                'http_status' => $result['http_status'],
                'raw_total'   => $result['raw_total'],
                'matched'     => count($cves),
                'message'     => $result['error'] !== ''
                    ? sprintf('%s (v%s): %s', $name, $version, $result['error'])
                    : sprintf('%s (v%s): Scanned %d NVD records, %d matched CVEs', $name, $version, $result['raw_total'], count($cves)),
            ]);

            if ($type === 'core' || $slug === 'wordpress') {
                delete_transient('webcareproscan_cve_core_' . sanitize_key($version));
            } else {
                delete_transient('webcareproscan_cve_plugin_' . sanitize_key($slug . '_' . $version));
                delete_transient('webcareproscan_cve_theme_' . sanitize_key($slug . '_' . $version));
            }
        }

        $state['logs'] = array_slice($logs, 0, 50);

        self::write_vault_catalog($catalog);
        $state['last_fetch_at'] = time();
        $has_more               = !empty($state['queue']);
        $state['is_running']    = $has_more;
        if (!$has_more) {
            $state['last_completed_at'] = time();
            if (function_exists('wp_clear_scheduled_hook')) {
                wp_clear_scheduled_hook(self::CRON_HOOK);
            }
        }
        update_option(self::OPTION_SYNC_STATE, $state, false);

        if ($has_more && !wp_next_scheduled(self::CRON_HOOK)) {
            wp_schedule_single_event(time() + self::BATCH_INTERVAL_SEC, self::CRON_HOOK);
        }
    }

    /**
     * Process a single real-time Complete/Custom Scan batch (4 components) without scheduling WP-Cron.
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

        $batch   = array_splice($state['queue'], 0, self::BATCH_SIZE);
        $catalog = self::read_vault_catalog();
        $logs    = is_array($state['logs'] ?? null) ? $state['logs'] : [];

        foreach ($batch as $comp) {
            $slug    = (string) ($comp['slug'] ?? '');
            $name    = (string) ($comp['name'] ?? $slug);
            $version = (string) ($comp['version'] ?? '0.0.0');
            $type    = (string) ($comp['type'] ?? 'plugin');
            if ($slug === '') {
                continue;
            }
            $result = self::query_nist_for_component($slug, $name, $version, $type);
            $cves   = $result['cves'];
            $now    = time();

            $catalog[$slug] = [
                'slug'          => $slug,
                'name'          => $name,
                'type'          => $type,
                'version'       => $version,
                'checked_at'    => $now,
                'query_keyword' => $result['query_keyword'],
                'http_status'   => $result['http_status'],
                'raw_total'     => $result['raw_total'],
                'error'         => $result['error'],
                'cves'          => $cves,
            ];
            $state['checked_count'] = (int) ($state['checked_count'] ?? 0) + 1;

            array_unshift($logs, [
                'ts'          => $now,
                'slug'        => $slug,
                'name'        => $name,
                'type'        => $type,
                'version'     => $version,
                'http_status' => $result['http_status'],
                'raw_total'   => $result['raw_total'],
                'matched'     => count($cves),
                'message'     => $result['error'] !== ''
                    ? sprintf('%s (v%s): %s', $name, $version, $result['error'])
                    : sprintf('%s (v%s): Scanned %d NVD records, %d matched CVEs', $name, $version, $result['raw_total'], count($cves)),
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
        foreach ($batch as $comp) {
            $c_slug = (string) ($comp['slug'] ?? '');
            $c_ver  = (string) ($comp['version'] ?? '0.0.0');
            if ($c_slug !== '') {
                delete_transient('webcareproscan_cve_plugin_' . sanitize_key($c_slug . '_' . $c_ver));
                delete_transient('webcareproscan_cve_theme_' . sanitize_key($c_slug . '_' . $c_ver));
            }
        }
        $state['last_fetch_at'] = time();
        $remaining              = count($state['queue']);
        $state['is_running']    = $remaining > 0;
        if ($remaining === 0) {
            $state['last_completed_at'] = time();
            if ($scan_id > 0) {
                self::sync_vault_findings_to_scan($scan_id);
            }
        }
        update_option(self::OPTION_SYNC_STATE, $state, false);

        return [
            'success'   => true,
            'has_more'  => $remaining > 0,
            'remaining' => $remaining,
            'status'    => self::get_status(),
        ];
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
        $catalog[$norm_slug] = [
            'slug'          => $norm_slug,
            'name'          => $name !== '' ? $name : $norm_slug,
            'type'          => $comp_type,
            'version'       => $version,
            'checked_at'    => $now,
            'query_keyword' => $result['query_keyword'],
            'http_status'   => $result['http_status'],
            'raw_total'     => $result['raw_total'],
            'error'         => $result['error'],
            'cves'          => $cves,
        ];
        self::write_vault_catalog($catalog);

        $state = get_option(self::OPTION_SYNC_STATE, []);
        if (!is_array($state)) {
            $state = [];
        }
        $logs = is_array($state['logs'] ?? null) ? $state['logs'] : [];
        array_unshift($logs, [
            'ts'          => $now,
            'slug'        => $norm_slug,
            'name'        => $name !== '' ? $name : $norm_slug,
            'type'        => $comp_type,
            'version'     => $version,
            'http_status' => $result['http_status'],
            'raw_total'   => $result['raw_total'],
            'matched'     => count($cves),
            'message'     => $result['error'] !== ''
                ? sprintf('%s (v%s): %s', $name !== '' ? $name : $norm_slug, $version, $result['error'])
                : sprintf('%s (v%s): Live-fetched %d NVD records, %d matched CVEs', $name !== '' ? $name : $norm_slug, $version, $result['raw_total'], count($cves)),
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
     * Enforces strict CPE product matching and version bounds to prevent cross-plugin false positives.
     */
    public static function evaluate_nvd_cve_for_component(
        array $cve,
        string $slug,
        string $name,
        string $version,
        string $type = 'plugin'
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

        // Inspect NVD CPE configurations strictly scoped to this component's CPE product
        $has_any_cpe      = false;
        $matching_cpes    = [];
        foreach (($cve['configurations'] ?? []) as $cfg) {
            foreach (($cfg['nodes'] ?? []) as $node) {
                foreach (($node['cpeMatch'] ?? []) as $match) {
                    if (empty($match['vulnerable'])) {
                        continue;
                    }
                    $has_any_cpe = true;
                    $criteria    = strtolower((string) ($match['criteria'] ?? ''));
                    $cpe_parts   = explode(':', $criteria);
                    // cpe:2.3:a:<vendor>:<product>:<version>:...:<target_sw>:...
                    $vendor    = $cpe_parts[3] ?? '';
                    $product   = $cpe_parts[4] ?? '';
                    $cpe_ver   = $cpe_parts[5] ?? '*';
                    $target_sw = $cpe_parts[10] ?? '*';

                    if ($is_core) {
                        if ($vendor === 'wordpress' && $product === 'wordpress' && ($target_sw === '*' || $target_sw === '-' || $target_sw === '')) {
                            $matching_cpes[] = ['match' => $match, 'cpe_ver' => $cpe_ver];
                        }
                    } else {
                        $norm_prod  = str_replace(['-', '_'], '', $product);
                        $norm_s     = str_replace(['-', '_'], '', $norm_slug);
                        $norm_sname = strtolower((string) preg_replace('/[^a-z0-9]/i', '', $short_name));
                        if ($product !== 'wordpress' && (
                            $product === $norm_slug
                            || $product === $slug_under
                            || ($norm_s !== '' && $norm_prod === $norm_s)
                            || ($norm_sname !== '' && strlen($norm_sname) >= 4 && $norm_prod === $norm_sname)
                        )) {
                            $matching_cpes[] = ['match' => $match, 'cpe_ver' => $cpe_ver];
                        }
                    }
                }
            }
        }

        $fixed_in            = 'Latest';
        $is_version_affected = false;

        if ($has_any_cpe) {
            // If NVD analyzed CPEs for this CVE and NONE belong to this component, it is a cross-reference false positive
            if (empty($matching_cpes)) {
                return null;
            }
            foreach ($matching_cpes as $entry) {
                $match   = $entry['match'];
                $cpe_ver = (string) $entry['cpe_ver'];

                $start_inc = (string) ($match['versionStartIncluding'] ?? '');
                $start_exc = (string) ($match['versionStartExcluding'] ?? '');
                $end_exc   = (string) ($match['versionEndExcluding'] ?? '');
                $end_inc   = (string) ($match['versionEndIncluding'] ?? '');

                $has_bound = ($start_inc !== '' || $start_exc !== '' || $end_exc !== '' || $end_inc !== '' || ($cpe_ver !== '*' && $cpe_ver !== '-' && $cpe_ver !== ''));
                if (!$has_bound) {
                    continue;
                }
                if ($version === '' || $version === '0.0.0') {
                    continue;
                }
                if ($cpe_ver !== '*' && $cpe_ver !== '-' && $cpe_ver !== '' && $start_inc === '' && $start_exc === '' && $end_exc === '' && $end_inc === '') {
                    if (version_compare($version, $cpe_ver, '==')) {
                        $is_version_affected = true;
                        break;
                    }
                    continue;
                }
                if ($start_inc !== '' && version_compare($version, $start_inc, '<')) {
                    continue;
                }
                if ($start_exc !== '' && version_compare($version, $start_exc, '<=')) {
                    continue;
                }
                if ($end_exc !== '') {
                    if (version_compare($version, $end_exc, '>=')) {
                        continue;
                    }
                    $fixed_in            = $end_exc;
                    $is_version_affected = true;
                    break;
                }
                if ($end_inc !== '') {
                    if (version_compare($version, $end_inc, '>')) {
                        continue;
                    }
                    $fixed_in            = '<= ' . $end_inc;
                    $is_version_affected = true;
                    break;
                }
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
     * Query NIST NVD 2.0 API for a WordPress component by keyword / CPE.
     *
     * @return array{cves: array, http_status: int, raw_total: int, query_keyword: string, error: string}
     */
    private static function query_nist_for_component(string $slug, string $name, string $version, string $type = 'plugin'): array {
        $norm_slug     = strtolower(trim($slug));
        $is_core       = ($type === 'core' || $norm_slug === 'wordpress');
        $query_keyword = self::build_nist_query_keyword($norm_slug, $name, $type);

        if ((defined('WEBCAREPROSCAN_TESTING') && WEBCAREPROSCAN_TESTING) || !function_exists('wp_remote_get')) {
            return ['cves' => [], 'http_status' => 0, 'raw_total' => 0, 'query_keyword' => $query_keyword, 'error' => 'Testing mode'];
        }

        if ($is_core && $version !== '' && $version !== '0.0.0') {
            $cpe_query     = 'cpe:2.3:a:wordpress:wordpress:' . $version . ':*:*:*:*:*:*:*';
            $query_keyword = $cpe_query;
            $url           = 'https://services.nvd.nist.gov/rest/json/cves/2.0?' . http_build_query([
                'cpeName'        => $cpe_query,
                'resultsPerPage' => 20,
            ], '', '&', PHP_QUERY_RFC3986);
        } else {
            $url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?' . http_build_query([
                'keywordSearch'  => $query_keyword,
                'resultsPerPage' => 20,
            ], '', '&', PHP_QUERY_RFC3986);
        }

        $headers = ['Accept' => 'application/json'];
        $api_key = self::get_api_key();
        if ($api_key !== '') {
            $headers['apiKey'] = $api_key;
        }

        $res = wp_remote_get($url, [
            'timeout'    => 10,
            'headers'    => $headers,
            'user-agent' => 'WEBCARE-NIST-Vault/' . (defined('WEBCAREPROSCAN_VERSION') ? WEBCAREPROSCAN_VERSION : '1.0'),
        ]);
        if (is_wp_error($res)) {
            return ['cves' => [], 'http_status' => 0, 'raw_total' => 0, 'query_keyword' => $query_keyword, 'error' => $res->get_error_message()];
        }
        $code = (int) wp_remote_retrieve_response_code($res);
        // If NIST rejects an unactivated/revoked API key (403/404), clear invalid key and retry once on Free Tier
        if (($code === 403 || $code === 404) && $api_key !== '') {
            $nist_hdr = strtolower((string) wp_remote_retrieve_header($res, 'message'));
            if (str_contains($nist_hdr, 'apikey') || $code === 403 || $code === 404) {
                delete_option(self::OPTION_API_KEY_ENC);
            }
            unset($headers['apiKey']);
            $res = wp_remote_get($url, [
                'timeout'    => 10,
                'headers'    => $headers,
                'user-agent' => 'WEBCARE-NIST-Vault/' . (defined('WEBCAREPROSCAN_VERSION') ? WEBCAREPROSCAN_VERSION : '1.0'),
            ]);
            if (!is_wp_error($res)) {
                $code = (int) wp_remote_retrieve_response_code($res);
            }
        }
        if ($code !== 200) {
            $nist_msg = (string) wp_remote_retrieve_header($res, 'message');
            $err      = $nist_msg !== '' ? "NIST HTTP {$code}: {$nist_msg}" : "NIST HTTP {$code}";
            return ['cves' => [], 'http_status' => $code, 'raw_total' => 0, 'query_keyword' => $query_keyword, 'error' => $err];
        }

        $body      = json_decode(wp_remote_retrieve_body($res), true);
        $raw_total = (int) ($body['totalResults'] ?? 0);
        $vulns     = $body['vulnerabilities'] ?? [];
        if (!is_array($vulns)) {
            return ['cves' => [], 'http_status' => $code, 'raw_total' => $raw_total, 'query_keyword' => $query_keyword, 'error' => ''];
        }

        $results = [];
        foreach ($vulns as $entry) {
            $cve = $entry['cve'] ?? [];
            if (!is_array($cve)) {
                continue;
            }
            $evaluated = self::evaluate_nvd_cve_for_component($cve, $norm_slug, $name, $version, $type);
            if ($evaluated !== null) {
                $results[] = $evaluated;
            }
        }

        return [
            'cves'          => $results,
            'http_status'   => $code,
            'raw_total'     => $raw_total,
            'query_keyword' => $query_keyword,
            'error'         => '',
        ];
    }
}
