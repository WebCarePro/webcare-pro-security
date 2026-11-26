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
    public const VAULT_FILE         = 'nist_cve_catalog.vault.json';

    public static function init(): void {
        add_action(self::CRON_HOOK, [__CLASS__, 'process_next_batch']);
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
     * Retrieve decrypted NIST NVD API key if configured.
     */
    public static function get_api_key(): string {
        $enc = get_option(self::OPTION_API_KEY_ENC, '');
        if (!is_string($enc) || $enc === '' || !class_exists(SecretVault::class)) {
            return '';
        }
        $dec = SecretVault::decrypt($enc);
        return is_string($dec) ? trim($dec) : '';
    }

    /**
     * Batch size per 30-second window (5 without API key, 25 with API key).
     */
    public static function get_batch_size(): int {
        return self::get_api_key() !== '' ? 25 : 5;
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
        $items = [];
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
            $result = self::query_nist_for_component($slug, $name, $version);
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
        }

        $state['logs'] = array_slice($logs, 0, 50);

        self::write_vault_catalog($catalog);
        $state['last_fetch_at'] = time();
        $state['is_running'] = !empty($state['queue']);
        update_option(self::OPTION_SYNC_STATE, $state, false);

        if (!empty($state['queue']) && !wp_next_scheduled(self::CRON_HOOK)) {
            wp_schedule_single_event(time() + 35, self::CRON_HOOK);
        }
    }

    /**
     * Live-fetch NIST NVD CVEs for a single plugin/theme and store in the encrypted Vault.
     */
    public static function fetch_single_component(string $slug, string $name, string $version): array {
        $norm_slug = strtolower(trim($slug));
        $result    = self::query_nist_for_component($norm_slug, $name, $version);
        $cves      = $result['cves'];
        $now       = time();

        $catalog = self::read_vault_catalog();
        $catalog[$norm_slug] = [
            'slug'          => $norm_slug,
            'name'          => $name !== '' ? $name : $norm_slug,
            'type'          => 'component',
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
            'type'        => 'manual',
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
        delete_transient('webcareproscan_cve_plugin_' . sanitize_key($norm_slug . '_' . $version));
        delete_transient('webcareproscan_cve_theme_' . sanitize_key($norm_slug . '_' . $version));

        return [
            'success' => true,
            'slug'    => $norm_slug,
            'cves'    => $cves,
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
            if ($fixed_in !== '' && $fixed_in !== 'Latest' && version_compare($version, $fixed_in, '>=')) {
                continue;
            }
            $cves[] = $item;
        }
        return $cves;
    }

    /**
     * Query NIST NVD 2.0 API for a WordPress component by keyword.
     *
     * @return array{cves: array, http_status: int, raw_total: int, query_keyword: string, error: string}
     */
    private static function query_nist_for_component(string $slug, string $name, string $version): array {
        $keyword       = trim($name !== '' ? $name : str_replace(['-', '_'], ' ', $slug));
        $query_keyword = 'WordPress ' . $keyword;

        if ((defined('WEBCAREPROSCAN_TESTING') && WEBCAREPROSCAN_TESTING) || !function_exists('wp_remote_get')) {
            return ['cves' => [], 'http_status' => 0, 'raw_total' => 0, 'query_keyword' => $query_keyword, 'error' => 'Testing mode'];
        }

        $url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?' . http_build_query([
            'keywordSearch'  => $query_keyword,
            'resultsPerPage' => 10,
        ], '', '&', PHP_QUERY_RFC3986);

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
        // If NIST rejects the API key (403/404), retry once without apiKey on Free Tier
        if (($code === 403 || $code === 404) && $api_key !== '') {
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
            $cve_id = strtoupper((string) ($cve['id'] ?? ''));
            if ($cve_id === '') {
                continue;
            }
            $desc = '';
            foreach (($cve['descriptions'] ?? []) as $d) {
                if (($d['lang'] ?? '') === 'en') {
                    $desc = (string) ($d['value'] ?? '');
                    break;
                }
            }
            if ($desc === '' || (stripos($desc, $keyword) === false && stripos($desc, $slug) === false)) {
                continue;
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

            // Check NVD CPE version ranges to avoid false positives on already-patched versions
            $fixed_in = 'Latest';
            $is_version_affected = true;
            foreach (($cve['configurations'] ?? []) as $cfg) {
                foreach (($cfg['nodes'] ?? []) as $node) {
                    foreach (($node['cpeMatch'] ?? []) as $match) {
                        if (empty($match['vulnerable'])) {
                            continue;
                        }
                        if (!empty($match['versionEndExcluding'])) {
                            $fixed_in = (string) $match['versionEndExcluding'];
                            if ($version !== '' && version_compare($version, $fixed_in, '>=')) {
                                $is_version_affected = false;
                            }
                        } elseif (!empty($match['versionEndIncluding'])) {
                            $end_inc = (string) $match['versionEndIncluding'];
                            if ($version !== '' && version_compare($version, $end_inc, '>')) {
                                $is_version_affected = false;
                            }
                        }
                    }
                }
            }
            if (!$is_version_affected) {
                continue;
            }

            $results[] = [
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

        return [
            'cves'          => $results,
            'http_status'   => $code,
            'raw_total'     => $raw_total,
            'query_keyword' => $query_keyword,
            'error'         => '',
        ];
    }
}
