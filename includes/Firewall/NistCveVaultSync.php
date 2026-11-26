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

        return [
            'is_running'       => !empty($state['is_running']),
            'total_components' => (int) ($state['total_components'] ?? count(self::collect_installed_components())),
            'checked_count'    => (int) ($state['checked_count'] ?? count($catalog)),
            'last_fetch_at'    => $last_ts,
            'last_fetch_human' => $last_ts > 0 ? human_time_diff($last_ts, time()) . ' ago' : 'Never',
            'has_api_key'      => self::get_api_key() !== '',
            'batch_size'       => self::get_batch_size(),
            'vault_entries'    => count($catalog),
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

        foreach ($batch as $comp) {
            $slug = (string) ($comp['slug'] ?? '');
            if ($slug === '') {
                continue;
            }
            $cves = self::query_nist_for_component(
                $slug,
                (string) ($comp['name'] ?? $slug),
                (string) ($comp['version'] ?? '0.0.0')
            );
            $catalog[$slug] = [
                'slug'       => $slug,
                'version'    => (string) ($comp['version'] ?? '0.0.0'),
                'checked_at' => time(),
                'cves'       => $cves,
            ];
            $state['checked_count'] = (int) ($state['checked_count'] ?? 0) + 1;
        }

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
        $cves = self::query_nist_for_component($norm_slug, $name, $version);

        $catalog = self::read_vault_catalog();
        $catalog[$norm_slug] = [
            'slug'       => $norm_slug,
            'version'    => $version,
            'checked_at' => time(),
            'cves'       => $cves,
        ];
        self::write_vault_catalog($catalog);

        $state = get_option(self::OPTION_SYNC_STATE, []);
        if (!is_array($state)) {
            $state = [];
        }
        $state['last_fetch_at'] = time();
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
     */
    private static function query_nist_for_component(string $slug, string $name, string $version): array {
        if ((defined('WEBCAREPROSCAN_TESTING') && WEBCAREPROSCAN_TESTING) || !function_exists('wp_remote_get')) {
            return [];
        }

        $keyword = trim($name !== '' ? $name : str_replace(['-', '_'], ' ', $slug));
        $url = add_query_arg([
            'keywordSearch'  => 'WordPress ' . $keyword,
            'resultsPerPage' => 10,
        ], 'https://services.nvd.nist.gov/rest/json/cves/2.0');

        $headers = ['Accept' => 'application/json'];
        $api_key = self::get_api_key();
        if ($api_key !== '') {
            $headers['apiKey'] = $api_key;
        }

        $res = wp_remote_get($url, [
            'timeout'    => 8,
            'headers'    => $headers,
            'user-agent' => 'WEBCARE-NIST-Vault/' . (defined('WEBCAREPROSCAN_VERSION') ? WEBCAREPROSCAN_VERSION : '1.0'),
        ]);
        if (is_wp_error($res) || wp_remote_retrieve_response_code($res) !== 200) {
            return [];
        }

        $body = json_decode(wp_remote_retrieve_body($res), true);
        $vulns = $body['vulnerabilities'] ?? [];
        if (!is_array($vulns)) {
            return [];
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
            if ($desc === '' || stripos($desc, $keyword) === false && stripos($desc, $slug) === false) {
                continue;
            }

            $cvss = 7.5;
            $metrics = $cve['metrics']['cvssMetricV31'][0]['cvssData'] ?? ($cve['metrics']['cvssMetricV30'][0]['cvssData'] ?? null);
            if (is_array($metrics) && isset($metrics['baseScore'])) {
                $cvss = (float) $metrics['baseScore'];
            }
            $severity = $cvss >= 9.0 ? 'critical' : ($cvss >= 7.0 ? 'high' : ($cvss >= 4.0 ? 'medium' : 'low'));

            $results[] = [
                'cve_id'      => $cve_id,
                'title'       => substr($desc, 0, 120),
                'severity'    => $severity,
                'cvss'        => $cvss,
                'fixed_in'    => 'Latest',
                'reference'   => "https://nvd.nist.gov/vuln/detail/{$cve_id}",
                'cve_details' => $desc,
            ];
        }

        return $results;
    }
}
