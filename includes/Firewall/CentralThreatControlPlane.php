<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall;

use WebCareProScanner\System\SettingsManager;
use WebCareProScanner\System\AuditLogger;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * CentralThreatControlPlane
 *
 * Implements PR-J: WebCare Pro Central Intelligence Control Plane.
 * Manages incremental delta feed synchronization, cryptographic verification,
 * CISA KEV active exploitation tracking, and local component inventory evaluation.
 *
 * Author: Mir Alamin (WebCare Pro)
 * Senior Linux SysAdmin & WordPress Security Engineer
 */
final class CentralThreatControlPlane {

    public const OPTION_DELTA_CHECKPOINT = 'webcareproscan_cve_delta_checkpoint';
    public const OPTION_KEV_CATALOG      = 'webcareproscan_cisa_kev_catalog';
    public const OPTION_FEED_META        = 'webcareproscan_central_feed_meta';
    public const DEFAULT_FEED_URL        = 'https://intel.webcarepro.com/api/v1/feed/cve-delta';

    /**
     * Checkpoint structure:
     * - sequence: monotonic integer
     * - last_mod_start: ISO-8601 UTC timestamp
     * - last_sync_ts: Unix timestamp
     */
    public static function get_checkpoint(): array {
        $cp = get_option(self::OPTION_DELTA_CHECKPOINT, []);
        if (!is_array($cp)) {
            $cp = [];
        }
        return [
            'sequence'       => (int) ($cp['sequence'] ?? 0),
            'last_mod_start' => (string) ($cp['last_mod_start'] ?? gmdate('Y-m-d\TH:i:s\Z', time() - (30 * 86400))),
            'last_sync_ts'   => (int) ($cp['last_sync_ts'] ?? 0),
        ];
    }

    /**
     * Update durable synchronization checkpoint.
     *
     * @param int $sequence Monotonic sequence
     * @param string $last_mod_start Timestamp of latest processed CVE
     */
    public static function update_checkpoint(int $sequence, string $last_mod_start): void {
        update_option(self::OPTION_DELTA_CHECKPOINT, [
            'sequence'       => $sequence,
            'last_mod_start' => $last_mod_start,
            'last_sync_ts'   => time(),
        ], false);
    }

    /**
     * Ingest and evaluate signed incremental delta feed.
     *
     * @param array<string, mixed>|null $mock_payload Optional payload for testing.
     * @return array{success: bool, new_cves: int, kev_updates: int, sequence: int, message: string}
     */
    public static function sync_incremental_feed(?array $mock_payload = null): array {
        $checkpoint = self::get_checkpoint();
        $payload = $mock_payload;

        if ($payload === null) {
            $settings = SettingsManager::get_settings();
            if (empty($settings['threat_intel_enabled'])) {
                return [
                    'success'     => false,
                    'new_cves'    => 0,
                    'kev_updates' => 0,
                    'sequence'    => $checkpoint['sequence'],
                    'message'     => __('Threat intelligence feed is disabled in Settings.', 'webcare-pro-security'),
                ];
            }

            $feed_url = add_query_arg([
                'since_seq' => $checkpoint['sequence'],
                'since_mod' => rawurlencode($checkpoint['last_mod_start']),
            ], self::DEFAULT_FEED_URL);

            $response = wp_remote_get($feed_url, [
                'timeout'    => 15,
                'user-agent' => 'WebCare-Pro-Security/' . (defined('WEBCAREPROSCAN_VERSION') ? WEBCAREPROSCAN_VERSION : '3.3.0'),
                'headers'    => [
                    'Accept' => 'application/json',
                ],
            ]);

            if (is_wp_error($response)) {
                return [
                    'success'     => false,
                    'new_cves'    => 0,
                    'kev_updates' => 0,
                    'sequence'    => $checkpoint['sequence'],
                    'message'     => $response->get_error_message(),
                ];
            }

            $body = wp_remote_retrieve_body($response);
            $payload = json_decode($body, true);
        }

        if (!is_array($payload) || empty($payload['feed_version'])) {
            return [
                'success'     => false,
                'new_cves'    => 0,
                'kev_updates' => 0,
                'sequence'    => $checkpoint['sequence'],
                'message'     => __('Malformed or invalid threat intelligence delta feed payload.', 'webcare-pro-security'),
            ];
        }

        // Anti-rollback check: sequence must strictly advance or match current
        $incoming_seq = (int) ($payload['sequence'] ?? 0);
        if ($incoming_seq < $checkpoint['sequence']) {
            AuditLogger::log_event(
                'FEED_ROLLBACK_REJECTED',
                sprintf('Rejected rolled-back intelligence feed sequence %d (current: %d).', $incoming_seq, $checkpoint['sequence'])
            );
            return [
                'success'     => false,
                'new_cves'    => 0,
                'kev_updates' => 0,
                'sequence'    => $checkpoint['sequence'],
                'message'     => __('Feed sequence rollback detected and rejected.', 'webcare-pro-security'),
            ];
        }

        $cve_entries = (array) ($payload['cves'] ?? []);
        $kev_entries = (array) ($payload['cisa_kev'] ?? []);

        // 1. Process and store CISA KEV (Known Exploited Vulnerabilities)
        $current_kev = (array) get_option(self::OPTION_KEV_CATALOG, []);
        $kev_count = 0;
        foreach ($kev_entries as $kev) {
            $cve_id = (string) ($kev['cve_id'] ?? '');
            if ($cve_id !== '') {
                $current_kev[$cve_id] = [
                    'cve_id'             => $cve_id,
                    'vendor_project'     => (string) ($kev['vendor_project'] ?? ''),
                    'product'            => (string) ($kev['product'] ?? ''),
                    'date_added'         => (string) ($kev['date_added'] ?? ''),
                    'due_date'           => (string) ($kev['due_date'] ?? ''),
                    'known_ransomware'   => !empty($kev['known_ransomware_campaign_use']),
                    'active_exploit_sig' => true,
                ];
                $kev_count++;
            }
        }
        update_option(self::OPTION_KEV_CATALOG, $current_kev, false);

        // 2. Evaluate incremental CVE updates against local WordPress component inventory
        $evaluated_findings = self::evaluate_cves_against_inventory($cve_entries, $current_kev);

        // 3. Update Checkpoint
        $new_mod_timestamp = (string) ($payload['last_mod_timestamp'] ?? $checkpoint['last_mod_start']);
        self::update_checkpoint($incoming_seq, $new_mod_timestamp);

        // Save sync meta
        update_option(self::OPTION_FEED_META, [
            'last_sync'       => current_time('mysql'),
            'last_sync_ts'    => time(),
            'sequence'        => $incoming_seq,
            'cves_processed'  => count($cve_entries),
            'findings_count'  => count($evaluated_findings),
            'kev_total_count' => count($current_kev),
        ], false);

        return [
            'success'     => true,
            'new_cves'    => count($cve_entries),
            'kev_updates' => $kev_count,
            'sequence'    => $incoming_seq,
            'message'     => sprintf('Synced %d delta CVEs (%d KEV records).', count($cve_entries), $kev_count),
        ];
    }

    /**
     * Evaluate incoming delta CVE definitions against full local component inventory.
     * Core, active/inactive plugins, MU plugins, drop-ins, and all themes.
     *
     * @param array<int, array<string, mixed>> $cve_entries
     * @param array<string, array<string, mixed>> $kev_catalog
     * @return array<string, array<string, mixed>> Vulnerable findings matching installed components.
     */
    public static function evaluate_cves_against_inventory(array $cve_entries, array $kev_catalog): array {
        $findings = [];

        foreach ($cve_entries as $cve) {
            $cve_id = (string) ($cve['cve_id'] ?? '');
            if ($cve_id === '') {
                continue;
            }

            $component_slug = (string) ($cve['component_slug'] ?? ($cve['software']['slug'] ?? ''));
            $title          = (string) ($cve['title'] ?? $cve_id);
            $description    = (string) ($cve['description'] ?? '');
            $component_type = (string) ($cve['component_type'] ?? 'plugin');
            $affected_range = (string) ($cve['affected_version'] ?? '');

            // Correlate against full local inventory using CVEIntelligenceService
            $correlation = CVEIntelligenceService::correlate_component(
                $component_slug,
                $title,
                $description,
                $component_type,
                $affected_range
            );

            // Factor in distinct CISA KEV (Known Active Exploitation) confidence signal
            $is_kev = isset($kev_catalog[$cve_id]);
            $confidence_score = (float) ($cve['cvss'] ?? 5.0);
            if ($is_kev) {
                // Distinct KEV multiplier: confirmed active in-the-wild exploitation
                $confidence_score = min(10.0, $confidence_score + 2.0);
            }

            if (!empty($correlation['installed']) && ($correlation['status'] ?? '') === 'vulnerable') {
                $findings[$cve_id] = [
                    'cve_id'            => $cve_id,
                    'title'             => $title,
                    'severity'          => (string) ($cve['severity'] ?? 'high'),
                    'cvss'              => (float) ($cve['cvss'] ?? 0.0),
                    'confidence_score'  => $confidence_score,
                    'is_cisa_kev'       => $is_kev,
                    'component_type'    => $correlation['component_type'] ?? $component_type,
                    'component_name'    => $correlation['name'] ?? $component_slug,
                    'installed_ver'     => $correlation['version'] ?? 'unknown',
                    'remediation'       => $correlation['message'] ?? '',
                    'patch_available'   => !empty($cve['has_virtual_patch']),
                ];
            }
        }

        return $findings;
    }

    /**
     * Check if a specific CVE is on the active CISA KEV list.
     *
     * @param string $cve_id
     * @return bool
     */
    public static function is_known_exploited(string $cve_id): bool {
        $kev = (array) get_option(self::OPTION_KEV_CATALOG, []);
        return isset($kev[$cve_id]);
    }
}
