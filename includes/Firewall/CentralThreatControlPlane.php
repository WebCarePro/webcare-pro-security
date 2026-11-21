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
    public const OPTION_CVE_FINDINGS     = 'webcareproscan_cve_evaluated_findings';
    public const OPTION_FEED_META        = 'webcareproscan_central_feed_meta';
    public const DEFAULT_FEED_URL        = 'https://intel.webcarespro.com/api/v1/feed/cve-delta';
    public const MAX_FEED_BYTES          = 2097152; // 2 MB strict ceiling on feed response size

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
            'payload_sha256' => (string) ($cp['payload_sha256'] ?? ''),
        ];
    }

    /**
     * Update durable synchronization checkpoint.
     *
     * @param int $sequence Monotonic sequence
     * @param string $last_mod_start Timestamp of latest processed CVE
     * @param string $payload_sha256 Canonical SHA256 of processed payload
     */
    public static function update_checkpoint(int $sequence, string $last_mod_start, string $payload_sha256 = ''): void {
        update_option(self::OPTION_DELTA_CHECKPOINT, [
            'sequence'       => $sequence,
            'last_mod_start' => $last_mod_start,
            'last_sync_ts'   => time(),
            'payload_sha256' => $payload_sha256,
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

            $response = wp_safe_remote_get($feed_url, [
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

            // Bounded response size check before json_decode
            if (strlen($body) > self::MAX_FEED_BYTES) {
                AuditLogger::log_event(
                    'FEED_PAYLOAD_TOO_LARGE',
                    sprintf('Threat intelligence feed response exceeds strict ceiling (%d bytes > %d max).', strlen($body), self::MAX_FEED_BYTES)
                );
                return [
                    'success'     => false,
                    'new_cves'    => 0,
                    'kev_updates' => 0,
                    'sequence'    => $checkpoint['sequence'],
                    'message'     => __('Threat intelligence feed response exceeded maximum allowable size (2 MB).', 'webcare-pro-security'),
                ];
            }

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

        // Cryptographic verification: enforce Ed25519 signed envelope on all incoming feeds
        $sig_result = DeclarativePatchVerifier::verify_signature_envelope($payload);
        if (!$sig_result['valid']) {
            AuditLogger::log_event(
                'FEED_SIGNATURE_INVALID',
                sprintf('Rejected delta intelligence feed with invalid/missing Ed25519 signature: %s', (string) $sig_result['error'])
            );
            return [
                'success'     => false,
                'new_cves'    => 0,
                'kev_updates' => 0,
                'sequence'    => $checkpoint['sequence'],
                'message'     => sprintf(__('Threat intelligence feed signature verification failed: %s', 'webcare-pro-security'), (string) $sig_result['error']),
            ];
        }

        // Anti-rollback check: sequence must strictly advance or match current
        $incoming_seq = (int) ($payload['sequence'] ?? 0);
        $payload_bytes = (string) wp_json_encode(DeclarativePatchVerifier::canonicalize_recursive($payload));
        $current_payload_sha256 = hash('sha256', $payload_bytes);

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

        // PR-J2: If incoming feed has identical sequence, reject replay unless payload SHA-256 matches identically
        if ($incoming_seq === $checkpoint['sequence'] && $checkpoint['sequence'] > 0) {
            $known_sha256 = (string) ($checkpoint['payload_sha256'] ?? '');
            if ($known_sha256 !== '' && $known_sha256 !== $current_payload_sha256) {
                AuditLogger::log_event(
                    'FEED_REPLAY_MUTATION_REJECTED',
                    sprintf('Rejected conflicting intelligence feed at sequence %d with differing payload hash.', $incoming_seq)
                );
                return [
                    'success'     => false,
                    'new_cves'    => 0,
                    'kev_updates' => 0,
                    'sequence'    => $checkpoint['sequence'],
                    'message'     => __('Feed replay conflict detected: differing payload submitted for identical sequence.', 'webcare-pro-security'),
                ];
            }
        }

        $cve_entries = (array) ($payload['cves'] ?? []);
        $cve_removed = (array) ($payload['cve_removed'] ?? []);
        $kev_entries = (array) ($payload['cisa_kev'] ?? []);
        $kev_removed = (array) ($payload['kev_removed'] ?? []);

        // 1. Process and store CISA KEV (Known Exploited Vulnerabilities)
        $current_kev = (array) get_option(self::OPTION_KEV_CATALOG, []);
        $kev_count = 0;

        // Remove revoked/remediated KEV entries
        foreach ($kev_removed as $removed_id) {
            $r_id = is_string($removed_id) ? trim($removed_id) : '';
            if ($r_id !== '' && isset($current_kev[$r_id])) {
                unset($current_kev[$r_id]);
            }
        }

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

        // Persist evaluated actionable findings durably (PR-J2: Support explicit cve_removed tombstones and update is_cisa_kev)
        $stored_findings = (array) get_option(self::OPTION_CVE_FINDINGS, []);

        // Remove explicitly withdrawn CVEs
        foreach ($cve_removed as $tombstone_cve) {
            $t_id = is_string($tombstone_cve) ? trim($tombstone_cve) : '';
            if ($t_id !== '' && isset($stored_findings[$t_id])) {
                unset($stored_findings[$t_id]);
            }
        }

        // When kev_removed removes a KEV entry, update is_cisa_kev = false on matching persisted findings
        foreach ($kev_removed as $r_kev) {
            $r_k_id = is_string($r_kev) ? trim($r_kev) : '';
            if ($r_k_id !== '' && isset($stored_findings[$r_k_id])) {
                $stored_findings[$r_k_id]['is_cisa_kev'] = false;
            }
        }

        foreach ($evaluated_findings as $cve_id => $finding) {
            $stored_findings[$cve_id] = $finding;
        }
        update_option(self::OPTION_CVE_FINDINGS, $stored_findings, false);

        // 3. Update Checkpoint - only after signature verification, finding persistence, and KEV updates succeed
        $new_mod_timestamp = (string) ($payload['last_mod_timestamp'] ?? $checkpoint['last_mod_start']);
        self::update_checkpoint($incoming_seq, $new_mod_timestamp, $current_payload_sha256);

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
