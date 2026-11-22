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
    public const OPTION_KEV_ETAG         = 'webcareproscan_cisa_kev_etag';
    public const OPTION_KEV_MOD          = 'webcareproscan_cisa_kev_last_mod';
    public const CISA_KEV_FEED_URL       = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
    public const NVD_CVE_FEED_URL        = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
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
     * Ingest and evaluate signed incremental delta feed or free public pull feeds.
     *
     * @param array<string, mixed>|null $mock_payload Optional payload for testing / signed envelopes.
     * @return array{success: bool, new_cves: int, kev_updates: int, sequence: int, message: string}
     */
    public static function sync_incremental_feed(?array $mock_payload = null): array {
        $checkpoint = self::get_checkpoint();

        // If mock_payload / signed envelope is supplied, run full cryptographic envelope processing
        if ($mock_payload !== null) {
            return self::process_signed_envelope($mock_payload, $checkpoint);
        }

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

        $kev_updates = 0;
        $cve_count   = 0;
        $status_msgs = [];

        // 1. CISA KEV (Known Exploited Vulnerabilities) - 100% Free Public Pull Feed
        if (!empty($settings['threat_intel_cisa_kev_enabled'])) {
            $kev_res = self::sync_cisa_kev_feed();
            if ($kev_res['success']) {
                $kev_updates = $kev_res['count'];
                $status_msgs[] = sprintf('CISA KEV: %d records', $kev_updates);
            } elseif (!empty($kev_res['message'])) {
                $status_msgs[] = 'CISA KEV: ' . $kev_res['message'];
            }
        }

        // 2. NVD CVE 2.0 (Incremental WordPress Delta) - 100% Free Public Pull Feed
        if (!empty($settings['threat_intel_nvd_cve_enabled'])) {
            $nvd_res = self::sync_nvd_wordpress_cves($checkpoint);
            if ($nvd_res['success']) {
                $cve_count = $nvd_res['count'];
                $status_msgs[] = sprintf('NVD: %d WordPress CVEs', $cve_count);
            } elseif (!empty($nvd_res['message'])) {
                $status_msgs[] = 'NVD: ' . $nvd_res['message'];
            }
        }

        $current_kev = (array) get_option(self::OPTION_KEV_CATALOG, []);
        $stored_findings = (array) get_option(self::OPTION_CVE_FINDINGS, []);

        // Advance sequence monotonically on public pull
        $next_seq = $checkpoint['sequence'] + 1;
        self::update_checkpoint($next_seq, gmdate('Y-m-d\TH:i:s\Z'), '');

        update_option(self::OPTION_FEED_META, [
            'last_sync'       => current_time('mysql'),
            'last_sync_ts'    => time(),
            'sequence'        => $next_seq,
            'cves_processed'  => $cve_count,
            'findings_count'  => count($stored_findings),
            'kev_total_count' => count($current_kev),
        ], false);

        $msg = !empty($status_msgs) ? implode(' | ', $status_msgs) : 'Public threat feeds synchronized.';
        return [
            'success'     => true,
            'new_cves'    => $cve_count,
            'kev_updates' => $kev_updates,
            'sequence'    => $next_seq,
            'message'     => $msg,
        ];
    }

    /**
     * Pull and cache CISA KEV catalog using If-Modified-Since / ETag caching.
     * Zero visitor or site data is ever sent outbound.
     *
     * @return array{success: bool, count: int, message: string}
     */
    public static function sync_cisa_kev_feed(): array {
        $headers = [
            'Accept'     => 'application/json',
            'User-Agent' => 'WebCare-Pro-Security',
        ];

        $cached_etag = (string) get_option(self::OPTION_KEV_ETAG, '');
        $cached_mod  = (string) get_option(self::OPTION_KEV_MOD, '');
        if ($cached_etag !== '') {
            $headers['If-None-Match'] = $cached_etag;
        }
        if ($cached_mod !== '') {
            $headers['If-Modified-Since'] = $cached_mod;
        }

        $response = wp_safe_remote_get(self::CISA_KEV_FEED_URL, [
            'timeout'    => 15,
            'user-agent' => 'WebCare-Pro-Security',
            'headers'    => $headers,
        ]);

        if (is_wp_error($response)) {
            return [
                'success' => false,
                'count'   => 0,
                'message' => $response->get_error_message(),
            ];
        }

        $code = (int) wp_remote_retrieve_response_code($response);
        if ($code === 304) {
            $current_kev = (array) get_option(self::OPTION_KEV_CATALOG, []);
            return [
                'success' => true,
                'count'   => count($current_kev),
                'message' => 'Up to date (304 Not Modified)',
            ];
        }

        if ($code !== 200) {
            return [
                'success' => false,
                'count'   => 0,
                'message' => sprintf('HTTP %d', $code),
            ];
        }

        $body = wp_remote_retrieve_body($response);
        if (strlen($body) > self::MAX_FEED_BYTES) {
            AuditLogger::log_event(
                'FEED_PAYLOAD_TOO_LARGE',
                sprintf('CISA KEV feed response exceeds strict ceiling (%d bytes > %d max).', strlen($body), self::MAX_FEED_BYTES)
            );
            return [
                'success' => false,
                'count'   => 0,
                'message' => 'Response exceeded 2 MB ceiling',
            ];
        }

        $data = json_decode($body, true);
        if (!is_array($data) || empty($data['vulnerabilities']) || !is_array($data['vulnerabilities'])) {
            return [
                'success' => false,
                'count'   => 0,
                'message' => 'Malformed CISA KEV JSON',
            ];
        }

        $current_kev = (array) get_option(self::OPTION_KEV_CATALOG, []);
        $count = 0;
        foreach ($data['vulnerabilities'] as $item) {
            $cve_id = (string) ($item['cveID'] ?? '');
            if ($cve_id !== '') {
                $current_kev[$cve_id] = [
                    'cve_id'             => $cve_id,
                    'vendor_project'     => (string) ($item['vendorProject'] ?? ''),
                    'product'            => (string) ($item['product'] ?? ''),
                    'date_added'         => (string) ($item['dateAdded'] ?? ''),
                    'due_date'           => (string) ($item['dueDate'] ?? ''),
                    'known_ransomware'   => strtolower((string) ($item['knownRansomwareCampaignUse'] ?? '')) === 'known',
                    'active_exploit_sig' => true,
                ];
                $count++;
            }
        }

        update_option(self::OPTION_KEV_CATALOG, $current_kev, false);

        // Store caching headers for next request
        $resp_headers = wp_remote_retrieve_headers($response);
        if (!empty($resp_headers['etag'])) {
            update_option(self::OPTION_KEV_ETAG, (string) $resp_headers['etag'], false);
        }
        if (!empty($resp_headers['last-modified'])) {
            update_option(self::OPTION_KEV_MOD, (string) $resp_headers['last-modified'], false);
        }

        return [
            'success' => true,
            'count'   => $count,
            'message' => 'Updated catalog',
        ];
    }

    /**
     * Pull incremental WordPress CVE delta from official NVD CVE 2.0 API.
     * Strictly generic keywordSearch=wordpress with zero site data outbound.
     *
     * @param array{sequence: int, last_mod_start: string, last_sync_ts: int, payload_sha256: string} $checkpoint
     * @return array{success: bool, count: int, message: string}
     */
    public static function sync_nvd_wordpress_cves(array $checkpoint): array {
        $now_utc = gmdate('Y-m-d\TH:i:s\Z');
        $start_date = !empty($checkpoint['last_mod_start']) ? $checkpoint['last_mod_start'] : gmdate('Y-m-d\TH:i:s\Z', time() - (30 * 86400));

        // Format dates for NVD REST API 2.0 (ISO-8601 with milliseconds, e.g. 2026-11-01T00:00:00.000)
        $start_clean = gmdate('Y-m-d\TH:i:s.000', strtotime($start_date));
        $end_clean   = gmdate('Y-m-d\TH:i:s.000', strtotime($now_utc));

        $url = add_query_arg([
            'keywordSearch'    => 'wordpress',
            'lastModStartDate' => $start_clean,
            'lastModEndDate'   => $end_clean,
            'resultsPerPage'   => 50,
        ], self::NVD_CVE_FEED_URL);

        $response = wp_safe_remote_get($url, [
            'timeout'    => 15,
            'user-agent' => 'WebCare-Pro-Security',
            'headers'    => [
                'Accept' => 'application/json',
            ],
        ]);

        if (is_wp_error($response)) {
            return [
                'success' => false,
                'count'   => 0,
                'message' => $response->get_error_message(),
            ];
        }

        $code = (int) wp_remote_retrieve_response_code($response);
        if ($code !== 200) {
            return [
                'success' => false,
                'count'   => 0,
                'message' => sprintf('NVD HTTP %d', $code),
            ];
        }

        $body = wp_remote_retrieve_body($response);
        if (strlen($body) > self::MAX_FEED_BYTES) {
            AuditLogger::log_event(
                'FEED_PAYLOAD_TOO_LARGE',
                sprintf('NVD CVE delta response exceeds strict ceiling (%d bytes > %d max).', strlen($body), self::MAX_FEED_BYTES)
            );
            return [
                'success' => false,
                'count'   => 0,
                'message' => 'NVD response exceeded 2 MB ceiling',
            ];
        }

        $data = json_decode($body, true);
        if (!is_array($data) || !isset($data['vulnerabilities']) || !is_array($data['vulnerabilities'])) {
            return [
                'success' => false,
                'count'   => 0,
                'message' => 'Empty or invalid NVD response',
            ];
        }

        $cve_entries = [];
        foreach ($data['vulnerabilities'] as $v) {
            $cve_item = $v['cve'] ?? [];
            $cve_id   = (string) ($cve_item['id'] ?? '');
            if ($cve_id === '') {
                continue;
            }

            $description = '';
            if (!empty($cve_item['descriptions']) && is_array($cve_item['descriptions'])) {
                foreach ($cve_item['descriptions'] as $desc) {
                    if (($desc['lang'] ?? '') === 'en') {
                        $description = (string) ($desc['value'] ?? '');
                        break;
                    }
                }
            }

            $cvss = 7.5;
            $severity = 'high';
            if (!empty($cve_item['metrics']['cvssMetricV31'][0]['cvssData'])) {
                $cvssData = $cve_item['metrics']['cvssMetricV31'][0]['cvssData'];
                $cvss     = (float) ($cvssData['baseScore'] ?? 7.5);
                $sev_raw  = strtolower((string) ($cvssData['baseSeverity'] ?? 'high'));
                if (in_array($sev_raw, ['critical', 'high', 'medium', 'low'], true)) {
                    $severity = $sev_raw;
                }
            }

            $cve_entries[] = [
                'cve_id'         => $cve_id,
                'title'          => $cve_id,
                'description'    => $description,
                'severity'       => $severity,
                'cvss'           => $cvss,
                'configurations' => (array) ($cve_item['configurations'] ?? []),
            ];
        }

        $current_kev = (array) get_option(self::OPTION_KEV_CATALOG, []);
        $evaluated   = self::evaluate_cves_against_inventory($cve_entries, $current_kev);

        if (!empty($evaluated)) {
            $stored_findings = (array) get_option(self::OPTION_CVE_FINDINGS, []);
            foreach ($evaluated as $cve_id => $finding) {
                $stored_findings[$cve_id] = $finding;
            }
            update_option(self::OPTION_CVE_FINDINGS, $stored_findings, false);
        }

        return [
            'success' => true,
            'count'   => count($cve_entries),
            'message' => sprintf('Evaluated %d CVEs', count($cve_entries)),
        ];
    }

    /**
     * Process Ed25519-signed envelope payload (for unit tests and optional signed feeds).
     *
     * @param array<string, mixed> $payload
     * @param array{sequence: int, last_mod_start: string, last_sync_ts: int, payload_sha256: string} $checkpoint
     * @return array{success: bool, new_cves: int, kev_updates: int, sequence: int, message: string}
     */
    public static function process_signed_envelope(array $payload, array $checkpoint): array {
        if (empty($payload['feed_version'])) {
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
                /* translators: %s: Error message detail */
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

            // Correlate against full local inventory using CVEIntelligenceService (including structured NVD configurations)
            $correlation = CVEIntelligenceService::correlate_component(
                $component_slug,
                $title,
                $description,
                $component_type,
                $affected_range,
                (array) ($cve['configurations'] ?? [])
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
