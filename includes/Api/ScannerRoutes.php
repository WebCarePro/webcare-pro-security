<?php
namespace WebCareProScanner\Api;

use WebCareProScanner\Scanner\Engine;
use WebCareProScanner\Filesystem\FileScanner;
use WebCareProScanner\Integrity\CoreIntegrity;
use WebCareProScanner\Integrity\ImportantFileFIM;
use WebCareProScanner\Integrity\PluginIntegrity;
use WebCareProScanner\Integrity\ThemeIntegrity;
use WebCareProScanner\Database\DatabaseScanner;
use WebCareProScanner\Content\ContentScanner;
use WebCareProScanner\WordPress\WordPressSecurityScanner;
use WebCareProScanner\WordPress\UserScanner;
use WebCareProScanner\WordPress\UpdateScanner;
use WebCareProScanner\System\ServerInfo;
use WebCareProScanner\Backup\DatabaseBackup;
use WebCareProScanner\Findings\CorrelationEngine;
use WebCareProScanner\Findings\RiskScorer;
use WebCareProScanner\Quarantine\QuarantineManager;
use WebCareProScanner\Quarantine\CoreRepairManager;
use WebCareProScanner\Scan\ScanLock;
use WebCareProScanner\Filesystem\UploadsScanner;
use WebCareProScanner\WordPress\CronScanner;
use WebCareProScanner\WordPress\PersistenceScanner;
use WebCareProScanner\Forensics\AttackChainEngine;
use WebCareProScanner\Firewall\VirtualPatchManager;
use WebCareProScanner\Firewall\ThreatIntelNetwork;
use WebCareProScanner\Firewall\VirtualPatchSynthesizer;
use WebCareProScanner\Firewall\HtaccessVaultManager;
use WebCareProScanner\Firewall\HtaccessShield;
use WebCareProScanner\Firewall\RedirectCanaryEngine;
use WebCareProScanner\Filesystem\PathValidator;
use WebCareProScanner\Reports\IncidentReportEngine;

if (!defined('ABSPATH')) {
    exit;
}

class ScannerRoutes {
    const NAMESPACE = 'webcare-pro-security/v1';

    public static function register() {
        if (class_exists(RestRouter::class)) {
            RestRouter::register();
        }
    }

    

    

    

    

    

    

    

    /**
     * Shared helper assembling enriched modular rules, component provenance/checksum dossiers,
     * and trust summary telemetry without duplicating logic across status and export routes.
     *
     * @param bool $deep_verify Whether to execute full disk & WP.org checksum verification.
     * @return array
     */
    private static function build_modular_dossier_context(bool $deep_verify = false): array {
        $vault_mgr = '\\WebCareProScanner\\Firewall\\Modular\\BehavioralVaultManager';
        $synth     = '\\WebCareProScanner\\Firewall\\Modular\\ModularFirewallSynthesizer';
        $analyzer  = '\\WebCareProScanner\\Firewall\\Modular\\SiteBehavioralAnalyzer';
        $verifier  = '\\WebCareProScanner\\Firewall\\Modular\\ComponentIntegrityVerifier';

        $vault_summary = class_exists($vault_mgr) ? $vault_mgr::get_vault_summary() : null;
        $rules         = class_exists($synth) ? $synth::get_active_rules() : [];
        $raw_inv       = class_exists($vault_mgr) ? ($vault_mgr::read_shard($vault_mgr::SHARD_INVENTORY) ?: []) : [];

        if (empty($raw_inv) && class_exists($analyzer) && method_exists($analyzer, 'discover_all_components')) {
            $raw_inv = $analyzer::discover_all_components($deep_verify);
        }

        $endpoint_map  = class_exists($vault_mgr) ? ($vault_mgr::read_shard($vault_mgr::SHARD_ENDPOINTS) ?: []) : [];
        $findings      = class_exists($vault_mgr) ? ($vault_mgr::read_shard($vault_mgr::SHARD_FINDINGS) ?: []) : [];
        $scan_progress = class_exists($analyzer) ? $analyzer::get_scan_progress() : null;

        $endpoint_counts = [];
        if (is_array($endpoint_map)) {
            foreach ($endpoint_map as $ep) {
                $comp_name = $ep['component'] ?? '';
                if ($comp_name !== '') {
                    $endpoint_counts[$comp_name] = ($endpoint_counts[$comp_name] ?? 0) + 1;
                }
            }
        }

        $finding_counts = [];
        if (is_array($findings)) {
            foreach ($findings as $fd) {
                $comp_name = $fd['component'] ?? '';
                if ($comp_name !== '') {
                    $finding_counts[$comp_name] = ($finding_counts[$comp_name] ?? 0) + 1;
                }
            }
        }

        $rules_list  = is_array($rules) ? array_values($rules) : [];
        $rule_counts = [];
        foreach ($rules_list as $rl) {
            $comp_name = $rl['origin_component'] ?? ($rl['target_component'] ?? '');
            if ($comp_name !== '' && ($rl['current_mode'] ?? 'off') !== 'off') {
                $rule_counts[$comp_name] = ($rule_counts[$comp_name] ?? 0) + 1;
            }
        }

        $inventory        = [];
        $comp_by_name     = [];
        $trust_summary    = [
            'official_wporg_count'    => 0,
            'known_vendor_count'      => 0,
            'custom_unmanaged_count'  => 0,
            'checksum_verified_count' => 0,
            'tamper_alert_count'      => 0,
            'outdated_count'          => 0,
        ];

        if (is_array($raw_inv)) {
            foreach ($raw_inv as $comp) {
                if (!is_array($comp)) {
                    continue;
                }
                // Always attach/refresh provenance & checksum status when missing or during deep verification
                if (class_exists($verifier) && ($deep_verify || !isset($comp['origin_type']))) {
                    $comp = array_merge($comp, $verifier::verify_component($comp, $deep_verify));
                }

                $name = $comp['name'] ?? ($comp['slug'] ?? '');
                $comp['endpoints_count'] = $endpoint_counts[$name] ?? 0;
                $comp['findings_count']  = $finding_counts[$name] ?? 0;
                $comp['rules_count']     = $rule_counts[$name] ?? 0;

                if (!empty($comp['is_official_wporg'])) {
                    $trust_summary['official_wporg_count']++;
                } elseif (!empty($comp['is_known_vendor'])) {
                    $trust_summary['known_vendor_count']++;
                } else {
                    $trust_summary['custom_unmanaged_count']++;
                }

                if (!empty($comp['checksum_verified'])) {
                    $trust_summary['checksum_verified_count']++;
                }
                if (($comp['trust_tier'] ?? '') === 'tamper_alert') {
                    $trust_summary['tamper_alert_count']++;
                }
                if (!empty($comp['update_available'])) {
                    $trust_summary['outdated_count']++;
                }

                $inventory[] = $comp;
                if ($name !== '') {
                    $comp_by_name[$name] = $comp;
                }
            }
        }

        // Enrich rules that are missing provenance/hash metadata (e.g. from pre-upgrade scans or custom rules)
        $findings_by_file = [];
        if (is_array($findings)) {
            foreach ($findings as $idx => $fd) {
                if (!empty($fd['file'])) {
                    $findings_by_file[$fd['file']] = $fd;
                }
            }
        }

        foreach ($rules_list as &$rl) {
            if (!isset($rl['file_sha256']) || !isset($rl['checksum_status']) || $deep_verify) {
                $matched_finding = !empty($rl['file']) ? ($findings_by_file[$rl['file']] ?? []) : [];
                if (class_exists($synth) && method_exists($synth, 'enrich_synthesized_rule')) {
                    $rl = $synth::enrich_synthesized_rule($rl, $matched_finding, $comp_by_name);
                }
            }
        }
        unset($rl);

        return [
            'vault_summary' => $vault_summary,
            'rules'         => $rules_list,
            'inventory'     => $inventory,
            'comp_by_name'  => $comp_by_name,
            'trust_summary' => $trust_summary,
            'endpoint_map'  => is_array($endpoint_map) ? array_values($endpoint_map) : [],
            'findings'      => is_array($findings) ? array_values($findings) : [],
            'scan_progress' => $scan_progress,
        ];
    }

    /**
     * Build a deduplicated cryptographic hash index for all PHP files referenced by rules and findings.
     */
    private static function build_file_hash_index(array $rules, array $findings): array {
        $verifier = '\\WebCareProScanner\\Firewall\\Modular\\ComponentIntegrityVerifier';
        $index    = [];

        foreach ($findings as $fd) {
            $rel = $fd['file'] ?? '';
            if ($rel === '') {
                continue;
            }
            if (!isset($index[$rel])) {
                $forensics = (!empty($fd['file_sha256']) && !empty($fd['file_md5']))
                    ? [
                        'file_sha256'       => $fd['file_sha256'],
                        'file_md5'          => $fd['file_md5'],
                        'file_size'         => $fd['file_size'] ?? 0,
                        'file_mtime'        => $fd['file_mtime'] ?? null,
                        'checksum_status'   => $fd['checksum_status'] ?? 'unmanaged_custom',
                        'expected_checksum' => $fd['expected_checksum'] ?? null,
                        'known_vendor_lib'  => $fd['known_vendor_lib'] ?? null,
                    ]
                    : (class_exists($verifier) ? $verifier::verify_file_forensics($rel) : []);

                $index[$rel] = array_merge([
                    'file'                => $rel,
                    'component'           => $fd['component'] ?? '',
                    'origin_type'         => $fd['origin_type'] ?? 'custom_unmanaged',
                    'finding_types'       => [],
                    'referenced_by_rules' => [],
                ], $forensics);
            }
            if (!empty($fd['type']) && !in_array($fd['type'], $index[$rel]['finding_types'], true)) {
                $index[$rel]['finding_types'][] = $fd['type'];
            }
        }

        foreach ($rules as $rl) {
            $rel = $rl['file'] ?? '';
            if ($rel === '') {
                continue;
            }
            if (!isset($index[$rel])) {
                $forensics = class_exists($verifier) ? $verifier::verify_file_forensics($rel) : [];
                $index[$rel] = array_merge([
                    'file'                => $rel,
                    'component'           => $rl['origin_component'] ?? '',
                    'origin_type'         => $rl['component_origin_type'] ?? 'custom_unmanaged',
                    'finding_types'       => [],
                    'referenced_by_rules' => [],
                ], $forensics);
            }
            if (!empty($rl['id']) && !in_array($rl['id'], $index[$rel]['referenced_by_rules'], true)) {
                $index[$rel]['referenced_by_rules'][] = $rl['id'];
            }
        }

        return $index;
    }

    /**
     * Collect firewall & pre-boot log correlation telemetry for false-positive analysis.
     * Pseudonymizes client IPs via keyed SHA-256 prefix so exported dossiers stay privacy-safe.
     */
    private static function build_modular_log_analysis_context(): array {
        global $wpdb;

        $salt        = function_exists('wp_salt') ? wp_salt('auth') : 'webcare_log_salt';
        $hash_ip     = static fn(string $ip): string => $ip !== '' ? substr(hash('sha256', $salt . $ip), 0, 12) : '';
        $records     = [];
        $seen_ids    = [];
        $hits_by_rule = [];
        $hits_by_uri  = [];
        $hits_by_act  = [];
        $top_uas      = [];

        $record_event = static function (array $row) use (&$records, &$seen_ids, &$hits_by_rule, &$hits_by_uri, &$hits_by_act, &$top_uas) {
            $dedup_key = ($row['incident_id'] ?? '') . '|' . ($row['created_at'] ?? '') . '|' . ($row['request_uri'] ?? '');
            if (isset($seen_ids[$dedup_key])) {
                return;
            }
            $seen_ids[$dedup_key] = true;
            $records[] = $row;

            $rid = $row['rule_id'] ?: ($row['rule_category'] ?: 'UNKNOWN');
            if (!isset($hits_by_rule[$rid])) {
                $hits_by_rule[$rid] = [
                    'count'          => 0,
                    'last_seen'      => $row['created_at'] ?? '',
                    'sample_uris'    => [],
                    'methods'        => [],
                    'actions'        => [],
                ];
            }
            $hits_by_rule[$rid]['count']++;
            $uri_clean = strtok((string) ($row['request_uri'] ?? '/'), '?') ?: '/';
            if (count($hits_by_rule[$rid]['sample_uris']) < 5 && !in_array($row['request_uri'] ?? '', $hits_by_rule[$rid]['sample_uris'], true)) {
                $hits_by_rule[$rid]['sample_uris'][] = $row['request_uri'] ?? '';
            }
            if (!empty($row['request_method']) && !in_array($row['request_method'], $hits_by_rule[$rid]['methods'], true)) {
                $hits_by_rule[$rid]['methods'][] = $row['request_method'];
            }
            if (!empty($row['action_taken']) && !in_array($row['action_taken'], $hits_by_rule[$rid]['actions'], true)) {
                $hits_by_rule[$rid]['actions'][] = $row['action_taken'];
            }

            $hits_by_uri[$uri_clean] = ($hits_by_uri[$uri_clean] ?? 0) + 1;
            $act = $row['action_taken'] ?? 'unknown';
            $hits_by_act[$act] = ($hits_by_act[$act] ?? 0) + 1;
            if (!empty($row['user_agent'])) {
                $ua = substr((string) $row['user_agent'], 0, 120);
                $top_uas[$ua] = ($top_uas[$ua] ?? 0) + 1;
            }
        };

        // 1. Query JSON WafFileLogger (last 30 days, modular & endpoint-relevant incidents)
        if (class_exists('\\WebCareProScanner\\Firewall\\WafFileLogger')) {
            $json_res = \WebCareProScanner\Firewall\WafFileLogger::query_logs(['range' => '30d'], 150, 0);
            $items    = is_array($json_res['logs'] ?? null) ? $json_res['logs'] : [];
            foreach ($items as $item) {
                $rid   = (string) ($item['rule_id'] ?? '');
                $rcat  = (string) ($item['rule_category'] ?? '');
                $rdesc = (string) ($item['rule_description'] ?? '');
                $ruri  = (string) ($item['request_uri'] ?? '');
                $is_relevant = str_starts_with($rid, 'MOD-')
                    || stripos($rcat, 'modular') !== false
                    || str_contains($rdesc, 'MOD-')
                    || str_contains($ruri, 'admin-ajax.php')
                    || str_contains($ruri, '/wp-json/');

                if ($is_relevant) {
                    $record_event([
                        'source'           => 'waf_file_logger',
                        'incident_id'      => $item['incident_id'] ?? ($item['id'] ?? ''),
                        'ip_hash'          => $hash_ip((string) ($item['ip_address'] ?? '')),
                        'rule_id'          => $rid,
                        'rule_name'        => $item['rule_name'] ?? '',
                        'rule_category'    => $rcat,
                        'rule_description' => $rdesc,
                        'request_method'   => $item['request_method'] ?? 'GET',
                        'request_uri'      => $ruri,
                        'http_status_code' => $item['http_status_code'] ?? 403,
                        'http_referer'     => $item['http_referer'] ?? null,
                        'payload_sample'   => $item['payload_sample'] ?? '',
                        'user_agent'       => $item['user_agent'] ?? '',
                        'action_taken'     => $item['action_taken'] ?? '',
                        'is_authenticated' => !empty($item['is_authenticated']),
                        'user_role'        => $item['user_role'] ?? '',
                        'created_at'       => $item['created_at_gmt'] ?? ($item['created_at'] ?? ''),
                    ]);
                }
            }
        }

        // 2. Query SQL webcareproscan_firewall_logs table for modular & endpoint events
        $firewall_logs_table = $wpdb->prefix . 'webcareproscan_firewall_logs';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $table_exists = $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($firewall_logs_table)));
        if ($table_exists === $firewall_logs_table) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $rows = $wpdb->get_results(
                $wpdb->prepare(
                    'SELECT id, incident_id, ip_address, request_uri, request_method, http_status_code, http_referer, rule_category, rule_description, payload_sample, user_agent, action_taken, created_at
                     FROM %i
                     WHERE rule_category = %s OR rule_description LIKE %s OR request_uri LIKE %s OR request_uri LIKE %s
                     ORDER BY id DESC
                     LIMIT 100',
                    $firewall_logs_table,
                    'Modular Behavioral WAF',
                    '%MOD-%',
                    '%admin-ajax.php%',
                    '%/wp-json/%'
                ),
                ARRAY_A
            );
            if (is_array($rows)) {
                foreach ($rows as $r) {
                    $extracted_id = '';
                    if (preg_match('/\[(MOD-[A-Z0-9-]+)\]/', (string) ($r['rule_description'] ?? ''), $m)) {
                        $extracted_id = $m[1];
                    }
                    $record_event([
                        'source'           => 'sql_firewall_logs',
                        'incident_id'      => $r['incident_id'] ?? ('sql_' . $r['id']),
                        'ip_hash'          => $hash_ip((string) ($r['ip_address'] ?? '')),
                        'rule_id'          => $extracted_id,
                        'rule_name'        => '',
                        'rule_category'    => $r['rule_category'] ?? '',
                        'rule_description' => $r['rule_description'] ?? '',
                        'request_method'   => $r['request_method'] ?? 'GET',
                        'request_uri'      => $r['request_uri'] ?? '',
                        'http_status_code' => intval($r['http_status_code'] ?? 403),
                        'http_referer'     => $r['http_referer'] ?? null,
                        'payload_sample'   => $r['payload_sample'] ?? '',
                        'user_agent'       => $r['user_agent'] ?? '',
                        'action_taken'     => $r['action_taken'] ?? '',
                        'is_authenticated' => false,
                        'user_role'        => '',
                        'created_at'       => $r['created_at'] ?? '',
                    ]);
                }
            }
        }

        // 3. Parse Pre-Boot Micro-WAF Fail2ban log tail for MOD-* events (masking raw IPs)
        $preboot_mod_lines = [];
        if (class_exists('\\WebCareProScanner\\Firewall\\MicroWafCompiler')) {
            $f2b_path = \WebCareProScanner\Firewall\MicroWafCompiler::get_fail2ban_log_path();
            if ($f2b_path && file_exists($f2b_path) && is_readable($f2b_path)) {
                $lines = @file($f2b_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                if (is_array($lines)) {
                    $tail = array_slice($lines, -200);
                    foreach (array_reverse($tail) as $line) {
                        if (str_contains($line, 'MOD-')) {
                            $masked = preg_replace_callback('/\b(?:\d{1,3}\.){3}\d{1,3}\b|[0-9a-fA-F:]{6,39}/', static function ($m) use ($hash_ip) {
                                return 'iphash:' . $hash_ip($m[0]);
                            }, $line);
                            $preboot_mod_lines[] = $masked;
                            if (count($preboot_mod_lines) >= 50) {
                                break;
                            }
                        }
                    }
                }
            }
        }

        arsort($hits_by_uri);
        arsort($top_uas);

        return [
            'total_events_analyzed' => count($records),
            'hits_by_rule'          => $hits_by_rule,
            'hits_by_action'        => $hits_by_act,
            'top_target_uris'       => array_slice($hits_by_uri, 0, 30, true),
            'top_user_agents'       => array_slice($top_uas, 0, 15, true),
            'preboot_fail2ban_lines'=> $preboot_mod_lines,
            'recent_log_records'    => array_slice($records, 0, 200),
        ];
    }

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    


    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    /**
     * Enrich findings with real-time WordPress post/page URLs, edit links, and file metadata.
     *
     * @param array $issues
     * @return array
     */
    public static function enrich_issues(array $issues) {
        $norm_abspath = wp_normalize_path(ABSPATH);

        foreach ($issues as &$item) {
            $filePath = $item['file_path'] ?? '';
            $engine = $item['engine'] ?? '';
            $type = $item['type'] ?? '';

            // 0. Check if finding is WordPress Updates / CVE Advisory
            if ($engine === 'wordpress-updates' || in_array($type, ['outdated_core', 'vulnerable_core', 'outdated_plugin', 'vulnerable_plugin', 'outdated_theme', 'vulnerable_theme'])) {
                $item['is_software_update'] = true;
                $evidence = $item['evidence'] ?? '';
                if (!empty($evidence) && is_string($evidence)) {
                    $decoded = json_decode($evidence, true);
                    if (json_last_error() === JSON_ERROR_NONE && is_array($decoded)) {
                        $item['cves'] = $decoded['cves'] ?? [];
                        $item['has_cve'] = !empty($decoded['has_cve']);
                        $item['is_outdated'] = !empty($decoded['is_outdated']);
                        $item['installed_version'] = $decoded['installed'] ?? '';
                        $item['latest_version'] = $decoded['latest'] ?? '';
                        $item['component_name'] = $decoded['name'] ?? '';
                        $item['component_type'] = $decoded['type'] ?? '';
                    }
                }
            }

            // 0b. Check if finding is Theme Checksums Unavailable (Custom / Child / Premium Theme)
            if ($type === 'theme_checksums_unavailable' || ($engine === 'integrity-theme' && (strpos($filePath, '/themes/') !== false || strpos($filePath, '\\themes\\') !== false) && !preg_match('/\.[a-zA-Z0-9]{2,5}$/', $filePath))) {
                $item['is_dir'] = true;
                $item['is_file'] = false;
                $item['can_view'] = false;
                $item['component_type'] = 'theme';

                $evidence_data = !empty($item['evidence']) && is_string($item['evidence']) ? json_decode($item['evidence'], true) : [];
                $path_lower = strtolower($filePath);
                $desc_lower = strtolower($item['description'] ?? '');

                $is_child = !empty($evidence_data['is_child']) || strpos($path_lower, '-child') !== false || strpos($desc_lower, 'child') !== false;
                $is_premium = !empty($evidence_data['is_premium']) || (bool) preg_match('/\b(premium|pro|commercial|license|themeforest|envato)\b/i', $filePath . ' ' . $desc_lower);

                if (!empty($evidence_data['display_title'])) {
                    $item['display_title'] = $evidence_data['display_title'];
                } elseif ($is_child) {
                    $item['display_title'] = __('Custom Child Theme', 'webcare-pro-security');
                } elseif ($is_premium) {
                    $item['display_title'] = __('Premium Theme', 'webcare-pro-security');
                } else {
                    $item['display_title'] = __('Custom or Premium Theme', 'webcare-pro-security');
                }

                $meta = self::get_theme_forensics_meta($filePath, is_array($evidence_data) ? $evidence_data : []);
                $item['component_meta'] = $meta;
                $item['component_name'] = $meta['name'];
                $item['installed_version'] = $meta['version'];
                $item['latest_version'] = $meta['latest_version'];
                $item['has_update'] = $meta['has_update'];
                $item['author_name'] = $meta['author'];
                $item['author_url'] = $meta['author_uri'];
                $item['component_status'] = $meta['status_label'];
                $item['last_updated'] = $meta['last_modified'];
                $item['has_changelog'] = $meta['has_changelog'];
            }
            // 0c. Check if finding is Plugin Checksums Unavailable (Custom or Premium Plugin)
            elseif ($type === 'plugin_checksums_unavailable' || ($engine === 'integrity-plugin' && (strpos($filePath, '/plugins/') !== false || strpos($filePath, '\\plugins\\') !== false) && !preg_match('/\.[a-zA-Z0-9]{2,5}$/', $filePath))) {
                $item['is_dir'] = true;
                $item['is_file'] = false;
                $item['can_view'] = false;
                $item['component_type'] = 'plugin';

                $evidence_data = !empty($item['evidence']) && is_string($item['evidence']) ? json_decode($item['evidence'], true) : [];
                $path_lower = strtolower($filePath);
                $desc_lower = strtolower($item['description'] ?? '');

                $is_premium = !empty($evidence_data['is_premium']) || (bool) preg_match('/(?:^|[-_])(premium|pro|addon|addons|unlimited|commercial)(?:[-_]|$)/i', $filePath) || (bool) preg_match('/\b(premium|pro|yith|woocommerce)\b/i', $desc_lower);

                if (!empty($evidence_data['display_title'])) {
                    $item['display_title'] = $evidence_data['display_title'];
                } elseif ($is_premium) {
                    $item['display_title'] = __('Premium Plugin', 'webcare-pro-security');
                } else {
                    $item['display_title'] = __('Custom or Premium Plugin', 'webcare-pro-security');
                }

                $meta = self::get_plugin_forensics_meta($filePath, is_array($evidence_data) ? $evidence_data : []);
                $item['component_meta'] = $meta;
                $item['component_name'] = $meta['name'];
                $item['installed_version'] = $meta['version'];
                $item['latest_version'] = $meta['latest_version'];
                $item['has_update'] = $meta['has_update'];
                $item['author_name'] = $meta['author'];
                $item['author_url'] = $meta['author_uri'];
                $item['component_status'] = $meta['status_label'];
                $item['last_updated'] = $meta['last_modified'];
                $item['has_changelog'] = $meta['has_changelog'];
            }

            // 1. Check if finding is a WordPress Post or Page
            if (preg_match('/^post:(\d+)/i', $filePath, $matches)) {
                $postId = (int) $matches[1];
                $post = get_post($postId);
                if ($post) {
                    $item['is_post'] = true;
                    $item['post_id'] = $postId;
                    $item['post_title'] = $post->post_title ?: __('(Untitled)', 'webcare-pro-security');
                    $item['post_type'] = $post->post_type;
                    $item['view_url'] = get_permalink($postId) ?: '';
                    $item['edit_url'] = get_edit_post_link($postId, 'raw') ?: admin_url("post.php?post={$postId}&action=edit");
                }
            } 
            // 2. Check if finding is a WordPress Comment
            elseif (preg_match('/comment[:_#]?\s*(\d+)/i', $filePath, $matches) || $engine === 'content-comments' || strpos($filePath, 'comment:') === 0) {
                $commentId = !empty($matches[1]) ? (int) $matches[1] : 0;
                $comment = $commentId > 0 ? get_comment($commentId) : null;
                $item['is_comment'] = true;
                $item['is_file'] = false;
                $item['is_dir'] = false;
                $item['can_view'] = false;
                $item['comment_id'] = $commentId;

                if ($comment) {
                    $item['author_id'] = (int) $comment->user_id;
                    $item['author_name'] = $comment->comment_author ?: __('(Anonymous)', 'webcare-pro-security');
                    $item['author_email'] = $comment->comment_author_email ?: '';
                    $item['author_url'] = $comment->comment_author_url ?: '';
                    $item['author_ip'] = $comment->comment_author_IP ?: '';
                    $item['comment_date'] = $comment->comment_date ?: '';
                    $item['comment_content'] = $comment->comment_content ?: '';
                    if (empty($item['code_snippet'])) {
                        $item['code_snippet'] = $comment->comment_content ?: '';
                    }
                    $postId = (int) $comment->comment_post_ID;
                    $item['post_id'] = $postId;
                    $item['post_title'] = $postId > 0 ? (get_the_title($postId) ?: __('(Untitled Post)', 'webcare-pro-security')) : '';
                    $item['post_url'] = $postId > 0 ? (get_permalink($postId) ?: '') : '';
                    $item['view_url'] = get_comment_link($comment) ?: '';
                    $item['edit_url'] = admin_url("comment.php?action=editcomment&c={$commentId}");
                } else {
                    $item['author_id'] = 0;
                    $item['author_name'] = preg_match('/by\s+(.+)$/i', $filePath, $am) ? trim($am[1]) : __('Unknown Author', 'webcare-pro-security');
                    $item['author_email'] = '';
                    $item['author_url'] = '';
                    $item['author_ip'] = '';
                    $item['comment_date'] = '';
                    $item['comment_content'] = $item['code_snippet'] ?? '';
                    $item['post_id'] = 0;
                    $item['post_title'] = '';
                    $item['post_url'] = '';
                    $item['view_url'] = '';
                    $item['edit_url'] = $commentId > 0 ? admin_url("comment.php?action=editcomment&c={$commentId}") : '';
                }
            } 
            // 3. Check if finding is a WordPress User Account
            elseif (
                preg_match('/(?:^user:|_users:user_id_|users\.ID\s*=\s*)(\d+)/i', $filePath, $userMatches) ||
                preg_match('/User ID:\s*(\d+)/i', $item['evidence'] ?? '', $userMatches) ||
                $engine === 'wordpress-users' ||
                strpos($filePath, 'user:') === 0 ||
                strpos($filePath, '_users:user_id_') !== false ||
                strpos($type, 'user_') === 0 ||
                in_array($type, ['rogue_admin_user', 'hidden_admin_user', 'elevated_privilege_user', 'suspicious_user_capabilities', 'tampered_role_definition', 'generic_admin_username', 'weak_password_detected', 'username_enumeration_risk', 'user_missing_capabilities'], true)
            ) {
                $userId = 0;
                if (!empty($userMatches[1])) {
                    $userId = (int) $userMatches[1];
                } elseif (preg_match('/(?:^user:|^author:|_users:user_id_|users\.ID\s*=\s*)(\d+)/i', $filePath, $m)) {
                    $userId = (int) $m[1];
                } elseif (preg_match('/(?:User|Author)\s*ID:\s*(\d+)/i', $item['evidence'] ?? '', $m)) {
                    $userId = (int) $m[1];
                } elseif (preg_match('/author\s*user\s*ID\s*\((\d+)\)/i', $item['description'] ?? '', $m)) {
                    $userId = (int) $m[1];
                }

                $user = $userId > 0 ? get_userdata($userId) : null;
                $item['is_user'] = true;
                $item['is_file'] = false;
                $item['is_dir'] = false;
                $item['can_view'] = false;
                $item['user_id'] = $userId;
                $item['user_login'] = $user ? $user->user_login : (preg_match('/\(([^)]+)\)/', $filePath, $m) ? $m[1] : (preg_match('/User\s*\'([^\']+)\'/i', $item['description'] ?? '', $m) ? $m[1] : 'user'));
                $item['user_email'] = $user ? $user->user_email : (preg_match('/Email:\s*([^,\s]+)/i', $item['evidence'] ?? '', $m) ? $m[1] : '');
                $item['user_registered'] = $user ? $user->user_registered : (preg_match('/Registered:\s*([^,\n]+)/i', $item['evidence'] ?? '', $m) ? trim($m[1]) : '');
                $item['user_display_name'] = $user ? $user->display_name : $item['user_login'];
                $item['user_nicename'] = $user ? $user->user_nicename : '';
                $item['first_name'] = $user ? $user->first_name : '';
                $item['last_name'] = $user ? $user->last_name : '';
                
                // User Roles extraction
                $user_roles = $user && !empty($user->roles) ? array_values((array) $user->roles) : [];
                $item['user_roles_list'] = $user_roles;
                $item['user_roles'] = !empty($user_roles) ? implode(', ', $user_roles) : ($item['user_roles'] ?? 'none');

                $current_user_id = function_exists('get_current_user_id') ? get_current_user_id() : 0;
                $is_current_user = ($userId > 0 && $userId === $current_user_id);
                $is_admin = ($user && in_array('administrator', $user_roles, true));

                $item['is_current_user'] = $is_current_user;
                $item['is_admin'] = $is_admin;
                $item['profile_url'] = $is_current_user ? admin_url('profile.php') : ($userId > 0 ? admin_url("user-edit.php?user_id={$userId}") : admin_url('users.php'));
                $item['password_url'] = $is_current_user ? admin_url('profile.php#password') : ($userId > 0 ? admin_url("user-edit.php?user_id={$userId}#password") : admin_url('users.php'));
                $item['edit_url'] = $userId > 0 ? admin_url("user-edit.php?user_id={$userId}") : admin_url("users.php");

                // Injected custom capabilities & complete capabilities matrix
                if ($userId > 0) {
                    global $wpdb;
                    $cap_key = $wpdb->prefix . 'capabilities';
                    $stored_caps = get_user_meta($userId, $cap_key, true);
                    $wp_roles = wp_roles();
                    $injected_caps = [];
                    if (is_array($stored_caps)) {
                        foreach ($stored_caps as $cap_name => $granted) {
                            if (!isset($wp_roles->roles[$cap_name])) {
                                $injected_caps[] = $cap_name;
                            }
                        }
                    }
                    $item['injected_caps'] = $injected_caps;

                    // Comprehensive Developer & Permissions Forensics
                    if ($user) {
                        $allcaps = !empty($user->allcaps) && is_array($user->allcaps) ? $user->allcaps : [];
                        $active_caps = array_keys(array_filter($allcaps));
                        sort($active_caps);
                        $item['all_capabilities'] = $active_caps;
                        $item['capabilities_count'] = count($active_caps);

                        // User Level
                        $user_level = get_user_meta($userId, $wpdb->prefix . 'user_level', true);
                        $item['user_level'] = $user_level !== '' ? (int) $user_level : 0;

                        // Authored Posts Count across published, drafts, pending
                        if (function_exists('count_user_posts')) {
                            $item['authored_posts_count'] = (int) count_user_posts($userId, 'post', true);
                        }

                        // Password hash algorithm preview (safe hint without disclosing hash)
                        if (!empty($user->user_pass)) {
                            $pass_str = (string) $user->user_pass;
                            if (strpos($pass_str, '$P$') === 0) {
                                $item['hash_type'] = 'WordPress phpass ($P$)';
                            } elseif (strpos($pass_str, '$2y$') === 0 || strpos($pass_str, '$2a$') === 0) {
                                $item['hash_type'] = 'Bcrypt ($2y$)';
                            } elseif (strpos($pass_str, '$argon2i$') === 0 || strpos($pass_str, '$argon2id$') === 0) {
                                $item['hash_type'] = 'Argon2';
                            } elseif (strlen($pass_str) === 32 && ctype_xdigit($pass_str)) {
                                $item['hash_type'] = 'Insecure Legacy MD5 (32-char hex)';
                            } else {
                                $item['hash_type'] = 'Standard Hash';
                            }
                        }

                        // Two Factor & Application Passwords detection
                        $app_passwords = get_user_meta($userId, '_application_passwords', true);
                        $item['has_application_passwords'] = is_array($app_passwords) && !empty($app_passwords);
                        $item['application_passwords_count'] = is_array($app_passwords) ? count($app_passwords) : 0;

                        $has_two_factor = get_user_meta($userId, '_two_factor_enabled', true) 
                            || get_user_meta($userId, 'two_factor_provider', true)
                            || get_user_meta($userId, 'wfls-2fa-enabled', true);
                        $item['two_factor_enabled'] = (bool) $has_two_factor;
                    }
                }

                // Specialized handling for Orphaned Post Author
                if ($type === 'orphaned_post_author' || strpos($filePath, 'author:') === 0) {
                    $item['is_orphaned_author'] = true;
                    $item['user_login'] = "Missing User #{$userId}";
                    $item['user_display_name'] = "Missing User #{$userId}";
                    $item['user_roles'] = 'MISSING (Deleted Account)';
                    $item['edit_url'] = ''; // Cannot edit non-existent user profile
                    $item['profile_url'] = '';

                    // Parse evidence or query sample post details
                    $sampleId = 0;
                    $metaJson = null;
                    if (!empty($item['evidence']) && preg_match('/Meta:\s*(\{.*\})/i', $item['evidence'], $mJson)) {
                        $metaJson = json_decode($mJson[1], true);
                    }
                    if ($metaJson && !empty($metaJson['sample_id'])) {
                        $sampleId = (int) $metaJson['sample_id'];
                        $item['orphaned_meta'] = $metaJson;
                    } elseif (!empty($item['description']) && preg_match('/Sample:\s*Post\s*#(\d+)/i', $item['description'], $sm)) {
                        $sampleId = (int) $sm[1];
                    }

                    if ($sampleId > 0) {
                        $samplePost = get_post($sampleId);
                        if ($samplePost) {
                            $item['sample_post_id'] = $sampleId;
                            $item['sample_post_title'] = !empty($samplePost->post_title) ? $samplePost->post_title : __('(Untitled Post)', 'webcare-pro-security');
                            $item['sample_post_slug'] = !empty($samplePost->post_name) ? $samplePost->post_name : '';
                            $item['sample_post_type'] = $samplePost->post_type;
                            $item['sample_post_status'] = $samplePost->post_status;
                            $item['sample_post_date'] = $samplePost->post_date;
                            $permalink = get_permalink($sampleId);
                            $item['sample_view_url'] = $permalink ?: '';
                            $editUrl = get_edit_post_link($sampleId, 'raw');
                            $item['sample_edit_url'] = $editUrl ?: admin_url("post.php?post={$sampleId}&action=edit");
                        }
                    }

                    // Provide current admin info and all active administrator choices for reassignment
                    $currId = function_exists('get_current_user_id') ? get_current_user_id() : 0;
                    $currUser = $currId > 0 ? get_userdata($currId) : null;
                    $item['reassign_target_id'] = $currId;
                    $item['reassign_target_name'] = $currUser ? ($currUser->display_name ?: $currUser->user_login) : 'Administrator';

                    $admin_users_raw = get_users([
                        'role'    => 'administrator',
                        'orderby' => 'display_name',
                        'order'   => 'ASC',
                        'fields'  => ['ID', 'user_login', 'display_name', 'user_email'],
                    ]);
                    $admin_options = [];
                    foreach ($admin_users_raw as $adm) {
                        $admin_options[] = [
                            'id'           => (int) $adm->ID,
                            'user_login'   => $adm->user_login,
                            'display_name' => $adm->display_name ?: $adm->user_login,
                            'user_email'   => $adm->user_email,
                            'is_current'   => ((int) $adm->ID === $currId),
                        ];
                    }
                    $item['admin_options'] = $admin_options;
                }
            } 
            // 4. Check if finding is a Database Table Row
            elseif ($engine === 'database-table' || preg_match('/^([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+)(?:\s*\[ID:\s*(\d+)\])?/i', $filePath)) {
                $tableName = '';
                $columnName = '';
                $rowId = null;

                if (preg_match('/^([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+)(?:\s*\[ID:\s*(\d+)\])?/i', $filePath, $dbMatches)) {
                    $tableName = !empty($dbMatches[1]) ? $dbMatches[1] : '';
                    $columnName = !empty($dbMatches[2]) ? $dbMatches[2] : '';
                    $rowId = !empty($dbMatches[3]) ? (int) $dbMatches[3] : null;
                }
                if (!$rowId && preg_match('/\[ID:\s*(\d+)\]/i', $filePath, $idM)) {
                    $rowId = (int) $idM[1];
                }
                if (!$tableName && strpos($filePath, '.') !== false) {
                    $tableName = explode('.', $filePath)[0];
                }
                if (!$columnName && strpos($filePath, '.') !== false) {
                    $parts = explode('.', $filePath);
                    $columnName = explode(' ', $parts[1])[0];
                }

                $item['is_db_table'] = true;
                $item['is_file'] = false;
                $item['is_dir'] = false;
                $item['can_view'] = false;
                $item['table_name'] = $tableName;
                $item['column_name'] = $columnName;
                $item['row_id'] = $rowId;
                $item['is_log_table'] = (bool) preg_match('/(log|logs|redirection|audit|history|stat|stats|traffic|404)/i', $tableName);

                // Pre-load full row data if available
                if ($tableName && $rowId) {
                    $mgr = new \WebCareProScanner\Database\DatabaseRemediationManager();
                    $dbRow = $mgr->get_row($tableName, $rowId);
                    if ($dbRow) {
                        $item['db_row'] = $dbRow;
                        $item['db_primary_key'] = $mgr->get_primary_key($tableName);
                        if (empty($item['code_snippet']) && isset($dbRow[$columnName])) {
                            $item['code_snippet'] = (string) $dbRow[$columnName];
                        }
                    }

                    // Check if table is WordPress Posts table
                    if (preg_match('/(?:^|_)posts$/i', $tableName)) {
                        $post = get_post($rowId);
                        if ($post) {
                            $item['is_post'] = true;
                            $item['post_id'] = (int) $rowId;
                            $item['post_title'] = !empty($post->post_title) ? $post->post_title : __('(Untitled Post)', 'webcare-pro-security');
                            $item['post_slug'] = !empty($post->post_name) ? $post->post_name : '';
                            $item['post_status'] = !empty($post->post_status) ? $post->post_status : 'publish';
                            $item['post_type'] = !empty($post->post_type) ? $post->post_type : 'post';
                            $item['post_date'] = !empty($post->post_date) ? $post->post_date : '';
                            $item['post_modified'] = !empty($post->post_modified) ? $post->post_modified : '';
                            $item['post_author'] = (int) $post->post_author;
                            $authorData = get_userdata($post->post_author);
                            $item['post_author_name'] = $authorData ? $authorData->display_name : '';
                            $permalink = get_permalink($rowId);
                            $item['post_url'] = $permalink ? $permalink : '';
                            $editUrl = get_edit_post_link($rowId, 'raw');
                            $item['edit_url'] = $editUrl ? $editUrl : admin_url("post.php?post={$rowId}&action=edit");
                        }
                    }
                }
            }
            // 4b. Check if finding is a Server/Network Configuration entity (e.g. reverse proxy, IP detection, network headers)
            elseif (
                $engine === 'ip-detection' ||
                $engine === 'waf-status' ||
                $type === 'reverse_proxy_misconfigured' ||
                strpos($filePath, 'server:') === 0
            ) {
                $item['is_server_config'] = true;
                $item['is_network'] = true;
                $item['is_file'] = false;
                $item['is_dir'] = false;
                $item['can_view'] = false;
                $item['file_exists'] = false;

                // Environment reconciliation: If running on local development or Docker container, reconcile open false-positives
                $env_type = function_exists('wp_get_environment_type') ? wp_get_environment_type() : (defined('WP_ENVIRONMENT_TYPE') ? WP_ENVIRONMENT_TYPE : 'production');
                $is_local_env = in_array($env_type, ['local', 'development'], true);
                $site_url = get_site_url();
                $host = wp_parse_url($site_url, PHP_URL_HOST) ?: '';
                $is_local_host = in_array($host, ['localhost', '127.0.0.1', '::1'], true)
                    || (bool) preg_match('/\.(local|test|site|internal|lan|docker|localwp|ddev)$/i', $host);
                $is_docker = file_exists('/.dockerenv')
                    || (file_exists('/proc/1/cgroup') && strpos(@file_get_contents('/proc/1/cgroup'), 'docker') !== false);

                if (($is_local_env || $is_local_host || $is_docker) && ($item['status'] ?? 'open') === 'open') {
                    $item['status'] = 'ignored';
                    $item['is_whitelisted'] = false;
                    $item['ignore_reason'] = 'Local development / Docker container environment (internal IP is normal).';
                }
            }
            // 5. Otherwise treat as a Filesystem finding
            else {
                $cleanPath = ltrim(str_replace(['../', '..\\'], '', $filePath), '/\\');
                $fullPath = wp_normalize_path(ABSPATH . $cleanPath);

                if (!file_exists($fullPath) && file_exists($filePath)) {
                    $fullPath = wp_normalize_path($filePath);
                }

                $realPath = realpath($fullPath);
                $wpRoots = \WebCareProScanner\Filesystem\PathValidator::get_wordpress_roots();
                $isParentWpConfig = (realpath(dirname(ABSPATH) . '/wp-config.php') && $realPath === realpath(dirname(ABSPATH) . '/wp-config.php'));
                $isInsideRoot = $realPath && (\WebCareProScanner\Filesystem\PathValidator::is_inside_any_root($realPath, $wpRoots) || $isParentWpConfig);

                $item['file_exists'] = $isInsideRoot && file_exists($realPath);
                if (!isset($item['is_dir'])) {
                    $item['is_dir'] = $item['file_exists'] && is_dir($realPath);
                }
                if (!isset($item['is_file'])) {
                    $item['is_file'] = $item['file_exists'] && is_file($realPath);
                }
                // Only allow viewing if it is a regular readable file (not a folder/directory)
                if (!isset($item['can_view'])) {
                    $item['can_view'] = !empty($item['is_file']) && is_readable($realPath);
                }

                // Real-Time Integrity Reconciliation: If finding was recorded as modified but local file is now restored/clean
                if (!empty($item['is_file']) && ($item['status'] ?? 'open') === 'open' && in_array($item['type'] ?? '', ['modified_core_file', 'modified_plugin_file', 'modified_theme_file'], true)) {
                    if (preg_match('/Expected:\s*([a-f0-9]{32})/i', $item['evidence'] ?? '', $em)) {
                        $expected_hash = strtolower($em[1]);
                        $current_hash = md5_file($realPath);
                        $is_now_clean = ($current_hash === $expected_hash);
                        if (!$is_now_clean) {
                            $raw_content = @file_get_contents($realPath);
                            if ($raw_content !== false && md5(str_replace("\r\n", "\n", $raw_content)) === $expected_hash) {
                                $is_now_clean = true;
                            }
                        }
                        if ($is_now_clean) {
                            $item['status'] = 'repaired';
                            $item['is_repaired'] = true;
                            $item['auto_reconciled'] = true;
                            // Persist repaired state to database so it stays solved
                            if (!empty($item['id'])) {
                                global $wpdb;
                                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                                $wpdb->update($wpdb->prefix . 'webcareproscan_scan_issues', ['status' => 'repaired'], ['id' => (int) $item['id']]);
                            }
                        }
                    }
                }

                // Attach deep filesystem forensics for developers and site owners
                if ($item['file_exists'] && $realPath) {
                    $mtime = @filemtime($realPath);
                    $ctime = @filectime($realPath);
                    $atime = @fileatime($realPath);
                    $fsize = @filesize($realPath);
                    $raw_perms = @fileperms($realPath);
                    $current_perms = $raw_perms !== false ? substr(sprintf('%o', $raw_perms), -4) : '0755';
                    $is_dir = is_dir($realPath);
                    $file_basename = strtolower(basename($realPath));
                    $is_wp_config = ($file_basename === 'wp-config.php');
                    $recommended_perms = $is_wp_config ? '0600' : ($is_dir ? '0755' : '0644');
                    $recommended_symbolic = $is_wp_config ? '-rw-------' : ($is_dir ? 'drwxr-xr-x' : '-rw-r--r--');

                    // Convert raw permissions to standard symbolic notation (e.g. -rw-r--r-- or -rwxrwxrwx)
                    $symbolic = '';
                    if ($raw_perms !== false) {
                        if ($is_dir) {
                            $symbolic .= 'd';
                        } elseif (is_link($realPath)) {
                            $symbolic .= 'l';
                        } else {
                            $symbolic .= '-';
                        }
                        $symbolic .= (($raw_perms & 0x0100) ? 'r' : '-');
                        $symbolic .= (($raw_perms & 0x0080) ? 'w' : '-');
                        $symbolic .= (($raw_perms & 0x0040) ? (($raw_perms & 0x0800) ? 's' : 'x') : (($raw_perms & 0x0800) ? 'S' : '-'));
                        $symbolic .= (($raw_perms & 0x0020) ? 'r' : '-');
                        $symbolic .= (($raw_perms & 0x0010) ? 'w' : '-');
                        $symbolic .= (($raw_perms & 0x0008) ? (($raw_perms & 0x0400) ? 's' : 'x') : (($raw_perms & 0x0400) ? 'S' : '-'));
                        $symbolic .= (($raw_perms & 0x0004) ? 'r' : '-');
                        $symbolic .= (($raw_perms & 0x0002) ? 'w' : '-');
                        $symbolic .= (($raw_perms & 0x0001) ? (($raw_perms & 0x0200) ? 't' : 'x') : (($raw_perms & 0x0200) ? 'T' : '-'));
                    }

                    // Owner and Group
                    $owner_uid = @fileowner($realPath);
                    $owner_name = ($owner_uid !== false && function_exists('posix_getpwuid')) ? (posix_getpwuid($owner_uid)['name'] ?? $owner_uid) : ($owner_uid !== false ? (string) $owner_uid : 'Unknown');
                    $group_gid = @filegroup($realPath);
                    $group_name = ($group_gid !== false && function_exists('posix_getgrgid')) ? (posix_getgrgid($group_gid)['name'] ?? $group_gid) : ($group_gid !== false ? (string) $group_gid : 'Unknown');

                    $parent_dir = dirname($realPath);
                    $parent_perms = file_exists($parent_dir) ? substr(sprintf('%o', fileperms($parent_dir)), -4) : '0755';
                    $now = current_time('timestamp', 1);

                    $sha256 = !$is_dir && $fsize <= 10485760 ? (hash_file('sha256', $realPath) ?: '') : '';
                    if ($sha256) {
                        $item['sha256'] = $sha256;
                        $item['file_sha256'] = $sha256;
                    }

                    $item['fs_forensics'] = [
                        'file_size'             => $fsize !== false ? $fsize : 0,
                        'file_size_formatted'   => $fsize !== false ? size_format($fsize) : '0 B',
                        'sha256'                => $sha256,
                        'created_time'          => $ctime ? gmdate('Y-m-d H:i:s', $ctime) . ' UTC' : null,
                        'created_time_human'    => $ctime ? human_time_diff($ctime, $now) . ' ago' : 'Unknown',
                        'modified_time'         => $mtime ? gmdate('Y-m-d H:i:s', $mtime) . ' UTC' : null,
                        'modified_time_human'   => $mtime ? human_time_diff($mtime, $now) . ' ago' : 'Unknown',
                        'accessed_time'         => $atime ? gmdate('Y-m-d H:i:s', $atime) . ' UTC' : null,
                        'accessed_time_human'   => $atime ? human_time_diff($atime, $now) . ' ago' : 'Unknown',
                        'current_permissions'   => $current_perms,
                        'symbolic_permissions'  => $symbolic ?: ($is_dir ? 'drwxr-xr-x' : '-rw-r--r--'),
                        'recommended_perms'     => $recommended_perms,
                        'recommended_symbolic'  => $recommended_symbolic,
                        'is_dir'                => $is_dir,
                        'is_writable'           => wp_is_writable($realPath),
                        'is_readable'           => is_readable($realPath),
                        'is_executable'         => is_executable($realPath),
                        'owner'                 => $owner_name,
                        'owner_uid'             => $owner_uid !== false ? $owner_uid : null,
                        'group'                 => $group_name,
                        'group_gid'             => $group_gid !== false ? $group_gid : null,
                        'parent_dir'            => $parent_dir,
                        'parent_perms'          => $parent_perms,
                        'file_extension'        => strtolower(pathinfo($realPath, PATHINFO_EXTENSION)),
                        'mime_type'             => function_exists('mime_content_type') ? @mime_content_type($realPath) : null,
                        'is_safe_directory_index' => in_array(strtolower(basename($realPath)), ['index.php', 'index.html', 'index.htm'], true) && \WebCareProScanner\System\SettingsManager::is_safe_directory_index($realPath),
                    ];

                    // Real-Time Directory Protection Index Reconciliation: If executable_in_uploads finding but file is a benign silence/protection index or legitimate plugin cache file
                    if (($item['type'] ?? '') === 'executable_in_uploads' && ($item['status'] ?? 'open') === 'open') {
                        $file_basename = strtolower(basename($realPath));
                        if (in_array($file_basename, ['index.php', 'index.html', 'index.htm'], true) && \WebCareProScanner\System\SettingsManager::is_safe_directory_index($realPath)) {
                            $item['status'] = 'repaired';
                            $item['is_repaired'] = true;
                            $item['auto_reconciled'] = true;
                            $item['reconciliation_reason'] = __('Benign directory listing protection index file (Silence is Golden / Directory Browsing Prevention).', 'webcare-pro-security');
                            if (!empty($item['id'])) {
                                global $wpdb;
                                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                                $wpdb->update($wpdb->prefix . 'webcareproscan_scan_issues', ['status' => 'repaired'], ['id' => (int) $item['id']]);
                            }
                        } elseif (\WebCareProScanner\System\SettingsManager::is_legitimate_uploads_cache_file($realPath)) {
                            $item['status'] = 'repaired';
                            $item['is_repaired'] = true;
                            $item['auto_reconciled'] = true;
                            $item['reconciliation_reason'] = __('Benign plugin compiled cache file (e.g. MailPoet Twig template cache) verified free of malware/webshells.', 'webcare-pro-security');
                            if (!empty($item['id'])) {
                                global $wpdb;
                                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                                $wpdb->update($wpdb->prefix . 'webcareproscan_scan_issues', ['status' => 'repaired'], ['id' => (int) $item['id']]);
                            }
                        }
                    }

                    // Real-Time Permission Reconciliation: If unsafe_permissions finding but file on disk is already hardened (not 0777 or 0666)
                    if (($item['type'] ?? '') === 'unsafe_permissions' && ($item['status'] ?? 'open') === 'open') {
                        if (!in_array($current_perms, ['0777', '0666', '0776', '0667'], true)) {
                            $item['status'] = 'repaired';
                            $item['is_repaired'] = true;
                            $item['auto_reconciled'] = true;
                            if (!empty($item['id'])) {
                                global $wpdb;
                                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                                $wpdb->update($wpdb->prefix . 'webcareproscan_scan_issues', ['status' => 'repaired'], ['id' => (int) $item['id']]);
                            }
                        }
                    }
                }
            }

            // Attach component forensics for any theme or plugin finding if not already populated
            if (empty($item['component_meta']) && !empty($filePath)) {
                if (strpos($filePath, '/themes/') !== false || strpos($filePath, '\\themes\\') !== false) {
                    if (preg_match('#(?:wp-content[\\\\/])?themes[\\\\/]([^\\\\/]+)#i', $filePath, $tm)) {
                        $theme_root = function_exists('get_theme_root') ? get_theme_root() : (WP_CONTENT_DIR . '/themes');
                        $theme_dir = wp_normalize_path($theme_root . '/' . $tm[1]);
                        if (is_dir($theme_dir)) {
                            $item['component_meta'] = self::get_theme_forensics_meta($theme_dir, ['theme_slug' => $tm[1]]);
                        }
                    }
                } elseif (strpos($filePath, '/plugins/') !== false || strpos($filePath, '\\plugins\\') !== false) {
                    if (preg_match('#(?:wp-content[\\\\/])?plugins[\\\\/]([^\\\\/]+)#i', $filePath, $pm)) {
                        $plugin_dir = wp_normalize_path(WP_PLUGIN_DIR . '/' . $pm[1]);
                        if (is_dir($plugin_dir)) {
                            $item['component_meta'] = self::get_plugin_forensics_meta($plugin_dir, ['plugin_dir' => $pm[1]]);
                        }
                    }
                }
            }

            if (!empty($item['component_meta'])) {
                if ($item['engine'] === 'wordpress-updates' || in_array($item['type'], ['outdated_plugin', 'outdated_theme', 'vulnerable_plugin', 'vulnerable_theme', 'outdated_core', 'vulnerable_core'], true)) {
                    // Outdated or vulnerable software update findings should preserve their descriptive update title
                    if ($item['type'] === 'vulnerable_plugin') {
                        $item['display_title'] = !empty($item['component_name']) 
                            /* translators: %s: plugin name */
                            ? sprintf(__('Vulnerable Plugin: %s', 'webcare-pro-security'), $item['component_name']) 
                            : __('Vulnerable Plugin', 'webcare-pro-security');
                    } elseif ($item['type'] === 'outdated_plugin') {
                        $item['display_title'] = !empty($item['component_name']) 
                            /* translators: %s: plugin name */
                            ? sprintf(__('Outdated Plugin: %s', 'webcare-pro-security'), $item['component_name']) 
                            : __('Outdated Plugin', 'webcare-pro-security');
                    } elseif ($item['type'] === 'vulnerable_theme') {
                        $item['display_title'] = !empty($item['component_name']) 
                            /* translators: %s: theme name */
                            ? sprintf(__('Vulnerable Theme: %s', 'webcare-pro-security'), $item['component_name']) 
                            : __('Vulnerable Theme', 'webcare-pro-security');
                    } elseif ($item['type'] === 'outdated_theme') {
                        $item['display_title'] = !empty($item['component_name']) 
                            /* translators: %s: theme name */
                            ? sprintf(__('Outdated Theme: %s', 'webcare-pro-security'), $item['component_name']) 
                            : __('Outdated Theme', 'webcare-pro-security');
                    } elseif ($item['type'] === 'vulnerable_core') {
                        $item['display_title'] = __('Vulnerable WordPress Core', 'webcare-pro-security');
                    } elseif ($item['type'] === 'outdated_core') {
                        $item['display_title'] = __('Outdated WordPress Core', 'webcare-pro-security');
                    } else {
                        $item['display_title'] = __('Software Update Available', 'webcare-pro-security');
                    }
                } elseif (!empty($item['component_meta']['classification'])) {
                    if (empty($item['display_title'])) {
                        $item['display_title'] = $item['component_meta']['classification'];
                    }
                }
                if (isset($item['component_meta']['is_wporg'])) {
                    $item['is_wporg'] = (bool) $item['component_meta']['is_wporg'];
                }
                if (!empty($item['component_meta']['is_custom']) || !empty($item['component_meta']['is_premium'])) {
                    $item['is_custom'] = !empty($item['component_meta']['is_custom']);
                    $item['is_premium'] = !empty($item['component_meta']['is_premium']);
                    $item['is_wporg'] = false;
                }
                if (empty($item['component_name']) && !empty($item['component_meta']['name'])) {
                    $item['component_name'] = $item['component_meta']['name'];
                }
                if (empty($item['installed_version']) && !empty($item['component_meta']['version'])) {
                    $item['installed_version'] = $item['component_meta']['version'];
                }
                if (empty($item['latest_version']) && !empty($item['component_meta']['latest_version'])) {
                    $item['latest_version'] = $item['component_meta']['latest_version'];
                }
                if (!isset($item['has_update']) && isset($item['component_meta']['has_update'])) {
                    $item['has_update'] = $item['component_meta']['has_update'];
                }
            }

            if (empty($item['display_title'])) {
                $type_map = [
                    'weak_password_detected'         => __('Weak User Password', 'webcare-pro-security'),
                    'weak_admin_password'            => __('Weak Administrator Password', 'webcare-pro-security'),
                    'weak_user_password'             => __('Weak User Password', 'webcare-pro-security'),
                    'username_enumeration_risk'      => __('Username Enumeration Vulnerability', 'webcare-pro-security'),
                    'generic_admin_username'         => __('Generic Admin Username', 'webcare-pro-security'),
                    'user_missing_capabilities'      => __('User Account Missing Role Capabilities', 'webcare-pro-security'),
                    'suspicious_user_capabilities'   => __('Suspicious User Capabilities', 'webcare-pro-security'),
                    'injected_user_capabilities'     => __('Injected User Capabilities', 'webcare-pro-security'),
                    'tampered_role_definition'       => __('Tampered Role Definition', 'webcare-pro-security'),
                    'orphaned_post_author'           => __('Orphaned Post Author', 'webcare-pro-security'),
                    'webshell_pattern'               => __('Webshell Signature Pattern', 'webcare-pro-security'),
                    'obfuscated_malware_payload'     => __('Obfuscated Malware Payload', 'webcare-pro-security'),
                    'suspicious_strings'             => __('Suspicious Remote Code Strings', 'webcare-pro-security'),
                    'obfuscation_detected'           => __('Code Obfuscation Detected', 'webcare-pro-security'),
                    'executable_in_uploads'          => __('Executable Script in Uploads Directory', 'webcare-pro-security'),
                    'unsafe_permissions'             => __('Unsafe File Permissions', 'webcare-pro-security'),
                    'symlink_detected'               => __('Filesystem Symbolic Link', 'webcare-pro-security'),
                    'unknown_core_file'              => __('Unrecognized Core Directory File', 'webcare-pro-security'),
                    'unknown_wp_admin_file'          => __('Unrecognized WP-Admin File', 'webcare-pro-security'),
                    'unknown_wp_includes_file'       => __('Unrecognized WP-Includes File', 'webcare-pro-security'),
                    'modified_core_file'             => __('Modified WordPress Core File', 'webcare-pro-security'),
                    'modified_theme_file'            => __('Modified Theme File', 'webcare-pro-security'),
                    'modified_plugin_file'           => __('Modified Plugin File', 'webcare-pro-security'),
                    'missing_core_file'              => __('Missing WordPress Core File', 'webcare-pro-security'),
                    'eval_in_options'                => __('PHP Code in WordPress Options', 'webcare-pro-security'),
                    'base64_in_options'              => __('Base64 Payload in Options', 'webcare-pro-security'),
                    'serialized_injection'           => __('Serialized Object Injection', 'webcare-pro-security'),
                    'malicious_cron_hook'            => __('Suspicious Scheduled Cron Hook', 'webcare-pro-security'),
                    'malicious_cron_hook_name'       => __('Suspicious Scheduled Cron Hook', 'webcare-pro-security'),
                    'orphaned_cron_hook'             => __('Orphaned Scheduled Cron Hook', 'webcare-pro-security'),
                    'malicious_system_crontab'       => __('Malicious System Crontab Entry', 'webcare-pro-security'),
                    'suspicious_crontab_execution'   => __('Suspicious Crontab Execution', 'webcare-pro-security'),
                    'hidden_directory_crontab'       => __('Hidden Directory Crontab Task', 'webcare-pro-security'),
                    'malicious_mu_plugin'            => __('Suspicious Must-Use (MU) Plugin', 'webcare-pro-security'),
                    'mu_plugin_warning'              => __('Unverified Must-Use Plugin', 'webcare-pro-security'),
                    'unexpected_wp_content_file'     => __('Unexpected File in WP-Content', 'webcare-pro-security'),
                    'malicious_dropin'               => __('Malicious WordPress Drop-in', 'webcare-pro-security'),
                    'unauthorized_dropin'            => __('Unauthorized WordPress Drop-in', 'webcare-pro-security'),
                    'db_autoload_malware_anchor'     => __('Autoload Database Malware Anchor', 'webcare-pro-security'),
                    'self_healing_malware_resurrection' => __('Self-Healing Malware Persistence', 'webcare-pro-security'),
                    'rogue_server_preloader'         => __('Rogue Server Auto-Preloader', 'webcare-pro-security'),
                    'ini_auto_prepend'               => __('PHP INI auto_prepend_file Injection', 'webcare-pro-security'),
                    'ini_auto_append'                => __('PHP INI auto_append_file Injection', 'webcare-pro-security'),
                    'user_ini_preloader'             => __('User INI Preload Injection', 'webcare-pro-security'),
                    'htaccess_preloader'             => __('htaccess Preload Injection', 'webcare-pro-security'),
                    'core_checksums_unavailable'     => __('WordPress Core Checksums Unavailable', 'webcare-pro-security'),
                    'theme_checksums_unavailable'    => __('Theme Checksums Unavailable', 'webcare-pro-security'),
                    'plugin_checksums_unavailable'   => __('Plugin Checksums Unavailable', 'webcare-pro-security'),
                ];

                if (!empty($item['type']) && isset($type_map[$item['type']])) {
                    $item['display_title'] = $type_map[$item['type']];
                } elseif (!empty($item['type'])) {
                    // Fallback to formatted title case: "my_suspicious_finding" -> "My Suspicious Finding"
                    $item['display_title'] = ucwords(str_replace(['_', '-'], ' ', $item['type']));
                }
            }

            // 6. Whitelist & False-Positive Rule Matching (Auto-suppression)
            $matched_rule = \WebCareProScanner\Findings\WhitelistManager::match_finding($item);
            if ($matched_rule !== null) {
                $item['is_whitelisted'] = true;
                $item['whitelist_rule'] = $matched_rule;
                if (!empty($item['id']) && ($item['status'] ?? '') === 'open') {
                    global $wpdb;
                    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                    $wpdb->update($wpdb->prefix . 'webcareproscan_scan_issues', ['status' => 'ignored'], ['id' => (int) $item['id']]);
                }
                $item['status']         = 'ignored';
            } else {
                $item['is_whitelisted'] = false;
            }

            if (!empty($item['created_at_gmt'])) {
                $item['created_at_gmt'] = gmdate('Y-m-d\TH:i:s\Z', strtotime($item['created_at_gmt']));
            } elseif (!empty($item['created_at'])) {
                $item['created_at_gmt'] = get_gmt_from_date($item['created_at'], 'Y-m-d\TH:i:s\Z');
            }

            // Non-Technical Owner Suite: Plain-English Translation Schema
            if (class_exists('\\WebCareProScanner\\Findings\\FindingTranslator')) {
                $item['plain_english'] = \WebCareProScanner\Findings\FindingTranslator::translate($item);
            }
        }
        unset($item);

        // Deduplicate identical issues by normalized signature (type + normalized target path + line number)
        $deduped = [];
        $seen_signatures = [];
        foreach ($issues as $entry) {
            $norm_path = self::normalize_finding_path($entry['file_path'] ?? ($entry['target'] ?? ''));
            $type = strtolower(trim($entry['type'] ?? ''));
            $line = (int) ($entry['line_number'] ?? 0);
            $sig = $type . '|' . $norm_path . '|' . $line;
            if (isset($seen_signatures[$sig])) {
                continue;
            }
            $seen_signatures[$sig] = true;
            $deduped[] = $entry;
        }

        return $deduped;
    }

    /**
     * Normalize a finding target key (file path or entity ID) to canonical format.
     *
     * @param string $path
     * @return string Canonical normalized target key
     */
    public static function normalize_finding_path(string $path): string {
        $clean = trim($path);
        if ($clean === '') {
            return '';
        }
        $normalized = str_replace('\\', '/', $clean);
        $normalized = preg_replace('#/+#', '/', $normalized);
        $normalized = strtolower(rtrim($normalized, '/'));

        if (defined('ABSPATH')) {
            $norm_abspath = strtolower(rtrim(str_replace('\\', '/', ABSPATH), '/'));
            if (!empty($norm_abspath) && str_starts_with($normalized, $norm_abspath)) {
                $normalized = ltrim(substr($normalized, strlen($norm_abspath)), '/');
            }
        }

        return $normalized;
    }

    /**
     * Prune duplicate issue rows for a scan to ensure each file/anomaly type is stored only once.
     *
     * @param int $scan_id
     * @return int Number of pruned duplicate rows
     */
    public static function prune_duplicate_issues(int $scan_id): int {
        global $wpdb;
        $table_issues = $wpdb->prefix . 'webcareproscan_scan_issues';
        $table_scans = $wpdb->prefix . 'webcareproscan_scans';

        if ($scan_id <= 0) {
            return 0;
        }

        $iss_query = "SELECT id, engine, type, file_path, line_number, confidence FROM `{$table_issues}` WHERE scan_id = %d ORDER BY id ASC";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $rows = $wpdb->get_results(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $wpdb->prepare($iss_query, $scan_id),
            ARRAY_A
        ) ?: [];

        if (empty($rows)) {
            return 0;
        }

        $seen = [];
        $ids_to_delete = [];

        foreach ($rows as $row) {
            $norm_path = self::normalize_finding_path($row['file_path'] ?? '');
            $type = strtolower(trim($row['type'] ?? ''));
            $line = (int) ($row['line_number'] ?? 0);
            $sig = $type . '|' . $norm_path . '|' . $line;

            if (isset($seen[$sig])) {
                $ids_to_delete[] = (int) $row['id'];
            } else {
                $seen[$sig] = (int) $row['id'];
            }
        }

        if (!empty($ids_to_delete)) {
            foreach (array_chunk($ids_to_delete, 80) as $chunk) {
                $placeholders = implode(',', array_fill(0, count($chunk), '%d'));
                $del_sql = "DELETE FROM `{$table_issues}` WHERE id IN ($placeholders)";
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
                $wpdb->query(
                    // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                    $wpdb->prepare($del_sql, ...$chunk)
                );
            }

            // Recalculate true active open issues on scan row
            $cnt_sql = "SELECT COUNT(*) FROM `{$table_issues}` WHERE scan_id = %d AND status = 'open'";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $open_count = (int) $wpdb->get_var(
                // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                $wpdb->prepare($cnt_sql, $scan_id)
            );
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->update($table_scans, ['issues_found' => $open_count], ['id' => $scan_id]);
        }

        return count($ids_to_delete);
    }

    /**
     * Extract deep forensic metadata for a WordPress theme directory.
     *
     * @param string $filePath
     * @param array $evidence_data
     * @return array
     */
    public static function get_theme_forensics_meta(string $filePath, array $evidence_data = []): array {
        $norm_path = wp_normalize_path($filePath);
        if (!empty($evidence_data['theme_slug'])) {
            $theme_slug = $evidence_data['theme_slug'];
        } elseif (preg_match('#(?:wp-content/themes|themes)/([^/]+)#i', $norm_path, $m)) {
            $theme_slug = $m[1];
        } else {
            $theme_slug = basename($norm_path);
        }
        $theme = wp_get_theme($theme_slug);

        // Fallback: check if directory exists even if slug slightly differed
        if (!$theme->exists() && file_exists($norm_path . '/style.css')) {
            $all_themes = function_exists('wp_get_themes') ? wp_get_themes() : [];
            foreach ($all_themes as $s => $t) {
                if (wp_normalize_path($t->get_stylesheet_directory()) === $norm_path) {
                    $theme = $t;
                    $theme_slug = $s;
                    break;
                }
            }
        }

        $theme_dir = $theme->exists() ? wp_normalize_path($theme->get_stylesheet_directory()) : (is_dir($norm_path) ? $norm_path : dirname($norm_path));

        $name = $theme->exists() ? $theme->get('Name') : (!empty($evidence_data['theme_name']) ? $evidence_data['theme_name'] : $theme_slug);
        $version = $theme->exists() ? (string) $theme->get('Version') : (!empty($evidence_data['version']) ? (string) $evidence_data['version'] : '');
        $author = $theme->exists() ? wp_strip_all_tags($theme->get('Author')) : '';
        $author_uri = $theme->exists() ? (string) $theme->get('AuthorURI') : '';
        $theme_uri = $theme->exists() ? (string) $theme->get('ThemeURI') : '';
        $description = $theme->exists() ? wp_strip_all_tags($theme->get('Description')) : '';
        $requires_wp = $theme->exists() ? (string) $theme->get('RequiresWP') : '';
        $requires_php = $theme->exists() ? (string) $theme->get('RequiresPHP') : '';
        $text_domain = $theme->exists() ? (string) $theme->get('TextDomain') : '';

        // Active state detection
        $current_stylesheet = function_exists('get_stylesheet') ? get_stylesheet() : '';
        $current_template = function_exists('get_template') ? get_template() : '';
        $is_active_child = ($theme_slug === $current_stylesheet && $theme_slug !== $current_template);
        $is_active_parent = ($theme_slug === $current_template);
        $is_active = ($theme_slug === $current_stylesheet || $theme_slug === $current_template);

        $parent_obj = $theme->exists() ? $theme->parent() : null;
        $is_child = (bool) $parent_obj || !empty($evidence_data['is_child']) || strpos(strtolower($norm_path), '-child') !== false;
        $parent_name = $parent_obj ? $parent_obj->get('Name') : (!empty($evidence_data['parent_theme']) ? $evidence_data['parent_theme'] : null);
        $parent_version = $parent_obj ? (string) $parent_obj->get('Version') : null;

        if ($is_active_child) {
            $status_label = 'Active Child Theme';
        } elseif ($is_active_parent && $current_stylesheet !== $current_template) {
            $status_label = 'Active Parent Template';
        } elseif ($is_active) {
            $status_label = 'Active Theme';
        } else {
            $status_label = 'Inactive';
        }

        // Check latest version in update_themes transient
        $latest_version = null;
        $has_update = false;
        $update_package = '';
        $is_wporg = false;
        $update_themes = get_site_transient('update_themes');
        if (!empty($update_themes->response[$theme_slug])) {
            $theme_update = (array) $update_themes->response[$theme_slug];
            $latest_version = $theme_update['new_version'] ?? null;
            $has_update = !empty($latest_version) && (!empty($version) ? version_compare($latest_version, $version, '>') : true);
            $update_package = $theme_update['package'] ?? '';
            $package_url = is_string($update_package) ? $update_package : '';
            $theme_url = is_string($theme_update['url'] ?? '') ? $theme_update['url'] : '';
            if (strpos($package_url, 'wordpress.org') !== false || strpos($theme_url, 'wordpress.org') !== false) {
                $is_wporg = true;
            }
        } elseif (!empty($update_themes->checked[$theme_slug])) {
            $latest_version = $update_themes->checked[$theme_slug];
            if (strpos($theme_uri, 'wordpress.org/themes') !== false || (bool) preg_match('/^twenty(ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|nineteen|twenty|twentyone|twentytwo|twentythree|twentyfour|twentyfive|twentysix)/i', $theme_slug)) {
                $is_wporg = true;
            }
        }

        $is_explicit_non_wporg = !empty($evidence_data['is_premium'])
            || !empty($evidence_data['is_child'])
            || $is_child
            || (isset($evidence_data['is_wporg']) && !$evidence_data['is_wporg'])
            || (!empty($evidence_data['display_title']) && in_array($evidence_data['display_title'], ['Premium Theme', 'Custom Child Theme', 'Custom or Premium Theme'], true));

        $is_premium = !empty($evidence_data['is_premium']) || (bool) preg_match('/\b(premium|pro|commercial|license|themeforest|envato)\b/i', $norm_path . ' ' . $name . ' ' . $description);

        if ($is_explicit_non_wporg || $is_premium) {
            $is_wporg = false;
        }

        if ($is_wporg) {
            $classification = __('Official WordPress Theme', 'webcare-pro-security');
        } elseif (!empty($evidence_data['display_title'])) {
            $classification = $evidence_data['display_title'];
        } elseif ($is_child) {
            $classification = __('Custom Child Theme', 'webcare-pro-security');
        } else {
            $classification = $is_premium ? __('Premium Theme', 'webcare-pro-security') : __('Custom or Premium Theme', 'webcare-pro-security');
        }

        // File stats and timestamps
        $mtime = file_exists($norm_path) ? filemtime($norm_path) : (file_exists($theme_dir . '/style.css') ? filemtime($theme_dir . '/style.css') : 0);
        $last_updated = $mtime ? gmdate('Y-m-d H:i:s', $mtime) . ' UTC' : 'Unknown';
        $last_updated_human = $mtime ? human_time_diff($mtime, current_time('timestamp', 1)) . ' ago' : 'Unknown';

        // Permissions
        $folder_perms = file_exists($theme_dir) ? substr(sprintf('%o', fileperms($theme_dir)), -4) : '0755';
        $style_css_path = file_exists($theme_dir . '/style.css') ? ($theme_dir . '/style.css') : (file_exists($norm_path) ? $norm_path : '');
        $file_perms = (!empty($style_css_path) && file_exists($style_css_path)) ? substr(sprintf('%o', fileperms($style_css_path)), -4) : '0644';

        // Check for changelog or readme file
        $changelog_info = self::detect_component_changelog($theme_dir);

        return [
            'type'                => 'theme',
            'slug'                => $theme_slug,
            'name'                => $name,
            'version'             => $version,
            'latest_version'      => $latest_version,
            'has_update'          => $has_update,
            'update_package'      => !empty($update_package),
            'author'              => $author,
            'author_uri'          => $author_uri,
            'theme_uri'           => $theme_uri,
            'description'         => $description,
            'is_active'           => $is_active,
            'is_child'            => $is_child,
            'parent_name'         => $parent_name,
            'parent_version'      => $parent_version,
            'status_label'        => $status_label,
            'requires_wp'         => $requires_wp,
            'requires_php'        => $requires_php,
            'text_domain'         => $text_domain,
            'path'                => $norm_path,
            'last_modified'       => $last_updated,
            'last_modified_human' => $last_updated_human,
            'folder_perms'        => $folder_perms,
            'main_file_perms'     => $file_perms,
            'main_file'           => file_exists($style_css_path) ? 'style.css' : '',
            'has_changelog'       => $changelog_info['has_changelog'],
            'changelog_file'      => $changelog_info['filename'],
            'admin_url'           => admin_url('themes.php'),
            'is_wporg'            => $is_wporg,
            'classification'      => $classification,
        ];
    }

    /**
     * Extract deep forensic metadata for a WordPress plugin directory or file.
     *
     * @param string $filePath
     * @param array $evidence_data
     * @return array
     */
    public static function get_plugin_forensics_meta(string $filePath, array $evidence_data = []): array {
        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $all_plugins = function_exists('get_plugins') ? get_plugins() : [];
        $norm_path = wp_normalize_path($filePath);

        $matched_file = '';
        $matched_data = [];

        // Check direct plugin_file from evidence_data first
        if (!empty($evidence_data['plugin_file']) && isset($all_plugins[$evidence_data['plugin_file']])) {
            $matched_file = $evidence_data['plugin_file'];
            $matched_data = $all_plugins[$matched_file];
        }

        if (empty($matched_file)) {
            $folder_name = !empty($evidence_data['plugin_dir']) ? $evidence_data['plugin_dir'] : basename($norm_path);
            foreach ($all_plugins as $plugin_file => $data) {
                $dir_name = dirname($plugin_file);
                if ($dir_name === $folder_name || $plugin_file === $folder_name) {
                    $matched_file = $plugin_file;
                    $matched_data = $data;
                    break;
                }
                $full_dir = wp_normalize_path(WP_PLUGIN_DIR . '/' . $dir_name);
                if ($full_dir === $norm_path) {
                    $matched_file = $plugin_file;
                    $matched_data = $data;
                    break;
                }
            }
        }

        $name = !empty($matched_data['Name']) ? $matched_data['Name'] : (!empty($evidence_data['plugin_name']) ? $evidence_data['plugin_name'] : basename($norm_path));
        $version = !empty($matched_data['Version']) ? (string) $matched_data['Version'] : (!empty($evidence_data['version']) ? (string) $evidence_data['version'] : '');
        $author = !empty($matched_data['Author']) ? wp_strip_all_tags($matched_data['Author']) : '';
        $author_uri = (string) ($matched_data['AuthorURI'] ?? '');
        $plugin_uri = (string) ($matched_data['PluginURI'] ?? '');
        $description = !empty($matched_data['Description']) ? wp_strip_all_tags($matched_data['Description']) : '';
        $requires_wp = (string) ($matched_data['RequiresWP'] ?? '');
        $requires_php = (string) ($matched_data['RequiresPHP'] ?? '');
        $text_domain = (string) ($matched_data['TextDomain'] ?? '');

        // Active state detection
        $is_active = false;
        $network_active = false;
        if (!empty($matched_file) && function_exists('is_plugin_active')) {
            $is_active = is_plugin_active($matched_file);
            if (is_multisite() && function_exists('is_plugin_active_for_network')) {
                $network_active = is_plugin_active_for_network($matched_file);
                if ($network_active) {
                    $is_active = true;
                }
            }
        }

        if ($network_active) {
            $status_label = 'Network Active';
        } elseif ($is_active) {
            $status_label = 'Active';
        } else {
            $status_label = 'Inactive';
        }

        // Check latest version in update_plugins transient
        $latest_version = null;
        $has_update = false;
        $update_package = '';
        $is_wporg = false;
        $update_plugins = get_site_transient('update_plugins');

        $update_entry = null;
        if (!empty($matched_file) && !empty($update_plugins->response[$matched_file])) {
            $update_entry = $update_plugins->response[$matched_file];
            $latest_version = $update_entry->new_version ?? null;
            $has_update = !empty($latest_version) && (!empty($version) ? version_compare($latest_version, $version, '>') : true);
            $update_package = $update_entry->package ?? '';
        } elseif (!empty($matched_file) && !empty($update_plugins->no_update[$matched_file])) {
            $update_entry = $update_plugins->no_update[$matched_file];
            $latest_version = $update_entry->new_version ?? $version;
        }

        // Check if update entry is verified from WordPress.org repository
        if (is_object($update_entry)) {
            $entry_id = is_string($update_entry->id ?? '') ? $update_entry->id : '';
            $entry_url = is_string($update_entry->url ?? '') ? $update_entry->url : '';
            $entry_pkg = is_string($update_entry->package ?? '') ? $update_entry->package : '';
            if (strpos($entry_id, 'w.org/') !== false || strpos($entry_id, 'wordpress.org') !== false
                || strpos($entry_url, 'wordpress.org/plugins') !== false
                || strpos($entry_pkg, 'downloads.wordpress.org') !== false
                || strpos($entry_pkg, 'wordpress.org') !== false) {
                $is_wporg = true;
            }
        }

        if (!$is_wporg && strpos($plugin_uri, 'wordpress.org/plugins') !== false) {
            $is_wporg = true;
        }

        // Check explicit non-wporg evidence or finding context (e.g. from PluginIntegrity / plugin_checksums_unavailable)
        $is_explicit_non_wporg = !empty($evidence_data['is_premium']) 
            || !empty($evidence_data['is_custom'])
            || (isset($evidence_data['is_wporg']) && !$evidence_data['is_wporg'])
            || (!empty($evidence_data['classification']) && in_array($evidence_data['classification'], ['premium_plugin', 'custom_plugin'], true))
            || (!empty($evidence_data['display_title']) && in_array($evidence_data['display_title'], ['Premium Plugin', 'Custom or Premium Plugin', 'Custom Plugin'], true));

        // Name, description or directory indicating commercial/pro/premium product
        $is_premium = !empty($evidence_data['is_premium']) 
            || (bool) preg_match('/(?:^|[-_])(premium|pro|addon|addons|unlimited|commercial)(?:[-_]|$)/i', $norm_path) 
            || (bool) preg_match('/\b(premium|pro|codecanyon|themeforest|envato|commercial|license)\b/i', $name . ' ' . $description);

        if ($is_explicit_non_wporg || $is_premium) {
            $is_wporg = false;
        }

        if ($is_wporg) {
            $classification = __('Official WordPress Plugin', 'webcare-pro-security');
        } elseif (!empty($evidence_data['display_title'])) {
            $classification = $evidence_data['display_title'];
        } elseif ($is_premium) {
            $classification = __('Premium Plugin', 'webcare-pro-security');
        } else {
            $classification = __('Custom or Premium Plugin', 'webcare-pro-security');
        }

        // Timestamps
        $main_file_full = (!empty($matched_file) && file_exists(WP_PLUGIN_DIR . '/' . $matched_file)) ? wp_normalize_path(WP_PLUGIN_DIR . '/' . $matched_file) : '';
        $mtime = $main_file_full ? filemtime($main_file_full) : (file_exists($norm_path) ? filemtime($norm_path) : 0);
        $last_updated = $mtime ? gmdate('Y-m-d H:i:s', $mtime) . ' UTC' : 'Unknown';
        $last_updated_human = $mtime ? human_time_diff($mtime, current_time('timestamp', 1)) . ' ago' : 'Unknown';

        // Permissions
        $folder_perms = file_exists($norm_path) ? substr(sprintf('%o', fileperms($norm_path)), -4) : '0755';
        $main_file_perms = $main_file_full ? substr(sprintf('%o', fileperms($main_file_full)), -4) : '0644';

        // Changelog detection
        $changelog_info = self::detect_component_changelog($norm_path);

        return [
            'type'                => 'plugin',
            'slug'                => !empty($matched_file) ? dirname($matched_file) : basename($norm_path),
            'plugin_file'         => $matched_file,
            'name'                => $name,
            'version'             => $version,
            'latest_version'      => $latest_version,
            'has_update'          => $has_update,
            'update_package'      => !empty($update_package),
            'author'              => $author,
            'author_uri'          => $author_uri,
            'plugin_uri'          => $plugin_uri,
            'description'         => $description,
            'is_active'           => $is_active,
            'network_active'      => $network_active,
            'status_label'        => $status_label,
            'requires_wp'         => $requires_wp,
            'requires_php'        => $requires_php,
            'text_domain'         => $text_domain,
            'path'                => $norm_path,
            'last_modified'       => $last_updated,
            'last_modified_human' => $last_updated_human,
            'folder_perms'        => $folder_perms,
            'main_file_perms'     => $main_file_perms,
            'main_file'           => $matched_file ? basename($matched_file) : '',
            'has_changelog'       => $changelog_info['has_changelog'],
            'changelog_file'      => $changelog_info['filename'],
            'admin_url'           => admin_url('plugins.php'),
            'is_wporg'            => $is_wporg,
            'classification'      => $classification,
        ];
    }

    /**
     * Inspect component folder for changelog or release history files.
     *
     * @param string $component_path
     * @return array
     */
    public static function detect_component_changelog(string $component_path): array {
        $candidates = [
            'changelog.txt', 'CHANGELOG.txt',
            'changelog.md', 'CHANGELOG.md',
            'readme.txt', 'README.txt',
            'readme.md', 'README.md',
            'history.md', 'HISTORY.md',
            'releases.md', 'RELEASES.md',
            'docs/changelog.txt', 'docs/CHANGELOG.md'
        ];

        foreach ($candidates as $cand) {
            $target = $component_path . '/' . $cand;
            if (file_exists($target) && is_readable($target) && is_file($target)) {
                return [
                    'has_changelog' => true,
                    'filename'      => basename($cand),
                    'full_path'     => wp_normalize_path($target)
                ];
            }
        }

        return [
            'has_changelog' => false,
            'filename'      => '',
            'full_path'     => ''
        ];
    }

    /**
     * Extract the Changelog section from a WordPress readme.txt / readme.md file.
     *
     * @param string $content
     * @return string
     */
    public static function extract_changelog_from_readme(string $content): string {
        if (empty($content)) {
            return '';
        }

        // Standard WordPress readme.txt: == Changelog ==
        if (preg_match('/==\s*Changelog\s*==(.*?)(?=(?:\n==\s*[^=]+\s*==|\Z))/is', $content, $matches)) {
            return trim("== Changelog ==\n" . trim($matches[1]));
        }

        // Markdown style: ## Changelog or # Changelog
        if (preg_match('/(?:^|\n)#{1,3}\s*Changelog\b(.*?)(?=(?:\n#{1,3}\s+[^\n]+|\Z))/is', $content, $matches)) {
            return trim("## Changelog\n" . trim($matches[1]));
        }

        return '';
    }

    /**
     * Convert WordPress.org API HTML changelog section into readable, formatted markdown text.
     *
     * @param string $html
     * @return string
     */
    public static function format_changelog_html(string $html): string {
        if (empty($html)) {
            return '';
        }

        $s = $html;
        $s = preg_replace('/<h[1-6][^>]*>(.*?)<\/h[1-6]>/is', "\n\n= $1 =\n", $s);
        $s = preg_replace('/<li[^>]*>(.*?)<\/li>/is', "* $1\n", $s);
        $s = preg_replace('/<code[^>]*>(.*?)<\/code>/is', '`$1`', $s);
        $s = preg_replace('/<\/p>/is', "\n\n", $s);
        $s = preg_replace('/<br\s*\/?>/is', "\n", $s);
        $s = wp_strip_all_tags($s);
        $s = html_entity_decode($s, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $s = preg_replace("/\n{3,}/", "\n\n", $s);

        return trim($s);
    }

    

    /**
     * Get high-precision current timestamp in WordPress local time.
     *
     * @return string e.g. "2026-10-12 01:10:12.345"
     */
    public static function now_fractional_mysql() {
        $micro = microtime(true);
        $seconds = (int) $micro;
        $millis = (int) round(($micro - $seconds) * 1000);
        if ($millis >= 1000) {
            $seconds++;
            $millis = 0;
        }
        $date_str = wp_date('Y-m-d H:i:s', $seconds);
        return sprintf('%s.%03d', $date_str, $millis);
    }

    /**
     * Formats duration in seconds or fractional seconds into human-readable representation.
     *
     * @param float $duration_secs Duration in seconds (e.g. 0.42, 1.85, 65.2)
     * @param int $duration_ms Duration in milliseconds (e.g. 420)
     * @return string e.g. "420ms", "1.85s", "1m 5s"
     */
    public static function format_duration_precise($duration_secs, $duration_ms = 0) {
        $ms = (int) $duration_ms;
        if ($ms <= 0 && $duration_secs > 0) {
            $ms = (int) round($duration_secs * 1000);
        }

        if ($ms < 1000 && $ms > 0) {
            return "{$ms}ms";
        }

        $secs = $duration_secs > 0 ? $duration_secs : round($ms / 1000, 2);
        if ($secs < 10) {
            return sprintf('%.2fs', $secs);
        } elseif ($secs < 60) {
            return sprintf('%.1fs', $secs);
        }

        $total_sec = (int) round($secs);
        $mins = floor($total_sec / 60);
        $rem_sec = $total_sec % 60;
        return "{$mins}m {$rem_sec}s";
    }

    /**
     * Resolves and formats descriptive metadata for any scan target (standard, custom, or targeted).
     *
     * @param string $target The raw scan target identifier (e.g. 'custom', 'plugins_themes', 'suspicious_uploads', etc.)
     * @return array Metadata array with name, short_name, category, category_label, and description.
     */
    public static function format_scan_target_meta(string $target): array {
        $target = sanitize_key($target);

        $definitions = [
            'custom' => [
                'name'           => 'Custom Security Scan',
                'short_name'     => 'Custom Scan',
                'category'       => 'custom',
                'category_label' => 'Custom Scan',
                'description'    => 'Administrator-configured modular audit tailored to specific security engines and directories.',
            ],
            'plugins_themes' => [
                'name'           => 'Quick Scan (Plugins & Themes)',
                'short_name'     => 'Quick Scan',
                'category'       => 'standard',
                'category_label' => 'Standard Scan',
                'description'    => 'Standard audit of active and installed plugins and themes.',
            ],
            'full' => [
                'name'           => 'Complete Website Scan (Full Filesystem)',
                'short_name'     => 'Complete Scan',
                'category'       => 'standard',
                'category_label' => 'Standard Scan',
                'description'    => 'Comprehensive audit of entire WordPress root, core, plugins, themes, uploads, and database.',
            ],
            'full_filesystem' => [
                'name'           => 'Complete Website Scan (Full Filesystem)',
                'short_name'     => 'Complete Scan',
                'category'       => 'standard',
                'category_label' => 'Standard Scan',
                'description'    => 'Comprehensive audit of entire WordPress root filesystem and database.',
            ],
            'modified_files' => [
                'name'           => 'Targeted: Modified Themes, Plugins & Core Audit',
                'short_name'     => 'Targeted: Modified Files',
                'category'       => 'targeted',
                'category_label' => 'Targeted Scan',
                'description'    => 'Targeted cryptographic checksum verification against official WordPress.org manifests.',
            ],
            'suspicious_uploads' => [
                'name'           => 'Targeted: Uploads Executables & Shell Audit',
                'short_name'     => 'Targeted: Uploads',
                'category'       => 'targeted',
                'category_label' => 'Targeted Scan',
                'description'    => 'Targeted forensic scan isolating dangerous scripts, shells, and double extensions in uploads.',
            ],
            'unknown_files' => [
                'name'           => 'Targeted: Unknown Files Integrity Audit',
                'short_name'     => 'Targeted: Unknown Files',
                'category'       => 'targeted',
                'category_label' => 'Targeted Scan',
                'description'    => 'Targeted reconciliation against official repositories to detect orphan files and backdoors.',
            ],
            'spam_content' => [
                'name'           => 'Targeted: Spam Content & Database Audit',
                'short_name'     => 'Targeted: Spam Content',
                'category'       => 'targeted',
                'category_label' => 'Targeted Scan',
                'description'    => 'Targeted database scan hunting for cloaked spam, blackhat SEO injections, and malicious comments.',
            ],
            'filesystem_only' => [
                'name'           => 'Targeted: Filesystem Permissions & Symlinks Audit',
                'short_name'     => 'Targeted: Filesystem',
                'category'       => 'targeted',
                'category_label' => 'Targeted Scan',
                'description'    => 'Targeted audit evaluating Unix permissions, writeability hazards, and symlink breakouts.',
            ],
            'user_security' => [
                'name'           => 'Targeted: User Accounts, Roles & Capability Auditor',
                'short_name'     => 'Targeted: User Accounts',
                'category'       => 'targeted',
                'category_label' => 'Targeted Scan',
                'description'    => 'Targeted scan inspecting rogue administrator privileges, ghost users, and weak credentials.',
            ],
            'outdated_software' => [
                'name'           => 'Targeted: Outdated Software & Vulnerability Audit',
                'short_name'     => 'Targeted: Outdated Software',
                'category'       => 'targeted',
                'category_label' => 'Targeted Scan',
                'description'    => 'Targeted CVE intelligence matching against active WordPress core, plugins, and themes.',
            ],
            'crontab_audit' => [
                'name'           => 'Targeted: Crontab & Scheduled Tasks Audit',
                'short_name'     => 'Targeted: Crontab Audit',
                'category'       => 'targeted',
                'category_label' => 'Targeted Scan',
                'description'    => 'Targeted Linux crontab and WP-Cron virtual hook inspection for scheduled stealth persistence.',
            ],
            'crontab_hooks' => [
                'name'           => 'Targeted: Crontab & Scheduled Tasks Audit',
                'short_name'     => 'Targeted: Crontab Audit',
                'category'       => 'targeted',
                'category_label' => 'Targeted Scan',
                'description'    => 'Targeted Linux crontab and WP-Cron virtual hook inspection.',
            ],
            'core_integrity' => [
                'name'           => 'Targeted: WordPress Core Integrity Audit',
                'short_name'     => 'Targeted: Core Integrity',
                'category'       => 'targeted',
                'category_label' => 'Targeted Scan',
                'description'    => 'Targeted cryptographic checksum verification strictly auditing core WordPress files.',
            ],
            'rogue_admin' => [
                'name'           => 'Targeted: Rogue Admins & DB Anomalies Audit',
                'short_name'     => 'Targeted: Rogue Admins',
                'category'       => 'targeted',
                'category_label' => 'Targeted Scan',
                'description'    => 'Targeted database scan detecting backdoor accounts, hidden administrators, and tampered capability roles.',
            ],
            'hook_sentinel' => [
                'name'           => 'Targeted: Hook Sentinel & LotL Traps Audit',
                'short_name'     => 'Targeted: Hook Sentinel',
                'category'       => 'targeted',
                'category_label' => 'Targeted Scan',
                'description'    => 'Targeted runtime inspection uncovering malicious filters, actions, and Living-off-the-Land persistence hooks.',
            ],
            'uploads_database' => [
                'name'           => 'Targeted: Uploads & Database Audit',
                'short_name'     => 'Targeted: Uploads & DB',
                'category'       => 'targeted',
                'category_label' => 'Targeted Scan',
                'description'    => 'Targeted inspection of media uploads folder and database tables.',
            ],
        ];

        $res = isset($definitions[$target]) ? $definitions[$target] : null;
        if (!$res) {
            $human_target = ucwords(str_replace(['_', '-'], ' ', $target));
            $is_custom = strpos($target, 'custom') !== false;
            $res = [
                'name'           => $is_custom ? ('Custom Scan: ' . $human_target) : ('Targeted: ' . $human_target),
                'short_name'     => $is_custom ? 'Custom Scan' : ('Targeted: ' . $human_target),
                'category'       => $is_custom ? 'custom' : 'targeted',
                'category_label' => $is_custom ? 'Custom Scan' : 'Targeted Scan',
                'description'    => 'Specialized security audit.',
            ];
        }

        $res['badge'] = $res['category_label'];
        if ($res['category'] === 'custom') {
            $res['badge_bg'] = '#faf5ff';
            $res['badge_color'] = '#7e22ce';
            $res['badge_border'] = '#e9d5ff';
        } elseif ($res['category'] === 'targeted') {
            $res['badge_bg'] = '#ecfeff';
            $res['badge_color'] = '#0891b2';
            $res['badge_border'] = '#a5f3fc';
        } else {
            $res['badge_bg'] = '#eff6ff';
            $res['badge_color'] = '#1d4ed8';
            $res['badge_border'] = '#bfdbfe';
        }

        return $res;
    }

    /**
     * Enriches scan row with unambiguous ISO 8601 UTC / GMT timestamps
     * using official WordPress get_gmt_from_date() conversion.
     *
     * @param array $row
     * @return array
     */
    public static function enrich_scan_row_timestamps(array $row): array {
        $tz_string = wp_timezone_string();
        $row['site_timezone'] = $tz_string;
        if (!empty($row['created_at_gmt'])) {
            $row['created_at_gmt'] = gmdate('Y-m-d\TH:i:s\Z', strtotime($row['created_at_gmt']));
        } elseif (!empty($row['created_at'])) {
            $row['created_at_gmt'] = get_gmt_from_date($row['created_at'], 'Y-m-d\TH:i:s\Z');
        }
        if (!empty($row['started_at'])) {
            $base_s = substr($row['started_at'], 0, 19);
            $sub_s  = substr($row['started_at'], 19);
            $gmt_s  = get_gmt_from_date($base_s, 'Y-m-d\TH:i:s');
            $row['started_at_gmt'] = $gmt_s ? ($gmt_s . ($sub_s ?: '') . 'Z') : null;
        }
        if (!empty($row['completed_at'])) {
            $base_c = substr($row['completed_at'], 0, 19);
            $sub_c  = substr($row['completed_at'], 19);
            $gmt_c  = get_gmt_from_date($base_c, 'Y-m-d\TH:i:s');
            $row['completed_at_gmt'] = $gmt_c ? ($gmt_c . ($sub_c ?: '') . 'Z') : null;
        }
        return $row;
    }

    /**
     * Build rich performance and system diagnostic telemetry for a scan.
     *
     * @param array $scan
     * @return array
     */
    public static function build_scan_diagnostics(array $scan) {
        $scan_id = (int) ($scan['id'] ?? 0);
        $cached_diag = $scan_id > 0 ? get_transient("webcareproscan_diag_{$scan_id}") : null;

        // Peak Memory
        $peak_bytes = memory_get_peak_usage(true);
        if ($cached_diag && !empty($cached_diag['peak_memory_bytes'])) {
            $peak_bytes = max($peak_bytes, (int) $cached_diag['peak_memory_bytes']);
        }
        $peak_mb = round($peak_bytes / (1024 * 1024), 2);

        // Memory Limit
        $memory_limit_raw = ini_get('memory_limit') ?: '256M';
        $limit_bytes = 256 * 1024 * 1024;
        if (preg_match('/^(\d+)(.)$/i', $memory_limit_raw, $m)) {
            $val = (int) $m[1];
            $unit = strtoupper($m[2]);
            if ($unit === 'G') $limit_bytes = $val * 1024 * 1024 * 1024;
            elseif ($unit === 'M') $limit_bytes = $val * 1024 * 1024;
            elseif ($unit === 'K') $limit_bytes = $val * 1024;
        }
        $memory_pct = $limit_bytes > 0 ? round(($peak_bytes / $limit_bytes) * 100, 1) : 0;

        // Accurate Duration & Throughput
        $duration_ms = (int) ($scan['duration_ms'] ?? 0);
        $duration_sec = isset($scan['duration']) ? (float) $scan['duration'] : 0.0;

        if ($duration_ms > 0) {
            $duration_sec = round($duration_ms / 1000, 3);
        } elseif ($duration_sec <= 0 && !empty($scan['started_at']) && !empty($scan['completed_at'])) {
            $start_dt = date_create_from_format('Y-m-d H:i:s.u', $scan['started_at']) ?: date_create($scan['started_at']);
            $end_dt = date_create_from_format('Y-m-d H:i:s.u', $scan['completed_at']) ?: date_create($scan['completed_at']);
            if ($start_dt && $end_dt) {
                $diff = $end_dt->getTimestamp() - $start_dt->getTimestamp() + (($end_dt->format('u') - $start_dt->format('u')) / 1000000);
                if ($diff > 0) {
                    $duration_sec = round($diff, 3);
                    $duration_ms = (int) round($diff * 1000);
                }
            }
        } elseif ($duration_sec <= 0 && !empty($scan['created_at'])) {
            $created_dt = date_create($scan['created_at'], wp_timezone());
            if ($created_dt) {
                $now_dt = date_create('now', wp_timezone());
                $diff = $now_dt->getTimestamp() - $created_dt->getTimestamp();
                $duration_sec = max(0.1, (float) $diff);
                $duration_ms = (int) round($duration_sec * 1000);
            }
        }

        $duration_fmt = self::format_duration_precise($duration_sec, $duration_ms);
        $scanned_files = (int) ($scan['scanned_files'] ?? ($scan['total_files'] ?? 0));
        $effective_sec = max(0.1, $duration_sec);
        $files_per_sec = round($scanned_files / $effective_sec, 1);

        // CPU Load Average
        $cpu_load = null;
        if (function_exists('sys_getloadavg')) {
            $load = @sys_getloadavg();
            if (is_array($load) && count($load) >= 3) {
                $cpu_load = [
                    '1m'  => round($load[0], 2),
                    '5m'  => round($load[1], 2),
                    '15m' => round($load[2], 2)
                ];
            }
        }

        // Server & System Environment details
        $php_version = PHP_VERSION;
        $php_sapi = php_sapi_name();
        $server_os = php_uname('s') . ' ' . php_uname('r');
        $server_arch = php_uname('m');
        $server_software = isset($_SERVER['SERVER_SOFTWARE']) ? sanitize_text_field(wp_unslash($_SERVER['SERVER_SOFTWARE'])) : 'Unknown';
        $max_execution_time = (int) ini_get('max_execution_time');
        $opcache_status = (extension_loaded('Zend OPcache') && ini_get('opcache.enable')) ? 'Enabled' : 'Disabled';

        // CPU Cores Detection
        $cpu_cores = null;
        $win_cores = getenv('NUMBER_OF_PROCESSORS');
        if ($win_cores && is_numeric($win_cores)) {
            $cpu_cores = (int) $win_cores;
        } elseif (is_readable('/proc/cpuinfo')) {
            $cpuinfo = @file_get_contents('/proc/cpuinfo');
            if ($cpuinfo) {
                $cpu_cores = substr_count($cpuinfo, 'processor');
            }
        }

        global $wpdb;
        $db_version = $wpdb ? $wpdb->db_version() : null;
        $db_name = defined('DB_NAME') ? DB_NAME : null;

        return [
            'duration_seconds'       => round($duration_sec, 2),
            'duration_ms'            => $duration_ms,
            'duration_formatted'     => $duration_fmt,
            'peak_memory_mb'         => $peak_mb,
            'peak_memory_fmt'        => "{$peak_mb} MB",
            'memory_limit_raw'       => $memory_limit_raw,
            'memory_percent'         => $memory_pct,
            'scanned_files'          => $scanned_files,
            'total_files'            => (int) ($scan['total_files'] ?? 0),
            'files_per_second'       => $files_per_sec,
            'cpu_load'               => $cpu_load,
            'cpu_cores'              => $cpu_cores,
            'server_software'        => $server_software,
            'server_os'              => $server_os,
            'server_arch'            => $server_arch,
            'php_version'            => $php_version,
            'php_sapi'               => $php_sapi,
            'php_max_execution_time' => $max_execution_time,
            'database_version'       => $db_version,
            'database_name'          => $db_name,
            'wordpress_version'      => get_bloginfo('version'),
            'ssl_active'             => is_ssl(),
            'opcache_status'         => $opcache_status,
            'engines_active'         => 23,
        ];
    }

    /**
     * Compute real-time telemetry metrics (memory, CPU, speed, progress, system context)
     * during active scan execution for administrator visibility.
     *
     * @param float|null $batch_start_time
     * @param array|null $batch_ru_start
     * @param int $scanned_files
     * @param int $total_files
     * @param int $issues_found
     * @param float $elapsed_sec
     * @param \WebCareProScanner\Resource\ResourceMonitor|null $governor
     * @return array
     */
    public static function get_realtime_resource_stats($batch_start_time = null, $batch_ru_start = null, $scanned_files = 0, $total_files = 0, $issues_found = 0, $elapsed_sec = 0.0, $governor = null) {
        // 1. Memory Metrics
        $mem_bytes = memory_get_usage(true);
        $mem_peak_bytes = memory_get_peak_usage(true);
        $mem_mb = round($mem_bytes / (1024 * 1024), 1);
        $mem_peak_mb = round($mem_peak_bytes / (1024 * 1024), 1);

        $memory_limit_raw = ini_get('memory_limit') ?: '256M';
        $limit_bytes = 256 * 1024 * 1024;
        if ($memory_limit_raw === '-1') {
            $limit_bytes = 0; // unlimited
        } elseif (preg_match('/^(\d+)(.)$/i', $memory_limit_raw, $m)) {
            $val = (int) $m[1];
            $unit = strtoupper($m[2]);
            if ($unit === 'G') $limit_bytes = $val * 1024 * 1024 * 1024;
            elseif ($unit === 'M') $limit_bytes = $val * 1024 * 1024;
            elseif ($unit === 'K') $limit_bytes = $val * 1024;
        }

        $mem_percent = $limit_bytes > 0 ? round(($mem_bytes / $limit_bytes) * 100, 1) : 0.0;
        $mem_peak_percent = $limit_bytes > 0 ? round(($mem_peak_bytes / $limit_bytes) * 100, 1) : 0.0;
        $mem_free_mb = $limit_bytes > 0 ? max(0, round(($limit_bytes - $mem_bytes) / (1024 * 1024), 1)) : 9999.0;

        // 2. CPU / Load Metrics
        $cpu_percent = null;
        if ($batch_start_time && $batch_ru_start && function_exists('getrusage')) {
            $batch_wall_time = max(0.001, microtime(true) - $batch_start_time);
            $ru_end = @getrusage();
            if (is_array($ru_end) && is_array($batch_ru_start)) {
                $user_start = ($batch_ru_start['ru_utime.tv_sec'] ?? 0) + (($batch_ru_start['ru_utime.tv_usec'] ?? 0) / 1000000);
                $sys_start  = ($batch_ru_start['ru_stime.tv_sec'] ?? 0) + (($batch_ru_start['ru_stime.tv_usec'] ?? 0) / 1000000);
                $user_end   = ($ru_end['ru_utime.tv_sec'] ?? 0) + (($ru_end['ru_utime.tv_usec'] ?? 0) / 1000000);
                $sys_end    = ($ru_end['ru_stime.tv_sec'] ?? 0) + (($ru_end['ru_stime.tv_usec'] ?? 0) / 1000000);
                $cpu_time_used = max(0, ($user_end + $sys_end) - ($user_start + $sys_start));
                $cpu_percent = min(100.0, round(($cpu_time_used / $batch_wall_time) * 100, 1));
            }
        }

        $cpu_load = null;
        if (function_exists('sys_getloadavg')) {
            $load = @sys_getloadavg();
            if (is_array($load) && count($load) >= 3) {
                $cpu_load = [
                    '1m'  => round($load[0], 2),
                    '5m'  => round($load[1], 2),
                    '15m' => round($load[2], 2),
                ];
            }
        }

        $cpu_cores = null;
        $win_cores = getenv('NUMBER_OF_PROCESSORS');
        if ($win_cores && is_numeric($win_cores)) {
            $cpu_cores = (int) $win_cores;
        } elseif (is_readable('/proc/cpuinfo')) {
            $cpuinfo = @file_get_contents('/proc/cpuinfo');
            if ($cpuinfo) {
                $cpu_cores = substr_count($cpuinfo, 'processor');
            }
        }

        // 3. Scan Throughput & ETA
        $files_per_sec = ($elapsed_sec > 0 && $scanned_files > 0) ? round($scanned_files / $elapsed_sec, 1) : 0.0;
        $remaining_files = max(0, $total_files - $scanned_files);
        $eta_seconds = ($files_per_sec > 0 && $remaining_files > 0) ? (int) round($remaining_files / $files_per_sec) : null;

        // 4. Server environment details
        $php_version = PHP_VERSION;
        $server_os = php_uname('s');
        $max_exec = (int) ini_get('max_execution_time');

        // 5. Dynamic Governor Telemetry & Visitor Protection Diagnostics
        $governor_info = null;
        if ($governor instanceof \WebCareProScanner\Resource\ResourceMonitor) {
            $governor_info = $governor->get_telemetry_payload();
        } else {
            $temp_gov = new \WebCareProScanner\Resource\ResourceMonitor(70, 18, 'balanced');
            $governor_info = $temp_gov->get_telemetry_payload();
        }

        return [
            'memory_mb'           => $mem_mb,
            'memory_peak_mb'      => $mem_peak_mb,
            'memory_limit_raw'    => $memory_limit_raw,
            'memory_percent'      => $mem_percent,
            'memory_peak_percent' => $mem_peak_percent,
            'memory_free_mb'      => $mem_free_mb,
            'cpu_percent'         => $cpu_percent,
            'cpu_load'            => $cpu_load,
            'cpu_cores'           => $cpu_cores,
            'scanned_files'       => $scanned_files,
            'total_files'         => $total_files,
            'files_per_sec'       => $files_per_sec,
            'eta_seconds'         => $eta_seconds,
            'issues_found'        => $issues_found,
            'php_version'         => $php_version,
            'server_os'           => $server_os,
            'max_execution_time'  => $max_exec,
            'governor'            => $governor_info,
        ];
    }

    

    /**
     * Redact database credentials and secret authentication keys from wp-config.php and env files.
     */
    public static function mask_sensitive_config_content($content) {
        $is_masked = false;

        $sensitive_keys = [
            'DB_NAME', 'DB_USER', 'DB_PASSWORD', 'DB_HOST',
            'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY',
            'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT',
            'FTP_USER', 'FTP_PASS', 'FTP_HOST', 'FTP_BASE',
            'FTP_SSL', 'FTP_SSH', 'FTP_PUBKEY', 'FTP_PRIKEY',
            'WEBCARE_VAULT_KEY', 'WEBCARE_MASTER_KEY', 'WEBCARE_ENCRYPTION_KEY',
            'CLOUDFLARE_API_KEY', 'CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_TOKEN',
        ];

        $keys_pattern = implode('|', array_map('preg_quote', $sensitive_keys));

        // 1. Mask define( 'KEY', 'VALUE' ) or define("KEY", "VALUE") - works across all quote styles and formatting
        $new_content = preg_replace_callback(
            "/define\\s*\\(\\s*(['\"])(" . $keys_pattern . ")\\1\\s*,\\s*([^;)]*?)\\s*\\)/i",
            function ($matches) use (&$is_masked) {
                $is_masked = true;
                $quote = $matches[1];
                $key = $matches[2];
                return "define( {$quote}{$key}{$quote}, '••••••••••••••••' ) /* [REDACTED BY WEBCARE PRO SECURITY] */";
            },
            $content
        );

        // 2. Mask .env style or assignment style: DB_PASSWORD=xxxx or DB_NAME=xxxx
        $env_keys = 'DB_PASSWORD|DB_PASS|DB_USER|DB_USERNAME|DB_HOST|DB_NAME|FTP_PASS|FTP_PASSWORD|WEBCARE_VAULT_KEY|WEBCARE_MASTER_KEY|WEBCARE_ENCRYPTION_KEY|CLOUDFLARE_API_KEY|CLOUDFLARE_API_TOKEN|CLOUDFLARE_TOKEN';
        $new_content = preg_replace_callback(
            "/^(\\s*(" . $env_keys . ")\\s*=\\s*)(.*?)$/mi",
            function ($matches) use (&$is_masked) {
                $is_masked = true;
                $prefix = $matches[1];
                return "{$prefix}'••••••••••••••••' # [REDACTED BY WEBCARE PRO SECURITY]";
            },
            $new_content
        );

        // 3. Mask array or variable assignment style: $db_password = '...' or $_ENV['DB_PASSWORD'] = '...'
        $new_content = preg_replace_callback(
            "/((?:\\\$|\\b_ENV\\[['\"]|\\b_SERVER\\[['\"])(" . $keys_pattern . ")(?:['\"]\\])?\\s*=\\s*)(['\"]).*?\\3/i",
            function ($matches) use (&$is_masked) {
                $is_masked = true;
                $prefix = $matches[1];
                return "{$prefix}'••••••••••••••••' /* [REDACTED BY WEBCARE PRO SECURITY] */";
            },
            $new_content
        );

        return [
            'content'   => $new_content,
            'is_masked' => $is_masked,
        ];
    }

    

    /**
     * Helper to build schedule time info payload
     */
    public static function build_schedule_time_info() {
        $next_run_timestamp = wp_next_scheduled(\WebCareProScanner\System\SettingsManager::CRON_HOOK);
        $now_utc = time();
        $diff_seconds = $next_run_timestamp ? max(0, $next_run_timestamp - $now_utc) : 0;

        $tz_string = get_option('timezone_string');
        $gmt_offset = get_option('gmt_offset');
        if (empty($tz_string)) {
            $offset_sign = $gmt_offset >= 0 ? '+' : '-';
            $offset_hours = abs((int) $gmt_offset);
            $offset_mins = abs((int) (($gmt_offset - (int) $gmt_offset) * 60));
            $tz_string = sprintf('UTC%s%02d:%02d', $offset_sign, $offset_hours, $offset_mins);
        }

        $is_cron_disabled = defined('DISABLE_WP_CRON') && DISABLE_WP_CRON;

        return [
            'next_run_timestamp' => $next_run_timestamp ?: null,
            'next_scheduled_wp'  => $next_run_timestamp ? (function_exists('wp_date') ? wp_date('Y-m-d H:i:s', $next_run_timestamp) : date_i18n('Y-m-d H:i:s', $next_run_timestamp + (int) ($gmt_offset * 3600))) : null,
            'next_scheduled_gmt' => $next_run_timestamp ? gmdate('Y-m-d H:i:s', $next_run_timestamp) . ' GMT' : null,
            'diff_seconds'       => $diff_seconds,
            'current_wp_time'    => current_time('Y-m-d H:i:s'),
            'current_gmt_time'   => gmdate('Y-m-d H:i:s') . ' GMT',
            'timezone'           => $tz_string,
            'gmt_offset'         => (float) $gmt_offset,
            'cron_disabled'      => $is_cron_disabled,
        ];
    }

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    /**
     * Build a method-specific Rule #37 allowlist update, removing equivalent legacy route-only entries.
     *
     * @param array<int,string> $lines
     * @param string            $route
     * @param string            $method
     * @return array{lines:array<int,string>,changed:bool,added:bool,legacy_route_replaced:bool}
     */
    private static function build_method_scoped_rest_allowlist(array $lines, string $route, string $method): array {
        $entry = strtoupper($method) . ' ' . $route;
        $route_key = rtrim('/' . ltrim(strtolower(trim($route)), '/'), '/');
        $result_lines = [];
        $exact_exists = false;
        $legacy_route_replaced = false;

        foreach ($lines as $line) {
            $line = trim((string) $line);
            if ($line === '') {
                continue;
            }

            if (strcasecmp($line, $entry) === 0) {
                $exact_exists = true;
                $result_lines[] = $line;
                continue;
            }

            // Methodless exact routes are legacy all-method grants. A one-click
            // method-specific action replaces them so the broader grant does not remain active.
            $has_method_prefix = (bool) preg_match('/^[A-Za-z]+(?:[,|][A-Za-z]+)*\s+/', $line);
            if (!$has_method_prefix && !str_starts_with($line, '#') && !str_contains($line, '*')) {
                $legacy_key = rtrim('/' . ltrim(strtolower($line), '/'), '/');
                if ($legacy_key === $route_key) {
                    $legacy_route_replaced = true;
                    continue;
                }
            }

            $result_lines[] = $line;
        }

        if (!$exact_exists) {
            $result_lines[] = $entry;
        }

        $result_lines = array_values(array_unique($result_lines));
        return [
            'lines'                 => $result_lines,
            'changed'               => !$exact_exists || $legacy_route_replaced,
            'added'                 => !$exact_exists,
            'legacy_route_replaced' => $legacy_route_replaced,
        ];
    }

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    


    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    /**
     * Helper to load CloudflareService reliably
     */
    private static function ensure_cloudflare_service(): bool {
        if (!class_exists('\WebCareProScanner\Cloudflare\CloudflareService')) {
            $candidates = [
                WEBCAREPROSCAN_PATH . 'includes/Cloudflare/CloudflareService.php',
                WEBCAREPROSCAN_PATH . 'includes/cloudflare/CloudflareService.php',
                WEBCAREPROSCAN_PATH . 'includes/Firewall/CloudflareService.php',
            ];
            foreach ($candidates as $file) {
                if (file_exists($file)) {
                    require_once $file;
                    break;
                }
            }
        }
        return class_exists('\WebCareProScanner\Cloudflare\CloudflareService');
    }

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    // ==========================================
    // 13. Whitelist & False-Positive Endpoints
    // ==========================================

    

    

    

    // ==========================================
    // 14. Behavioral Baseline Engine Endpoints
    // ==========================================

    

    

    

    // ==========================================
    // 15. Transactional Remediation & Rollback
    // ==========================================

    

    

    // ==========================================
    // 16. Model Context Protocol (MCP) Agent Service
    // ==========================================

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    // ==========================================
    // 17. Supply-Chain Defense & SBOM Sentinel Handlers
    // ==========================================

    

    

    

    

    

    

    

    

    

    

    

    

    

    // ==========================================
    // 17.5. Behavioral WAF, Bot Traps & Rate Limiting (Pillar 3)
    // ==========================================

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    // ==========================================
    // 17.6. Zero-Trust Identity, Session Forensics & JIT Elevation (Pillar 4)
    // ==========================================

    

    

    

    

    

    

    

    // ==========================================
    // 18. Unified WebCare Vault Status & Rotator
    // ==========================================

    

    

    

    

    /**
     * Audit exposed sensitive files (.env, debug.log, backup.sql, .git/config, wp-config.php.bak)
     */
    public static function audit_exposed_sensitive_files(string $scan_id): array {
        $findings = [];
        $sensitive_files = [
            '.env'                 => ['severity' => 'critical', 'desc' => 'Environment configuration file containing plain-text database credentials, API keys, or JWT secrets.'],
            'debug.log'            => ['severity' => 'medium',   'desc' => 'WordPress debug log file containing stack traces, SQL errors, or sensitive payload data.'],
            'wp-content/debug.log' => ['severity' => 'medium',   'desc' => 'WordPress debug log in wp-content containing runtime exceptions and system filepaths.'],
            'wp-config.php.bak'    => ['severity' => 'critical', 'desc' => 'Backup copy of wp-config.php accessible via HTTP request, leaking raw database credentials.'],
            'wp-config.bak'        => ['severity' => 'critical', 'desc' => 'Backup copy of wp-config.php accessible via HTTP request.'],
            'wp-config.old'        => ['severity' => 'critical', 'desc' => 'Archived wp-config file leaking database secrets.'],
            '.git/config'          => ['severity' => 'high',     'desc' => 'Exposed Git version control repository exposing source code commits and deploy keys.'],
            'backup.sql'           => ['severity' => 'critical', 'desc' => 'Raw database dump backup file accessible in web root.'],
            'database.sql'         => ['severity' => 'critical', 'desc' => 'Raw database SQL dump file located in publicly accessible folder.'],
        ];

        foreach ($sensitive_files as $rel => $meta) {
            $abs = ABSPATH . $rel;
            if (file_exists($abs) && is_readable($abs)) {
                $size = @filesize($abs) ?: 0;
                $findings[] = new \WebCareProScanner\Findings\Finding([
                    'engine'      => 'system-config',
                    'type'        => 'exposed_sensitive_file',
                    'severity'    => $meta['severity'],
                    'confidence'  => 100,
                    'file_path'   => $rel,
                    'description' => "Publicly accessible sensitive file found: {$rel}. {$meta['desc']}",
                    'evidence'    => "File size: {$size} bytes. Permissions: " . substr(sprintf('%o', fileperms($abs)), -4),
                ]);
            }
        }

        return $findings;
    }

    /**
     * Audit quarantine directory isolation & .htaccess protection
     */
    public static function audit_quarantine_exposure(string $scan_id): array {
        $findings = [];
        $quarantine_dir = \WebCareProScanner\Quarantine\QuarantineManager::get_quarantine_dir();
        if (!is_dir($quarantine_dir)) {
            return $findings;
        }

        $htaccess = rtrim($quarantine_dir, '/\\') . '/.htaccess';
        if (!file_exists($htaccess)) {
            $findings[] = new \WebCareProScanner\Findings\Finding([
                'engine'      => 'quarantine',
                'type'        => 'quarantine_unprotected',
                'severity'    => 'high',
                'confidence'  => 95,
                'file_path'   => str_replace(ABSPATH, '', $quarantine_dir),
                'description' => 'Quarantine isolation storage is missing .htaccess web protection. Quarantined malware could potentially be executed or retrieved via direct URL requests.',
                'evidence'    => 'Missing .htaccess blocking directive in quarantine vault directory.'
            ]);
        } else {
            $content = (string) @file_get_contents($htaccess);
            if (strpos($content, 'Deny from all') === false && strpos($content, 'Require all denied') === false) {
                $findings[] = new \WebCareProScanner\Findings\Finding([
                    'engine'      => 'quarantine',
                    'type'        => 'quarantine_permissive_access',
                    'severity'    => 'medium',
                    'confidence'  => 90,
                    'file_path'   => str_replace(ABSPATH, '', $htaccess),
                    'description' => 'Quarantine .htaccess directive does not include strict "Require all denied" or "Deny from all" access control.',
                    'evidence'    => 'Permissive quarantine web server rule.'
                ]);
            }
        }

        return $findings;
    }

    /**
     * Audit visitor IP detection headers & reverse proxy trust with high-level architecture intelligence.
     *
     * Handles:
     * 1. Localhost / Docker / Local Development: Auto-suppressed (100% normal for local testing).
     * 2. Direct VPS / Dedicated / Shared Hosting: Verifies raw public visitor IP (Direct mode, healthy).
     * 3. Reverse Proxies & CDNs: Inspects all 8 standard proxy headers (Cloudflare, AWS ALB, Nginx, Fastly, Akamai, RFC 7239).
     * 4. WP-Cron & CLI executions: Ignores internal loopback runs to prevent false-positives.
     */
    public static function audit_visitor_ip_detection(string $scan_id): array {
        $findings = [];

        // 1. Check for CLI, WP-Cron, or internal self-scan contexts
        if ((php_sapi_name() === 'cli') || defined('WP_CLI') || (defined('DOING_CRON') && DOING_CRON)) {
            return [];
        }

        // 2. High-Level Localhost & Containerized Environment Intelligence
        $env_type = function_exists('wp_get_environment_type') ? wp_get_environment_type() : (defined('WP_ENVIRONMENT_TYPE') ? WP_ENVIRONMENT_TYPE : 'production');
        $is_local_env = in_array($env_type, ['local', 'development'], true);

        $site_url = get_site_url();
        $host = wp_parse_url($site_url, PHP_URL_HOST) ?: '';
        $is_local_host = in_array($host, ['localhost', '127.0.0.1', '::1'], true)
            || (bool) preg_match('/\.(local|test|site|internal|lan|docker|localwp|ddev)$/i', $host);

        $is_docker = file_exists('/.dockerenv')
            || (file_exists('/proc/1/cgroup') && strpos(@file_get_contents('/proc/1/cgroup'), 'docker') !== false);

        // If running in local development or Docker container environment, internal IPs are standard and safe
        if ($is_local_env || $is_local_host || $is_docker) {
            return [];
        }

        $remote_addr = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field((string) wp_unslash($_SERVER['REMOTE_ADDR'])) : '';
        if (empty($remote_addr)) {
            return [];
        }

        // 3. Loopback Request Check (Server connecting to itself via HTTP loopback during background audit)
        $server_addr = isset($_SERVER['SERVER_ADDR']) ? sanitize_text_field((string) wp_unslash($_SERVER['SERVER_ADDR'])) : '';
        if ($remote_addr === '127.0.0.1' || $remote_addr === '::1' || ($server_addr && $remote_addr === $server_addr)) {
            return [];
        }

        // 4. Direct Public Connection Mode (VPS / Dedicated / Shared hosting with no CDN or reverse proxy)
        // If REMOTE_ADDR is already a public non-private IP, direct visitor logging is operating correctly!
        $is_public_remote = filter_var($remote_addr, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
        if ($is_public_remote) {
            return [];
        }

        // 5. Multi-Architecture Reverse Proxy & CDN Header Detection
        // Inspects all 8 standard reverse proxy headers across Cloudflare, AWS ALB, Nginx, Fastly, Akamai, Traefik, RFC 7239
        $proxy_headers = [
            'HTTP_CF_CONNECTING_IP',       // Cloudflare
            'HTTP_X_FORWARDED_FOR',        // Standard Reverse Proxy / AWS ALB / GCP
            'HTTP_X_REAL_IP',              // Nginx Upstream
            'HTTP_TRUE_CLIENT_IP',         // Akamai & Cloudflare Enterprise
            'HTTP_FASTLY_CLIENT_IP',       // Fastly CDN
            'HTTP_FORWARDED',              // RFC 7239 Standard (Forwarded: for=...)
            'HTTP_X_CLUSTER_CLIENT_IP',    // Clustered Load Balancers
            'HTTP_CLIENT_IP',              // Apache mod_remoteip / Proxies
        ];

        foreach ($proxy_headers as $hdr) {
            if (!empty($_SERVER[$hdr])) {
                $raw_val = sanitize_text_field((string) wp_unslash($_SERVER[$hdr]));
                // RFC 7239 Forwarded: for=198.51.100.1
                if ($hdr === 'HTTP_FORWARDED' && preg_match('/for="?([^";,\s]+)"?/i', $raw_val, $fm)) {
                    $raw_val = $fm[1];
                }
                $first_ip = trim(explode(',', $raw_val)[0]);
                // If a valid IP was forwarded by any proxy/CDN, headers are operating properly
                if (filter_var($first_ip, FILTER_VALIDATE_IP)) {
                    return [];
                }
            }
        }

        // 6. Genuine Live Production Misconfiguration Alert:
        // A live production website on a public domain is receiving external traffic through a private upstream IP
        // with ZERO forwarding headers, collapsing all visitor IPs into a single internal proxy address.
        $evidence_payload = [
            'remote_addr'      => $remote_addr,
            'environment'      => $env_type,
            'is_server_config' => true,
            'is_network'       => true,
            'remediation'      => [
                'type'        => 'reverse_proxy_config',
                'description' => 'Configure your reverse proxy (Nginx, Apache, or Cloudflare) to pass standard visitor IP headers (X-Forwarded-For or CF-Connecting-IP), or define reverse proxy headers in wp-config.php.',
                'wp_config_snippet' => "if (isset(\$_SERVER['HTTP_X_FORWARDED_FOR'])) {\n    \$ips = explode(',', \$_SERVER['HTTP_X_FORWARDED_FOR']);\n    \$_SERVER['REMOTE_ADDR'] = trim(\$ips[0]);\n}",
            ],
        ];

        $findings[] = new \WebCareProScanner\Findings\Finding([
            'engine'      => 'ip-detection',
            'type'        => 'reverse_proxy_misconfigured',
            'severity'    => 'medium',
            'confidence'  => 85,
            'file_path'   => 'server:REMOTE_ADDR',
            'description' => "Server REMOTE_ADDR is an internal or loopback IP ({$remote_addr}) while no reverse proxy forwarding header was received. Rate limiting and IP bans may affect all visitors uniformly.",
            'evidence'    => wp_json_encode($evidence_payload)
        ]);

        return $findings;
    }

    /**
     * Audit password strength against common predictable dictionary terms
     */
    public static function audit_password_strength(string $scan_id): array {
        $findings = [];
        $common_passwords = [
            'password', '123456', '12345678', '123456789', 'admin', 'admin123',
            'root', 'welcome', 'qwerty', 'login', 'pass123', 'wordpress', 'master',
            'pass@123', 'admin@123', 'change_me', 'iloveyou'
        ];

        $admins = get_users(['role' => 'administrator', 'number' => 50]);
        foreach ($admins as $admin) {
            $test_passwords = array_unique(array_filter([
                $admin->user_login,
                strtolower($admin->user_login),
                $admin->user_nicename,
                $admin->display_name,
                strtolower(get_bloginfo('name')),
                ...$common_passwords,
            ]));

            foreach ($test_passwords as $weak_pwd) {
                if (strlen($weak_pwd) < 3) continue;
                if (wp_check_password($weak_pwd, $admin->user_pass, $admin->ID)) {
                    $findings[] = new \WebCareProScanner\Findings\Finding([
                        'engine'      => 'user-credentials',
                        'type'        => 'weak_admin_password',
                        'severity'    => 'critical',
                        'confidence'  => 100,
                        'file_path'   => "user:{$admin->ID} ({$admin->user_login})",
                        'description' => "CRITICAL: Administrator account '{$admin->user_login}' has an extremely weak password matching common dictionary entries or account username.",
                        'evidence'    => "Password match verified against high-frequency attack wordlist. Immediate password change required."
                    ]);
                    break;
                }
            }
        }

        return $findings;
    }

    /**
     * Monitor disk space & inode capacity
     */
    public static function audit_disk_space(string $scan_id): array {
        $findings = [];
        $path = untrailingslashit(ABSPATH);
        $total = @disk_total_space($path);
        $free = @disk_free_space($path);

        if ($total && $free && $total > 0) {
            $used = $total - $free;
            $percent_used = round(($used / $total) * 100, 1);
            $free_mb = round($free / 1024 / 1024);

            if ($percent_used >= 95 || $free_mb < 250) {
                $findings[] = new \WebCareProScanner\Findings\Finding([
                    'engine'      => 'system-storage',
                    'type'        => 'disk_space_critical',
                    'severity'    => 'critical',
                    'confidence'  => 100,
                    'file_path'   => 'system:storage:disk',
                    'description' => "Server disk space is dangerously exhausted ({$percent_used}% used, only {$free_mb} MB available). Risk of immediate database corruption, failed updates, and log write halts.",
                    'evidence'    => "Total: " . round($total / 1024 / 1024 / 1024, 2) . " GB, Free: " . round($free / 1024 / 1024 / 1024, 2) . " GB ({$percent_used}% used)."
                ]);
            } elseif ($percent_used >= 88) {
                $findings[] = new \WebCareProScanner\Findings\Finding([
                    'engine'      => 'system-storage',
                    'type'        => 'disk_space_warning',
                    'severity'    => 'medium',
                    'confidence'  => 95,
                    'file_path'   => 'system:storage:disk',
                    'description' => "Server disk space usage is high ({$percent_used}% used, {$free_mb} MB available). Consider pruning old backups or log files.",
                    'evidence'    => "Used: {$percent_used}%."
                ]);
            }
        }

        return $findings;
    }

    /**
     * Monitor Web Application Firewall status
     */
    public static function audit_waf_status(string $scan_id): array {
        $findings = [];
        $waf_enabled = \WebCareProScanner\System\SettingsManager::get('waf_enabled', true);
        $waf_mode = \WebCareProScanner\System\SettingsManager::get('waf_mode', 'enabled');

        if (!$waf_enabled || $waf_mode === 'disabled') {
            $findings[] = new \WebCareProScanner\Findings\Finding([
                'engine'      => 'firewall',
                'type'        => 'waf_inactive',
                'severity'    => 'high',
                'confidence'  => 100,
                'file_path'   => 'firewall:status',
                'description' => 'Web Application Firewall (WAF) is currently disabled. Incoming malicious HTTP payloads (SQLi, XSS, Path Traversal) are not being filtered at the application boundary.',
                'evidence'    => 'WAF state: disabled in plugin security settings.'
            ]);
        } elseif ($waf_mode === 'learning') {
            $findings[] = new \WebCareProScanner\Findings\Finding([
                'engine'      => 'firewall',
                'type'        => 'waf_learning_mode',
                'severity'    => 'low',
                'confidence'  => 100,
                'file_path'   => 'firewall:status',
                'description' => 'Web Application Firewall is in Learning Mode. Requests are being inspected and logged but malicious requests are not actively blocked.',
                'evidence'    => 'WAF mode: learning.'
            ]);
        }

        return $findings;
    }

    /**
     * Reputation checks (Domain blocklist, Spamvertised, Spam IP)
     */
    public static function audit_reputation_checks(string $scan_id, array $opts): array {
        $findings = [];
        $site_url = get_bloginfo('url');
        $host = wp_parse_url($site_url, PHP_URL_HOST);

        // Allow test domain/IP override via options or filter for testing/verification
        $test_host = apply_filters('webcareproscan_test_reputation_domain', $opts['test_domain'] ?? null);
        if (!empty($test_host)) {
            $host = $test_host;
        }

        // Skip loopback/local dev hosts for public DNSBL checks unless a test domain is explicitly passed
        $is_local_host = in_array(strtolower((string)$host), ['localhost', '127.0.0.1', '::1'], true) || preg_match('/\.(local|test|example|invalid)$/i', (string)$host);

        // 1. Check if website is on a domain blocklist (Spamhaus DBL & SURBL)
        if (!empty($opts['check_domain_blocklist']) && !empty($host) && (!$is_local_host || !empty($test_host))) {
            // Forward lookup format: {domain}.dbl.spamhaus.org
            $dbl_query = "{$host}.dbl.spamhaus.org";
            $ip = @gethostbyname($dbl_query);
            // 127.0.1.x indicates legitimate Spamhaus DBL listing; 127.255.255.x indicates public resolver rate-limit
            if ($ip && $ip !== $dbl_query && strpos($ip, '127.0.1.') === 0) {
                $findings[] = new \WebCareProScanner\Findings\Finding([
                    'engine'      => 'reputation',
                    'type'        => 'domain_blocklisted',
                    'severity'    => 'critical',
                    'confidence'  => 95,
                    'file_path'   => "domain:{$host}",
                    'description' => "CRITICAL REPUTATION ALERT: The domain '{$host}' is listed on the Spamhaus Domain Blocklist (DBL) as spam, malicious, or compromised.",
                    'evidence'    => "Spamhaus DBL response code: {$ip}"
                ]);
            }
        }

        // 2. Check if website is being "Spamvertised" (SURBL multi.surbl.org)
        if (!empty($opts['check_spamvertised']) && !empty($host) && (!$is_local_host || !empty($test_host))) {
            $surbl_query = "{$host}.multi.surbl.org";
            $surbl_res = @gethostbyname($surbl_query);
            if ($surbl_res && $surbl_res !== $surbl_query && strpos($surbl_res, '127.0.0.') === 0) {
                $findings[] = new \WebCareProScanner\Findings\Finding([
                    'engine'      => 'reputation',
                    'type'        => 'domain_spamvertised',
                    'severity'    => 'critical',
                    'confidence'  => 95,
                    'file_path'   => "domain:{$host}",
                    'description' => "CRITICAL REPUTATION ALERT: The domain '{$host}' is listed on SURBL as actively 'Spamvertised' in bulk unsolicited email or phishing campaigns.",
                    'evidence'    => "SURBL return code: {$surbl_res}"
                ]);
            }
        }

        // 3. Check if website IP is generating spam (Spamcop, Barracuda, Spamhaus ZEN)
        if (!empty($opts['check_spam_ip'])) {
            $test_ip = apply_filters('webcareproscan_test_reputation_ip', $opts['test_ip'] ?? null);
            $raw_srv_ip = isset($_SERVER['SERVER_ADDR']) ? sanitize_text_field((string) wp_unslash($_SERVER['SERVER_ADDR'])) : '';
            $server_ip = !empty($test_ip) ? $test_ip : ($raw_srv_ip ?: gethostbyname($host ?: 'localhost'));

            if (filter_var($server_ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) || !empty($test_ip)) {
                $rev_ip = implode('.', array_reverse(explode('.', $server_ip)));

                // 3.1 Spamcop SCBL
                $spamcop_query = "{$rev_ip}.bl.spamcop.net";
                $sc_res = @gethostbyname($spamcop_query);
                if ($sc_res && $sc_res !== $spamcop_query && strpos($sc_res, '127.0.0.') === 0) {
                    $findings[] = new \WebCareProScanner\Findings\Finding([
                        'engine'      => 'reputation',
                        'type'        => 'server_ip_spam_blocklisted',
                        'severity'    => 'high',
                        'confidence'  => 95,
                        'file_path'   => "ip:{$server_ip}",
                        'description' => "Server outbound IP '{$server_ip}' is actively listed on the Spamcop Blocking List (SCBL) as an active source of unsolicited spam.",
                        'evidence'    => "Spamcop DNSBL code: {$sc_res}"
                    ]);
                }

                // 3.2 Barracuda Reputation Network (BRBL)
                $barracuda_query = "{$rev_ip}.b.barracudacentral.org";
                $bc_res = @gethostbyname($barracuda_query);
                if ($bc_res && $bc_res !== $barracuda_query && strpos($bc_res, '127.0.0.') === 0) {
                    $findings[] = new \WebCareProScanner\Findings\Finding([
                        'engine'      => 'reputation',
                        'type'        => 'server_ip_spam_blocklisted',
                        'severity'    => 'high',
                        'confidence'  => 90,
                        'file_path'   => "ip:{$server_ip}",
                        'description' => "Server outbound IP '{$server_ip}' is listed on the Barracuda Reputation Network blocklist (BRBL). Outbound transactional emails may be rejected as spam.",
                        'evidence'    => "Barracuda DNSBL code: {$bc_res}"
                    ]);
                }

                // 3.3 Spamhaus ZEN
                $zen_query = "{$rev_ip}.zen.spamhaus.org";
                $zen_res = @gethostbyname($zen_query);
                if ($zen_res && $zen_res !== $zen_query && strpos($zen_res, '127.0.0.') === 0) {
                    $findings[] = new \WebCareProScanner\Findings\Finding([
                        'engine'      => 'reputation',
                        'type'        => 'server_ip_spam_blocklisted',
                        'severity'    => 'high',
                        'confidence'  => 90,
                        'file_path'   => "ip:{$server_ip}",
                        'description' => "Server outbound IP '{$server_ip}' is listed on the Spamhaus ZEN anti-spam database. Outbound transactional emails may be rejected as spam.",
                        'evidence'    => "Spamhaus ZEN code: {$zen_res}"
                    ]);
                }
            }
        }

        return $findings;
    }

    // ==========================================
    // 16. Plugin Self-Defense & Anti-Tamper Endpoints
    // ==========================================

    

    

    

    

    // =========================================================================
    // Pillar 5: Continuous Threat Intel Network & Automated Virtual Patching Ecosystem
    // =========================================================================

    

    

    

    

    

    

    

    

    

    

    

    // =========================================================================
    // 20. 2026 AI Threat Defense, MCP Governance & Decoy Ghost Routes Handlers
    // =========================================================================

    

    

    

    

    

    

    

    

    

    

    

    

    

    // ==========================================
    // Phase 5: 72-Hour Reinfection Watchdog Handlers
    // ==========================================

    

    

    

    

    // ==========================================
    // Phase 5: "Time-Machine" Local Snapshots Handlers
    // ==========================================

    

    

    

    

    

    

    // ==========================================
    // Phase 5: Domain Reputation & SSL Sentinel Handlers
    // ==========================================

    

    

    // ==========================================
    // Phase 6: Threat Correlation Hierarchy Handlers
    // ==========================================

    

    // ==========================================
    // Phase 6: WebAuthn Passkeys (Biometric FIDO2) Handlers
    // ==========================================

    

    

    

    

    

    

    

    // ==========================================
    // Phase 6: Server Security Verification & Caddy
    // ==========================================

    

    

    // ==========================================
    // 21. Activity & Forensic Audit Log Handlers
    // ==========================================

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

    

}
