<?php
declare(strict_types=1);

namespace WebCareProScanner\Api\Controllers;

use WebCareProScanner\Api\ScannerRoutes;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * ScanController
 *
 * Scan & Vulnerability Management REST Controller.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
final class ScanController extends AbstractApiController {

    /**
     * Register endpoints for this domain.
     *
     * @param string   $namespace REST API route namespace.
     * @param callable $permission Permission callback.
     */
    public static function register(string $namespace, callable $permission): void {
        register_rest_route($namespace, '/scan/start', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'start_scan'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/scan/batch', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'process_batch'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/scan/deep-audit', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'run_deep_audit'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/scan/latest', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_latest_scan'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/scan/active', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_active_scan'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/scan/abort', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'abort_scan'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/scan/history', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_scan_history'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/scan/history/clear', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'clear_scan_history'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/scan/history/(?P<id>\d+)', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_scan_log_detail'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/scan/export', [
            'methods'             => ['GET', 'POST'],
            'callback'            => [self::class, 'export_scan_results'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/scan/manifest', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_scan_manifest'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/scan/manifest/download', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'download_scan_manifest'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/vulnerabilities/report', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_vulnerabilities_report'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/file/view', [
            'methods'             => ['GET', 'POST'],
            'callback'            => [self::class, 'view_file_content'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/post/view', [
            'methods'             => ['GET', 'POST'],
            'callback'            => [self::class, 'view_post_content'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/component/changelog', [
            'methods'             => ['GET', 'POST'],
            'callback'            => [self::class, 'get_component_changelog'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/issues/(?P<id>\d+)', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'update_issue'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/vulnerabilities/virtual-shield', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'activate_vulnerability_virtual_shield'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/vulnerabilities/safe-update', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'execute_safe_plugin_update'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/vulnerabilities/safe-rollback', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'execute_safe_plugin_rollback'],
            'permission_callback' => $permission,
        ]);

    }

    public static function get_scan_manifest(\WP_REST_Request $request) {
        if (is_multisite() && !current_user_can('manage_network')) {
            return new \WP_Error('rest_forbidden', __('Multisite network administrator privileges required.', 'webcare-pro-security'), ['status' => 403]);
        }

        $scan_id = (int) $request->get_param('scan_id');
        if ($scan_id <= 0) {
            global $wpdb;
            $table_scans = $wpdb->prefix . 'webcareproscan_scans';
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $scan_id = (int) $wpdb->get_var($wpdb->prepare('SELECT id FROM %i ORDER BY id DESC LIMIT 1', $table_scans));
        }

        if ($scan_id <= 0) {
            return new \WP_Error('no_scans', __('No scans found.', 'webcare-pro-security'), ['status' => 404]);
        }

        $page     = max(1, (int) $request->get_param('page'));
        $per_page = max(1, min(500, (int) ($request->get_param('per_page') ?: 50)));
        $search   = sanitize_text_field((string) $request->get_param('search'));
        $status   = sanitize_text_field((string) $request->get_param('status'));

        $summary = null;
        $result  = null;
        if (class_exists('\\WebCareProScanner\\Scan\\ScanVaultManager')) {
            $summary = \WebCareProScanner\Scan\ScanVaultManager::get_manifest_summary($scan_id);
            // Correct parameter order: ($scan_id, $page, $limit, $status, $search)
            $result  = \WebCareProScanner\Scan\ScanVaultManager::get_manifest_files($scan_id, $page, $per_page, $status, $search);
        }

        // Fallback for legacy scans stored in MySQL table only when no Vault manifest exists
        if (!$result || empty($result['success'])) {
            global $wpdb;
            $table_files = $wpdb->prefix . 'webcareproscan_scan_files';
            $where = ['scan_id = %d'];
            $params = [$scan_id];
            if ($status) {
                $where[] = 'status = %s';
                $params[] = $status;
            }
            if ($search) {
                $where[] = 'file_path LIKE %s';
                $params[] = '%' . $wpdb->esc_like($search) . '%';
            }
            $where_sql = implode(' AND ', $where);
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $total_legacy = (int) $wpdb->get_var(
                // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare -- $where_sql is assembled from fixed clauses and placeholders above; all request values are passed as prepared arguments.
                $wpdb->prepare("SELECT COUNT(*) FROM %i WHERE {$where_sql}", ...array_merge([$table_files], $params))
            );
            $offset = ($page - 1) * $per_page;
            $params_page = array_merge($params, [$per_page, $offset]);
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $legacy_files = $wpdb->get_results(
                // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber -- $where_sql is assembled from fixed clauses and placeholders above; table name and all request values are supplied as prepared arguments.
                $wpdb->prepare("SELECT * FROM %i WHERE {$where_sql} ORDER BY id ASC LIMIT %d OFFSET %d", ...array_merge([$table_files], $params_page)),
                ARRAY_A
            ) ?: [];

            $result = [
                'success'     => true,
                'files'       => $legacy_files,
                'total'       => $total_legacy,
                'total_count' => $total_legacy,
                'page'        => $page,
                'limit'       => $per_page,
                'per_page'    => $per_page,
                'total_pages' => (int) ceil($total_legacy / max(1, $per_page)),
                'source'      => 'legacy_database',
            ];
        }

        return rest_ensure_response([
            'success'   => true,
            'scan_id'   => $scan_id,
            'summary'   => $summary,
            'manifest'  => $result,
        ]);
    }

    public static function start_scan(\WP_REST_Request $request) {
        global $wpdb;

        // Check for concurrent active scan lock
        $locked_id = ScanLock::get_locked_scan_id();
        if ($locked_id) {
            $table_scans = $wpdb->prefix . 'webcareproscan_scans';
            $exist_sql = "SELECT * FROM `{$table_scans}` WHERE id = %d";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $existing_scan = $wpdb->get_row(
                // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                $wpdb->prepare($exist_sql, $locked_id),
                ARRAY_A
            );
            if (!$existing_scan || $existing_scan['status'] !== 'running') {
                ScanLock::force_release($locked_id);
            } else {
                $existing_token = ScanLock::get_active_lease_token($locked_id);
                if (empty($existing_token)) {
                    // Stored lease is corrupted or missing token -> force release and allow fresh scan
                    ScanLock::force_release($locked_id);
                } else {
                    $remaining = \WebCareProScanner\Scan\ScanQueueManager::get_remaining_count($locked_id);
                    return rest_ensure_response([
                        'success'       => true,
                        'scan_id'       => $locked_id,
                        'lease_token'   => $existing_token,
                        'scan_target'   => $existing_scan['scan_target'],
                        'total_files'   => (int) $existing_scan['total_files'],
                        'scanned_files' => (int) $existing_scan['scanned_files'],
                        'remaining'     => $remaining,
                        'status'        => 'running',
                        'resumed'       => true,
                    ]);
                }
            }
        }

        $target = sanitize_text_field($request->get_param('target') ?: 'plugins_themes');
        $custom_options = $request->get_param('custom_options');
        if (!is_array($custom_options)) {
            $settings = \WebCareProScanner\System\SettingsManager::get_settings();
            $custom_options = $settings['custom_scan_options'] ?? \WebCareProScanner\System\SettingsManager::get_default_custom_scan_options();
        } else {
            $custom_options = \WebCareProScanner\System\SettingsManager::sanitize_custom_scan_options($custom_options);
        }
        
        $paths = [];

        // Determine scannable filesystem files based on scan profile (0 = unlimited)
        $file_limit = (int) apply_filters('webcareproscan_file_limit', 0, $target);

        if ($target === 'custom') {
            $has_filesystem_scan = !empty($custom_options['scan_known_malware'])
                || !empty($custom_options['scan_backdoors_heuristics'])
                || !empty($custom_options['scan_malicious_urls'])
                || !empty($custom_options['scan_core_integrity'])
                || !empty($custom_options['scan_theme_integrity'])
                || !empty($custom_options['scan_plugin_integrity'])
                || !empty($custom_options['scan_unbundled_files'])
                || !empty($custom_options['scan_outside_root'])
                || !empty($custom_options['scan_images_executable']);

            if ($has_filesystem_scan) {
                if (!empty($custom_options['scan_outside_root'])) {
                    $parent = dirname(ABSPATH);
                    if (is_dir($parent) && is_readable($parent) && realpath($parent) !== realpath(ABSPATH)) {
                        $paths[] = untrailingslashit($parent);
                    } else {
                        $paths[] = untrailingslashit(ABSPATH);
                    }
                } elseif (!empty($custom_options['scan_core_integrity']) || !empty($custom_options['scan_unbundled_files'])) {
                    $paths[] = untrailingslashit(ABSPATH);
                } else {
                    if (!empty($custom_options['scan_plugin_integrity'])) {
                        $paths[] = WP_PLUGIN_DIR;
                    }
                    if (!empty($custom_options['scan_theme_integrity'])) {
                        $paths[] = get_theme_root();
                    }
                    if (empty($paths)) {
                        $paths[] = untrailingslashit(ABSPATH);
                    }
                }
            }
        } elseif (in_array($target, ['unknown_files', 'spam_content', 'user_security', 'outdated_software', 'suspicious_uploads', 'crontab_audit', 'core_integrity', 'rogue_admin', 'hook_sentinel', 'modified_files'], true)) {
            // Targeted deep engines do not queue filesystem files
            $paths = [];
        } elseif ($target === 'filesystem_only' || $target === 'full') {
            $paths[] = untrailingslashit(ABSPATH);
        } else { // default plugins_themes
            $paths[] = WP_PLUGIN_DIR;
            $paths[] = get_theme_root();
        }

        $table_scans = $wpdb->prefix . 'webcareproscan_scans';
        $now_exact = self::now_fractional_mysql();
        $start_micro = microtime(true);

        // Pre-insert scan record to obtain unique scan_id
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->insert($table_scans, [
            'status'        => 'running',
            'scan_target'   => $target,
            'trigger_type'  => 'manual',
            'scanned_files' => 0,
            'total_files'   => 0,
            'issues_found'  => 0,
            'risk_score'    => 0,
            'duration'      => 0,
            'duration_ms'   => 0,
            'created_at'    => current_time('mysql'),
            'created_at_gmt'=> gmdate('Y-m-d H:i:s'),
            'started_at'    => $now_exact,
        ]);
        $scan_id = (int) $wpdb->insert_id;

        // Acquire lock
        if (!ScanLock::acquire($scan_id)) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->delete($table_scans, ['id' => $scan_id]);
            return new \WP_Error(
                'scan_locked',
                __('A security scan is currently running in another process or held by a concurrent lock.', 'webcare-pro-security'),
                ['status' => 409]
            );
        }
        $lease_token = ScanLock::get_active_lease_token($scan_id);
        if (empty($lease_token)) {
            ScanLock::force_release($scan_id);
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->delete($table_scans, ['id' => $scan_id]);
            return new \WP_Error(
                'scan_lease_token_failed',
                __('Failed to acquire a valid cryptographic scan lease token.', 'webcare-pro-security'),
                ['status' => 500]
            );
        }

        // Initialize high-performance streaming session queue on disk
        $total_files = 0;
        if (!empty($paths)) {
            $total_files = \WebCareProScanner\Scan\ScanQueueManager::init_queue($scan_id, $paths, $file_limit);
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->update($table_scans, [
            'total_files' => $total_files,
        ], ['id' => $scan_id]);

        if ($target === 'custom' && !empty($custom_options)) {
            set_transient("webcareproscan_custom_options_{$scan_id}", $custom_options, HOUR_IN_SECONDS);
        }

        set_transient("webcareproscan_scan_start_micro_{$scan_id}", $start_micro, HOUR_IN_SECONDS);

        $init_telemetry = self::get_realtime_resource_stats(null, null, 0, $total_files, 0, 0.0);
        set_transient("webcareproscan_scan_live_telemetry_{$scan_id}", $init_telemetry, 600);

        // Schedule background continuation worker so the scan continues autonomously if the user navigates away
        if (class_exists('\\WebCareProScanner\\Scan\\ScanBackgroundWorker')) {
            \WebCareProScanner\Scan\ScanBackgroundWorker::schedule_continuation(10);
        }

        return rest_ensure_response([
            'success'     => true,
            'scan_id'     => $scan_id,
            'lease_token' => $lease_token,
            'total_files' => $total_files,
            'status'      => 'running',
            'started_at'  => $now_exact,
            'telemetry'   => $init_telemetry,
        ]);
    }

    public static function process_batch(\WP_REST_Request $request) {
        global $wpdb;

        $scan_id = (int) $request->get_param('scan_id');
        $lease_token = sanitize_text_field((string) ($request->get_param('lease_token') ?? ''));
        if (empty($lease_token)) {
            return new \WP_Error(
                'invalid_lease_token',
                __('Valid scan lease token is required for batch execution.', 'webcare-pro-security'),
                ['status' => 403]
            );
        }

        $configured_batch = (int) \WebCareProScanner\System\SettingsManager::get('scan_batch_size', 50);
        $param_batch = (int) $request->get_param('batch_size');
        $batch_size = $param_batch > 0 ? max($param_batch, $configured_batch) : $configured_batch;
        $batch_start = microtime(true);
        $batch_ru_start = function_exists('getrusage') ? @getrusage() : null;

        // Acquire per-batch mutex and verify active scan lease
        if (!ScanLock::acquire_batch_lock($scan_id, $lease_token)) {
            return new \WP_Error(
                'scan_lock_conflict',
                __('Concurrent scan batch execution rejected or active scan lease not held.', 'webcare-pro-security'),
                ['status' => 409]
            );
        }

        // Record live touch timestamp if request originated from active browser session
        if (!empty($request->get_param('from_browser')) || (defined('DOING_CRON') && !DOING_CRON)) {
            set_transient("webcareproscan_active_scan_last_browser_touch_{$scan_id}", microtime(true), 120);
        }

        // Keep background continuation armed with a grace delay
        if (class_exists('\\WebCareProScanner\\Scan\\ScanBackgroundWorker')) {
            \WebCareProScanner\Scan\ScanBackgroundWorker::schedule_continuation(12);
        }

        // Initialize Dynamic Resource Governor
        $governor = new \WebCareProScanner\Resource\ResourceMonitor(70, 18, 'balanced');
        $effective_batch_size = $governor->get_adaptive_batch_size($batch_size);

        $batch_data = \WebCareProScanner\Scan\ScanQueueManager::get_batch($scan_id, $effective_batch_size);
        $files_to_process = $batch_data['files'];
        $line_bytes = $batch_data['line_bytes'];
        $remaining = $batch_data['remaining'];

        if (empty($files_to_process)) {
            // Check if scan exists in DB to prevent hard 404 failure
            $check_sql = "SELECT id FROM {$wpdb->prefix}webcareproscan_scans WHERE id = %d";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $scan_exists = $wpdb->get_var(
                // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                $wpdb->prepare($check_sql, $scan_id)
            );
            if ($scan_exists) {
                \WebCareProScanner\Scan\ScanQueueManager::cleanup($scan_id);
                ScanLock::release_batch_lock();
                return rest_ensure_response([
                    'success'     => true,
                    'is_finished' => true,
                    'remaining'   => 0,
                    'processed'   => 0,
                    'last_file'   => '',
                ]);
            }
            ScanLock::release_batch_lock();
            return new \WP_Error('scan_not_found', 'Scan queue expired or not found', ['status' => 404]);
        }

        $table_scans = $wpdb->prefix . 'webcareproscan_scans';
        $table_issues = $wpdb->prefix . 'webcareproscan_scan_issues';
        $table_files = $wpdb->prefix . 'webcareproscan_scan_files';

        $file_scanner = new FileScanner();
        $processed_count = 0;
        $accumulated_weight = 0.0;
        $bytes_consumed = 0;
        $batch_files_records = [];

        foreach ($files_to_process as $idx => $filepath) {
            // Adaptive breathing and resource headroom check before each file
            if ($governor->throttle_and_check()) {
                break;
            }

            // Update live heartbeat and last active file path
            set_transient("webcareproscan_active_scan_file_{$scan_id}", $filepath, 120);

            // Factor in file complexity weight
            $weight = \WebCareProScanner\Resource\ResourceMonitor::get_file_weight($filepath);
            $accumulated_weight += $weight;

            // If heavy files filled the batch weight budget early, save remaining and yield
            if ($accumulated_weight >= ($effective_batch_size * 1.25) && $processed_count > 10) {
                break;
            }

            $findings = $file_scanner->scan_file($filepath, (string) $scan_id);
            $rel_path = ltrim(str_replace(wp_normalize_path(ABSPATH), '', wp_normalize_path($filepath)), '/');
            $file_size = @filesize($filepath) ?: 0;
            $file_status = !empty($findings) ? 'threat' : 'clean';

            $batch_files_records[] = [
                'file_path'    => $rel_path,
                'full_path'    => $filepath,
                'file_size'    => $file_size,
                'status'       => $file_status,
                'threat_count' => count($findings),
            ];

            $processed_count++;
            if (!empty($line_bytes[$idx])) {
                $bytes_consumed += $line_bytes[$idx];
            }

            foreach ($findings as $f) {
                $item = $f->to_array();
                $matched_rule = \WebCareProScanner\Findings\WhitelistManager::match_finding($item);
                $status = ($matched_rule !== null) ? 'ignored' : 'open';

                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                $wpdb->insert($table_issues, [
                    'scan_id'      => $scan_id,
                    'engine'       => $item['engine'],
                    'type'         => $item['type'],
                    'severity'     => $item['severity'],
                    'confidence'   => $item['confidence'],
                    'file_path'    => $item['file_path'],
                    'line_number'  => $item['line_number'] ?? null,
                    'code_snippet' => $item['code_snippet'] ?? null,
                    'evidence'     => $item['evidence'] ?? null,
                    'description'  => $item['description'],
                    'status'       => $status,
                    'created_at'   => current_time('mysql'),
                    'created_at_gmt'=> gmdate('Y-m-d H:i:s'),
                ]);
            }
        }

        // Offload scanned file telemetry to WebCare Scan Vault JSON manifest (zero database write bloat)
        if (!empty($batch_files_records) && class_exists('\\WebCareProScanner\\Scan\\ScanVaultManager')) {
            \WebCareProScanner\Scan\ScanVaultManager::append_batch($scan_id, $batch_files_records);
        }

        $remaining = \WebCareProScanner\Scan\ScanQueueManager::advance($scan_id, $processed_count, $bytes_consumed);
        $is_finished = ($remaining === 0);


        $tot_sql = "SELECT total_files FROM `{$table_scans}` WHERE id = %d";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $scan_row = $wpdb->get_row(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $wpdb->prepare($tot_sql, $scan_id),
            ARRAY_A
        );
        if (!$scan_row) {
            // Self-healing: recreate running scan row if missing
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->insert($table_scans, [
                'id'            => $scan_id,
                'status'        => 'running',
                'scan_type'     => 'full',
                'scanned_files' => 0,
                'total_files'   => max(1, $remaining),
                'issues_found'  => 0,
                'risk_score'    => 0,
                'created_at'    => current_time('mysql'),
                'created_at_gmt'=> gmdate('Y-m-d H:i:s'),
            ]);
            $scan_row = ['total_files' => max(1, $remaining)];
        }
        $scan_total = (int) ($scan_row['total_files'] ?? 0);
        $scanned_so_far = max(0, $scan_total - $remaining);
        $iss_sql = "SELECT COUNT(*) FROM `{$table_issues}` WHERE scan_id = %d AND status = 'open'";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $current_issues_total = (int) $wpdb->get_var(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $wpdb->prepare($iss_sql, $scan_id)
        );

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->update($table_scans, [
            'scanned_files' => $scanned_so_far,
            'issues_found'  => $current_issues_total,
        ], ['id' => $scan_id]);

        $start_micro = get_transient("webcareproscan_scan_start_micro_{$scan_id}");
        $elapsed_sec = ($start_micro && is_numeric($start_micro)) ? max(0.1, microtime(true) - (float) $start_micro) : 0.0;
        $telemetry = self::get_realtime_resource_stats(
            $batch_start,
            $batch_ru_start,
            $scanned_so_far,
            $scan_total,
            $current_issues_total,
            $elapsed_sec,
            $governor
        );
        set_transient("webcareproscan_scan_live_telemetry_{$scan_id}", $telemetry, 600);

        ScanLock::release_batch_lock();

        return rest_ensure_response([
            'success'        => true,
            'is_finished'    => $is_finished,
            'remaining'      => $remaining,
            'processed'      => count($files_to_process),
            'scanned_files'  => $scanned_so_far,
            'total_files'    => $scan_total,
            'issues_found'   => $current_issues_total,
            'last_file'      => !empty($files_to_process) ? basename(end($files_to_process)) : '',
            'telemetry'      => $telemetry,
        ]);
    }

    public static function run_deep_audit(\WP_REST_Request $request) {
        global $wpdb;

        // Ensure sufficient execution time and memory for deep forensic correlation
        if (function_exists('set_time_limit')) {
            // phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged
            @set_time_limit(180);
        }
        if (function_exists('wp_raise_memory_limit')) {
            @wp_raise_memory_limit('admin');
        }

        $scan_id = (int) $request->get_param('scan_id');
        $lease_token = sanitize_text_field((string) ($request->get_param('lease_token') ?? ''));
        if (empty($lease_token)) {
            return new \WP_Error(
                'invalid_lease_token',
                __('Valid scan lease token is required for deep audit execution.', 'webcare-pro-security'),
                ['status' => 403]
            );
        }

        $target = sanitize_text_field($request->get_param('target') ?: '');
        $admins_only = (bool) $request->get_param('admins_only');

        $table_issues = $wpdb->prefix . 'webcareproscan_scan_issues';
        $table_scans = $wpdb->prefix . 'webcareproscan_scans';

        // Keep lock alive and verify lease token ownership
        if (!ScanLock::heartbeat($scan_id, $lease_token)) {
            return new \WP_Error(
                'scan_lock_conflict',
                __('Active scan lease verification failed or scan timed out.', 'webcare-pro-security'),
                ['status' => 409]
            );
        }

        // If scan is already completed, return results directly (idempotent for reconnects)
        $scan_query = "SELECT * FROM `{$table_scans}` WHERE id = %d";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $scan_row = $wpdb->get_row(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $wpdb->prepare($scan_query, $scan_id),
            ARRAY_A
        );
        if ($scan_row && $scan_row['status'] === 'completed') {
            $issues_query = "SELECT * FROM `{$table_issues}` WHERE scan_id = %d";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $all_scan_issues = $wpdb->get_results(
                // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                $wpdb->prepare($issues_query, $scan_id),
                ARRAY_A
            );
            $scorer = new RiskScorer();
            $summary = $scorer->calculate($all_scan_issues);
            $diagnostics = self::build_scan_diagnostics($scan_row);
            return rest_ensure_response([
                'success'     => true,
                'summary'     => $summary,
                'issues'      => self::enrich_issues($all_scan_issues),
                'diagnostics' => $diagnostics,
                'status'      => 'completed'
            ]);
        }

        if (empty($target)) {
            $target = $scan_row ? ($scan_row['scan_target'] ?? 'plugins_themes') : 'plugins_themes';
        }

        $all_deep_findings = [];

        $assert_lease_active = static function () use ($scan_id, $lease_token): void {
            if (!ScanLock::heartbeat($scan_id, $lease_token)) {
                throw new \WebCareProScanner\Scan\ScanLeaseLostException(esc_html__('Active scan lease lost or superseded during deep audit.', 'webcare-pro-security'));
            }
        };

        try {
            $assert_lease_active();
            if ($target === 'unknown_files') {
                // Find only unknown files (core & plugins & themes)
                $core_integrity = new CoreIntegrity();
                $plugin_integrity = new PluginIntegrity();
                $all_deep_findings = array_merge($all_deep_findings, $core_integrity->verify((string) $scan_id));
                $all_deep_findings = array_merge($all_deep_findings, $plugin_integrity->verify((string) $scan_id));
                // Filter strictly for unknown/unrecognized files
                $all_deep_findings = array_filter($all_deep_findings, function ($f) {
                    $arr = is_array($f) ? $f : $f->to_array();
                    return in_array($arr['type'], ['unknown_core_file', 'unknown_plugin_file'], true);
                });
            } elseif ($target === 'spam_content') {
                // Scan for spam posts/pages only
                $content_scanner = new ContentScanner();
                $all_deep_findings = array_merge($all_deep_findings, $content_scanner->scan((string) $scan_id, 300));
            } elseif ($target === 'user_security') {
                // Password strength, privilege escalation, and Trojan capability injection audit across all accounts
                $user_scanner = new UserScanner();
                $all_deep_findings = array_merge($all_deep_findings, $user_scanner->scan((string) $scan_id, false, $lease_token));
            } elseif ($target === 'outdated_software') {
                // Check outdated WP core, plugins, themes
                $update_scanner = new UpdateScanner();
                $all_deep_findings = array_merge($all_deep_findings, $update_scanner->scan((string) $scan_id));
            } elseif ($target === 'suspicious_uploads') {
                // Detect .php, .sh, or suspicious file extensions inside wp-content/uploads
                $uploads_scanner = new UploadsScanner();
                $all_deep_findings = array_merge($all_deep_findings, $uploads_scanner->scan((string) $scan_id));
            } elseif ($target === 'crontab_audit') {
                // Crontab & WP-Cron scheduled tasks audit
                $cron_scanner = new CronScanner();
                $all_deep_findings = array_merge($all_deep_findings, $cron_scanner->scan((string) $scan_id));
            } elseif ($target === 'core_integrity') {
                // WordPress Core files integrity check against official checksums
                $core_integrity = new CoreIntegrity();
                $all_deep_findings = array_merge($all_deep_findings, $core_integrity->verify((string) $scan_id));
            } elseif ($target === 'rogue_admin') {
                // Rogue Administrator & Database Micro-Anomaly Audit
                $rogue_detector = new \WebCareProScanner\Database\RogueAdminAnomalyDetector();
                $all_deep_findings = array_merge($all_deep_findings, $rogue_detector->scan((string) $scan_id));
                $user_scanner = new UserScanner();
                $all_deep_findings = array_merge($all_deep_findings, $user_scanner->scan((string) $scan_id, true, $lease_token));
            } elseif ($target === 'hook_sentinel') {
                // Living-off-the-Land (LotL) Native Hook Infiltration Sentinel
                $hook_sentinel = new \WebCareProScanner\WordPress\HookInfiltrationSentinel();
                $all_deep_findings = array_merge($all_deep_findings, $hook_sentinel->scan((string) $scan_id));
                $persistence_scanner = new PersistenceScanner();
                $all_deep_findings = array_merge($all_deep_findings, $persistence_scanner->scan((string) $scan_id));
            } elseif ($target === 'modified_files') {
                // Modified Core, Plugins, and Themes Audit against official WordPress.org checksums
                $core_integrity = new CoreIntegrity();
                $plugin_integrity = new PluginIntegrity();
                $theme_integrity = new ThemeIntegrity();
                $important_fim = new ImportantFileFIM();

                $integrity_findings = array_merge(
                    $core_integrity->verify((string) $scan_id),
                    $plugin_integrity->verify((string) $scan_id),
                    $theme_integrity->verify((string) $scan_id),
                    $important_fim->verify((string) $scan_id)
                );

                // Filter strictly for modified or tampered files (excluding informational notes)
                $modified_items = array_filter($integrity_findings, function ($f) {
                    $arr = is_array($f) ? $f : $f->to_array();
                    return in_array($arr['type'], [
                        'modified_core_file',
                        'modified_plugin_file',
                        'modified_theme_file',
                        'missing_core_file',
                        'missing_plugin_file',
                        'missing_theme_file',
                        'important_file_modified',
                    ], true);
                });

                $all_deep_findings = array_merge($all_deep_findings, $modified_items);

                // Additionally run AST malware inspection on any modified files to identify injected backdoors
                $file_scanner = new FileScanner();
                foreach ($modified_items as $mf) {
                    $item = is_array($mf) ? $mf : $mf->to_array();
                    $file_path = $item['file_path'] ?? '';
                    if ($file_path) {
                        $abs_path = (strpos($file_path, ABSPATH) === 0) ? $file_path : (rtrim(ABSPATH, '/\\') . '/' . ltrim($file_path, '/\\'));
                        if (file_exists($abs_path) && is_file($abs_path)) {
                            $code_findings = $file_scanner->scan_file($abs_path, (string) $scan_id);
                            if (!empty($code_findings)) {
                                $all_deep_findings = array_merge($all_deep_findings, $code_findings);
                            }
                        }
                    }
                }
            } elseif ($target === 'custom') {
                $custom_options = get_transient("webcareproscan_custom_options_{$scan_id}");
                if (!is_array($custom_options)) {
                    $req_custom = $request->get_param('custom_options');
                    if (is_array($req_custom)) {
                        $custom_options = \WebCareProScanner\System\SettingsManager::sanitize_custom_scan_options($req_custom);
                    } else {
                        $settings = \WebCareProScanner\System\SettingsManager::get_settings();
                        $custom_options = $settings['custom_scan_options'] ?? \WebCareProScanner\System\SettingsManager::get_default_custom_scan_options();
                    }
                }

                // 1. Scan core files against repository versions for changes
                if (!empty($custom_options['scan_core_integrity'])) {
                    $core_integrity = new CoreIntegrity();
                    $all_deep_findings = array_merge($all_deep_findings, $core_integrity->verify((string) $scan_id));
                }

                // 2. Scan theme files against repository versions for changes
                if (!empty($custom_options['scan_theme_integrity'])) {
                    $theme_integrity = new ThemeIntegrity();
                    $all_deep_findings = array_merge($all_deep_findings, $theme_integrity->verify((string) $scan_id));
                }

                // 3. Scan plugin files against repository versions for changes
                if (!empty($custom_options['scan_plugin_integrity'])) {
                    $plugin_integrity = new PluginIntegrity();
                    $all_deep_findings = array_merge($all_deep_findings, $plugin_integrity->verify((string) $scan_id));
                }

                // 4. Scan wp-admin and wp-includes for files not bundled with WordPress
                if (!empty($custom_options['scan_unbundled_files']) && empty($custom_options['scan_core_integrity'])) {
                    $core_integrity = new CoreIntegrity();
                    $core_results = $core_integrity->verify((string) $scan_id);
                    $unbundled = array_filter($core_results, function ($f) {
                        $arr = is_array($f) ? $f : $f->to_array();
                        return in_array($arr['type'] ?? '', ['unknown_core_file'], true);
                    });
                    $all_deep_findings = array_merge($all_deep_findings, $unbundled);
                }

                // 5. Scan for publicly accessible configuration, backup, or log files
                if (!empty($custom_options['scan_public_config'])) {
                    $important_fim = new ImportantFileFIM();
                    $all_deep_findings = array_merge($all_deep_findings, $important_fim->verify((string) $scan_id));
                    $config_scanner = new \WebCareProScanner\WordPress\ConfigScanner();
                    $all_deep_findings = array_merge($all_deep_findings, $config_scanner->scan((string) $scan_id));
                    $exposed = self::audit_exposed_sensitive_files((string) $scan_id);
                    $all_deep_findings = array_merge($all_deep_findings, $exposed);
                }

                // 6. Scan for publicly accessible quarantined files
                if (!empty($custom_options['scan_public_quarantine'])) {
                    $quarantine_exposure = self::audit_quarantine_exposure((string) $scan_id);
                    $all_deep_findings = array_merge($all_deep_findings, $quarantine_exposure);
                }

                // 7. Scan for misconfigured visitor IP detection headers
                if (!empty($custom_options['scan_ip_detection'])) {
                    $ip_findings = self::audit_visitor_ip_detection((string) $scan_id);
                    $all_deep_findings = array_merge($all_deep_findings, $ip_findings);
                }

                // 8. Scan posts for known dangerous URLs and suspicious content
                if (!empty($custom_options['scan_posts_content'])) {
                    $content_scanner = new ContentScanner();
                    $all_deep_findings = array_merge($all_deep_findings, $content_scanner->scan_posts_only((string) $scan_id, 100));
                }

                // 9. Scan comments for known dangerous URLs and suspicious content
                if (!empty($custom_options['scan_comments_content'])) {
                    $content_scanner = new ContentScanner();
                    $all_deep_findings = array_merge($all_deep_findings, $content_scanner->scan_comments_only((string) $scan_id, 100));
                }

                // 10. Scan WordPress core, plugin, and theme options
                if (!empty($custom_options['scan_options_content'])) {
                    $option_scanner = new \WebCareProScanner\Database\OptionScanner();
                    $all_deep_findings = array_merge($all_deep_findings, $option_scanner->scan_options((string) $scan_id));
                }

                // 11. Scan for out of date, abandoned, and vulnerable plugins, themes, and WP
                if (!empty($custom_options['scan_vulnerable_software'])) {
                    $update_scanner = new UpdateScanner();
                    $all_deep_findings = array_merge($all_deep_findings, $update_scanner->scan((string) $scan_id));
                }

                // 12. Scan for suspicious admin users created outside of WordPress
                if (!empty($custom_options['scan_rogue_admins'])) {
                    $rogue_detector = new \WebCareProScanner\Database\RogueAdminAnomalyDetector();
                    $all_deep_findings = array_merge($all_deep_findings, $rogue_detector->scan((string) $scan_id));
                    $user_scanner = new UserScanner();
                    $all_deep_findings = array_merge($all_deep_findings, $user_scanner->scan((string) $scan_id, true, $lease_token));
                }

                // 13. Check the strength of passwords
                if (!empty($custom_options['scan_password_strength'])) {
                    $pwd_findings = self::audit_password_strength((string) $scan_id);
                    $all_deep_findings = array_merge($all_deep_findings, $pwd_findings);
                }

                // 14. Monitor disk space
                if (!empty($custom_options['monitor_disk_space'])) {
                    $disk_findings = self::audit_disk_space((string) $scan_id);
                    $all_deep_findings = array_merge($all_deep_findings, $disk_findings);
                }

                // 15. Monitor Web Application Firewall status
                if (!empty($custom_options['monitor_firewall_status'])) {
                    $waf_findings = self::audit_waf_status((string) $scan_id);
                    $all_deep_findings = array_merge($all_deep_findings, $waf_findings);
                }

                // 16. Scan images, binary, and other files as if they were executable
                if (!empty($custom_options['scan_images_executable'])) {
                    $uploads_scanner = new UploadsScanner();
                    $all_deep_findings = array_merge($all_deep_findings, $uploads_scanner->scan((string) $scan_id));
                }

                // 17. Reputation Checks (Domain blocklist, spamvertised, spam IP)
                if (!empty($custom_options['check_domain_blocklist']) || !empty($custom_options['check_spamvertised']) || !empty($custom_options['check_spam_ip'])) {
                    $reputation_findings = self::audit_reputation_checks((string) $scan_id, $custom_options);
                    $all_deep_findings = array_merge($all_deep_findings, $reputation_findings);
                }
            } elseif ($target === 'filesystem_only') {
                // Filesystem-only scan: no additional deep audit engines needed
            } else {
                // Full or plugins_themes: execute deep audit engines with heartbeat & fault isolation
                $assert_lease_active();
                try {
                    set_transient("webcareproscan_active_scan_file_{$scan_id}", 'Core Integrity: Verifying WordPress core files against official WP.org API checksums...', 120);
                    $core_integrity = new CoreIntegrity();
                    $all_deep_findings = array_merge($all_deep_findings, $core_integrity->verify((string) $scan_id));
                } catch (\Throwable $e) {
                    if ($e instanceof \WebCareProScanner\Scan\ScanLeaseLostException || str_contains(strtolower($e->getMessage()), 'lease')) {
                        throw $e;
                    }
                }

                try {
                    set_transient("webcareproscan_active_scan_file_{$scan_id}", 'File Integrity: Checking critical system files (wp-config.php, .htaccess, index.php)...', 120);
                    $important_fim = new ImportantFileFIM();
                    $all_deep_findings = array_merge($all_deep_findings, $important_fim->verify((string) $scan_id));
                } catch (\Throwable $e) {
                    if ($e instanceof \WebCareProScanner\Scan\ScanLeaseLostException || str_contains(strtolower($e->getMessage()), 'lease')) {
                        throw $e;
                    }
                }

                $assert_lease_active();
                try {
                    set_transient("webcareproscan_active_scan_file_{$scan_id}", 'Plugin Integrity: Verifying installed plugins against official WordPress.org checksums...', 120);
                    $plugin_integrity = new PluginIntegrity();
                    $all_deep_findings = array_merge($all_deep_findings, $plugin_integrity->verify((string) $scan_id));
                } catch (\Throwable $e) {
                    if ($e instanceof \WebCareProScanner\Scan\ScanLeaseLostException || str_contains(strtolower($e->getMessage()), 'lease')) {
                        throw $e;
                    }
                }

                $assert_lease_active();
                try {
                    set_transient("webcareproscan_active_scan_file_{$scan_id}", 'Theme Integrity: Verifying active and installed themes against repository checksums...', 120);
                    $theme_integrity = new ThemeIntegrity();
                    $all_deep_findings = array_merge($all_deep_findings, $theme_integrity->verify((string) $scan_id));
                } catch (\Throwable $e) {
                    if ($e instanceof \WebCareProScanner\Scan\ScanLeaseLostException || str_contains(strtolower($e->getMessage()), 'lease')) {
                        throw $e;
                    }
                }

                $assert_lease_active();
                try {
                    $db_scanner = new DatabaseScanner();
                    $all_deep_findings = array_merge($all_deep_findings, $db_scanner->scan((string) $scan_id, 100));
                } catch (\Throwable $e) {
                    if ($e instanceof \WebCareProScanner\Scan\ScanLeaseLostException || str_contains(strtolower($e->getMessage()), 'lease')) {
                        throw $e;
                    }
                }

                $assert_lease_active();
                try {
                    set_transient("webcareproscan_active_scan_file_{$scan_id}", 'Content & Post Scanner: Inspecting published posts and comments for hidden SEO spam and XSS...', 120);
                    $content_scanner = new ContentScanner();
                    $all_deep_findings = array_merge($all_deep_findings, $content_scanner->scan((string) $scan_id, 100));
                } catch (\Throwable $e) {
                    if ($e instanceof \WebCareProScanner\Scan\ScanLeaseLostException || str_contains(strtolower($e->getMessage()), 'lease')) {
                        throw $e;
                    }
                }

                $assert_lease_active();
                try {
                    set_transient("webcareproscan_active_scan_file_{$scan_id}", 'User & Auth Sentinel: Auditing user accounts, administrator privileges, and password strength...', 120);
                    $wp_security = new WordPressSecurityScanner();
                    $all_deep_findings = array_merge($all_deep_findings, $wp_security->scan((string) $scan_id, $lease_token));
                } catch (\Throwable $e) {
                    if ($e instanceof \WebCareProScanner\Scan\ScanLeaseLostException || str_contains(strtolower($e->getMessage()), 'lease')) {
                        throw $e;
                    }
                }

                $assert_lease_active();
                try {
                    set_transient("webcareproscan_active_scan_file_{$scan_id}", 'Vulnerability Intelligence: Checking installed plugins, themes, and WP Core against CVE database...', 120);
                    $update_scanner = new UpdateScanner();
                    $all_deep_findings = array_merge($all_deep_findings, $update_scanner->scan((string) $scan_id));
                } catch (\Throwable $e) {
                    if ($e instanceof \WebCareProScanner\Scan\ScanLeaseLostException || str_contains(strtolower($e->getMessage()), 'lease')) {
                        throw $e;
                    }
                }

                $assert_lease_active();
                try {
                    set_transient("webcareproscan_active_scan_file_{$scan_id}", 'Media & Uploads Audit: Inspecting image metadata and attachments for embedded PHP code...', 120);
                    $uploads_scanner = new UploadsScanner();
                    $all_deep_findings = array_merge($all_deep_findings, $uploads_scanner->scan((string) $scan_id));
                } catch (\Throwable $e) {
                    if ($e instanceof \WebCareProScanner\Scan\ScanLeaseLostException || str_contains(strtolower($e->getMessage()), 'lease')) {
                        throw $e;
                    }
                }

                // Quick reputation check (skips if non-responsive or local)
                try {
                    set_transient("webcareproscan_active_scan_file_{$scan_id}", 'Reputation Intel: Verifying domain blocklists, Google Safe Browsing, and spamvertising...', 120);
                    $reputation_findings = self::audit_reputation_checks((string) $scan_id, [
                        'check_domain_blocklist' => true,
                        'check_spamvertised'     => true,
                        'check_spam_ip'          => true,
                    ]);
                    $all_deep_findings = array_merge($all_deep_findings, $reputation_findings);
                } catch (\Throwable $e) {
                    if ($e instanceof \WebCareProScanner\Scan\ScanLeaseLostException || str_contains(strtolower($e->getMessage()), 'lease')) {
                        throw $e;
                    }
                }
            }

            // Cross-engine Correlation
            $correlation = new CorrelationEngine();
            $correlated = $correlation->correlate($all_deep_findings);

            // Assert lease is still held before mutating issue table
            $assert_lease_active();

            // Pre-load all existing findings already saved for this scan to prevent any duplicate insertions
            $exist_sql = "SELECT engine, type, file_path, line_number, description FROM `{$table_issues}` WHERE scan_id = %d";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $existing_issues = $wpdb->get_results(
                // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                $wpdb->prepare($exist_sql, $scan_id),
                ARRAY_A
            ) ?: [];

            $inserted_signatures = [];
            foreach ($existing_issues as $ex) {
                $norm_path = self::normalize_finding_path($ex['file_path'] ?? '');
                $line_no = (int) ($ex['line_number'] ?? 0);
                $sig = strtolower($ex['type'] ?? '') . '|' . $norm_path . '|' . $line_no;
                $inserted_signatures[$sig] = true;
            }

            foreach ($correlated as $f) {
                $item = $f->to_array();
                $norm_path = self::normalize_finding_path($item['file_path'] ?? '');
                $line_no = (int) ($item['line_number'] ?? 0);
                $sig = strtolower($item['type'] ?? '') . '|' . $norm_path . '|' . $line_no;
                if (isset($inserted_signatures[$sig])) {
                    continue; // Skip exact duplicate finding for this scan
                }
                $inserted_signatures[$sig] = true;

                $matched_rule = \WebCareProScanner\Findings\WhitelistManager::match_finding($item);
                $status = ($matched_rule !== null) ? 'ignored' : 'open';

                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                $wpdb->insert($table_issues, [
                    'scan_id'      => $scan_id,
                    'engine'       => $item['engine'],
                    'type'         => $item['type'],
                    'severity'     => $item['severity'],
                    'confidence'   => $item['confidence'],
                    'file_path'    => $item['file_path'],
                    'line_number'  => $item['line_number'] ?? null,
                    'code_snippet' => UploadsScanner::sanitize_utf8($item['code_snippet'] ?? null),
                    'evidence'     => UploadsScanner::sanitize_utf8($item['evidence'] ?? null),
                    'description'  => $item['description'],
                    'status'       => $status,
                    'created_at'   => current_time('mysql'),
                    'created_at_gmt'=> gmdate('Y-m-d H:i:s'),
                ]);
            }

            // Prune any duplicate issue rows to ensure clean database storage
            self::prune_duplicate_issues($scan_id);

            // Calculate final risk score across all findings (decorating whitelist status)
            $all_iss_sql = "SELECT * FROM `{$table_issues}` WHERE scan_id = %d";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $all_scan_issues = $wpdb->get_results(
                // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                $wpdb->prepare($all_iss_sql, $scan_id),
                ARRAY_A
            );
            $enriched_issues = self::enrich_issues($all_scan_issues);

            $scorer = new RiskScorer();
            $summary = $scorer->calculate($enriched_issues);

            $cnt_sql = "SELECT COUNT(*) FROM `{$table_issues}` WHERE scan_id = %d AND status = 'open'";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $open_issues_count = (int) $wpdb->get_var(
                // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                $wpdb->prepare($cnt_sql, $scan_id)
            );

            // Calculate duration accurately with millisecond precision
            $row_sql = "SELECT * FROM `{$table_scans}` WHERE id = %d";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $scan_row = $wpdb->get_row(
                // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                $wpdb->prepare($row_sql, $scan_id),
                ARRAY_A
            );
            $client_duration_ms = (int) $request->get_param('client_duration_ms');
            $client_duration = (int) $request->get_param('client_duration');
            $start_micro = get_transient("webcareproscan_scan_start_micro_{$scan_id}");
            $completed_at_exact = self::now_fractional_mysql();

            $duration_ms = 0;
            $duration_sec = 0;

            if ($start_micro && is_numeric($start_micro)) {
                $calc_diff = microtime(true) - (float) $start_micro;
                if ($calc_diff > 0) {
                    $duration_ms = (int) round($calc_diff * 1000);
                    $duration_sec = max(1, (int) round($calc_diff));
                }
            }

            if ($duration_ms <= 0 && $client_duration_ms > 0) {
                $duration_ms = $client_duration_ms;
                $duration_sec = max(1, (int) round($client_duration_ms / 1000));
            } elseif ($duration_ms <= 0 && $client_duration > 0) {
                $duration_sec = $client_duration;
                $duration_ms = $client_duration * 1000;
            } elseif ($duration_ms <= 0 && $scan_row) {
                if (!empty($scan_row['started_at'])) {
                    $start_dt = date_create($scan_row['started_at'], wp_timezone());
                    $end_dt = date_create($completed_at_exact, wp_timezone());
                    if ($start_dt && $end_dt) {
                        $diff_sec = $end_dt->getTimestamp() - $start_dt->getTimestamp() + (($end_dt->format('u') - $start_dt->format('u')) / 1000000);
                        if ($diff_sec > 0) {
                            $duration_ms = (int) round($diff_sec * 1000);
                            $duration_sec = max(1, (int) round($diff_sec));
                        }
                    }
                }

                if ($duration_ms <= 0 && !empty($scan_row['created_at'])) {
                    $created_dt = date_create($scan_row['created_at'], wp_timezone());
                    if ($created_dt) {
                        $now_dt = date_create('now', wp_timezone());
                        $diff_sec = max(0.1, $now_dt->getTimestamp() - $created_dt->getTimestamp());
                        $duration_ms = (int) round($diff_sec * 1000);
                        $duration_sec = max(1, (int) round($diff_sec));
                    }
                }
            }

            if ($duration_ms <= 0) {
                $duration_ms = 100;
                $duration_sec = 1;
            }

            delete_transient("webcareproscan_scan_start_micro_{$scan_id}");

            $started_at_db = !empty($scan_row['started_at']) ? $scan_row['started_at'] : ($scan_row['created_at'] ?? $completed_at_exact);

            if (!$scan_row) {
                // Self-healing: recreate missing scan record so results are guaranteed to persist
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                $wpdb->insert($table_scans, [
                    'id'            => $scan_id,
                    'status'        => 'completed',
                    'scan_target'   => $target ?: 'full',
                    'trigger_type'  => 'manual',
                    'scanned_files' => (int) ($scan_row['scanned_files'] ?? ($scan_row['total_files'] ?? count($all_scan_issues))),
                    'total_files'   => (int) ($scan_row['total_files'] ?? count($all_scan_issues)),
                    'issues_found'  => $open_issues_count,
                    'risk_score'    => $summary['score'],
                    'duration'      => $duration_sec,
                    'duration_ms'   => $duration_ms,
                    'created_at'    => current_time('mysql'),
                    'created_at_gmt'=> gmdate('Y-m-d H:i:s'),
                    'started_at'    => $started_at_db,
                    'completed_at'  => $completed_at_exact,
                ]);
            } else {
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                $wpdb->update($table_scans, [
                    'status'        => 'completed',
                    'issues_found'  => $open_issues_count,
                    'risk_score'    => $summary['score'],
                    'duration'      => $duration_sec,
                    'duration_ms'   => $duration_ms,
                    'started_at'    => $started_at_db,
                    'completed_at'  => $completed_at_exact,
                ], ['id' => $scan_id]);
            }

            $completed_scan_row = [
                'id'            => $scan_id,
                'status'        => 'completed',
                'issues_found'  => $open_issues_count,
                'risk_score'    => $summary['score'],
                'duration'      => $duration_sec,
                'duration_ms'   => $duration_ms,
                'scanned_files' => (int) ($scan_row['scanned_files'] ?? ($scan_row['total_files'] ?? 0)),
                'total_files'   => (int) ($scan_row['total_files'] ?? 0),
                'created_at'    => $scan_row['created_at'] ?? current_time('mysql'),
                'started_at'    => $started_at_db,
                'completed_at'  => $completed_at_exact,
            ];
            $diagnostics = self::build_scan_diagnostics($completed_scan_row);

            // Assemble and seal immutable Scan Vault JSON manifest
            if (class_exists('\\WebCareProScanner\\Scan\\ScanVaultManager')) {
                \WebCareProScanner\Scan\ScanVaultManager::finalize_manifest($scan_id, $completed_scan_row);
            }

            // Release the scan lock upon completion and clear background worker continuation
            ScanLock::release($scan_id, $lease_token);
            if (class_exists('\\WebCareProScanner\\Scan\\ScanBackgroundWorker')) {
                \WebCareProScanner\Scan\ScanBackgroundWorker::unschedule_continuation();
            }
            delete_transient("webcareproscan_active_scan_last_browser_touch_{$scan_id}");

            // Dispatch granular event notifications via NotificationDispatcher
            if (class_exists('\\WebCareProScanner\\Notifications\\NotificationDispatcher')) {
                $is_targeted = ($target && !in_array($target, ['full', 'full_filesystem', 'plugins_themes', 'custom'], true));
                if ($is_targeted) {
                    \WebCareProScanner\Notifications\NotificationDispatcher::trigger('scan_targeted_complete', [
                        'severity' => ($open_issues_count > 0) ? 'high' : 'info',
                        /* translators: 1: scan ID, 2: target name, 3: issues found, 4: risk score */
                        'message'  => sprintf(__('Targeted scan #%1$d finished for target "%2$s". %3$d issue(s) identified (Risk Score: %4$d/100).', 'webcare-pro-security'), $scan_id, $target, $open_issues_count, $summary['score']),
                        'details'  => [
                            'Scan ID'        => $scan_id,
                            'Target'         => $target,
                            'Scanned Files'  => number_format((int) ($completed_scan_row['scanned_files'] ?? 0)),
                            'Issues Found'   => $open_issues_count,
                            'Risk Score'     => $summary['score'] . '/100',
                            'Duration'       => $duration_sec . 's',
                        ],
                    ]);
                } else {
                    \WebCareProScanner\Notifications\NotificationDispatcher::trigger('scan_manual_complete', [
                        'severity' => ($open_issues_count > 0) ? 'high' : 'info',
                        /* translators: 1: scan ID, 2: issues found, 3: risk score */
                        'message'  => sprintf(__('Manual scan #%1$d finished. %2$d issue(s) identified (Risk Score: %3$d/100).', 'webcare-pro-security'), $scan_id, $open_issues_count, $summary['score']),
                        'details'  => [
                            'Scan ID'        => $scan_id,
                            'Target'         => $target,
                            'Scanned Files'  => number_format((int) ($completed_scan_row['scanned_files'] ?? 0)),
                            'Issues Found'   => $open_issues_count,
                            'Risk Score'     => $summary['score'] . '/100',
                            'Duration'       => $duration_sec . 's',
                        ],
                    ]);
                }

                // Critical or High threats event
                $critical_or_high = array_filter($enriched_issues, function($iss) {
                    $sev = is_array($iss) ? ($iss['severity'] ?? '') : ($iss->severity ?? '');
                    return in_array($sev, ['critical', 'high'], true);
                });
                if (!empty($critical_or_high)) {
                    \WebCareProScanner\Notifications\NotificationDispatcher::trigger('scan_threats_found', [
                        'severity' => 'critical',
                        /* translators: 1: scan ID, 2: threat count */
                        'message'  => sprintf(__('Critical or high-priority security threats were detected during scan #%1$d (%2$d threats).', 'webcare-pro-security'), $scan_id, count($critical_or_high)),
                        'details'  => [
                            'Scan ID'        => $scan_id,
                            'Critical Threats' => count($critical_or_high),
                            'Top Threats'    => implode(', ', array_slice(array_map(function($i) { return is_array($i) ? ($i['description'] ?? '') : ($i->description ?? ''); }, $critical_or_high), 0, 3)),
                        ],
                    ]);
                }
            }

            // Dispatch DevSecOps Webhooks (Slack, Discord, ClickUp, Asana, Generic)
            if (class_exists('\\WebCareProScanner\\Notifications\\WebhookService')) {
                \WebCareProScanner\Notifications\WebhookService::send_scan_alert($scan_id, $open_issues_count, $summary['score'], $target, $enriched_issues);
            }

            return rest_ensure_response([
                'success'     => true,
                'summary'     => $summary,
                'issues'      => $enriched_issues,
                'diagnostics' => $diagnostics,
                'status'      => 'completed'
            ]);
        } catch (\Throwable $e) {
            if (!empty($lease_token)) {
                ScanLock::release($scan_id, $lease_token);
            } else {
                ScanLock::force_release($scan_id);
            }

            if ($e instanceof \WebCareProScanner\Scan\ScanLeaseLostException || str_contains(strtolower($e->getMessage()), 'lease')) {
                return new \WP_Error(
                    'scan_lock_conflict',
                    $e->getMessage(),
                    ['status' => 409]
                );
            }

            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
            error_log('[WebCare Pro] Error during deep audit: ' . $e->getMessage() . ' in ' . $e->getFile() . ':' . $e->getLine());

            return new \WP_Error(
                'audit_error',
                /* translators: %s: error message */
                sprintf(__('Audit failed: %s', 'webcare-pro-security'), $e->getMessage()),
                ['status' => 500]
            );
        }
    }

    public static function get_latest_scan(\WP_REST_Request $request) {
        global $wpdb;

        $table_scans = $wpdb->prefix . 'webcareproscan_scans';
        $table_issues = $wpdb->prefix . 'webcareproscan_scan_issues';
        $table_files = $wpdb->prefix . 'webcareproscan_scan_files';

        // Retrieve available scans for the Dashboard scan ID switcher (comprehensive, custom & targeted scans)
        $avail_sql = "SELECT id, scan_target, status, started_at, completed_at, total_files, scanned_files, issues_found, risk_score FROM `{$table_scans}` ORDER BY id DESC LIMIT 50";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $available_scans_raw = $wpdb->get_results(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $avail_sql,
            ARRAY_A
        );
        $available_scans = [];
        if (!empty($available_scans_raw)) {
            foreach ($available_scans_raw as $as_row) {
                $as_meta = self::format_scan_target_meta($as_row['scan_target'] ?? 'plugins_themes');
                $as_row['scan_target_name'] = $as_meta['name'];
                $as_row['scan_target_short'] = $as_meta['short_name'];
                $as_row['scan_target_category'] = $as_meta['category'];
                $as_row['scan_category'] = $as_meta['category'];
                $as_row['target_meta'] = $as_meta;
                $available_scans[] = $as_row;
            }
        }

        $requested_scan_id = (int) $request->get_param('scan_id');
        if (!$requested_scan_id && !empty($_SERVER['REQUEST_URI'])) {
            $raw_req_uri = sanitize_text_field((string) wp_unslash($_SERVER['REQUEST_URI']));
            if (preg_match('/[?&]scan_id=(\d+)/', $raw_req_uri, $m)) {
                $requested_scan_id = (int) $m[1];
            }
        }
        $target_filter = sanitize_text_field($request->get_param('target'));

        if ($requested_scan_id > 0) {
            // Specific scan ID requested via dashboard switcher
            $req_sql = "SELECT * FROM `{$table_scans}` WHERE id = %d";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $latest_scan = $wpdb->get_row(
                // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                $wpdb->prepare($req_sql, $requested_scan_id),
                ARRAY_A
            );
        } elseif ($target_filter) {
            $target_sql = "SELECT * FROM `{$table_scans}` WHERE scan_target = %s ORDER BY id DESC LIMIT 1";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $latest_scan = $wpdb->get_row(
                // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                $wpdb->prepare($target_sql, $target_filter),
                ARRAY_A
            );
        } else {
            // Prefer comprehensive or custom scan for main dashboard view
            $std_sql = "SELECT * FROM `{$table_scans}` WHERE scan_target IN ('plugins_themes', 'full', 'custom') ORDER BY id DESC LIMIT 1";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $latest_scan = $wpdb->get_row(
                // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                $std_sql,
                ARRAY_A
            );
            if (!$latest_scan) {
                // Fallback to any latest scan if no standard/custom scan exists
                $fall_sql = "SELECT * FROM `{$table_scans}` ORDER BY id DESC LIMIT 1";
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
                $latest_scan = $wpdb->get_row(
                    // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                    $fall_sql,
                    ARRAY_A
                );
            }
        }

        if (!$latest_scan) {
            return rest_ensure_response([
                'has_scan'        => false,
                'scan'            => null,
                'summary'         => null,
                'issues'          => [],
                'files'           => [],
                'available_scans' => $available_scans ?: [],
            ]);
        }

        // Prune any duplicate issue rows for this scan to keep database clean
        self::prune_duplicate_issues((int) $latest_scan['id']);

        $iss_list_sql = "SELECT * FROM `{$table_issues}` WHERE scan_id = %d ORDER BY FIELD(severity, 'critical', 'high', 'medium', 'low', 'info'), id DESC";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $issues = $wpdb->get_results(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $wpdb->prepare($iss_list_sql, $latest_scan['id']),
            ARRAY_A
        );
        $issues = self::enrich_issues($issues);

        // Recalculate true active open issues count for latest scan record
        $open_issues_count = count(array_filter($issues, function ($i) {
            return ($i['status'] ?? 'open') === 'open' && empty($i['is_whitelisted']);
        }));
        if ((int) $latest_scan['issues_found'] !== $open_issues_count) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->update($table_scans, ['issues_found' => $open_issues_count], ['id' => $latest_scan['id']]);
            $latest_scan['issues_found'] = $open_issues_count;
        }

        $files_list_sql = "SELECT * FROM `{$table_files}` WHERE scan_id = %d ORDER BY id ASC LIMIT 500";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $scanned_files = $wpdb->get_results(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $wpdb->prepare($files_list_sql, $latest_scan['id']),
            ARRAY_A
        );

        $manifest_summary = null;
        if (class_exists('\\WebCareProScanner\\Scan\\ScanVaultManager')) {
            $manifest_summary = \WebCareProScanner\Scan\ScanVaultManager::get_manifest_summary((int) $latest_scan['id']);
            if (empty($scanned_files) && !empty($manifest_summary)) {
                $scanned_files = \WebCareProScanner\Scan\ScanVaultManager::get_manifest_sample((int) $latest_scan['id'], 100);
            }
        }

        $scorer = new RiskScorer();
        $summary = $scorer->calculate($issues);
        if ((int) $latest_scan['risk_score'] !== (int) $summary['score']) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->update($table_scans, ['risk_score' => (int) $summary['score']], ['id' => $latest_scan['id']]);
            $latest_scan['risk_score'] = (int) $summary['score'];
        }
        $latest_target_meta = self::format_scan_target_meta($latest_scan['scan_target'] ?? 'plugins_themes');
        $latest_scan['target_meta'] = $latest_target_meta;
        $latest_scan['scan_target_name'] = $latest_target_meta['name'];
        $latest_scan['scan_target_short'] = $latest_target_meta['short_name'];
        $latest_scan['scan_target_category'] = $latest_target_meta['category'];

        $diagnostics = self::build_scan_diagnostics($latest_scan);

        return rest_ensure_response([
            'has_scan'         => true,
            'scan'             => $latest_scan,
            'summary'          => $summary,
            'issues'           => $issues,
            'files'            => $scanned_files ?: [],
            'manifest_summary' => $manifest_summary,
            'diagnostics'      => $diagnostics,
            'available_scans'  => $available_scans ?: [],
        ]);
    }

    public static function update_issue(\WP_REST_Request $request) {
        global $wpdb;

        $issue_id = (int) $request->get_param('id');
        $status = sanitize_text_field($request->get_param('status') ?: 'ignored');

        $table_issues = $wpdb->prefix . 'webcareproscan_scan_issues';
        $iss_row_sql = "SELECT * FROM {$table_issues} WHERE id = %d";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $issue = $wpdb->get_row(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $wpdb->prepare($iss_row_sql, $issue_id)
        );

        if ($status === 'open' && $issue && !empty($issue->file_path)) {
            \WebCareProScanner\Findings\WhitelistManager::revoke_rules_for_target($issue->file_path, $issue->type ?? '');
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $updated = $wpdb->update($table_issues, ['status' => $status], ['id' => $issue_id]);

        if ($issue && !empty($issue->scan_id)) {
            $table_scans = $wpdb->prefix . 'webcareproscan_scans';
            $open_iss_sql = "SELECT COUNT(*) FROM {$table_issues} WHERE scan_id = %d AND status = 'open'";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $open_issues = (int) $wpdb->get_var(
                // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                $wpdb->prepare($open_iss_sql, $issue->scan_id)
            );
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->update($table_scans, ['issues_found' => $open_issues], ['id' => $issue->scan_id]);
        }

        return rest_ensure_response([
            'success' => $updated !== false,
            'id'      => $issue_id,
            'status'  => $status,
        ]);
    }

    public static function get_scan_history(\WP_REST_Request $request) {
        global $wpdb;
        $table_scans = $wpdb->prefix . 'webcareproscan_scans';
        $limit = (int) ($request->get_param('limit') ?: 50);
        $hist_sql = "SELECT * FROM `{$table_scans}` ORDER BY id DESC LIMIT %d";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $history = $wpdb->get_results(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $wpdb->prepare($hist_sql, $limit),
            ARRAY_A
        );

        $scans = [];
        if (!empty($history)) {
            foreach ($history as $row) {
                $diag = self::build_scan_diagnostics($row);
                $row['diagnostics'] = $diag;
                $row['duration_formatted'] = $diag['duration_formatted'] ?? ($row['duration'] . 's');
                if (empty($row['trigger_type'])) {
                    $row['trigger_type'] = 'manual';
                }
                $t_meta = self::format_scan_target_meta($row['scan_target'] ?? 'plugins_themes');
                $row['target_meta'] = $t_meta;
                $row['scan_target_name'] = $t_meta['name'];
                $row['scan_target_short'] = $t_meta['short_name'];
                $row['scan_target_category'] = $t_meta['category'];
                $row['id'] = (int) $row['id'];
                $row['scanned_files'] = (int) ($row['scanned_files'] ?? 0);
                $row['issues_found'] = (int) ($row['issues_found'] ?? 0);
                $row['risk_score'] = (int) ($row['risk_score'] ?? 0);
                $row['duration'] = is_numeric($row['duration'] ?? null) ? (float) $row['duration'] : 0.0;
                $row = self::enrich_scan_row_timestamps($row);

                if (in_array($row['status'], ['interrupted', 'aborted', 'failed'], true)) {
                    $row['interruption'] = \WebCareProScanner\Scan\ScanInterruptionForensics::get($row['id']);
                }

                $scans[] = $row;
            }
        }

        return rest_ensure_response([
            'success' => true,
            'scans'   => $scans,
        ]);
    }

    public static function clear_scan_history(\WP_REST_Request $request) {
        global $wpdb;
        $table_scans = $wpdb->prefix . 'webcareproscan_scans';
        $table_issues = $wpdb->prefix . 'webcareproscan_scan_issues';
        $table_files = $wpdb->prefix . 'webcareproscan_scan_files';

        // 1. Identify any scans that are actively running or in progress
        $run_sql = "SELECT id FROM `{$table_scans}` WHERE status = 'running'";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $running_scans = $wpdb->get_results(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $run_sql,
            ARRAY_A
        );
        $running_ids = !empty($running_scans) ? array_map('intval', wp_list_pluck($running_scans, 'id')) : [];

        // Check if there is an active lock for an additional running scan
        $locked_id = (int) ScanLock::get_locked_scan_id();
        if ($locked_id > 0 && !in_array($locked_id, $running_ids, true)) {
            $running_ids[] = $locked_id;
        }

        if (!empty($running_ids)) {
            // There IS an active scan in progress!
            // Preserve the active running scan(s) and their issues/files. Delete only historical records.
            $placeholders = implode(',', array_map('intval', $running_ids));
            $del_iss_sql = "DELETE FROM `{$table_issues}` WHERE scan_id NOT IN ({$placeholders})";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $wpdb->query($del_iss_sql);

            $del_files_sql = "DELETE FROM `{$table_files}` WHERE scan_id NOT IN ({$placeholders})";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $wpdb->query($del_files_sql);

            $del_scans_sql = "DELETE FROM `{$table_scans}` WHERE id NOT IN ({$placeholders})";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $wpdb->query($del_scans_sql);

            // Clear historical Scan Vault JSON manifests as well
            if (class_exists('\\WebCareProScanner\\Scan\\ScanVaultManager')) {
                \WebCareProScanner\Scan\ScanVaultManager::clear_historical_manifests($running_ids);
            }

            // Do NOT release lock because the scan is actively running!
            return rest_ensure_response([
                'success'        => true,
                'has_active'     => true,
                'active_scan_id' => reset($running_ids),
                'message'        => sprintf(
                    /* translators: %s: running scan IDs */
                    __('Past scan logs cleared successfully. Actively running scan (#%s) was preserved and continues executing uninterrupted.', 'webcare-pro-security'),
                    implode(', #', $running_ids)
                ),
            ]);
        }

        // 2. No scan is currently running: safe to truncate all tables cleanly
        $trunc_scans = "TRUNCATE TABLE `{$table_scans}`";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $wpdb->query($trunc_scans);
        $trunc_issues = "TRUNCATE TABLE `{$table_issues}`";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $wpdb->query($trunc_issues);
        $trunc_files = "TRUNCATE TABLE `{$table_files}`";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $wpdb->query($trunc_files);

        // Clear all Scan Vault JSON manifests
        if (class_exists('\\WebCareProScanner\\Scan\\ScanVaultManager')) {
            \WebCareProScanner\Scan\ScanVaultManager::clear_all_manifests();
        }

        if (ScanLock::is_locked() && !ScanLock::force_release()) {
            return new \WP_Error(
                'clear_history_lock_failed',
                __('Failed to clear active scan lock.', 'webcare-pro-security'),
                ['status' => 500]
            );
        }

        return rest_ensure_response([
            'success'    => true,
            'has_active' => false,
            'message'    => __('All old scan logs and history records cleared successfully.', 'webcare-pro-security'),
        ]);
    }

    public static function get_scan_log_detail(\WP_REST_Request $request) {
        global $wpdb;
        $scan_id = (int) $request->get_param('id');
        $table_scans = $wpdb->prefix . 'webcareproscan_scans';
        $table_issues = $wpdb->prefix . 'webcareproscan_scan_issues';
        $table_files = $wpdb->prefix . 'webcareproscan_scan_files';

        $get_scan_sql = "SELECT * FROM `{$table_scans}` WHERE id = %d";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $scan = $wpdb->get_row(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $wpdb->prepare($get_scan_sql, $scan_id),
            ARRAY_A
        );
        if (!$scan) {
            return new \WP_Error('scan_not_found', 'Scan log not found', ['status' => 404]);
        }

        // Prune any duplicate issue rows for this historical log to heal database
        self::prune_duplicate_issues($scan_id);

        $scan_iss_sql = "SELECT * FROM `{$table_issues}` WHERE scan_id = %d ORDER BY FIELD(severity, 'critical', 'high', 'medium', 'low', 'info'), id DESC";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $issues = $wpdb->get_results(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $wpdb->prepare($scan_iss_sql, $scan_id),
            ARRAY_A
        );
        $issues = self::enrich_issues($issues);

        $fc_sql = "SELECT COUNT(*) FROM `{$table_files}` WHERE scan_id = %d";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $files_count = (int) $wpdb->get_var(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $wpdb->prepare($fc_sql, $scan_id)
        );

        $manifest_summary = null;
        if (class_exists('\\WebCareProScanner\\Scan\\ScanVaultManager')) {
            $manifest_summary = \WebCareProScanner\Scan\ScanVaultManager::get_manifest_summary($scan_id);
            if ($files_count === 0 && !empty($manifest_summary['files_count'])) {
                $files_count = (int) $manifest_summary['files_count'];
            }
        }

        if (empty($scan['trigger_type'])) {
            $scan['trigger_type'] = 'manual';
        }
        $detail_target_meta = self::format_scan_target_meta($scan['scan_target'] ?? 'plugins_themes');
        $scan['target_meta'] = $detail_target_meta;
        $scan['scan_target_name'] = $detail_target_meta['name'];
        $scan['scan_target_short'] = $detail_target_meta['short_name'];
        $scan['scan_target_category'] = $detail_target_meta['category'];
        $scan = self::enrich_scan_row_timestamps($scan);

        $scorer = new RiskScorer();
        $summary = $scorer->calculate($issues);
        $diagnostics = self::build_scan_diagnostics($scan);

        $interruption = null;
        if (in_array($scan['status'], ['interrupted', 'aborted', 'failed'], true)) {
            $interruption = \WebCareProScanner\Scan\ScanInterruptionForensics::get($scan_id);
        }

        return rest_ensure_response([
            'success'          => true,
            'scan'             => $scan,
            'summary'          => $summary,
            'issues'           => $issues,
            'files_count'      => $files_count,
            'manifest_summary' => $manifest_summary,
            'diagnostics'      => $diagnostics,
            'interruption' => $interruption,
        ]);
    }

    public static function export_scan_results(\WP_REST_Request $request) {
        global $wpdb;
        $scan_id = (int) $request->get_param('scan_id');
        $format  = sanitize_key($request->get_param('format') ?: 'json');

        $table_scans  = $wpdb->prefix . 'webcareproscan_scans';
        $table_issues = $wpdb->prefix . 'webcareproscan_scan_issues';

        if ($scan_id > 0) {
            $get_s_sql = "SELECT * FROM `{$table_scans}` WHERE id = %d";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $scan = $wpdb->get_row(
                // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                $wpdb->prepare($get_s_sql, $scan_id),
                ARRAY_A
            );
        } else {
            $get_s_sql = "SELECT * FROM `{$table_scans}` ORDER BY id DESC LIMIT 1";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $scan = $wpdb->get_row(
                // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                $get_s_sql,
                ARRAY_A
            );
        }

        if (!$scan) {
            return new \WP_Error('scan_not_found', 'No scan record found to export.', ['status' => 404]);
        }

        $iss_s_sql = "SELECT * FROM `{$table_issues}` WHERE scan_id = %d ORDER BY FIELD(severity, 'critical', 'high', 'medium', 'low', 'info'), id DESC";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $issues = $wpdb->get_results(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $wpdb->prepare($iss_s_sql, (int) $scan['id']),
            ARRAY_A
        );
        $issues = self::enrich_issues($issues);

        $scorer  = new RiskScorer();
        $summary = $scorer->calculate($issues);
        $diagnostics = self::build_scan_diagnostics($scan);

        $include_system_info = !empty($request->get_param('include_system_info'));

        if ($format === 'csv') {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Writing to in-memory temporary stream for REST CSV export
            $output  = fopen('php://temp', 'r+');
            // Sysadmin Telemetry & Environment comments header
            $site_url = get_site_url();
            $site_name = get_bloginfo('name');

            if ($include_system_info) {
                $peak_ram = $diagnostics['peak_memory_fmt'] . ' / ' . $diagnostics['memory_limit_raw'] . ' (' . $diagnostics['memory_percent'] . '%)';
                $throughput = $diagnostics['files_per_second'] . ' files/sec';
                $cpu_str = !empty($diagnostics['cpu_load'])
                    ? '1m: ' . ($diagnostics['cpu_load']['1m'] ?? '-') . ', 5m: ' . ($diagnostics['cpu_load']['5m'] ?? '-') . ', 15m: ' . ($diagnostics['cpu_load']['15m'] ?? '-')
                    : 'N/A';
                if (!empty($diagnostics['cpu_cores'])) {
                    $cpu_str .= ' (' . $diagnostics['cpu_cores'] . ' Cores)';
                }
                $server_soft = $diagnostics['server_software'] ?? 'Unknown';
                $server_os = $diagnostics['server_os'] . ' (' . ($diagnostics['server_arch'] ?? 'x86_64') . ')';
                $php_info = 'PHP ' . $diagnostics['php_version'] . ' (' . $diagnostics['php_sapi'] . ') | Max Execution: ' . ($diagnostics['php_max_execution_time'] ?? '30') . 's';
                $db_info = 'MySQL ' . ($diagnostics['database_version'] ?? 'N/A');

                $telemetry = class_exists('\\WebCareProScanner\\System\\TelemetrySnapshot') ? \WebCareProScanner\System\TelemetrySnapshot::get_snapshot() : null;
                $cf_text = !empty($telemetry['edge_network']['powered_by_cloudflare']) ? 'YES (' . ($telemetry['edge_network']['cloudflare_status'] ?? 'Cloudflare Edge') . ')' : 'NO (Direct Origin)';
                $act_plugins = !empty($telemetry['plugins']['active_plugins']) ? array_column($telemetry['plugins']['active_plugins'], 'name') : [];
                $act_plugins_str = implode(', ', array_slice($act_plugins, 0, 15)) . (count($act_plugins) > 15 ? sprintf(' ... (+%d more)', count($act_plugins) - 15) : '');

                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
                fwrite($output, "# ====================================================================\r\n");
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
                fwrite($output, "# WebCare Pro Security & Firewall - Audit Findings Report\r\n");
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
                fwrite($output, "# Auditor: Mir Alamin (WebCare Pro) - Senior Linux SysAdmin & WordPress Security Engineer\r\n");
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
                fwrite($output, "# Target: {$site_name} ({$site_url})\r\n");
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
                fwrite($output, "# Real Server IP: " . ($telemetry['server']['real_ip'] ?? 'Unknown') . " | Cloudflare: {$cf_text}\r\n");
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
                fwrite($output, "# Peak RAM: {$peak_ram}\r\n");
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
                fwrite($output, "# Throughput: {$throughput}\r\n");
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
                fwrite($output, "# CPU Load: {$cpu_str}\r\n");
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
                fwrite($output, "# Server Software: {$server_soft}\r\n");
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
                fwrite($output, "# Platform & OS: {$server_os}\r\n");
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
                fwrite($output, "# PHP Environment: {$php_info}\r\n");
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
                fwrite($output, "# Database: {$db_info}\r\n");
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
                fwrite($output, "# Active Theme: " . ($telemetry['theme']['active_theme']['name'] ?? 'Unknown') . " (v" . ($telemetry['theme']['active_theme']['version'] ?? 'Unknown') . ")\r\n");
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
                fwrite($output, "# Active Plugins (" . count($act_plugins) . "): {$act_plugins_str}\r\n");
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
                fwrite($output, "# Active Engines: " . ($diagnostics['engines_active'] ?? 23) . " Core Security Engines\r\n");
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
                fwrite($output, "# Exported: " . current_time('mysql') . "\r\n");
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
                fwrite($output, "# ====================================================================\r\n");
            }
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
            fwrite($output, "# Target: {$site_name} ({$site_url})\r\n");
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
            fwrite($output, "# Peak RAM: {$peak_ram}\r\n");
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
            fwrite($output, "# Throughput: {$throughput}\r\n");
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
            fwrite($output, "# CPU Load: {$cpu_str}\r\n");
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
            fwrite($output, "# Server Software: {$server_soft}\r\n");
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
            fwrite($output, "# Platform & OS: {$server_os}\r\n");
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
            fwrite($output, "# PHP Environment: {$php_info}\r\n");
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
            fwrite($output, "# Database: {$db_info}\r\n");
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
            fwrite($output, "# Active Engines: " . ($diagnostics['engines_active'] ?? 23) . " Core Security Engines\r\n");
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
            fwrite($output, "# Exported: " . current_time('mysql') . "\r\n");
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
            fwrite($output, "# ====================================================================\r\n");

            $headers = [
                'ID',
                'Severity',
                'Engine',
                'Threat Type',
                'File / Target',
                'Line Number',
                'SHA-256 Hash',
                'File Permissions',
                'Owner:Group',
                'File Size',
                'Created Time (ctime)',
                'Last Edited (mtime)',
                'Last Accessed (atime)',
                'MIME Type',
                'Is Writable',
                'Status',
                'Description & Remediation',
            ];
            fputcsv($output, $headers);

            foreach ($issues as $issue) {
                $fs = $issue['fs_forensics'] ?? [];
                $sha256 = $issue['sha256'] ?? ($issue['file_sha256'] ?? ($fs['sha256'] ?? ''));
                $perms = !empty($fs['current_permissions']) ? $fs['current_permissions'] . ' (' . ($fs['symbolic_permissions'] ?? '') . ')' : '';
                $owner_group = (!empty($fs['owner']) || !empty($fs['group'])) ? ($fs['owner'] ?? 'unknown') . ':' . ($fs['group'] ?? 'unknown') : '';
                $size = $fs['file_size_formatted'] ?? (!empty($fs['file_size']) ? $fs['file_size'] . ' B' : '');
                $ctime = $fs['created_time'] ?? '';
                $mtime = $fs['modified_time'] ?? '';
                $atime = $fs['accessed_time'] ?? '';
                $mime = $fs['mime_type'] ?? '';
                $writable = isset($fs['is_writable']) ? ($fs['is_writable'] ? 'Yes' : 'No') : '';

                fputcsv($output, [
                    $issue['id'] ?? '',
                    strtoupper($issue['severity'] ?? 'low'),
                    $issue['engine'] ?? '',
                    $issue['display_title'] ?? ($issue['type'] ?? ''),
                    $issue['file_path'] ?? '',
                    $issue['line_number'] ?? '',
                    $sha256,
                    $perms,
                    $owner_group,
                    $size,
                    $ctime,
                    $mtime,
                    $atime,
                    $mime,
                    $writable,
                    $issue['status'] ?? 'open',
                    $issue['description'] ?? '',
                ]);
            }

            rewind($output);
            $csv_data = stream_get_contents($output);
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
            fclose($output);

            $host_raw   = wp_parse_url(get_site_url(), PHP_URL_HOST) ?: 'site';
            $domain     = strtolower(preg_replace('/[^a-z0-9]/i', '-', preg_replace('/^www\./i', '', $host_raw)));
            $date_token = gmdate('Y-m-d');
            $time_token = gmdate('His');
            $rand_token = substr(wp_generate_password(8, false), 0, 5);
            $filename   = "scan-report-{$date_token}-{$time_token}-{$domain}-{$rand_token}.csv";

            return rest_ensure_response([
                'success'     => true,
                'format'      => 'csv',
                'filename'    => $filename,
                'csv_data'    => $csv_data,
                'diagnostics' => $diagnostics,
            ]);
        }

        $host_raw   = wp_parse_url(get_site_url(), PHP_URL_HOST) ?: 'site';
        $domain     = strtolower(preg_replace('/[^a-z0-9]/i', '-', preg_replace('/^www\./i', '', $host_raw)));
        $date_token = gmdate('Y-m-d');
        $time_token = gmdate('His');
        $rand_token = substr(wp_generate_password(8, false), 0, 5);
        $filename   = "scan-report-{$date_token}-{$time_token}-{$domain}-{$rand_token}.json";

        $response_data = [
            'success'            => true,
            'format'             => 'json',
            'filename'           => $filename,
            'report_generator'   => 'WebCare Pro Security & Firewall',
            'specialist'         => 'Mir Alamin (WebCare Pro)',
            'specialist_role'    => 'Senior Linux SysAdmin & WordPress Security Engineer',
            'site_url'           => get_site_url(),
            'site_name'          => get_bloginfo('name'),
            'exported_at'        => current_time('mysql'),
            'scan'               => $scan,
            'summary'            => $summary,
            'diagnostics'        => $diagnostics,
            'server_diagnostics' => [
                'peak_ram'               => $diagnostics['peak_memory_fmt'],
                'peak_ram_mb'            => $diagnostics['peak_memory_mb'],
                'memory_limit'           => $diagnostics['memory_limit_raw'],
                'memory_usage_percent'   => $diagnostics['memory_percent'] . '%',
                'throughput'             => $diagnostics['files_per_second'] . ' files/sec',
                'files_per_second'       => $diagnostics['files_per_second'],
                'cpu_load'               => $diagnostics['cpu_load'],
                'cpu_cores'              => $diagnostics['cpu_cores'] ?? null,
                'server_software'        => $diagnostics['server_software'] ?? 'Unknown',
                'server_os'              => $diagnostics['server_os'],
                'server_architecture'    => $diagnostics['server_arch'] ?? 'x86_64',
                'php_version'            => $diagnostics['php_version'],
                'php_sapi'               => $diagnostics['php_sapi'],
                'php_max_execution_time' => ($diagnostics['php_max_execution_time'] ?? 30) . 's',
                'database_version'       => $diagnostics['database_version'] ?? 'N/A',
                'database_name'          => $diagnostics['database_name'] ?? 'N/A',
                'wordpress_version'      => $diagnostics['wordpress_version'] ?? 'N/A',
                'ssl_active'             => !empty($diagnostics['ssl_active']) ? 'Active (HTTPS)' : 'Inactive (HTTP)',
                'opcache'                => $diagnostics['opcache_status'] ?? 'Disabled',
                'active_engines'         => $diagnostics['engines_active'] ?? 23,
            ],
            'findings_count'     => count($issues),
            'findings'           => $issues,
        ];

        if ($include_system_info && class_exists('\\WebCareProScanner\\System\\TelemetrySnapshot')) {
            $response_data['environment_snapshot'] = \WebCareProScanner\System\TelemetrySnapshot::get_snapshot();
        }

        return rest_ensure_response($response_data);
    }

    /**
     * Download the full raw Scan Vault JSON manifest for a given scan ID.
     */
    public static function download_scan_manifest(\WP_REST_Request $request) {
        if (is_multisite() && !current_user_can('manage_network')) {
            return new \WP_Error('rest_forbidden', __('Multisite network administrator privileges required.', 'webcare-pro-security'), ['status' => 403]);
        }

        $scan_id = (int) $request->get_param('scan_id');
        if ($scan_id <= 0) {
            global $wpdb;
            $table_scans = $wpdb->prefix . 'webcareproscan_scans';
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $scan_id = (int) $wpdb->get_var($wpdb->prepare('SELECT id FROM %i ORDER BY id DESC LIMIT 1', $table_scans));
        }

        if ($scan_id <= 0) {
            return new \WP_Error('no_scans', __('No scans found.', 'webcare-pro-security'), ['status' => 404]);
        }

        $manifest_json = null;
        $filename      = null;

        if (class_exists('\\WebCareProScanner\\Scan\\ScanVaultManager')) {
            $manifest_file = \WebCareProScanner\Scan\ScanVaultManager::find_manifest_file($scan_id);
            if ($manifest_file) {
                $raw_base = basename($manifest_file);
                if (str_ends_with($raw_base, '.temp.jsonl')) {
                    $filename = \WebCareProScanner\Scan\ScanVaultManager::get_manifest_filename($scan_id, '', true);
                } else {
                    // Strip internal _{24-char-hmac} suffix from user-facing download filename
                    $filename = (string) preg_replace('/_[a-f0-9]{24}\.json$/i', '.json', $raw_base);
                }
                $manifest_json = \WebCareProScanner\Scan\ScanVaultManager::get_full_manifest_content($scan_id);
            }
        }

        if (!$manifest_json) {
            // Check legacy database fallback
            global $wpdb;
            $table_files = $wpdb->prefix . 'webcareproscan_scan_files';
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $legacy_files = $wpdb->get_results(
                $wpdb->prepare('SELECT * FROM %i WHERE scan_id = %d ORDER BY id ASC', $table_files, $scan_id),
                ARRAY_A
            );

            if (!empty($legacy_files)) {
                $host_raw = wp_parse_url(get_site_url(), PHP_URL_HOST) ?: 'site';
                $domain   = strtolower(preg_replace('/[^a-z0-9]/i', '-', preg_replace('/^www\./i', '', $host_raw)));
                $filename = "{$domain}_scan{$scan_id}_legacy.json";
                $manifest_json = (string) wp_json_encode([
                    'vault_format' => '1.0-legacy-db',
                    'scan_id'      => $scan_id,
                    'site_url'     => get_site_url(),
                    'files_count'  => count($legacy_files),
                    'files'        => $legacy_files,
                ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
            }
        }

        if (!$manifest_json) {
            return new \WP_Error('manifest_not_found', __('Scan Vault manifest JSON file was not found for this scan.', 'webcare-pro-security'), ['status' => 404]);
        }

        return rest_ensure_response([
            'success'       => true,
            'scan_id'       => $scan_id,
            'filename'      => $filename ?: "scan_{$scan_id}_manifest.json",
            'manifest_json' => $manifest_json,
        ]);
    }

    public static function get_vulnerabilities_report(\WP_REST_Request $request) {
        $report = UpdateScanner::get_detailed_report();

        $shielded_slugs = [];
        if (class_exists('\\WebCareProScanner\\Firewall\\Modular\\ModularFirewallSynthesizer')) {
            foreach (\WebCareProScanner\Firewall\Modular\ModularFirewallSynthesizer::get_active_rules() as $mr) {
                if (($mr['category'] ?? '') === 'cve_patch' && ($mr['current_mode'] ?? '') === 'enforce' && !empty($mr['component_slug'])) {
                    $shielded_slugs[$mr['component_slug']] = $mr['id'];
                }
            }
        }
        $safe_backups = get_option(\WebCareProScanner\Firewall\RescueAssistantManager::OPTION_SAFE_UPDATES, []);

        return rest_ensure_response([
            'success'             => true,
            'report'              => $report,
            'virtual_shields'     => $shielded_slugs,
            'safe_update_backups' => is_array($safe_backups) ? $safe_backups : [],
        ]);
    }

    /**
     * Activate 1-click Virtual Shield (MOD-CVE-*) for an outdated or vulnerable component without updating.
     */
    public static function activate_vulnerability_virtual_shield(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\Modular\\ModularFirewallSynthesizer')) {
            return new \WP_REST_Response(['success' => false, 'message' => __('Virtual shield synthesizer unavailable.', 'webcare-pro-security')], 500);
        }
        $params = $request->get_json_params() ?: [];
        $slug   = sanitize_key($params['slug'] ?? '');
        $type   = sanitize_key($params['type'] ?? 'plugin');
        $res    = \WebCareProScanner\Firewall\Modular\ModularFirewallSynthesizer::activate_cve_shield($slug, $type);
        return new \WP_REST_Response($res, !empty($res['success']) ? 200 : 400);
    }

    /**
     * Safely back up a plugin to Gatekeeper storage and run WordPress Plugin_Upgrader.
     */
    public static function execute_safe_plugin_update(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\RescueAssistantManager')) {
            return new \WP_REST_Response(['success' => false, 'message' => __('Safe update manager unavailable.', 'webcare-pro-security')], 500);
        }
        $params      = $request->get_json_params() ?: [];
        $plugin_file = sanitize_text_field(wp_unslash($params['plugin_file'] ?? ''));
        $slug        = sanitize_key($params['slug'] ?? '');
        $name        = sanitize_text_field(wp_unslash($params['name'] ?? ''));
        $res         = \WebCareProScanner\Firewall\RescueAssistantManager::safe_update_plugin($plugin_file, $slug, $name);
        return new \WP_REST_Response($res, !empty($res['success']) ? 200 : 400);
    }

    /**
     * Roll back a safely updated plugin to its Gatekeeper pre-update backup snapshot.
     */
    public static function execute_safe_plugin_rollback(\WP_REST_Request $request) {
        if (!class_exists('\\WebCareProScanner\\Firewall\\RescueAssistantManager')) {
            return new \WP_REST_Response(['success' => false, 'message' => __('Safe update manager unavailable.', 'webcare-pro-security')], 500);
        }
        $params      = $request->get_json_params() ?: [];
        $snapshot_id = sanitize_text_field(wp_unslash($params['snapshot_id'] ?? ''));
        $res         = \WebCareProScanner\Firewall\RescueAssistantManager::rollback_safe_update($snapshot_id);
        return new \WP_REST_Response($res, !empty($res['success']) ? 200 : 400);
    }

    public static function get_active_scan(\WP_REST_Request $request) {
        global $wpdb;

        $table_scans = $wpdb->prefix . 'webcareproscan_scans';
        $locked_id = ScanLock::get_locked_scan_id();

        // If no lock option exists, check if there is an active scan record in the DB created recently
        if (!$locked_id) {
            // Find and record any stale scans marked 'running' older than 10 minutes
            $stale_scans_sql = "SELECT id, scanned_files, total_files FROM `{$table_scans}` WHERE status = 'running' AND created_at < DATE_SUB(NOW(), INTERVAL 10 MINUTE)";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $stale_scans = $wpdb->get_results($stale_scans_sql, ARRAY_A);
            if (!empty($stale_scans)) {
                foreach ($stale_scans as $stale_row) {
                    $stale_id = (int) $stale_row['id'];
                    \WebCareProScanner\Scan\ScanInterruptionForensics::record($stale_id, \WebCareProScanner\Scan\ScanInterruptionForensics::REASON_STALE_HEARTBEAT);
                }
            }

            // Clean up any stale scans marked 'running' older than 10 minutes
            $cleanup_stale = "UPDATE `{$table_scans}` SET status = 'interrupted', completed_at = NOW() WHERE status = 'running' AND created_at < DATE_SUB(NOW(), INTERVAL 10 MINUTE)";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $wpdb->query($cleanup_stale);

            // Fallback: check if any recent scan (< 5 mins) is legitimately running in database
            $rec_act_sql = "SELECT * FROM `{$table_scans}` WHERE status = 'running' AND created_at >= DATE_SUB(NOW(), INTERVAL 5 MINUTE) ORDER BY id DESC LIMIT 1";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $recent_active = $wpdb->get_row($rec_act_sql, ARRAY_A);

            if ($recent_active) {
                $locked_id = (int) $recent_active['id'];
                ScanLock::acquire($locked_id);
            } else {
                return rest_ensure_response([
                    'is_running' => false,
                ]);
            }
        }

        $run_scan_sql = "SELECT * FROM `{$table_scans}` WHERE id = %d";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $running_scan = $wpdb->get_row(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $wpdb->prepare($run_scan_sql, $locked_id),
            ARRAY_A
        );

        if (!$running_scan || $running_scan['status'] !== 'running') {
            ScanLock::force_release($locked_id);
            return rest_ensure_response([
                'is_running' => false,
            ]);
        }

        // Lock heartbeat
        $total = (int) $running_scan['total_files'];
        $scanned = (int) $running_scan['scanned_files'];
        $trigger_type = !empty($running_scan['trigger_type']) ? $running_scan['trigger_type'] : 'manual';
        $remaining = \WebCareProScanner\Scan\ScanQueueManager::get_remaining_count($locked_id);
        if ($remaining === 0 && $total > $scanned) {
            $remaining = max(0, $total - $scanned);
        }
        $last_file = get_transient("webcareproscan_active_scan_file_{$locked_id}") ?: '';
        $db_progress = get_transient("webcareproscan_scan_db_progress_{$locked_id}");

        $live_telemetry = get_transient("webcareproscan_scan_live_telemetry_{$locked_id}");
        if (!$live_telemetry || !is_array($live_telemetry)) {
            $live_telemetry = self::get_realtime_resource_stats(null, null, $scanned, $total, (int) $running_scan['issues_found'], 0.0);
        }

        return rest_ensure_response([
            'is_running'     => true,
            'scan_id'        => $locked_id,
            'lease_token'    => ScanLock::get_active_lease_token($locked_id),
            'scan_target'    => $running_scan['scan_target'],
            'trigger_type'   => $trigger_type,
            'status'         => 'running',
            'scanned_files'  => $scanned,
            'total_files'    => $total,
            'remaining'      => $remaining,
            'last_file'      => $last_file,
            'db_progress'    => is_array($db_progress) ? $db_progress : null,
            'issues_found'   => (int) $running_scan['issues_found'],
            'telemetry'      => $live_telemetry,
            'phase'          => ($trigger_type === 'scheduled') 
                ? (($scanned >= $total && $total > 0) ? 'deep_audit' : 'batch')
                : (($remaining > 0) ? 'batch' : 'deep_audit'),
            'created_at'     => $running_scan['created_at'],
            'started_at'     => $running_scan['started_at'] ?? $running_scan['created_at'],
            'elapsed'        => (function() use ($running_scan, $locked_id) {
                $start_micro = get_transient("webcareproscan_scan_start_micro_{$locked_id}");
                if ($start_micro && is_numeric($start_micro)) {
                    $diff = microtime(true) - (float) $start_micro;
                    if ($diff > 0) return max(1, (int) round($diff));
                }
                if (!empty($running_scan['started_at'])) {
                    $start_dt = date_create($running_scan['started_at'], wp_timezone());
                    if ($start_dt) {
                        $now_dt = date_create('now', wp_timezone());
                        return max(1, $now_dt->getTimestamp() - $start_dt->getTimestamp());
                    }
                }
                if (empty($running_scan['created_at'])) return 1;
                $created_dt = date_create($running_scan['created_at'], wp_timezone());
                if ($created_dt) {
                    $now_dt = date_create('now', wp_timezone());
                    return max(1, $now_dt->getTimestamp() - $created_dt->getTimestamp());
                }
                return 1;
            })(),
            'elapsed_ms'     => (function() use ($running_scan, $locked_id) {
                $start_micro = get_transient("webcareproscan_scan_start_micro_{$locked_id}");
                if ($start_micro && is_numeric($start_micro)) {
                    $diff = microtime(true) - (float) $start_micro;
                    if ($diff > 0) return (int) round($diff * 1000);
                }
                if (!empty($running_scan['started_at'])) {
                    $start_dt = date_create($running_scan['started_at'], wp_timezone());
                    if ($start_dt) {
                        $now_dt = date_create('now', wp_timezone());
                        $diff = $now_dt->getTimestamp() - $start_dt->getTimestamp() + (($now_dt->format('u') - $start_dt->format('u')) / 1000000);
                        return max(100, (int) round($diff * 1000));
                    }
                }
                return 1000;
            })(),
        ]);
    }

    public static function abort_scan(\WP_REST_Request $request) {
        global $wpdb;

        $table_scans = $wpdb->prefix . 'webcareproscan_scans';
        $scan_id = (int) $request->get_param('scan_id');
        if (!$scan_id) {
            $scan_id = ScanLock::get_locked_scan_id();
        }

        $now_exact = self::now_fractional_mysql();

        if ($scan_id) {
            $aborted = ScanLock::force_release($scan_id);
            if (class_exists('\\WebCareProScanner\\Scan\\ScanBackgroundWorker')) {
                \WebCareProScanner\Scan\ScanBackgroundWorker::unschedule_continuation();
            }
            delete_transient("webcareproscan_active_scan_last_browser_touch_{$scan_id}");
            if (!$aborted) {
                return new \WP_Error(
                    'abort_failed',
                    esc_html__('Failed to forcefully release active scan lock due to database mutex timeout or storage persistence error.', 'webcare-pro-security'),
                    ['status' => 500]
                );
            }

            $start_micro = get_transient("webcareproscan_scan_start_micro_{$scan_id}");
            $duration_ms = 0;
            $duration_sec = 0;
            if ($start_micro && is_numeric($start_micro)) {
                $calc_diff = microtime(true) - (float) $start_micro;
                if ($calc_diff > 0) {
                    $duration_ms = (int) round($calc_diff * 1000);
                    $duration_sec = max(1, (int) round($calc_diff));
                }
            }
            $last_file = get_transient("webcareproscan_active_scan_file_{$scan_id}") ?: '';
            delete_transient("webcareproscan_scan_start_micro_{$scan_id}");

            // Record manual abort forensic details
            \WebCareProScanner\Scan\ScanInterruptionForensics::record($scan_id, \WebCareProScanner\Scan\ScanInterruptionForensics::REASON_MANUAL_ABORT, [
                'last_file' => $last_file,
            ]);

            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->update($table_scans, [
                'status'       => 'aborted',
                'duration'     => $duration_sec,
                'duration_ms'  => $duration_ms,
                'completed_at' => $now_exact,
            ], ['id' => $scan_id]);
            \WebCareProScanner\Scan\ScanQueueManager::cleanup($scan_id);
        }

        // Also release any active scan lock and ensure any hanging scans are aborted
        if (ScanLock::is_locked() && !ScanLock::force_release()) {
            return new \WP_Error(
                'abort_failed',
                esc_html__('Failed to forcefully release active scan lock due to database mutex timeout or storage persistence error.', 'webcare-pro-security'),
                ['status' => 500]
            );
        }
        $abort_sql = "UPDATE `{$table_scans}` SET status = 'aborted', completed_at = %s WHERE status = 'running'";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $wpdb->query(
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $wpdb->prepare($abort_sql, $now_exact)
        );

        return rest_ensure_response([
            'success' => true,
            'message' => 'Scan successfully aborted and lock released.',
        ]);
    }

    /**
     * Retrieve changelog content for a specific theme or plugin component.
     * Prioritizes fetching the latest upstream release changelog from official WordPress.org.
     * If latest version changelog is not found or fails, gracefully falls back to the locally installed version.
     *
     * @param \WP_REST_Request $request
     * @return \WP_REST_Response|\WP_Error
     */
    public static function get_component_changelog(\WP_REST_Request $request) {
        $raw_path = sanitize_text_field($request->get_param('path') ?: ($request->get_param('file_path') ?: ''));
        $slug = sanitize_text_field($request->get_param('slug') ?: '');
        $type = sanitize_key($request->get_param('type') ?: 'plugin'); // 'plugin' or 'theme'
        $installed_ver = sanitize_text_field($request->get_param('installed_version') ?: '');
        $latest_ver = sanitize_text_field($request->get_param('latest_version') ?: '');

        $target_dir = '';
        if (!empty($raw_path)) {
            $raw_path = str_replace(['../', '..\\'], '', $raw_path);
            if (is_dir($raw_path)) {
                $target_dir = wp_normalize_path($raw_path);
            } elseif (is_file($raw_path)) {
                $target_dir = wp_normalize_path(dirname($raw_path));
            }
        }

        if (empty($target_dir) && !empty($slug)) {
            if ($type === 'theme') {
                $theme_root = function_exists('get_theme_root') ? get_theme_root() : (WP_CONTENT_DIR . '/themes');
                $candidate = wp_normalize_path($theme_root . '/' . $slug);
                if (file_exists($candidate) && is_dir($candidate)) {
                    $target_dir = $candidate;
                }
            } else {
                $candidate = wp_normalize_path(WP_PLUGIN_DIR . '/' . $slug);
                if (file_exists($candidate) && is_dir($candidate)) {
                    $target_dir = $candidate;
                }
            }
        }

        // Derive slug if empty
        if (empty($slug)) {
            $check_path = $target_dir ?: $raw_path;
            if (preg_match('#[\\\\/]wp-content[\\\\/]themes[\\\\/]([^\\\\/]+)#i', $check_path, $m)) {
                $slug = $m[1];
                $type = 'theme';
            } elseif (preg_match('#[\\\\/]wp-content[\\\\/]plugins[\\\\/]([^\\\\/]+)#i', $check_path, $m)) {
                $slug = $m[1];
                $type = 'plugin';
            } elseif (!empty($target_dir)) {
                $slug = basename($target_dir);
            }
        }
        $slug = preg_replace('/\.php$/i', '', $slug);

        // Fetch component metadata if versions are not provided
        if (empty($installed_ver) || empty($latest_ver)) {
            if ($type === 'theme' && !empty($target_dir)) {
                $meta = self::get_theme_forensics_meta($target_dir, ['theme_slug' => $slug]);
                $installed_ver = $installed_ver ?: ($meta['version'] ?? '');
                $latest_ver = $latest_ver ?: ($meta['latest_version'] ?? '');
            } elseif (!empty($target_dir)) {
                $meta = self::get_plugin_forensics_meta($target_dir, ['plugin_dir' => $slug]);
                $installed_ver = $installed_ver ?: ($meta['version'] ?? '');
                $latest_ver = $latest_ver ?: ($meta['latest_version'] ?? '');
            }
        }

        $latest_changelog_found = false;
        $latest_content = '';
        $latest_source = '';
        $resolved_latest_version = $latest_ver;

        // --- STEP 1: Attempt to retrieve latest version changelog from WordPress Update Manager / Vendor API / Official Repository ---
        if ($type === 'plugin' && (!empty($slug) || !empty($target_dir))) {
            $cache_key = 'webcareproscan_up_cl_pl_' . substr(md5(($slug ?: basename($target_dir)) . '_' . $latest_ver), 0, 16);
            $cached = function_exists('get_transient') ? get_transient($cache_key) : false;
            if (!empty($cached) && is_array($cached) && !empty($cached['content'])) {
                $latest_changelog_found = true;
                $latest_content = $cached['content'];
                $latest_source = $cached['source'];
                $resolved_latest_version = $cached['version'] ?: $latest_ver;
            } else {
                // 1.1 Resolve plugin main file
                $matched_file = '';
                if (!function_exists('get_plugins')) {
                    require_once ABSPATH . 'wp-admin/includes/plugin.php';
                }
                $all_plugins = function_exists('get_plugins') ? get_plugins() : [];
                $norm_target = wp_normalize_path($target_dir);
                $folder_name = $slug ?: basename($norm_target);

                foreach ($all_plugins as $p_file => $p_data) {
                    if (dirname($p_file) === $folder_name || $p_file === $folder_name || (!empty($norm_target) && wp_normalize_path(WP_PLUGIN_DIR . '/' . dirname($p_file)) === $norm_target)) {
                        $matched_file = $p_file;
                        break;
                    }
                }

                // 1.2 Inspect WordPress update transient (handles premium updaters like YITH, EDD, PUC, WooCommerce Helper)
                $update_plugins = function_exists('get_site_transient') ? get_site_transient('update_plugins') : false;
                $update_entry = null;

                if (!empty($update_plugins) && is_object($update_plugins)) {
                    if (!empty($matched_file) && !empty($update_plugins->response[$matched_file])) {
                        $update_entry = $update_plugins->response[$matched_file];
                    } elseif (!empty($matched_file) && !empty($update_plugins->no_update[$matched_file])) {
                        $update_entry = $update_plugins->no_update[$matched_file];
                    } else {
                        foreach ($update_plugins->response ?? [] as $up_file => $up_data) {
                            if (dirname($up_file) === $folder_name || (!empty($up_data->slug) && $up_data->slug === $folder_name)) {
                                $update_entry = $up_data;
                                $matched_file = $up_file;
                                break;
                            }
                        }
                        if (!$update_entry) {
                            foreach ($update_plugins->no_update ?? [] as $up_file => $up_data) {
                                if (dirname($up_file) === $folder_name || (!empty($up_data->slug) && $up_data->slug === $folder_name)) {
                                    $update_entry = $up_data;
                                    $matched_file = $up_file;
                                    break;
                                }
                            }
                        }
                    }
                }

                if (is_object($update_entry)) {
                    if (!empty($update_entry->new_version)) {
                        $resolved_latest_version = $update_entry->new_version;
                    }
                    // Check direct changelog inside update transient
                    if (!empty($update_entry->sections['changelog'])) {
                        $latest_content = self::format_changelog_html($update_entry->sections['changelog']);
                        $latest_changelog_found = true;
                        $latest_source = 'WordPress Plugin Update Manager';
                    } elseif (!empty($update_entry->changelog)) {
                        $latest_content = self::format_changelog_html($update_entry->changelog);
                        $latest_changelog_found = true;
                        $latest_source = 'WordPress Plugin Update Manager';
                    } elseif (!empty($update_entry->upgrade_notice)) {
                        $latest_content = self::format_changelog_html($update_entry->upgrade_notice);
                        $latest_changelog_found = true;
                        $latest_source = 'WordPress Plugin Update Manager';
                    }
                }

                // 1.3 Native WordPress plugins_api (queries registered updater filters e.g. YITH License Manager, PUC, etc.)
                if (!$latest_changelog_found) {
                    if (!function_exists('plugins_api')) {
                        require_once ABSPATH . 'wp-admin/includes/plugin-install.php';
                    }

                    $slug_candidates = [];
                    if (is_object($update_entry)) {
                        if (!empty($update_entry->slug)) $slug_candidates[] = (string) $update_entry->slug;
                        if (!empty($update_entry->id)) $slug_candidates[] = (string) $update_entry->id;
                    }
                    if (!empty($slug)) $slug_candidates[] = $slug;
                    if (!empty($folder_name)) $slug_candidates[] = $folder_name;
                    if (!empty($matched_file)) {
                        $slug_candidates[] = $matched_file;
                        $slug_candidates[] = dirname($matched_file);
                    }
                    $slug_candidates = array_unique(array_filter($slug_candidates));

                    if (function_exists('plugins_api')) {
                        foreach ($slug_candidates as $try_slug) {
                            $api = plugins_api('plugin_information', [
                                'slug'   => $try_slug,
                                'is_ssl' => is_ssl(),
                                'fields' => [
                                    'sections' => true,
                                    'version'  => true,
                                    'banners'  => false,
                                    'reviews'  => false,
                                ],
                            ]);

                            if (!is_wp_error($api) && is_object($api) && !empty($api->sections['changelog'])) {
                                $latest_content = self::format_changelog_html($api->sections['changelog']);
                                $latest_changelog_found = true;
                                $vendor_name = !empty($api->name) ? $api->name : 'Plugin Update Manager';
                                $latest_source = $vendor_name . ' Update API';
                                if (!empty($api->version)) {
                                    $resolved_latest_version = $api->version;
                                }
                                break;
                            }
                        }
                    }
                }

                // 1.4 Official WordPress.org SVN Repository (for free/official directory plugins)
                if (!$latest_changelog_found && !empty($slug)) {
                    $svn_urls = [];
                    if (!empty($latest_ver)) {
                        $svn_urls[] = "https://plugins.svn.wordpress.org/{$slug}/tags/{$latest_ver}/readme.txt";
                    }
                    $svn_urls[] = "https://plugins.svn.wordpress.org/{$slug}/trunk/readme.txt";

                    foreach ($svn_urls as $url) {
                        $response = function_exists('wp_remote_get')
                            ? wp_remote_get($url, ['timeout' => 4, 'sslverify' => true, 'headers' => ['User-Agent' => 'WordPress/' . get_bloginfo('version')]])
                            : false;

                        if (!is_wp_error($response) && is_array($response)) {
                            $code = wp_remote_retrieve_response_code($response);
                            if ($code === 200) {
                                $body = wp_remote_retrieve_body($response);
                                if (!empty($body)) {
                                    $extracted = self::extract_changelog_from_readme($body);
                                    $latest_content = !empty($extracted) ? $extracted : $body;
                                    $latest_changelog_found = true;
                                    $latest_source = 'WordPress.org SVN Repository';
                                    break;
                                }
                            }
                        }
                    }
                }

                if ($latest_changelog_found && function_exists('set_transient')) {
                    set_transient($cache_key, [
                        'content' => $latest_content,
                        'source'  => $latest_source,
                        'version' => $resolved_latest_version,
                    ], 12 * HOUR_IN_SECONDS);
                }
            }
        } elseif ($type === 'theme' && !empty($slug)) {
            $cache_key = 'webcareproscan_up_cl_th_' . substr(md5($slug . '_' . $latest_ver), 0, 16);
            $cached = function_exists('get_transient') ? get_transient($cache_key) : false;
            if (!empty($cached) && is_array($cached) && !empty($cached['content'])) {
                $latest_changelog_found = true;
                $latest_content = $cached['content'];
                $latest_source = $cached['source'];
                $resolved_latest_version = $cached['version'] ?: $latest_ver;
            } else {
                $candidates = [];
                if (!empty($latest_ver)) {
                    $candidates[] = "https://themes.svn.wordpress.org/{$slug}/{$latest_ver}/readme.txt";
                    $candidates[] = "https://themes.svn.wordpress.org/{$slug}/{$latest_ver}/changelog.txt";
                }
                foreach ($candidates as $url) {
                    $response = function_exists('wp_remote_get')
                        ? wp_remote_get($url, ['timeout' => 4, 'sslverify' => true])
                        : false;
                    if (!is_wp_error($response) && is_array($response)) {
                        $code = wp_remote_retrieve_response_code($response);
                        if ($code === 200) {
                            $body = wp_remote_retrieve_body($response);
                            if (!empty($body)) {
                                $latest_content = self::extract_changelog_from_readme($body) ?: $body;
                                $latest_changelog_found = true;
                                $latest_source = 'WordPress.org Themes Repository';
                                break;
                            }
                        }
                    }
                }
                if ($latest_changelog_found && function_exists('set_transient')) {
                    set_transient($cache_key, [
                        'content' => $latest_content,
                        'source'  => $latest_source,
                        'version' => $resolved_latest_version,
                    ], 12 * HOUR_IN_SECONDS);
                }
            }
        }

        // If latest upstream changelog was found, return it immediately
        if ($latest_changelog_found && !empty($latest_content)) {
            $version_label = $resolved_latest_version ? "v{$resolved_latest_version}" : 'Latest';
            $source_title = !empty($latest_source) ? $latest_source : 'WordPress Update Manager';
            return rest_ensure_response([
                'success'           => true,
                'has_changelog'     => true,
                'is_latest'         => true,
                'latest_not_found'  => false,
                'source'            => 'upstream_latest',
                /* translators: 1: version label, 2: source title */
                'source_label'      => sprintf(__('Latest Upstream Version (%1$s) from %2$s', 'webcare-pro-security'), $version_label, $source_title),
                'filename'          => "{$source_title} {$version_label} Release Notes",
                'file_size'         => strlen($latest_content),
                'version_shown'     => $resolved_latest_version ?: ($latest_ver ?: 'Latest'),
                'installed_version' => $installed_ver,
                'latest_version'    => $resolved_latest_version ?: $latest_ver,
                'content'           => $latest_content,
                'notice'            => '',
            ]);
        }

        // --- STEP 2: Fallback to reading the locally installed version changelog ---
        if (!empty($target_dir) && PathValidator::is_inside_root($target_dir, ABSPATH)) {
            $changelog = self::detect_component_changelog($target_dir);
            if ($changelog['has_changelog']) {
                $file_path = $changelog['full_path'];
                if (PathValidator::is_inside_root($file_path, $target_dir)) {
                    $max_bytes = 250 * 1024;
                    $content = file_get_contents($file_path, false, null, 0, $max_bytes);
                    if ($content !== false) {
                        if (function_exists('mb_check_encoding') && !mb_check_encoding($content, 'UTF-8')) {
                            $content = mb_convert_encoding($content, 'UTF-8', 'ISO-8859-1');
                        }

                        $target_label = $latest_ver ? "v{$latest_ver}" : 'latest upstream';
                        $installed_label = $installed_ver ? "v{$installed_ver}" : 'local';

                        return rest_ensure_response([
                            'success'           => true,
                            'has_changelog'     => true,
                            'is_latest'         => false,
                            'latest_not_found'  => true,
                            'source'            => 'local_installed',
                            'source_label'      => sprintf(
                                /* translators: %s: installed version label */
                                __('Currently Installed Version (%s) [Local Disk]', 'webcare-pro-security'),
                                $installed_label
                            ),
                            'filename'          => $changelog['filename'],
                            'file_size'         => (int) filesize($file_path),
                            'last_modified'     => gmdate('Y-m-d H:i:s', filemtime($file_path)) . ' UTC',
                            'version_shown'     => $installed_ver ?: 'Installed',
                            'installed_version' => $installed_ver,
                            'latest_version'    => $latest_ver,
                            'content'           => $content,
                            'notice'            => sprintf(
                                /* translators: 1: target version label, 2: installed version label */
                                __('Latest version (%1$s) changelog was not found on remote repositories or plugin update manager. Displaying currently installed version (%2$s) changelog from local disk below.', 'webcare-pro-security'),
                                $target_label,
                                $installed_label
                            ),
                        ]);
                    }
                }
            }
        }

        // --- STEP 3: Neither latest nor local changelog found ---
        return rest_ensure_response([
            'success'           => true,
            'has_changelog'     => false,
            'is_latest'         => false,
            'latest_not_found'  => true,
            'source'            => 'none',
            'filename'          => '',
            'content'           => '',
            'message'           => sprintf(
                /* translators: %s: latest version label */
                __('Latest version (%s) changelog was not found on WordPress.org, and no local changelog file (changelog.txt, readme.txt, or changelog.md) exists in the installed component folder.', 'webcare-pro-security'),
                $latest_ver ? "v{$latest_ver}" : 'upstream'
            ),
        ]);
    }

    /**
     * Safely read and return file content for code inspection popup modal.
     */
    public static function view_file_content(\WP_REST_Request $request) {
        if (is_multisite() && !current_user_can('manage_network')) {
            return new \WP_Error('rest_forbidden', __('Multisite network administrator privileges required.', 'webcare-pro-security'), ['status' => 403]);
        }
        $raw_path = sanitize_text_field($request->get_param('file_path') ?: ($request->get_param('path') ?: ''));
        if (empty($raw_path)) {
            return new \WP_Error('missing_path', __('File path parameter is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        // Clean path and ensure inside ABSPATH
        $raw_path = str_replace(['../', '..\\'], '', $raw_path);
        $norm_abspath = wp_normalize_path(ABSPATH);

        $target_full = '';
        if (file_exists($raw_path)) {
            $target_full = wp_normalize_path($raw_path);
        } else {
            $candidate = wp_normalize_path(ABSPATH . ltrim($raw_path, '/\\'));
            if (file_exists($candidate)) {
                $target_full = $candidate;
            }
        }

        if (empty($target_full) || !file_exists($target_full)) {
            return new \WP_Error('file_not_found', __('File does not exist or has been removed from server.', 'webcare-pro-security'), ['status' => 404]);
        }

        $wp_roots = \WebCareProScanner\Filesystem\PathValidator::get_wordpress_roots();
        $is_parent_wp_config = (realpath(dirname(ABSPATH) . '/wp-config.php') && realpath($target_full) === realpath(dirname(ABSPATH) . '/wp-config.php'));

        // Canonical directory boundary check: Enforce trailing slash on root to eliminate sibling directory escapes
        if (!\WebCareProScanner\Filesystem\PathValidator::is_inside_any_root($target_full, $wp_roots) && !$is_parent_wp_config) {
            return new \WP_Error('forbidden_path', __('Access to this file path is restricted outside WordPress root.', 'webcare-pro-security'), ['status' => 403]);
        }

        $real_path = realpath($target_full);
        if (!$real_path || !is_file($real_path)) {
            return new \WP_Error('not_a_file', __('The requested path is a directory or special file, not a viewable file.', 'webcare-pro-security'), ['status' => 400]);
        }

        // Resolve symlinks before enforcing the WordPress root boundary.
        if (!\WebCareProScanner\Filesystem\PathValidator::is_inside_any_root($real_path, $wp_roots) && !$is_parent_wp_config) {
            return new \WP_Error('forbidden_path', __('Access to this file path is restricted outside WordPress root.', 'webcare-pro-security'), ['status' => 403]);
        }

        if (!is_readable($real_path)) {
            return new \WP_Error('unreadable_file', __('File is not readable due to server permissions.', 'webcare-pro-security'), ['status' => 403]);
        }

        $file_size = (int) filesize($real_path);
        $max_read = 750 * 1024; // 750KB limit to protect memory
        $is_truncated = $file_size > $max_read;

        $content = file_get_contents($real_path, false, null, 0, $max_read);
        if ($content === false) {
            return new \WP_Error('read_error', __('Failed to read file content.', 'webcare-pro-security'), ['status' => 500]);
        }

        $perms = substr(sprintf('%o', fileperms($real_path)), -4);

        $extension = strtolower(pathinfo($real_path, PATHINFO_EXTENSION));
        $image_mimes = [
            'png'  => 'image/png',
            'jpg'  => 'image/jpeg',
            'jpeg' => 'image/jpeg',
            'gif'  => 'image/gif',
            'webp' => 'image/webp',
            'svg'  => 'image/svg+xml',
            'ico'  => 'image/x-icon',
            'bmp'  => 'image/bmp',
        ];

        $is_image_ext = isset($image_mimes[$extension]);
        $is_image = false;
        $image_base64 = null;
        $image_dimensions = null;
        $image_security = [
            'is_valid_binary'    => false,
            'detected_type'      => null,
            'magic_bytes_match'  => false,
            'threat_warning'     => null,
            'has_embedded_php'   => false,
            'disguised_exec'     => null,
        ];

        if ($is_image_ext) {
            $magic_header = @file_get_contents($real_path, false, null, 0, 32);

            // 1. Binary Magic Header Check for True Image Formats
            $magic_matches = false;
            $detected_format = null;

            if ($magic_header !== false && strlen($magic_header) >= 4) {
                // PNG: 89 50 4E 47 0D 0A 1A 0A
                if (str_starts_with($magic_header, "\x89PNG\r\n\x1a\n")) {
                    $magic_matches = in_array($extension, ['png'], true);
                    $detected_format = 'PNG Image';
                }
                // JPEG: FF D8 FF
                elseif (str_starts_with($magic_header, "\xFF\xD8\xFF")) {
                    $magic_matches = in_array($extension, ['jpg', 'jpeg'], true);
                    $detected_format = 'JPEG Image';
                }
                // GIF: GIF87a or GIF89a
                elseif (str_starts_with($magic_header, 'GIF87a') || str_starts_with($magic_header, 'GIF89a')) {
                    $magic_matches = in_array($extension, ['gif'], true);
                    $detected_format = 'GIF Image';
                }
                // WebP: RIFF....WEBP
                elseif (str_starts_with($magic_header, 'RIFF') && strlen($magic_header) >= 12 && substr($magic_header, 8, 4) === 'WEBP') {
                    $magic_matches = in_array($extension, ['webp'], true);
                    $detected_format = 'WebP Image';
                }
                // BMP: BM
                elseif (str_starts_with($magic_header, 'BM')) {
                    $magic_matches = in_array($extension, ['bmp'], true);
                    $detected_format = 'BMP Image';
                }
                // ICO: 00 00 01 00
                elseif (str_starts_with($magic_header, "\x00\x00\x01\x00")) {
                    $magic_matches = in_array($extension, ['ico'], true);
                    $detected_format = 'ICO Icon';
                }
                // SVG: XML header or <svg tag
                elseif ($extension === 'svg') {
                    $trimmed_head = ltrim($magic_header);
                    if (str_starts_with($trimmed_head, '<?xml') || str_starts_with($trimmed_head, '<svg')) {
                        $magic_matches = true;
                        $detected_format = 'SVG Vector';
                    }
                }
            }

            // 2. Check for Disguised Executable Binaries (PE, ELF, Mach-O, Shell Shebang)
            $disguised_exec = null;
            if ($magic_header !== false) {
                if (str_starts_with($magic_header, 'MZ')) {
                    $disguised_exec = 'Windows PE Executable / DLL (MZ Header)';
                } elseif (str_starts_with($magic_header, "\x7fELF")) {
                    $disguised_exec = 'Linux ELF Binary Executable';
                } elseif (in_array(substr($magic_header, 0, 4), ["\xca\xfe\xba\xbe", "\xcf\xfa\xed\xfe", "\xce\xfa\xed\xfe"], true)) {
                    $disguised_exec = 'Mach-O Binary Executable';
                } elseif (str_starts_with($magic_header, '#!') && preg_match('/^#!\s*\/(bin|usr)/i', $magic_header)) {
                    $disguised_exec = 'Unix Shell Script (Shebang Header)';
                } elseif (preg_match('/^\s*<\?php/i', $magic_header)) {
                    $disguised_exec = 'Pure PHP Script disguised with Image Extension';
                }
            }

            // 3. Check for Embedded Active PHP Polyglots (Head, EXIF, or Tail)
            $has_embedded_php = false;
            $php_pattern = '/<\?(?:php\s+[\s\S]{0,500}?(?:eval|assert|system|passthru|shell_exec|exec|base64_decode|\$_[A-Z]+|\$[a-zA-Z0-9_]+)|\=\s*[\s\S]{0,200}?(?:eval|assert|\$_[A-Z]+|\$[a-zA-Z0-9_]+))/i';
            
            // Scan first 8KB
            $head_8k = @file_get_contents($real_path, false, null, 0, 8192);
            if ($head_8k !== false && preg_match($php_pattern, $head_8k)) {
                $has_embedded_php = true;
            }

            // Scan trailing 8KB for appended payloads
            if (!$has_embedded_php && $file_size > 8192) {
                $tail_offset = max(0, $file_size - 8192);
                $tail_8k = @file_get_contents($real_path, false, null, $tail_offset, 8192);
                if ($tail_8k !== false && preg_match($php_pattern, $tail_8k)) {
                    $has_embedded_php = true;
                }
            }

            // Determine if safe to render visually as image
            $is_image = $magic_matches && empty($disguised_exec);

            $threat_warning = null;
            if (!empty($disguised_exec)) {
                $threat_warning = "MALICIOUS DISGUISED EXECUTABLE: File has a '.{$extension}' extension but its binary signature indicates it is a {$disguised_exec}.";
            } elseif (!$magic_matches) {
                $threat_warning = "MISMATCHED BINARY SIGNATURE: File claims to be an image (.{$extension}), but lacks valid image magic bytes. " . ($detected_format ? "Detected as: {$detected_format}." : "It may be a disguised script or corrupt file.");
            } elseif ($has_embedded_php) {
                $threat_warning = "MALICIOUS POLYGLOT: File is a valid {$detected_format}, but contains embedded executable PHP script code or backdoor tokens.";
            }

            $image_security = [
                'is_valid_binary'   => $magic_matches,
                'detected_type'     => $detected_format,
                'magic_bytes_match' => $magic_matches,
                'threat_warning'    => $threat_warning,
                'has_embedded_php'  => $has_embedded_php,
                'disguised_exec'    => $disguised_exec,
            ];

            // If genuine image, load base64 preview and dimensions
            if ($is_image) {
                $raw_bytes = file_get_contents($real_path, false, null, 0, 5 * 1024 * 1024);
                if ($raw_bytes !== false) {
                    $image_base64 = 'data:' . $image_mimes[$extension] . ';base64,' . base64_encode($raw_bytes);
                }
                if ($extension !== 'svg' && function_exists('getimagesize')) {
                    $img_size = @getimagesize($real_path);
                    if (!empty($img_size)) {
                        $image_dimensions = [
                            'width'  => $img_size[0] ?? null,
                            'height' => $img_size[1] ?? null,
                        ];
                    }
                }
            }
        }

        $is_masked = false;
        $file_basename = strtolower(basename($real_path));
        if (preg_match('/(?:^|[\\/\\\\])wp-config(?:-[^\\/\\\\]+)?(?:\.php)?(?:\.(?:bak|old|orig|save|txt|backup|swp|dist|inc))?$/i', $real_path) ||
            preg_match('/^(?:\\.env(?:\\.[a-z0-9_-]+)?|wp-config(?:-[^\\/\\\\]+)?(?:\.php)?(?:\.(?:bak|old|orig|save|txt|backup|swp|dist|inc))?)$/i', $file_basename)
        ) {
            $masked_res = self::mask_sensitive_config_content($content);
            $content = $masked_res['content'];
            $is_masked = $masked_res['is_masked'];
        }

        $lines = explode("\n", $content);
        $line_count = count($lines);

        $rel_path = str_replace(wp_normalize_path(ABSPATH), '', wp_normalize_path($real_path));
        $rel_path = ltrim($rel_path, '/\\');

        $sha256 = hash_file('sha256', $real_path) ?: '';
        $md5 = md5_file($real_path) ?: '';

        // Forensic filesystem timestamps & stat metadata
        $stat = @stat($real_path) ?: [];
        $ctime = isset($stat['ctime']) ? (int) $stat['ctime'] : @filectime($real_path);
        $mtime = isset($stat['mtime']) ? (int) $stat['mtime'] : @filemtime($real_path);
        $atime = isset($stat['atime']) ? (int) $stat['atime'] : @fileatime($real_path);

        $owner_uid = isset($stat['uid']) ? (int) $stat['uid'] : (function_exists('fileowner') ? @fileowner($real_path) : null);
        $group_gid = isset($stat['gid']) ? (int) $stat['gid'] : (function_exists('filegroup') ? @filegroup($real_path) : null);

        $owner_name = null;
        if ($owner_uid !== null && function_exists('posix_getpwuid')) {
            $pw = @posix_getpwuid($owner_uid);
            if (!empty($pw['name'])) {
                $owner_name = $pw['name'];
            }
        }
        if (!$owner_name && $owner_uid !== null) {
            $owner_name = (string) $owner_uid;
        }

        $group_name = null;
        if ($group_gid !== null && function_exists('posix_getgrgid')) {
            $gr = @posix_getgrgid($group_gid);
            if (!empty($gr['name'])) {
                $group_name = $gr['name'];
            }
        }
        if (!$group_name && $group_gid !== null) {
            $group_name = (string) $group_gid;
        }

        $ownership_formatted = ($owner_name && $group_name) ? "{$owner_name}:{$group_name}" : ($owner_name ?: 'unknown');

        // Detected MIME type
        $mime_type = null;
        if (function_exists('mime_content_type')) {
            $mime_type = @mime_content_type($real_path) ?: null;
        }
        if (!$mime_type && function_exists('finfo_open')) {
            $finfo = @finfo_open(FILEINFO_MIME_TYPE);
            if ($finfo) {
                $mime_type = @finfo_file($finfo, $real_path) ?: null;
                @finfo_close($finfo);
            }
        }
        if (!$mime_type) {
            $mime_type = $is_image_ext ? ($image_mimes[$extension] ?? 'image/' . $extension) : 'text/plain';
        }

        return rest_ensure_response([
            'success'          => true,
            'filename'         => basename($real_path),
            'file_path'        => $rel_path,
            'full_path'        => $real_path,
            'sha256'           => $sha256,
            'md5'              => $md5,
            'size_bytes'       => $file_size,
            'size_formatted'   => size_format($file_size, 2),
            'permissions'      => $perms,
            'is_writable'      => wp_is_writable($real_path),
            'ctime'            => $ctime ? gmdate('Y-m-d H:i:s \U\T\C', $ctime) : 'N/A',
            'mtime'            => $mtime ? gmdate('Y-m-d H:i:s \U\T\C', $mtime) : 'N/A',
            'atime'            => $atime ? gmdate('Y-m-d H:i:s \U\T\C', $atime) : 'N/A',
            'ctime_raw'        => $ctime ?: null,
            'mtime_raw'        => $mtime ?: null,
            'atime_raw'        => $atime ?: null,
            'owner'            => $owner_name ?: 'unknown',
            'group'            => $group_name ?: 'unknown',
            'ownership'        => $ownership_formatted,
            'mime_type'        => $mime_type,
            'line_count'       => $line_count,
            'content'          => $content,
            'is_truncated'     => $is_truncated,
            'is_masked'        => $is_masked,
            'is_image'         => $is_image_ext,
            'is_valid_image'   => $is_image,
            'image_mime'       => $is_image_ext ? $image_mimes[$extension] : null,
            'image_base64'     => $image_base64,
            'image_dimensions' => $image_dimensions,
            'image_security'   => $image_security,
        ]);
    }

    /**
     * Safely read and return post/page content for inspection popup modal.
     */
    public static function view_post_content(\WP_REST_Request $request) {
        $post_id = (int) $request->get_param('post_id');
        if (!$post_id) {
            $path = sanitize_text_field($request->get_param('path') ?: '');
            if (preg_match('/^post:(\d+)/i', $path, $matches)) {
                $post_id = (int) $matches[1];
            }
        }

        if (!$post_id) {
            return new \WP_Error('missing_post_id', __('Valid post ID is required.', 'webcare-pro-security'), ['status' => 400]);
        }

        $post = get_post($post_id);
        if (!$post) {
            return new \WP_Error('post_not_found', __('The requested post or page was not found.', 'webcare-pro-security'), ['status' => 404]);
        }

        return rest_ensure_response([
            'success'      => true,
            'post_id'      => $post_id,
            'title'        => $post->post_title ?: __('(Untitled)', 'webcare-pro-security'),
            'post_type'    => $post->post_type,
            'post_status'  => $post->post_status,
            'author'       => get_the_author_meta('display_name', $post->post_author),
            'content'      => $post->post_content,
            'view_url'     => get_permalink($post_id) ?: '',
            'edit_url'     => get_edit_post_link($post_id, 'raw') ?: admin_url("post.php?post={$post_id}&action=edit"),
            'date'         => $post->post_date,
            'modified'     => $post->post_modified,
        ]);
    }
}
