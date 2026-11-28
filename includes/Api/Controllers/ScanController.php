<?php
declare(strict_types=1);

namespace WebCareProScanner\Api\Controllers;

if (!defined('ABSPATH')) {
    exit;
}

use WebCareProScanner\Filesystem\PathValidator;
use WebCareProScanner\Scan\ScanLock;
use WebCareProScanner\WordPress\UpdateScanner;
use WebCareProScanner\Filesystem\UploadsScanner;
use WebCareProScanner\Content\ContentScanner;
use WebCareProScanner\Integrity\CoreIntegrity;
use WebCareProScanner\Findings\CorrelationEngine;
use WebCareProScanner\WordPress\CronScanner;
use WebCareProScanner\Database\DatabaseScanner;
use WebCareProScanner\Filesystem\FileScanner;
use WebCareProScanner\Integrity\ImportantFileFIM;
use WebCareProScanner\WordPress\PersistenceScanner;
use WebCareProScanner\Integrity\PluginIntegrity;
use WebCareProScanner\Findings\RiskScorer;
use WebCareProScanner\Integrity\ThemeIntegrity;
use WebCareProScanner\WordPress\UserScanner;
use WebCareProScanner\WordPress\WordPressSecurityScanner;
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
            'methods'             => ['GET', 'DELETE'],
            'callback'            => [self::class, 'handle_scan_history_route'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/scan/history/clear', [
            'methods'             => ['POST', 'DELETE'],
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

        register_rest_route($namespace, '/advisor/recommendations', [
            'methods'             => 'GET',
            'callback'            => [self::class, 'get_local_advisor_recommendations'],
            'permission_callback' => $permission,
        ]);

        register_rest_route($namespace, '/scanner/delete-user', [
            'methods'             => 'POST',
            'callback'            => [self::class, 'delete_flagged_user'],
            'permission_callback' => $permission,
        ]);

    }

    /**
     * Safely delete a flagged WordPress user account from a security finding.
     */
    public static function delete_flagged_user(\WP_REST_Request $request): \WP_REST_Response {
        if (!current_user_can('delete_users')) {
            return new \WP_REST_Response(['success' => false, 'message' => __('Insufficient permissions to delete users.', 'webcare-pro-security')], 403);
        }

        $user_id  = absint($request->get_param('user_id'));
        $issue_id = absint($request->get_param('issue_id'));
        if ($user_id <= 0) {
            return new \WP_REST_Response(['success' => false, 'message' => __('Invalid user ID.', 'webcare-pro-security')], 400);
        }
        if ($user_id === get_current_user_id()) {
            return new \WP_REST_Response(['success' => false, 'message' => __('You cannot delete your own currently logged-in account.', 'webcare-pro-security')], 400);
        }

        require_once ABSPATH . 'wp-admin/includes/user.php';
        $deleted = wp_delete_user($user_id, get_current_user_id());
        if (!$deleted) {
            return new \WP_REST_Response(['success' => false, 'message' => __('Failed to delete user.', 'webcare-pro-security')], 500);
        }

        if ($issue_id > 0) {
            global $wpdb;
            $table = $wpdb->prefix . 'webcareproscan_findings';
            $wpdb->update($table, ['status' => 'resolved'], ['id' => $issue_id], ['%s'], ['%d']);
        }

        return new \WP_REST_Response(['success' => true, 'user_id' => $user_id], 200);
    }

    /**
     * Get Local Adaptive Intelligence Advisor recommendations (recommend-only).
     *
     * @param \WP_REST_Request $request
     * @return \WP_REST_Response
     */
    public static function get_local_advisor_recommendations(\WP_REST_Request $request): \WP_REST_Response {
        $force = !empty($request->get_param('force_refresh'));
        $data = class_exists('\\WebCareProScanner\\Firewall\\CAF\\LocalIntelligenceAdvisor')
            ? \WebCareProScanner\Firewall\CAF\LocalIntelligenceAdvisor::get_recommendations($force)
            : ['generated_at' => time(), 'recommendations' => [], 'status' => 'unavailable'];

        return new \WP_REST_Response($data, 200);
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
            $needs_full_abspath = !empty($custom_options['scan_known_malware'])
                || !empty($custom_options['scan_backdoors_heuristics'])
                || !empty($custom_options['scan_malicious_urls'])
                || !empty($custom_options['scan_images_executable'])
                || !empty($custom_options['scan_core_integrity'])
                || !empty($custom_options['scan_unbundled_files'])
                || !empty($custom_options['scan_outside_root']);

            $has_filesystem_scan = $needs_full_abspath
                || !empty($custom_options['scan_theme_integrity'])
                || !empty($custom_options['scan_plugin_integrity']);

            if ($has_filesystem_scan) {
                if ($needs_full_abspath) {
                    $paths[] = untrailingslashit(ABSPATH);
                } else {
                    if (!empty($custom_options['scan_plugin_integrity'])) {
                        $paths[] = WP_PLUGIN_DIR;
                    }
                    if (!empty($custom_options['scan_theme_integrity'])) {
                        $paths[] = get_theme_root();
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
        $generation_token = wp_generate_password(32, false);

        // Pre-insert scan record with unique generation_token to obtain scan_id
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->insert($table_scans, [
            'status'           => 'running',
            'generation_token' => $generation_token,
            'scan_target'      => $target,
            'trigger_type'     => 'manual',
            'scanned_files'    => 0,
            'total_files'      => 0,
            'issues_found'     => 0,
            'risk_score'       => 0,
            'duration'         => 0,
            'duration_ms'      => 0,
            'created_at'       => current_time('mysql'),
            'created_at_gmt'   => gmdate('Y-m-d H:i:s'),
            'started_at'       => $now_exact,
        ]);
        $scan_id = (int) $wpdb->insert_id;

        // Acquire lock using generation_token as cryptographic lease token
        if (!ScanLock::acquire($scan_id, $generation_token)) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->delete($table_scans, ['id' => $scan_id]);
            return new \WP_Error(
                'scan_locked',
                __('A security scan is currently running in another process or held by a concurrent lock.', 'webcare-pro-security'),
                ['status' => 409]
            );
        }
        $lease_token = ScanLock::get_active_lease_token($scan_id);
        if (empty($lease_token) || !hash_equals($lease_token, $generation_token)) {
            ScanLock::force_release($scan_id, $generation_token);
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
            set_transient("webcareproscan_custom_options_{$scan_id}", $custom_options, DAY_IN_SECONDS);
            update_option("webcareproscan_scan_opts_{$scan_id}", $custom_options, false);
        }

        set_transient("webcareproscan_scan_start_micro_{$scan_id}", $start_micro, DAY_IN_SECONDS);
        set_transient("webcareproscan_scan_last_activity_{$scan_id}", time(), 12 * HOUR_IN_SECONDS);

        $init_telemetry = self::get_realtime_resource_stats(null, null, 0, $total_files, 0, 0.0);
        set_transient("webcareproscan_scan_live_telemetry_{$scan_id}", $init_telemetry, DAY_IN_SECONDS);

        // Schedule background continuation worker so the scan continues autonomously if the user navigates away
        if (class_exists('\\WebCareProScanner\\Scan\\ScanBackgroundWorker')) {
            \WebCareProScanner\Scan\ScanBackgroundWorker::schedule_continuation(5);
            if (\WebCareProScanner\System\SettingsManager::get('scan_execution_strategy', 'ajax_client') !== 'ajax_client') {
                \WebCareProScanner\Scan\ScanBackgroundWorker::dispatch_deferred_tick($scan_id);
            }
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

        if (function_exists('set_time_limit')) {
            // phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged
            @set_time_limit(60);
        }
        if (function_exists('wp_raise_memory_limit')) {
            @wp_raise_memory_limit('admin');
        }

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
        $is_from_browser = !empty($request->get_param('from_browser'));

        // Acquire per-batch lease mutex and verify active scan lease
        $batch_worker_token = null;
        if (!ScanLock::acquire_batch_lock($scan_id, $lease_token, $batch_worker_token)) {
            return new \WP_Error(
                'scan_lock_conflict',
                __('Concurrent scan batch execution rejected or active scan lease not held.', 'webcare-pro-security'),
                ['status' => 409]
            );
        }

        $batch_finished_cleanly = false;
        $processed_count = 0;
        $checkpointed_count = 0;
        $bytes_consumed = 0;
        $checkpointed_bytes = 0;
        $batch_files_records = [];
        $in_progress_filepath = '';
        $in_progress_bytes = 0;
        $table_scans = $wpdb->prefix . 'webcareproscan_scans';
        $table_issues = $wpdb->prefix . 'webcareproscan_scan_issues';
        $table_files = $wpdb->prefix . 'webcareproscan_scan_files';

        if (!(defined('WEBCAREPROSCAN_TESTING') && WEBCAREPROSCAN_TESTING)) {
            register_shutdown_function(static function () use (
                &$batch_finished_cleanly,
                &$processed_count,
                &$checkpointed_count,
                &$bytes_consumed,
                &$checkpointed_bytes,
                &$batch_files_records,
                &$in_progress_filepath,
                &$in_progress_bytes,
                $scan_id,
                $lease_token,
                $batch_worker_token,
                $is_from_browser,
                $table_scans,
                $table_issues
            ): void {
                if ($batch_finished_cleanly) {
                    return;
                }

                // Recover progress up to the fatal/timed-out file and skip a single poison-pill file
                global $wpdb;
                $uncommitted_files = max(0, $processed_count - $checkpointed_count);
                $uncommitted_bytes = max(0, $bytes_consumed - $checkpointed_bytes);
                if ($in_progress_filepath !== '' && $in_progress_bytes > 0) {
                    $uncommitted_files++;
                    $uncommitted_bytes += $in_progress_bytes;
                    set_transient("webcareproscan_active_scan_file_{$scan_id}", 'Skipped timed-out/heavy file: ' . basename($in_progress_filepath), 120);
                    if (class_exists('\\WebCareProScanner\\System\\AuditLogger')) {
                        \WebCareProScanner\System\AuditLogger::log(
                            'scan_file_skipped_recovery',
                            sprintf('Skipped heavy/timed-out file during batch recovery (Scan #%d): %s', $scan_id, $in_progress_filepath),
                            'warning'
                        );
                    }
                }

                if ($wpdb instanceof \wpdb && ($uncommitted_files > 0 || $uncommitted_bytes > 0)) {
                    if (!empty($batch_files_records) && class_exists('\\WebCareProScanner\\Scan\\ScanVaultManager')) {
                        \WebCareProScanner\Scan\ScanVaultManager::append_batch($scan_id, $batch_files_records);
                    }
                    $rem = \WebCareProScanner\Scan\ScanQueueManager::advance($scan_id, $uncommitted_files, $uncommitted_bytes);
                    $tot_val = (int) $wpdb->get_var(
                        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
                        $wpdb->prepare("SELECT total_files FROM `{$table_scans}` WHERE id = %d", $scan_id)
                    );
                    $iss_val = (int) $wpdb->get_var(
                        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
                        $wpdb->prepare("SELECT COUNT(*) FROM `{$table_issues}` WHERE scan_id = %d AND status = 'open'", $scan_id)
                    );
                    $done_so_far = max(0, $tot_val - $rem);
                    // phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
                    $wpdb->query(
                        $wpdb->prepare(
                            "UPDATE `{$table_scans}` SET scanned_files = %d, issues_found = %d WHERE id = %d AND status = 'running' AND generation_token = %s",
                            $done_so_far,
                            $iss_val,
                            $scan_id,
                            $lease_token
                        )
                    );
                    // phpcs:enable
                }

                ScanLock::release_batch_lock($batch_worker_token);

                if (class_exists('\\WebCareProScanner\\Scan\\ScanBackgroundWorker')) {
                    \WebCareProScanner\Scan\ScanBackgroundWorker::schedule_continuation(3);
                    if (!$is_from_browser || (function_exists('connection_aborted') && connection_aborted())) {
                        \WebCareProScanner\Scan\ScanBackgroundWorker::trigger_loopback_tick($scan_id);
                    }
                }
            });
        }

        try {
            // Record live touch timestamp strictly when request originated from active browser session
            if ($is_from_browser) {
                set_transient("webcareproscan_active_scan_last_browser_touch_{$scan_id}", microtime(true), 120);
            }

            // Record activity timestamp for stale-scan watchdog resilience across multi-hour background runs
            set_transient("webcareproscan_scan_last_activity_{$scan_id}", time(), 12 * HOUR_IN_SECONDS);

            // Keep background continuation armed with a grace delay
            if (class_exists('\\WebCareProScanner\\Scan\\ScanBackgroundWorker')) {
                \WebCareProScanner\Scan\ScanBackgroundWorker::schedule_continuation(12);
            }

            // Initialize Dynamic Resource Governor with host timeout/RAM-safe ceilings
            $max_exec_time = (int) ini_get('max_execution_time');
            $batch_time_budget = ($max_exec_time > 0 && $max_exec_time < 30) ? max(8, $max_exec_time - 6) : 14;
            $governor = new \WebCareProScanner\Resource\ResourceMonitor(70, $batch_time_budget, 'balanced');
            $effective_batch_size = $governor->get_adaptive_batch_size($batch_size);
            $mem_limit_raw = (string) (ini_get('memory_limit') ?: '256M');
            if ($mem_limit_raw !== '-1' && preg_match('/^(\d+)M$/i', trim($mem_limit_raw), $mm) && (int) $mm[1] <= 128) {
                $effective_batch_size = min(35, $effective_batch_size);
            }

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
                    $batch_finished_cleanly = true;
                    return rest_ensure_response([
                        'success'     => true,
                        'is_finished' => true,
                        'remaining'   => 0,
                        'processed'   => 0,
                        'last_file'   => '',
                    ]);
                }
                $batch_finished_cleanly = true;
                return new \WP_Error('scan_not_found', 'Scan queue expired or not found', ['status' => 404]);
            }

            $file_scanner = new FileScanner();
            $batch_custom_options = self::get_scan_custom_options($scan_id);
            $accumulated_weight = 0.0;
            $start_micro = get_transient("webcareproscan_scan_start_micro_{$scan_id}");
            $cached_total_files = (int) $wpdb->get_var(
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
                $wpdb->prepare("SELECT total_files FROM `{$table_scans}` WHERE id = %d", $scan_id)
            );

            foreach ($files_to_process as $idx => $filepath) {
                // Adaptive breathing and resource headroom check before each file (always advance at least 1 file)
                if ($processed_count > 0 && $governor->throttle_and_check()) {
                    break;
                }

                // Track active file before scanning so shutdown recovery can isolate any fatal/poison file
                $in_progress_filepath = $filepath;
                $in_progress_bytes = (int) ($line_bytes[$idx] ?? 0);

                // Update live heartbeat and last active file path
                set_transient("webcareproscan_active_scan_file_{$scan_id}", $filepath, 120);

                // Factor in file complexity weight
                $weight = \WebCareProScanner\Resource\ResourceMonitor::get_file_weight($filepath);
                $accumulated_weight += $weight;

                // If heavy files filled the batch weight budget early, save remaining and yield
                if ($accumulated_weight >= ($effective_batch_size * 1.25) && $processed_count > 10) {
                    $in_progress_filepath = '';
                    $in_progress_bytes = 0;
                    break;
                }

                $findings = $file_scanner->scan_file($filepath, (string) $scan_id, $batch_custom_options);
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
                $bytes_consumed += $in_progress_bytes;
                $in_progress_filepath = '';
                $in_progress_bytes = 0;

                foreach ($findings as $f) {
                    // Assert ownership + non-cancelled validation immediately before finding insert
                    if (get_transient("webcareproscan_scan_cancelled_{$scan_id}")) {
                        $batch_finished_cleanly = true;
                        return new \WP_Error('scan_aborted', __('Scan was aborted. Halting finding inserts.', 'webcare-pro-security'), ['status' => 409]);
                    }

                    $scan_check_sql = "SELECT id FROM `{$table_scans}` WHERE id = %d AND status = 'running' AND generation_token = %s";
                    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.NotPrepared
                    $valid_scan = $wpdb->get_var($wpdb->prepare($scan_check_sql, $scan_id, $lease_token));
                    if (!$valid_scan) {
                        $batch_finished_cleanly = true;
                        return new \WP_Error('scan_ownership_lost', __('Scan ownership lost or superseded. Aborting worker immediately.', 'webcare-pro-security'), ['status' => 409]);
                    }

                    $item = $f->to_array();
                    $matched_rule = \WebCareProScanner\Findings\WhitelistManager::match_finding($item);
                    $status = ($matched_rule !== null) ? 'ignored' : 'open';

                    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                    $wpdb->insert($table_issues, [
                        'scan_id'        => $scan_id,
                        'engine'         => $item['engine'],
                        'type'           => $item['type'],
                        'severity'       => $item['severity'],
                        'confidence'     => $item['confidence'],
                        'file_path'      => $item['file_path'],
                        'line_number'    => $item['line_number'] ?? null,
                        'code_snippet'   => $item['code_snippet'] ?? null,
                        'evidence'       => $item['evidence'] ?? null,
                        'description'    => $item['description'],
                        'status'         => $status,
                        'created_at'     => current_time('mysql'),
                        'created_at_gmt' => gmdate('Y-m-d H:i:s'),
                    ]);
                }

                // Checkpoint queue cursor and progress every 10 files so live status stays current
                // and mid-batch timeouts/crashes never roll progress back to 0.
                if (($processed_count - $checkpointed_count) >= 10) {
                    if (get_transient("webcareproscan_scan_cancelled_{$scan_id}")) {
                        $batch_finished_cleanly = true;
                        return new \WP_Error('scan_aborted', __('Scan was aborted. Halting progress update.', 'webcare-pro-security'), ['status' => 409]);
                    }
                    $delta_count = $processed_count - $checkpointed_count;
                    $delta_bytes = $bytes_consumed - $checkpointed_bytes;
                    if (!empty($batch_files_records) && class_exists('\\WebCareProScanner\\Scan\\ScanVaultManager')) {
                        \WebCareProScanner\Scan\ScanVaultManager::append_batch($scan_id, $batch_files_records);
                        $batch_files_records = [];
                    }
                    $cp_remaining = \WebCareProScanner\Scan\ScanQueueManager::advance($scan_id, $delta_count, $delta_bytes);
                    $checkpointed_count = $processed_count;
                    $checkpointed_bytes = $bytes_consumed;

                    $cp_scanned = max(0, $cached_total_files - $cp_remaining);
                    $cp_issues = (int) $wpdb->get_var(
                        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
                        $wpdb->prepare("SELECT COUNT(*) FROM `{$table_issues}` WHERE scan_id = %d AND status = 'open'", $scan_id)
                    );
                    // phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
                    $wpdb->query(
                        $wpdb->prepare(
                            "UPDATE `{$table_scans}` SET scanned_files = %d, issues_found = %d WHERE id = %d AND status = 'running' AND generation_token = %s",
                            $cp_scanned,
                            $cp_issues,
                            $scan_id,
                            $lease_token
                        )
                    );
                    // phpcs:enable
                    set_transient("webcareproscan_scan_last_activity_{$scan_id}", time(), 12 * HOUR_IN_SECONDS);
                    if ($is_from_browser) {
                        set_transient("webcareproscan_active_scan_last_browser_touch_{$scan_id}", microtime(true), 120);
                    }
                    if (is_string($batch_worker_token)) {
                        ScanLock::renew_batch_lock($scan_id, $batch_worker_token);
                    }
                    $cp_elapsed = ($start_micro && is_numeric($start_micro)) ? max(0.1, microtime(true) - (float) $start_micro) : 0.0;
                    $cp_tel = self::get_realtime_resource_stats($batch_start, $batch_ru_start, $cp_scanned, $cached_total_files, $cp_issues, $cp_elapsed, $governor);
                    set_transient("webcareproscan_scan_live_telemetry_{$scan_id}", $cp_tel, DAY_IN_SECONDS);
                }
            }

            // Verify scan was not cancelled and ownership is intact before performing final batch advance
            if (get_transient("webcareproscan_scan_cancelled_{$scan_id}")) {
                $batch_finished_cleanly = true;
                return new \WP_Error('scan_aborted', __('Scan was aborted. Halting vault and queue updates.', 'webcare-pro-security'), ['status' => 409]);
            }

            $scan_pre_advance_sql = "SELECT id FROM `{$table_scans}` WHERE id = %d AND status = 'running' AND generation_token = %s";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.NotPrepared
            $valid_pre_advance = $wpdb->get_var($wpdb->prepare($scan_pre_advance_sql, $scan_id, $lease_token));
            if (!$valid_pre_advance) {
                $batch_finished_cleanly = true;
                return new \WP_Error('scan_ownership_lost', __('Scan ownership lost or superseded. Halting vault and queue updates.', 'webcare-pro-security'), ['status' => 409]);
            }

            // Offload remaining scanned file telemetry to WebCare Scan Vault JSON manifest
            if (!empty($batch_files_records) && class_exists('\\WebCareProScanner\\Scan\\ScanVaultManager')) {
                \WebCareProScanner\Scan\ScanVaultManager::append_batch($scan_id, $batch_files_records);
                $batch_files_records = [];
            }

            $final_delta_count = max(0, $processed_count - $checkpointed_count);
            $final_delta_bytes = max(0, $bytes_consumed - $checkpointed_bytes);
            if ($final_delta_count > 0 || $checkpointed_count === 0) {
                $remaining = \WebCareProScanner\Scan\ScanQueueManager::advance($scan_id, $final_delta_count, $final_delta_bytes);
            } else {
                $remaining = \WebCareProScanner\Scan\ScanQueueManager::get_remaining_count($scan_id);
            }
            $checkpointed_count = $processed_count;
            $checkpointed_bytes = $bytes_consumed;
            $is_finished = ($remaining === 0);

            $tot_sql = "SELECT total_files, status FROM `{$table_scans}` WHERE id = %d";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $scan_row = $wpdb->get_row(
                // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                $wpdb->prepare($tot_sql, $scan_id),
                ARRAY_A
            );
            $is_cancelled = (bool) get_transient("webcareproscan_scan_cancelled_{$scan_id}");
            if (!$scan_row && !$is_cancelled) {
                // Self-healing: recreate running scan row only if missing and NOT aborted/cancelled
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                $wpdb->insert($table_scans, [
                    'id'               => $scan_id,
                    'status'           => 'running',
                    'generation_token' => $lease_token,
                    'scan_type'        => 'full',
                    'scanned_files'    => 0,
                    'total_files'      => max(1, $remaining),
                    'issues_found'     => 0,
                    'risk_score'       => 0,
                    'created_at'       => current_time('mysql'),
                    'created_at_gmt'   => gmdate('Y-m-d H:i:s'),
                ]);
                $scan_row = ['total_files' => max(1, $remaining), 'status' => 'running'];
            } elseif (!$scan_row || $is_cancelled || ($scan_row['status'] ?? '') !== 'running') {
                $batch_finished_cleanly = true;
                return new \WP_Error('scan_aborted', __('Scan was aborted or completed. Stopping progress update.', 'webcare-pro-security'), ['status' => 409]);
            }

            $scan_total = (int) ($scan_row['total_files'] ?? 0);
            $scanned_so_far = max(0, $scan_total - $remaining);
            $iss_sql = "SELECT COUNT(*) FROM `{$table_issues}` WHERE scan_id = %d AND status = 'open'";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $current_issues_total = (int) $wpdb->get_var(
                // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                $wpdb->prepare($iss_sql, $scan_id)
            );

            // Conditional progress update: WHERE id = %d AND status = 'running' AND generation_token = %s
            $update_progress_sql = "UPDATE `{$table_scans}` SET scanned_files = %d, issues_found = %d WHERE id = %d AND status = 'running' AND generation_token = %s";
            // phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.NotPrepared
            $rows_affected = $wpdb->query(
                $wpdb->prepare($update_progress_sql, $scanned_so_far, $current_issues_total, $scan_id, $lease_token)
            );
            // phpcs:enable
            if ((int) $rows_affected < 1) {
                // MySQL returns 0 when scanned_files & issues_found already match the 10-file checkpoint values.
                // Confirm row ownership directly before rejecting.
                $still_owned_sql = "SELECT id FROM `{$table_scans}` WHERE id = %d AND status = 'running' AND generation_token = %s";
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.NotPrepared
                $still_owned = $wpdb->get_var($wpdb->prepare($still_owned_sql, $scan_id, $lease_token));
                if (!$still_owned) {
                    $batch_finished_cleanly = true;
                    return new \WP_Error('scan_ownership_lost', __('Scan progress update rejected: scan aborted or generation token mismatch.', 'webcare-pro-security'), ['status' => 409]);
                }
            }

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
            set_transient("webcareproscan_scan_live_telemetry_{$scan_id}", $telemetry, DAY_IN_SECONDS);

            $batch_finished_cleanly = true;

            return rest_ensure_response([
                'success'        => true,
                'is_finished'    => $is_finished,
                'remaining'      => $remaining,
                'processed'      => $processed_count,
                'scanned_files'  => $scanned_so_far,
                'total_files'    => $scan_total,
                'issues_found'   => $current_issues_total,
                'last_file'      => !empty($files_to_process) ? basename(end($files_to_process)) : '',
                'telemetry'      => $telemetry,
            ]);
        } finally {
            $batch_finished_cleanly = true;
            ScanLock::release_batch_lock($batch_worker_token);
        }
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

        $all_deep_findings  = [];
        $engine_diagnostics = [];

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
                $custom_options = self::get_scan_custom_options($scan_id);
                if (!is_array($custom_options)) {
                    $req_custom = $request->get_param('custom_options');
                    if (is_array($req_custom)) {
                        $custom_options = \WebCareProScanner\System\SettingsManager::sanitize_custom_scan_options($req_custom);
                    } else {
                        $settings = \WebCareProScanner\System\SettingsManager::get_settings();
                        $custom_options = $settings['custom_scan_options'] ?? \WebCareProScanner\System\SettingsManager::get_default_custom_scan_options();
                    }
                }

                $all_deep_findings = array_merge(
                    $all_deep_findings,
                    self::execute_custom_deep_engines($scan_id, $custom_options, $lease_token, $engine_diagnostics, $assert_lease_active)
                );

                delete_option("webcareproscan_scan_opts_{$scan_id}");
            } elseif ($target === 'filesystem_only') {
                // Filesystem-only scan: no additional deep audit engines needed
            } else {
                // Full or plugins_themes: execute deep audit engines with heartbeat, fault isolation & diagnostic tracking
                $assert_lease_active();
                self::run_isolated_audit_engine($scan_id, 'core_integrity', 'WordPress Core Integrity', static function () use ($scan_id) {
                    set_transient("webcareproscan_active_scan_file_{$scan_id}", 'Core Integrity: Verifying WordPress core files against official WP.org API checksums...', 120);
                    return (new CoreIntegrity())->verify((string) $scan_id);
                }, $all_deep_findings, $engine_diagnostics);

                self::run_isolated_audit_engine($scan_id, 'important_fim', 'Important Files Integrity (FIM)', static function () use ($scan_id) {
                    set_transient("webcareproscan_active_scan_file_{$scan_id}", 'File Integrity: Checking critical system files (wp-config.php, .htaccess, index.php)...', 120);
                    return (new ImportantFileFIM())->verify((string) $scan_id);
                }, $all_deep_findings, $engine_diagnostics);

                $assert_lease_active();
                self::run_isolated_audit_engine($scan_id, 'plugin_integrity', 'Plugin Integrity', static function () use ($scan_id) {
                    set_transient("webcareproscan_active_scan_file_{$scan_id}", 'Plugin Integrity: Verifying installed plugins against official WordPress.org checksums...', 120);
                    return (new PluginIntegrity())->verify((string) $scan_id);
                }, $all_deep_findings, $engine_diagnostics);

                $assert_lease_active();
                self::run_isolated_audit_engine($scan_id, 'theme_integrity', 'Theme Integrity', static function () use ($scan_id) {
                    set_transient("webcareproscan_active_scan_file_{$scan_id}", 'Theme Integrity: Verifying active and installed themes against repository checksums...', 120);
                    return (new ThemeIntegrity())->verify((string) $scan_id);
                }, $all_deep_findings, $engine_diagnostics);

                $assert_lease_active();
                $db_scanner = new DatabaseScanner();
                self::run_isolated_audit_engine(
                    $scan_id,
                    'database',
                    'Database & Persistence Scanner',
                    static fn() => $db_scanner->scan((string) $scan_id, 100),
                    $all_deep_findings,
                    $engine_diagnostics,
                    static fn(): ?string => $db_scanner->get_last_scan_error()
                );

                $assert_lease_active();
                self::run_isolated_audit_engine($scan_id, 'content', 'Content & Post Scanner', static function () use ($scan_id) {
                    set_transient("webcareproscan_active_scan_file_{$scan_id}", 'Content & Post Scanner: Inspecting published posts and comments for hidden SEO spam and XSS...', 120);
                    return (new ContentScanner())->scan((string) $scan_id, 100);
                }, $all_deep_findings, $engine_diagnostics);

                $assert_lease_active();
                self::run_isolated_audit_engine($scan_id, 'wp_security', 'User & Auth Sentinel', static function () use ($scan_id, $lease_token) {
                    set_transient("webcareproscan_active_scan_file_{$scan_id}", 'User & Auth Sentinel: Auditing user accounts, administrator privileges, and password strength...', 120);
                    return (new WordPressSecurityScanner())->scan((string) $scan_id, $lease_token);
                }, $all_deep_findings, $engine_diagnostics);

                $assert_lease_active();
                self::run_isolated_audit_engine($scan_id, 'vulnerable_software', 'Software Updates & CVE Scanner', static function () use ($scan_id) {
                    set_transient("webcareproscan_active_scan_file_{$scan_id}", 'Vulnerability Intelligence: Checking installed plugins, themes, and WP Core against CVE database...', 120);
                    return (new UpdateScanner())->scan((string) $scan_id);
                }, $all_deep_findings, $engine_diagnostics);

                $assert_lease_active();
                self::run_isolated_audit_engine($scan_id, 'uploads_audit', 'Media & Uploads Audit', static function () use ($scan_id) {
                    set_transient("webcareproscan_active_scan_file_{$scan_id}", 'Media & Uploads Audit: Inspecting image metadata and attachments for embedded PHP code...', 120);
                    return (new UploadsScanner())->scan((string) $scan_id);
                }, $all_deep_findings, $engine_diagnostics);

                self::run_isolated_audit_engine($scan_id, 'reputation', 'Reputation & DNSBL Checks', static function () use ($scan_id) {
                    set_transient("webcareproscan_active_scan_file_{$scan_id}", 'Reputation Intel: Verifying domain blocklists, Google Safe Browsing, and spamvertising...', 120);
                    return self::audit_reputation_checks((string) $scan_id, [
                        'check_domain_blocklist' => true,
                        'check_spamvertised'     => true,
                        'check_spam_ip'          => true,
                    ]);
                }, $all_deep_findings, $engine_diagnostics);

                // System, Exposure, Vault CVE, Credential Leak, FIM Drift & Script Drift Audits on Complete Scans
                if ($target === 'full') {
                    self::run_isolated_audit_engine($scan_id, 'exposed_sensitive_files', 'Exposed Sensitive Files Audit', static fn() => self::audit_exposed_sensitive_files((string) $scan_id), $all_deep_findings, $engine_diagnostics);
                    self::run_isolated_audit_engine($scan_id, 'quarantine_exposure', 'Quarantine Exposure Audit', static fn() => self::audit_quarantine_exposure((string) $scan_id), $all_deep_findings, $engine_diagnostics);
                    self::run_isolated_audit_engine($scan_id, 'ip_detection', 'Reverse Proxy & IP Detection Audit', static fn() => self::audit_visitor_ip_detection((string) $scan_id), $all_deep_findings, $engine_diagnostics);
                    self::run_isolated_audit_engine($scan_id, 'disk_space', 'Server Disk Space Monitor', static fn() => self::audit_disk_space((string) $scan_id), $all_deep_findings, $engine_diagnostics);
                    self::run_isolated_audit_engine($scan_id, 'waf_status', 'Firewall Status Audit', static fn() => self::audit_waf_status((string) $scan_id), $all_deep_findings, $engine_diagnostics);

                    $silo_errors = [];
                    self::run_isolated_audit_engine(
                        $scan_id,
                        'silo_security',
                        'Credentials, FIM & Script Drift Audit',
                        static function () use ($scan_id, &$silo_errors) {
                            return self::collect_silo_security_findings((string) $scan_id, true, true, true, $silo_errors);
                        },
                        $all_deep_findings,
                        $engine_diagnostics,
                        static fn(): ?string => !empty($silo_errors) ? implode('; ', $silo_errors) : null
                    );
                }
                if (class_exists('\\WebCareProScanner\\Firewall\\NistCveVaultSync')) {
                    self::run_isolated_audit_engine(
                        $scan_id,
                        'nist_cve_vault',
                        'NIST NVD CVE Vault Check',
                        static fn() => self::deduplicate_vault_findings_against_updates(
                            \WebCareProScanner\Firewall\NistCveVaultSync::collect_vault_findings((string) $scan_id),
                            $all_deep_findings
                        ),
                        $all_deep_findings,
                        $engine_diagnostics
                    );
                }
            }

            // Persist per-engine health/degradation diagnostics (even if all engines succeeded cleanly)
            self::persist_scan_engine_diagnostics($scan_id, $engine_diagnostics);

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
                // Assert ownership + non-cancelled validation immediately before finding insert
                if (get_transient("webcareproscan_scan_cancelled_{$scan_id}")) {
                    ScanLock::release($scan_id, $lease_token);
                    return new \WP_Error('scan_aborted', __('Scan was aborted. Halting finding inserts.', 'webcare-pro-security'), ['status' => 409]);
                }

                $scan_check_sql = "SELECT id FROM `{$table_scans}` WHERE id = %d AND status = 'running' AND generation_token = %s";
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.NotPrepared
                $valid_scan = $wpdb->get_var($wpdb->prepare($scan_check_sql, $scan_id, $lease_token));
                if (!$valid_scan) {
                    ScanLock::release($scan_id, $lease_token);
                    return new \WP_Error('scan_ownership_lost', __('Scan ownership lost or superseded. Aborting worker immediately.', 'webcare-pro-security'), ['status' => 409]);
                }

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
                $tz = function_exists('wp_timezone') ? wp_timezone() : new \DateTimeZone('UTC');
                if (!empty($scan_row['started_at'])) {
                    $start_dt = date_create($scan_row['started_at'], $tz);
                    $end_dt = date_create($completed_at_exact, $tz);
                    if ($start_dt && $end_dt) {
                        $diff_sec = $end_dt->getTimestamp() - $start_dt->getTimestamp() + (($end_dt->format('u') - $start_dt->format('u')) / 1000000);
                        if ($diff_sec > 0) {
                            $duration_ms = (int) round($diff_sec * 1000);
                            $duration_sec = max(1, (int) round($diff_sec));
                        }
                    }
                }

                if ($duration_ms <= 0 && !empty($scan_row['created_at_gmt'])) {
                    $created_gmt_ts = strtotime((string) $scan_row['created_at_gmt'] . ' UTC');
                    if ($created_gmt_ts && time() > $created_gmt_ts) {
                        $diff_sec = time() - $created_gmt_ts;
                        $duration_ms = (int) round($diff_sec * 1000);
                        $duration_sec = max(1, (int) round($diff_sec));
                    }
                }

                if ($duration_ms <= 0 && !empty($scan_row['created_at'])) {
                    $created_dt = date_create($scan_row['created_at'], $tz);
                    if ($created_dt) {
                        $now_dt = date_create('now', $tz);
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

            $is_cancelled = (bool) get_transient("webcareproscan_scan_cancelled_{$scan_id}");
            if (!$scan_row && !$is_cancelled) {
                // Self-healing: recreate missing scan record so results are guaranteed to persist ONLY if not aborted
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                $wpdb->insert($table_scans, [
                    'id'            => $scan_id,
                    'status'        => 'completed',
                    'generation_token' => $lease_token,
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
            } elseif (!$scan_row || $is_cancelled || ($scan_row['status'] ?? '') !== 'running') {
                ScanLock::release($scan_id, $lease_token);
                return new \WP_Error('scan_aborted', __('Scan was cancelled or aborted before finalization.', 'webcare-pro-security'), ['status' => 409]);
            } else {
                // Conditional finalization update: WHERE id = %d AND status = 'running' AND generation_token = %s
                $fin_sql = "UPDATE `{$table_scans}` SET status = 'completed', issues_found = %d, risk_score = %d, duration = %d, duration_ms = %d, started_at = %s, completed_at = %s WHERE id = %d AND status = 'running' AND generation_token = %s";
                // phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.NotPrepared
                $rows_affected = $wpdb->query(
                    $wpdb->prepare($fin_sql, $open_issues_count, $summary['score'], $duration_sec, $duration_ms, $started_at_db, $completed_at_exact, $scan_id, $lease_token)
                );
                // phpcs:enable
                if ($rows_affected === 0) {
                    ScanLock::release($scan_id, $lease_token);
                    return new \WP_Error('scan_ownership_lost', __('Scan finalization rejected: scan aborted or generation token mismatch.', 'webcare-pro-security'), ['status' => 409]);
                }
            }

            $completed_scan_row = [
                'id'                 => $scan_id,
                'status'             => 'completed',
                'issues_found'       => $open_issues_count,
                'risk_score'         => $summary['score'],
                'duration'           => $duration_sec,
                'duration_ms'        => $duration_ms,
                'scanned_files'      => (int) ($scan_row['scanned_files'] ?? ($scan_row['total_files'] ?? 0)),
                'total_files'        => (int) ($scan_row['total_files'] ?? 0),
                'created_at'         => $scan_row['created_at'] ?? current_time('mysql'),
                'started_at'         => $started_at_db,
                'completed_at'       => $completed_at_exact,
                'engine_diagnostics' => array_values($engine_diagnostics),
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
            delete_transient("webcareproscan_scan_last_activity_{$scan_id}");
            delete_transient("webcareproscan_bg_last_tick_{$scan_id}");
            delete_transient("webcareproscan_bg_advance_cooldown_{$scan_id}");

            // Dispatch granular event notifications via NotificationDispatcher
            $is_scheduled_trigger = (($scan_row['trigger_type'] ?? '') === 'scheduled');
            if ($is_scheduled_trigger && class_exists('\\WebCareProScanner\\System\\Scheduler')) {
                \WebCareProScanner\System\Scheduler::send_scan_notification($scan_id, $open_issues_count, $summary['score'], (string) $target);
            } elseif (class_exists('\\WebCareProScanner\\Notifications\\NotificationDispatcher')) {
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

            if ($e instanceof \WebCareProScanner\Scan\ScanLeaseLostException) {
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

    public static function handle_scan_history_route(\WP_REST_Request $request) {
        if ($request->get_method() === 'DELETE') {
            return self::clear_scan_history($request);
        }
        return self::get_scan_history($request);
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

            // Clean up historical per-scan engine diagnostics options while preserving active scan(s)
            $diag_like = $wpdb->esc_like('webcareproscan_scan_engine_diag_') . '%';
            $preserve_names = array_map(static fn(int $rid): string => 'webcareproscan_scan_engine_diag_' . $rid, $running_ids);
            $preserve_placeholders = implode(', ', array_fill(0, count($preserve_names), '%s'));
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $wpdb->query($wpdb->prepare("DELETE FROM `{$wpdb->options}` WHERE option_name LIKE %s AND option_name NOT IN ({$preserve_placeholders})", ...array_merge([$diag_like], $preserve_names)));

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
        // Clean up persisted per-scan engine diagnostics options
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->query($wpdb->prepare("DELETE FROM `{$wpdb->options}` WHERE option_name LIKE %s", $wpdb->esc_like('webcareproscan_scan_engine_diag_') . '%'));

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
                if (!empty($diagnostics['degraded_engines'])) {
                    $deg_labels = implode(', ', array_map(static fn(array $d): string => (string) ($d['label'] ?? $d['engine'] ?? 'unknown'), $diagnostics['degraded_engines']));
                    // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
                    fwrite($output, "# Engine Diagnostics: DEGRADED ({$deg_labels})\r\n");
                }
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
            if (!empty($diagnostics['degraded_engines'])) {
                $deg_labels = implode(', ', array_map(static fn(array $d): string => (string) ($d['label'] ?? $d['engine'] ?? 'unknown'), $diagnostics['degraded_engines']));
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
                fwrite($output, "# Engine Diagnostics: DEGRADED ({$deg_labels})\r\n");
            }
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
        if (class_exists('\\WebCareProScanner\\Firewall\\CustomRules\\ModularFirewallSynthesizer')) {
            foreach (\WebCareProScanner\Firewall\CustomRules\ModularFirewallSynthesizer::get_active_rules() as $mr) {
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
        if (!class_exists('\\WebCareProScanner\\Firewall\\CustomRules\\ModularFirewallSynthesizer')) {
            return new \WP_REST_Response(['success' => false, 'message' => __('Virtual shield synthesizer unavailable.', 'webcare-pro-security')], 500);
        }
        $params = $request->get_json_params() ?: [];
        $slug   = sanitize_key($params['slug'] ?? '');
        $type   = sanitize_key($params['type'] ?? 'plugin');
        $res    = \WebCareProScanner\Firewall\CustomRules\ModularFirewallSynthesizer::activate_cve_shield($slug, $type);
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

    /**
     * Resolve the latest Unix activity timestamp across browser touches, background worker ticks, queue mtime, and DB start timestamps.
     *
     * @param array<string, mixed> $scan_row
     * @return int Unix timestamp (seconds).
     */
    private static function resolve_scan_last_activity_ts(array $scan_row): int {
        $scan_id = (int) ($scan_row['id'] ?? 0);
        $latest  = 0;

        if ($scan_id > 0) {
            foreach ([
                "webcareproscan_scan_last_activity_{$scan_id}",
                "webcareproscan_bg_last_tick_{$scan_id}",
                "webcareproscan_active_scan_last_browser_touch_{$scan_id}",
            ] as $t_key) {
                $val = get_transient($t_key);
                if (is_numeric($val)) {
                    $latest = max($latest, (int) round((float) $val));
                }
            }

            if (class_exists('\\WebCareProScanner\\Scan\\ScanQueueManager')) {
                $sdir = \WebCareProScanner\Scan\ScanQueueManager::get_session_dir($scan_id);
                if ($sdir && is_file($sdir . '/' . \WebCareProScanner\Scan\ScanQueueManager::META_FILE_NAME)) {
                    $mtime = @filemtime($sdir . '/' . \WebCareProScanner\Scan\ScanQueueManager::META_FILE_NAME);
                    if ($mtime) {
                        $latest = max($latest, (int) $mtime);
                    }
                }
            }
        }

        if (!empty($scan_row['created_at_gmt'])) {
            $gmt_ts = strtotime((string) $scan_row['created_at_gmt'] . ' UTC');
            if ($gmt_ts) {
                $latest = max($latest, (int) $gmt_ts);
            }
        } elseif (!empty($scan_row['started_at'])) {
            $tz = function_exists('wp_timezone') ? wp_timezone() : new \DateTimeZone('UTC');
            $dt = date_create((string) $scan_row['started_at'], $tz);
            if ($dt) {
                $latest = max($latest, $dt->getTimestamp());
            }
        } elseif (!empty($scan_row['created_at'])) {
            $tz = function_exists('wp_timezone') ? wp_timezone() : new \DateTimeZone('UTC');
            $dt = date_create((string) $scan_row['created_at'], $tz);
            if ($dt) {
                $latest = max($latest, $dt->getTimestamp());
            }
        }

        return $latest > 0 ? $latest : time();
    }

    public static function get_active_scan(\WP_REST_Request $request) {
        global $wpdb;

        $table_scans = $wpdb->prefix . 'webcareproscan_scans';
        $locked_id = ScanLock::get_locked_scan_id();

        // If no lock option exists, check if there is an active scan record in the DB created recently
        if (!$locked_id) {
            $running_sql = "SELECT * FROM `{$table_scans}` WHERE status = 'running' ORDER BY id DESC LIMIT 10";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $running_rows = $wpdb->get_results($running_sql, ARRAY_A);
            $now_ts = time();

            if (!empty($running_rows)) {
                foreach ($running_rows as $row) {
                    $cand_id = (int) ($row['id'] ?? 0);
                    if ($cand_id <= 0) {
                        continue;
                    }
                    $orig_token = (string) ($row['generation_token'] ?? '');

                    if (get_transient("webcareproscan_scan_cancelled_{$cand_id}")) {
                        $abort_cas = $wpdb->prepare(
                            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
                            "UPDATE `{$table_scans}` SET status = 'aborted', completed_at = %s WHERE id = %d AND status = 'running'",
                            self::now_fractional_mysql(),
                            $cand_id
                        );
                        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
                        $wpdb->query($abort_cas);
                        continue;
                    }

                    $has_queue = class_exists('\\WebCareProScanner\\Scan\\ScanQueueManager')
                        ? \WebCareProScanner\Scan\ScanQueueManager::has_queue($cand_id)
                        : false;
                    $idle_sec = max(0, $now_ts - self::resolve_scan_last_activity_ts($row));

                    // Branch 1: Scan is within its recovery window -> attempt recovery, NEVER interrupt on lock acquisition failure
                    $within_recovery_window = $has_queue ? ($idle_sec < 1800) : ($idle_sec < 600);
                    if ($within_recovery_window) {
                        if ($locked_id === null) {
                            $acquired = ScanLock::acquire($cand_id, $orig_token !== '' ? $orig_token : null);
                            if ($acquired) {
                                $locked_id = $cand_id;
                                set_transient("webcareproscan_scan_last_activity_{$cand_id}", $now_ts, 12 * HOUR_IN_SECONDS);
                                if (class_exists('\\WebCareProScanner\\Scan\\ScanBackgroundWorker')) {
                                    \WebCareProScanner\Scan\ScanBackgroundWorker::schedule_continuation(5);
                                    \WebCareProScanner\Scan\ScanBackgroundWorker::dispatch_deferred_tick($cand_id);
                                }
                                continue;
                            }

                            // Recovery attempt failed (e.g. GET_LOCK contention/timeout or concurrent worker update):
                            // Re-read the active lock and DB row; do NOT interrupt a healthy or concurrently progressing scan.
                            $recheck_locked = ScanLock::get_locked_scan_id();
                            $recheck_sql = $wpdb->prepare(
                                // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
                                "SELECT * FROM `{$table_scans}` WHERE id = %d",
                                $cand_id
                            );
                            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
                            $recheck_row = $wpdb->get_row($recheck_sql, ARRAY_A);
                            if ($recheck_locked !== null && $recheck_locked > 0 && is_array($recheck_row) && (($recheck_row['status'] ?? '') === 'running' || $recheck_locked !== $cand_id)) {
                                $locked_id = $recheck_locked;
                            }
                        }
                        continue;
                    }

                    // Branch 2: Scan is outside its recovery window -> revalidate lock and DB row before CAS interruption
                    $recheck_locked = ScanLock::get_locked_scan_id();
                    if ($recheck_locked !== null && $recheck_locked === $cand_id) {
                        $locked_id = $recheck_locked;
                        continue;
                    }

                    $fresh_sql = $wpdb->prepare(
                        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
                        "SELECT * FROM `{$table_scans}` WHERE id = %d",
                        $cand_id
                    );
                    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
                    $fresh_row = $wpdb->get_row($fresh_sql, ARRAY_A);
                    if (!is_array($fresh_row) || ($fresh_row['status'] ?? '') !== 'running') {
                        // Scan completed, aborted, or transitioned concurrently -> never overwrite
                        continue;
                    }

                    $fresh_token = (string) ($fresh_row['generation_token'] ?? '');
                    if ($fresh_token !== $orig_token) {
                        continue;
                    }

                    $fresh_has_queue = class_exists('\\WebCareProScanner\\Scan\\ScanQueueManager')
                        ? \WebCareProScanner\Scan\ScanQueueManager::has_queue($cand_id)
                        : false;
                    $fresh_idle_sec = max(0, time() - self::resolve_scan_last_activity_ts($fresh_row));
                    if (($fresh_has_queue && $fresh_idle_sec < 1800) || (!$fresh_has_queue && $fresh_idle_sec < 600)) {
                        continue;
                    }

                    // Confirmed genuinely stale: atomic compare-and-set transition bound to original generation_token
                    \WebCareProScanner\Scan\ScanInterruptionForensics::record(
                        $cand_id,
                        \WebCareProScanner\Scan\ScanInterruptionForensics::REASON_STALE_HEARTBEAT,
                        [
                            'expected_generation_token' => $orig_token,
                            'require_cas_transition'    => true,
                        ]
                    );
                }
            }

            if (!$locked_id) {
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

        // Actively self-heal stalled background continuation ticks ONLY on passive/non-batch monitors;
        // do not write last_browser_touch on GET /scan/active so 409 sync polling never starves background workers.
        $trigger_type = !empty($running_scan['trigger_type']) ? $running_scan['trigger_type'] : 'manual';
        if (empty($request->get_param('from_browser')) && class_exists('\\WebCareProScanner\\Scan\\ScanBackgroundWorker')) {
            \WebCareProScanner\Scan\ScanBackgroundWorker::maybe_advance_stalled_scan((int) $locked_id);
        }

        // Lock heartbeat
        $total = (int) $running_scan['total_files'];
        $scanned = (int) $running_scan['scanned_files'];
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
                $tz = function_exists('wp_timezone') ? wp_timezone() : new \DateTimeZone('UTC');
                if (!empty($running_scan['started_at'])) {
                    $start_dt = date_create($running_scan['started_at'], $tz);
                    if ($start_dt) {
                        $now_dt = date_create('now', $tz);
                        return max(1, $now_dt->getTimestamp() - $start_dt->getTimestamp());
                    }
                }
                if (empty($running_scan['created_at'])) return 1;
                $created_dt = date_create($running_scan['created_at'], $tz);
                if ($created_dt) {
                    $now_dt = date_create('now', $tz);
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
                $tz = function_exists('wp_timezone') ? wp_timezone() : new \DateTimeZone('UTC');
                if (!empty($running_scan['started_at'])) {
                    $start_dt = date_create($running_scan['started_at'], $tz);
                    if ($start_dt) {
                        $now_dt = date_create('now', $tz);
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
            // Retrieve generation_token for targeted release and cancellation marking
            $gen_sql = "SELECT generation_token FROM `{$table_scans}` WHERE id = %d";
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.NotPrepared
            $gen_token = $wpdb->get_var($wpdb->prepare($gen_sql, $scan_id));

            // Set durable cancellation marker transient
            set_transient("webcareproscan_scan_cancelled_{$scan_id}", true, 3600);

            // Atomically mark status = 'aborted' before releasing lock
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->update($table_scans, [
                'status'       => 'aborted',
                'completed_at' => $now_exact,
            ], ['id' => $scan_id]);

            $aborted = ScanLock::force_release($scan_id, is_string($gen_token) ? $gen_token : null);
            if (class_exists('\\WebCareProScanner\\Scan\\ScanBackgroundWorker')) {
                \WebCareProScanner\Scan\ScanBackgroundWorker::unschedule_continuation();
            }
            delete_transient("webcareproscan_active_scan_last_browser_touch_{$scan_id}");
            delete_transient("webcareproscan_scan_last_activity_{$scan_id}");
            delete_transient("webcareproscan_bg_last_tick_{$scan_id}");
            delete_transient("webcareproscan_bg_advance_cooldown_{$scan_id}");
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

            // Update final status to aborted and record duration
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->update($table_scans, [
                'status'       => 'aborted',
                'duration'     => $duration_sec,
                'duration_ms'  => $duration_ms,
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
        $raw_slug = sanitize_text_field($request->get_param('slug') ?: '');
        $type = sanitize_key($request->get_param('type') ?: 'plugin'); // 'plugin' or 'theme'
        $installed_ver = sanitize_text_field($request->get_param('installed_version') ?: '');
        $raw_latest_ver = sanitize_text_field($request->get_param('latest_version') ?: '');

        // Validate slug and version identifiers strictly before filesystem or SVN remote lookup
        $slug = (preg_match('/^[a-zA-Z0-9._-]{1,120}$/', $raw_slug) === 1 && !str_contains($raw_slug, '..'))
            ? $raw_slug
            : '';
        $latest_ver = (preg_match('/^[a-zA-Z0-9._+-]{1,40}$/', $raw_latest_ver) === 1 && !str_contains($raw_latest_ver, '..'))
            ? $raw_latest_ver
            : '';

        $target_dir = '';
        if (!empty($raw_path) && !str_contains($raw_path, "\0")) {
            $real_target = realpath($raw_path);
            if ($real_target !== false) {
                $norm_real    = wp_normalize_path($real_target);
                $allowed_roots = array_filter([
                    defined('ABSPATH') ? realpath(ABSPATH) : false,
                    defined('WP_CONTENT_DIR') ? realpath(WP_CONTENT_DIR) : false,
                    defined('WP_PLUGIN_DIR') ? realpath(WP_PLUGIN_DIR) : false,
                ]);
                $inside_root = false;
                foreach ($allowed_roots as $root) {
                    $norm_root = rtrim(wp_normalize_path($root), '/') . '/';
                    if (str_starts_with(rtrim($norm_real, '/') . '/', $norm_root)) {
                        $inside_root = true;
                        break;
                    }
                }
                if ($inside_root) {
                    if (is_dir($real_target)) {
                        $target_dir = $norm_real;
                    } elseif (is_file($real_target)) {
                        $target_dir = wp_normalize_path(dirname($real_target));
                    }
                }
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
        if (preg_match('/^[a-zA-Z0-9._-]{1,120}$/', (string) $slug) !== 1 || str_contains((string) $slug, '..')) {
            $slug = '';
        }

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
                    $enc_slug = rawurlencode($slug);
                    if (!empty($latest_ver)) {
                        $svn_urls[] = 'https://plugins.svn.wordpress.org/' . $enc_slug . '/tags/' . rawurlencode($latest_ver) . '/readme.txt';
                    }
                    $svn_urls[] = 'https://plugins.svn.wordpress.org/' . $enc_slug . '/trunk/readme.txt';

                    foreach ($svn_urls as $url) {
                        $response = function_exists('wp_safe_remote_get')
                            ? wp_safe_remote_get($url, ['timeout' => 4, 'sslverify' => true, 'headers' => ['User-Agent' => 'WordPress/' . get_bloginfo('version')]])
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
                    $enc_theme = rawurlencode($slug);
                    $enc_ver   = rawurlencode($latest_ver);
                    $candidates[] = 'https://themes.svn.wordpress.org/' . $enc_theme . '/' . $enc_ver . '/readme.txt';
                    $candidates[] = 'https://themes.svn.wordpress.org/' . $enc_theme . '/' . $enc_ver . '/changelog.txt';
                }
                foreach ($candidates as $url) {
                    $response = function_exists('wp_safe_remote_get')
                        ? wp_safe_remote_get($url, ['timeout' => 4, 'sslverify' => true])
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
            // 4b. Check if finding is a Server/Network/Reputation/System/CVE non-file entity
            elseif (
                in_array($engine, ['ip-detection', 'waf-status', 'firewall', 'system-storage', 'reputation', 'nist-cve'], true) ||
                $type === 'reverse_proxy_misconfigured' ||
                str_starts_with($filePath, 'server:') ||
                str_starts_with($filePath, 'system:') ||
                str_starts_with($filePath, 'firewall:') ||
                str_starts_with($filePath, 'domain:') ||
                str_starts_with($filePath, 'ip:') ||
                str_starts_with($filePath, 'cve:') ||
                str_starts_with($filePath, 'ram:')
            ) {
                $item['is_server_config'] = true;
                $item['is_network'] = in_array($engine, ['ip-detection', 'reputation'], true) || str_starts_with($filePath, 'domain:') || str_starts_with($filePath, 'ip:');
                $item['is_software_update'] = ($engine === 'nist-cve' || str_starts_with($filePath, 'cve:'));
                $item['is_file'] = false;
                $item['is_dir'] = false;
                $item['can_view'] = false;
                $item['file_exists'] = false;

                // Environment reconciliation: ONLY reconcile reverse_proxy_misconfigured on localhost/Docker
                if ($type === 'reverse_proxy_misconfigured') {
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
                if (($item['engine'] ?? '') === 'wordpress-updates' || in_array($item['type'] ?? '', ['outdated_plugin', 'outdated_theme', 'vulnerable_plugin', 'vulnerable_theme', 'outdated_core', 'vulnerable_core'], true)) {
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
                } elseif (
                    !empty($item['component_meta']['classification']) &&
                    in_array($item['type'] ?? '', ['plugin_checksums_unavailable', 'theme_checksums_unavailable'], true)
                ) {
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
                    'polymorphic_taint_webshell'     => __('Polymorphic Taint Webshell / Code Injection', 'webcare-pro-security'),
                    'obfuscated_malware_payload'     => __('Obfuscated Malware Payload', 'webcare-pro-security'),
                    'known_malware_hash'             => __('Known Malware Cryptographic Hash Match', 'webcare-pro-security'),
                    'client_side_malware'            => __('Client-Side JavaScript Malware / C2 Loader', 'webcare-pro-security'),
                    'suspicious_javascript'          => __('Suspicious JavaScript Behavior', 'webcare-pro-security'),
                    'suspicious_strings'             => __('Suspicious Remote Code Strings', 'webcare-pro-security'),
                    'obfuscation_detected'           => __('Code Obfuscation Detected', 'webcare-pro-security'),
                    'executable_in_uploads'          => __('Executable Script in Uploads Directory', 'webcare-pro-security'),
                    'disguised_php_in_uploads'       => __('Disguised PHP Script in Uploads Directory', 'webcare-pro-security'),
                    'phar_polyglot_in_uploads'       => __('Phar Deserialization Polyglot in Uploads', 'webcare-pro-security'),
                    'spoofed_binary_in_uploads'      => __('Spoofed Binary Executable in Uploads', 'webcare-pro-security'),
                    'malicious_svg_in_uploads'       => __('Malicious Script inside Uploaded SVG', 'webcare-pro-security'),
                    'double_extension_in_uploads'    => __('Double-Extension Executable in Uploads', 'webcare-pro-security'),
                    'server_override_in_uploads'     => __('Server Config Override in Uploads', 'webcare-pro-security'),
                    'quarantined_suspected_file'     => __('Residual .suspected Malware Artifact', 'webcare-pro-security'),
                    'exposed_config_backup'          => __('Exposed wp-config.php Backup / Swap File', 'webcare-pro-security'),
                    'exposed_db_tool'                => __('Exposed Standalone Database Utility', 'webcare-pro-security'),
                    'unsafe_permissions'             => __('Unsafe File Permissions', 'webcare-pro-security'),
                    'symlink_detected'               => __('Filesystem Symbolic Link', 'webcare-pro-security'),
                    'unknown_core_file'              => __('Unrecognized Core Directory File', 'webcare-pro-security'),
                    'unknown_plugin_file'            => __('Unrecognized Plugin File', 'webcare-pro-security'),
                    'unknown_theme_file'             => __('Unrecognized Theme File', 'webcare-pro-security'),
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
                    'scan_engine_degraded'           => __('Scan Engine Incomplete / Degraded', 'webcare-pro-security'),
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
            $package_url = (isset($update_package) && is_string($update_package)) ? $update_package : '';
            $theme_url = (isset($theme_update['url']) && is_string($theme_update['url'])) ? $theme_update['url'] : '';
            if (($package_url !== '' && str_contains($package_url, 'wordpress.org')) || ($theme_url !== '' && str_contains($theme_url, 'wordpress.org'))) {
                $is_wporg = true;
            }
        } elseif (!empty($update_themes->checked[$theme_slug])) {
            $latest_version = $update_themes->checked[$theme_slug];
            if (($theme_uri !== '' && str_contains($theme_uri, 'wordpress.org/themes')) || (bool) preg_match('/^twenty(ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|nineteen|twenty|twentyone|twentytwo|twentythree|twentyfour|twentyfive|twentysix)/i', $theme_slug)) {
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
            $entry_id = (isset($update_entry->id) && is_string($update_entry->id)) ? $update_entry->id : '';
            $entry_url = (isset($update_entry->url) && is_string($update_entry->url)) ? $update_entry->url : '';
            $entry_pkg = (isset($update_entry->package) && is_string($update_entry->package)) ? $update_entry->package : '';
            if (($entry_id !== '' && (str_contains($entry_id, 'w.org/') || str_contains($entry_id, 'wordpress.org')))
                || ($entry_url !== '' && str_contains($entry_url, 'wordpress.org/plugins'))
                || ($entry_pkg !== '' && (str_contains($entry_pkg, 'downloads.wordpress.org') || str_contains($entry_pkg, 'wordpress.org')))) {
                $is_wporg = true;
            }
        }

        if (!$is_wporg && $plugin_uri !== '' && str_contains($plugin_uri, 'wordpress.org/plugins')) {
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

        $engine_diag_list = !empty($scan['engine_diagnostics']) && is_array($scan['engine_diagnostics'])
            ? array_values($scan['engine_diagnostics'])
            : self::load_scan_engine_diagnostics($scan_id);

        $degraded_engines = [];
        $completed_engines = 0;
        foreach ($engine_diag_list as $ed) {
            if (!is_array($ed)) {
                continue;
            }
            $st = strtolower((string) ($ed['status'] ?? 'completed'));
            if ($st === 'degraded' || $st === 'incomplete') {
                $degraded_engines[] = $ed;
            } else {
                $completed_engines++;
            }
        }
        $is_complete = empty($degraded_engines);
        $engines_active = max(0, 24 - count($degraded_engines));

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
            'engines_active'         => $engines_active,
            'engine_status'          => $is_complete ? 'complete' : 'degraded',
            'is_complete'            => $is_complete,
            'engines_completed'      => $completed_engines,
            'engines_degraded'       => count($degraded_engines),
            'degraded_engines'       => $degraded_engines,
            'engine_diagnostics'     => $engine_diag_list,
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
     * Resolve persisted custom_options for a running custom scan (returns null for non-custom scans).
     */
    private static function get_scan_custom_options(int $scan_id): ?array {
        if ($scan_id <= 0) {
            return null;
        }
        $opts = get_transient("webcareproscan_custom_options_{$scan_id}");
        if (is_array($opts)) {
            return $opts;
        }
        $opt_db = get_option("webcareproscan_scan_opts_{$scan_id}", null);
        if (is_array($opt_db)) {
            return $opt_db;
        }
        return null;
    }

    /**
     * Scan loose top-level files directly inside dirname(ABSPATH) without recursing into sibling websites.
     */
    public static function audit_outside_root_loose_files(string $scan_id, ?array $custom_options = null): array {
        $findings = [];
        $parent = dirname(untrailingslashit(ABSPATH));
        if (!is_dir($parent) || !is_readable($parent) || realpath($parent) === realpath(ABSPATH)) {
            return $findings;
        }
        $entries = @scandir($parent);
        if (!is_array($entries)) {
            return $findings;
        }
        $scanner = new FileScanner();
        $parent_wp_config = realpath($parent . '/wp-config.php');
        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            $full = $parent . '/' . $entry;
            if (!is_file($full) || !is_readable($full)) {
                continue;
            }
            if ($parent_wp_config && realpath($full) === $parent_wp_config) {
                continue;
            }
            $ext = strtolower(pathinfo($full, PATHINFO_EXTENSION));
            if (!in_array($ext, ['php', 'phtml', 'pht', 'php7', 'php8', 'phar', 'suspected', 'sh', 'py', 'pl', 'cgi', 'js', 'sql', 'bak', 'env'], true)) {
                continue;
            }
            $sub = $scanner->scan_file($full, $scan_id, $custom_options);
            if (!empty($sub)) {
                $findings = array_merge($findings, $sub);
            }
        }
        return $findings;
    }

    /**
     * Execute all enabled Custom Scan deep engines with fault isolation and diagnostic tracking.
     *
     * @param int $scan_id
     * @param array $custom_options
     * @param string $lease_token
     * @param array $engine_diagnostics Populated by reference with per-engine completion/degradation state
     * @param callable|null $assert_lease_active Optional lease heartbeat check callback
     * @return list<\WebCareProScanner\Findings\Finding>
     */
    public static function execute_custom_deep_engines(
        int $scan_id,
        array $custom_options,
        string $lease_token = '',
        array &$engine_diagnostics = [],
        ?callable $assert_lease_active = null
    ): array {
        $findings = [];
        $heartbeat = $assert_lease_active ?? static function (): void {};

        // 1. Scan core files against repository versions for changes
        if (!empty($custom_options['scan_core_integrity'])) {
            $heartbeat();
            self::run_isolated_audit_engine($scan_id, 'core_integrity', 'WordPress Core Integrity', static function () use ($scan_id, $custom_options) {
                $core_results = (new CoreIntegrity())->verify((string) $scan_id);
                if (empty($custom_options['scan_unbundled_files'])) {
                    $core_results = array_values(array_filter($core_results, static function ($f) {
                        $arr = is_array($f) ? $f : $f->to_array();
                        return ($arr['type'] ?? '') !== 'unknown_core_file';
                    }));
                }
                return $core_results;
            }, $findings, $engine_diagnostics);
        }

        // 2. Scan theme files against repository versions for changes
        if (!empty($custom_options['scan_theme_integrity'])) {
            $heartbeat();
            self::run_isolated_audit_engine($scan_id, 'theme_integrity', 'Theme Integrity', static fn() => (new ThemeIntegrity())->verify((string) $scan_id), $findings, $engine_diagnostics);
        }

        // 3. Scan plugin files against repository versions for changes
        if (!empty($custom_options['scan_plugin_integrity'])) {
            $heartbeat();
            self::run_isolated_audit_engine($scan_id, 'plugin_integrity', 'Plugin Integrity', static fn() => (new PluginIntegrity())->verify((string) $scan_id), $findings, $engine_diagnostics);
        }

        // 4. Scan wp-admin and wp-includes for files not bundled with WordPress
        if (!empty($custom_options['scan_unbundled_files']) && empty($custom_options['scan_core_integrity'])) {
            $heartbeat();
            self::run_isolated_audit_engine($scan_id, 'unbundled_files', 'Unbundled Core Files', static function () use ($scan_id) {
                $core_results = (new CoreIntegrity())->verify((string) $scan_id);
                return array_values(array_filter($core_results, static function ($f) {
                    $arr = is_array($f) ? $f : $f->to_array();
                    return in_array($arr['type'] ?? '', ['unknown_core_file'], true);
                }));
            }, $findings, $engine_diagnostics);
        }

        // 4b. Deep Backdoor, Persistence, Hook, Cron, Snippet & Rogue Trigger Audits
        if (!empty($custom_options['scan_backdoors_heuristics'])) {
            $heartbeat();
            self::run_isolated_audit_engine($scan_id, 'persistence', 'Persistence & MU-Plugin Sentinel', static fn() => (new PersistenceScanner())->scan((string) $scan_id), $findings, $engine_diagnostics);
            self::run_isolated_audit_engine($scan_id, 'hook_sentinel', 'LotL Hook Infiltration Sentinel', static fn() => (new \WebCareProScanner\WordPress\HookInfiltrationSentinel())->scan((string) $scan_id), $findings, $engine_diagnostics);
            self::run_isolated_audit_engine($scan_id, 'cron_persistence', 'WP-Cron Persistence Sentinel', static fn() => (new \WebCareProScanner\Database\CronPersistenceScanner())->scan((string) $scan_id), $findings, $engine_diagnostics);

            $snippet_auditor = new \WebCareProScanner\Database\SnippetCodeAuditor();
            self::run_isolated_audit_engine(
                $scan_id,
                'snippet_auditor',
                'Database Snippet Auditor',
                static fn() => $snippet_auditor->scan((string) $scan_id),
                $findings,
                $engine_diagnostics,
                static fn(): ?string => $snippet_auditor->get_last_error()
            );

            $db_triggers = new DatabaseScanner();
            self::run_isolated_audit_engine(
                $scan_id,
                'rogue_triggers',
                'MySQL Trigger Persistence Audit',
                static fn() => $db_triggers->scan_rogue_triggers((string) $scan_id),
                $findings,
                $engine_diagnostics,
                static fn(): ?string => $db_triggers->get_last_trigger_error()
            );
        }

        // 4c. Scan loose files directly outside WordPress installation root (without recursing sibling vhosts)
        if (!empty($custom_options['scan_outside_root'])) {
            self::run_isolated_audit_engine($scan_id, 'outside_root', 'Outside-Root Loose Files Audit', static fn() => self::audit_outside_root_loose_files((string) $scan_id, $custom_options), $findings, $engine_diagnostics);
        }

        // 5. Scan for publicly accessible configuration, backup, or log files + Credential Exposure
        if (!empty($custom_options['scan_public_config'])) {
            self::run_isolated_audit_engine($scan_id, 'important_fim', 'Critical Config File Integrity', static fn() => (new ImportantFileFIM())->verify((string) $scan_id), $findings, $engine_diagnostics);
            self::run_isolated_audit_engine($scan_id, 'config_scanner', 'WordPress Configuration Audit', static fn() => (new \WebCareProScanner\WordPress\ConfigScanner())->scan((string) $scan_id), $findings, $engine_diagnostics);
            self::run_isolated_audit_engine($scan_id, 'exposed_sensitive_files', 'Exposed Sensitive Files Audit', static fn() => self::audit_exposed_sensitive_files((string) $scan_id), $findings, $engine_diagnostics);

            $cred_errors = [];
            self::run_isolated_audit_engine(
                $scan_id,
                'credential_exposure',
                'Plaintext Credential Exposure Audit',
                static function () use ($scan_id, &$cred_errors) {
                    return self::collect_silo_security_findings((string) $scan_id, true, false, false, $cred_errors);
                },
                $findings,
                $engine_diagnostics,
                static fn(): ?string => !empty($cred_errors) ? implode('; ', $cred_errors) : null
            );
        }

        // 5b. FIM Vault Drift & Script Inventory Drift (when calibrated)
        if (!empty($custom_options['scan_core_integrity']) || !empty($custom_options['scan_plugin_integrity']) || !empty($custom_options['scan_theme_integrity']) || !empty($custom_options['scan_malicious_urls'])) {
            $drift_errors = [];
            $inc_fim = !empty($custom_options['scan_plugin_integrity']) || !empty($custom_options['scan_theme_integrity']);
            $inc_scr = !empty($custom_options['scan_malicious_urls']) || !empty($custom_options['scan_backdoors_heuristics']);
            self::run_isolated_audit_engine(
                $scan_id,
                'silo_drift',
                'FIM Vault & Script Inventory Drift Audit',
                static function () use ($scan_id, $inc_fim, $inc_scr, &$drift_errors) {
                    return self::collect_silo_security_findings((string) $scan_id, false, $inc_fim, $inc_scr, $drift_errors);
                },
                $findings,
                $engine_diagnostics,
                static fn(): ?string => !empty($drift_errors) ? implode('; ', $drift_errors) : null
            );
        }

        // 6. Scan for publicly accessible quarantined files
        if (!empty($custom_options['scan_public_quarantine'])) {
            self::run_isolated_audit_engine($scan_id, 'public_quarantine', 'Quarantine Exposure Audit', static fn() => self::audit_quarantine_exposure((string) $scan_id), $findings, $engine_diagnostics);
        }

        // 7. Scan for misconfigured visitor IP detection headers
        if (!empty($custom_options['scan_ip_detection'])) {
            self::run_isolated_audit_engine($scan_id, 'ip_detection', 'Reverse Proxy & IP Detection Audit', static fn() => self::audit_visitor_ip_detection((string) $scan_id), $findings, $engine_diagnostics);
        }

        // 8. Scan posts & custom DB tables (including postmeta / Elementor) for dangerous URLs & content
        if (!empty($custom_options['scan_posts_content'])) {
            $heartbeat();
            self::run_isolated_audit_engine($scan_id, 'posts_content', 'Posts & FSE Content Scanner', static fn() => (new ContentScanner())->scan_posts_only((string) $scan_id, 100), $findings, $engine_diagnostics);

            $table_errors = [];
            $table_incomplete = false;
            self::run_isolated_audit_engine(
                $scan_id,
                'database_tables',
                'Custom Database Tables Scanner',
                static function () use ($scan_id, &$table_errors, &$table_incomplete) {
                    $table_scanner = new \WebCareProScanner\Database\TableScanner();
                    $monitor = class_exists('\\WebCareProScanner\\Resource\\ResourceMonitor')
                        ? new \WebCareProScanner\Resource\ResourceMonitor(70, 20, 'balanced')
                        : null;
                    $res = $table_scanner->scan_all_custom_tables((string) $scan_id, 250, $monitor);
                    $table_errors = is_array($res['errors'] ?? null) ? $res['errors'] : [];
                    $table_incomplete = !empty($res['incomplete']);
                    return is_array($res['findings'] ?? null) ? $res['findings'] : [];
                },
                $findings,
                $engine_diagnostics,
                static function () use (&$table_errors, &$table_incomplete): ?string {
                    if (!empty($table_errors)) {
                        return implode('; ', $table_errors);
                    }
                    return $table_incomplete ? 'Custom database table scan stopped early before inspecting all tables.' : null;
                }
            );
        }

        // 9. Scan comments for known dangerous URLs and suspicious content
        if (!empty($custom_options['scan_comments_content'])) {
            self::run_isolated_audit_engine($scan_id, 'comments_content', 'Comments Content Scanner', static fn() => (new ContentScanner())->scan_comments_only((string) $scan_id, 100), $findings, $engine_diagnostics);
        }

        // 10. Scan WordPress core, plugin, and theme options
        if (!empty($custom_options['scan_options_content'])) {
            self::run_isolated_audit_engine($scan_id, 'options_content', 'WordPress Options Scanner', static fn() => (new \WebCareProScanner\Database\OptionScanner())->scan_options((string) $scan_id), $findings, $engine_diagnostics);
        }

        // 11. Scan for out of date, abandoned, and vulnerable plugins, themes, and WP
        if (!empty($custom_options['scan_vulnerable_software'])) {
            self::run_isolated_audit_engine($scan_id, 'vulnerable_software', 'Software Updates & CVE Scanner', static fn() => (new UpdateScanner())->scan((string) $scan_id), $findings, $engine_diagnostics);
        }

        // 11b. NIST NVD CVE Vault Check (and background sync trigger if run headless/cron)
        if (!empty($custom_options['scan_cve_vulnerabilities']) && class_exists('\\WebCareProScanner\\Firewall\\NistCveVaultSync')) {
            self::run_isolated_audit_engine($scan_id, 'nist_cve_vault', 'NIST NVD CVE Vault Check', static function () use ($scan_id, $findings) {
                if (defined('DOING_CRON') && DOING_CRON) {
                    \WebCareProScanner\Firewall\NistCveVaultSync::maybe_run_daily_sync();
                }
                return self::deduplicate_vault_findings_against_updates(
                    \WebCareProScanner\Firewall\NistCveVaultSync::collect_vault_findings((string) $scan_id),
                    $findings
                );
            }, $findings, $engine_diagnostics);
        }

        // 12. Scan for suspicious admin users created outside of WordPress (without leaking password checks)
        if (!empty($custom_options['scan_rogue_admins'])) {
            self::run_isolated_audit_engine($scan_id, 'rogue_admins', 'Rogue Administrator Anomaly Audit', static function () use ($scan_id, $lease_token) {
                $rogue_findings = (new \WebCareProScanner\Database\RogueAdminAnomalyDetector())->scan((string) $scan_id);
                $user_findings  = (new UserScanner())->scan((string) $scan_id, true, $lease_token, false);
                return array_merge($rogue_findings, $user_findings);
            }, $findings, $engine_diagnostics);
        }

        // 13. Check the strength of passwords
        if (!empty($custom_options['scan_password_strength'])) {
            self::run_isolated_audit_engine($scan_id, 'password_strength', 'Password Strength Audit', static fn() => self::audit_password_strength((string) $scan_id), $findings, $engine_diagnostics);
        }

        // 14. Monitor disk space
        if (!empty($custom_options['monitor_disk_space'])) {
            self::run_isolated_audit_engine($scan_id, 'disk_space', 'Server Disk Space Monitor', static fn() => self::audit_disk_space((string) $scan_id), $findings, $engine_diagnostics);
        }

        // 15. Monitor Web Application Firewall status
        if (!empty($custom_options['monitor_firewall_status'])) {
            self::run_isolated_audit_engine($scan_id, 'waf_status', 'Firewall Status Audit', static fn() => self::audit_waf_status((string) $scan_id), $findings, $engine_diagnostics);
        }

        // 16. Scan images, binary, and other files as if they were executable
        if (!empty($custom_options['scan_images_executable'])) {
            self::run_isolated_audit_engine($scan_id, 'uploads_audit', 'Media & Uploads Executable Audit', static fn() => (new UploadsScanner())->scan((string) $scan_id), $findings, $engine_diagnostics);
        }

        // 17. Reputation Checks (Domain blocklist, spamvertised, spam IP)
        if (!empty($custom_options['check_domain_blocklist']) || !empty($custom_options['check_spamvertised']) || !empty($custom_options['check_spam_ip'])) {
            self::run_isolated_audit_engine($scan_id, 'reputation', 'Domain & IP Reputation Checks', static fn() => self::audit_reputation_checks((string) $scan_id, $custom_options), $findings, $engine_diagnostics);
        }

        return $findings;
    }

    /**
     * Suppress duplicate `nist-cve` Vault findings when `wordpress-updates` already emitted the exact
     * same component and CVE set in the same scan pass.
     *
     * @param list<\WebCareProScanner\Findings\Finding> $vault_findings
     * @param list<\WebCareProScanner\Findings\Finding> $existing_findings
     * @return list<\WebCareProScanner\Findings\Finding>
     */
    public static function deduplicate_vault_findings_against_updates(array $vault_findings, array $existing_findings): array {
        if (empty($vault_findings) || empty($existing_findings)) {
            return $vault_findings;
        }
        $canon = static function (string $slug): string {
            $s = strtolower(trim($slug));
            return class_exists('\\WebCareProScanner\\Firewall\\NistCveVaultSync')
                ? \WebCareProScanner\Firewall\NistCveVaultSync::resolve_canonical_slug($s)
                : $s;
        };

        $covered = [];
        foreach ($existing_findings as $ef) {
            if (!is_object($ef) || !method_exists($ef, 'to_array')) {
                continue;
            }
            $row = $ef->to_array();
            if (($row['engine'] ?? '') !== 'wordpress-updates') {
                continue;
            }
            $ev = json_decode((string) ($row['evidence'] ?? ''), true);
            if (!is_array($ev) || empty($ev['cves']) || !is_array($ev['cves'])) {
                continue;
            }
            $comp_type = (string) ($ev['type'] ?? '');
            $comp_slug = $canon((string) ($ev['slug'] ?? ($comp_type === 'core' ? 'wordpress' : '')));
            if ($comp_type === '' || $comp_slug === '') {
                continue;
            }
            $comp_key = $comp_type . ':' . $comp_slug;
            foreach ($ev['cves'] as $c) {
                $cid = strtoupper((string) ($c['cve_id'] ?? ''));
                if ($cid !== '') {
                    $covered[$comp_key][$cid] = true;
                }
            }
        }

        if (empty($covered)) {
            return $vault_findings;
        }

        $unique = [];
        foreach ($vault_findings as $vf) {
            if (!is_object($vf) || !method_exists($vf, 'to_array')) {
                continue;
            }
            $row = $vf->to_array();
            $ev  = json_decode((string) ($row['evidence'] ?? ''), true);
            $comp_type = is_array($ev) ? (string) ($ev['type'] ?? '') : '';
            $comp_slug = is_array($ev) ? $canon((string) ($ev['slug'] ?? ($comp_type === 'core' ? 'wordpress' : ''))) : '';
            $comp_key  = $comp_type . ':' . $comp_slug;

            if ($comp_type !== '' && $comp_slug !== '' && isset($covered[$comp_key]) && !empty($ev['cves']) && is_array($ev['cves'])) {
                $has_uncovered = false;
                foreach ($ev['cves'] as $c) {
                    $cid = strtoupper((string) ($c['cve_id'] ?? ''));
                    if ($cid !== '' && !isset($covered[$comp_key][$cid])) {
                        $has_uncovered = true;
                        break;
                    }
                }
                if (!$has_uncovered) {
                    continue;
                }
            }
            $unique[] = $vf;
        }

        return $unique;
    }

    /**
     * Execute a single deep-audit engine with fault isolation, sanitized operational logging,
     * and degraded/incomplete diagnostic emission so failed checks never masquerade as clean passes.
     */
    private static function run_isolated_audit_engine(
        int $scan_id,
        string $engine_key,
        string $engine_label,
        callable $runner,
        array &$all_findings,
        array &$engine_diagnostics,
        ?callable $error_inspector = null
    ): void {
        try {
            $result = $runner();
            if (is_array($result) && !empty($result)) {
                $all_findings = array_merge($all_findings, $result);
            }

            $degraded_reason = ($error_inspector !== null) ? $error_inspector() : null;
            if (is_string($degraded_reason) && trim($degraded_reason) !== '') {
                $sanitized_reason = self::sanitize_diagnostic_reason($degraded_reason);
                self::record_degraded_engine_diagnostic($scan_id, $engine_key, $engine_label, $sanitized_reason, $all_findings, $engine_diagnostics, 'incomplete');
                return;
            }

            $engine_diagnostics[$engine_key] = [
                'engine'         => $engine_key,
                'label'          => $engine_label,
                'status'         => 'completed',
                'findings_count' => is_array($result) ? count($result) : 0,
                'timestamp'      => gmdate('Y-m-d\TH:i:s\Z'),
            ];
        } catch (\Throwable $e) {
            if ($e instanceof \WebCareProScanner\Scan\ScanLeaseLostException) {
                throw $e;
            }

            $short_class = (new \ReflectionClass($e))->getShortName();
            $raw_reason  = $short_class . ': ' . $e->getMessage();
            $sanitized_reason = self::sanitize_diagnostic_reason($raw_reason);
            self::record_degraded_engine_diagnostic($scan_id, $engine_key, $engine_label, $sanitized_reason, $all_findings, $engine_diagnostics, 'degraded');
        }
    }

    /**
     * Sanitize an operational diagnostic reason for safe storage and administrator display.
     */
    private static function sanitize_diagnostic_reason(string $raw_reason): string {
        $clean = sanitize_text_field($raw_reason);
        $clean = str_replace(["\r", "\n", "\t"], ' ', $clean);
        if (defined('ABSPATH')) {
            $clean = str_replace(wp_normalize_path(ABSPATH), '[ABSPATH]/', wp_normalize_path($clean));
        }
        $clean = trim((string) preg_replace('/\s+/', ' ', $clean));
        if ($clean === '') {
            return 'Unexpected engine execution failure';
        }
        return substr($clean, 0, 180);
    }

    /**
     * Record a degraded/incomplete engine diagnostic operationally, update per-scan telemetry,
     * and emit a non-clean diagnostic Finding so an incomplete scan never appears as a clean pass.
     */
    private static function record_degraded_engine_diagnostic(
        int $scan_id,
        string $engine_key,
        string $engine_label,
        string $sanitized_reason,
        array &$all_findings,
        array &$engine_diagnostics,
        string $status = 'degraded'
    ): void {
        if (class_exists('\\WebCareProScanner\\System\\AuditLogger')) {
            try {
                \WebCareProScanner\System\AuditLogger::log_operational('scan_engine_degraded', [
                    'scan_id' => $scan_id,
                    'engine'  => $engine_key,
                    'label'   => $engine_label,
                    'status'  => $status,
                    'reason'  => $sanitized_reason,
                ]);
            } catch (\Throwable $ignore) {}
        }

        $engine_diagnostics[$engine_key] = [
            'engine'    => $engine_key,
            'label'     => $engine_label,
            'status'    => $status,
            'reason'    => $sanitized_reason,
            'timestamp' => gmdate('Y-m-d\TH:i:s\Z'),
        ];

        $all_findings[] = new \WebCareProScanner\Findings\Finding([
            'engine'       => 'scan-diagnostics',
            'type'         => 'scan_engine_degraded',
            'severity'     => 'info',
            'confidence'   => 100,
            'file_path'    => "engine:{$engine_key}",
            'description'  => sprintf(
                '%s could not complete (%s). Inspection coverage for this check is incomplete.',
                $engine_label,
                $sanitized_reason
            ),
            'evidence'     => wp_json_encode([
                'incomplete' => true,
                'engine'     => $engine_key,
                'label'      => $engine_label,
                'status'     => $status,
                'reason'     => $sanitized_reason,
            ]),
            'code_snippet' => "Engine Status: " . strtoupper($status) . " ({$engine_label})",
        ]);
    }

    /**
     * Persist per-scan engine diagnostics for later inspection in latest/history/export endpoints.
     */
    private static function persist_scan_engine_diagnostics(int $scan_id, array $engine_diagnostics): void {
        if ($scan_id <= 0) {
            return;
        }
        $list = array_values($engine_diagnostics);
        update_option("webcareproscan_scan_engine_diag_{$scan_id}", $list, false);
    }

    /**
     * Load persisted per-scan engine diagnostics for a scan ID.
     */
    private static function load_scan_engine_diagnostics(int $scan_id): array {
        if ($scan_id <= 0) {
            return [];
        }
        $stored = get_option("webcareproscan_scan_engine_diag_{$scan_id}", []);
        return is_array($stored) ? array_values($stored) : [];
    }

    /**
     * Collect findings from previously siloed security engines (CredentialExposureScanner, FimDriftDetector, ScriptInventoryMonitor).
     *
     * @param list<string> $errors Populated by reference with sanitized errors if any silo engine fails
     */
    public static function collect_silo_security_findings(
        string $scan_id,
        bool $include_credentials = true,
        bool $include_fim_drift = true,
        bool $include_script_drift = true,
        array &$errors = []
    ): array {
        $findings = [];

        // 1. Plaintext AI / Cloud / Payment / SSH Credential Exposure
        if ($include_credentials && class_exists('\\WebCareProScanner\\Security\\CredentialExposureScanner')) {
            try {
                $cred_report = \WebCareProScanner\Security\CredentialExposureScanner::run_scan(true);
                foreach (($cred_report['findings'] ?? []) as $cf) {
                    $findings[] = new \WebCareProScanner\Findings\Finding([
                        'engine'       => 'credential-exposure',
                        'type'         => 'exposed_credential_' . sanitize_key((string) ($cf['type'] ?? 'secret')),
                        'severity'     => (string) ($cf['severity'] ?? 'critical'),
                        'confidence'   => 98,
                        'file_path'    => (string) ($cf['file'] ?? ''),
                        'line_number'  => isset($cf['line']) ? (int) $cf['line'] : null,
                        'code_snippet' => isset($cf['masked']) ? 'Masked secret: ' . (string) $cf['masked'] : null,
                        'description'  => sprintf('%s in %s: %s', (string) ($cf['title'] ?? 'Exposed Secret'), (string) ($cf['file'] ?? 'file'), (string) ($cf['description'] ?? '')),
                        'evidence'     => wp_json_encode($cf),
                    ]);
                }
            } catch (\Throwable $e) {
                $errors[] = 'CredentialExposureScanner: ' . self::sanitize_diagnostic_reason($e->getMessage());
            }
        }

        // 2. Calibrated FIM Vault Drift (catches tampered premium/custom plugins & themes without WP.org checksums)
        if ($include_fim_drift && class_exists('\\WebCareProScanner\\Integrity\\FimDriftDetector') && class_exists('\\WebCareProScanner\\Integrity\\FimVaultManager')) {
            try {
                $v_status = \WebCareProScanner\Integrity\FimVaultManager::get_vault_status();
                if (!empty($v_status['is_calibrated'])) {
                    $drift = \WebCareProScanner\Integrity\FimDriftDetector::audit_drift('all', 100);
                    foreach (($drift['drift_items'] ?? []) as $di) {
                        $change = (string) ($di['change_type'] ?? 'modified');
                        if ($change === 'deleted') {
                            continue;
                        }
                        $rel = (string) ($di['rel_path'] ?? $di['path'] ?? '');
                        if ($rel === '') {
                            continue;
                        }
                        $findings[] = new \WebCareProScanner\Findings\Finding([
                            'engine'      => 'fim-vault',
                            'type'        => 'fim_baseline_' . sanitize_key($change),
                            'severity'    => (string) ($di['severity'] ?? 'high'),
                            'confidence'  => 95,
                            'file_path'   => $rel,
                            'description' => sprintf('Calibrated FIM baseline drift (%s) detected on %s.', $change, $rel),
                            'evidence'    => wp_json_encode($di),
                        ]);
                    }
                }
            } catch (\Throwable $e) {
                $errors[] = 'FimDriftDetector: ' . self::sanitize_diagnostic_reason($e->getMessage());
            }
        }

        // 3. Third-Party Checkout / Auth Script Inventory Drift (Magecart SRI/domain drift)
        if ($include_script_drift && class_exists('\\WebCareProScanner\\Content\\ScriptInventoryMonitor')) {
            try {
                $alerts = get_option(\WebCareProScanner\Content\ScriptInventoryMonitor::OPTION_ALERTS, []);
                if (is_array($alerts)) {
                    foreach (array_slice($alerts, 0, 50) as $al) {
                        if (!is_array($al) || ($al['status'] ?? 'open') === 'dismissed') {
                            continue;
                        }
                        $src = (string) ($al['src'] ?? $al['handle'] ?? 'unknown-script');
                        $findings[] = new \WebCareProScanner\Findings\Finding([
                            'engine'       => 'script-inventory',
                            'type'         => 'unauthorized_external_script_drift',
                            'severity'     => !empty($al['sensitive_page']) ? 'critical' : 'high',
                            'confidence'   => 92,
                            'file_path'    => 'server:script-inventory:' . md5($src),
                            'code_snippet' => $src,
                            'description'  => sprintf('Unauthorized external JavaScript drift detected (%s): %s', (string) ($al['reason'] ?? 'new_external_script'), $src),
                            'evidence'     => wp_json_encode($al),
                        ]);
                    }
                }
            } catch (\Throwable $e) {
                $errors[] = 'ScriptInventoryMonitor: ' . self::sanitize_diagnostic_reason($e->getMessage());
            }
        }

        return $findings;
    }

    /**
     * Audit exposed sensitive files (.env, debug.log, backup.sql, .git/config)
     * Note: wp-config.php backups are audited by ConfigScanner to prevent duplicate findings.
     */
    public static function audit_exposed_sensitive_files(string $scan_id): array {
        $findings = [];
        $sensitive_files = [
            '.env'                 => ['severity' => 'critical', 'desc' => 'Environment configuration file containing plain-text database credentials, API keys, or JWT secrets.'],
            'debug.log'            => ['severity' => 'medium',   'desc' => 'WordPress debug log file containing stack traces, SQL errors, or sensitive payload data.'],
            'wp-content/debug.log' => ['severity' => 'medium',   'desc' => 'WordPress debug log in wp-content containing runtime exceptions and system filepaths.'],
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

        $admins = get_users(['role__in' => ['administrator', 'editor', 'shop_manager'], 'number' => 200]);
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
                'engine'      => 'waf-status',
                'type'        => 'waf_inactive',
                'severity'    => 'high',
                'confidence'  => 100,
                'file_path'   => 'firewall:status',
                'description' => 'Web Application Firewall (WAF) is currently disabled. Incoming malicious HTTP payloads (SQLi, XSS, Path Traversal) are not being filtered at the application boundary.',
                'evidence'    => 'WAF state: disabled in plugin security settings.'
            ]);
        } elseif ($waf_mode === 'learning') {
            $findings[] = new \WebCareProScanner\Findings\Finding([
                'engine'      => 'waf-status',
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

        // 1. Check if website is on a domain blocklist (Spamhaus DBL)
        if (!empty($opts['check_domain_blocklist']) && !empty($host) && (!$is_local_host || !empty($test_host))) {
            // Forward lookup format: {domain}.dbl.spamhaus.org
            $dbl_query = "{$host}.dbl.spamhaus.org";
            $ip = @gethostbyname($dbl_query);
            // 127.0.1.2..127.0.1.106 indicates legitimate Spamhaus DBL listing; 127.0.1.255 / 127.255.255.x indicates resolver error/IP query
            if ($ip && $ip !== $dbl_query && str_starts_with($ip, '127.0.1.') && $ip !== '127.0.1.255') {
                $findings[] = new \WebCareProScanner\Findings\Finding([
                    'engine'      => 'reputation',
                    'type'        => 'domain_blocklisted',
                    'severity'    => 'critical',
                    'confidence'  => 95,
                    'file_path'   => "domain:{$host}:dbl",
                    'description' => "CRITICAL REPUTATION ALERT: The domain '{$host}' is listed on the Spamhaus Domain Blocklist (DBL) as spam, malicious, or compromised.",
                    'evidence'    => "Spamhaus DBL response code: {$ip}"
                ]);
            }
        }

        // 2. Check if website is being "Spamvertised" (SURBL multi.surbl.org)
        // CRITICAL: 127.0.0.1 on SURBL means "Query Refused (public DNS resolver blocked)", NOT listed! Real listings are bitmask >= 127.0.0.2.
        if (!empty($opts['check_spamvertised']) && !empty($host) && (!$is_local_host || !empty($test_host))) {
            $surbl_query = "{$host}.multi.surbl.org";
            $surbl_res = @gethostbyname($surbl_query);
            if ($surbl_res && $surbl_res !== $surbl_query && str_starts_with($surbl_res, '127.0.0.') && $surbl_res !== '127.0.0.1') {
                $findings[] = new \WebCareProScanner\Findings\Finding([
                    'engine'      => 'reputation',
                    'type'        => 'domain_spamvertised',
                    'severity'    => 'critical',
                    'confidence'  => 95,
                    'file_path'   => "domain:{$host}:surbl",
                    'description' => "CRITICAL REPUTATION ALERT: The domain '{$host}' is listed on SURBL as actively 'Spamvertised' in bulk unsolicited email or phishing campaigns.",
                    'evidence'    => "SURBL return code: {$surbl_res}"
                ]);
            }
        }

        // 3. Check if website IP is generating spam (Spamcop, Barracuda, Spamhaus ZEN — IPv4 reverse-octet DNSBLs)
        if (!empty($opts['check_spam_ip'])) {
            $test_ip = apply_filters('webcareproscan_test_reputation_ip', $opts['test_ip'] ?? null);
            $raw_srv_ip = isset($_SERVER['SERVER_ADDR']) ? sanitize_text_field((string) wp_unslash($_SERVER['SERVER_ADDR'])) : '';
            $server_ip = !empty($test_ip) ? $test_ip : ($raw_srv_ip ?: gethostbyname($host ?: 'localhost'));

            $is_valid_ipv4 = filter_var($server_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
            $is_public_ipv4 = filter_var($server_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;

            if ($is_valid_ipv4 && ($is_public_ipv4 || !empty($test_ip))) {
                $rev_ip = implode('.', array_reverse(explode('.', $server_ip)));

                // 3.1 Spamcop SCBL (127.0.0.2 is listed)
                $spamcop_query = "{$rev_ip}.bl.spamcop.net";
                $sc_res = @gethostbyname($spamcop_query);
                if ($sc_res && $sc_res !== $spamcop_query && $sc_res === '127.0.0.2') {
                    $findings[] = new \WebCareProScanner\Findings\Finding([
                        'engine'      => 'reputation',
                        'type'        => 'server_ip_spam_blocklisted',
                        'severity'    => 'high',
                        'confidence'  => 95,
                        'file_path'   => "ip:{$server_ip}:spamcop",
                        'description' => "Server outbound IP '{$server_ip}' is actively listed on the Spamcop Blocking List (SCBL) as an active source of unsolicited spam.",
                        'evidence'    => "Spamcop DNSBL code: {$sc_res}"
                    ]);
                }

                // 3.2 Barracuda Reputation Network (BRBL — 127.0.0.2 is listed)
                $barracuda_query = "{$rev_ip}.b.barracudacentral.org";
                $bc_res = @gethostbyname($barracuda_query);
                if ($bc_res && $bc_res !== $barracuda_query && $bc_res === '127.0.0.2') {
                    $findings[] = new \WebCareProScanner\Findings\Finding([
                        'engine'      => 'reputation',
                        'type'        => 'server_ip_spam_blocklisted',
                        'severity'    => 'high',
                        'confidence'  => 90,
                        'file_path'   => "ip:{$server_ip}:barracuda",
                        'description' => "Server outbound IP '{$server_ip}' is listed on the Barracuda Reputation Network blocklist (BRBL). Outbound transactional emails may be rejected as spam.",
                        'evidence'    => "Barracuda DNSBL code: {$bc_res}"
                    ]);
                }

                // 3.3 Spamhaus ZEN (127.0.0.2..11 are SBL/CSS/XBL/PBL listings; 127.255.255.* are open-resolver error codes)
                $zen_query = "{$rev_ip}.zen.spamhaus.org";
                $zen_res = @gethostbyname($zen_query);
                if ($zen_res && $zen_res !== $zen_query && in_array($zen_res, ['127.0.0.2', '127.0.0.3', '127.0.0.4', '127.0.0.9', '127.0.0.10', '127.0.0.11'], true)) {
                    $findings[] = new \WebCareProScanner\Findings\Finding([
                        'engine'      => 'reputation',
                        'type'        => 'server_ip_spam_blocklisted',
                        'severity'    => 'high',
                        'confidence'  => 90,
                        'file_path'   => "ip:{$server_ip}:spamhaus-zen",
                        'description' => "Server outbound IP '{$server_ip}' is listed on the Spamhaus ZEN anti-spam database. Outbound transactional emails may be rejected as spam.",
                        'evidence'    => "Spamhaus ZEN code: {$zen_res}"
                    ]);
                }
            }
        }

        return $findings;
    }
}
