<?php
declare(strict_types=1);

namespace WebCareProScanner\Scan;

use WebCareProScanner\Api\ScannerRoutes;
use WebCareProScanner\System\Cron\CronControlCenter;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * ScanBackgroundWorker
 *
 * Autonomous background continuation worker for the WebCare Pro Security Scanner.
 * Automatically executes chunked file batches in server-side WP-Cron ticks when the
 * admin navigates away or closes their browser tab.
 *
 * Features:
 * - Zero Memory Accumulation: Runs each batch with an independent, strictly bounded memory footprint.
 * - Dynamic Resource Guard: Micro-yields before hitting FastCGI / PHP timeout boundaries.
 * - Auto-Healing Heartbeat: Refreshes ScanLock cryptographic lease so scans are never marked interrupted.
 * - Live UI Re-attachment: Seamlessly yields execution when the browser tab returns and resumes polling.
 *
 * Author: Mir Alamin (WebCare Pro)
 * Senior Linux SysAdmin & WordPress Security Engineer
 *
 * @package WebCareProScanner\Scan
 */
final class ScanBackgroundWorker {

    public const CRON_HOOK = 'webcareproscan_scan_step_worker';

    /**
     * Minimum idle seconds since the last browser batch before the background cron worker takes over.
     */
    public const BROWSER_IDLE_THRESHOLD_SECONDS = 8.0;

    /**
     * Maximum execution window per background cron tick (in seconds) to prevent hosting timeouts.
     */
    public const MAX_CRON_SLICE_SECONDS = 9.0;

    /**
     * Register WP-Cron action handlers for scan background continuation.
     */
    public static function register(): void {
        if (class_exists(CronControlCenter::class)) {
            add_action(self::CRON_HOOK, static function (): void {
                CronControlCenter::invoke_task_handler(self::CRON_HOOK, 'wp_cron');
            });
            return;
        }

        add_action(self::CRON_HOOK, static function (): void {
            self::run_background_step();
        });
    }

    /**
     * Schedule a delayed background continuation tick if one is not already queued.
     *
     * @param int $delay_seconds Delay in seconds before running (default: 5s).
     */
    public static function schedule_continuation(int $delay_seconds = 5): void {
        if (class_exists(CronControlCenter::class) && !CronControlCenter::is_task_enabled(self::CRON_HOOK)) {
            self::unschedule_continuation();
            return;
        }

        if (!wp_next_scheduled(self::CRON_HOOK)) {
            wp_schedule_single_event(time() + max(2, $delay_seconds), self::CRON_HOOK);
        }
    }

    /**
     * Cancel and remove any scheduled background scan continuation events.
     */
    public static function unschedule_continuation(): void {
        $ts = wp_next_scheduled(self::CRON_HOOK);
        while ($ts) {
            wp_unschedule_event($ts, self::CRON_HOOK);
            $ts = wp_next_scheduled(self::CRON_HOOK);
        }
        if (function_exists('wp_clear_scheduled_hook')) {
            wp_clear_scheduled_hook(self::CRON_HOOK);
        }
    }

    /**
     * WP-Cron Worker: advances an active running scan in the background when no browser is polling.
     *
     * @param bool $bypass_idle_check If true, ignores browser idle wait and processes a batch immediately.
     * @return array<string, mixed> Execution status report.
     */
    public static function run_background_step(bool $bypass_idle_check = false): array {
        global $wpdb;

        $locked_id = ScanLock::get_locked_scan_id();
        if (!$locked_id) {
            self::unschedule_continuation();
            return [
                'status'  => 'skipped',
                'summary' => __('No active scan lock held.', 'webcare-pro-security'),
            ];
        }

        $lease_token = ScanLock::get_active_lease_token($locked_id);
        if (empty($lease_token)) {
            self::unschedule_continuation();
            return [
                'status'  => 'skipped',
                'summary' => __('No valid lease token found for active scan.', 'webcare-pro-security'),
            ];
        }

        $table_scans = $wpdb->prefix . 'webcareproscan_scans';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $scan_row = $wpdb->get_row(
            $wpdb->prepare("SELECT * FROM `{$table_scans}` WHERE id = %d", $locked_id),
            ARRAY_A
        );

        if (!$scan_row || ($scan_row['status'] ?? '') !== 'running') {
            self::unschedule_continuation();
            return [
                'status'  => 'skipped',
                'summary' => __('Scan is not in running status.', 'webcare-pro-security'),
            ];
        }

        // Check if browser actively polled recently
        $last_touch = (float) get_transient("webcareproscan_active_scan_last_browser_touch_{$locked_id}");
        if (!$bypass_idle_check && $last_touch > 0 && (microtime(true) - $last_touch) < self::BROWSER_IDLE_THRESHOLD_SECONDS) {
            // Browser tab is still active and driving batches; back off and check again in 10s
            self::schedule_continuation(10);
            return [
                'status'  => 'skipped',
                'summary' => __('Browser tab is actively driving scan batches.', 'webcare-pro-security'),
            ];
        }

        // Memory & execution safeguards
        if (function_exists('set_time_limit')) {
            // phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged
            @set_time_limit(60);
        }

        $start_time = microtime(true);
        $total_processed_in_tick = 0;
        $configured_batch = (int) \WebCareProScanner\System\SettingsManager::get('scan_batch_size', 50);
        $batch_size = max(25, min(100, $configured_batch));

        $slices = 0;
        $max_slices = 5;

        while ($slices < $max_slices && (microtime(true) - $start_time) < self::MAX_CRON_SLICE_SECONDS) {
            $slices++;

            // Create synthetic WP_REST_Request for ScannerRoutes::process_batch()
            $request = new \WP_REST_Request('POST', '/webcare-pro-security/v1/scan/batch');
            $request->set_param('scan_id', $locked_id);
            $request->set_param('lease_token', $lease_token);
            $request->set_param('batch_size', $batch_size);

            $batch_res = ScannerRoutes::process_batch($request);
            if (is_wp_error($batch_res)) {
                $err_code = $batch_res->get_error_code();
                if ($err_code === 'scan_lock_conflict') {
                    // Browser or another worker holds batch lock; yield gracefully
                    self::schedule_continuation(5);
                    return [
                        'status'  => 'yielded',
                        'summary' => __('Batch lock currently held by another worker.', 'webcare-pro-security'),
                    ];
                }
                break;
            }

            $data = $batch_res instanceof \WP_REST_Response ? $batch_res->get_data() : (array) $batch_res;
            $processed = (int) ($data['processed'] ?? 0);
            $total_processed_in_tick += $processed;

            if (!empty($data['is_finished'])) {
                // Filesystem queue is complete! Trigger deep audit
                $audit_request = new \WP_REST_Request('POST', '/webcare-pro-security/v1/scan/deep-audit');
                $audit_request->set_param('scan_id', $locked_id);
                $audit_request->set_param('lease_token', $lease_token);
                $audit_request->set_param('target', $scan_row['scan_target'] ?? 'full');

                $audit_res = ScannerRoutes::run_deep_audit($audit_request);
                self::unschedule_continuation();

                return [
                    'status'  => 'success',
                    'summary' => sprintf(
                        /* translators: 1: scan ID, 2: files processed in tick */
                        __('Background scan #%1$d finished completely (%2$d files in final tick).', 'webcare-pro-security'),
                        $locked_id,
                        $total_processed_in_tick
                    ),
                    'metrics' => [
                        'scan_id'   => $locked_id,
                        'completed' => true,
                    ],
                ];
            }

            if ($processed === 0) {
                break;
            }
        }

        // Check if scan is still running; if so, schedule next continuation tick
        $is_still_running = ScanLock::get_locked_scan_id() === $locked_id;
        if ($is_still_running) {
            self::schedule_continuation(2);
            if (function_exists('spawn_cron')) {
                @spawn_cron();
            }
        } else {
            self::unschedule_continuation();
        }

        return [
            'status'  => 'success',
            'summary' => sprintf(
                /* translators: 1: files processed in tick, 2: scan ID */
                __('Background worker advanced scan #%2$d by %1$d files.', 'webcare-pro-security'),
                $total_processed_in_tick,
                $locked_id
            ),
            'metrics' => [
                'scan_id'   => $locked_id,
                'processed' => $total_processed_in_tick,
            ],
        ];
    }
}
