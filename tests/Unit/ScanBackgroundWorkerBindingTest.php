<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Scan\ScanBackgroundWorker;
use WebCareProScanner\Scan\ScanLock;

/**
 * ScanBackgroundWorkerBindingTest
 *
 * Verifies that ScanBackgroundWorker::run_background_step() strictly verifies
 * expected_scan_id against the active lock and aborts with scan_id_mismatch if desynchronized.
 */
final class ScanBackgroundWorkerBindingTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $GLOBALS['wp_mock_options'] = [];
        $GLOBALS['wpdb'] = new \wpdb();
        $GLOBALS['wpdb']->mock_get_var_callback = static fn(string $q) => 1;
        ScanLock::force_release();
    }

    protected function tearDown(): void
    {
        ScanLock::force_release();
        parent::tearDown();
    }

    public function testRejectsWhenExpectedScanIdMismatchesActiveLock(): void
    {
        // Acquire lock for scan #100
        $acquired = ScanLock::acquire(100);
        $this->assertTrue($acquired, 'Should acquire lock for scan 100.');

        // Attempt to run background step expecting scan #101
        $result = ScanBackgroundWorker::run_background_step(true, 101);

        $this->assertFalse($result['success'] ?? true);
        $this->assertSame('scan_id_mismatch', $result['status'] ?? '');
    }

    public function testAcceptsMatchingExpectedScanId(): void
    {
        // Acquire lock for scan #200
        $acquired = ScanLock::acquire(200);
        $this->assertTrue($acquired, 'Should acquire lock for scan 200.');

        // Execute background step expecting scan #200
        // (Even if scan row is not in running status, it passes the scan_id_mismatch check)
        $result = ScanBackgroundWorker::run_background_step(true, 200);

        $this->assertNotSame('scan_id_mismatch', $result['status'] ?? '');
    }

    public function testReschedulesOverdueContinuationAndSelfHealsIdleScan(): void
    {
        update_option('cron', []);
        unset($GLOBALS['wp_mock_transients']);

        // Seed an overdue WP-Cron continuation stuck 3 minutes in the past
        $staleTs = time() - 180;
        wp_schedule_single_event($staleTs, ScanBackgroundWorker::CRON_HOOK);
        $this->assertSame($staleTs, wp_next_scheduled(ScanBackgroundWorker::CRON_HOOK));

        ScanBackgroundWorker::schedule_continuation(5);
        $newTs = wp_next_scheduled(ScanBackgroundWorker::CRON_HOOK);
        $this->assertIsInt($newTs);
        $this->assertGreaterThan(time() - 5, $newTs, 'Stale overdue continuation slot must be replaced with a future timestamp.');

        // Seed active scan lock with idle browser/worker heartbeats -> self-heal must arm continuation
        ScanLock::acquire(305, 'tok_305');
        set_transient('webcareproscan_active_scan_last_browser_touch_305', microtime(true) - 30, 120);
        set_transient('webcareproscan_bg_last_tick_305', microtime(true) - 30, 120);

        $this->assertTrue(ScanBackgroundWorker::maybe_advance_stalled_scan(305));
        $this->assertFalse(ScanBackgroundWorker::maybe_advance_stalled_scan(305), 'Self-heal cooldown must debounce back-to-back status polls.');
    }

    public function testLongRunningScanRecoversLockWithOriginalGenerationTokenAndComputesRealDuration(): void
    {
        unset($GLOBALS['wp_mock_transients']);
        $sixHoursAgoUtc = gmdate('Y-m-d H:i:s', time() - 21600);
        $scanId = 812;

        // Simulate expired start_micro transient (>1 hour old) but recent batch activity 90s ago + queue still present
        set_transient("webcareproscan_scan_last_activity_{$scanId}", time() - 90, 3600);

        $uploads = wp_upload_dir()['basedir'];
        $sDir    = $uploads . '/webcare-pro-security/scan-sessions/' . $scanId;
        if (!is_dir($sDir)) {
            mkdir($sDir, 0755, true);
        }
        file_put_contents($sDir . '/queue.txt', "/var/www/html/wp-config.php\n");
        file_put_contents($sDir . '/meta.json', wp_json_encode([
            'scan_id'         => $scanId,
            'storage_mode'    => 'disk',
            'total_files'     => 100,
            'processed_count' => 80,
            'cursor_offset'   => 0,
            'created_at'      => time() - 21600,
        ]));

        // Simulate expired ScanLock on a 6-hour-old running scan
        $row = [
            'id'               => $scanId,
            'status'           => 'running',
            'generation_token' => 'gen_tok_812',
            'scan_target'      => 'full',
            'trigger_type'     => 'manual',
            'total_files'      => 100,
            'scanned_files'    => 80,
            'issues_found'     => 0,
            'created_at'       => $sixHoursAgoUtc,
            'created_at_gmt'   => $sixHoursAgoUtc,
            'started_at'       => $sixHoursAgoUtc,
        ];

        $wpdbMock = new class($row) extends \wpdb {
            private array $scanRow;
            public function __construct(array $scanRow) {
                $this->scanRow = $scanRow;
                $this->mock_get_var_callback = static fn(string $q) => 1;
            }
            public function get_results(string $query, string $output = 'OBJECT') {
                $this->queries[] = $query;
                return str_contains($query, "status = 'running'") ? [$this->scanRow] : [];
            }
            public function get_row(string $query, string $output = 'OBJECT') {
                $this->queries[] = $query;
                return str_contains($query, 'WHERE id =') ? $this->scanRow : null;
            }
        };
        $GLOBALS['wpdb'] = $wpdbMock;

        try {
            $resp = \WebCareProScanner\Api\Controllers\ScanController::get_active_scan(new \WP_REST_Request('GET', '/webcare-pro-security/v1/scan/active'));
            $data = $resp instanceof \WP_REST_Response ? $resp->get_data() : (array) $resp;
            $this->assertTrue($data['is_running'] ?? false, 'Active 6-hour scan with recent activity must be recovered rather than killed as interrupted.');
            $this->assertSame('gen_tok_812', $data['lease_token'] ?? '', 'Lock recovery must preserve the DB generation_token.');

            // Also verify ScanInterruptionForensics computes ~21600s instead of 1s when start_micro transient is missing
            $forensics = \WebCareProScanner\Scan\ScanInterruptionForensics::record($scanId, \WebCareProScanner\Scan\ScanInterruptionForensics::REASON_STALE_HEARTBEAT);
            $this->assertGreaterThan(20000, $forensics['elapsed_seconds'] ?? 0);
        } finally {
            @unlink($sDir . '/queue.txt');
            @unlink($sDir . '/meta.json');
            @rmdir($sDir);
            ScanLock::force_release();
            delete_option('webcareproscan_interruption_' . $scanId);
        }
    }
}
