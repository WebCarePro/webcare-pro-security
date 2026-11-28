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

    public function testFailedAdvisoryLockAcquisitionDoesNotInterruptHealthyScanWithinRecoveryWindow(): void
    {
        unset($GLOBALS['wp_mock_transients']);
        $scanId = 901;
        $recentUtc = gmdate('Y-m-d H:i:s', time() - 30);
        set_transient("webcareproscan_scan_last_activity_{$scanId}", time() - 20, 3600);

        $row = [
            'id'               => $scanId,
            'status'           => 'running',
            'generation_token' => 'gen_tok_901',
            'scan_target'      => 'full',
            'trigger_type'     => 'manual',
            'total_files'      => 500,
            'scanned_files'    => 250,
            'issues_found'     => 0,
            'created_at'       => $recentUtc,
            'created_at_gmt'   => $recentUtc,
            'started_at'       => $recentUtc,
        ];

        // Advisory GET_LOCK fails (returns 0) -> ScanLock::acquire() fails transiently
        $wpdbMock = new class($row) extends \wpdb {
            public array $rowState;
            public function __construct(array $row) {
                $this->rowState = $row;
                $this->mock_get_var_callback = static fn(string $q) => 0;
            }
            public function get_results(string $query, string $output = 'OBJECT') {
                $this->queries[] = $query;
                return str_contains($query, "status = 'running'") ? [$this->rowState] : [];
            }
            public function get_row(string $query, string $output = 'OBJECT') {
                $this->queries[] = $query;
                return str_contains($query, 'WHERE id =') ? $this->rowState : null;
            }
            public function update(string $table, array $data, array $where, ?array $format = null, ?array $where_format = null) {
                $this->queries[] = "UPDATE {$table}";
                $this->rowState = array_merge($this->rowState, $data);
                return 1;
            }
        };
        $GLOBALS['wpdb'] = $wpdbMock;

        $resp = \WebCareProScanner\Api\Controllers\ScanController::get_active_scan(new \WP_REST_Request('GET', '/webcare-pro-security/v1/scan/active'));
        $data = $resp instanceof \WP_REST_Response ? $resp->get_data() : (array) $resp;

        $this->assertFalse($data['is_running'] ?? true);
        $this->assertSame('running', $wpdbMock->rowState['status'], 'Transient ScanLock::acquire() failure inside recovery window must NOT mark scan interrupted.');
        $this->assertNull(get_option('webcareproscan_interruption_' . $scanId, null), 'Must not write interruption forensics when scan is still within recovery window.');
    }

    public function testConcurrentLockAcquisitionDuringFailedRecoveryReturnsActiveStateWithoutInterrupting(): void
    {
        unset($GLOBALS['wp_mock_transients']);
        $scanId = 902;
        $recentUtc = gmdate('Y-m-d H:i:s', time() - 30);
        set_transient("webcareproscan_scan_last_activity_{$scanId}", time() - 15, 3600);

        $row = [
            'id'               => $scanId,
            'status'           => 'running',
            'generation_token' => 'concurrent_tok_902',
            'scan_target'      => 'full',
            'trigger_type'     => 'manual',
            'total_files'      => 500,
            'scanned_files'    => 300,
            'issues_found'     => 0,
            'created_at'       => $recentUtc,
            'created_at_gmt'   => $recentUtc,
            'started_at'       => $recentUtc,
        ];

        $wpdbMock = new class($row, $scanId) extends \wpdb {
            public array $rowState;
            private int $scanId;
            private int $getVarCalls = 0;
            public function __construct(array $row, int $scanId) {
                $this->rowState = $row;
                $this->scanId   = $scanId;
                $this->mock_get_var_callback = function (string $q) {
                    $this->getVarCalls++;
                    // Simulate another worker winning ScanLock right as GET_LOCK contention happens
                    if (str_contains($q, 'GET_LOCK')) {
                        update_option(ScanLock::LOCK_OPTION, [
                            'scan_id'     => $this->scanId,
                            'time'        => time(),
                            'lease_token' => 'concurrent_tok_902',
                        ]);
                        return 0;
                    }
                    return 1;
                };
            }
            public function get_results(string $query, string $output = 'OBJECT') {
                $this->queries[] = $query;
                return str_contains($query, "status = 'running'") ? [$this->rowState] : [];
            }
            public function get_row(string $query, string $output = 'OBJECT') {
                $this->queries[] = $query;
                return str_contains($query, 'WHERE id =') ? $this->rowState : null;
            }
        };
        $GLOBALS['wpdb'] = $wpdbMock;

        try {
            $resp = \WebCareProScanner\Api\Controllers\ScanController::get_active_scan(new \WP_REST_Request('GET', '/webcare-pro-security/v1/scan/active'));
            $data = $resp instanceof \WP_REST_Response ? $resp->get_data() : (array) $resp;

            $this->assertTrue($data['is_running'] ?? false, 'Re-reading concurrent lock acquisition must recover active scan state.');
            $this->assertSame($scanId, $data['scan_id'] ?? 0);
            $this->assertSame('concurrent_tok_902', $data['lease_token'] ?? '');
            $this->assertSame('running', $wpdbMock->rowState['status']);
            $this->assertNull(get_option('webcareproscan_interruption_' . $scanId, null));
        } finally {
            delete_option(ScanLock::LOCK_OPTION);
        }
    }

    public function testConcurrentlyCompletedScanIsNotOverwrittenByStaleWatchdogCas(): void
    {
        unset($GLOBALS['wp_mock_transients']);
        $scanId   = 903;
        $staleUtc = gmdate('Y-m-d H:i:s', time() - 3600);

        $initialRow = [
            'id'               => $scanId,
            'status'           => 'running',
            'generation_token' => 'tok_903',
            'scan_target'      => 'full',
            'trigger_type'     => 'manual',
            'total_files'      => 100,
            'scanned_files'    => 100,
            'issues_found'     => 0,
            'created_at'       => $staleUtc,
            'created_at_gmt'   => $staleUtc,
            'started_at'       => $staleUtc,
        ];

        $wpdbMock = new class($initialRow) extends \wpdb {
            public array $rowState;
            public int $getRowCalls = 0;
            public function __construct(array $row) {
                $this->rowState = $row;
                $this->mock_get_var_callback = static fn(string $q) => 1;
            }
            public function get_results(string $query, string $output = 'OBJECT') {
                $this->queries[] = $query;
                return str_contains($query, "status = 'running'") ? [$this->rowState] : [];
            }
            public function get_row(string $query, string $output = 'OBJECT') {
                $this->queries[] = $query;
                $this->getRowCalls++;
                if (str_contains($query, 'WHERE id =')) {
                    // Simulate another worker completing the scan right before watchdog revalidation!
                    $this->rowState['status'] = 'completed';
                    return $this->rowState;
                }
                return null;
            }
            public function query(string $query) {
                $this->queries[] = $query;
                if (str_contains($query, "status = 'interrupted'")) {
                    // Enforce SQL CAS: WHERE status = 'running' AND generation_token = '...'
                    if ($this->rowState['status'] === 'running' && str_contains($query, $this->rowState['generation_token'])) {
                        $this->rowState['status'] = 'interrupted';
                        return 1;
                    }
                    return 0;
                }
                return parent::query($query);
            }
        };
        $GLOBALS['wpdb'] = $wpdbMock;

        $resp = \WebCareProScanner\Api\Controllers\ScanController::get_active_scan(new \WP_REST_Request('GET', '/webcare-pro-security/v1/scan/active'));
        $data = $resp instanceof \WP_REST_Response ? $resp->get_data() : (array) $resp;

        $this->assertFalse($data['is_running'] ?? true);
        $this->assertSame('completed', $wpdbMock->rowState['status'], 'Concurrently completed scan must remain completed.');
        $this->assertNull(get_option('webcareproscan_interruption_' . $scanId, null), 'Must not write interruption record for completed scan.');

        // Also directly test ScanInterruptionForensics CAS guard with stale token or completed row
        $casRes = \WebCareProScanner\Scan\ScanInterruptionForensics::record($scanId, \WebCareProScanner\Scan\ScanInterruptionForensics::REASON_STALE_HEARTBEAT, [
            'expected_generation_token' => 'tok_903',
            'require_cas_transition'    => true,
        ]);
        $this->assertSame([], $casRes, 'CAS forensics transition must abort cleanly when row is no longer running.');
        $this->assertSame('completed', $wpdbMock->rowState['status']);
    }

    public function testRecoveringNewestScanDoesNotInterruptSecondaryWithinWindowRow(): void
    {
        unset($GLOBALS['wp_mock_transients']);
        $recentUtc = gmdate('Y-m-d H:i:s', time() - 30);
        set_transient('webcareproscan_scan_last_activity_905', time() - 10, 3600);
        set_transient('webcareproscan_scan_last_activity_904', time() - 20, 3600);

        $rows = [
            905 => [
                'id'               => 905,
                'status'           => 'running',
                'generation_token' => 'tok_905',
                'scan_target'      => 'full',
                'trigger_type'     => 'manual',
                'total_files'      => 100,
                'scanned_files'    => 10,
                'issues_found'     => 0,
                'created_at'       => $recentUtc,
                'created_at_gmt'   => $recentUtc,
                'started_at'       => $recentUtc,
            ],
            904 => [
                'id'               => 904,
                'status'           => 'running',
                'generation_token' => 'tok_904',
                'scan_target'      => 'full',
                'trigger_type'     => 'manual',
                'total_files'      => 100,
                'scanned_files'    => 50,
                'issues_found'     => 0,
                'created_at'       => $recentUtc,
                'created_at_gmt'   => $recentUtc,
                'started_at'       => $recentUtc,
            ],
        ];

        $wpdbMock = new class($rows) extends \wpdb {
            public array $rows;
            public function __construct(array $rows) {
                $this->rows = $rows;
                $this->mock_get_var_callback = static fn(string $q) => 1;
            }
            public function get_results(string $query, string $output = 'OBJECT') {
                $this->queries[] = $query;
                return str_contains($query, "status = 'running'") ? array_values($this->rows) : [];
            }
            public function get_row(string $query, string $output = 'OBJECT') {
                $this->queries[] = $query;
                if (preg_match('/WHERE id = (\d+)/', $query, $m) && isset($this->rows[(int) $m[1]])) {
                    return $this->rows[(int) $m[1]];
                }
                return null;
            }
        };
        $GLOBALS['wpdb'] = $wpdbMock;

        try {
            $resp = \WebCareProScanner\Api\Controllers\ScanController::get_active_scan(new \WP_REST_Request('GET', '/webcare-pro-security/v1/scan/active'));
            $data = $resp instanceof \WP_REST_Response ? $resp->get_data() : (array) $resp;

            $this->assertTrue($data['is_running'] ?? false);
            $this->assertSame(905, $data['scan_id'] ?? 0);
            $this->assertNull(get_option('webcareproscan_interruption_904', null), 'Secondary within-window scan must not be blindly interrupted just because primary scan recovered.');
        } finally {
            ScanLock::force_release();
        }
    }

    public function testWatchdogCasIdempotencyManualAbortCompatibilityAndForensicsFallback(): void
    {
        unset($GLOBALS['wp_mock_transients']);
        $staleUtc = gmdate('Y-m-d H:i:s', time() - 3600);

        $rows = [
            906 => [
                'id'               => 906,
                'status'           => 'running',
                'generation_token' => 'tok_906',
                'scan_target'      => 'full',
                'trigger_type'     => 'manual',
                'total_files'      => 100,
                'scanned_files'    => 10,
                'issues_found'     => 0,
                'created_at'       => $staleUtc,
                'created_at_gmt'   => $staleUtc,
                'started_at'       => $staleUtc,
                'duration'         => 3600,
            ],
            907 => [
                'id'               => 907,
                'status'           => 'aborted',
                'generation_token' => 'tok_907',
                'scan_target'      => 'full',
                'trigger_type'     => 'manual',
                'total_files'      => 100,
                'scanned_files'    => 40,
                'issues_found'     => 0,
                'created_at'       => $staleUtc,
                'created_at_gmt'   => $staleUtc,
                'started_at'       => $staleUtc,
                'duration'         => 120,
            ],
            908 => [
                'id'               => 908,
                'status'           => 'interrupted',
                'generation_token' => 'tok_908',
                'scan_target'      => 'full',
                'trigger_type'     => 'manual',
                'total_files'      => 200,
                'scanned_files'    => 120,
                'issues_found'     => 0,
                'created_at'       => $staleUtc,
                'created_at_gmt'   => $staleUtc,
                'started_at'       => $staleUtc,
                'duration'         => 950,
            ],
        ];

        $wpdbMock = new class($rows) extends \wpdb {
            public array $rows;
            public int $casTransitions = 0;
            public function __construct(array $rows) {
                $this->rows = $rows;
                $this->mock_get_var_callback = static fn(string $q) => 1;
            }
            public function get_row(string $query, string $output = 'OBJECT') {
                $this->queries[] = $query;
                if (preg_match('/WHERE id = (\d+)/', $query, $m) && isset($this->rows[(int) $m[1]])) {
                    return $this->rows[(int) $m[1]];
                }
                return null;
            }
            public function query(string $query) {
                $this->queries[] = $query;
                if (preg_match("/SET status = 'interrupted'.*WHERE id = (\d+) AND status = 'running' AND generation_token = '([^']+)'/s", $query, $m)) {
                    $id  = (int) $m[1];
                    $tok = $m[2];
                    if (isset($this->rows[$id]) && $this->rows[$id]['status'] === 'running' && $this->rows[$id]['generation_token'] === $tok) {
                        $this->rows[$id]['status'] = 'interrupted';
                        $this->casTransitions++;
                        return 1;
                    }
                    return 0;
                }
                return parent::query($query);
            }
        };
        $GLOBALS['wpdb'] = $wpdbMock;

        // 1. First CAS interruption succeeds once; repeated invocation on now-interrupted row is an idempotent no-op
        $first = \WebCareProScanner\Scan\ScanInterruptionForensics::record(906, \WebCareProScanner\Scan\ScanInterruptionForensics::REASON_STALE_HEARTBEAT, [
            'expected_generation_token' => 'tok_906',
            'require_cas_transition'    => true,
        ]);
        $second = \WebCareProScanner\Scan\ScanInterruptionForensics::record(906, \WebCareProScanner\Scan\ScanInterruptionForensics::REASON_STALE_HEARTBEAT, [
            'expected_generation_token' => 'tok_906',
            'require_cas_transition'    => true,
        ]);
        $this->assertSame('interrupted', $wpdbMock->rows[906]['status']);
        $this->assertNotEmpty($first);
        $this->assertSame([], $second);
        $this->assertSame(1, $wpdbMock->casTransitions);

        // 2. Manual abort compatibility: writes dossier option without overwriting DB status away from 'aborted'
        $manual = \WebCareProScanner\Scan\ScanInterruptionForensics::record(907, \WebCareProScanner\Scan\ScanInterruptionForensics::REASON_MANUAL_ABORT, [
            'last_file' => 'wp-content/index.php',
        ]);
        $this->assertSame(\WebCareProScanner\Scan\ScanInterruptionForensics::REASON_MANUAL_ABORT, $manual['reason_code'] ?? '');
        $this->assertSame('aborted', $wpdbMock->rows[907]['status']);

        // 3. Fallback retrieval in ScanInterruptionForensics::get() when stored option is absent executes with zero undefined variables
        delete_option(\WebCareProScanner\Scan\ScanInterruptionForensics::OPTION_PREFIX . 908);
        $deduced = \WebCareProScanner\Scan\ScanInterruptionForensics::get(908);
        $this->assertIsArray($deduced);
        $this->assertSame(\WebCareProScanner\Scan\ScanInterruptionForensics::REASON_STALE_HEARTBEAT, $deduced['reason_code'] ?? '');
        $this->assertSame(120, $deduced['scanned_files'] ?? 0);

        delete_option(\WebCareProScanner\Scan\ScanInterruptionForensics::OPTION_PREFIX . 906);
        delete_option(\WebCareProScanner\Scan\ScanInterruptionForensics::OPTION_PREFIX . 907);
    }
}
