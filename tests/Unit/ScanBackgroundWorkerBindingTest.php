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
}
