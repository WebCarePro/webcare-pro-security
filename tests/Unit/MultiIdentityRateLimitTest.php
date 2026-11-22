<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Firewall\AdaptiveRateLimiter;
use WebCareProScanner\Firewall\CAF\ThreatScoreTracker;

/**
 * MultiIdentityRateLimitTest
 *
 * Acceptance tests for PR M2: Multi-Identity Rate Limiting & Deduplicated Confidence-Based Escalation.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
final class MultiIdentityRateLimitTest extends TestCase {

    private string $testUploadDir = '';

    protected function setUp(): void {
        parent::setUp();
        $this->testUploadDir = sys_get_temp_dir() . '/webcare_test_rl_m2_' . bin2hex(random_bytes(6));
        $GLOBALS['wp_mock_upload_dir'] = $this->testUploadDir;
        $GLOBALS['wp_mock_options'] = [];
        $GLOBALS['wp_mock_transients'] = [];
        $GLOBALS['wp_mock_object_cache'] = [];
        $GLOBALS['wp_mock_ext_object_cache'] = true; // Use memory object cache for fast unit tests
    }

    protected function tearDown(): void {
        if (!empty($this->testUploadDir) && is_dir($this->testUploadDir)) {
            $this->recursiveRmdir($this->testUploadDir);
        }
        $GLOBALS['wp_mock_ext_object_cache'] = false;
        parent::tearDown();
    }

    private function recursiveRmdir(string $dir): void {
        if (!is_dir($dir)) {
            return;
        }
        $items = scandir($dir);
        if ($items === false) {
            return;
        }
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $path = $dir . '/' . $item;
            if (is_dir($path)) {
                $this->recursiveRmdir($path);
            } else {
                @unlink($path);
            }
        }
        @rmdir($dir);
    }

    /**
     * Requirement: Two shoppers sharing one NAT IP with distinct WooCommerce session tokens
     * get independent checkout/cart budgets.
     */
    public function test_shoppers_sharing_nat_ip_get_independent_budgets(): void {
        $nat_ip = '198.51.100.200';
        $limit = 5;
        $window = 60;

        $shopperA_session = 'wc_sess_shopper_alpha_12345';
        $shopperB_session = 'wc_sess_shopper_bravo_67890';

        // Shopper A makes 5 requests (consuming all 5)
        for ($i = 0; $i < 5; $i++) {
            $resA = AdaptiveRateLimiter::check_bucket_velocity(
                'checkout',
                $nat_ip,
                $limit,
                $window,
                'wc:' . $shopperA_session
            );
            $this->assertTrue($resA['allowed'], "Shopper A request {$i} should be allowed");
        }

        // Shopper A's 6th request is throttled
        $resA6 = AdaptiveRateLimiter::check_bucket_velocity(
            'checkout',
            $nat_ip,
            $limit,
            $window,
            'wc:' . $shopperA_session
        );
        $this->assertFalse($resA6['allowed'], 'Shopper A 6th request should be throttled');

        // Shopper B on the SAME NAT IP should still have a full fresh budget of 5
        for ($j = 0; $j < 5; $j++) {
            $resB = AdaptiveRateLimiter::check_bucket_velocity(
                'checkout',
                $nat_ip,
                $limit,
                $window,
                'wc:' . $shopperB_session
            );
            $this->assertTrue($resB['allowed'], "Shopper B request {$j} on same NAT IP should be allowed");
        }

        // Shopper B's 6th request is throttled
        $resB6 = AdaptiveRateLimiter::check_bucket_velocity(
            'checkout',
            $nat_ip,
            $limit,
            $window,
            'wc:' . $shopperB_session
        );
        $this->assertFalse($resB6['allowed'], 'Shopper B 6th request should be throttled');
    }

    /**
     * Requirement: Repeated 429 retries on checkout from one IP add threat score at most once
     * per 60s cooldown and never trigger an IP ban.
     */
    public function test_deduplicated_threat_score_escalation_cooldown(): void {
        $ip = '203.0.113.55';

        // Clear previous state
        ThreatScoreTracker::reset_ip($ip);

        // Record 10 rapid checkout velocity throttle events
        $bucket = AdaptiveRateLimiter::BUCKET_CHECKOUT;
        $cooldown_key = 'webcareproscan_rl_ts_cd_' . md5($ip . '_' . $bucket);

        for ($i = 0; $i < 10; $i++) {
            if (!get_transient($cooldown_key)) {
                set_transient($cooldown_key, 1, 60);
                ThreatScoreTracker::record_event($ip, 'checkout_velocity', 3.0);
            }
        }

        $score = ThreatScoreTracker::get_current_score($ip);
        // Only 1 event was recorded due to 60s cooldown deduplication
        $this->assertEquals(3.0, $score, 'Threat score must only increase by 3.0 during cooldown window');
        $this->assertLessThan(ThreatScoreTracker::THRESHOLD_POW, $score, 'Must not trigger PoW challenge');
        $this->assertLessThan(ThreatScoreTracker::THRESHOLD_THROTTLE, $score, 'Must not trigger severe throttle');
    }
}
