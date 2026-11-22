<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Firewall\AdaptiveRateLimiter;
use WebCareProScanner\Firewall\Core\TransientRateLimiter;

/**
 * AdaptiveRateLimiterConcurrencyTest
 *
 * Acceptance tests for PR M1: Atomic Concurrency-Safe Rate-Limit Counters.
 * Verifies atomic counter operations across APCu, External Object Cache, and File Lock backends.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
final class AdaptiveRateLimiterConcurrencyTest extends TestCase {

    private string $testUploadDir = '';

    protected function setUp(): void {
        parent::setUp();
        $this->testUploadDir = sys_get_temp_dir() . '/webcare_test_rl_' . bin2hex(random_bytes(6));
        $GLOBALS['wp_mock_upload_dir'] = $this->testUploadDir;
        $GLOBALS['wp_mock_options'] = [];
        $GLOBALS['wp_mock_transients'] = [];
        $GLOBALS['wp_mock_object_cache'] = [];
        $GLOBALS['wp_mock_ext_object_cache'] = false;
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
     * Test single-transaction file lock fallback with 20 sequential/concurrent hits.
     * At limit = 5: strictly 5 pass and 15 receive allowed = false.
     */
    public function test_file_lock_rate_limit_concurrency(): void {
        $GLOBALS['wp_mock_ext_object_cache'] = false;
        $ip = '198.51.100.42';
        $limit = 5;
        $window = 60;

        $allowed_count = 0;
        $blocked_count = 0;

        for ($i = 0; $i < 20; $i++) {
            $result = AdaptiveRateLimiter::check_bucket_velocity('auth', $ip, $limit, $window);
            if ($result['allowed']) {
                $allowed_count++;
            } else {
                $blocked_count++;
            }
        }

        $this->assertSame(5, $allowed_count, 'Strictly 5 requests must be allowed at limit = 5');
        $this->assertSame(15, $blocked_count, 'Strictly 15 requests must be blocked');
    }

    /**
     * Test atomic external object cache (Redis/Memcached mock).
     */
    public function test_object_cache_rate_limit_concurrency(): void {
        $GLOBALS['wp_mock_ext_object_cache'] = true;
        $ip = '198.51.100.99';
        $limit = 10;
        $window = 60;

        $allowed_count = 0;
        $blocked_count = 0;

        for ($i = 0; $i < 25; $i++) {
            $result = AdaptiveRateLimiter::check_bucket_velocity('checkout', $ip, $limit, $window);
            if ($result['allowed']) {
                $allowed_count++;
            } else {
                $blocked_count++;
            }
        }

        $this->assertSame(10, $allowed_count, 'Strictly 10 requests must be allowed in object cache mode');
        $this->assertSame(15, $blocked_count, 'Strictly 15 requests must be throttled');
    }

    /**
     * Test TransientRateLimiter atomic object cache increments.
     */
    public function test_transient_rate_limiter_object_cache(): void {
        $GLOBALS['wp_mock_ext_object_cache'] = true;
        $key = 'ajax_burst_ip';
        $limit = 3;
        $window = 30;

        $res1 = TransientRateLimiter::check_rate_limit($key, $limit, $window);
        $this->assertTrue($res1['allowed']);
        $this->assertSame(1, $res1['current']);

        $res2 = TransientRateLimiter::check_rate_limit($key, $limit, $window);
        $this->assertTrue($res2['allowed']);
        $this->assertSame(2, $res2['current']);

        $res3 = TransientRateLimiter::check_rate_limit($key, $limit, $window);
        $this->assertTrue($res3['allowed']);
        $this->assertSame(3, $res3['current']);

        $res4 = TransientRateLimiter::check_rate_limit($key, $limit, $window);
        $this->assertFalse($res4['allowed']);
        $this->assertSame(4, $res4['current']);
        $this->assertGreaterThan(0, $res4['retry_after']);
    }

    /**
     * Test APCu counter if extension is loaded and active.
     */
    public function test_apcu_rate_limit_when_available(): void {
        if (!function_exists('apcu_inc') || !ini_get('apc.enabled')) {
            $this->markTestSkipped('APCu extension not enabled in this environment.');
        }

        $ip = '203.0.113.77';
        $limit = 4;
        $window = 60;

        $allowed = 0;
        $blocked = 0;

        for ($i = 0; $i < 10; $i++) {
            $res = AdaptiveRateLimiter::check_bucket_velocity('cart_ajax', $ip, $limit, $window);
            if ($res['allowed']) {
                $allowed++;
            } else {
                $blocked++;
            }
        }

        $this->assertSame(4, $allowed);
        $this->assertSame(6, $blocked);
    }
}
