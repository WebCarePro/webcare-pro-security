<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use WebCareProScanner\Security\AtomicNonceStore;

/**
 * AtomicNonceStoreTest
 *
 * Verifies single-use consumption, SHA-256 key derivation, replay rejection,
 * strict TTL bounds validation/clamping, and atomic single-statement DB fallback.
 */
final class AtomicNonceStoreTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        if (function_exists('wp_cache_flush')) {
            wp_cache_flush();
        }
        $GLOBALS['wp_mock_object_cache'] = [];
        wp_using_ext_object_cache(false);
    }

    protected function tearDown(): void
    {
        if (function_exists('wp_cache_flush')) {
            wp_cache_flush();
        }
        $GLOBALS['wp_mock_object_cache'] = [];
        wp_using_ext_object_cache(false);
        parent::tearDown();
    }

    public function testConsumeSucceedsOnceAndRejectsReplay(): void
    {
        $nonce = bin2hex(random_bytes(16));
        $namespace = 'test_loopback';

        // First consume should succeed
        $first = AtomicNonceStore::consume($namespace, $nonce, 60);
        $this->assertTrue($first, 'First nonce consume attempt must succeed.');

        // Second consume with exact same nonce must fail (replay rejected)
        $second = AtomicNonceStore::consume($namespace, $nonce, 60);
        $this->assertFalse($second, 'Second nonce consume attempt must be rejected as replayed.');

        // Different namespace with same nonce is considered isolated
        $diffNamespace = AtomicNonceStore::consume('other_ns', $nonce, 60);
        $this->assertTrue($diffNamespace, 'Different namespace should have its own isolated key.');

        // Empty nonce must always return false
        $this->assertFalse(AtomicNonceStore::consume($namespace, '', 60));
    }

    public function testKeyDerivationUsesSha256(): void
    {
        $namespace = 'test_sha256';
        $nonce = 'nonce_value_123';
        $expectedHash = substr(hash('sha256', $namespace . '|' . $nonce), 0, 40);
        $expectedKey = 'wcp_nonce_' . $expectedHash;

        global $wpdb;
        if ($wpdb instanceof \wpdb && !empty($wpdb->options)) {
            AtomicNonceStore::consume($namespace, $nonce, 60);
            $lastQuery = end($wpdb->queries) ?: '';
            $this->assertStringContainsString($expectedKey, $lastQuery);
        } else {
            AtomicNonceStore::consume($namespace, $nonce, 60);
            $this->assertNotEmpty(get_option($expectedKey));
        }
    }

    public function testExpiredNonceCanBeReclaimed(): void
    {
        $namespace = 'test_expire';
        $nonce = bin2hex(random_bytes(16));
        $key = 'wcp_nonce_' . substr(hash('sha256', $namespace . '|' . $nonce), 0, 40);

        // Pre-insert an expired record (expired 10 seconds ago)
        update_option($key, (string) (time() - 10), false);

        // Consuming now should reclaim the expired row
        $claimed = AtomicNonceStore::consume($namespace, $nonce, 60);
        $this->assertTrue($claimed, 'An expired nonce must be atomically reclaimable.');

        // Consuming again immediately must fail
        $replayed = AtomicNonceStore::consume($namespace, $nonce, 60);
        $this->assertFalse($replayed, 'Unexpired claimed nonce must reject replay.');
    }

    public function testZeroTtlThrowsInvalidArgumentException(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('AtomicNonceStore TTL must be a positive integer.');
        AtomicNonceStore::consume('ttl_test', 'nonce_zero', 0);
    }

    public function testNegativeTtlThrowsInvalidArgumentException(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('AtomicNonceStore TTL must be a positive integer.');
        AtomicNonceStore::consume('ttl_test', 'nonce_negative', -10);
    }

    public function testExcessiveAndTinyPositiveTtlsAreClampedToBounds(): void
    {
        $now = time();

        // Excessive TTL (999999) clamped to MAX_TTL (86400)
        $nonceMax = 'nonce_clamp_max_' . bin2hex(random_bytes(8));
        $keyMax = 'wcp_nonce_' . substr(hash('sha256', 'ttl_clamp|' . $nonceMax), 0, 40);
        $this->assertTrue(AtomicNonceStore::consume('ttl_clamp', $nonceMax, 999999));

        $storedMaxExpires = (int) get_option($keyMax);
        $this->assertGreaterThanOrEqual($now + AtomicNonceStore::MAX_TTL - 1, $storedMaxExpires);
        $this->assertLessThanOrEqual(time() + AtomicNonceStore::MAX_TTL + 2, $storedMaxExpires);

        // Tiny positive TTL (1) clamped to MIN_TTL (5)
        $nonceMin = 'nonce_clamp_min_' . bin2hex(random_bytes(8));
        $keyMin = 'wcp_nonce_' . substr(hash('sha256', 'ttl_clamp|' . $nonceMin), 0, 40);
        $this->assertTrue(AtomicNonceStore::consume('ttl_clamp', $nonceMin, 1));

        $storedMinExpires = (int) get_option($keyMin);
        $this->assertGreaterThanOrEqual($now + AtomicNonceStore::MIN_TTL - 1, $storedMinExpires);
        $this->assertLessThanOrEqual(time() + AtomicNonceStore::MIN_TTL + 2, $storedMinExpires);
    }
}
