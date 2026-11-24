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

    public function testOpportunisticBoundedPruningRemovesExpiredUnrelatedNoncesAndProtectsActiveNonces(): void
    {
        global $wpdb;
        $origWpdb = $wpdb ?? null;
        $mockDb = new \wpdb();
        $mockDb->options = 'wp_options';
        $GLOBALS['wpdb'] = $mockDb;

        try {
            $GLOBALS['wp_mock_options'] = [];
            AtomicNonceStore::reset_prune_throttle();
            $now = time();

            // Seed 65 expired unrelated nonce rows (exceeding PRUNE_BATCH_LIMIT = 50)
            $expiredKeys = [];
            for ($i = 0; $i < 65; $i++) {
                $k = 'wcp_nonce_' . str_pad(dechex($i + 1), 40, '0', STR_PAD_LEFT);
                $expiredKeys[] = $k;
                update_option($k, (string) ($now - 120), false);
            }

            // Seed 2 active unexpired unrelated nonce rows + 1 non-nonce option
            $activeKey1 = 'wcp_nonce_' . str_repeat('a', 40);
            $activeKey2 = 'wcp_nonce_' . str_repeat('b', 40);
            update_option($activeKey1, (string) ($now + 300), false);
            update_option($activeKey2, (string) ($now + 5), false);
            update_option('webcareproscan_unrelated_setting', '1', false);

            // Consume a fresh nonce -> triggers atomic throttle claim + bounded prune (removes at most 50 expired rows)
            $freshNonce = 'fresh_delivery_' . bin2hex(random_bytes(8));
            $freshKey = 'wcp_nonce_' . substr(hash('sha256', 'wh_github|' . $freshNonce), 0, 40);
            $this->assertTrue(AtomicNonceStore::consume('wh_github', $freshNonce, 300));

            // Newly claimed nonce + throttle row + active nonces + non-nonce option MUST remain intact
            $this->assertNotFalse(get_option($freshKey, false), 'Newly claimed nonce must never be deleted by cleanup.');
            $this->assertNotFalse(get_option(AtomicNonceStore::PRUNE_THROTTLE_KEY, false), 'Atomic prune throttle row must remain intact.');
            $this->assertNotFalse(get_option($activeKey1, false), 'Unexpired nonce #1 must remain protected.');
            $this->assertNotFalse(get_option($activeKey2, false), 'Unexpired nonce #2 must remain protected.');
            $this->assertSame('1', get_option('webcareproscan_unrelated_setting'));

            // Exactly 15 expired rows remain because batch size is capped at PRUNE_BATCH_LIMIT (50)
            $remainingExpired = 0;
            foreach ($expiredKeys as $ek) {
                if (get_option($ek, null) !== null) {
                    $remainingExpired++;
                }
            }
            $this->assertSame(15, $remainingExpired, 'Cleanup must be bounded to PRUNE_BATCH_LIMIT (50) rows per run.');

            // Immediate subsequent consume within throttle window (60s) must be rejected by atomic throttle claim and NOT run DELETE
            $queryCountBefore = count($mockDb->queries);
            $secondNonce = 'second_delivery_' . bin2hex(random_bytes(8));
            $this->assertTrue(AtomicNonceStore::consume('wh_github', $secondNonce, 300));
            $recentQueries = array_slice($mockDb->queries, $queryCountBefore);
            foreach ($recentQueries as $rq) {
                $this->assertStringNotContainsString(
                    'DELETE FROM',
                    $rq,
                    'Throttled consume must not execute DELETE when atomic 60s throttle lease is already claimed.'
                );
            }
            $remainingAfterThrottle = 0;
            foreach ($expiredKeys as $ek) {
                if (get_option($ek, null) !== null) {
                    $remainingAfterThrottle++;
                }
            }
            $this->assertSame(15, $remainingAfterThrottle, 'Throttle must skip opportunistic pruning until window expires.');

            // Once atomic throttle lease expires, next consume reclaims the throttle slot and prunes the remaining 15 expired rows
            update_option(AtomicNonceStore::PRUNE_THROTTLE_KEY, (string) ($now - 5), false);
            $thirdNonce = 'third_delivery_' . bin2hex(random_bytes(8));
            $this->assertTrue(AtomicNonceStore::consume('wh_github', $thirdNonce, 300));

            $remainingFinal = 0;
            foreach ($expiredKeys as $ek) {
                if (get_option($ek, null) !== null) {
                    $remainingFinal++;
                }
            }
            $this->assertSame(0, $remainingFinal, 'Remaining expired rows must be pruned once throttle window elapses.');
            $this->assertNotFalse(get_option($freshKey, false));
            $this->assertNotFalse(get_option($activeKey1, false));
            $this->assertNotFalse(get_option($activeKey2, false));
        } finally {
            $GLOBALS['wpdb'] = $origWpdb;
            AtomicNonceStore::reset_prune_throttle();
        }
    }

    public function testValidatedOptionsTableIdentifierEnforcesSqlAndRejectsUnsafeNames(): void
    {
        global $wpdb;
        $origWpdb = $wpdb ?? null;
        $mockDb = new \wpdb();
        $mockDb->options = 'wp_options; DROP TABLE wp_users';
        $GLOBALS['wpdb'] = $mockDb;

        try {
            $nonce = 'unsafe_tbl_' . bin2hex(random_bytes(8));
            // Unsafe $wpdb->options fails table validation and never interpolates into $mockDb->queries
            $mockDb->queries = [];
            AtomicNonceStore::consume('tbl_check', $nonce, 60);
            $this->assertSame([], $mockDb->queries, 'Unsafe $wpdb->options table name must never be interpolated into SQL.');

            // Valid table identifier executes atomic INSERT statement and enforces replay rejection
            $mockDb->options = 'wp_options';
            $validNonce = 'valid_tbl_' . bin2hex(random_bytes(8));
            $this->assertTrue(AtomicNonceStore::consume('tbl_check', $validNonce, 60));
            $this->assertFalse(AtomicNonceStore::consume('tbl_check', $validNonce, 60));
            $this->assertNotEmpty($mockDb->queries);
            $this->assertStringContainsString('INSERT INTO wp_options', $mockDb->queries[0]);
        } finally {
            $GLOBALS['wpdb'] = $origWpdb;
        }
    }
}
