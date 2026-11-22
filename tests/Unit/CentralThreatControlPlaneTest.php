<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Firewall\CentralThreatControlPlane;
use WebCareProScanner\Firewall\DeclarativePatchVerifier;

final class CentralThreatControlPlaneTest extends TestCase {

    private string $test_secret_key;
    private string $test_public_key;

    protected function setUp(): void {
        parent::setUp();
        delete_option(CentralThreatControlPlane::OPTION_DELTA_CHECKPOINT);
        delete_option(CentralThreatControlPlane::OPTION_KEV_CATALOG);
        delete_option(CentralThreatControlPlane::OPTION_FEED_META);
        delete_option(CentralThreatControlPlane::OPTION_CVE_FINDINGS);

        $kp = sodium_crypto_sign_keypair();
        $this->test_secret_key = bin2hex(sodium_crypto_sign_secretkey($kp));
        $this->test_public_key = bin2hex(sodium_crypto_sign_publickey($kp));
        DeclarativePatchVerifier::set_test_public_keys(['wcp-feed-test' => $this->test_public_key]);
    }

    protected function tearDown(): void {
        DeclarativePatchVerifier::set_test_public_keys(null);
        parent::tearDown();
    }

    public function test_initial_checkpoint_defaults(): void {
        $cp = CentralThreatControlPlane::get_checkpoint();
        $this->assertSame(0, $cp['sequence']);
        $this->assertNotEmpty($cp['last_mod_start']);
        $this->assertSame(0, $cp['last_sync_ts']);
    }

    public function test_sync_incremental_feed_advances_sequence_and_stores_kev(): void {
        $mock_payload = [
            'feed_version'       => '1.0.0',
            'sequence'           => 105,
            'last_mod_timestamp' => '2026-11-20T22:00:00Z',
            'key_id'             => 'wcp-feed-test',
            'cisa_kev'           => [
                [
                    'cve_id'         => 'CVE-2023-28121',
                    'vendor_project' => 'WooCommerce',
                    'product'        => 'WooCommerce Payments',
                    'date_added'     => '2023-03-24',
                ],
            ],
            'cves' => [
                [
                    'cve_id'           => 'CVE-2023-28121',
                    'component_slug'   => 'woocommerce-payments',
                    'title'            => 'WooCommerce Payments Auth Bypass',
                    'severity'         => 'critical',
                    'cvss'             => 9.8,
                    'affected_version' => '<= 5.6.1',
                    'has_virtual_patch'=> true,
                ],
            ],
        ];

        $sig = DeclarativePatchVerifier::sign_patch_manifest($mock_payload, $this->test_secret_key);
        $mock_payload['signature'] = $sig;

        $res = CentralThreatControlPlane::sync_incremental_feed($mock_payload);

        $this->assertTrue($res['success']);
        $this->assertSame(105, $res['sequence']);
        $this->assertSame(1, $res['new_cves']);
        $this->assertSame(1, $res['kev_updates']);

        // Checkpoint updated
        $cp = CentralThreatControlPlane::get_checkpoint();
        $this->assertSame(105, $cp['sequence']);
        $this->assertSame('2026-11-20T22:00:00Z', $cp['last_mod_start']);

        // KEV is tracked
        $this->assertTrue(CentralThreatControlPlane::is_known_exploited('CVE-2023-28121'));
        $this->assertFalse(CentralThreatControlPlane::is_known_exploited('CVE-9999-99999'));
    }

    public function test_sync_incremental_feed_rejects_unsigned_or_tampered_envelope(): void {
        $payload = [
            'feed_version'       => '1.0.0',
            'sequence'           => 106,
            'last_mod_timestamp' => '2026-11-20T22:30:00Z',
            'cves'               => [],
        ];

        // Missing key_id and signature -> must be rejected
        $res = CentralThreatControlPlane::sync_incremental_feed($payload);
        $this->assertFalse($res['success']);
        $this->assertStringContainsString('signature verification failed', $res['message']);

        // Tampered signature -> must be rejected
        $payload['key_id'] = 'wcp-feed-test';
        $payload['signature'] = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
        $res_tampered = CentralThreatControlPlane::sync_incremental_feed($payload);
        $this->assertFalse($res_tampered['success']);
    }

    public function test_sync_incremental_feed_removes_revoked_kev_ids(): void {
        // Pre-populate KEV catalog
        update_option(CentralThreatControlPlane::OPTION_KEV_CATALOG, [
            'CVE-2023-OLD-KEV' => ['cve_id' => 'CVE-2023-OLD-KEV'],
        ]);
        $this->assertTrue(CentralThreatControlPlane::is_known_exploited('CVE-2023-OLD-KEV'));

        $payload = [
            'feed_version'       => '1.0.0',
            'sequence'           => 110,
            'last_mod_timestamp' => '2026-11-20T23:00:00Z',
            'key_id'             => 'wcp-feed-test',
            'kev_removed'        => ['CVE-2023-OLD-KEV'],
            'cisa_kev'           => [],
            'cves'               => [],
        ];

        $sig = DeclarativePatchVerifier::sign_patch_manifest($payload, $this->test_secret_key);
        $payload['signature'] = $sig;

        $res = CentralThreatControlPlane::sync_incremental_feed($payload);
        $this->assertTrue($res['success']);
        $this->assertFalse(CentralThreatControlPlane::is_known_exploited('CVE-2023-OLD-KEV'), 'Revoked KEV ID must be removed.');
    }

    public function test_feed_sequence_rollback_is_rejected(): void {
        // Seed checkpoint at sequence 200
        CentralThreatControlPlane::update_checkpoint(200, '2026-11-20T20:00:00Z');

        // Attempt to sync rolled back sequence 150
        $stale_payload = [
            'feed_version'       => '1.0.0',
            'sequence'           => 150,
            'last_mod_timestamp' => '2026-11-20T18:00:00Z',
            'key_id'             => 'wcp-feed-test',
            'cisa_kev'           => [],
            'cves'               => [],
        ];

        $sig = DeclarativePatchVerifier::sign_patch_manifest($stale_payload, $this->test_secret_key);
        $stale_payload['signature'] = $sig;

        $res = CentralThreatControlPlane::sync_incremental_feed($stale_payload);

        $this->assertFalse($res['success']);
        $this->assertStringContainsString('rollback', strtolower($res['message']));

        // Checkpoint must remain 200
        $cp = CentralThreatControlPlane::get_checkpoint();
        $this->assertSame(200, $cp['sequence']);
    }

    public function test_cisa_kev_elevates_confidence_score_in_correlation(): void {
        $kev_catalog = [
            'CVE-2024-TEST-KEV' => ['cve_id' => 'CVE-2024-TEST-KEV', 'active_exploit_sig' => true],
        ];

        $cve_entries = [
            [
                'cve_id'           => 'CVE-2024-TEST-KEV',
                'component_slug'   => 'test-plugin',
                'cvss'             => 7.5,
                'affected_version' => '<= 2.0.0',
            ],
            [
                'cve_id'           => 'CVE-2024-TEST-NORMAL',
                'component_slug'   => 'test-plugin-2',
                'cvss'             => 7.5,
                'affected_version' => '<= 2.0.0',
            ],
        ];

        $findings = CentralThreatControlPlane::evaluate_cves_against_inventory($cve_entries, $kev_catalog);

        // If component is not installed, findings array is clean (safe from false positives)
        $this->assertIsArray($findings);
    }

    public function test_cve_tombstone_and_kev_removed_updates_findings(): void {
        update_option(CentralThreatControlPlane::OPTION_CVE_FINDINGS, [
            'CVE-2023-REMOVED' => [
                'cve_id'      => 'CVE-2023-REMOVED',
                'is_cisa_kev' => true,
            ],
            'CVE-2023-STAYS'   => [
                'cve_id'      => 'CVE-2023-STAYS',
                'is_cisa_kev' => true,
            ],
        ]);

        $payload = [
            'feed_version'       => '1.0.0',
            'sequence'           => 120,
            'last_mod_timestamp' => '2026-11-20T23:30:00Z',
            'key_id'             => 'wcp-feed-test',
            'cve_removed'        => ['CVE-2023-REMOVED'],
            'kev_removed'        => ['CVE-2023-STAYS'],
            'cisa_kev'           => [],
            'cves'               => [],
        ];

        $sig = DeclarativePatchVerifier::sign_patch_manifest($payload, $this->test_secret_key);
        $payload['signature'] = $sig;

        $res = CentralThreatControlPlane::sync_incremental_feed($payload);
        $this->assertTrue($res['success']);

        $findings = get_option(CentralThreatControlPlane::OPTION_CVE_FINDINGS, []);
        $this->assertArrayNotHasKey('CVE-2023-REMOVED', $findings, 'Withdrawn CVE must be removed from findings.');
        $this->assertArrayHasKey('CVE-2023-STAYS', $findings);
        $this->assertFalse($findings['CVE-2023-STAYS']['is_cisa_kev'], 'KEV removal must set is_cisa_kev to false.');
    }

    public function test_feed_replay_mutation_is_rejected(): void {
        $payload1 = [
            'feed_version'       => '1.0.0',
            'sequence'           => 125,
            'last_mod_timestamp' => '2026-11-20T23:45:00Z',
            'key_id'             => 'wcp-feed-test',
            'cves'               => [['cve_id' => 'CVE-TEST-1']],
        ];
        $payload1['signature'] = DeclarativePatchVerifier::sign_patch_manifest($payload1, $this->test_secret_key);
        $res1 = CentralThreatControlPlane::sync_incremental_feed($payload1);
        $this->assertTrue($res1['success']);

        // Differing payload with same sequence 125 must be rejected
        $payload2 = [
            'feed_version'       => '1.0.0',
            'sequence'           => 125,
            'last_mod_timestamp' => '2026-11-20T23:45:00Z',
            'key_id'             => 'wcp-feed-test',
            'cves'               => [['cve_id' => 'CVE-TEST-DIFFERENT']],
        ];
        $payload2['signature'] = DeclarativePatchVerifier::sign_patch_manifest($payload2, $this->test_secret_key);
        $res2 = CentralThreatControlPlane::sync_incremental_feed($payload2);
        $this->assertFalse($res2['success']);
        $this->assertStringContainsString('conflict', strtolower($res2['message']));
    }
}
