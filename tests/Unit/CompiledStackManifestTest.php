<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Contracts\RouteClass;
use WebCareProScanner\Contracts\SiteArchetype;
use WebCareProScanner\Core\CompiledStackManifest;
use WebCareProScanner\Core\PolicyManager;
use WebCareProScanner\Core\RouteClassifier;

class CompiledStackManifestTest extends TestCase {

    public function testRouteClassifierDeterminism(): void {
        $serverPublic = ['REQUEST_URI' => '/hello-world/', 'REQUEST_METHOD' => 'GET'];
        $this->assertSame(RouteClass::PublicGet, RouteClassifier::classify($serverPublic));

        $serverCommerce = ['REQUEST_URI' => '/checkout/', 'REQUEST_METHOD' => 'POST'];
        $this->assertSame(RouteClass::Commerce, RouteClassifier::classify($serverCommerce));

        // Trailing-slash normalization (R-02)
        $serverCommerceNoSlash = ['REQUEST_URI' => '/checkout', 'REQUEST_METHOD' => 'GET'];
        $this->assertSame(RouteClass::Commerce, RouteClassifier::classify($serverCommerceNoSlash));

        $serverLogin = ['REQUEST_URI' => '/wp-login.php', 'REQUEST_METHOD' => 'POST'];
        $this->assertSame(RouteClass::AuthLogin, RouteClassifier::classify($serverLogin));

        $serverRest = ['REQUEST_URI' => '/wp-json/wp/v2/posts', 'REQUEST_METHOD' => 'GET'];
        $this->assertSame(RouteClass::RestApi, RouteClassifier::classify($serverRest));

        $serverAjax = ['REQUEST_URI' => '/wp-admin/admin-ajax.php', 'REQUEST_METHOD' => 'POST'];
        $this->assertSame(RouteClass::AdminAjax, RouteClassifier::classify($serverAjax));

        $serverAdmin = ['REQUEST_URI' => '/wp-admin/options-general.php', 'REQUEST_METHOD' => 'GET'];
        $this->assertSame(RouteClass::AdminUi, RouteClassifier::classify($serverAdmin));

        // Membership routes (R-02)
        $serverMembership = ['REQUEST_URI' => '/my-account', 'REQUEST_METHOD' => 'GET'];
        $this->assertSame(RouteClass::Membership, RouteClassifier::classify($serverMembership));
    }

    public function testRouteClassifierRestParityAndDecoding(): void {
        // Percent-encoded /%77p-json/ must be decoded and classified as RestApi
        $serverEncoded = ['REQUEST_URI' => '/%77p-json/wp/v2/users', 'REQUEST_METHOD' => 'GET'];
        $this->assertSame(RouteClass::RestApi, RouteClassifier::classify($serverEncoded));

        // ?rest_route=/... must be classified as RestApi even without $_GET populated
        $serverQuery = ['REQUEST_URI' => '/?rest_route=/wp/v2/users', 'REQUEST_METHOD' => 'GET'];
        $this->assertSame(RouteClass::RestApi, RouteClassifier::classify($serverQuery));

        // ?wc-ajax= must be classified as Commerce even without $_GET populated
        $serverWcAjax = ['REQUEST_URI' => '/?wc-ajax=get_refreshed_fragments', 'REQUEST_METHOD' => 'POST'];
        $this->assertSame(RouteClass::Commerce, RouteClassifier::classify($serverWcAjax));
    }

    public function testManifestCompilationProducesValidArray(): void {
        $result = CompiledStackManifest::compile();
        $this->assertTrue($result['success']);
        $this->assertFileExists($result['path']);

        $manifest = CompiledStackManifest::load();
        $this->assertIsArray($manifest);
        $this->assertArrayHasKey('archetype', $manifest);
        $this->assertArrayHasKey('ecosystems', $manifest);
        $this->assertArrayHasKey('routes', $manifest);
        $this->assertNotEmpty($manifest['routes']['public_get']);
        $this->assertNotEmpty($manifest['routes']['graphql']);
        $this->assertNotEmpty($manifest['routes']['membership']);
        $this->assertArrayHasKey('commerce_slugs', $manifest);
        $this->assertArrayHasKey('membership_slugs', $manifest);

        // Test in-memory request cache (R-03)
        $manifest2 = CompiledStackManifest::load();
        $this->assertSame($manifest, $manifest2);
    }

    public function testStaleManifestAutoHealsOnLoad(): void {
        // Compile fresh manifest
        CompiledStackManifest::compile();
        $manifestPath = CompiledStackManifest::get_manifest_path();
        $this->assertFileExists($manifestPath);

        // Load and alter required_evaluators_hash on disk to simulate a stale manifest
        $manifestData = include $manifestPath;
        $this->assertIsArray($manifestData);
        $manifestData['required_evaluators_hash'] = 'stale_hash_from_previous_version';

        $export = var_export($manifestData, true);
        $staleContent = "<?php\ndefined('ABSPATH') || exit;\nreturn " . $export . ";\n";
        file_put_contents($manifestPath, $staleContent, LOCK_EX);

        // Update stored HMAC to match the stale content so HMAC check passes
        $secretKey = \WebCareProScanner\Security\SecretVault::get_key();
        $staleHmac = hash_hmac('sha256', $staleContent, $secretKey);
        update_option(CompiledStackManifest::OPTION_MANIFEST_HMAC, $staleHmac, false);

        // Clear in-memory cache via reflection to force load() to read from disk
        $refCache = new \ReflectionProperty(CompiledStackManifest::class, 'request_cache');
        $refCache->setValue(null, null);

        $refRecomp = new \ReflectionProperty(CompiledStackManifest::class, 'recompiled_this_request');
        $refRecomp->setValue(null, false);

        // load() should detect stale hash, auto-recompile, and return healed manifest
        $healedManifest = CompiledStackManifest::load();
        $this->assertIsArray($healedManifest);
        $expectedHash = hash('sha256', implode('|', array_keys(CompiledStackManifest::EXPECTED_REQUIRED_EVALUATORS)));
        $this->assertSame($expectedHash, $healedManifest['required_evaluators_hash']);
        $this->assertNotSame('stale_hash_from_previous_version', $healedManifest['required_evaluators_hash']);
    }

    public function testPolicyManagerPathResolution(): void {
        $path = PolicyManager::get_policy_file_path();
        $this->assertStringEndsWith('webcare-policy.php', $path);
    }
}
