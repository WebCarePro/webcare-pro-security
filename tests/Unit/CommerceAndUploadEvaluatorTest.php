<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Contracts\RequestContext;
use WebCareProScanner\Contracts\RouteClass;
use WebCareProScanner\Contracts\WafAction;
use WebCareProScanner\Core\CompiledStackManifest;
use WebCareProScanner\Firewall\Evaluators\CommerceAndUploadEvaluator;
use WebCareProScanner\System\SettingsManager;

final class CommerceAndUploadEvaluatorTest extends TestCase {

    private CommerceAndUploadEvaluator $evaluator;

    protected function setUp(): void {
        parent::setUp();
        $this->evaluator = new CommerceAndUploadEvaluator();
        SettingsManager::update_setting('waf_enabled', true);
        SettingsManager::update_setting('waf_block_malicious_uploads', true);
        SettingsManager::update_setting('waf_affiliate_shield_enabled', true);
        SettingsManager::update_setting('waf_affiliate_anti_injection', true);
        \wp_set_current_user(0);
    }

    public function test_forged_stripe_signature_on_login_from_untrusted_ip_blocked(): void {
        $ctx = new RequestContext(
            ip: '198.51.100.77', // Untrusted non-Stripe IP
            method: 'POST',
            uri: '/wp-login.php',
            headers: [
                'stripe-signature' => 't=1612345678,v1=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
            ]
        );

        $verdict = $this->evaluator->evaluate_runtime_request($ctx);
        $this->assertNotNull($verdict);
        $this->assertSame(WafAction::Block, $verdict->action);
        $this->assertSame(403, $verdict->statusCode);
        $this->assertSame('WAF-FORGED-WEBHOOK-TRAP', $verdict->ruleId);
    }

    public function test_empty_files_short_circuits_cleanly(): void {
        $ctx = new RequestContext(
            ip: '198.51.100.88',
            method: 'POST',
            uri: '/wp-admin/admin-ajax.php',
            files: []
        );

        $verdict = $this->evaluator->evaluate_runtime_request($ctx);
        $this->assertNull($verdict);
    }

    public function test_malicious_uploaded_php_file_blocked(): void {
        $tmp_file = tempnam(sys_get_temp_dir(), 'wc_test_up_');
        file_put_contents($tmp_file, "<?php phpinfo(); ?>");

        $ctx = new RequestContext(
            ip: '198.51.100.99',
            method: 'POST',
            uri: '/wp-admin/async-upload.php',
            files: [
                'async-upload' => [
                    'name'     => 'shell.php',
                    'type'     => 'application/x-php',
                    'tmp_name' => $tmp_file,
                    'error'    => 0,
                    'size'     => filesize($tmp_file),
                ],
            ]
        );

        try {
            $verdict = $this->evaluator->evaluate_runtime_request($ctx);
            $this->assertNotNull($verdict);
            $this->assertSame(WafAction::Block, $verdict->action);
            $this->assertSame(403, $verdict->statusCode);
        } finally {
            if (file_exists($tmp_file)) {
                @unlink($tmp_file);
            }
        }
    }

    public function test_compiled_manifest_excludes_commerce_and_upload_from_public_get(): void {
        $manifest = CompiledStackManifest::load();
        $this->assertIsArray($manifest);
        $this->assertArrayHasKey('routes', $manifest);

        $public_get_routes = $manifest['routes'][RouteClass::PublicGet->value] ?? [];
        $this->assertNotContains(
            CommerceAndUploadEvaluator::class,
            $public_get_routes,
            'CommerceAndUploadEvaluator must NOT run on RouteClass::PublicGet requests.'
        );

        $commerce_routes = $manifest['routes'][RouteClass::Commerce->value] ?? [];
        $this->assertContains(
            CommerceAndUploadEvaluator::class,
            $commerce_routes,
            'CommerceAndUploadEvaluator must be registered for RouteClass::Commerce.'
        );

        $mutation_routes = $manifest['routes'][RouteClass::PublicMutation->value] ?? [];
        $this->assertContains(
            CommerceAndUploadEvaluator::class,
            $mutation_routes,
            'CommerceAndUploadEvaluator must be registered for RouteClass::PublicMutation.'
        );
    }
}
