<?php

declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Content\BlockDirectiveSanitizer;
use WebCareProScanner\Firewall\CAF\CloudflareSlotOptimizer;
use WebCareProScanner\System\CrashGuard;
use WebCareProScanner\System\SettingsManager;

class ChatGptReviewRegressionsTest extends TestCase
{
    public function test_block_directive_sanitizer_filter_post_content_does_not_throw_type_error(): void
    {
        if (!function_exists('wp_slash')) {
            eval('function wp_slash($value) { return is_string($value) ? addslashes($value) : $value; }');
        }
        $dirty_content = '<!-- wp:paragraph {"data-wp-interactive":"test"} --><div data-wp-on--click="actions.eval" data-wp-context=\'{"__proto__":{"polluted":true}}\'>Hello</div><!-- /wp:paragraph -->';
        $data = ['post_content' => $dirty_content, 'post_type' => 'post'];
        $postarr = ['ID' => 42];

        $filtered = BlockDirectiveSanitizer::filter_post_content_directives($data, $postarr);

        $this->assertIsArray($filtered);
        $this->assertArrayHasKey('post_content', $filtered);
        $this->assertStringNotContainsString('__proto__', $filtered['post_content']);
    }

    public function test_cloudflare_rule4_does_not_exempt_entire_asn_17012(): void
    {
        $optimizer   = new CloudflareSlotOptimizer();
        $expr_no_woo = $optimizer->compile_rule4_sqli_lfi_expression(false);
        $expr_woo    = $optimizer->compile_rule4_sqli_lfi_expression(true);

        $this->assertStringNotContainsString('ip.geoip.asnum in {17012}', $expr_no_woo);
        $this->assertStringNotContainsString('ip.geoip.asnum in {17012}', $expr_woo);
    }

    public function test_settings_defaults_include_cron_cve_audit_enabled(): void
    {
        $defaults = SettingsManager::get_defaults();
        $this->assertArrayHasKey('cron_cve_audit_enabled', $defaults);
        $this->assertTrue($defaults['cron_cve_audit_enabled']);
    }

    public function test_crash_guard_extract_code_context_redacts_multiline_pem_key(): void
    {
        $tmp_file = sys_get_temp_dir() . '/wcp_crash_pem_test_' . uniqid('', true) . '.php';
        $pem_content = "<?php\n"
            . "\$key = <<<PEM\n"
            . "-----BEGIN RSA PRIVATE KEY-----\n"
            . "MIIEowIBAAKCAQEAv7testSecretKeyMaterialLine1\n"
            . "MIIEowIBAAKCAQEAv7testSecretKeyMaterialLine2\n"
            . "-----END RSA PRIVATE KEY-----\n"
            . "PEM;\n"
            . "trigger_error('test', E_USER_ERROR);\n";
        file_put_contents($tmp_file, $pem_content);

        try {
            $ref = new \ReflectionMethod(CrashGuard::class, 'extract_code_context');
            $ref->setAccessible(true);
            $snippet = $ref->invoke(null, $tmp_file, 8);

            $this->assertIsArray($snippet);
            $joined = implode("\n", array_column($snippet, 'content'));
            $this->assertStringNotContainsString('MIIEowIBAAKCAQEAv7testSecretKeyMaterialLine1', $joined);
        } finally {
            @unlink($tmp_file);
        }
    }
}
