<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Firewall\MicroWafCompiler;

class MicroWafCompilerTest extends TestCase {

    protected function setUp(): void {
        parent::setUp();
        $GLOBALS['wp_mock_options'] = [];
        $dir = MicroWafCompiler::get_compiled_dir();
        if (is_dir($dir)) {
            foreach (glob($dir . '/*') ?: [] as $file) {
                @unlink($file);
            }
            @rmdir($dir);
        }
    }

    public function testAssertStrictlyDataTokensAcceptsPureDataArrays(): void {
        $validCode = "<?php\n// Auto-generated\nreturn array(\n  'version' => '2.18.0',\n  'enabled' => true,\n  'count' => 42,\n  'ratio' => 1.5,\n  'empty' => null,\n);\n";

        $this->assertTrue(
            MicroWafCompiler::assert_strictly_data_tokens($validCode),
            'Pure PHP literal arrays and scalar constants must pass AST token validation.'
        );
    }

    public function testAssertStrictlyDataTokensBlocksFunctionCallsAndVariables(): void {
        $maliciousPayloads = [
            "<?php return array('cmd' => system('id'));",
            "<?php return array('exec' => \$_GET['x']);",
            "<?php eval('echo 1;'); return array();",
            "<?php return array('fn' => phpinfo());",
            "<?php return array('backtick' => `whoami`);",
            "<?php return array('const' => ABSPATH);",
        ];

        foreach ($maliciousPayloads as $payload) {
            $this->assertFalse(
                MicroWafCompiler::assert_strictly_data_tokens($payload),
                "AST validator failed to reject dangerous payload: {$payload}"
            );
        }
    }

    public function testCompileCreatesHardenedDirectoryIndexAndHtaccess(): void {
        $result = MicroWafCompiler::compile();

        $this->assertTrue($result['success'], 'MicroWafCompiler::compile() should succeed.');

        $dir = MicroWafCompiler::get_compiled_dir();
        $indexFile = $dir . '/index.php';
        $htaccessFile = $dir . '/.htaccess';
        $compiledFile = MicroWafCompiler::get_compiled_file_path();

        $this->assertFileExists($indexFile, 'Directory must contain silent index.php.');
        $this->assertFileExists($htaccessFile, 'Directory must contain .htaccess access restriction.');
        $this->assertFileExists($compiledFile, 'Compiled micro-waf script must exist.');

        $htaccessContent = file_get_contents($htaccessFile);
        $this->assertStringContainsString('Deny from all', (string) $htaccessContent);
        $this->assertStringContainsString('Require all denied', (string) $htaccessContent);
    }

    public function testCompileCafDataArtifactWritesValidHmacAndSignature(): void {
        $ok = MicroWafCompiler::compile_caf_data_artifact();
        $this->assertTrue($ok, 'CAF data artifact compilation must succeed.');

        $cafFile = MicroWafCompiler::get_caf_compiled_file_path();
        $sigFile = MicroWafCompiler::get_caf_compiled_sig_path();

        $this->assertFileExists($cafFile, 'CAF compiled rules file must exist.');
        $this->assertFileExists($sigFile, 'Detached HMAC signature file must exist.');

        $code = (string) file_get_contents($cafFile);
        $sig  = (string) include $sigFile;

        $expectedHmac = hash_hmac('sha256', $code, MicroWafCompiler::get_caf_auth_key());
        $this->assertSame($expectedHmac, $sig, 'Detached .sig.php file must match HMAC-SHA256 of compiled CAF artifact.');
        $this->assertSame($expectedHmac, get_option(MicroWafCompiler::OPTION_CAF_HMAC), 'Stored option HMAC must match.');

        $loadedData = include $cafFile;
        $this->assertIsArray($loadedData);
        $this->assertArrayHasKey('active_rest_namespaces', $loadedData);
        $this->assertContains('webcare-pro-security/v1', $loadedData['active_rest_namespaces']);
    }

    public function testCompiledStandaloneScriptSyntaxIsValid(): void {
        MicroWafCompiler::compile();
        $compiledFile = MicroWafCompiler::get_compiled_file_path();

        $content = (string) file_get_contents($compiledFile);
        $this->assertStringStartsWith('<?php', $content);
        $this->assertStringContainsString('WEBCAREPRO_PRELOAD_WAF_ACTIVE', $content);
        $this->assertStringContainsString('SQLI-CORE', $content);
        $this->assertStringContainsString('RCE-EXEC', $content);
        $this->assertStringContainsString('LFI-PATH', $content);
    }

    /**
     * Requirement: Compiled Micro-WAF gates HTTP_CF_CONNECTING_IP behind explicit cloudflare_enabled setting.
     */
    public function testCompiledMicroWafGatesCfConnectingIpBehindCloudflareEnabled(): void {
        // 1. Compile with cloudflare_enabled = false
        $GLOBALS['wp_mock_options']['webcareproscan_settings'] = [
            'waf_enabled'        => true,
            'cloudflare_enabled' => false,
        ];
        MicroWafCompiler::compile();
        $compiledFile = MicroWafCompiler::get_compiled_file_path();
        $content = (string) file_get_contents($compiledFile);

        $this->assertStringContainsString('$cf_enabled = false;', $content);
        $this->assertStringContainsString('if ($cf_enabled && $is_cf_ip && isset($_SERVER[\'HTTP_CF_CONNECTING_IP\'])', $content);

        // 2. Compile with cloudflare_enabled = true
        $GLOBALS['wp_mock_options']['webcareproscan_settings'] = [
            'waf_enabled'        => true,
            'cloudflare_enabled' => true,
        ];
        MicroWafCompiler::compile();
        $contentTrue = (string) file_get_contents($compiledFile);
        $this->assertStringContainsString('$cf_enabled = true;', $contentTrue);
    }
}
