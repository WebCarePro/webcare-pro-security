<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Firewall\MicroWafCompiler;

final class MicroWafPreloadBodyTest extends TestCase
{
    public function testCompilerEmitsPreloadBodyBudgetAndDirectScriptTargeting(): void
    {
        $result = MicroWafCompiler::compile();
        $this->assertTrue($result['success'] ?? false);

        $compiledPath = MicroWafCompiler::get_compiled_file_path();
        $this->assertFileExists($compiledPath);

        $phpCode = (string) file_get_contents($compiledPath);

        $this->assertStringContainsString('$preload_body_budget = 65536;', $phpCode);
        $this->assertStringContainsString('$preload_body_truncated = false;', $phpCode);
        $this->assertStringContainsString('$is_direct_script_target =', $phpCode);
        $this->assertStringContainsString('$auth_bypass_body = $is_direct_script_target ? $mod_is_admin_user : $mod_has_login_cookie;', $phpCode);
        $this->assertStringContainsString("webcare_micro_waf_block(\$ip, 'PRELOAD-BODY-TRUNCATED'", $phpCode);
        $this->assertStringContainsString('application/(?:[a-z0-9.+-]+\\+)?xml', $phpCode);

        // Verify $mod_clean_uri is always initialized strictly BEFORE its first reference in $is_direct_script_target
        $initPos = strpos($phpCode, '$mod_clean_uri = (string) $raw_clean_path;');
        $usePos  = strpos($phpCode, '$is_direct_script_target =');
        $this->assertNotFalse($initPos, '$mod_clean_uri initialization must exist in compiled Micro-WAF.');
        $this->assertNotFalse($usePos, '$is_direct_script_target check must exist in compiled Micro-WAF.');
        $this->assertLessThan($usePos, $initPos, '$mod_clean_uri must be defined before $is_direct_script_target uses it.');
    }

    public function testCompiledMicroWafExecutesCleanlyWithZeroWarningsOrDeprecationsAcrossRoutes(): void
    {
        $GLOBALS['wp_mock_options']['webcareproscan_settings'] = [
            'waf_enabled'          => true,
            'waf_mode'             => 'enabled',
            'waf_whitelisted_urls' => "/allowed-healthcheck\n",
        ];

        $result = MicroWafCompiler::compile();
        $this->assertTrue($result['success'] ?? false);
        $compiledPath = MicroWafCompiler::get_compiled_file_path();
        $this->assertFileExists($compiledPath);

        $origServer  = $_SERVER;
        $origPost    = $_POST;
        $origGet     = $_GET;
        $origRequest = $_REQUEST;

        $scenarios = [
            [
                'REMOTE_ADDR'    => '198.51.100.25',
                'REQUEST_METHOD' => 'GET',
                'REQUEST_URI'    => '/wp-admin/tools.php?page=plugin-check&plugin=webcare-pro-security%2Fwebcare-pro-security.php',
                'QUERY_STRING'   => 'page=plugin-check&plugin=webcare-pro-security%2Fwebcare-pro-security.php',
                'PHP_SELF'       => '/wp-admin/tools.php',
                'POST'           => [],
            ],
            [
                'REMOTE_ADDR'    => '198.51.100.26',
                'REQUEST_METHOD' => 'POST',
                'REQUEST_URI'    => '/wp-admin/admin-ajax.php',
                'QUERY_STRING'   => '',
                'PHP_SELF'       => '/wp-admin/admin-ajax.php',
                'CONTENT_TYPE'   => 'application/x-www-form-urlencoded',
                'POST'           => ['action' => 'heartbeat', 'data' => ['wp-auth-check' => true]],
            ],
            [
                'REMOTE_ADDR'    => '198.51.100.27',
                'REQUEST_METHOD' => 'POST',
                'REQUEST_URI'    => '/wp-content/plugins/example/endpoint.php',
                'QUERY_STRING'   => '',
                'PHP_SELF'       => '/wp-content/plugins/example/endpoint.php',
                'CONTENT_TYPE'   => 'application/json',
                'POST'           => ['benign_key' => 'benign_value'],
            ],
        ];

        try {
            foreach ($scenarios as $s) {
                $_SERVER = array_merge($origServer, [
                    'REMOTE_ADDR'    => $s['REMOTE_ADDR'],
                    'REQUEST_METHOD' => $s['REQUEST_METHOD'],
                    'REQUEST_URI'    => $s['REQUEST_URI'],
                    'QUERY_STRING'   => $s['QUERY_STRING'],
                    'PHP_SELF'       => $s['PHP_SELF'],
                    'CONTENT_TYPE'   => $s['CONTENT_TYPE'] ?? '',
                ]);
                $_POST    = $s['POST'];
                $_GET     = [];
                $_REQUEST = $s['POST'];

                ob_start();
                include $compiledPath;
                $output = (string) ob_get_clean();

                $this->assertSame('', $output, 'Benign request through compiled Micro-WAF must emit zero stdout/HTML warnings.');
            }
        } finally {
            $_SERVER  = $origServer;
            $_POST    = $origPost;
            $_GET     = $origGet;
            $_REQUEST = $origRequest;
        }
    }
}
