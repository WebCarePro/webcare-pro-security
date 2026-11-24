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
    }
}
