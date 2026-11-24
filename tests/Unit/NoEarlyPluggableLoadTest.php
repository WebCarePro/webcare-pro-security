<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;

final class NoEarlyPluggableLoadTest extends TestCase
{
    public function testFirewallEngineDoesNotRequirePluggableDirectly(): void
    {
        $engineFile = __DIR__ . '/../../includes/Firewall/FirewallEngine.php';
        $contents = (string) file_get_contents($engineFile);

        $this->assertStringNotContainsString('require_once ABSPATH . \'wp-includes/pluggable.php\'', $contents);
        $this->assertStringNotContainsString('require_once ABSPATH . "wp-includes/pluggable.php"', $contents);
        $this->assertStringNotContainsString('wp-includes/pluggable.php', $contents);
    }
}
