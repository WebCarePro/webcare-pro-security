<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Firewall\NextGen\ResponseDlpSentinel;

final class ResponseDlpStreamSafetyTest extends TestCase
{
    public function testMagicByteExemptionBypassesBinaryMedia(): void
    {
        // PNG header
        $png = "\x89PNG\r\n\x1a\n" . str_repeat("\x00", 100);
        $res = ResponseDlpSentinel::inspect_and_redact($png, true);
        $this->assertFalse($res['leaked']);
        $this->assertSame($png, $res['safe_body']);

        // ZIP header
        $zip = "PK\x03\x04" . str_repeat("\x00", 100);
        $res = ResponseDlpSentinel::inspect_and_redact($zip, true);
        $this->assertFalse($res['leaked']);
        $this->assertSame($zip, $res['safe_body']);

        // GZIP header
        $gzip = "\x1F\x8B\x08" . str_repeat("\x00", 100);
        $res = ResponseDlpSentinel::inspect_and_redact($gzip, true);
        $this->assertFalse($res['leaked']);
        $this->assertSame($gzip, $res['safe_body']);
    }

    public function testRedactDataRecursiveThrowsOnDepthExhaustion(): void
    {
        $has_leak = false;
        $matched_pattern = '';
        $nodes = 0;
        $visited = [];
        $max_depth = 0;

        // Build 30 levels deep nested array (exceeding MAX_RECURSION_DEPTH = 25)
        $nested = 'leaf';
        for ($i = 0; $i < 30; $i++) {
            $nested = ['child' => $nested];
        }

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('DLP recursion limit exceeded');

        ResponseDlpSentinel::redact_data_recursive($nested, $has_leak, $matched_pattern, 0, $nodes, $visited, $max_depth);
    }
}
