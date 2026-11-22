<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Contracts\RequestContext;
use WebCareProScanner\Firewall\Core\RequestBodyReader;
use WebCareProScanner\Firewall\Core\ExploitSignatureEngine;
use WebCareProScanner\Firewall\NextGen\ModernApiShield;

class RequestContextIsolationTest extends TestCase {

    private string $temp_dir;

    protected function setUp(): void {
        parent::setUp();
        RequestBodyReader::reset();
        $_GET = [];
        $_POST = [];
        $_COOKIE = [];
        $_FILES = [];
        $_SERVER = [];
        $this->temp_dir = sys_get_temp_dir() . '/wcp_test_ctx_' . bin2hex(random_bytes(6));
        @mkdir($this->temp_dir, 0755, true);
    }

    protected function tearDown(): void {
        RequestBodyReader::reset();
        RequestBodyReader::$mock_raw_body = null; $this->clean_dir($this->temp_dir);
        parent::tearDown();
    }

    private function clean_dir(string $dir): void {
        if (!is_dir($dir)) {
            return;
        }
        $items = scandir($dir) ?: [];
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $p = $dir . '/' . $item;
            if (is_dir($p)) {
                $this->clean_dir($p);
            } else {
                @unlink($p);
            }
        }
        @rmdir($dir);
    }

    /**
     * Requirement 1: Cookie parameter isolation.
     * Cookie named 'action' must never leak into queryParams, formParams, or ajaxAction.
     * Duplicate query vs form parameters remain distinguishable in queryParams vs formParams.
     */
    public function testCookiesDoNotLeakIntoParamsAndSourcesAreIsolated(): void {
        $_GET['action'] = 'view_product';
        $_GET['item_id'] = '42';

        $_POST['action'] = 'submit_order';
        $_POST['order_note'] = 'Fragile delivery';

        $_COOKIE['action'] = 'malicious_cookie_override';
        $_COOKIE['session_id'] = 'sess_xyz123';

        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_SERVER['REQUEST_URI'] = '/checkout/?action=view_product&item_id=42';
        $_SERVER['CONTENT_TYPE'] = 'application/x-www-form-urlencoded';

        $ctx = RequestContext::from_globals();

        // 1. Cookies are strictly stored in $ctx->cookies
        $this->assertArrayHasKey('action', $ctx->cookies);
        $this->assertSame('malicious_cookie_override', $ctx->cookies['action']);
        $this->assertArrayHasKey('session_id', $ctx->cookies);

        // 2. Cookie values NEVER appear in queryParams or formParams
        $this->assertSame('view_product', $ctx->queryParams['action']);
        $this->assertSame('submit_order', $ctx->formParams['action']);

        // 3. $ctx->params is strictly queryParams + formParams + jsonParams (NOT cookies)
        $this->assertNotSame('malicious_cookie_override', $ctx->params['action']);
        $this->assertArrayNotHasKey('session_id', $ctx->params, 'Cookies must never be merged into $ctx->params.');

        // 4. Distinguishable query vs form params
        $this->assertSame('42', $ctx->queryParams['item_id']);
        $this->assertSame('Fragile delivery', $ctx->formParams['order_note']);
    }

    /**
     * Requirement 2: Truncated JSON invariant.
     * 512 KB JSON body stops at 262145 bytes, marks is_truncated() === true,
     * and is NEVER parsed partially into $ctx->jsonParams or $ctx->params.
     */
    public function testOversizedJsonBodySetsTruncatedAndNeverParsesPartially(): void {
        // Generate a 512 KB JSON string
        $large_data = ['field' => str_repeat('A', 512 * 1024)];
        $raw_json = json_encode($large_data);

        RequestBodyReader::$mock_raw_body = $raw_json;

        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_SERVER['REQUEST_URI'] = '/wp-json/my-api/v1/update';
        $_SERVER['CONTENT_TYPE'] = 'application/json';

        $ctx = RequestContext::from_globals();

        $this->assertTrue($ctx->rawBodyMetadata['truncated'], 'Truncated flag must be true for 512 KB JSON body.');
        $this->assertGreaterThan(262144, $ctx->rawBodyMetadata['bytes_read']);

        // Crucial invariant: truncated JSON body must NOT be parsed into jsonParams or params
        $this->assertEmpty($ctx->jsonParams, 'Truncated JSON must never be partially decoded.');
        $this->assertArrayNotHasKey('field', $ctx->params, 'Truncated JSON keys must not leak into params.');

        // ModernApiShield also fails closed on truncated GraphQL query
        $queries = ModernApiShield::extract_graphql_queries($ctx);
        $this->assertFalse($queries, 'ModernApiShield::extract_graphql_queries must return false on truncated body.');
    }

    /**
     * Requirement 3: Stateful streaming upload scanner & zip bomb guard.
     * A signature split across chunk boundary is caught; zip bombs are rejected.
     */
    public function testStreamingUploadInspectionAndZipBombGuard(): void {
        // 1. Test signature split across 64 KB boundary
        $test_file = $this->temp_dir . '/large_payload.bin';
        $prefix = str_repeat('X', 65530); // 6 bytes before 64 KB (65536)
        $sig_part1 = 'ev';
        $sig_part2 = 'al(base64_decode('; // Crosses 65536 boundary
        $suffix = str_repeat('Y', 1000);

        file_put_contents($test_file, $prefix . $sig_part1 . $sig_part2 . $suffix);

        $signatures = [
            'rce_eval' => '/eval\s*\(\s*base64_decode\s*\(/i',
        ];

        // Chunk size 65536 with 512-byte overlap
        $result = ExploitSignatureEngine::stream_inspect_file($test_file, $signatures, 65536, 512);
        $this->assertTrue($result['matched'], 'Split signature across 64 KB boundary must be detected.');
        $this->assertSame('rce_eval', $result['sig_key']);

        // 2. Test ZIP bomb detection
        if (class_exists('ZipArchive')) {
            $zip_bomb_file = $this->temp_dir . '/bomb.zip';
            $zip = new \ZipArchive();
            if ($zip->open($zip_bomb_file, \ZipArchive::CREATE) === true) {
                // Highly compressible repeating data: 2 MB of zeros compresses to ~2 KB (> 1000:1 ratio)
                $zip->addFromString('huge_zero.txt', str_repeat("\0", 2 * 1024 * 1024));
                $zip->close();

                $safety = ExploitSignatureEngine::validate_zip_archive_safety($zip_bomb_file, 5000, 67108864, 100.0);
                $this->assertFalse($safety['safe'], 'High compression ratio zip bomb must be rejected.');
                $this->assertStringContainsString('ZIP bomb detected', $safety['reason']);
            }
        }
    }

    /**
     * Requirement 4: Split request source isolation in ExploitSignatureEngine.
     * Query parameters must never impersonate form POST parameters.
     * RequestBodyReader::stream_file_windowed directly detects boundary crossing in constant memory.
     */
    public function testQueryParamDoesNotImpersonateFormPostAndStreamWindowedWorks(): void {
        // 1. Verify query param does not populate formParams
        $ctx = new RequestContext(
            ip: '127.0.0.1',
            method: 'POST',
            uri: '/wp-admin/post.php?post_ID=100',
            formParams: ['title' => 'Safe Post'],
            queryParams: ['post_ID' => '100', 'exploit_field' => 'cmd.exe'],
        );

        $this->assertArrayNotHasKey('exploit_field', $ctx->formParams);
        $this->assertSame('100', $ctx->queryParams['post_ID']);

        // 2. Direct test of RequestBodyReader::stream_file_windowed across 64 KB boundary
        $test_file = $this->temp_dir . '/windowed_payload.bin';
        $prefix = str_repeat('A', 65530);
        $needle = 'MALICIOUS_PAYLOAD_TOKEN';
        $suffix = str_repeat('B', 2000);
        file_put_contents($test_file, $prefix . $needle . $suffix);

        $found = false;
        $stream_res = RequestBodyReader::stream_file_windowed(
            $test_file,
            static function (string $window) use ($needle, &$found): ?array {
                if (str_contains($window, $needle)) {
                    $found = true;
                    return ['detected' => true];
                }
                return null;
            },
            65536,
            4096
        );

        $this->assertTrue($found, 'stream_file_windowed must detect token spanning 64 KB boundary.');
        $this->assertTrue($stream_res['completed']);
        $this->assertSame(['detected' => true], $stream_res['result']);

        // 3. Test unreadable or failed stream inspection does not result in clean pass
        $missing_file = $this->temp_dir . '/non_existent_file.bin';
        $inspect_res = ExploitSignatureEngine::stream_inspect_file($missing_file, ['SIG_TEST' => '/payload/']);
        $this->assertFalse($inspect_res['matched']);

        // When stream encounters incomplete read
        $incomplete_res = RequestBodyReader::stream_file_windowed($missing_file, static fn() => null);
        $this->assertFalse($incomplete_res['completed']);
        $this->assertTrue($incomplete_res['read_failed']);
    }
}
