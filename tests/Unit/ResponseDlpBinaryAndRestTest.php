<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Firewall\NextGen\ResponseDlpSentinel;

final class ResponseDlpBinaryAndRestTest extends TestCase
{
    protected function tearDown(): void
    {
        ResponseDlpSentinel::$custom_headers_list = null;
        parent::tearDown();
    }

    public function testFilterGuestOutputBufferBypassesBinaryContentTypes(): void
    {
        $fake_leak = 'DB_PASSWORD = "super_secret_password_123"';

        // When content-type is image/webp, should bypass without redaction
        ResponseDlpSentinel::$custom_headers_list = ['Content-Type: image/webp'];
        $out = ResponseDlpSentinel::filter_guest_output_buffer($fake_leak);
        $this->assertSame($fake_leak, $out);

        // When content-type is application/pdf, should bypass
        ResponseDlpSentinel::$custom_headers_list = ['Content-Type: application/pdf'];
        $out = ResponseDlpSentinel::filter_guest_output_buffer($fake_leak);
        $this->assertSame($fake_leak, $out);

        // When content-type is font/woff2, should bypass
        ResponseDlpSentinel::$custom_headers_list = ['Content-Type: font/woff2'];
        $out = ResponseDlpSentinel::filter_guest_output_buffer($fake_leak);
        $this->assertSame($fake_leak, $out);

        // When content-encoding is zstd, should bypass
        ResponseDlpSentinel::$custom_headers_list = ['Content-Encoding: zstd'];
        $out = ResponseDlpSentinel::filter_guest_output_buffer($fake_leak);
        $this->assertSame($fake_leak, $out);

        // When content-encoding is deflate, should bypass
        ResponseDlpSentinel::$custom_headers_list = ['Content-Encoding: deflate'];
        $out = ResponseDlpSentinel::filter_guest_output_buffer($fake_leak);
        $this->assertSame($fake_leak, $out);
    }

    public function testRestDlpBudgetExhaustionReturns503FailClosed(): void
    {
        // Construct deeply nested array (> 25 levels)
        $nested = 'leaf';
        for ($i = 0; $i < 30; $i++) {
            $nested = ['child' => $nested];
        }

        $request = new \WP_REST_Request('GET', '/wp/v2/posts');
        $response = new \WP_REST_Response($nested, 200);

        // Ensure user is not logged in
        $GLOBALS['wp_mock_current_user'] = null;

        $filtered = ResponseDlpSentinel::filter_rest_response($response, null, $request);

        $this->assertInstanceOf(\WP_REST_Response::class, $filtered);
        $this->assertSame(503, $filtered->get_status());
        $data = $filtered->get_data();
        $this->assertSame('webcare_dlp_inspection_unavailable', $data['code']);
    }
}
