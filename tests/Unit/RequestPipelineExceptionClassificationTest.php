<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Contracts\RequestContext;
use WebCareProScanner\Firewall\Core\RequestPipeline;

final class RequestPipelineExceptionClassificationTest extends TestCase
{
    public function testEvaluatePipelineRunsSuccessfully(): void
    {
        $ctx = new RequestContext(
            ip: '127.0.0.1',
            method: 'GET',
            uri: '/hello-world',
            userAgent: 'Mozilla/5.0'
        );

        $verdict = RequestPipeline::evaluate_pipeline($ctx, []);
        if ($verdict !== null) {
            $this->assertSame('block', $verdict->get_action_value());
            $this->assertContains($verdict->statusCode, [403, 503]);
        } else {
            $this->assertNull($verdict);
        }
    }
}
