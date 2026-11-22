<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Contracts\RequestContext;
use WebCareProScanner\Firewall\NextGen\ModernApiShield;
use WebCareProScanner\System\SettingsManager;

final class ModernApiShieldTest extends TestCase {

    protected function setUp(): void {
        parent::setUp();
        SettingsManager::update_setting('waf_nextgen_graphql_block_introspection', true);
        SettingsManager::update_setting('waf_nextgen_graphql_max_depth', 7);
        SettingsManager::update_setting('waf_nextgen_graphql_max_batch', 10);
    }

    public function test_blocks_introspection_outside_comments_and_block_strings(): void {
        $q1 = '{ __schema { types { name } } }';
        $this->assertTrue(ModernApiShield::contains_introspection($q1));

        // Introspection keyword inside a string literal should NOT be treated as introspection
        $q2 = '{ field(text: "__schema") }';
        $this->assertFalse(ModernApiShield::contains_introspection($q2));

        // Introspection keyword inside a comment should NOT be treated as introspection
        $q3 = "{\n  # this is a comment referring to __schema\n  user { id name }\n}";
        $this->assertFalse(ModernApiShield::contains_introspection($q3));

        // Introspection keyword inside a triple-quoted block string should NOT be treated as introspection
        $q4 = "{\n  post(description: \"\"\"\n    We document __schema and __type here in docs.\n  \"\"\") { id }\n}";
        $this->assertFalse(ModernApiShield::contains_introspection($q4));
    }

    public function test_raw_application_graphql_introspection_is_blocked(): void {
        $ctx = new RequestContext(
            ip: '198.51.100.20',
            method: 'POST',
            uri: '/graphql',
            headers: ['content-type' => 'application/graphql'],
            params: ['query' => '{ __type(name: "User") { name } }']
        );

        $shield = new ModernApiShield();
        $verdict = $shield->evaluate_runtime_request($ctx);
        $this->assertNotNull($verdict);
        $this->assertSame('WAF-GRAPHQL-INTROSPECTION', $verdict->ruleId);
    }

    public function test_measure_query_complexity_ignores_block_strings_and_comments(): void {
        $q = "{\n  # { { { nested comment braces } } }\n  post(content: \"\"\"\n    { { not real query braces } }\n  \"\"\") {\n    title\n  }\n}";
        $metrics = ModernApiShield::measure_query_complexity($q);
        $this->assertSame(2, $metrics['max_depth']);
    }
}
