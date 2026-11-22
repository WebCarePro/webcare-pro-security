<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Firewall\NextGen\ModernApiShield;
use WebCareProScanner\Firewall\RescueAssistantManager;

/**
 * Unit tests for PR-D:
 * 1. Single-pass stateful GraphQL lexer with comments and quotes.
 * 2. Strict scoped allowlisting (Finding #15).
 */
final class AllowlistScopeTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $GLOBALS['wp_mock_options'] = [];
        unset($GLOBALS['wp_mock_current_user']);
    }

    protected function tearDown(): void
    {
        unset($GLOBALS['wp_mock_current_user']);
        parent::tearDown();
    }

    /**
     * Test single-pass stateful GraphQL lexer comments & quotes edge cases.
     */
    public function testGraphQLLexerStringAndCommentHandling(): void
    {
        $shield = new ModernApiShield();

        // 1. String containing '#' inside query must NOT be treated as comment
        $queryWithHashInString = '{ user(notes: "Contains #not_a_comment inside quotes") { id name } }';
        $normalized = ModernApiShield::lex_graphql_syntax($queryWithHashInString);
        $this->assertStringContainsString('user', $normalized);
        $this->assertStringContainsString('id', $normalized);

        // 2. Comments with double quotes must be stripped cleanly
        $queryWithQuotesInComment = "{ user {\n # This comment has \"quoted string\" inside it\n id\n } }";
        $normalized2 = ModernApiShield::lex_graphql_syntax($queryWithQuotesInComment);
        $this->assertStringNotContainsString('quoted string', $normalized2);
        $this->assertStringContainsString('user', $normalized2);
        $this->assertStringContainsString('id', $normalized2);

        // 3. Introspection inside string literal should NOT trigger introspection detection
        $queryWithFakeIntrospection = '{ post(search: "__schema __type") { title } }';
        $isIntrospection = $shield->contains_introspection($queryWithFakeIntrospection);
        $this->assertFalse($isIntrospection, 'Introspection token inside string literals must not be flagged.');

        // 4. Real introspection outside string literal MUST be flagged
        $realIntrospection = '{ __schema { types { name } } }';
        $isIntrospectionReal = $shield->contains_introspection($realIntrospection);
        $this->assertTrue($isIntrospectionReal, 'Real GraphQL introspection query must be flagged.');
    }

    /**
     * Test strict scoped allowlist enforcement:
     * - Route exact matching vs subpath traversal
     * - Method matching
     * - Parameter key matching
     * - User role matching
     * - Zero-tolerance rules (RCE, SQLi, etc.) must NEVER be bypassed
     */
    public function testEnforceFullStoredScopeInRescueAllowlists(): void
    {
        // Setup allowlist item with full scope: /checkout, POST, order_comments, customer
        RescueAssistantManager::trust_and_allow_action([
            'type'      => 'uri',
            'value'     => '/checkout',
            'method'    => 'POST',
            'param_key' => 'order_comments',
            'user_role' => 'customer',
            'rule_id'   => 'WAF-CUSTOM-HEURISTIC',
        ]);

        // Mock current user as customer
        $GLOBALS['wp_mock_current_user'] = new class {
            public int $ID = 42;
            public string $user_login = 'test_customer';
            public array $roles = ['customer'];
            public array $allcaps = [];
            public function exists(): bool {
                return true;
            }
        };

        // 1. Exact match on /checkout with POST, order_comments, customer -> TRUSTED
        $is_trusted = RescueAssistantManager::is_rule_or_request_trusted(
            rule_id: 'WAF-CUSTOM-HEURISTIC',
            clean_uri: '/checkout',
            ajax_action: '',
            rest_query: '',
            method: 'POST',
            param_key: 'order_comments'
        );
        $this->assertTrue($is_trusted, 'Exact scope match (route + method + param_key + role) must be trusted.');

        // 2. Different route (/checkout-admin) -> NOT TRUSTED
        $diff_route = RescueAssistantManager::is_rule_or_request_trusted(
            rule_id: 'WAF-CUSTOM-HEURISTIC',
            clean_uri: '/checkout-admin',
            ajax_action: '',
            rest_query: '',
            method: 'POST',
            param_key: 'order_comments'
        );
        $this->assertFalse($diff_route, 'Subpath /checkout-admin must not match /checkout.');

        // 3. Different HTTP method (GET) -> NOT TRUSTED
        $diff_method = RescueAssistantManager::is_rule_or_request_trusted(
            rule_id: 'WAF-CUSTOM-HEURISTIC',
            clean_uri: '/checkout',
            ajax_action: '',
            rest_query: '',
            method: 'GET',
            param_key: 'order_comments'
        );
        $this->assertFalse($diff_method, 'Method mismatch must invalidate allowlist exemption.');

        // 4. Different parameter key (billing_address) -> NOT TRUSTED
        $diff_param = RescueAssistantManager::is_rule_or_request_trusted(
            rule_id: 'WAF-CUSTOM-HEURISTIC',
            clean_uri: '/checkout',
            ajax_action: '',
            rest_query: '',
            method: 'POST',
            param_key: 'billing_address'
        );
        $this->assertFalse($diff_param, 'Parameter key mismatch must invalidate allowlist exemption.');

        // 5. Different role (subscriber instead of customer) -> NOT TRUSTED
        $GLOBALS['wp_mock_current_user']->roles = ['subscriber'];
        $diff_role = RescueAssistantManager::is_rule_or_request_trusted(
            rule_id: 'WAF-CUSTOM-HEURISTIC',
            clean_uri: '/checkout',
            ajax_action: '',
            rest_query: '',
            method: 'POST',
            param_key: 'order_comments'
        );
        $this->assertFalse($diff_role, 'Role mismatch must invalidate allowlist exemption.');

        // Reset role back to customer
        $GLOBALS['wp_mock_current_user']->roles = ['customer'];

        // 6. Zero-Tolerance rules (e.g. WAF-RCE, WAF-SQLI) must NEVER be bypassed by any allowlist
        $rce_bypass = RescueAssistantManager::is_rule_or_request_trusted(
            rule_id: 'WAF-RCE',
            clean_uri: '/checkout',
            ajax_action: '',
            rest_query: '',
            method: 'POST',
            param_key: 'order_comments'
        );
        $this->assertFalse($rce_bypass, 'Zero-tolerance rule WAF-RCE must NEVER be bypassable by allowlists.');

        $sqli_bypass = RescueAssistantManager::is_rule_or_request_trusted(
            rule_id: 'WAF-SQLI',
            clean_uri: '/checkout',
            ajax_action: '',
            rest_query: '',
            method: 'POST',
            param_key: 'order_comments'
        );
        $this->assertFalse($sqli_bypass, 'Zero-tolerance rule WAF-SQLI must NEVER be bypassable by allowlists.');

        // 7. Empty parameter context must NOT match an allowlist entry with a non-empty param_key
        $empty_param = RescueAssistantManager::is_rule_or_request_trusted(
            rule_id: 'WAF-CUSTOM-HEURISTIC',
            clean_uri: '/checkout',
            ajax_action: '',
            rest_query: '',
            method: 'POST',
            param_key: '' // Empty parameter context
        );
        $this->assertFalse($empty_param, 'Allowlist with param_key must NOT match when parameter context is empty.');

        // 8. Enforce Path-Segment Boundary on /* wildcards:
        // /checkout/* should match /checkout/ and /checkout/order-pay, but NEVER /checkout-admin
        RescueAssistantManager::trust_and_allow_action([
            'type'      => 'uri',
            'value'     => '/checkout/*',
            'method'    => 'POST',
            'rule_id'   => 'WAF-CUSTOM-HEURISTIC',
        ]);

        $wildcard_match = RescueAssistantManager::is_rule_or_request_trusted(
            rule_id: 'WAF-CUSTOM-HEURISTIC',
            clean_uri: '/checkout/order-pay',
            ajax_action: '',
            rest_query: '',
            method: 'POST',
            param_key: ''
        );
        $this->assertTrue($wildcard_match, '/checkout/* must match /checkout/order-pay.');

        $wildcard_nomatch = RescueAssistantManager::is_rule_or_request_trusted(
            rule_id: 'WAF-CUSTOM-HEURISTIC',
            clean_uri: '/checkout-admin',
            ajax_action: '',
            rest_query: '',
            method: 'POST',
            param_key: ''
        );
        $this->assertFalse($wildcard_nomatch, '/checkout/* must NEVER match /checkout-admin.');
    }
}
