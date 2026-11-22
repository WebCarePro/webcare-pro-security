<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Firewall\NextGen\RuntimeSqlRaspEngine;

class RuntimeSqlRaspEngineTest extends TestCase {

    protected function setUp(): void {
        parent::setUp();
        RuntimeSqlRaspEngine::reset_runtime_auth_state();
    }

    public function testCommentKeywordSplittingEvasionIsBlocked(): void {
        // Attackers split keywords with comments to evade naive regex
        $query = "SELECT * FROM wp_posts WHERE id = 1 UN/**/ION SEL/**/ECT user_login, user_pass FROM wp_users";
        $anomaly = RuntimeSqlRaspEngine::detect_sql_anomaly($query);

        $this->assertSame('UNION_SELECT_CREDENTIAL_TABLE', $anomaly, 'Comment-split UNION SELECT targeting credentials must be blocked.');
    }

    public function testMysqlConditionalCommentUnwrapping(): void {
        // MySQL conditional comments /*!50000 SELECT */ executed in MySQL must be unwrapped and inspected
        $query = "SELECT * FROM wp_posts WHERE id = 1 /*!50000 UNION SELECT */ user_login, user_pass FROM wp_users";
        $anomaly = RuntimeSqlRaspEngine::detect_sql_anomaly($query);

        $this->assertSame('UNION_SELECT_CREDENTIAL_TABLE', $anomaly, 'MySQL conditional comment injection must be unwrapped and detected.');
    }

    public function testStackedQueryExecutionIsBlocked(): void {
        $query = "SELECT * FROM wp_posts WHERE id = 1; DROP TABLE wp_users";
        $anomaly = RuntimeSqlRaspEngine::detect_sql_anomaly($query);

        $this->assertSame('STACKED_QUERY_ATTEMPT', $anomaly, 'Stacked multi-query DROP TABLE must be detected.');
    }

    public function testErrorBasedExtractionIsBlocked(): void {
        $query = "SELECT * FROM wp_posts WHERE id = 1 AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT user_pass FROM wp_users LIMIT 1)))";
        $anomaly = RuntimeSqlRaspEngine::detect_sql_anomaly($query);

        $this->assertSame('ERROR_BASED_SQLI_PRIMITIVE', $anomaly, 'EXTRACTVALUE error-based injection must be detected.');
    }

    public function testInternalQueryDepthBypassesSafelyWithoutSubstrings(): void {
        // Inside run_internal_query, queries bypass RASP checks
        $result = RuntimeSqlRaspEngine::run_internal_query(function () {
            $internalQuery = "SELECT * FROM wp_posts WHERE id = 1 UNION SELECT user_login, user_pass FROM wp_users";
            return RuntimeSqlRaspEngine::detect_sql_anomaly($internalQuery);
        });

        $this->assertNull($result, 'Queries executed inside run_internal_query must bypass RASP checks.');
    }
}
