<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Firewall\NextGen\RuntimeSqlRaspEngine;

class RuntimeSqlRaspEngineTest extends TestCase {

    /** @var string[] */
    private array $tempPathsToClean = [];

    protected function setUp(): void {
        parent::setUp();
        RuntimeSqlRaspEngine::reset_runtime_auth_state();
        $pluginRoot = defined('WP_PLUGIN_DIR') ? rtrim(str_replace('\\', '/', WP_PLUGIN_DIR), '/') : '';
        if ($pluginRoot !== '' && !is_dir($pluginRoot)) {
            mkdir($pluginRoot, 0777, true);
        }
    }

    protected function tearDown(): void {
        foreach (array_reverse($this->tempPathsToClean) as $path) {
            $this->removeTempPath($path);
        }
        $this->tempPathsToClean = [];
        parent::tearDown();
    }

    private function removeTempPath(string $path): void {
        if (is_link($path)) {
            @unlink($path) || @rmdir($path);
            return;
        }
        if (DIRECTORY_SEPARATOR === '\\') {
            $winPath = (string) preg_replace('#[\\\\/]+#', '\\', $path);
            // If it is a junction / directory (including dangling junctions), rmdir removes the junction safely
            @exec('rmdir ' . escapeshellarg($winPath) . ' >nul 2>&1');
            clearstatcache(true, $path);
            if (!file_exists($path) && !is_dir($path)) {
                return;
            }
        }
        if (is_file($path)) {
            @unlink($path);
        } elseif (is_dir($path)) {
            @rmdir($path);
        }
    }

    private function createTempFile(string $fullPath): string {
        $dir = dirname($fullPath);
        if (!is_dir($dir)) {
            $partsToTrack = [];
            $cur = $dir;
            while ($cur !== '' && !is_dir($cur) && $cur !== dirname($cur)) {
                $partsToTrack[] = $cur;
                $cur = dirname($cur);
            }
            mkdir($dir, 0777, true);
            foreach (array_reverse($partsToTrack) as $createdDir) {
                $this->tempPathsToClean[] = $createdDir;
            }
        }
        file_put_contents($fullPath, "<?php\n");
        $this->tempPathsToClean[] = $fullPath;
        return $fullPath;
    }

    private function createDirectorySymlink(string $targetDir, string $linkPath): bool {
        $this->removeTempPath($linkPath);
        if (!is_dir($targetDir)) {
            mkdir($targetDir, 0777, true);
            $this->tempPathsToClean[] = $targetDir;
        }
        if (@symlink($targetDir, $linkPath)) {
            $this->tempPathsToClean[] = $linkPath;
            return true;
        }
        if (DIRECTORY_SEPARATOR === '\\') {
            $winLink   = (string) preg_replace('#[\\\\/]+#', '\\', $linkPath);
            $winTarget = (string) preg_replace('#[\\\\/]+#', '\\', $targetDir);
            $cmd = 'mklink /J ' . escapeshellarg($winLink) . ' ' . escapeshellarg($winTarget) . ' >nul 2>&1';
            exec($cmd, $out, $code);
            clearstatcache(true, $linkPath);
            if ($code === 0 && is_dir($linkPath)) {
                $this->tempPathsToClean[] = $linkPath;
                return true;
            }
        }
        return false;
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

    public function testUsersInsertFromUnrelatedPluginIsRejected(): void {
        $pluginRoot = rtrim(str_replace('\\', '/', (string) WP_PLUGIN_DIR), '/');
        $rogueFile  = $this->createTempFile($pluginRoot . '/some-unrelated-plugin/rogue.php');
        $sql = "INSERT INTO `wp_users` (`user_login`, `user_pass`, `user_email`) VALUES ('rogue', 'hash', 'rogue@example.com')";
        $frames = [
            ['file' => $rogueFile, 'function' => 'do_something'],
            ['file' => $rogueFile, 'function' => 'wp_insert_user', 'args' => [['role' => 'subscriber']]],
        ];

        $this->assertFalse(RuntimeSqlRaspEngine::is_legitimate_users_table_mutation($sql, $frames));
    }

    public function testUsersInsertFromGravityFormsWithoutRegistrationFrameIsRejected(): void {
        $pluginRoot = rtrim(str_replace('\\', '/', (string) WP_PLUGIN_DIR), '/');
        $gfFile     = $this->createTempFile($pluginRoot . '/gravityformsuserregistration/class-gf-user-registration.php');
        $sql = "INSERT INTO `wp_users` (`user_login`, `user_pass`, `user_email`) VALUES ('student1', 'hash', 's@example.com')";
        $frames = [
            ['file' => $gfFile, 'function' => 'arbitrary_helper'],
        ];

        $this->assertFalse(RuntimeSqlRaspEngine::is_legitimate_users_table_mutation($sql, $frames));
    }

    public function testUsersInsertWithPrivilegedRoleArgumentIsRejected(): void {
        $coreUserFile = $this->createTempFile(rtrim(str_replace('\\', '/', (string) ABSPATH), '/') . '/wp-includes/user.php');
        $sql = "INSERT INTO `wp_users` (`user_login`, `user_pass`, `user_email`) VALUES ('pwn', 'hash', 'pwn@example.com')";
        $frames = [
            ['file' => $coreUserFile, 'function' => 'wp_insert_user', 'args' => [['user_login' => 'pwn', 'role' => 'administrator']]],
        ];

        $this->assertFalse(RuntimeSqlRaspEngine::is_legitimate_users_table_mutation($sql, $frames));
    }

    public function testUsersInsertWithNestedPrivilegedRoleArgumentIsRejected(): void {
        $pluginRoot = rtrim(str_replace('\\', '/', (string) WP_PLUGIN_DIR), '/');
        $gfFile     = $this->createTempFile($pluginRoot . '/gravityformsuserregistration/class-gf-user-registration.php');
        $sql = "INSERT INTO `wp_users` (`user_login`, `user_pass`, `user_email`) VALUES ('pwn2', 'hash', 'pwn2@example.com')";
        $frames = [
            [
                'file' => $gfFile,
                'class' => 'GF_User_Registration',
                'function' => 'create_user',
                'args' => [['feed' => ['meta' => ['role' => 'administrator']]]],
            ],
        ];

        $this->assertFalse(RuntimeSqlRaspEngine::is_legitimate_users_table_mutation($sql, $frames));
    }

    public function testUsersInsertFromVerifiedGravityFormsRegistrationFlowIsAllowed(): void {
        $pluginRoot   = rtrim(str_replace('\\', '/', (string) WP_PLUGIN_DIR), '/');
        $gfFile       = $this->createTempFile($pluginRoot . '/gravityformsuserregistration/class-gf-user-registration.php');
        $coreUserFile = $this->createTempFile(rtrim(str_replace('\\', '/', (string) ABSPATH), '/') . '/wp-includes/user.php');
        $sql = "INSERT INTO `wp_users` (`user_login`, `user_pass`, `user_email`) VALUES ('student1', 'hash', 's@example.com')";
        $frames = [
            [
                'file' => $gfFile,
                'class' => 'GF_User_Registration',
                'function' => 'create_user',
                'args' => [['role' => 'subscriber']],
            ],
            [
                'file' => $coreUserFile,
                'function' => 'wp_insert_user',
                'args' => [['user_login' => 'student1', 'role' => 'subscriber']],
            ],
        ];

        $this->assertTrue(RuntimeSqlRaspEngine::is_legitimate_users_table_mutation($sql, $frames));
    }

    public function testUsersInsertViaSymlinkedPluginDirectoryOutsideRootIsRejected(): void {
        $pluginRoot = rtrim(str_replace('\\', '/', (string) WP_PLUGIN_DIR), '/');
        $outsideDir = sys_get_temp_dir() . '/wcp_outside_plugin_' . bin2hex(random_bytes(4));
        $outsideFile = $this->createTempFile($outsideDir . '/evil-reg.php');
        $symlinkPluginDir = $pluginRoot . '/wpforms-user-registration';

        // Clean any pre-existing test link/dir before linking
        if (is_link($symlinkPluginDir) || is_dir($symlinkPluginDir)) {
            @rmdir($symlinkPluginDir);
        }
        $linked = $this->createDirectorySymlink($outsideDir, $symlinkPluginDir);
        $this->assertTrue($linked, 'Filesystem symlink/junction must be created to test realpath escape defense.');

        $sql = "INSERT INTO `wp_users` (`user_login`, `user_pass`, `user_email`) VALUES ('sym', 'hash', 'sym@example.com')";
        $frames = [
            [
                'file' => $symlinkPluginDir . '/evil-reg.php',
                'class' => 'WPForms_User_Registration',
                'function' => 'register_user',
                'args' => [['role' => 'subscriber']],
            ],
        ];

        $this->assertFileExists($outsideFile);
        $this->assertFalse(RuntimeSqlRaspEngine::is_legitimate_users_table_mutation($sql, $frames));
    }

    public function testUsersInsertRejectsUnresolvableNonExistentPluginPath(): void {
        $pluginRoot = rtrim(str_replace('\\', '/', (string) WP_PLUGIN_DIR), '/');
        $sql = "INSERT INTO `wp_users` (`user_login`, `user_pass`, `user_email`) VALUES ('ghost', 'hash', 'ghost@example.com')";
        $frames = [
            [
                'file' => $pluginRoot . '/gravityformsuserregistration/does-not-exist.php',
                'class' => 'GF_User_Registration',
                'function' => 'create_user',
                'args' => [['role' => 'subscriber']],
            ],
        ];

        $this->assertFalse(RuntimeSqlRaspEngine::is_legitimate_users_table_mutation($sql, $frames));
    }

    public function testSecurityScannerCallerProvenanceRequiresVerifiedRealpathDescendant(): void {
        $pluginRoot = rtrim(str_replace('\\', '/', (string) WP_PLUGIN_DIR), '/');
        $wfFile     = $this->createTempFile($pluginRoot . '/wordfence/lib/wfUpdateCheck.php');

        $this->assertTrue(RuntimeSqlRaspEngine::is_legitimate_security_or_core_caller([
            ['file' => $wfFile],
        ]));
        $this->assertFalse(RuntimeSqlRaspEngine::is_legitimate_security_or_core_caller([
            ['file' => $pluginRoot . '/wordfence/lib/nonexistent.php'],
        ]));
        $this->assertFalse(RuntimeSqlRaspEngine::is_legitimate_security_or_core_caller([
            ['file' => '/tmp/evil/plugins/wordfence/lib/wfUpdateCheck.php'],
        ]));
    }
}
