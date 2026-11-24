<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Cli\WafCliCommand;
use WebCareProScanner\Database\Migration;
use WebCareProScanner\Firewall\Core\BlocklistRepository;
use WebCareProScanner\Firewall\Core\WafVaultManager;
use WebCareProScanner\Firewall\WafFileLogger;
use WebCareProScanner\Plugin;
use WebCareProScanner\System\SettingsManager;

class Phase5And6ArchitectureTest extends TestCase {

    protected function setUp(): void {
        parent::setUp();
        webcare_purge_test_storage();
        SettingsManager::reset_settings_cache();
        $GLOBALS['wp_mock_options']         = [];
        $GLOBALS['wp_mock_is_multisite']    = false;
        $GLOBALS['wp_mock_current_blog_id'] = 1;
        $GLOBALS['wpdb']                    = new \wpdb();
        unset($GLOBALS['wp_mock_current_user_can'], $GLOBALS['wp_mock_current_user_can_callback']);
    }

    protected function tearDown(): void {
        unset($GLOBALS['wp_mock_current_user_can'], $GLOBALS['wp_mock_current_user_can_callback']);
        $GLOBALS['wp_mock_is_multisite']    = false;
        $GLOBALS['wp_mock_current_blog_id'] = 1;
        webcare_purge_test_storage();
        SettingsManager::reset_settings_cache();
        parent::tearDown();
    }

    public function test_multisite_vault_and_waf_logger_isolate_subsite_directories(): void {
        $GLOBALS['wp_mock_is_multisite']    = true;
        $GLOBALS['wp_mock_current_blog_id'] = 1;

        $root_vault = WafVaultManager::get_vault_dir_readonly();
        $root_logs  = WafFileLogger::get_storage_dir();
        $this->assertStringEndsWith('/webcare-waf/vault', $root_vault);
        $this->assertStringEndsWith('/webcare-waf/vault/logs', $root_logs);

        $GLOBALS['wp_mock_current_blog_id'] = 2;
        $sub_vault = WafVaultManager::get_vault_dir_readonly();
        $sub_logs  = WafFileLogger::get_storage_dir();
        $this->assertStringEndsWith('/webcare-waf/sites/2/vault', $sub_vault);
        $this->assertStringEndsWith('/webcare-waf/sites/2/vault/logs', $sub_logs);
        $this->assertNotSame($root_vault, $sub_vault);
        $this->assertNotSame($root_logs, $sub_logs);
    }

    public function test_multisite_blog_deletion_cleans_subsite_storage_and_skips_main_blog(): void {
        $content_base = defined('WP_CONTENT_DIR') ? WP_CONTENT_DIR : ABSPATH . 'wp-content';
        $sub_waf_dir  = rtrim((string) $content_base, '/\\') . '/webcare-waf/sites/7/vault';
        wp_mkdir_p($sub_waf_dir);
        file_put_contents($sub_waf_dir . '/test.json', '{}');

        $main_vault = rtrim((string) $content_base, '/\\') . '/webcare-waf/vault';
        wp_mkdir_p($main_vault);
        file_put_contents($main_vault . '/keep.json', '{}');

        // Blog 1 must never be deleted by subsite deletion cleanup
        Plugin::cleanup_deleted_multisite_blog(1);
        $this->assertFileExists($main_vault . '/keep.json');

        // Subsite 7 must be purged cleanly
        $GLOBALS['wpdb'] = new class extends \wpdb {
            public function get_blog_prefix($blog_id = null): string {
                return 'wp_' . (int) $blog_id . '_';
            }
        };
        Plugin::cleanup_deleted_multisite_blog((object) ['blog_id' => 7]);
        $this->assertDirectoryDoesNotExist(rtrim((string) $content_base, '/\\') . '/webcare-waf/sites/7');
        $this->assertFileExists($main_vault . '/keep.json');
    }

    public function test_zero_waste_loading_and_migration_indexes_and_uninstall_defaults(): void {
        $root       = dirname(__DIR__, 2) . '/';
        $plugin_src = (string) file_get_contents($root . 'includes/Plugin.php');
        $this->assertStringContainsString("wp_delete_site", $plugin_src);
        $this->assertStringContainsString("WafCliCommand::register()", $plugin_src);
        $this->assertStringContainsString("\$is_admin || \$is_cron || \$is_cli", $plugin_src);

        $migration_src = (string) file_get_contents($root . 'includes/Database/Migration.php');
        foreach (['status_created', 'scan_status', 'scan_severity', 'sha256', 'status_quarantined', 'action_created', 'user_login_time'] as $idx) {
            $this->assertStringContainsString($idx, $migration_src, "Expected composite index {$idx} in Migration.php");
        }

        $uninstall_src = (string) file_get_contents($root . 'uninstall.php');
        $this->assertStringContainsString('$webcareproscan_delete_data = false;', $uninstall_src);
        $this->assertStringContainsString("'/webcare-waf'", $uninstall_src);
    }

    public function test_waf_cli_commands_manage_status_allowlist_and_unblock(): void {
        $GLOBALS['wp_mock_current_user_can'] = true;

        // Avoid defining global constant WP_CLI across in-process PHPUnit tests so WAF/DLP runtime guards stay active for subsequent tests.
        if (!class_exists('\\WP_CLI')) {
            eval('
                class WP_CLI {
                    public static array $messages = [];
                    public static function add_command($name, $callable) {}
                    public static function line($msg) { self::$messages[] = "LINE:" . $msg; }
                    public static function success($msg) { self::$messages[] = "SUCCESS:" . $msg; }
                    public static function warning($msg) { self::$messages[] = "WARNING:" . $msg; }
                    public static function error($msg) { self::$messages[] = "ERROR:" . $msg; }
                }
            ');
        }

        \WP_CLI::$messages = [];
        WafCliCommand::cmd_status([], ['format' => 'json']);
        $json = str_replace('LINE:', '', \WP_CLI::$messages[0] ?? '');
        $decoded = json_decode($json, true);
        $this->assertIsArray($decoded);
        $this->assertArrayHasKey('waf_enabled', $decoded);

        \WP_CLI::$messages = [];
        WafCliCommand::cmd_allowlist(['add', '198.51.100.77']);
        $settings = SettingsManager::get_settings();
        $this->assertStringContainsString('198.51.100.77', (string) ($settings['waf_whitelisted_ips'] ?? ''));

        \WP_CLI::$messages = [];
        WafCliCommand::cmd_allowlist(['remove', '198.51.100.77']);
        $settings = SettingsManager::get_settings();
        $this->assertStringNotContainsString('198.51.100.77', (string) ($settings['waf_whitelisted_ips'] ?? ''));

        BlocklistRepository::block_ip('203.0.113.88', 'cli_test', 3600, false);
        $this->assertTrue(BlocklistRepository::is_ip_blocked('203.0.113.88'));

        \WP_CLI::$messages = [];
        WafCliCommand::cmd_unblock(['203.0.113.88']);
        $this->assertFalse(BlocklistRepository::is_ip_blocked('203.0.113.88'));
    }
}
