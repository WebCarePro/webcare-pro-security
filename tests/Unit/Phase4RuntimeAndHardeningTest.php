<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Admin\DashboardWidget;
use WebCareProScanner\Content\BlockDirectiveSanitizer;
use WebCareProScanner\Firewall\FirewallEngine;
use WebCareProScanner\Firewall\RescueAssistantManager;
use WebCareProScanner\Notifications\NotificationDispatcher;
use WebCareProScanner\Notifications\WebhookService;
use WebCareProScanner\System\ActivityLogs\ActivityRetention;
use WebCareProScanner\System\ActivityLogs\ActivityStorage;
use WebCareProScanner\System\CrashGuard;
use WebCareProScanner\System\Cron\CronControlCenter;
use WebCareProScanner\System\SettingsManager;

class Phase4RuntimeAndHardeningTest extends TestCase {

    protected function setUp(): void {
        parent::setUp();
        webcare_purge_test_storage();
        FirewallEngine::reset_client_ip_cache();
        SettingsManager::reset_settings_cache();
        $GLOBALS['wp_mock_options']      = [];
        $GLOBALS['wp_mock_transients']   = [];
        $GLOBALS['wp_mock_users']        = [];
        $GLOBALS['wp_mock_current_user'] = null;
        $GLOBALS['wpdb']                 = new \wpdb();
        unset($GLOBALS['wp_mock_current_user_can'], $GLOBALS['wp_mock_current_user_can_callback']);
        $_SERVER['REMOTE_ADDR']          = '203.0.113.10';
        unset($_SERVER['HTTP_CF_CONNECTING_IP'], $_SERVER['HTTP_X_FORWARDED_FOR']);
    }

    protected function tearDown(): void {
        unset($GLOBALS['wp_mock_current_user_can'], $GLOBALS['wp_mock_current_user_can_callback']);
        webcare_purge_test_storage();
        FirewallEngine::reset_client_ip_cache();
        SettingsManager::reset_settings_cache();
        parent::tearDown();
    }

    public function test_dashboard_widget_renders_without_missing_rescue_class_or_method(): void {
        $admin_user = new \WP_User(1, 'admin');
        $admin_user->roles = ['administrator'];
        $GLOBALS['wp_mock_users'][1]     = $admin_user;
        $GLOBALS['wp_mock_current_user'] = $admin_user;
        $GLOBALS['wp_mock_current_user_can'] = true;

        $pause_res = RescueAssistantManager::pause_strict_firewall_15m();
        $this->assertTrue(!empty($pause_res['paused']));

        ob_start();
        try {
            DashboardWidget::render();
            $html = (string) ob_get_contents();
        } finally {
            ob_end_clean();
        }

        $this->assertStringContainsString('Blocked Today', $html);
        $this->assertStringContainsString('Open Security Dashboard', $html);
        $this->assertStringContainsString('webcare-status-safe', $html);
    }

    public function test_activity_retention_prune_returns_bool_without_void_type_error(): void {
        $dir = ActivityStorage::get_log_dir();
        foreach ((array) glob($dir . '/activity-*.json.php') as $existing) {
            if (is_string($existing) && file_exists($existing)) {
                @unlink($existing);
            }
        }
        $expired_date = gmdate('Y-m-d', strtotime('-120 days'));
        $expired_file = $dir . '/activity-' . $expired_date . '-001.json.php';
        file_put_contents($expired_file, '');

        $res = ActivityRetention::prune_expired_partitions();
        $this->assertSame(1, $res['pruned_count']);
        $this->assertContains('activity-' . $expired_date . '-001.json.php', $res['files']);
        $this->assertFileDoesNotExist($expired_file);
    }

    public function test_cron_control_center_prunes_activity_partitions_on_retention_task(): void {
        SettingsManager::save_settings(['waf_log_retention_days' => 0]);

        $dir = ActivityStorage::get_log_dir();
        $expired_date = gmdate('Y-m-d', strtotime('-150 days'));
        $expired_file = $dir . '/activity-' . $expired_date . '-002.json.php';
        file_put_contents($expired_file, '');

        $result = CronControlCenter::invoke_task_handler('webcareproscan_waf_log_retention_prune', 'wp_cron');
        $this->assertSame('success', $result['status'] ?? '');
        $this->assertSame(1, (int) ($result['metrics']['activity_pruned'] ?? 0));
        $this->assertFileDoesNotExist($expired_file);
    }

    public function test_block_directive_sanitizer_catches_obfuscated_prototype_and_bind_payloads(): void {
        $html_payload = '<div data-wp-context=\'{"\\u005f\\u005fproto\\u005f\\u005f":{"isAdmin":true}}\' '
            . 'data-wp-bind--formaction="&#x6a;avascript:alert(1)" '
            . 'data-wp-bind--srcdoc=javascript:alert(2) '
            . 'data-wp-bind--href="https://example.com/safe">Test</div>';

        $audit = BlockDirectiveSanitizer::audit_content($html_payload);
        $types = array_column($audit, 'type');
        $this->assertContains('interactivity_context_prototype_pollution', $types);
        $this->assertContains('interactivity_hostile_attribute_bind', $types);

        $sanitized = BlockDirectiveSanitizer::sanitize_content($html_payload);
        $this->assertTrue($sanitized['modified']);
        $this->assertStringContainsString('data-wp-context="{}"', $sanitized['content']);
        $this->assertStringNotContainsString('formaction', $sanitized['content']);
        $this->assertStringNotContainsString('srcdoc', $sanitized['content']);
        $this->assertStringContainsString('data-wp-bind--href="https://example.com/safe"', $sanitized['content']);
    }

    public function test_webhook_service_blocks_ssrf_targets_and_redacts_secrets(): void {
        $ssrf_targets = [
            'http://hooks.slack.com/services/T1/B1/X1',
            'https://169.254.169.254/latest/meta-data/',
            'https://127.0.0.1/internal-hook',
            'https://[::1]/internal-hook',
            'https://10.0.0.5/webhook',
            'https://192.168.1.10/webhook',
            'https://172.16.0.4/webhook',
            'https://service.internal/webhook',
            'https://printer.local/webhook',
            'https://0x7f000001/webhook',
        ];
        foreach ($ssrf_targets as $url) {
            $check = WebhookService::validate_webhook_target($url);
            $this->assertFalse($check['valid'], "Expected SSRF target rejected: {$url}");
        }

        $valid_check = WebhookService::validate_webhook_target('https://hooks.slack.com/services/T000/B000/XXXX');
        $this->assertTrue($valid_check['valid']);

        $dirty = [
            'message' => 'Alert leaked OpenAI sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ123456 token',
        ];
        $cleaned = WebhookService::sanitize_webhook_payload($dirty);
        $this->assertStringNotContainsString('sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ123456', $cleaned['message']);
    }

    public function test_notification_dispatcher_enqueues_live_webhooks_without_blocking(): void {
        SettingsManager::save_settings([
            'notification_master_enabled' => true,
            'slack_enabled'               => true,
            'slack_webhook_url'           => 'https://hooks.slack.com/services/T000/B000/LIVE123',
            'notification_events'         => [
                'scan_threats_found' => ['email' => false, 'webhook' => true],
            ],
        ]);

        $res = NotificationDispatcher::trigger('scan_threats_found', [
            'message' => 'Critical backdoor signature found',
        ]);

        $this->assertTrue((bool) $res['webhook']);
        $queue = get_option('webcareproscan_async_webhook_queue', []);
        $this->assertNotEmpty($queue);
        $this->assertSame('https://hooks.slack.com/services/T000/B000/LIVE123', $queue[0]['url']);
    }

    public function test_crash_guard_redacts_secret_files_and_rejects_untrusted_proxy_ip(): void {
        $extract_method = new \ReflectionMethod(CrashGuard::class, 'extract_code_context');
        $extract_method->setAccessible(true);

        $wp_config_tmp = sys_get_temp_dir() . '/wp-config.php';
        file_put_contents($wp_config_tmp, "<?php\ndefine('DB_PASSWORD', 'super-secret-db-pass');\n");
        $this->assertSame([], $extract_method->invoke(null, $wp_config_tmp, 2));
        @unlink($wp_config_tmp);

        $normal_tmp = sys_get_temp_dir() . '/wcp-crash-sample.php';
        file_put_contents($normal_tmp, "<?php\n\$api_key = 'secret-api-value-12345';\nthrow new Exception('boom');\n");
        $snippet = $extract_method->invoke(null, $normal_tmp, 3);
        @unlink($normal_tmp);
        $joined = implode("\n", array_column($snippet, 'content'));
        $this->assertStringNotContainsString('secret-api-value-12345', $joined);

        $_SERVER['REMOTE_ADDR']          = '198.51.100.25';
        $_SERVER['HTTP_CF_CONNECTING_IP'] = '1.2.3.4';
        $ip_method = new \ReflectionMethod(CrashGuard::class, 'get_sanitized_ip');
        $ip_method->setAccessible(true);
        $this->assertSame('198.51.100.25', $ip_method->invoke(null));
    }

    public function test_solo_freelancer_copy_and_updater_ui_removal(): void {
        $root = dirname(__DIR__, 2) . '/';
        $scheduler_src = (string) file_get_contents($root . 'includes/System/Scheduler.php');
        $this->assertStringNotContainsString('we keep your online presence', $scheduler_src);
        $this->assertStringContainsString('Mir Alamin (WebCare Pro)', $scheduler_src);
        $this->assertStringContainsString("esc_url(\$admin_url)", $scheduler_src);

        $export_src = (string) file_get_contents($root . 'src/exportUtils.ts');
        $this->assertStringNotContainsString('we keep your online presence', $export_src);

        $settings_src = (string) file_get_contents($root . 'src/SettingsPage.tsx');
        $this->assertStringNotContainsString('/updater/status', $settings_src);
        $this->assertStringNotContainsString("activeSubTab === 'updates'", $settings_src);
    }
}
