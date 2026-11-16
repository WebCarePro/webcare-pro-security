<?php
/**
 * Regression coverage for server-side remediation authorization, cache traversal completeness,
 * threat-score weight validation, and Argon 4 security review fixes.
 *
 * Run with PHP against a disposable WordPress installation. WEBCARE_TEST_WP_LOAD may override
 * the default local Docker path.
 */

$wp_load = getenv('WEBCARE_TEST_WP_LOAD') ?: '/var/www/html/wp-load.php';
if (!is_file($wp_load)) {
    fwrite(STDERR, "WordPress bootstrap not found. Set WEBCARE_TEST_WP_LOAD to wp-load.php.\n");
    exit(2);
}
$plugin_root = getenv('WEBCARE_PLUGIN_ROOT') ?: dirname(__DIR__);

require_once $wp_load;
require_once ABSPATH . 'wp-admin/includes/user.php';
require_once $plugin_root . '/includes/WordPress/UserRemediationManager.php';
require_once $plugin_root . '/includes/Filesystem/DirectoryWalker.php';
require_once $plugin_root . '/includes/Scan/ScanState.php';
require_once $plugin_root . '/includes/Scan/ScanManager.php';
require_once $plugin_root . '/includes/Firewall/CAF/ThreatScoreTracker.php';
require_once $plugin_root . '/includes/Firewall/NextGen/RuntimeSqlRaspEngine.php';
require_once $plugin_root . '/includes/Firewall/HoneyTokenEngine.php';
require_once $plugin_root . '/includes/Firewall/Core/ExploitSignatureEngine.php';
require_once $plugin_root . '/includes/Firewall/MicroWafCompiler.php';

use WebCareProScanner\Filesystem\DirectoryWalker;
use WebCareProScanner\Firewall\CAF\ThreatScoreTracker;
use WebCareProScanner\Scan\ScanManager;
use WebCareProScanner\Scan\ScanState;
use WebCareProScanner\WordPress\UserRemediationManager;

$passed = 0;
$failed = 0;
$skipped = 0;

function run_review_followup_test(string $name, callable $test): void {
    global $passed, $failed;
    try {
        if ($test()) {
            echo "[PASS] {$name}\n";
            $passed++;
        } else {
            echo "[FAIL] {$name}\n";
            $failed++;
        }
    } catch (Throwable $exception) {
        echo '[ERROR] ' . $name . ': ' . $exception->getMessage() . "\n";
        $failed++;
    }
}

function skip_review_followup_test(string $name, string $reason): void {
    global $skipped;
    echo "[SKIP] {$name}: {$reason}\n";
    $skipped++;
}

$previous_user_id = get_current_user_id();
$fixture_user_ids = [];
$manager = null;
$backup_directory = untrailingslashit(wp_upload_dir()['basedir']) . '/webcare-pro-security/.backups/remediation';
$backup_directory_existed = is_dir($backup_directory);

try {
    $admins = get_users(['role' => 'administrator', 'number' => 1]);
    if (empty($admins) || !user_can($admins[0], 'manage_options')) {
        throw new RuntimeException('A manage_options administrator is required to run this integration suite.');
    }
    $admin_id = (int) $admins[0]->ID;
    wp_set_current_user($admin_id);

    $create_fixture_user = static function (string $role) use (&$fixture_user_ids): int {
        $suffix = bin2hex(random_bytes(5));
        $user_id = wp_create_user('wcp_review_' . $suffix, wp_generate_password(24), 'wcp_review_' . $suffix . '@example.test');
        if (is_wp_error($user_id)) {
            throw new RuntimeException('Could not create a temporary user fixture.');
        }
        $fixture_user_ids[] = (int) $user_id;
        $user = get_userdata((int) $user_id);
        if (!$user instanceof WP_User) {
            throw new RuntimeException('Temporary user fixture could not be loaded.');
        }
        $user->set_role($role);
        return (int) $user_id;
    };

    $subscriber_id = $create_fixture_user('subscriber');
    $editor_id = $create_fixture_user('editor');
    $deleted_user_id = $create_fixture_user('subscriber');
    if (!wp_delete_user($deleted_user_id)) {
        throw new RuntimeException('Could not delete the missing-user fixture.');
    }
    $fixture_user_ids = array_values(array_diff($fixture_user_ids, [$deleted_user_id]));

    wp_set_current_user($previous_user_id);
    $manager = new UserRemediationManager();
    $orphaned_author_id = 2000000000 + random_int(1, 100000);

    run_review_followup_test('SQL RASP keeps third-party REST inspection enabled when its query spoofs the WebCare route', static function (): bool {
        $saved_request_uri = $_SERVER['REQUEST_URI'] ?? null;
        $saved_path_info = $_SERVER['PATH_INFO'] ?? null;
        $saved_php_self = $_SERVER['PHP_SELF'] ?? null;
        $saved_request_method = $_SERVER['REQUEST_METHOD'] ?? null;
        $saved_get = $_GET;
        $saved_user_id = get_current_user_id();
        try {
            wp_set_current_user(0);
            $_SERVER['REQUEST_URI'] = '/wp-json/third-party/v1/item?_wcp=/wp-json/webcare-pro-security/v1/settings';
            unset($_SERVER['PATH_INFO'], $_SERVER['PHP_SELF']);
            $_GET = ['_wcp' => '/wp-json/webcare-pro-security/v1/settings'];
            $spoofed_route_is_protected = \WebCareProScanner\Firewall\NextGen\RuntimeSqlRaspEngine::is_guest_plugin_surface();

            $_SERVER['REQUEST_URI'] = '/index.php';
            $_SERVER['PATH_INFO'] = '/wp-json/third-party/v1/item';
            $_SERVER['PHP_SELF'] = '/index.php';
            $_GET = [];
            $path_info_route_is_protected = \WebCareProScanner\Firewall\NextGen\RuntimeSqlRaspEngine::is_guest_plugin_surface();

            $_SERVER['REQUEST_URI'] = '/wp-json/webcare-pro-security/v1/settings';
            unset($_SERVER['PATH_INFO'], $_SERVER['PHP_SELF']);
            $_GET = [];
            $own_route_is_exempt = !\WebCareProScanner\Firewall\NextGen\RuntimeSqlRaspEngine::is_guest_plugin_surface();

            $_SERVER['REQUEST_URI'] = '/xmlrpc.php';
            $xmlrpc_is_protected = \WebCareProScanner\Firewall\NextGen\RuntimeSqlRaspEngine::is_guest_plugin_surface();

            $_SERVER['REQUEST_URI'] = '/';
            $_GET = ['wc-ajax' => 'checkout'];
            $wc_ajax_is_protected = \WebCareProScanner\Firewall\NextGen\RuntimeSqlRaspEngine::is_guest_plugin_surface();

            return $spoofed_route_is_protected && $path_info_route_is_protected && $own_route_is_exempt && $xmlrpc_is_protected && $wc_ajax_is_protected;
        } finally {
            wp_set_current_user($saved_user_id);
            $_GET = $saved_get;
            foreach (['REQUEST_URI' => $saved_request_uri, 'PATH_INFO' => $saved_path_info, 'PHP_SELF' => $saved_php_self, 'REQUEST_METHOD' => $saved_request_method] as $key => $value) {
                if ($value === null) {
                    unset($_SERVER[$key]);
                } else {
                    $_SERVER[$key] = $value;
                }
            }
        }
    });

    run_review_followup_test('Unauthenticated deletion of administrator capabilities and application passwords is blocked', static function () use ($admin_id): bool {
        global $wpdb;
        $saved_user_id = get_current_user_id();
        $saved_remote_addr = $_SERVER['REMOTE_ADDR'] ?? null;
        $caps_key = $wpdb->get_blog_prefix($admin_id) . 'capabilities';
        try {
            wp_set_current_user(0);
            $_SERVER['REMOTE_ADDR'] = '198.51.100.217';
            \WebCareProScanner\Firewall\FirewallEngine::reset_client_ip_cache();
            add_filter('delete_user_metadata', [\WebCareProScanner\Firewall\FirewallEngine::class, 'rasp_guard_user_metadata_deletion'], 1, 5);
            $caps_deleted = delete_user_meta($admin_id, $caps_key);
            $application_passwords_deleted = delete_user_meta($admin_id, '_application_passwords');
            return $caps_deleted === false
                && $application_passwords_deleted === false
                && user_can($admin_id, 'manage_options');
        } finally {
            remove_filter('delete_user_metadata', [\WebCareProScanner\Firewall\FirewallEngine::class, 'rasp_guard_user_metadata_deletion'], 1);
            wp_set_current_user($saved_user_id);
            if ($saved_remote_addr === null) {
                unset($_SERVER['REMOTE_ADDR']);
            } else {
                $_SERVER['REMOTE_ADDR'] = $saved_remote_addr;
            }
            \WebCareProScanner\Firewall\FirewallEngine::reset_client_ip_cache();
        }
    });

    run_review_followup_test('Direct role API hooks reverse unauthorized administrator additions and removals', static function () use ($admin_id, $create_fixture_user): bool {
        $saved_user_id = get_current_user_id();
        $saved_remote_addr = $_SERVER['REMOTE_ADDR'] ?? null;
        $unauthorized_user_id = $create_fixture_user('subscriber');
        $wp_die_calls = 0;
        $test_die_handler = static function ($message = '', $title = '', $args = []) use (&$wp_die_calls): void {
            $wp_die_calls++;
            throw new RuntimeException('Expected role API RASP denial.');
        };
        $handler_filter = static function ($handler) use ($test_die_handler) {
            return $test_die_handler;
        };
        $blocked_add = false;
        $blocked_remove = false;
        try {
            wp_set_current_user(0);
            $_SERVER['REMOTE_ADDR'] = '198.51.100.218';
            \WebCareProScanner\Firewall\FirewallEngine::reset_client_ip_cache();
            add_filter('wp_die_handler', $handler_filter, PHP_INT_MAX);

            try {
                get_userdata($unauthorized_user_id)->add_role('administrator');
            } catch (RuntimeException $exception) {
                if ($exception->getMessage() !== 'Expected role API RASP denial.') {
                    throw $exception;
                }
                $blocked_add = true;
            }

            try {
                get_userdata($admin_id)->remove_role('administrator');
            } catch (RuntimeException $exception) {
                if ($exception->getMessage() !== 'Expected role API RASP denial.') {
                    throw $exception;
                }
                $blocked_remove = true;
            }

            $unauthorized_user = get_userdata($unauthorized_user_id);
            return $blocked_add
                && $blocked_remove
                && $wp_die_calls === 2
                && $unauthorized_user instanceof WP_User
                && !in_array('administrator', $unauthorized_user->roles, true)
                && user_can($admin_id, 'manage_options');
        } finally {
            remove_filter('wp_die_handler', $handler_filter, PHP_INT_MAX);
            wp_set_current_user($saved_user_id);
            if ($saved_remote_addr === null) {
                unset($_SERVER['REMOTE_ADDR']);
            } else {
                $_SERVER['REMOTE_ADDR'] = $saved_remote_addr;
            }
            \WebCareProScanner\Firewall\FirewallEngine::reset_client_ip_cache();
        }
    });

    run_review_followup_test('Restricted JavaScript and INI uploads are rejected and scored without an IP ban', static function (): bool {
        $saved_remote_addr = $_SERVER['REMOTE_ADDR'] ?? null;
        $test_ips = ['198.51.100.221', '198.51.100.222'];
        $extensions = ['js', 'ini'];
        $all_rejected_and_scored = true;
        try {
            foreach ($test_ips as $index => $test_ip) {
                $_SERVER['REMOTE_ADDR'] = $test_ip;
                \WebCareProScanner\Firewall\FirewallEngine::reset_client_ip_cache();
                ThreatScoreTracker::reset_ip($test_ip);
                $upload = \WebCareProScanner\Firewall\Core\ExploitSignatureEngine::inspect_uploaded_file([
                    'name'     => 'review-fixture.' . $extensions[$index],
                    'tmp_name' => __FILE__,
                    'type'     => 'application/octet-stream',
                    'error'    => UPLOAD_ERR_OK,
                    'size'     => 1,
                ]);
                $preflight_upload = \WebCareProScanner\Firewall\Core\ExploitSignatureEngine::inspect_uploaded_file([
                    'name'     => 'review-fixture.' . $extensions[$index],
                    'tmp_name' => __FILE__,
                    'type'     => 'application/octet-stream',
                    'error'    => UPLOAD_ERR_OK,
                    'size'     => 1,
                ], false);
                $preflight_tier = \WebCareProScanner\Firewall\FirewallEngine::get_rule_enforcement_tier([
                    'id'       => $preflight_upload['rule_id'] ?? '',
                    'category' => $preflight_upload['category'] ?? '',
                    'detector' => $preflight_upload['detector'] ?? '',
                    'sig_id'   => $preflight_upload['sig_id'] ?? '',
                ]);
                $blocked_ips = (string) \WebCareProScanner\System\SettingsManager::get('waf_blocked_ips', '');
                $all_rejected_and_scored = $all_rejected_and_scored
                    && !empty($upload['error'])
                    && !empty($preflight_upload['error'])
                    && ($preflight_upload['rule_id'] ?? '') === 'WAF-RESTRICTED-UPLOAD-EXTENSION'
                    && $preflight_tier === \WebCareProScanner\Firewall\FirewallEngine::TIER_HEURISTIC
                    && ThreatScoreTracker::get_current_score($test_ip) >= 15.0
                    && !in_array($test_ip, preg_split('/\r\n|\r|\n/', $blocked_ips), true);
            }
            return $all_rejected_and_scored;
        } finally {
            foreach ($test_ips as $test_ip) {
                ThreatScoreTracker::reset_ip($test_ip);
            }
            if ($saved_remote_addr === null) {
                unset($_SERVER['REMOTE_ADDR']);
            } else {
                $_SERVER['REMOTE_ADDR'] = $saved_remote_addr;
            }
            \WebCareProScanner\Firewall\FirewallEngine::reset_client_ip_cache();
        }
    });

    run_review_followup_test('POST form honeypots still record prefetch-marked submissions', static function (): bool {
        $saved_user_id = get_current_user_id();
        $saved_post = $_POST;
        $saved_server = [];
        foreach (['REQUEST_METHOD', 'HTTP_SEC_PURPOSE', 'REMOTE_ADDR', 'REQUEST_URI'] as $key) {
            $saved_server[$key] = $_SERVER[$key] ?? null;
        }
        $saved_catches = get_option(\WebCareProScanner\Firewall\HoneyTokenEngine::OPTION_CATCHES, false);
        $test_ip = '198.51.100.219';
        $hit_transient = 'webcare_honeypot_form_hit_' . md5($test_ip);
        delete_transient($hit_transient);
        try {
            wp_set_current_user(0);
            $_SERVER['REQUEST_METHOD'] = 'POST';
            $_SERVER['HTTP_SEC_PURPOSE'] = 'prefetch';
            $_SERVER['REMOTE_ADDR'] = $test_ip;
            \WebCareProScanner\Firewall\FirewallEngine::reset_client_ip_cache();
            $_POST = [
                \WebCareProScanner\Firewall\HoneyTokenEngine::FIELD_FLAG => '1',
                \WebCareProScanner\Firewall\HoneyTokenEngine::FIELD_NAME => 'automated fixture',
            ];
            $result = \WebCareProScanner\Firewall\HoneyTokenEngine::inspect_auth_honeytoken(null, 'fixture-user', 'invalid-password');
            $form_catch_recorded = is_wp_error($result)
                && $result->get_error_code() === 'honeypot_triggered'
                && (int) get_transient($hit_transient) === 1;
            $catch_count_after_form = count((array) get_option(\WebCareProScanner\Firewall\HoneyTokenEngine::OPTION_CATCHES, []));
            $_SERVER['REQUEST_METHOD'] = 'GET';
            $_SERVER['REQUEST_URI'] = '/.well-known/webcare-security-decoy';
            \WebCareProScanner\Firewall\HoneyTokenEngine::check_phantom_endpoints();
            $catch_count_after_prefetch = count((array) get_option(\WebCareProScanner\Firewall\HoneyTokenEngine::OPTION_CATCHES, []));
            return $form_catch_recorded && $catch_count_after_prefetch === $catch_count_after_form;
        } finally {
            wp_set_current_user($saved_user_id);
            $_POST = $saved_post;
            delete_transient($hit_transient);
            if ($saved_catches === false) {
                delete_option(\WebCareProScanner\Firewall\HoneyTokenEngine::OPTION_CATCHES);
            } else {
                update_option(\WebCareProScanner\Firewall\HoneyTokenEngine::OPTION_CATCHES, $saved_catches, false);
            }
            foreach ($saved_server as $key => $value) {
                if ($value === null) {
                    unset($_SERVER[$key]);
                } else {
                    $_SERVER[$key] = $value;
                }
            }
            \WebCareProScanner\Firewall\FirewallEngine::reset_client_ip_cache();
        }
    });

    run_review_followup_test('Nested plugin cache directories remain visible to the main filesystem walker', static function (): bool {
        $cache_root = sys_get_temp_dir() . '/wcp_plugin_cache_review_' . bin2hex(random_bytes(6));
        $executable = $cache_root . '/wp-content/plugins/test-plugin/cache/shell.php';
        wp_mkdir_p(dirname($executable));
        $created = file_put_contents($executable, '<?php echo "fixture";') !== false;
        try {
            $batch = (new DirectoryWalker())->get_batch($cache_root, [], 100);
            $normalized_files = array_map(static function ($path): string {
                return str_replace('\\', '/', $path);
            }, $batch['files']);
            return $created && in_array(str_replace('\\', '/', $executable), $normalized_files, true);
        } finally {
            if (is_file($executable)) {
                wp_delete_file($executable);
            }
            foreach ([
                dirname($executable),
                dirname(dirname($executable)),
                dirname(dirname(dirname($executable))),
                $cache_root . '/wp-content/plugins',
                $cache_root . '/wp-content',
                $cache_root,
            ] as $directory) {
                if (is_dir($directory)) {
                    @rmdir($directory);
                }
            }
        }
    });

    run_review_followup_test('Preload Micro-WAF includes bounded request bodies and normalized server paths', static function (): bool {
        $compiler = new ReflectionClass(\WebCareProScanner\Firewall\MicroWafCompiler::class);
        $generator = $compiler->getMethod('generate_standalone_code');
        $generator->setAccessible(true);
        $source = $generator->invoke(null, [], [], sys_get_temp_dir() . '/webcare-preload-test.log', 'test-token');
        try {
            token_get_all($source, TOKEN_PARSE);
        } catch (ParseError $exception) {
            return false;
        }
        return str_contains($source, 'php://input')
            && str_contains($source, '32768')
            && str_contains($source, 'PATH_INFO')
            && str_contains($source, 'PHP_SELF')
            && str_contains($source, 'collect_preload_post');
    });

    run_review_followup_test('Preload Micro-WAF defers request body inspection for authenticated sessions', static function (): bool {
        $compiler = new ReflectionClass(\WebCareProScanner\Firewall\MicroWafCompiler::class);
        $generator = $compiler->getMethod('generate_standalone_code');
        $generator->setAccessible(true);
        $source = $generator->invoke(null, [], [], sys_get_temp_dir() . '/webcare-preload-test.log', 'test-token');
        return str_contains($source, '!$mod_has_login_cookie && in_array($mod_req_method');
    });

    run_review_followup_test('Orphaned-post reassignment rejects a missing target ID', static function () use ($manager, $orphaned_author_id): bool {
        $result = $manager->reassign_orphaned_posts($orphaned_author_id, null);
        return empty($result['success']) && str_contains($result['error'] ?? '', 'explicit administrator');
    });

    run_review_followup_test('Orphaned-post reassignment rejects a non-positive target ID', static function () use ($manager, $orphaned_author_id): bool {
        $result = $manager->reassign_orphaned_posts($orphaned_author_id, 0);
        return empty($result['success']) && str_contains($result['error'] ?? '', 'explicit administrator');
    });

    run_review_followup_test('Orphaned-post reassignment rejects a subscriber target', static function () use ($manager, $orphaned_author_id, $subscriber_id): bool {
        $result = $manager->reassign_orphaned_posts($orphaned_author_id, $subscriber_id);
        return empty($result['success']) && str_contains($result['error'] ?? '', 'manage_options');
    });

    run_review_followup_test('Orphaned-post reassignment rejects an editor target', static function () use ($manager, $orphaned_author_id, $editor_id): bool {
        $result = $manager->reassign_orphaned_posts($orphaned_author_id, $editor_id);
        return empty($result['success']) && str_contains($result['error'] ?? '', 'manage_options');
    });

    run_review_followup_test('Orphaned-post reassignment rejects a deleted target', static function () use ($manager, $orphaned_author_id, $deleted_user_id): bool {
        $result = $manager->reassign_orphaned_posts($orphaned_author_id, $deleted_user_id);
        return empty($result['success']) && str_contains($result['error'] ?? '', 'not found');
    });

    run_review_followup_test('Orphaned-post reassignment accepts an explicit administrator', static function () use ($manager, $orphaned_author_id, $admin_id): bool {
        $result = $manager->reassign_orphaned_posts($orphaned_author_id, $admin_id);
        return !empty($result['success'])
            && (int) ($result['target_user_id'] ?? 0) === $admin_id
            && (int) ($result['reassigned_count'] ?? -1) === 0;
    });

    $cache_root = sys_get_temp_dir() . '/wcp_cache_review_' . bin2hex(random_bytes(6));
    $blocked_cache_dir = $cache_root . '/wp-content/cache/unreadable';
    wp_mkdir_p($blocked_cache_dir);
    chmod($blocked_cache_dir, 0000);
    clearstatcache(true, $blocked_cache_dir);
    if (!is_readable($blocked_cache_dir)) {
        $cache_scan_meta = [];
        run_review_followup_test('Cache traversal errors mark inspection incomplete without claiming budget truncation', static function () use ($cache_root, &$cache_scan_meta): bool {
            $cache_scan_meta = [];
            $walker = new DirectoryWalker();
            $walker->scan_cache_dirs_for_executables($cache_root, 5, $cache_scan_meta);
            return (int) ($cache_scan_meta['traversal_errors'] ?? 0) > 0
                && empty($cache_scan_meta['truncated'])
                && empty($cache_scan_meta['complete']);
        });
    } else {
        skip_review_followup_test('Cache traversal permission-error fixture', 'this PHP process can still read mode-000 directories');
    }
    chmod($blocked_cache_dir, 0700);
    clearstatcache(true, $blocked_cache_dir);
    rmdir($blocked_cache_dir);
    rmdir(dirname($blocked_cache_dir));
    rmdir(dirname(dirname($blocked_cache_dir)));
    rmdir($cache_root);

    $depth_cache_root = sys_get_temp_dir() . '/wcp_cache_depth_review_' . bin2hex(random_bytes(6));
    $deep_directory = $depth_cache_root . '/wp-content/cache/level-2/level-3/level-4/level-5/level-6';
    $deep_executable = $deep_directory . '/depth-hidden.php';
    wp_mkdir_p($deep_directory);
    $deep_executable_created = file_put_contents($deep_executable, '<?php echo "fixture";') !== false;
    $depth_scan_meta = [];
    $depth_found = (new DirectoryWalker())->scan_cache_dirs_for_executables($depth_cache_root, 5, $depth_scan_meta);
    run_review_followup_test('Executable below the recursion limit is omitted but marks cache inspection incomplete', static function () use ($deep_executable_created, $depth_scan_meta, $depth_found, $deep_executable): bool {
        return $deep_executable_created
            && !in_array(str_replace('\\', '/', $deep_executable), array_map(static function ($path): string {
            return str_replace('\\', '/', $path);
        }, $depth_found), true)
            && (int) ($depth_scan_meta['depth_limited'] ?? 0) > 0
            && empty($depth_scan_meta['truncated'])
            && (int) ($depth_scan_meta['traversal_errors'] ?? 0) === 0
            && empty($depth_scan_meta['complete']);
    });
    wp_delete_file($deep_executable);
    $depth_directories = [
        $depth_cache_root,
        $depth_cache_root . '/wp-content',
        $depth_cache_root . '/wp-content/cache',
        $depth_cache_root . '/wp-content/cache/level-2',
        $depth_cache_root . '/wp-content/cache/level-2/level-3',
        $depth_cache_root . '/wp-content/cache/level-2/level-3/level-4',
        $depth_cache_root . '/wp-content/cache/level-2/level-3/level-4/level-5',
        $deep_directory,
    ];
    foreach (array_reverse($depth_directories) as $directory) {
        if (is_dir($directory)) {
            @rmdir($directory);
        }
    }

    run_review_followup_test('Persisted cache traversal errors and depth limits produce incomplete response warnings', static function (): bool {
        $scan_id = 'review-cache-error-' . bin2hex(random_bytes(5));
        $state = new ScanState($scan_id, 'filesystem', 0, [
            'cache_scan_truncated' => false,
            'cache_scan_errors' => 1,
            'cache_scan_depth_limited' => 2,
            'cache_scan_complete' => false,
        ]);
        $state->save();
        $loaded_state = ScanState::load($scan_id);

        $manager_reflection = new ReflectionClass(ScanManager::class);
        $manager_instance = $manager_reflection->newInstanceWithoutConstructor();
        $response_method = $manager_reflection->getMethod('build_response');
        $response_method->setAccessible(true);
        $response = $response_method->invoke($manager_instance, $loaded_state, [], 0, true);
        delete_transient(ScanState::OPTION_PREFIX . $scan_id);

        return $response['cache_scan_complete'] === false
            && $response['cache_scan_errors'] === 1
            && $response['cache_scan_depth_limited'] === 2
            && count($response['warnings']) === 2
            && str_contains(implode(' ', $response['warnings']), 'excluded one or more subdirectories');
    });

    $ip_base = random_int(10, 180);
    $weight_cases = [
        ['non-finite positive', INF, 10.0],
        ['not-a-number', NAN, 10.0],
        ['negative', -5.0, 0.0],
        ['oversized', 10000.0, ThreatScoreTracker::MAX_CUSTOM_WEIGHT],
        ['valid fractional', 4.5, 4.5],
    ];
    foreach ($weight_cases as $offset => [$label, $weight, $expected_delta]) {
        $ip = '198.51.100.' . ($ip_base + $offset);
        run_review_followup_test('Threat-score custom weight ' . $label . ' is normalized safely', static function () use ($ip, $weight, $expected_delta): bool {
            delete_transient(ThreatScoreTracker::TRANSIENT_PREFIX . substr(md5($ip), 0, 16));
            $result = ThreatScoreTracker::record_event($ip, 'auth_fail', $weight);
            delete_transient(ThreatScoreTracker::TRANSIENT_PREFIX . substr(md5($ip), 0, 16));
            return (float) ($result['delta'] ?? -1) === $expected_delta
                && (float) ($result['score'] ?? 101) <= ThreatScoreTracker::MAX_CUSTOM_WEIGHT
                && ($result['action'] ?? '') !== 'throttle';
        });
    }
} finally {
    wp_set_current_user($admin_id ?? $previous_user_id);
    foreach ($fixture_user_ids as $fixture_user_id) {
        wp_delete_user((int) $fixture_user_id);
    }
    wp_set_current_user($previous_user_id);

    if (!$backup_directory_existed) {
        foreach (['.htaccess', 'index.php'] as $filename) {
            $path = $backup_directory . '/' . $filename;
            if (is_file($path)) {
                wp_delete_file($path);
            }
        }
        @rmdir($backup_directory);
        @rmdir(dirname($backup_directory));
        @rmdir(dirname(dirname($backup_directory)));
    }
}

echo sprintf("RESULTS: %d passed, %d failed, %d skipped\n", $passed, $failed, $skipped);
exit($failed === 0 ? 0 : 1);
