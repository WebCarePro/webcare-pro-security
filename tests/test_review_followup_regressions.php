<?php
/**
 * Regression coverage for server-side remediation authorization, cache traversal completeness,
 * and threat-score weight validation.
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
            && count($response['warnings']) === 2;
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
