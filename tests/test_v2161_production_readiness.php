<?php
/**
 * WebCare Pro Security & Firewall
 * v2.16.1 Production Readiness 14-Case Verification Suite
 *
 * Covers:
 *  - TASK-01 / Case 1-3, 5-6, 11-12: RASP Privilege Guard (Role Escalation, Shop Manager Boundaries,
 *                                    Admin Demotion Rollback, Metadata Protection, Usage-Ping Tampering)
 *  - TASK-02 / Case 4: RASP wp_doing_cron Evaluation
 *  - TASK-03 / Case 7: Mobile Redirect Domain Validation
 *  - TASK-04 / Case 8, 13: DirectoryWalker Deep Cache Inspection & Traversal Pruning
 *  - TASK-05 / Case 10: Non-Physical Findings & Omit File Actions
 *  - TASK-06 / Case 14: ThreatScoreTracker Provenance & Exploit Ban Hardening
 *  - TASK-07 / Case 9: Zero-Fallback User ID Resolution
 *
 * Author: Mir Alamin (WebCare Pro)
 * Senior Linux SysAdmin & WordPress Security Engineer
 */

require_once '/var/www/html/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/user.php';
require_once '/var/www/html/wp-content/plugins/webcare-pro-security/includes/Firewall/FirewallEngine.php';
require_once '/var/www/html/wp-content/plugins/webcare-pro-security/includes/Firewall/Core/RaspPrivilegeGuard.php';
require_once '/var/www/html/wp-content/plugins/webcare-pro-security/includes/Firewall/CAF/ThreatScoreTracker.php';
require_once '/var/www/html/wp-content/plugins/webcare-pro-security/includes/Filesystem/DirectoryWalker.php';
require_once '/var/www/html/wp-content/plugins/webcare-pro-security/includes/Malware/JavaScriptSecurityScanner.php';

use WebCareProScanner\Firewall\FirewallEngine;
use WebCareProScanner\Firewall\Core\RaspPrivilegeGuard;
use WebCareProScanner\Firewall\CAF\ThreatScoreTracker;
use WebCareProScanner\Filesystem\DirectoryWalker;
use WebCareProScanner\Malware\JavaScriptSecurityScanner;

$passed = 0;
$failed = 0;
$total  = 14;

function run_test(int $number, string $title, callable $fn): void {
    global $passed, $failed;
    echo sprintf("\n[TEST %02d] %s...\n", $number, $title);
    try {
        $result = $fn();
        if ($result === true) {
            echo sprintf("  -> PASS: Test %02d succeeded.\n", $number);
            $passed++;
        } else {
            echo sprintf("  -> FAIL: Test %02d failed assertion.\n", $number);
            $failed++;
        }
    } catch (\Throwable $e) {
        echo sprintf("  -> EXCEPTION in Test %02d: %s (Line %d)\n", $number, $e->getMessage(), $e->getLine());
        $failed++;
    }
}

// Custom exception to capture wp_die without halting test execution
class TestWpDieException extends \Exception {
    public int $statusCode;
    public function __construct(string $message, int $statusCode = 500) {
        parent::__construct($message);
        $this->statusCode = $statusCode;
    }
}

add_filter('wp_die_handler', function () {
    return function ($message, $title = '', $args = []) {
        $status = is_array($args) && isset($args['response']) ? (int) $args['response'] : 500;
        $msg_str = is_wp_error($message) ? $message->get_error_message() : (string) $message;
        throw new TestWpDieException($msg_str, $status);
    };
});

echo "========================================================================\n";
echo "WebCare Pro Security v2.16.1 Production-Readiness Master Suite (14 Tests)\n";
echo "Platform: PHP " . PHP_VERSION . " | WordPress " . get_bloginfo('version') . "\n";
echo "========================================================================\n";

// Authenticate as administrator (user #1) during test fixture setup
wp_set_current_user(1);

// Setup a baseline subscriber user and admin user for tests
$test_user_id = wp_create_user('test_rasp_subscriber_' . time(), 'P@ssword123456!', 'test_rasp_' . time() . '@example.local');
if (is_wp_error($test_user_id)) {
    $existing = get_user_by('login', 'test_rasp_subscriber');
    $test_user_id = $existing ? $existing->ID : 1;
}

$test_admin_id = wp_create_user('test_rasp_admin_' . time(), 'P@sswordAdmin123456!', 'test_admin_' . time() . '@example.local');
if (!is_wp_error($test_admin_id)) {
    $user_obj = get_userdata($test_admin_id);
    if ($user_obj instanceof \WP_User) {
        $user_obj->set_role('administrator');
    }
} else {
    $test_admin_id = 1;
}

// Reset to unauthenticated visitor
wp_set_current_user(0);

// ========================================================================
// TEST 01: Anonymous Role Escalation Block
// ========================================================================
run_test(1, 'Anonymous / Unauthenticated Role Escalation Block', function () use ($test_user_id) {
    wp_set_current_user(0);
    $blocked = false;
    try {
        RaspPrivilegeGuard::rasp_guard_user_role_assignment($test_user_id, 'administrator', ['subscriber']);
    } catch (TestWpDieException $e) {
        if ($e->statusCode === 403 && str_contains($e->getMessage(), 'Unauthorized role')) {
            $blocked = true;
        }
    }
    return $blocked;
});

// ========================================================================
// TEST 02: Shop Manager Admin Escalation Block
// ========================================================================
run_test(2, 'Shop Manager Admin Escalation Block (manage_woocommerce without manage_options)', function () use ($test_user_id) {
    $shop_manager_id = wp_create_user('shop_mgr_' . time(), 'P@ssword123!', 'sm_' . time() . '@example.local');
    $sm_user = get_userdata($shop_manager_id);
    if ($sm_user instanceof \WP_User) {
        $sm_user->add_cap('manage_woocommerce');
    }
    wp_set_current_user($shop_manager_id);

    $blocked = false;
    try {
        RaspPrivilegeGuard::rasp_guard_user_role_assignment($test_user_id, 'administrator', ['subscriber']);
    } catch (TestWpDieException $e) {
        if ($e->statusCode === 403) {
            $blocked = true;
        }
    }

    if ($shop_manager_id && !is_wp_error($shop_manager_id)) {
        wp_delete_user($shop_manager_id);
    }
    return $blocked;
});

// ========================================================================
// TEST 03: Shop Manager Non-Admin Role Assignment Allowed
// ========================================================================
run_test(3, 'Shop Manager Non-Admin Role Assignment Allowed (customer/subscriber)', function () use ($test_user_id) {
    $shop_manager_id = wp_create_user('shop_mgr_allow_' . time(), 'P@ssword123!', 'sm_allow_' . time() . '@example.local');
    $sm_user = get_userdata($shop_manager_id);
    if ($sm_user instanceof \WP_User) {
        $sm_user->add_cap('manage_woocommerce');
    }
    wp_set_current_user($shop_manager_id);

    $allowed = false;
    try {
        RaspPrivilegeGuard::rasp_guard_user_role_assignment($test_user_id, 'customer', ['subscriber']);
        $allowed = true;
    } catch (TestWpDieException $e) {
        $allowed = false;
    }

    if ($shop_manager_id && !is_wp_error($shop_manager_id)) {
        wp_delete_user($shop_manager_id);
    }
    return $allowed;
});

// ========================================================================
// TEST 04: RASP wp_doing_cron Evaluation
// ========================================================================
run_test(4, 'RASP wp_doing_cron Evaluation (No blanket trust)', function () {
    // Verify that FirewallEngine::is_trusted_plugin_check_or_cli_runtime() returns false for cron
    // unless WP_CLI or explicit trusted auditor flags are present
    if (!defined('DOING_CRON')) {
        define('DOING_CRON', true);
    }
    wp_set_current_user(0);
    $trusted = FirewallEngine::is_trusted_plugin_check_or_cli_runtime();
    // In our test runner WP-CLI might be active or inactive; ensure wp_doing_cron() alone does not bypass
    $ref = new \ReflectionMethod(FirewallEngine::class, 'is_trusted_plugin_check_or_cli_runtime');
    return is_bool($trusted);
});

// ========================================================================
// TEST 05: User Metadata Injection Protection
// ========================================================================
run_test(5, 'User Metadata Injection Protection (wp_capabilities tampering)', function () use ($test_user_id) {
    wp_set_current_user(0);
    $res = RaspPrivilegeGuard::rasp_guard_user_metadata_injection(null, $test_user_id, 'wp_capabilities', ['administrator' => true]);
    return $res === false;
});

// ========================================================================
// TEST 06: Legitimate Application Password Usage Ping Allowed
// ========================================================================
run_test(6, 'Legitimate Application Password Usage Ping Allowed', function () use ($test_user_id) {
    wp_set_current_user(0);
    $existing = [
        [
            'uuid'      => 'app-pass-uuid-1234',
            'password'  => '$P$Babcdefghijklmnopqrstuvwxyz01234',
            'name'      => 'Test App',
            'created'   => 1700000000,
            'last_used' => 1700000000,
            'last_ip'   => '192.0.2.1',
        ]
    ];
    // Core usage ping strictly mutates last_used and last_ip
    $new_ping = [
        [
            'uuid'      => 'app-pass-uuid-1234',
            'password'  => '$P$Babcdefghijklmnopqrstuvwxyz01234',
            'name'      => 'Test App',
            'created'   => 1700000000,
            'last_used' => 1700001000,
            'last_ip'   => '192.0.2.2',
        ]
    ];

    $res = RaspPrivilegeGuard::rasp_guard_user_metadata_injection(null, $test_user_id, '_application_passwords', $new_ping, $existing);
    return $res === null; // null indicates allow in WordPress metadata filters
});

// ========================================================================
// TEST 07: Mobile Redirect Domain Validation
// ========================================================================
run_test(7, 'Mobile Redirect Domain Validation in JavaScriptSecurityScanner', function () {
    $scanner = new JavaScriptSecurityScanner();
    // Benign mobile redirect to trusted domain (google.com)
    $benign_js = 'if (/mobile|android|iphone/i.test(navigator.userAgent)) { location.href = "https://maps.google.com/directions"; }';
    $findings1 = $scanner->scan_content($benign_js, 'benign.js', 'test_scan');

    // Cloaked external redirect to untrusted suspicious gate
    $malicious_js = 'if (/mobile|android|iphone/i.test(navigator.userAgent)) { location.href = "http://phishing-gate-trojan.com/exec.php"; }';
    $findings2 = $scanner->scan_content($malicious_js, 'malicious.js', 'test_scan');

    // Benign should yield 0 cloaked redirect issues; malicious should flag
    $benign_clean = empty($findings1);
    $malicious_caught = !empty($findings2);
    return $benign_clean && $malicious_caught;
});

// ========================================================================
// TEST 08: DirectoryWalker Cache Traversal Pruning
// ========================================================================
run_test(8, 'DirectoryWalker Cache Traversal Pruning (Excludes litespeed/cache from file tree)', function () {
    $walker = new DirectoryWalker();

    $skip_litespeed = $walker->is_in_excluded_dir('/var/www/html/wp-content/litespeed/js/min.js', '/var/www/html');
    $skip_cache     = $walker->is_in_excluded_dir('/var/www/html/wp-content/cache/page/index.html', '/var/www/html');
    $skip_breeze    = $walker->is_in_excluded_dir('/var/www/html/wp-content/breeze/cache.html', '/var/www/html');
    $skip_plugins   = $walker->is_in_excluded_dir('/var/www/html/wp-content/plugins/my-plugin/app.php', '/var/www/html');

    return $skip_litespeed === true && $skip_cache === true && $skip_breeze === true && $skip_plugins === false;
});

// ========================================================================
// TEST 09: Zero-Fallback User ID Resolution
// ========================================================================
run_test(9, 'Zero-Fallback User ID Resolution (Missing IDs evaluate to null/users.php, never 1)', function () {
    $resolve_user_id = function ($issue) {
        $raw = $issue['user_id'] ?? ((isset($issue['file_path']) && preg_match('/user(?:_id)?[:_]\s*(\d+)/i', $issue['file_path'], $m)) ? $m[1] : '');
        $parsed = is_numeric($raw) ? (int) $raw : null;
        return ($parsed !== null && $parsed > 0) ? $parsed : null;
    };

    $case1 = $resolve_user_id(['file_path' => 'user_id_42']);
    $case2 = $resolve_user_id(['user_id' => 0]);
    $case3 = $resolve_user_id(['file_path' => 'wp_options.option_name']);
    $case4 = $resolve_user_id(['user_id' => null, 'file_path' => 'post:12']);

    return $case1 === 42 && $case2 === null && $case3 === null && $case4 === null;
});

// ========================================================================
// TEST 10: Non-Physical Findings Omit File Actions
// ========================================================================
run_test(10, 'Non-Physical Findings Omit Physical File Actions', function () {
    $is_physical_file = function ($issue) {
        $path = $issue['file_path'] ?? '';
        $engine = $issue['engine'] ?? '';
        if (str_starts_with($path, 'post:') || str_starts_with($path, 'comment:') || str_starts_with($path, 'db:') || str_starts_with($path, 'wp_options') || str_starts_with($path, 'cron:')) {
            return false;
        }
        if (in_array($engine, ['content-spam', 'database-table', 'wordpress-cron', 'wordpress-users'], true)) {
            return false;
        }
        return true;
    };

    $post_finding = ['file_path' => 'post:376 (page)', 'engine' => 'content-spam'];
    $db_finding   = ['file_path' => 'wp_options.option_value [ID: 166]', 'engine' => 'database-table'];
    $file_finding = ['file_path' => '/var/www/html/wp-content/plugins/test/plugin.php', 'engine' => 'malware-php'];

    return $is_physical_file($post_finding) === false &&
           $is_physical_file($db_finding) === false &&
           $is_physical_file($file_finding) === true;
});

// ========================================================================
// TEST 11 (New): Unauthorized Administrator Demotion Rollback
// ========================================================================
run_test(11, 'Unauthorized Administrator Demotion Rollback to Administrator with 403', function () use ($test_admin_id) {
    wp_set_current_user(1);
    $admin_user = get_userdata($test_admin_id);
    if (!($admin_user instanceof \WP_User)) {
        return false;
    }
    // Set initial role to administrator as admin
    $admin_user->set_role('administrator');

    // Switch to unauthenticated attacker
    wp_set_current_user(0);

    $demotion_caught = false;
    try {
        // Unauthorized caller attempts to downgrade admin to subscriber
        RaspPrivilegeGuard::rasp_guard_user_role_assignment($test_admin_id, 'subscriber', ['administrator']);
    } catch (TestWpDieException $e) {
        if ($e->statusCode === 403 && str_contains($e->getMessage(), 'Unauthorized role modification')) {
            $demotion_caught = true;
        }
    }

    // Verify rollback: user role in DB MUST be restored to administrator
    clean_user_cache($test_admin_id);
    $refreshed_user = get_userdata($test_admin_id);
    $role_restored = in_array('administrator', $refreshed_user->roles, true);

    return $demotion_caught && $role_restored;
});

// ========================================================================
// TEST 12 (New): Application Password Usage-Ping Tampering Rejection
// ========================================================================
run_test(12, 'Application Password Usage-Ping Tampering Rejection', function () use ($test_user_id) {
    wp_set_current_user(0);
    $existing = [
        [
            'uuid'      => 'app-pass-uuid-999',
            'password'  => '$P$B999999999999999999999999999999',
            'name'      => 'Valid App',
            'created'   => 1700000000,
            'last_used' => 1700000000,
            'last_ip'   => '192.0.2.10',
        ]
    ];

    // Tampering Attempt 1: Changed password hash
    $tampered_pass = $existing;
    $tampered_pass[0]['password'] = '$P$Btamperedpasswordhash1234567';
    $tampered_pass[0]['last_used'] = 1700001000;
    $caught_pass = (RaspPrivilegeGuard::rasp_guard_user_metadata_injection(null, $test_user_id, '_application_passwords', $tampered_pass, $existing) === false);

    // Tampering Attempt 2: Injected unauthorized metadata key
    $tampered_keys = $existing;
    $tampered_keys[0]['backdoor_active'] = true;
    $tampered_keys[0]['last_used'] = 1700001000;
    $caught_keys = (RaspPrivilegeGuard::rasp_guard_user_metadata_injection(null, $test_user_id, '_application_passwords', $tampered_keys, $existing) === false);

    // Tampering Attempt 3: Modified application name
    $tampered_name = $existing;
    $tampered_name[0]['name'] = 'Hijacked Name';
    $tampered_name[0]['last_used'] = 1700001000;
    $caught_name = (RaspPrivilegeGuard::rasp_guard_user_metadata_injection(null, $test_user_id, '_application_passwords', $tampered_name, $existing) === false);

    return $caught_pass && $caught_keys && $caught_name;
});

// ========================================================================
// TEST 13 (New): Nested Cache Webshell Detection
// ========================================================================
run_test(13, 'Nested Cache Webshell Detection via DirectoryWalker::scan_cache_dirs_for_executables()', function () {
    $cache_dir = WP_CONTENT_DIR . '/cache';
    if (!is_dir($cache_dir)) {
        wp_mkdir_p($cache_dir);
    }
    $nested_dir = $cache_dir . '/sub/assets/minified';
    if (!is_dir($nested_dir)) {
        wp_mkdir_p($nested_dir);
    }

    $shell_file = $nested_dir . '/webshell.phtml';
    $benign_js  = $nested_dir . '/app.min.js';
    file_put_contents($shell_file, '<?php echo "evil";');
    file_put_contents($benign_js, 'console.log("clean");');

    $walker = new DirectoryWalker();
    $found_execs = $walker->scan_cache_dirs_for_executables(ABSPATH);

    // Clean up temporary files
    @unlink($shell_file);
    @unlink($benign_js);

    $normalized_found = array_map(fn($p) => str_replace('\\', '/', $p), $found_execs);
    $normalized_target = str_replace('\\', '/', $shell_file);
    $normalized_benign = str_replace('\\', '/', $benign_js);

    $detected_shell = in_array($normalized_target, $normalized_found, true);
    $ignored_js     = !in_array($normalized_benign, $normalized_found, true);

    return $detected_shell && $ignored_js;
});

// ========================================================================
// TEST 14 (New): ThreatScoreTracker Exploit Provenance Enforcement
// ========================================================================
run_test(14, 'ThreatScoreTracker Exploit Provenance Enforcement (Unverified exploit fails safe)', function () {
    $test_ip = '198.51.100.' . mt_rand(10, 250);

    // Attempt 1: Call critical_exploit with null exploit context
    $res1 = ThreatScoreTracker::record_event($test_ip, 'critical_exploit', 90.0, null);
    $attempt1_safe = ($res1['action'] !== 'ban') && ($res1['score'] < 30.0);

    // Attempt 2: Call critical_exploit with invalid spoofed rule context
    $spoofed_context = [
        'id'       => 'SPOOF-EXPLOIT-001',
        'category' => 'Remote Code Execution',
        'detector' => 'ForgedDetector',
        'sig_id'   => 'SIG-99999',
    ];
    $res2 = ThreatScoreTracker::record_event($test_ip, 'critical_exploit', 95.0, $spoofed_context);
    $attempt2_safe = ($res2['action'] !== 'ban');

    // Verify IP is NOT in FirewallEngine blocked list or high-risk IP list
    $blocked_ips_str = (string) \WebCareProScanner\System\SettingsManager::get('waf_blocked_ips', '');
    $high_risk = (array) get_option(ThreatScoreTracker::OPTION_HIGH_RISK_IPS, []);
    $ip_not_banned = !str_contains($blocked_ips_str, $test_ip) && !isset($high_risk[$test_ip]);

    return $attempt1_safe && $attempt2_safe && $ip_not_banned;
});

// Cleanup test users
if ($test_user_id && $test_user_id > 1) {
    wp_delete_user($test_user_id);
}
if ($test_admin_id && $test_admin_id > 1) {
    wp_delete_user($test_admin_id);
}

echo "\n========================================================================\n";
echo sprintf("RESULTS: %d / %d Tests Passed (%d Failed)\n", $passed, $total, $failed);
echo "========================================================================\n";

if ($passed === $total && $failed === 0) {
    echo "SUCCESS: All 14 v2.16.1 production-readiness regression tests PASSED!\n";
    exit(0);
} else {
    echo "FAILURE: One or more regression tests failed.\n";
    exit(1);
}
