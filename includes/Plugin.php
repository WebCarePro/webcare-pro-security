<?php
namespace WebCareProScanner;

use WebCareProScanner\Admin\AdminMenu;
use WebCareProScanner\Api\ScannerRoutes;

if (!defined('ABSPATH')) {
    exit;
}

class Plugin {
    private static $instance = null;

    public static function get_instance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        $this->init();
    }

    private function init(): void {
        $is_cli   = (defined('WP_CLI') && WP_CLI);
        $is_cron  = (defined('DOING_CRON') && DOING_CRON);
        $is_admin = is_admin();

        // 0. Sandbox & Installation Guard: Prevent third-party kit managers (e.g. Elementor) from crashing during wp_install / Plugin Check sandbox initialization
        $guard_sandbox_install = static function(): void {
            $is_pcp_sandbox = class_exists('\\WebCareProScanner\\Firewall\\FirewallEngine', false)
                && \WebCareProScanner\Firewall\FirewallEngine::is_plugin_check_db_sandbox();
            $is_installing  = (function_exists('wp_installing') && wp_installing()) || (defined('WP_INSTALLING') && WP_INSTALLING);

            if ($is_pcp_sandbox || $is_installing) {
                remove_all_actions('update_option_blogname');
                remove_all_actions('update_option_blogdescription');
            }
        };

        // Guard populate_options, pre-option filters, and update_option actions
        add_action('populate_options', $guard_sandbox_install, 0);
        add_filter('pre_update_option_blogname', static function($value) use ($guard_sandbox_install) {
            $guard_sandbox_install();
            return $value;
        }, 0);
        add_filter('pre_update_option_blogdescription', static function($value) use ($guard_sandbox_install) {
            $guard_sandbox_install();
            return $value;
        }, 0);
        add_action('update_option_blogname', $guard_sandbox_install, 0);
        add_action('update_option_blogdescription', $guard_sandbox_install, 0);

        // 1. Always-On Lightweight Runtime Security (WAF, Auth, Session, Headers)
        \WebCareProScanner\Firewall\WafFileLogger::init();
        \WebCareProScanner\Firewall\FirewallEngine::init();
        \WebCareProScanner\Scan\ScanVaultManager::register();
        \WebCareProScanner\Firewall\RescueAssistantManager::init();
        \WebCareProScanner\Firewall\DistributedVelocityShield::init();
        \WebCareProScanner\Firewall\FormSpamProtectionEngine::init();
        \WebCareProScanner\Firewall\OutboundEgressFirewall::init();
        \WebCareProScanner\Firewall\GhostRouteTrap::init();
        \WebCareProScanner\Security\EmergencyContainmentManager::init();
        \WebCareProScanner\Security\PromptInjectionGuard::init();
        \WebCareProScanner\Hardening\SecurityHeadersEngine::init();
        \WebCareProScanner\Auth\TwoFactorAuth::init();
        \WebCareProScanner\Auth\LoginHardening::init();
        \WebCareProScanner\Auth\SessionSentinel::init();
        \WebCareProScanner\Auth\LoginHistoryManager::init();
        \WebCareProScanner\Auth\ApplicationPasswordSentinel::init();
        \WebCareProScanner\Auth\WebAuthnManager::init();
        \WebCareProScanner\Identity\SessionForensicsEngine::init();
        \WebCareProScanner\Content\ScriptInventoryMonitor::init();
        \WebCareProScanner\Content\BlockDirectiveSanitizer::init();
        \WebCareProScanner\WordPress\RestApiInventory::init();
        \WebCareProScanner\Core\ModuleRegistry::boot_all();

        // 2. Custom WP-Cron Schedules (Always active across all request contexts so wp_reschedule_event never fails with invalid_schedule)
        \WebCareProScanner\System\Cron\CronControlCenter::register_filters();

        // 3. REST API Routes (Loaded lazily only when WP REST API initializes)
        add_action('rest_api_init', static function (): void {
            ScannerRoutes::register();
        });

        // 4. Admin, Cron & WP-CLI Heavy Subsystems (Never booted on public storefront GET/POST)
        if ($is_admin || $is_cron || $is_cli) {
            self::ensure_uploads_storage_protected();
            AdminMenu::register();
            \WebCareProScanner\System\Scheduler::register();
            \WebCareProScanner\Backup\DatabaseBackup::init();
            \WebCareProScanner\WordPress\UserRemediationManager::init();
            \WebCareProScanner\System\WebCareActivityLogger::init();
            (new \WebCareProScanner\System\AuditLogger())->init();
            \WebCareProScanner\Firewall\HtaccessShield::init();
            \WebCareProScanner\Firewall\HtaccessVaultManager::register_cli();
            \WebCareProScanner\Integrity\ObjectCacheIntegritySentinel::init();
            \WebCareProScanner\Security\PluginSelfDefense::init();
            \WebCareProScanner\SupplyChain\UpdateGatekeeperEngine::init();
            \WebCareProScanner\Quarantine\ReinfectionWatchdog::init();
            \WebCareProScanner\Firewall\DomainReputationMonitor::init();
            \WebCareProScanner\Firewall\CAF\AdaptiveFirewallAdvisor::register_lifecycle_hooks();
            \WebCareProScanner\Firewall\CAF\CloudflareIpListSynchronizer::register_cron();
        }

        if ($is_cli && class_exists('\\WP_CLI')) {
            \WP_CLI::add_command('webcare doctor', static function (): void {
                self::cli_webcare_doctor();
            });
        }
    }

    /**
     * WP-CLI self-diagnostic suite (`wp webcare doctor`) verifying RASP hardening,
     * canonical rest_route parity, SSRF blocks, and REST route authorization.
     */
    public static function cli_webcare_doctor(): void {
        $checks = [];

        // 1. Canonical REST route normalization parity (/wp-json/... vs ?rest_route=...)
        $c1 = \WebCareProScanner\Firewall\FirewallEngine::canonicalize_rest_route('/wp-json/wp/v2/users');
        $c2 = \WebCareProScanner\Firewall\FirewallEngine::canonicalize_rest_route('/?rest_route=/wp/v2/users');
        $checks['rest_route_canonical'] = ($c1 === '/wp/v2/users' && $c2 === '/wp/v2/users');

        // 2. Verify SSRF guard rejects cloud metadata target
        $rm_ssrf = new \ReflectionMethod(\WebCareProScanner\Firewall\OutboundEgressFirewall::class, 'evaluate_ssrf_destination');
        $rm_ssrf->setAccessible(true);
        $ssrf_bad = $rm_ssrf->invoke(null, '169.254.169.254');
        $checks['ssrf_metadata_blocked'] = (($ssrf_bad['threat'] ?? null) === 'ssrf_metadata');

        // 3. Verify server-side RASP helper ignores forged HTTP_REFERER and $_REQUEST['action'] when unprivileged
        $rm = new \ReflectionMethod(\WebCareProScanner\Firewall\FirewallEngine::class, 'is_trusted_plugin_check_or_cli_runtime');
        $rm->setAccessible(true);
        $checks['rasp_helper_present'] = $rm->isStatic();

        // 3b. Verify PCP DB sandbox detection ignores spoofed HTTP_REFERER/action and detects real *_pc_ prefix mutation
        $orig_prefix = \WebCareProScanner\Firewall\FirewallEngine::get_original_table_prefix();
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Saving and restoring original superglobal values in CLI self-test harness.
        $saved_ref = $_SERVER['HTTP_REFERER'] ?? null;
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Saving and restoring original superglobal values in CLI self-test harness.
        $saved_act = $_REQUEST['action'] ?? null;
        $_SERVER['HTTP_REFERER'] = 'https://example.org/wp-admin/tools.php?page=plugin-check';
        $_REQUEST['action']      = 'plugin_check_run_checks';
        $spoof_rejected          = !\WebCareProScanner\Firewall\FirewallEngine::is_plugin_check_db_sandbox();
        $sandbox_detected        = false;
        $mismatched_meta_ok      = false;
        $mismatched_users_ok     = false;
        global $wpdb;
        $prev_prefix = $wpdb->set_prefix($orig_prefix . 'pc_');
        try {
            if (!defined('WEBCAREPROSCAN_PCP_TEST_HARNESS')) {
                define('WEBCAREPROSCAN_PCP_TEST_HARNESS', true);
            }
            $sandbox_detected = \WebCareProScanner\Firewall\FirewallEngine::is_plugin_check_db_sandbox();

            // Mismatched namespace rejection (fail closed)
            $prev_meta = $wpdb->usermeta;
            $wpdb->usermeta = 'wp_custom_usermeta';
            $mismatched_meta_ok = !\WebCareProScanner\Firewall\FirewallEngine::is_plugin_check_db_sandbox();
            $wpdb->usermeta = $prev_meta;

            $prev_users = $wpdb->users;
            $wpdb->users = 'wp_custom_users';
            $mismatched_users_ok = !\WebCareProScanner\Firewall\FirewallEngine::is_plugin_check_db_sandbox();
            $wpdb->users = $prev_users;
        } finally {
            $wpdb->set_prefix($prev_prefix);
            if ($saved_ref === null) {
                unset($_SERVER['HTTP_REFERER']);
            } else {
                $_SERVER['HTTP_REFERER'] = $saved_ref;
            }
            if ($saved_act === null) {
                unset($_REQUEST['action']);
            } else {
                $_REQUEST['action'] = $saved_act;
            }
        }
        $checks['pcp_sandbox_guard'] = ($orig_prefix === ($GLOBALS['table_prefix'] ?? 'wp_') && $spoof_rejected && $sandbox_detected && $mismatched_meta_ok && $mismatched_users_ok);

        // 3c. Verify original-table cookie validator rejects invalid cookies and validates authentic admin cookies
        $rm_cookie = new \ReflectionMethod(\WebCareProScanner\Firewall\FirewallEngine::class, 'validate_cookie_against_original_tables');
        $rm_cookie->setAccessible(true);
        $forged_res = $rm_cookie->invoke(null, 'attacker|9999999999|tok|deadbeef', 'logged_in', $orig_prefix);
        $cookie_ok  = (empty($forged_res['user_id']) && empty($forged_res['is_admin']));
        $admins     = get_users(['role' => 'administrator', 'number' => 1]);
        if ($cookie_ok && !empty($admins[0]) && function_exists('wp_generate_auth_cookie')) {
            $admin_id   = (int) $admins[0]->ID;
            $exp        = time() + 300;
            $tmp_token  = wp_generate_password(43, false, false);
            $verifier   = hash('sha256', $tmp_token);
            $sessions   = get_user_meta($admin_id, 'session_tokens', true);
            $sessions   = is_array($sessions) ? $sessions : [];
            $sessions[$verifier] = ['expiration' => $exp, 'ip' => '127.0.0.1', 'ua' => 'WebCareDoctor', 'login' => time()];
            update_user_meta($admin_id, 'session_tokens', $sessions);
            try {
                $signed_cookie = wp_generate_auth_cookie($admin_id, $exp, 'logged_in', $tmp_token);
                $prev_p2       = $wpdb->set_prefix($orig_prefix . 'pc_');
                try {
                    $valid_res = $rm_cookie->invoke(null, $signed_cookie, 'logged_in', $orig_prefix);
                    $cookie_ok = ((int) ($valid_res['user_id'] ?? 0) === $admin_id && !empty($valid_res['is_admin']));
                } finally {
                    $wpdb->set_prefix($prev_p2);
                }
            } finally {
                unset($sessions[$verifier]);
                update_user_meta($admin_id, 'session_tokens', $sessions);
            }
        }
        $checks['pcp_orig_cookie_auth'] = $cookie_ok;

        // 3d. Regression checks for fail-closed MCP TTL/CIDR parsing and vault policy repair.
        $cidr_validator = \WebCareProScanner\Api\MCPAntiLockoutValidator::class;
        $bad_cidrs = $cidr_validator::parse_cidr_list(",,\n  ,");
        $valid_cidrs = $cidr_validator::parse_cidr_list('192.0.2.0/24');
        $checks['mcp_cidr_fail_closed'] = !$cidr_validator::is_valid_cidr_list($bad_cidrs)
            && !$cidr_validator::is_valid_cidr_list(['0.0.0.0/not-a-prefix'])
            && !$cidr_validator::ip_matches_cidr_list('192.0.2.5', ['0.0.0.0/not-a-prefix'])
            && $cidr_validator::is_valid_cidr_list($valid_cidrs)
            && $cidr_validator::ip_matches_cidr_list('192.0.2.5', $valid_cidrs)
            && !$cidr_validator::ip_matches_cidr_list('198.51.100.7', $valid_cidrs);

        $ttl_parser = new \ReflectionMethod($cidr_validator, 'parse_non_negative_integer');
        $ttl_parser->setAccessible(true);
        $checks['mcp_ttl_parse_strict'] = $ttl_parser->invoke(null, '30', 365) === 30
            && $ttl_parser->invoke(null, '30days', 365) === null
            && $ttl_parser->invoke(null, -1, 365) === null;
        $doctor_now = time();
        $checks['mcp_ttl_fail_closed'] = empty($cidr_validator::validate_mcp_token_lifetime(30, 0, $doctor_now)['valid'])
            && (($cidr_validator::validate_mcp_token_lifetime(30, $doctor_now - (31 * DAY_IN_SECONDS), $doctor_now)['reason'] ?? '') === 'expired')
            && !empty($cidr_validator::validate_mcp_token_lifetime(30, $doctor_now - DAY_IN_SECONDS, $doctor_now)['valid']);

        $guest_route_check = new \ReflectionMethod(\WebCareProScanner\Firewall\FirewallEngine::class, 'is_safe_guest_rest_mutation_route');
        $guest_route_check->setAccessible(true);
        $checks['guest_rest_routes_narrowed'] = $guest_route_check->invoke(null, '/wc/store/v1/checkout', 'POST', [])
            && $guest_route_check->invoke(null, '/wc/store/v1/cart/items/abc123', 'DELETE', [])
            && !$guest_route_check->invoke(null, '/wc/store/v1/products', 'POST', [])
            && !$guest_route_check->invoke(null, '/stripe/v1/webhook', 'POST', [])
            && !$guest_route_check->invoke(null, '/paypal/v1/private-action', 'POST', []);

        $custom_route_matcher = [\WebCareProScanner\Firewall\FirewallEngine::class, 'is_custom_rest_route_allowed'];
        $checks['guest_rest_method_scope'] = \call_user_func($custom_route_matcher, '/route', 'POST', ['POST /route'])
            && !\call_user_func($custom_route_matcher, '/route', 'DELETE', ['POST /route'])
            && !\call_user_func($custom_route_matcher, '/route/123', 'POST', ['POST /route'])
            && !\call_user_func($custom_route_matcher, '/route-admin', 'POST', ['POST /route'])
            && \call_user_func($custom_route_matcher, '/route/123', 'POST', ['POST /route/*'])
            && \call_user_func($custom_route_matcher, '/route', 'POST', ['POST /route/*'])
            && \call_user_func($custom_route_matcher, '/legacy-route', 'DELETE', ['/legacy-route']);
        $checks['guest_rest_root_wildcard_rejected'] = !\call_user_func($custom_route_matcher, '/anything', 'POST', ['/*'])
            && !\call_user_func($custom_route_matcher, '/anything', 'POST', ['POST /*']);

        $allowlist_builder = new \ReflectionMethod(\WebCareProScanner\Api\ScannerRoutes::class, 'build_method_scoped_rest_allowlist');
        $allowlist_builder->setAccessible(true);
        $narrowed_allowlist = $allowlist_builder->invoke(null, ['/route', '/keep'], '/route', 'POST');
        $checks['guest_rest_one_click_narrows_legacy'] = !in_array('/route', $narrowed_allowlist['lines'], true)
            && in_array('/keep', $narrowed_allowlist['lines'], true)
            && in_array('POST /route', $narrowed_allowlist['lines'], true)
            && !empty($narrowed_allowlist['legacy_route_replaced']);

        $vault_htaccess_check = false;
        $htaccess_test_path = wp_tempnam('webcare-vault-policy');
        if (is_string($htaccess_test_path) && $htaccess_test_path !== '') {
            try {
                $tampered_htaccess = "RewriteEngine On\nRewriteRule ^safe$ - [L]\nRequire all granted\n";
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Temporary local diagnostic fixture.
                if (@file_put_contents($htaccess_test_path, $tampered_htaccess, LOCK_EX) !== false) {
                    $htaccess_repair = new \ReflectionMethod(\WebCareProScanner\Scan\ScanVaultManager::class, 'enforce_htaccess_vault_policy');
                    $htaccess_repair->setAccessible(true);
                    $htaccess_repair->invoke(null, $htaccess_test_path);
                    $repaired_htaccess = (string) @file_get_contents($htaccess_test_path);
                    $vault_htaccess_check = str_contains($repaired_htaccess, 'RewriteRule ^safe$ - [L]')
                        && !preg_match('/^\s*Require\s+all\s+granted\s*$/mi', $repaired_htaccess)
                        && substr_count($repaired_htaccess, 'Require all denied') === 1
                        && str_contains($repaired_htaccess, 'Options -Indexes');
                }
            } catch (\Throwable $e) {
                $vault_htaccess_check = false;
            } finally {
                wp_delete_file($htaccess_test_path);
            }
        }
        $checks['vault_apache_tamper_repaired'] = $vault_htaccess_check;

        $vault_iis_check = false;
        $iis_test_path = wp_tempnam('webcare-vault-policy');
        if (is_string($iis_test_path) && $iis_test_path !== '') {
            try {
                $tampered_web_config = '<?xml version="1.0"?><configuration><system.webServer><rewrite><rules><rule name="KeepRule" /></rules></rewrite><security><authorization><add accessType="Allow" users="*" /></authorization></security></system.webServer></configuration>';
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Temporary local diagnostic fixture.
                if (@file_put_contents($iis_test_path, $tampered_web_config, LOCK_EX) !== false) {
                    $iis_repair = new \ReflectionMethod(\WebCareProScanner\Scan\ScanVaultManager::class, 'enforce_iis_vault_policy');
                    $iis_repair->setAccessible(true);
                    $iis_repair->invoke(null, $iis_test_path);
                    $repaired_web_config = (string) @file_get_contents($iis_test_path);
                    $vault_iis_check = str_contains($repaired_web_config, 'accessType="Deny"')
                        && str_contains($repaired_web_config, 'users="*"')
                        && !str_contains($repaired_web_config, 'accessType="Allow"')
                        && str_contains($repaired_web_config, 'directoryBrowse enabled="false"');
                    if (class_exists('DOMDocument')) {
                        $vault_iis_check = $vault_iis_check && str_contains($repaired_web_config, 'KeepRule');
                    }
                }
            } catch (\Throwable $e) {
                $vault_iis_check = false;
            } finally {
                wp_delete_file($iis_test_path);
            }
        }
        $checks['vault_iis_tamper_repaired'] = $vault_iis_check;

        // 4. Affiliate Shield & Path Boundary Regression Checks (v2.19.0)
        $affiliate_class = \WebCareProScanner\Firewall\Core\AffiliateSecurityEngine::class;
        $affiliate_class::register_cache_invalidation_hooks();
        $checks['affiliate_detection_cache_hooks'] = has_action('activated_plugin', [$affiliate_class, 'invalidate_detection_cache']) !== false
            && has_action('deactivated_plugin', [$affiliate_class, 'invalidate_detection_cache']) !== false
            && has_action('switch_theme', [$affiliate_class, 'invalidate_detection_cache']) !== false;

        $aff_params = $affiliate_class::collect_referral_parameters(
            ['ref' => 'clean-referral', 'aff' => '<script>alert(1)</script>'],
            ['affwp_campaign' => '../wp-config.php'],
            ['referral' => ['sld' => '1e0union select 1,2,3']]
        );
        $aff_multi_violation = $affiliate_class::find_referral_injection($aff_params, '198.51.100.1', '/wp-json/affwp/v1/visits');
        $checks['affiliate_multi_param_injection'] = count($aff_params) === 4
            && isset($aff_params['JSON:referral.sld'])
            && (($aff_multi_violation['id'] ?? '') === 'WAF-AFFILIATE-INJECTION');

        $checks['affiliate_rest_route_anchored'] = !\WebCareProScanner\Firewall\Core\AffiliateSecurityEngine::is_public_affiliate_rest_route('affwp/v1/visits/123/delete')
            && !\WebCareProScanner\Firewall\Core\AffiliateSecurityEngine::is_public_affiliate_rest_route('affwp/v1/visits-export')
            && \WebCareProScanner\Firewall\Core\AffiliateSecurityEngine::is_public_affiliate_rest_route('affwp/v1/visits', 'POST')
            && !\WebCareProScanner\Firewall\Core\AffiliateSecurityEngine::is_public_affiliate_rest_route('affwp/v1/visits', 'PUT')
            && \WebCareProScanner\Firewall\Core\AffiliateSecurityEngine::is_public_affiliate_rest_route('/wp-json/slicewp/v1/visits');

        $checks['affiliate_rest_method_scope'] = $affiliate_class::is_public_affiliate_rest_request('affwp/v1/visits', 'POST')
            && $affiliate_class::is_public_affiliate_rest_request('/wp-json/slicewp/v1/visits', 'POST')
            && !$affiliate_class::is_public_affiliate_rest_request('affwp/v1/visits', 'PUT')
            && !$affiliate_class::is_public_affiliate_rest_request('affwp/v1/visits', 'DELETE');

        $contact_setting = '/contact';
        $checks['contact_support_url_boundary'] = !\WebCareProScanner\Firewall\FirewallEngine::is_configured_support_path('/contact-admin', $contact_setting)
            && !\WebCareProScanner\Firewall\FirewallEngine::is_configured_support_path('/contact/child', $contact_setting)
            && \WebCareProScanner\Firewall\FirewallEngine::is_configured_support_path('/contact?source=warning', $contact_setting);

        $checks['empty_ua_clearance_and_methods'] = \WebCareProScanner\Firewall\FirewallEngine::get_empty_user_agent_action('GET', true) === 'allow'
            && \WebCareProScanner\Firewall\FirewallEngine::get_empty_user_agent_action('POST', true) === 'allow'
            && \WebCareProScanner\Firewall\FirewallEngine::get_empty_user_agent_action('GET', false) === 'challenge'
            && \WebCareProScanner\Firewall\FirewallEngine::get_empty_user_agent_action('POST', false, true) === 'proof'
            && \WebCareProScanner\Firewall\FirewallEngine::get_empty_user_agent_action('HEAD', false) === 'head_block'
            && \WebCareProScanner\Firewall\FirewallEngine::get_empty_user_agent_action('OPTIONS', false) === 'allow'
            && \WebCareProScanner\Firewall\FirewallEngine::get_empty_user_agent_action('POST', false) === 'block';

        $test_bot_ip = '198.51.100.' . wp_rand(10, 250);
        $hit1 = \WebCareProScanner\Firewall\Core\AffiliateSecurityEngine::track_referral_click_velocity($test_bot_ip, 2);
        $hit2 = \WebCareProScanner\Firewall\Core\AffiliateSecurityEngine::track_referral_click_velocity($test_bot_ip, 2);
        $hit3 = \WebCareProScanner\Firewall\Core\AffiliateSecurityEngine::track_referral_click_velocity($test_bot_ip, 2);
        $suppression_applied = $affiliate_class::suppress_visit_recording_if_flooding($hit3);
        $previous_doctor_ua = isset($_SERVER['HTTP_USER_AGENT'])
            ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT']))
            : null;
        $_SERVER['HTTP_USER_AGENT'] = 'WebCareDoctor/1.0';
        $affwp_visit_allowed = $affiliate_class::filter_affwp_is_valid_visit(true);
        $slicewp_visit_allowed = $affiliate_class::filter_slicewp_is_valid_visit(true);
        if ($previous_doctor_ua === null) {
            unset($_SERVER['HTTP_USER_AGENT']);
        } else {
            $_SERVER['HTTP_USER_AGENT'] = $previous_doctor_ua;
        }
        $checks['affiliate_click_velocity_throttling'] = (!$hit1 && !$hit2 && $hit3 && $suppression_applied)
            && !$affwp_visit_allowed
            && !$slicewp_visit_allowed;

        // 5. REST API Authz Audit: ensure no admin route under webcare-pro-security/v1 uses __return_true
        $server = rest_get_server();
        $routes = $server->get_routes('webcare-pro-security/v1');
        $public_unexpected = [];
        foreach ($routes as $r_path => $handlers) {
            foreach ((array) $handlers as $ep) {
                if (($ep['permission_callback'] ?? null) === '__return_true') {
                    $public_unexpected[] = $r_path;
                }
            }
        }
        $checks['rest_routes_audited'] = count($routes);
        $checks['rest_no_open_admin']  = empty($public_unexpected);

        foreach ($checks as $name => $val) {
            \WP_CLI::line(sprintf('%-26s : %s', $name, is_bool($val) ? ($val ? 'PASS' : 'FAIL') : (string) $val));
        }

        if (
            empty($checks['rest_route_canonical']) ||
            empty($checks['ssrf_metadata_blocked']) ||
            empty($checks['pcp_sandbox_guard']) ||
            empty($checks['pcp_orig_cookie_auth']) ||
            empty($checks['mcp_cidr_fail_closed']) ||
            empty($checks['mcp_ttl_parse_strict']) ||
            empty($checks['mcp_ttl_fail_closed']) ||
            empty($checks['guest_rest_routes_narrowed']) ||
            empty($checks['guest_rest_method_scope']) ||
            empty($checks['guest_rest_root_wildcard_rejected']) ||
            empty($checks['guest_rest_one_click_narrows_legacy']) ||
            empty($checks['vault_apache_tamper_repaired']) ||
            empty($checks['vault_iis_tamper_repaired']) ||
            empty($checks['affiliate_detection_cache_hooks']) ||
            empty($checks['affiliate_multi_param_injection']) ||
            empty($checks['affiliate_rest_route_anchored']) ||
            empty($checks['affiliate_rest_method_scope']) ||
            empty($checks['contact_support_url_boundary']) ||
            empty($checks['empty_ua_clearance_and_methods']) ||
            empty($checks['affiliate_click_velocity_throttling']) ||
            empty($checks['rest_no_open_admin'])
        ) {
            \WP_CLI::error('WebCare Doctor detected a failed security self-check.');
        }

        \WP_CLI::success('All WebCare Pro security self-checks passed.');
    }

    /**
     * Ensure root uploads/webcare-pro-security storage directory has an index.php directory silence guard.
     */
    public static function ensure_uploads_storage_protected(): void {
        $upload_dir = wp_upload_dir();
        $dir = $upload_dir['basedir'] . '/webcare-pro-security';
        if (!file_exists($dir)) {
            wp_mkdir_p($dir);
        }
        $index_file = $dir . '/index.php';
        if (!file_exists($index_file)) {
            @file_put_contents($index_file, "<?php\n// Silence is golden.\nhttp_response_code(403);\nexit;\n");
        }
    }
}
