<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall\Core;

use WebCareProScanner\Firewall\FirewallEngine;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * FirewallTelemetryService
 *
 * Dedicated service providing telemetry, engine status, rule catalogs, and log management.
 * Loaded strictly in administrative, REST, and WP-CLI contexts.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
final class FirewallTelemetryService {

    /**
     * Get statistics & summary of firewall activity
     */
    public static function get_status(): array {
        global $wpdb;
        $table = $wpdb->prefix . 'webcareproscan_firewall_logs';

        $settings = SettingsManager::get_settings();
        $env = self::detect_environment();

        $total_blocks = 0;
        $blocks_24h   = 0;
        $blocks_today = 0;
        $unique_ips   = 0;
        $top_rules    = [];

        // 1. Fetch aggregate metrics scoped strictly to TODAY's single partition file to eliminate multi-month JSON scan overhead
        $today_file   = WafFileLogger::get_storage_dir() . DIRECTORY_SEPARATOR . WafFileLogger::get_daily_filename();
        $today_exists = file_exists($today_file);

        if ($today_exists) {
            $file_stats   = WafFileLogger::get_log_stats('today');
            $blocks_today = (int) ($file_stats['blocked_24h'] ?? 0);
            $unique_ips   = (int) ($file_stats['unique_attack_ips'] ?? 0);
            $top_rules    = array_slice($file_stats['top_categories'] ?? [], 0, 5);
        }

        // Fast O(1) lifetime persistent counter via Vault JSON (zero SQL overhead)
        $vault_stats      = \WebCareProScanner\Firewall\Core\WafVaultManager::get_stats_summary();
        $lifetime_counter = $vault_stats['lifetime_blocked'];
        if ($lifetime_counter < $blocks_today) {
            $lifetime_counter = $blocks_today;
        }

        $total_blocks = $lifetime_counter;
        $blocks_24h   = $blocks_today;

        // 2. Fallback / merge legacy SQL database table only if file logging partition is absent
        if (!$today_exists) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $table_exists = $wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $table));
            if ($table_exists) {
                $total_sql = "SELECT COUNT(*) FROM `{$table}` WHERE action_taken = 'blocked'";
                $blocks_24h_sql = "SELECT COUNT(*) FROM `{$table}` WHERE action_taken = 'blocked' AND created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)";
                $top_rules_sql = "SELECT rule_category, COUNT(*) as count FROM `{$table}` WHERE action_taken = 'blocked' GROUP BY rule_category ORDER BY count DESC LIMIT 5";
                // phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.NotPrepared
                $db_total = (int) $wpdb->get_var($total_sql);
                $db_24h   = (int) $wpdb->get_var($blocks_24h_sql);
                if ($db_total > 0) {
                    $total_blocks += $db_total;
                    $blocks_24h   += $db_24h;
                    $blocks_today += $db_24h;
                    if (empty($top_rules)) {
                        $top_rules = $wpdb->get_results(
                            $top_rules_sql,
                            ARRAY_A
                        ) ?: [];
                    }
                }
                // phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.NotPrepared
            }
        }

        $active_mode = 'disabled';
        if (!empty($settings['waf_enabled'])) {
            if (($settings['waf_mode'] ?? 'enabled') === 'learning') {
                $active_mode = 'learning';
            } elseif (!empty($settings['waf_complementary_mode']) && $env['has_coexisting_waf']) {
                $active_mode = 'complementary';
            } else {
                $active_mode = 'active';
            }
        }

        return [
            'enabled'            => !empty($settings['waf_enabled']),
            'mode'               => $settings['waf_mode'] ?? 'enabled',
            'active_mode'        => $active_mode,
            'environment'        => $env,
            'total_blocks'       => $total_blocks,
            'blocks_24h'         => $blocks_24h,
            'blocks_today'       => $blocks_today,
            'today_date'         => current_time('M j, Y'),
            'today_date_full'    => current_time('F j, Y'),
            'unique_attack_ips'  => $unique_ips,
            'top_rules'          => $top_rules,
            'client_ip'          => self::get_client_ip(),
            'threat_intel'       => ThreatIntelService::get_status(),
            'edge_advisor'       => class_exists('\\WebCareProScanner\\Cloudflare\\CloudflareService')
                ? \WebCareProScanner\Cloudflare\CloudflareService::get_edge_advisor()
                : null,
            'server_telemetry'   => self::get_server_telemetry(),
            'available_roles'    => self::get_available_roles(),
            'commerce_telemetry' => (function () use ($settings) {
                $detected_commerce = array_values(array_filter([
                    // Archetype Profile
                    in_array(get_option('webcareproscan_site_archetype'), ['ecommerce', 'membership'], true) ? 'Configured ' . ucfirst((string) get_option('webcareproscan_site_archetype')) . ' Archetype' : null,
                    // E-Commerce
                    class_exists('WooCommerce') ? 'WooCommerce' : null,
                    class_exists('Easy_Digital_Downloads') ? 'Easy Digital Downloads' : null,
                    (class_exists('\\SureCart\\SureCart') || defined('SURECART_PLUGIN_FILE')) ? 'SureCart' : null,
                    (class_exists('Ecwid_Product') || defined('ECWID_PLUGIN_DIR')) ? 'Ecwid by Lightspeed' : null,
                    (class_exists('wp_easycart') || defined('EC_CURRENT_VERSION')) ? 'WP EasyCart' : null,
                    (class_exists('\\FluentCart\\App\\App') || defined('FLUENTCART_VERSION')) ? 'FluentCart' : null,
                    (class_exists('\\BigCommerce\\Container') || defined('BIGCOMMERCE_VERSION')) ? 'BigCommerce' : null,
                    (class_exists('SimplePay') || defined('SIMPLE_PAY_VERSION')) ? 'WP Simple Pay' : null,
                    (class_exists('Cart66') || defined('CART66_VERSION')) ? 'Cart66' : null,
                    class_exists('WP_DLM') ? 'Download Monitor' : null,
                    (class_exists('Give') || defined('GIVE_VERSION')) ? 'GiveWP' : null,
                    // Membership
                    class_exists('MeprAppCtrl') ? 'MemberPress' : null,
                    defined('PMPRO_VERSION') ? 'Paid Memberships Pro' : null,
                    (class_exists('Restrict_Content_Pro') || defined('RCP_PLUGIN_VERSION')) ? 'Restrict Content Pro / Kadence Memberships' : null,
                    (class_exists('\\SureMembers\\SureMembers') || defined('SUREMEMBERS_VERSION')) ? 'SureMembers' : null,
                    (class_exists('ARM_main') || defined('MEMBERSHIP_VERSION')) ? 'ARMember' : null,
                    (class_exists('MemberMouse') || defined('MM_VERSION')) ? 'MemberMouse' : null,
                    (class_exists('WishListMember') || defined('WLM_VERSION')) ? 'WishList Member' : null,
                    (class_exists('SimpleWpMembership') || defined('SWPM_VERSION')) ? 'Simple Membership' : null,
                    class_exists('WC_Memberships') ? 'WooCommerce Memberships' : null,
                    (class_exists('Pms_Member') || defined('PMS_VERSION')) ? 'Paid Member Subscriptions' : null,
                    class_exists('c_ws_plugin__s2member_menu_pages') ? 's2Member' : null,
                    (class_exists('IhsuMpMain') || defined('UHP_VERSION')) ? 'Ultimate Membership Pro' : null,
                    class_exists('LearnDash_Settings_Section') ? 'LearnDash' : null,
                    class_exists('LifterLMS') ? 'LifterLMS' : null,
                    // Profiles & Registration
                    (class_exists('UM') || defined('um_plugin')) ? 'Ultimate Member' : null,
                    (class_exists('Profile_Builder') || defined('WPPB_PLUGIN_DIR')) ? 'User Profile Builder' : null,
                    (class_exists('WP_User_Manager') || defined('WPUM_VERSION')) ? 'WP User Manager' : null,
                    (class_exists('ProfilePress') || defined('PPRESS_VERSION_NUMBER')) ? 'ProfilePress' : null,
                    (class_exists('User_Registration') || defined('UR_VERSION')) ? 'User Registration' : null,
                    (class_exists('Registration_Magic') || defined('RM_PLUGIN_VERSION')) ? 'RegistrationMagic' : null,
                    (class_exists('Profile_Grid') || defined('PG_PLUGIN_VERSION')) ? 'ProfileGrid' : null,
                    (class_exists('Theme_My_Login') || defined('TML_VERSION')) ? 'ThemeMyLogin' : null,
                    class_exists('FrmRegAppController') ? 'Formidable User Registration' : null,
                    class_exists('wpmembers') ? 'WP-Members' : null,
                    (class_exists('BuddyBoss_Platform') || defined('BP_PLATFORM_VERSION')) ? 'BuddyBoss Platform' : null,
                    (class_exists('Youzify') || defined('YOUZIFY_VERSION')) ? 'Youzify' : null,
                ]));
                $has_detected = count($detected_commerce) > 0;
                return [
                    'is_active'            => self::is_commerce_active(),
                    'has_detected_plugins' => $has_detected,
                    'detected_names'       => $detected_commerce,
                    'has_woocommerce'      => class_exists('WooCommerce'),
                    'is_manually_enabled'  => !empty($settings['waf_ecommerce_safe_mode']) && !$has_detected,
                ];
            })(),
            'forms_telemetry'    => [
                'is_active' => (
                    defined('WPCF7_VERSION') || class_exists('WPCF7') ||
                    defined('WPFORMS_VERSION') || class_exists('WPForms') ||
                    defined('FLUENTFORM_VERSION') ||
                    class_exists('GFForms') ||
                    class_exists('Ninja_Forms') ||
                    class_exists('FrmAppController') ||
                    defined('WS_FORM_VERSION') ||
                    defined('CALDERA_FORMS_VERSION') ||
                    defined('HAPPYFORMS_VERSION') ||
                    defined('EVEREST_FORMS_VERSION') ||
                    defined('ELEMENTOR_PRO_VERSION') || class_exists('\\ElementorPro\\Modules\\Forms\\Module')
                ),
                'detected_names' => array_values(array_filter([
                    (defined('ELEMENTOR_PRO_VERSION') || class_exists('\\ElementorPro\\Modules\\Forms\\Module')) ? 'Elementor Pro Forms' : null,
                    (defined('WPCF7_VERSION') || class_exists('WPCF7')) ? 'Contact Form 7' : null,
                    (defined('WPFORMS_VERSION') || class_exists('WPForms')) ? 'WPForms' : null,
                    defined('FLUENTFORM_VERSION') ? 'Fluent Forms' : null,
                    class_exists('GFForms') ? 'Gravity Forms' : null,
                    class_exists('Ninja_Forms') ? 'Ninja Forms' : null,
                    class_exists('FrmAppController') ? 'Formidable Forms' : null,
                    defined('WS_FORM_VERSION') ? 'WS Form' : null,
                    defined('CALDERA_FORMS_VERSION') ? 'Caldera Forms' : null,
                    defined('HAPPYFORMS_VERSION') ? 'HappyForms' : null,
                    defined('EVEREST_FORMS_VERSION') ? 'Everest Forms' : null,
                ])),
                'stats' => class_exists('WebCareProScanner\\Firewall\\FormSpamProtectionEngine') ? \WebCareProScanner\Firewall\FormSpamProtectionEngine::get_stats() : ['total_blocked' => 0],
            ],
            'affiliate_telemetry' => (function () {
                if (class_exists(AffiliateSecurityEngine::class)) {
                    return AffiliateSecurityEngine::get_detected_ecosystem();
                }
                return [
                    'is_active' => false,
                    'plugins'   => [],
                    'themes'    => [],
                    'summary'   => 'No affiliate ecosystem detected',
                ];
            })(),
            'integrations_telemetry' => [
                'has_builders' => (
                    defined('ELEMENTOR_VERSION') ||
                    defined('ET_BUILDER_VERSION') ||
                    defined('FL_BUILDER_VERSION') ||
                    defined('BRICKS_VERSION') ||
                    defined('BREAKDANCE_VERSION') ||
                    defined('CT_VERSION') || // Oxygen
                    defined('SEEDPROD_VERSION') ||
                    defined('BRIZY_VERSION') ||
                    defined('TVE_VERSION') || // Thrive Architect
                    defined('WPB_VC_VERSION') || // WPBakery
                    defined('VCV_VERSION') || // Visual Composer
                    defined('THEMIFY_BUILDER_VERSION') ||
                    defined('SITEORIGIN_PANELS_VERSION') ||
                    defined('DROIP_VERSION') ||
                    defined('DSLC_VERSION') || // Live Composer
                    (function_exists('wp_is_block_theme') && wp_is_block_theme()) || // WP Site Editor FSE
                    defined('GENERATEBLOCKS_VERSION') ||
                    defined('KADENCE_BLOCKS_VERSION') ||
                    defined('UAGB_VER') || // Spectra
                    defined('FUSION_BUILDER_VERSION') // Avada Fusion Builder
                ),
                'builder_names' => array_values(array_filter([
                    defined('ELEMENTOR_VERSION') ? 'Elementor' : null,
                    defined('ET_BUILDER_VERSION') ? 'Divi Builder' : null,
                    defined('FL_BUILDER_VERSION') ? 'Beaver Builder' : null,
                    defined('BRICKS_VERSION') ? 'Bricks Builder' : null,
                    defined('BREAKDANCE_VERSION') ? 'Breakdance' : null,
                    defined('CT_VERSION') ? 'Oxygen Builder' : null,
                    defined('SEEDPROD_VERSION') ? 'SeedProd' : null,
                    defined('BRIZY_VERSION') ? 'Brizy' : null,
                    defined('TVE_VERSION') ? 'Thrive Architect' : null,
                    defined('WPB_VC_VERSION') ? 'WPBakery' : null,
                    defined('VCV_VERSION') ? 'Visual Composer' : null,
                    defined('THEMIFY_BUILDER_VERSION') ? 'Themify Builder' : null,
                    defined('SITEORIGIN_PANELS_VERSION') ? 'SiteOrigin Page Builder' : null,
                    defined('DROIP_VERSION') ? 'Droip' : null,
                    defined('DSLC_VERSION') ? 'Live Composer' : null,
                    (function_exists('wp_is_block_theme') && wp_is_block_theme()) ? 'WordPress Site Editor (FSE)' : null,
                    defined('GENERATEBLOCKS_VERSION') ? 'GenerateBlocks' : null,
                    defined('KADENCE_BLOCKS_VERSION') ? 'Kadence Blocks' : null,
                    defined('UAGB_VER') ? 'Spectra' : null,
                    defined('FUSION_BUILDER_VERSION') ? 'Avada Fusion Builder' : null,
                ])),
                'has_jetpack' => class_exists('Jetpack'),
                'has_central_management' => (
                    class_exists('MMB_Core') ||
                    class_exists('MainWP_Child') ||
                    class_exists('IWP_MMB_Core') ||
                    defined('MMB_WORKER_VERSION')
                ),
                'management_names' => array_values(array_filter([
                    (class_exists('MMB_Core') || defined('MMB_WORKER_VERSION')) ? 'ManageWP Worker' : null,
                    class_exists('MainWP_Child') ? 'MainWP Child' : null,
                    class_exists('IWP_MMB_Core') ? 'InfiniteWP Client' : null,
                ])),
            ],
            'active_plugin_slugs' => self::get_active_plugin_slugs(),
        ];
    }

    /**
     * Compute comprehensive server, host runtime, and developer diagnostics for the Firewall dashboard.
     *
     * @return array
     */
    public static function get_server_telemetry(): array {
        // 1. Linux Uname & OS Distribution
        $uname_s = php_uname('s');
        $uname_r = php_uname('r');
        $uname_m = php_uname('m');
        $uname_n = php_uname('n');
        $uname_full = php_uname('a');
        $linux_uname_short = "{$uname_s} {$uname_r} ({$uname_m})";

        $distro_name = $uname_s . ' ' . $uname_r;

        // 2. Server Software & SAPI
        $server_software_raw = !empty($_SERVER['SERVER_SOFTWARE'])
            ? sanitize_text_field(wp_unslash($_SERVER['SERVER_SOFTWARE']))
            : (function_exists('apache_get_version') ? (string) @apache_get_version() : '');
        if (empty($server_software_raw)) {
            if (strpos(php_sapi_name(), 'fpm') !== false) {
                $server_software_raw = 'nginx / PHP-FPM';
            } else {
                $server_software_raw = 'Web Server (' . php_sapi_name() . ')';
            }
        }
        $server_software_type = 'Other';
        if (stripos($server_software_raw, 'litespeed') !== false || stripos($server_software_raw, 'openlitespeed') !== false) {
            $server_software_type = 'LiteSpeed';
        } elseif (stripos($server_software_raw, 'nginx') !== false) {
            $server_software_type = 'Nginx';
        } elseif (stripos($server_software_raw, 'apache') !== false) {
            $server_software_type = 'Apache';
        } elseif (stripos($server_software_raw, 'caddy') !== false) {
            $server_software_type = 'Caddy';
        } elseif (stripos($server_software_raw, 'microsoft-iis') !== false) {
            $server_software_type = 'Microsoft IIS';
        }
        $php_sapi = php_sapi_name();

        // 3. PHP Version & Architecture
        $php_version = PHP_VERSION;
        $php_arch = PHP_INT_SIZE === 8 ? '64-bit' : '32-bit';
        $opcache_active = (bool) (extension_loaded('Zend OPcache') && ini_get('opcache.enable'));

        // 4. Real Server Origin IPs (IPv4 and IPv6)
        $real_server_ip = 'Unknown';
        $real_server_ipv4 = '';
        $real_server_ipv6 = '';

        if (class_exists('\\WebCareProScanner\\System\\ServerInfo')) {
            $all_server_ips = \WebCareProScanner\System\ServerInfo::get_all_server_ips();
            foreach ($all_server_ips as $s_ip) {
                if (filter_var($s_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && $s_ip !== '127.0.0.1' && empty($real_server_ipv4)) {
                    $real_server_ipv4 = $s_ip;
                }
                if (filter_var($s_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) && $s_ip !== '::1' && strpos($s_ip, 'fe80:') !== 0 && empty($real_server_ipv6)) {
                    $real_server_ipv6 = $s_ip;
                }
            }
            $real_server_ip = \WebCareProScanner\System\ServerInfo::get_server_ip();
        } else {
            $real_server_ip = isset($_SERVER['SERVER_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['SERVER_ADDR'])) : 'Unknown';
            if (filter_var($real_server_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $real_server_ipv4 = $real_server_ip;
            } elseif (filter_var($real_server_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                $real_server_ipv6 = $real_server_ip;
            }
        }

        if (empty($real_server_ipv4) && filter_var($real_server_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $real_server_ipv4 = $real_server_ip;
        }

        $is_server_ip_private = !filter_var($real_server_ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);

        // 5. Website CDN Detection & CDN IPs (IPv4 and IPv6)
        $cdn_detected = false;
        $cdn_provider = 'None (Direct Origin)';
        $cdn_ip = 'N/A';
        $cdn_ipv4 = '';
        $cdn_ipv6 = '';

        // Check if connecting peer or raw peer is an edge proxy
        $raw_peer = self::$connecting_peer_ip ?: (!empty($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '');

        // Check incoming CDN headers
        if (!empty($_SERVER['HTTP_CF_RAY']) || !empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            $cdn_detected = true;
            $cdn_provider = 'Cloudflare Anycast';
            if (!empty($raw_peer) && self::is_cloudflare_ip($raw_peer)) {
                $cdn_ip = $raw_peer;
            }
        } elseif (!empty($_SERVER['HTTP_FASTLY_CLIENT_IP']) || !empty($_SERVER['HTTP_X_FASTLY_REQUEST_ID'])) {
            $cdn_detected = true;
            $cdn_provider = 'Fastly CDN';
            if (!empty($raw_peer) && filter_var($raw_peer, FILTER_VALIDATE_IP)) {
                $cdn_ip = $raw_peer;
            }
        } elseif (!empty($_SERVER['HTTP_X_AMZ_CF_ID']) || !empty($_SERVER['HTTP_CLOUDFRONT_FORWARDED_PROTO'])) {
            $cdn_detected = true;
            $cdn_provider = 'Amazon CloudFront';
            if (!empty($raw_peer) && filter_var($raw_peer, FILTER_VALIDATE_IP)) {
                $cdn_ip = $raw_peer;
            }
        } elseif (!empty($_SERVER['HTTP_TRUE_CLIENT_IP']) || !empty($_SERVER['HTTP_X_AKAMAI_EDGESCAPE'])) {
            $cdn_detected = true;
            $cdn_provider = 'Akamai CDN';
            if (!empty($raw_peer) && filter_var($raw_peer, FILTER_VALIDATE_IP)) {
                $cdn_ip = $raw_peer;
            }
        } elseif (!empty($_SERVER['HTTP_X_SUCURI_CLIENTIP'])) {
            $cdn_detected = true;
            $cdn_provider = 'Sucuri WAF/CDN';
            if (!empty($raw_peer) && filter_var($raw_peer, FILTER_VALIDATE_IP)) {
                $cdn_ip = $raw_peer;
            }
        } elseif (!empty($_SERVER['HTTP_INCAP_CLIENT_IP'])) {
            $cdn_detected = true;
            $cdn_provider = 'Imperva / Incapsula';
            if (!empty($raw_peer) && filter_var($raw_peer, FILTER_VALIDATE_IP)) {
                $cdn_ip = $raw_peer;
            }
        } elseif (!empty($_SERVER['HTTP_X_BUNNY_CLIENT_IP'])) {
            $cdn_detected = true;
            $cdn_provider = 'Bunny CDN';
            if (!empty($raw_peer) && filter_var($raw_peer, FILTER_VALIDATE_IP)) {
                $cdn_ip = $raw_peer;
            }
        }

        // Domain Host resolution for Edge IP verification
        $site_host = wp_parse_url(get_site_url(), PHP_URL_HOST);
        $is_local_host = empty($site_host) || in_array($site_host, ['localhost', '127.0.0.1', '::1', 'local.test'], true) || preg_match('/\.local$/i', $site_host) || preg_match('/\.test$/i', $site_host);

        // Resolve DNS records (both A and AAAA) for site hostname to capture edge IPv4 and IPv6
        $resolved_ips = [];
        if (!$is_local_host) {
            // Method A: dns_get_record for A and AAAA
            if (function_exists('dns_get_record')) {
                $dns_a = @dns_get_record($site_host, DNS_A);
                if (is_array($dns_a)) {
                    foreach ($dns_a as $rec) {
                        if (!empty($rec['ip']) && filter_var($rec['ip'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                            $resolved_ips[] = $rec['ip'];
                        }
                    }
                }
                $dns_aaaa = @dns_get_record($site_host, DNS_AAAA);
                if (is_array($dns_aaaa)) {
                    foreach ($dns_aaaa as $rec) {
                        if (!empty($rec['ipv6']) && filter_var($rec['ipv6'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                            $resolved_ips[] = $rec['ipv6'];
                        }
                    }
                }
            }

            // Method B: gethostbynamel / gethostbyname fallback
            if (empty($resolved_ips) && function_exists('gethostbynamel')) {
                $hosts = @gethostbynamel($site_host);
                if (is_array($hosts)) {
                    $resolved_ips = array_merge($resolved_ips, $hosts);
                }
            }
            if (empty($resolved_ips) && function_exists('gethostbyname')) {
                $single = @gethostbyname($site_host);
                if (!empty($single) && $single !== $site_host && filter_var($single, FILTER_VALIDATE_IP)) {
                    $resolved_ips[] = $single;
                }
            }

            $resolved_ips = array_values(array_unique(array_filter($resolved_ips)));

            // Extract IPv4 and IPv6 edge IPs
            foreach ($resolved_ips as $rip) {
                if (filter_var($rip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && empty($cdn_ipv4)) {
                    $cdn_ipv4 = $rip;
                }
                if (filter_var($rip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) && empty($cdn_ipv6)) {
                    $cdn_ipv6 = $rip;
                }

                if (self::is_cloudflare_ip($rip)) {
                    $cdn_detected = true;
                    if ($cdn_provider === 'None (Direct Origin)') {
                        $cdn_provider = 'Cloudflare Anycast';
                    }
                }
            }

            // Assign primary CDN IP (prefer connecting raw peer if edge, or resolved IPv4, or resolved IPv6)
            if ($cdn_detected) {
                if (!empty($raw_peer) && (self::is_cloudflare_ip($raw_peer) || filter_var($raw_peer, FILTER_VALIDATE_IP))) {
                    $cdn_ip = $raw_peer;
                    if (filter_var($raw_peer, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                        $cdn_ipv4 = $raw_peer;
                    } elseif (filter_var($raw_peer, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                        $cdn_ipv6 = $raw_peer;
                    }
                } elseif (!empty($cdn_ipv4)) {
                    $cdn_ip = $cdn_ipv4;
                } elseif (!empty($cdn_ipv6)) {
                    $cdn_ip = $cdn_ipv6;
                } elseif (!empty($resolved_ips)) {
                    $cdn_ip = reset($resolved_ips);
                }
            }
        }

        // Contextual defaults when no CDN is active
        if (!$cdn_detected) {
            if ($is_local_host) {
                $cdn_ip = 'Local Dev (No CDN)';
            } else {
                $cdn_ip = 'Direct Connection';
            }
        } elseif ($cdn_ip === 'N/A') {
            $cdn_ip = $cdn_provider . ' Edge';
        }

        // 6. PHP RAM Limit & Process Allocation
        $raw_limit = ini_get('memory_limit') ?: '256M';
        $current_usage = memory_get_usage(true);
        $peak_usage = memory_get_peak_usage(true);
        $current_usage_mb = round($current_usage / (1024 * 1024), 1);
        $peak_usage_mb = round($peak_usage / (1024 * 1024), 1);

        // Shared hosting detection via server root path (without probing /proc or system directories)
        $is_shared_hosting = false;
        $hosting_env_label = 'Standard Web Hosting';
        $doc_root = isset($_SERVER['DOCUMENT_ROOT']) ? sanitize_text_field(wp_unslash($_SERVER['DOCUMENT_ROOT'])) : '';
        if (!empty($doc_root) && (strpos($doc_root, '/home/') !== false || strpos($doc_root, '/home2/') !== false || strpos($doc_root, '/vhosts/') !== false || strpos($doc_root, 'public_html') !== false)) {
            $is_shared_hosting = true;
            $hosting_env_label = 'cPanel Shared Hosting';
        }

        if ($raw_limit === '-1') {
            $display_limit = 'Unlimited (-1)';
            $free_str = 'Unlimited';
            $usage_percent = 5;
        } else {
            $display_limit = $raw_limit;
            $limit_bytes = 0;
            if (function_exists('wp_convert_hr_to_bytes')) {
                $limit_bytes = wp_convert_hr_to_bytes($raw_limit);
            } else {
                $value = trim($raw_limit);
                $last = strtolower($value[strlen($value) - 1]);
                $val = (int) $value;
                switch ($last) {
                    case 'g': $val *= 1024 * 1024 * 1024; break;
                    case 'm': $val *= 1024 * 1024; break;
                    case 'k': $val *= 1024; break;
                }
                $limit_bytes = $val;
            }
            $free_bytes = $limit_bytes > 0 ? max(0, $limit_bytes - $current_usage) : 0;
            $free_str = round($free_bytes / (1024 * 1024), 1) . ' MB';
            $usage_percent = ($limit_bytes > 0) ? min(100, round(($current_usage / $limit_bytes) * 100, 1)) : 0;
        }

        // 7. Developer Extras (Max Execution Time, Upload Limits, Execution User)
        $max_execution_time = ini_get('max_execution_time') ?: '30';
        $upload_max_filesize = ini_get('upload_max_filesize') ?: '32M';
        $post_max_size = ini_get('post_max_size') ?: '32M';
        $php_user = function_exists('get_current_user') ? get_current_user() : 'web-user';

        $auto_prepend = ini_get('auto_prepend_file');
        $waf_hook_mode = (!empty($auto_prepend) && strpos($auto_prepend, 'webcare') !== false)
            ? 'Early Prepend (auto_prepend_file)'
            : 'WordPress Runtime Filter (mu-plugin / action hook)';

        return [
            'linux_uname'          => $linux_uname_short,
            'linux_uname_full'     => $uname_full,
            'distro_name'          => $distro_name,
            'server_software'      => $server_software_raw,
            'server_software_type' => $server_software_type,
            'php_version'          => $php_version,
            'php_sapi'             => $php_sapi,
            'php_arch'             => $php_arch,
            'opcache_active'       => $opcache_active,
            'real_server_ip'       => $real_server_ip,
            'real_server_ipv4'     => $real_server_ipv4,
            'real_server_ipv6'     => $real_server_ipv6,
            'is_server_ip_private' => $is_server_ip_private,
            'cdn_available'        => $cdn_detected,
            'cdn_provider'         => $cdn_provider,
            'cdn_ip'               => $cdn_ip,
            'cdn_ipv4'             => $cdn_ipv4,
            'cdn_ipv6'             => $cdn_ipv6,
            'php_ram_limit'        => $display_limit,
            'php_ram_used'         => $current_usage_mb . ' MB',
            'php_ram_peak'         => $peak_usage_mb . ' MB',
            'php_ram_free'         => $free_str,
            'php_ram_percent'      => $usage_percent,
            'is_shared_hosting'    => $is_shared_hosting,
            'hosting_env_label'    => $hosting_env_label,
            'account_ram_limit'    => $is_shared_hosting ? 'cPanel Plan Limit (~1 GB)' : null,
            'max_execution_time'   => $max_execution_time . 's',
            'upload_max_filesize'  => $upload_max_filesize,
            'post_max_size'        => $post_max_size,
            'php_user'             => $php_user,
            'waf_hook_mode'        => $waf_hook_mode,
        ];
    }

    /**
     * Retrieve complete catalog of inspectable firewall rules and category groups
     *
     * @return array
     */
    public static function get_firewall_rules_catalog(): array {
        $catalog = [
            // Incident Containment & Upgrades
            ['id' => 'WAF-CONTAINMENT-LOCKDOWN', 'name' => 'Emergency Containment Write Lockdown', 'category' => 'Incident Containment', 'description' => 'Write operations are strictly prohibited while site is in Emergency Containment Mode.'],
            ['id' => 'WAF-CONTAINMENT-SURFACE-LOCK', 'name' => 'Emergency Containment Attack Surface Lock', 'category' => 'Incident Containment', 'description' => 'Endpoint locked down by Emergency Containment Mode.'],
            ['id' => 'WAF-ATOMIC-UPGRADE-LOCK', 'name' => 'Atomic Upgrade Lock Route Shield', 'category' => 'Supply Chain Defense', 'description' => 'Target resource is locked against unauthenticated access during an active software update.'],

            // Context-Adaptive & Dormant Surface
            ['id' => 'WAF-CAF-DORMANT-SURFACE', 'name' => 'Context-Adaptive Dormant Attack Surface Lockdown', 'category' => 'Dormant Surface Shield', 'description' => 'Direct requests to deactivated plugins are strictly blocked.'],
            ['id' => 'WAF-CAF-DORMANT-THEME', 'name' => 'Context-Adaptive Dormant Theme Surface Lockdown', 'category' => 'Dormant Surface Shield', 'description' => 'Direct requests to inactive themes are strictly blocked.'],

            // DoS, Buffer & Resource Floods
            ['id' => 'WAF-OVERSIZED-URI', 'name' => 'Oversized URI Buffer Overflow Guard', 'category' => 'DoS & Resource Shield', 'description' => 'Request URI length exceeded security buffer threshold.'],
            ['id' => 'WAF-OVERSIZED-QUERY', 'name' => 'Oversized Query String Guard', 'category' => 'DoS & Resource Shield', 'description' => 'Query string length exceeded security threshold.'],
            ['id' => 'WAF-OVERSIZED-POST-VARS', 'name' => 'Excessive Parameter Count Flood Guard', 'category' => 'DoS & Resource Shield', 'description' => 'POST payload exceeds recursive parameter threshold.'],
            ['id' => 'WAF-ADMIN-AJAX-BURST', 'name' => 'admin-ajax.php Burst Flood Limit Exceeded', 'category' => 'DoS & Resource Shield', 'description' => 'Unauthenticated client exceeded rate threshold on admin-ajax.php.'],
            ['id' => 'WAF-EXTERNAL-CRON-BLOCK', 'name' => 'External wp-cron.php Abuse Block', 'category' => 'DoS & Resource Shield', 'description' => 'External HTTP trigger to wp-cron.php blocked to prevent resource exhaustion.'],

            // Protocol, Header & Transport Defense
            ['id' => 'WAF-HOST-HEADER-POISON', 'name' => 'Host Header Poisoning & Cache Spoof Defense', 'category' => 'Protocol Defense', 'description' => 'HTTP Host header spoofing and poisoning attempt intercepted.'],
            ['id' => 'WAF-UNSAFE-HTTP-METHOD', 'name' => 'Unsafe HTTP Method Block', 'category' => 'Protocol Defense', 'description' => 'Unsafe or dangerous HTTP verbs (TRACE, TRACK, CONNECT, DEBUG) rejected.'],
            ['id' => 'WAF-UNAUTHORIZED-PUT-UPLOAD', 'name' => 'Unauthorized HTTP PUT File Upload Guard', 'category' => 'Protocol Defense', 'description' => 'Direct HTTP PUT file modification attempt blocked.'],
            ['id' => 'WAF-GUEST-AJAX-EMPTY', 'name' => 'Guest Endpoint Missing Action Probe', 'category' => 'Protocol Defense', 'description' => 'Unauthenticated empty action request to AJAX handler rejected.'],

            // Bot & Scraping Defense
            ['id' => 'WAF-EMPTY-POST-UA-REFERER', 'name' => 'Blank User-Agent & Referer POST Block', 'category' => 'Bot Defense', 'description' => 'Automated bot POST with empty User-Agent and Referer headers dropped.'],
            ['id' => 'WAF-EMPTY-USER-AGENT', 'name' => 'Blank or Missing User-Agent Block', 'category' => 'Bot Defense', 'description' => 'Automated guest request rejected: The HTTP User-Agent header was missing or blank (malicious vulnerability scanner or headless probe signature).'],

            // File Reconnaissance & Path Traversal
            ['id' => 'WAF-SENSITIVE-FILE-PROBE', 'name' => 'Sensitive File & Backup Probe Block', 'category' => 'File Reconnaissance', 'description' => 'Probing for .git, .env, wp-config backups, or SQL dumps blocked.'],
            ['id' => 'WAF-PATH-TRAVERSAL', 'name' => 'Path Traversal & LFI/RFI File Inclusion Armor', 'category' => 'Path Traversal', 'description' => 'Directory traversal (../, ..\\) and system file inclusion (/etc/passwd, php://filter) intercepted.'],

            // Core Web Exploits & Injection Armor
            ['id' => 'WAF-SQLI-ARMOR', 'name' => 'SQL Injection (SQLi) Heuristic Armor', 'category' => 'SQL Injection', 'description' => 'Malicious SQL exploitation signatures (UNION SELECT, benchmark, sleep) dropped.'],
            ['id' => 'WAF-PHP-CODE-INJECTION', 'name' => 'PHP Code Injection & Web Shell Shield', 'category' => 'PHP Code Injection', 'description' => 'Direct PHP script tag or dangerous execution function payload blocked.'],
            ['id' => 'WAF-XSS-ARMOR', 'name' => 'Cross-Site Scripting (XSS) Sanitization Guard', 'category' => 'Cross-Site Scripting (XSS)', 'description' => 'Hostile JavaScript injection, malicious SVG, or payload script tag dropped.'],
            ['id' => 'WAF-OBJECT-STREAM-INJECTION', 'name' => 'PHP Object Injection & Stream Wrapper Shield', 'category' => 'Execution Armor', 'description' => 'Serialized object payload or dangerous stream wrapper (phar://) blocked.'],
            ['id' => 'WAF-UPLOADS-PHP-DENY', 'name' => 'Uploads Directory PHP Execution Deny', 'category' => 'Execution Armor', 'description' => 'Direct PHP script execution inside uploads directory strictly blocked.'],

            // Security Policy & Hardening
            ['id' => 'WAF-XMLRPC-DISABLED', 'name' => 'XML-RPC Access Prohibited', 'category' => 'XML-RPC Disabled', 'description' => 'XML-RPC invocation blocked by administrator security policy.'],
            ['id' => 'WAF-DISALLOW-PHPMYADMIN-PLUGIN', 'name' => 'Prohibited Database Manager Plugin Installation', 'category' => 'Security Policy Enforcement', 'description' => 'Ad-hoc web database manager plugins are prohibited.'],
            ['id' => 'WAF-DISALLOW-FILEMANAGER-PLUGIN', 'name' => 'Prohibited File Manager Plugin Installation', 'category' => 'Security Policy Enforcement', 'description' => 'Web file manager plugins are prohibited on production environments.'],
            ['id' => 'WAF-INSTALL-LOCKDOWN', 'name' => 'WordPress Installer Lockdown', 'category' => 'Hardening Defense', 'description' => 'Access to install.php/upgrade.php blocked on established site.'],

            // AI & Prompt Injection
            ['id' => 'WAF-AI-PROMPT-INJECTION', 'name' => 'AI Prompt Injection & Agent Poisoning Shield', 'category' => 'AI & Agent Defense', 'description' => 'Hostile prompt injection, jailbreak syntax, and agent poisoning patterns neutralized.'],

            // Identity, Honeypots & Reconnaissance
            ['id' => 'WAF-FORBIDDEN-USERNAME-TRAP', 'name' => 'Forbidden Honeypot Username Trap', 'category' => 'Identity Defense', 'description' => 'Authentication attempt using trap usernames (admin, root) blocked.'],
            ['id' => 'WAF-REST-USER-ENUM', 'name' => 'REST API User Enumeration Interceptor', 'category' => 'Reconnaissance & Enumeration', 'description' => 'Unauthenticated user enumeration on /wp/v2/users intercepted.'],
            ['id' => 'WAF-AUTHOR-ENUM', 'name' => 'Author Permalink Enumeration Suppression', 'category' => 'Reconnaissance & Enumeration', 'description' => 'Author scan attempts (?author=1) deflected.'],
            ['id' => 'WAF-LOSTPW-VIEW-FLOOD', 'name' => 'Lost-Password View Burst Limit Exceeded', 'category' => 'Brute Force & Auth Armor', 'description' => 'Excessive views on lost password endpoint throttled.'],
            ['id' => 'WAF-LOSTPW-FLOOD-IP', 'name' => 'Lost-Password Request Flood Limit (IP)', 'category' => 'Brute Force & Auth Armor', 'description' => 'Too many password reset requests originating from this IP.'],
            ['id' => 'WAF-LOSTPW-FLOOD-USER', 'name' => 'Lost-Password Target User Bombing Guard', 'category' => 'Brute Force & Auth Armor', 'description' => 'Too many reset attempts targeting a single account identifier.'],

            // Behavioral & Unauthenticated API Defense
            ['id' => 'WAF-GUEST-AJAX-PROBE', 'name' => 'Unregistered Guest Action Probe', 'category' => 'Behavioral Defense', 'description' => 'Probing unregistered AJAX action hooks blocked.'],
            ['id' => 'WAF-GUEST-REST-BATCH-MUTATION', 'name' => 'Unauthenticated REST Batch Mutation Probe', 'category' => 'Behavioral Defense', 'description' => 'Batch modification probes on REST API blocked.'],
            ['id' => 'WAF-GUEST-REST-MUTATION', 'name' => 'Unauthenticated REST API Mutation Probe', 'category' => 'Behavioral Defense', 'description' => 'Direct unauthenticated POST/PUT/DELETE mutations to REST endpoints blocked.'],

            // WooCommerce & E-Commerce Defenses
            ['id' => 'WAF-WOO-CARDING-BLOCKED', 'name' => 'WooCommerce Carding Attack & Checkout Velocity Mitigation', 'category' => 'Behavioral Defense', 'description' => 'Rapid card testing and checkout bot spray blocked.'],
            ['id' => 'WAF-WOO-CARDING-THRESHOLD', 'name' => 'WooCommerce Carding Velocity Threshold Exceeded', 'category' => 'Behavioral Defense', 'description' => 'Excessive failed checkouts from this IP address.'],
            ['id' => 'WAF-WOO-COUPON-BLOCKED', 'name' => 'WooCommerce Coupon Enumeration & Brute-Force Shield', 'category' => 'Behavioral Defense', 'description' => 'Dictionary attack on coupon codes intercepted.'],
            ['id' => 'WAF-WOO-COUPON-THRESHOLD', 'name' => 'WooCommerce Coupon Velocity Threshold Exceeded', 'category' => 'Behavioral Defense', 'description' => 'Coupon testing threshold breached.'],
            ['id' => 'WAF-WOO-REG-DISPOSABLE-EMAIL', 'name' => 'WooCommerce Disposable Email Registration Block', 'category' => 'Behavioral Defense', 'description' => 'Customer registration using disposable/throwaway domain blocked.'],
            ['id' => 'WAF-WOO-REG-VELOCITY-BLOCKED', 'name' => 'WooCommerce Customer Registration Velocity Limit', 'category' => 'Behavioral Defense', 'description' => 'Excessive new customer account creations from this IP.'],
            ['id' => 'WAF-WOO-CART-VELOCITY-BLOCKED', 'name' => 'WooCommerce Cart Flooding Velocity Limit', 'category' => 'Behavioral Defense', 'description' => 'Denial of inventory cart manipulation blocked.'],
            ['id' => 'WAF-WOO-INVENTORY-HOARDING', 'name' => 'WooCommerce Denial of Inventory Cap Exceeded', 'category' => 'Behavioral Defense', 'description' => 'Mass cart abandonment holding stock captive blocked.'],
            ['id' => 'WAF-WOO-SCRAPING-BLOCKED', 'name' => 'WooCommerce Catalog & Price Scraping Mitigation', 'category' => 'Behavioral Defense', 'description' => 'Aggressive automated catalog pricing scraping blocked.'],
            ['id' => 'WAF-WOO-SCRAPING-THRESHOLD', 'name' => 'WooCommerce Catalog Scraping Threshold Exceeded', 'category' => 'Behavioral Defense', 'description' => 'Product view request rate exceeded scraping threshold.'],

            // Runtime RASP Protections
            ['id' => 'WAF-RASP-OPTION-TAMPER', 'name' => 'Runtime Option Tampering Guard', 'category' => 'Runtime RASP Hook Defense', 'description' => 'Runtime tampering of core site options (siteurl, home) intercepted.'],
            ['id' => 'WAF-RASP-ROLE-ESCALATION', 'name' => 'Runtime Privilege Escalation Guard', 'category' => 'Runtime RASP Hook Defense', 'description' => 'Unauthorized promotion of user capabilities intercepted.'],
            ['id' => 'WAF-RASP-ADMIN-REG-BLOCKED', 'name' => 'Runtime Administrator Registration Guard', 'category' => 'Runtime RASP Hook Defense', 'description' => 'Unauthorized account creation with administrator privileges blocked.'],
            ['id' => 'WAF-RASP-META-INJECTION', 'name' => 'Runtime User Meta Injection Guard', 'category' => 'Runtime RASP Hook Defense', 'description' => 'Hostile user meta manipulation targeting wp_capabilities blocked.'],
        ];

        // Affiliate Ecosystem Shield & Click-Fraud Armor (Rule #43: Only loaded if affiliate plugins detected)
        if (class_exists(AffiliateSecurityEngine::class)) {
            $ecosystem = AffiliateSecurityEngine::get_detected_ecosystem();
            if (!empty($ecosystem['is_active'])) {
                $catalog[] = ['id' => 'WAF-AFFILIATE-INJECTION', 'name' => 'Affiliate Referral Parameter Anti-Injection Armor', 'category' => 'Affiliate Defense', 'description' => 'SQL injection, XSS, or directory traversal exploit payload in affiliate referral parameter blocked.'];
                $catalog[] = ['id' => 'WAF-AFFILIATE-CLICK-FLOOD', 'name' => 'Affiliate Referral Click-Flood & Database Bloat Shield', 'category' => 'Affiliate Defense', 'description' => 'High-velocity referral click flood from IP exceeded safety threshold. Suppressed database visit logging to prevent table bloat and click-fraud.'];
                $catalog[] = ['id' => 'WAF-AFFILIATE-SPAM-REG', 'name' => 'Affiliate Registration Anti-Spam Gate', 'category' => 'Affiliate Defense', 'description' => 'Automated bot registration or disposable email rejected for affiliate account.'];
                $catalog[] = ['id' => 'WAF-AFFILIATE-SPOOF', 'name' => 'Affiliate Direct Link Tracking Referer Integrity Armor', 'category' => 'Affiliate Defense', 'description' => 'Automated crawler or headless request attempting fake direct link attribution blocked.'];
            }
        }

        return $catalog;
    }

    /**
     * Get recent blocked logs from daily JSON filesystem partitions
     */
    public static function get_logs(int $limit = 50, int $offset = 0, array $filters = []): array {
        return WafFileLogger::query_logs($filters, $limit, $offset);
    }

    /**
     * Get aggregate statistics and metrics for WAF logs dashboard
     */
    public static function get_log_stats(string $range = 'today'): array {
        return WafFileLogger::get_log_stats($range);
    }

    /**
     * Delete a single firewall incident log entry
     *
     * @param int|string $id
     */
    public static function delete_log($id): bool {
        return WafFileLogger::delete_log($id);
    }

    /**
     * Clear firewall logs
     */
    public static function clear_logs(): bool {
        if (class_exists('\\WebCareProScanner\\Firewall\\OutboundEgressFirewall')) {
            update_option(\WebCareProScanner\Firewall\OutboundEgressFirewall::OPTION_EVENTS, [], false);
        }
        return WafFileLogger::clear_all_logs();
    }
}
