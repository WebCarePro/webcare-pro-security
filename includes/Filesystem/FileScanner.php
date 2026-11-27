<?php
namespace WebCareProScanner\Filesystem;

use WebCareProScanner\Findings\Finding;
use WebCareProScanner\Malware\HeuristicEngine;

if (!defined('ABSPATH')) {
    exit;
}

class FileScanner {
    
    private $symlink_scanner;
    private $permission_scanner;
    private $hasher;
    private $heuristic_engine;
    private $js_scanner;
    private $url_scanner;

    public function __construct() {
        $this->symlink_scanner = new SymlinkScanner();
        $this->permission_scanner = new PermissionScanner();
        $this->hasher = new FileHasher();
        $this->heuristic_engine = new HeuristicEngine();
        $this->js_scanner = new \WebCareProScanner\Malware\JavaScriptSecurityScanner();
        $this->url_scanner = new \WebCareProScanner\Content\URLScanner();
    }

    /**
     * Scan a single file for anomalies and metadata.
     *
     * @param string     $file_path
     * @param string     $scan_id
     * @param array|null $custom_options Optional Custom Scan flag map (`null` = run all engines).
     * @return Finding[] Array of findings
     */
    public function scan_file($file_path, $scan_id, ?array $custom_options = null) {
        $findings = [];
        $run_all          = ($custom_options === null);
        $do_known_malware = $run_all || !empty($custom_options['scan_known_malware']);
        $do_backdoors     = $run_all || !empty($custom_options['scan_backdoors_heuristics']);
        $do_urls          = $run_all || !empty($custom_options['scan_malicious_urls']);
        $do_images_exec   = $run_all || !empty($custom_options['scan_images_executable']);
        $do_core          = $run_all || !empty($custom_options['scan_core_integrity']);
        $do_unbundled     = $run_all || !empty($custom_options['scan_unbundled_files']);
        $do_plugins       = $run_all || !empty($custom_options['scan_plugin_integrity']);
        $do_themes        = $run_all || !empty($custom_options['scan_theme_integrity']);
        
        if (!file_exists($file_path) && !is_link($file_path)) {
            return $findings; // Might have been deleted mid-scan
        }

        // Self-Exclusion: Do not scan the scanner's own plugin files or tests
        $norm_path = str_replace('\\', '/', $file_path);
        if (defined('WEBCAREPROSCAN_PATH')) {
            $plugin_root = str_replace('\\', '/', untrailingslashit(WEBCAREPROSCAN_PATH));
            if ($plugin_root !== '' && str_starts_with($norm_path, $plugin_root)) {
                return $findings;
            }
        }
        if (strpos($norm_path, '/plugins/webcare-pro-security/') !== false) {
            return $findings;
        }

        // Respect user-defined excluded paths / patterns
        if (class_exists('\\WebCareProScanner\\System\\SettingsManager') && \WebCareProScanner\System\SettingsManager::is_path_excluded($norm_path)) {
            return $findings;
        }

        // Uploads Cryptographic Hash Whitelist Check (0 database queries via local JSON registry):
        // If file resides in wp-content/uploads/ and matches an authentic verified file hash, skip heuristics and threat scans.
        if (strpos($norm_path, '/wp-content/uploads/') !== false) {
            if (class_exists('\\WebCareProScanner\\Findings\\WhitelistManager') && \WebCareProScanner\Findings\WhitelistManager::is_uploads_hash_whitelisted($file_path)) {
                return $findings;
            }
        }

        // 2. Symlink check (runs even on dangling links before metadata stat)
        if ($do_backdoors || $do_core || $do_plugins || $do_themes || $do_unbundled) {
            $symlink_finding = $this->symlink_scanner->scan($file_path, $scan_id);
            if ($symlink_finding) {
                $findings[] = $symlink_finding;
            }
        }

        if (!file_exists($file_path)) {
            return $findings;
        }

        $metadata = new FileMetadata($file_path);

        // 1. Permission check
        if ($do_backdoors || $do_core || $do_plugins || $do_themes) {
            $perm_finding = $this->permission_scanner->scan($file_path, $metadata, $scan_id);
            if ($perm_finding) {
                $findings[] = $perm_finding;
            }
        }

        // 3. Executable & .user.ini/.htaccess hijack check in uploads and subdirectories
        $norm_path = str_replace('\\', '/', $file_path);
        $ext = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
        $basename = strtolower(basename($file_path));

        if ($do_images_exec || $do_backdoors || $do_known_malware) {
            if (strpos($norm_path, '/wp-content/uploads/') !== false) {
                if (!preg_match('#/(webcare-pro-security|webcare-pro-quarantine|webcare-vault|webcare-waf|webcare-quarantine)/#i', $norm_path) && !\WebCareProScanner\System\SettingsManager::is_path_excluded($norm_path)) {
                    if (in_array($ext, ['php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'pht', 'phar', 'hphp', 'phps', 'pgif', 'suspected', 'sh', 'py', 'pl', 'cgi', 'rb'], true)) {
                        if (($basename === 'index.php' || $basename === 'index.html' || $basename === 'index.htm') && \WebCareProScanner\System\SettingsManager::is_safe_directory_index($file_path)) {
                            // Harmless directory silence placeholder, ignore
                        } elseif (\WebCareProScanner\System\SettingsManager::is_legitimate_uploads_cache_file($file_path)) {
                            // Legitimate verified plugin cache file with 0 malware
                        } else {
                            $findings[] = new Finding([
                                'engine'      => 'filesystem',
                                'type'        => 'executable_in_uploads',
                                'severity'    => 'high',
                                'confidence'  => 85,
                                'file_path'   => $file_path,
                                'description' => 'Executable script file found in uploads directory.',
                                'evidence'    => "Extension: {$ext} in /uploads/",
                            ]);
                        }
                    }
                }
            } elseif ($ext === 'suspected') {
                $findings[] = new Finding([
                    'engine'      => 'filesystem',
                    'type'        => 'quarantined_suspected_file',
                    'severity'    => 'high',
                    'confidence'  => 95,
                    'file_path'   => $file_path,
                    'description' => 'Residual .suspected file detected on disk. Often left behind when a compromised script is partially quarantined.',
                    'evidence'    => 'File uses .suspected extension: ' . basename($file_path),
                ]);
            }

            // 3c. Subdirectory .user.ini / php.ini / .htaccess PHP handler or auto_prepend_file hijack
            if (in_array($basename, ['.user.ini', 'php.ini', '.htaccess'], true)) {
                $abs_root = rtrim(str_replace('\\', '/', ABSPATH), '/');
                $is_root_cfg = (dirname($norm_path) === $abs_root);
                if (!$is_root_cfg && is_readable($file_path) && filesize($file_path) <= 262144) {
                    $cfg_body = (string) @file_get_contents($file_path);
                    if ($basename === '.htaccess') {
                        if (preg_match('/^\s*(?:AddHandler|SetHandler|AddType)\s+[^\r\n]*(?:php|cgi|fcgi|phtml)/mi', $cfg_body, $hm)
                            || preg_match('/^\s*php_value\s+auto_(?:prepend|append)_file\s+(\S+)/mi', $cfg_body, $hm)
                        ) {
                            $findings[] = new Finding([
                                'engine'       => 'filesystem',
                                'type'         => 'rogue_subdirectory_htaccess',
                                'severity'     => 'critical',
                                'confidence'   => 95,
                                'file_path'    => $file_path,
                                'code_snippet' => trim($hm[0]),
                                'description'  => 'Subdirectory .htaccess enables rogue PHP/CGI execution or auto_prepend_file hijacking.',
                                'evidence'     => 'Malicious Apache directive in subdirectory .htaccess: ' . trim($hm[0]),
                            ]);
                        }
                    } else {
                        if (preg_match('/^\s*auto_(?:prepend|append)_file\s*=\s*([^\r\n;]+)/mi', $cfg_body, $im)) {
                            $target_prep = trim($im[1], " \t\"'");
                            if ($target_prep !== '' && strtolower($target_prep) !== 'none' && strpos($target_prep, 'webcare') === false && strpos($target_prep, 'wordfence-waf.php') === false) {
                                $findings[] = new Finding([
                                    'engine'       => 'filesystem',
                                    'type'         => 'rogue_user_ini_prepend',
                                    'severity'     => 'critical',
                                    'confidence'   => 98,
                                    'file_path'    => $file_path,
                                    'code_snippet' => trim($im[0]),
                                    'description'  => "Subdirectory {$basename} hijacks PHP-FPM execution via auto_prepend_file / auto_append_file.",
                                    'evidence'     => 'Directive: ' . trim($im[0]),
                                ]);
                            }
                        }
                    }
                }
            }
        }

        // 4. PHP Heuristic Malware Scan
        if ($do_known_malware || $do_backdoors || $do_urls) {
            try {
                $malware_findings = $this->heuristic_engine->scan_file($file_path, $scan_id, $custom_options);
                if (!empty($malware_findings)) {
                    $findings = array_merge($findings, $malware_findings);
                }
            } catch (\Throwable $e) {
                // Guard against individual file heuristic failure
            }
        }

        // 5. Client-Side JavaScript & Inline Script Threat Scan (ClickFix, EtherHiding, Magecart, Skimmers)
        if ($do_backdoors || $do_urls) {
            if (in_array($ext, ['js', 'mjs', 'cjs'], true)) {
                $js_findings = $this->js_scanner->scan_file($file_path, $scan_id);
                if (!empty($js_findings)) {
                    $findings = array_merge($findings, $js_findings);
                }
            } elseif (in_array($ext, ['html', 'htm', 'shtml', 'php', 'phtml'], true) && is_readable($file_path) && filesize($file_path) <= 2 * 1024 * 1024) {
                // Skip verified official Core/Plugin/Theme files for inline JS & URL extraction
                $is_authentic = \WebCareProScanner\Integrity\ChecksumProvider::is_authentic_core_file($file_path)
                    || \WebCareProScanner\Integrity\ChecksumProvider::is_authentic_plugin_file($file_path)
                    || \WebCareProScanner\Integrity\ChecksumProvider::is_authentic_theme_file($file_path)
                    || \WebCareProScanner\Integrity\ChecksumProvider::is_authentic_known_library($file_path);

                if (!$is_authentic) {
                    $raw_markup = (string) @file_get_contents($file_path);
                    if ($raw_markup !== '' && stripos($raw_markup, '<script') !== false) {
                        if (preg_match_all('/<script\b[^>]*>([\s\S]*?)<\/script>/i', $raw_markup, $sm) && !empty($sm[1])) {
                            $combined_js = implode("\n;\n", $sm[1]);
                            if (trim($combined_js) !== '') {
                                $inline_js_findings = $this->js_scanner->scan_content($combined_js, $file_path, $scan_id);
                                if (!empty($inline_js_findings)) {
                                    $findings = array_merge($findings, $inline_js_findings);
                                }
                            }
                        }
                    }
                    if ($do_urls && $raw_markup !== '') {
                        foreach ($this->url_scanner->scan_urls($raw_markup) as $uh) {
                            if (($uh['severity'] ?? 'low') === 'low') {
                                continue;
                            }
                            $findings[] = new Finding([
                                'engine'      => 'malware-url',
                                'type'        => $uh['type'] ?? 'suspicious_external_url',
                                'severity'    => $uh['severity'] ?? 'high',
                                'confidence'  => $uh['confidence'] ?? 85,
                                'file_path'   => $file_path,
                                'description' => $uh['desc'] ?? 'Suspicious external URL detected in file.',
                                'evidence'    => 'URL: ' . ($uh['url'] ?? ''),
                            ]);
                        }
                    }
                }
            }
        }

        // 5b. Dedicated URL Threat Intel on standalone JS files when scan_malicious_urls is active
        if ($do_urls && in_array($ext, ['js', 'mjs', 'cjs'], true) && is_readable($file_path) && filesize($file_path) <= 4194304) {
            if (!\WebCareProScanner\Integrity\ChecksumProvider::is_authentic_core_file($file_path)
                && !\WebCareProScanner\Integrity\ChecksumProvider::is_authentic_plugin_file($file_path)
                && !\WebCareProScanner\Integrity\ChecksumProvider::is_authentic_theme_file($file_path)
                && !\WebCareProScanner\Integrity\ChecksumProvider::is_authentic_known_library($file_path)
            ) {
                $js_body = (string) @file_get_contents($file_path);
                if ($js_body !== '') {
                    foreach ($this->url_scanner->scan_urls($js_body) as $uh) {
                        if (($uh['severity'] ?? 'low') === 'low') {
                            continue;
                        }
                        $findings[] = new Finding([
                            'engine'      => 'malware-url',
                            'type'        => $uh['type'] ?? 'suspicious_external_url',
                            'severity'    => $uh['severity'] ?? 'high',
                            'confidence'  => $uh['confidence'] ?? 85,
                            'file_path'   => $file_path,
                            'description' => $uh['desc'] ?? 'Suspicious external URL detected in JavaScript file.',
                            'evidence'    => 'URL: ' . ($uh['url'] ?? ''),
                        ]);
                    }
                }
            }
        }

        // 6. Strict Official Integrity & Rogue/Unknown File Detection
        if ($do_core || $do_unbundled || $do_plugins || $do_themes) {
            try {
                $integrity_findings = $this->verify_official_integrity($file_path, $scan_id, $custom_options);
                if (!empty($integrity_findings)) {
                    $findings = array_merge($findings, $integrity_findings);
                }
            } catch (\Throwable $e) {
                // Guard against individual file integrity verification error
            }
        }

        return $findings;
    }

    /**
     * Strictly verify files against official WordPress.org release manifests (Core, Plugins, Themes)
     * and strictly detect modified files or unknown rogue files inside core, root, or official components.
     *
     * @param string     $file_path
     * @param string     $scan_id
     * @param array|null $custom_options
     * @return Finding[]
     */
    private function verify_official_integrity($file_path, $scan_id, ?array $custom_options = null) {
        $findings     = [];
        $run_all      = ($custom_options === null);
        $do_core      = $run_all || !empty($custom_options['scan_core_integrity']);
        $do_unbundled = $run_all || !empty($custom_options['scan_unbundled_files']);
        $do_plugins   = $run_all || !empty($custom_options['scan_plugin_integrity']);
        $do_themes    = $run_all || !empty($custom_options['scan_theme_integrity']);

        // 1. Core & Root Integrity Verification
        if ($do_core || $do_unbundled) {
            $core_check = \WebCareProScanner\Integrity\ChecksumProvider::verify_core_file($file_path);
            if ($core_check['status'] === 'modified' && $do_core) {
                $findings[] = new Finding([
                    'engine'      => 'integrity-core',
                    'type'        => 'modified_core_file',
                    'severity'    => 'high',
                    'confidence'  => 99,
                    'file_path'   => wp_normalize_path($file_path),
                    'description' => "WordPress core file differs from the official checksum: {$core_check['rel_file']}",
                    'evidence'    => "Expected: {$core_check['expected']}, Actual: {$core_check['actual']}"
                ]);
            } elseif ($core_check['status'] === 'unknown' && $do_unbundled) {
                $basename_lower = strtolower(basename($file_path));
                $norm_path = str_replace('\\', '/', $file_path);

                if (strpos($norm_path, '/.well-known/') !== false) {
                    return $findings;
                }
                if ($basename_lower === '.htaccess') {
                    if (class_exists('\\WebCareProScanner\\System\\SettingsManager') && \WebCareProScanner\System\SettingsManager::is_safe_protective_htaccess($file_path)) {
                        return $findings;
                    }
                }
                if ($basename_lower === 'wordfence-waf.php') {
                    $content = @file_get_contents($file_path, false, null, 0, 8192);
                    if ($content !== false && (strpos($content, 'WFWAF_LOG_PATH') !== false || strpos($content, 'wordfence/waf/bootstrap.php') !== false || strpos($content, 'wordfence') !== false)) {
                        return $findings;
                    }
                }

                $ext = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
                $is_executable = in_array($ext, ['php', 'phtml', 'php5', 'php7', 'phar', 'inc', 'cgi', 'sh', 'pl'], true);
                $findings[] = new Finding([
                    'engine'      => 'integrity-core',
                    'type'        => 'unknown_core_file',
                    'severity'    => $is_executable ? 'high' : 'medium',
                    'confidence'  => 95,
                    'file_path'   => wp_normalize_path($file_path),
                    'description' => "Unrecognized/unknown file found inside WordPress core/root: {$core_check['rel_file']}",
                    'evidence'    => "File '{$core_check['rel_file']}' is not part of the official WordPress release manifest."
                ]);
            }
        }

        // 2. Official Plugins Integrity Verification
        if ($do_plugins) {
            $plugin_check = \WebCareProScanner\Integrity\ChecksumProvider::verify_plugin_file($file_path);
            if ($plugin_check['status'] === 'modified') {
                $findings[] = new Finding([
                    'engine'      => 'integrity-plugin',
                    'type'        => 'modified_plugin_file',
                    'severity'    => 'high',
                    'confidence'  => 95,
                    'file_path'   => wp_normalize_path($file_path),
                    'description' => "Plugin file differs from official WordPress.org checksum: {$plugin_check['slug']}/{$plugin_check['rel_file']}",
                    'evidence'    => "Expected: {$plugin_check['expected']}, Actual: {$plugin_check['actual']}"
                ]);
            } elseif ($plugin_check['status'] === 'unknown' && ($run_all || $do_unbundled || $do_plugins)) {
                $ext = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
                $is_executable = in_array($ext, ['php', 'phtml', 'php5', 'php7', 'phar', 'inc', 'cgi', 'sh', 'pl'], true);
                $findings[] = new Finding([
                    'engine'      => 'integrity-plugin',
                    'type'        => 'unknown_plugin_file',
                    'severity'    => $is_executable ? 'high' : 'medium',
                    'confidence'  => 95,
                    'file_path'   => wp_normalize_path($file_path),
                    'description' => "Unrecognized/unknown file found inside official plugin {$plugin_check['slug']}: {$plugin_check['rel_file']}",
                    'evidence'    => "File '{$plugin_check['rel_file']}' is not part of the official WordPress.org release manifest for plugin {$plugin_check['slug']}."
                ]);
            }
        }

        // 3. Official Themes Integrity Verification
        if ($do_themes) {
            $theme_check = \WebCareProScanner\Integrity\ChecksumProvider::verify_theme_file($file_path);
            if ($theme_check['status'] === 'modified') {
                $findings[] = new Finding([
                    'engine'      => 'integrity-theme',
                    'type'        => 'modified_theme_file',
                    'severity'    => 'high',
                    'confidence'  => 95,
                    'file_path'   => wp_normalize_path($file_path),
                    'description' => "Theme file differs from official WordPress.org checksum: {$theme_check['slug']}/{$theme_check['rel_file']}",
                    'evidence'    => "Expected: {$theme_check['expected']}, Actual: {$theme_check['actual']}"
                ]);
            } elseif ($theme_check['status'] === 'unknown' && ($run_all || $do_unbundled || $do_themes)) {
                $ext = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
                $is_executable = in_array($ext, ['php', 'phtml', 'php5', 'php7', 'phar', 'inc', 'cgi', 'sh', 'pl'], true);
                $findings[] = new Finding([
                    'engine'      => 'integrity-theme',
                    'type'        => 'unknown_theme_file',
                    'severity'    => $is_executable ? 'high' : 'medium',
                    'confidence'  => 95,
                    'file_path'   => wp_normalize_path($file_path),
                    'description' => "Unrecognized/unknown file found inside official theme {$theme_check['slug']}: {$theme_check['rel_file']}",
                    'evidence'    => "File '{$theme_check['rel_file']}' is not part of the official WordPress.org release manifest for theme {$theme_check['slug']}."
                ]);
            }
        }

        return $findings;
    }
}
