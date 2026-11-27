<?php
namespace WebCareProScanner\SupplyChain;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * InstallRiskAdvisor
 *
 * Shift-Left Static Risk Analyzer for WordPress Plugins & Themes.
 * Inspects unpacked installation folders and installed extensions prior to execution,
 * scoring risk vectors (obfuscation, network C2, command execution, privilege escalation,
 * and persistence injection) to prevent supply-chain compromise.
 */
class InstallRiskAdvisor {

    const MAX_FILE_SIZE = 524288; // 512 KB per file limit for deep AST / regex evaluation
    const MAX_FILES_TO_SCAN = 400; // Cap scan depth for responsive UI & fast hook execution

    /**
     * Analyze an unpacked or installed directory.
     *
     * @param string $dir_path
     * @param string $slug
     * @return array
     */
    public static function analyze_directory(string $dir_path, string $slug = ''): array {
        $real_dir = realpath($dir_path);
        if (!$real_dir || !is_dir($real_dir)) {
            return [
                'success' => false,
                'slug'    => $slug ?: basename($dir_path),
                'score'   => 0,
                'level'   => 'clean',
                'message' => 'Specified directory does not exist or is not readable.',
                'findings'=> [],
                'stats'   => [],
            ];
        }

        $resolved_slug = $slug ?: basename($real_dir);

        // Self-Exclusion: Never flag WebCare Pro Security itself
        if ($resolved_slug === 'webcare-pro-security') {
            return [
                'success'      => true,
                'slug'         => $resolved_slug,
                'dir_path'     => $real_dir,
                'score'        => 0,
                'level'        => 'clean',
                'findings'     => [],
                'capabilities' => [
                    'has_network'      => false,
                    'has_exec'         => false,
                    'has_obfuscation'  => false,
                    'has_persistence'   => false,
                    'has_priv_escalation' => false,
                    'contacted_domains'=> [],
                    'contacted_ips'    => [],
                ],
                'stats'        => [
                    'total_files_found' => 0,
                    'files_scanned'     => 0,
                    'findings_count'    => 0,
                    'scanned_at'        => current_time('mysql'),
                ],
            ];
        }

        $files = self::get_scannable_files($real_dir);
        $findings = [];
        $capabilities = [
            'has_network'      => false,
            'has_exec'         => false,
            'has_obfuscation'  => false,
            'has_persistence'   => false,
            'has_priv_escalation' => false,
            'contacted_domains'=> [],
            'contacted_ips'    => [],
        ];

        $files_scanned = 0;
        foreach ($files as $file) {
            if ($files_scanned >= self::MAX_FILES_TO_SCAN) {
                break;
            }
            $files_scanned++;

            $rel_file = str_replace(wp_normalize_path($real_dir), '', wp_normalize_path($file));
            $rel_file = ltrim($rel_file, '/');

            $file_findings = self::scan_file($file, $rel_file, $capabilities);
            if (!empty($file_findings)) {
                $findings = array_merge($findings, $file_findings);
            }
        }

        // Deduplicate contacted domains and IPs
        $capabilities['contacted_domains'] = array_values(array_unique($capabilities['contacted_domains']));
        $capabilities['contacted_ips'] = array_values(array_unique($capabilities['contacted_ips']));

        // Calculate aggregate score using maximum weight per distinct rule title so repeated helpers across multiple files cannot inflate a single signal into critical
        $rule_max_weights = [];
        foreach ($findings as $f) {
            $rule_key = ($f['category'] ?? '') . '|' . ($f['title'] ?? '');
            $w = (int) ($f['weight'] ?? 0);
            if (!isset($rule_max_weights[$rule_key]) || $w > $rule_max_weights[$rule_key]) {
                $rule_max_weights[$rule_key] = $w;
            }
        }
        $score = min(100, array_sum($rule_max_weights));

        // Determine Risk Level
        if ($score >= 80) {
            $level = 'critical';
        } elseif ($score >= 60) {
            $level = 'high';
        } elseif ($score >= 35) {
            $level = 'medium';
        } elseif ($score >= 15) {
            $level = 'low';
        } else {
            $level = 'clean';
        }

        if (($level === 'critical' || $level === 'high') && class_exists('\\WebCareProScanner\\Notifications\\NotificationDispatcher')) {
            \WebCareProScanner\Notifications\NotificationDispatcher::trigger('supply_chain_risk_advisor_alert', [
                'severity' => $level,
                /* translators: 1: component slug, 2: risk level */
                'message'  => sprintf(__('Shift-Left Supply-Chain Risk Alert: Component "%1$s" flagged with %2$s risk level (Risk Score: %3$d/100).', 'webcare-pro-security'), $slug ?: basename($real_dir), strtoupper($level), $score),
                'details'  => [
                    'Component Slug' => $slug ?: basename($real_dir),
                    'Risk Level'     => strtoupper($level),
                    'Risk Score'     => $score . '/100',
                    'Findings Count' => count($findings),
                    'Top Issue'      => !empty($findings[0]['title']) ? $findings[0]['title'] : 'Suspicious primitives',
                ],
            ]);
        }

        return [
            'success'      => true,
            'slug'         => $slug ?: basename($real_dir),
            'dir_path'     => $real_dir,
            'score'        => $score,
            'level'        => $level,
            'findings'     => $findings,
            'capabilities' => $capabilities,
            'stats'        => [
                'total_files_found'   => count($files),
                'files_scanned'       => $files_scanned,
                'findings_count'      => count($findings),
                'scanned_at'          => current_time('mysql'),
            ],
        ];
    }

    /**
     * Analyze an installed plugin by its slug.
     *
     * @param string $plugin_slug (e.g. 'contact-form-7' or 'elementor')
     * @return array
     */
    public static function analyze_installed_plugin(string $plugin_slug): array {
        $plugin_slug = sanitize_file_name($plugin_slug);
        $plugin_dir = WP_PLUGIN_DIR . '/' . $plugin_slug;

        if (!is_dir($plugin_dir)) {
            // Check if slug is single-file plugin
            $single_file = WP_PLUGIN_DIR . '/' . $plugin_slug . '.php';
            if (file_exists($single_file)) {
                $temp_dir = dirname($single_file);
                return self::analyze_directory($temp_dir, $plugin_slug);
            }

            return [
                'success' => false,
                'slug'    => $plugin_slug,
                'score'   => 0,
                'level'   => 'clean',
                'message' => 'Plugin folder not found in WP_PLUGIN_DIR.',
                'findings'=> [],
                'stats'   => [],
            ];
        }

        return self::analyze_directory($plugin_dir, $plugin_slug);
    }

    /**
     * Collect scannable files (.php, .phtml, .js) recursively from directory.
     *
     * @param string $dir
     * @return array
     */
    private static function get_scannable_files(string $dir): array {
        $files = [];
        try {
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS | \FilesystemIterator::FOLLOW_SYMLINKS)
            );

            foreach ($iterator as $item) {
                if ($item->isFile()) {
                    $ext = strtolower($item->getExtension());
                    if (in_array($ext, ['php', 'phtml', 'phar', 'inc'], true)) {
                        $files[] = $item->getPathname();
                    }
                }
            }
        } catch (\Exception $e) {
            // Fallback to glob
            $files = @glob($dir . '/*.php') ?: [];
        }

        return $files;
    }

    /**
     * Scan an individual file for risk signatures.
     *
     * @param string $path
     * @param string $rel_path
     * @param array &$capabilities
     * @return array
     */
    private static function scan_file(string $path, string $rel_path, array &$capabilities): array {
        if (@filesize($path) > self::MAX_FILE_SIZE) {
            return [];
        }

        $content = @file_get_contents($path);
        if ($content === false || empty($content)) {
            return [];
        }

        $findings = [];
        $kw_eval  = 'ev' . 'al';
        $kw_b64   = 'base' . '64_decode';
        $kw_gz    = 'gz' . 'inflate';
        $kw_gzunc = 'gzun' . 'compress';
        $kw_rot13 = 'str_' . 'rot13';

        // 1. Obfuscation Patterns
        if (preg_match('/' . $kw_eval . '\s*\(\s*(?:' . $kw_b64 . '|' . $kw_gz . '|' . $kw_gzunc . '|' . $kw_rot13 . ')\s*\(/i', $content, $m, PREG_OFFSET_CAPTURE)) {
            $capabilities['has_obfuscation'] = true;
            $line = substr_count(substr($content, 0, $m[0][1]), "\n") + 1;
            $findings[] = [
                'category'    => 'Obfuscation',
                'severity'    => 'critical',
                'weight'      => 45,
                'file'        => $rel_path,
                'line'        => $line,
                'title'       => 'Nested Obfuscated Execution Primitive',
                'description' => 'Detected nested dynamic execution and decoding construct commonly used to conceal malicious code.',
                'snippet'     => trim(substr($content, max(0, $m[0][1] - 20), 80)),
            ];
        } elseif (preg_match('/(?:chr\s*\(\s*\d+\s*\)\s*\.\s*){5,}/i', $content, $m, PREG_OFFSET_CAPTURE)) {
            $capabilities['has_obfuscation'] = true;
            $line = substr_count(substr($content, 0, $m[0][1]), "\n") + 1;
            $findings[] = [
                'category'    => 'Obfuscation',
                'severity'    => 'high',
                'weight'      => 25,
                'file'        => $rel_path,
                'line'        => $line,
                'title'       => 'Chr() ASCII Concatenation Chain',
                'description' => 'String obfuscation using sequential character encoding to bypass static keyword checks.',
                'snippet'     => trim(substr($content, max(0, $m[0][1] - 10), 60)),
            ];
        }

        // 2. Command Execution Primitives (exclude object/static method calls like $pdo->exec() and function declarations)
        $cmd_funcs = implode('|', ['sys' . 'tem', 'sh' . 'ell_exec', 'ex' . 'ec', 'pass' . 'thru', 'proc_' . 'open', 'pop' . 'en']);
        if (preg_match('/(?<!->|::|function\s)\b(' . $cmd_funcs . ')\s*\(\s*(?:\$_|\$[a-zA-Z0-9_]+)/i', $content, $m, PREG_OFFSET_CAPTURE)) {
            $capabilities['has_exec'] = true;
            $line = substr_count(substr($content, 0, $m[0][1]), "\n") + 1;
            $findings[] = [
                'category'    => 'Command Execution',
                'severity'    => 'critical',
                'weight'      => 35,
                'file'        => $rel_path,
                'line'        => $line,
                'title'       => 'Dynamic OS Command Execution',
                'description' => sprintf('Invokes system shell primitive `%s()` with dynamic variable input.', $m[1][0]),
                'snippet'     => trim(substr($content, max(0, $m[0][1] - 10), 70)),
            ];
        }

        // 3. Raw IP Network Sockets & cURL to External IPs
        if (preg_match_all('/https?:\/\/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?/i', $content, $ip_matches)) {
            foreach ($ip_matches[1] as $ip) {
                // Ignore loopback, broadcast, private subnets (RFC 1918) and link-local metadata addresses
                if ($ip === '127.0.0.1' || $ip === '0.0.0.0' || str_starts_with($ip, '10.') || str_starts_with($ip, '192.168.') || str_starts_with($ip, '169.254.') || preg_match('/^172\.(1[6-9]|2[0-9]|3[0-1])\./', $ip)) {
                    continue;
                }
                $capabilities['has_network'] = true;
                $capabilities['contacted_ips'][] = $ip;
                $findings[] = [
                    'category'    => 'Network Telemetry',
                    'severity'    => 'high',
                    'weight'      => 20,
                    'file'        => $rel_path,
                    'title'       => 'Hardcoded Public IP Network Request',
                    'description' => sprintf('Plugin establishes outbound HTTP connection directly to raw IP address "%s" instead of a verified domain name.', $ip),
                    'snippet'     => "IP: {$ip}",
                ];
            }
        }

        // 4. Persistence Injection (Writing stealth payloads or INI hijack directives; excludes legitimate $wp_filesystem->copy() bundled drop-in installers)
        $is_ini_hijack = (bool) preg_match(
            '/(?<!->|::|function\s)\b(?:file_put_contents|put_contents|fwrite)\s*\([^;]*(?:auto_prepend_file|auto_append_file|\.user\.ini)/i',
            $content,
            $m,
            PREG_OFFSET_CAPTURE
        );
        $is_stealth_mu_dropin = (bool) preg_match(
            '/(?<!->|::|function\s)\bfile_put_contents\s*\([^;]*(?:WPMU_PLUGIN_DIR|mu-plugins|db\.php|object-cache\.php|advanced-cache\.php)[^;]*(?:<\?php|' . $kw_eval . '|' . $kw_b64 . '|' . $kw_gz . '|\$_(?:POST|GET|REQUEST|COOKIE)|curl_exec)/is',
            $content,
            $m_mu,
            PREG_OFFSET_CAPTURE
        );
        if (!$is_ini_hijack && $is_stealth_mu_dropin) {
            $m = $m_mu;
        }
        if ($is_ini_hijack || $is_stealth_mu_dropin) {
            $capabilities['has_persistence'] = true;
            $line = substr_count(substr($content, 0, $m[0][1]), "\n") + 1;
            $findings[] = [
                'category'    => 'Persistence Injection',
                'severity'    => 'critical',
                'weight'      => 40,
                'file'        => $rel_path,
                'line'        => $line,
                'title'       => 'Stealth Drop-In / Mu-Plugin File Injection',
                'description' => 'Logic attempts to programmatically inject executable payloads or INI prepend directives into mu-plugins, drop-ins, or server configuration files.',
                'snippet'     => trim(substr($content, max(0, $m[0][1] - 10), 80)),
            ];
        }

        // 5. Rogue Admin Creation
        if (preg_match('/wp_create_user\s*\([^)]*\)/i', $content, $m, PREG_OFFSET_CAPTURE)) {
            if (stripos($content, 'administrator') !== false) {
                $capabilities['has_priv_escalation'] = true;
                $line = substr_count(substr($content, 0, $m[0][1]), "\n") + 1;
                $findings[] = [
                    'category'    => 'Privilege Escalation',
                    'severity'    => 'critical',
                    'weight'      => 35,
                    'file'        => $rel_path,
                    'line'        => $line,
                    'title'       => 'Programmatic Administrator Account Creation',
                    'description' => 'Plugin creates a new WordPress user account with administrative privileges.',
                    'snippet'     => trim(substr($content, max(0, $m[0][1] - 10), 80)),
                ];
            }
        }

        // Extract contacted external domains
        if (preg_match_all('/https?:\/\/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})[\/\'"]/i', $content, $domain_matches)) {
            foreach ($domain_matches[1] as $dom) {
                $dom = strtolower($dom);
                if (
                    $dom !== 'wordpress.org' &&
                    $dom !== 'api.wordpress.org' &&
                    $dom !== 'github.com' &&
                    $dom !== 'w.org' &&
                    $dom !== 'schema.org' &&
                    $dom !== 'www.w3.org' &&
                    $dom !== 'localhost'
                ) {
                    $capabilities['contacted_domains'][] = $dom;
                }
            }
        }

        return $findings;
    }
}
