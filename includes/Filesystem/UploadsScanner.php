<?php
namespace WebCareProScanner\Filesystem;

use WebCareProScanner\Findings\Finding;

if (!defined('ABSPATH')) {
    exit;
}

class UploadsScanner {

    /**
     * Dangerous executable and script extensions prohibited in media uploads.
     */
    private $executable_extensions = [
        'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'phar', 'inc', 'hphp', 'pht', 'suspected',
        'sh', 'bash', 'zsh', 'ksh', 'csh', 'pl', 'cgi', 'py', 'rb',
        'exe', 'bat', 'cmd', 'com', 'bin', 'elf', 'so', 'dll', 'vbs', 'wsf', 'scr',
        'jsp', 'asp', 'aspx'
    ];

    /**
     * Common image and media extensions subject to deep forensic inspection.
     */
    private $image_extensions = [
        'jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'ico', 'svg', 'svgz', 'tiff', 'tif', 'avif'
    ];

    /**
     * Document and other non-executable media extensions.
     */
    private $document_extensions = [
        'txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'csv'
    ];

    /**
     * Scan the WordPress uploads directory for any scripts or suspicious files.
     *
     * @param string $scan_id
     * @return Finding[]
     */
    public function scan($scan_id) {
        $findings = [];

        $upload_dir_info = wp_upload_dir();
        $uploads_path = !empty($upload_dir_info['basedir']) ? $upload_dir_info['basedir'] : '';

        if (empty($uploads_path) || !is_dir($uploads_path)) {
            return $findings;
        }

        try {
            $flags = \FilesystemIterator::KEY_AS_PATHNAME | \FilesystemIterator::CURRENT_AS_FILEINFO | \FilesystemIterator::SKIP_DOTS;
            $dir_iterator = new \RecursiveDirectoryIterator($uploads_path, $flags);
            $iterator = new \RecursiveIteratorIterator(
                $dir_iterator,
                \RecursiveIteratorIterator::SELF_FIRST,
                \RecursiveIteratorIterator::CATCH_GET_CHILD // Silently skip unreadable subdirectories without crashing
            );

            $normalized_uploads = str_replace('\\', '/', rtrim($uploads_path, '/\\') . '/');
            $files_inspected = 0;
            $uploads_mode = class_exists('\\WebCareProScanner\\System\\SettingsManager')
                ? \WebCareProScanner\System\SettingsManager::get('scan_uploads_mode', 'deep_raster')
                : 'deep_raster';
            $max_files_limit = ($uploads_mode === 'deep_raster') ? 25000 : 5000;
            $monitor = new \WebCareProScanner\Resource\ResourceMonitor(70, 20, 'balanced');

            $symlink_scanner = new SymlinkScanner();
            $js_scanner      = new \WebCareProScanner\Malware\JavaScriptSecurityScanner();

            foreach ($iterator as $item) {
                // Adaptive breathing & memory headroom check before each file
                if ($monitor->throttle_and_check()) {
                    break;
                }

                try {
                    if ($item->isLink()) {
                        $sym_finding = $symlink_scanner->scan($item->getPathname(), $scan_id);
                        if ($sym_finding) {
                            $findings[] = $sym_finding;
                        }
                        continue;
                    }
                    if (!$item->isFile()) {
                        continue;
                    }
                } catch (\Throwable $e) {
                    continue;
                }

                $files_inspected++;
                if ($files_inspected > $max_files_limit) {
                    break;
                }

                $real_path = $item->getPathname();
                $normalized_path = str_replace('\\', '/', $real_path);

                // Exclude plugin's internal secure storage (quarantine, logs, backups, fim-vault, etc.) and user exclusions
                if (preg_match('#/(webcare-pro-security|webcare-pro-quarantine|webcare-vault|webcare-waf|webcare-quarantine)/#i', $normalized_path)) {
                    continue;
                }

                // Check user configured excluded paths
                if (\WebCareProScanner\System\SettingsManager::is_path_excluded($normalized_path)) {
                    continue;
                }

                $rel_path = str_replace($normalized_uploads, '', $normalized_path);
                $basename = $item->getBasename();
                $lower_name = strtolower($basename);
                $ext = strtolower($item->getExtension());
                $file_size = (int) @$item->getSize();

                // 1. Direct prohibited executable / shell extension
                if (in_array($ext, $this->executable_extensions, true)) {
                    // Check if harmless WordPress directory listing prevention placeholder
                    if (($lower_name === 'index.php' || $lower_name === 'index.html' || $lower_name === 'index.htm') && \WebCareProScanner\System\SettingsManager::is_safe_directory_index($real_path)) {
                        continue;
                    }

                    // Check if legitimate, verified plugin cache (e.g. MailPoet Twig template cache) with 0 malware indicators
                    if (\WebCareProScanner\System\SettingsManager::is_legitimate_uploads_cache_file($real_path)) {
                        continue;
                    }

                    $snippet = $this->extract_preview_snippet($real_path);
                    $findings[] = new Finding([
                        'engine'       => 'uploads-scanner',
                        'type'         => 'executable_in_uploads',
                        'severity'     => 'critical',
                        'confidence'   => 100,
                        'file_path'    => $real_path,
                        'code_snippet' => $snippet,
                        'description'  => "Dangerous executable script (.{$ext}) found inside WordPress uploads directory: {$rel_path}",
                        'evidence'     => "File extension '.{$ext}' is strictly forbidden in the media library."
                    ]);
                    continue;
                }

                // 2. Dangerous server overrides (.htaccess / web.config / .user.ini / php.ini in uploads)
                if ($lower_name === '.user.ini' || $lower_name === 'php.ini') {
                    $ini_content = @file_get_contents($real_path, false, null, 0, 8192) ?: '';
                    $findings[] = new Finding([
                        'engine'       => 'uploads-scanner',
                        'type'         => 'server_override_in_uploads',
                        'severity'     => 'critical',
                        'confidence'   => 99,
                        'file_path'    => $real_path,
                        'code_snippet' => self::sanitize_utf8(substr($ini_content, 0, 250)),
                        'description'  => "PHP-FPM configuration override '{$basename}' found inside uploads directory. Used by attackers for auto_prepend_file polyglot execution.",
                        'evidence'     => "Found {$basename} inside media uploads: {$rel_path}",
                    ]);
                    continue;
                }

                // 2b. Client-side phishing / ClickFix / skimmer scripts (.html, .htm, .shtml, .js, .mjs, .cjs) in uploads
                if (in_array($ext, ['html', 'htm', 'shtml', 'js', 'mjs', 'cjs'], true)) {
                    if (($lower_name === 'index.html' || $lower_name === 'index.htm') && \WebCareProScanner\System\SettingsManager::is_safe_directory_index($real_path)) {
                        continue;
                    }
                    if (!\WebCareProScanner\Integrity\ChecksumProvider::is_authentic_known_library($real_path)) {
                        $raw_web = $file_size <= 1572864 ? ((string) @file_get_contents($real_path)) : '';
                        $js_hits = $raw_web !== '' ? $js_scanner->scan_content($raw_web, $real_path, $scan_id) : [];
                        if (!empty($js_hits)) {
                            $findings = array_merge($findings, $js_hits);
                            continue;
                        }
                        if (in_array($ext, ['html', 'htm', 'shtml'], true) && $raw_web !== '' && preg_match('/(<script\b|<form\b[^>]*action\s*=|navigator\.clipboard|http-equiv\s*=\s*[\'"]?refresh)/i', $raw_web, $wm)) {
                            $findings[] = new Finding([
                                'engine'       => 'uploads-scanner',
                                'type'         => 'phishing_html_in_uploads',
                                'severity'     => 'high',
                                'confidence'   => 92,
                                'file_path'    => $real_path,
                                'code_snippet' => $this->extract_context_snippet($raw_web, $wm[0]),
                                'description'  => "Active HTML page '{$basename}' with embedded script/form/redirect found inside uploads: {$rel_path}",
                                'evidence'     => "Matched active markup '{$wm[0]}' in uploaded HTML file.",
                            ]);
                            continue;
                        }
                    }
                }

                if ($lower_name === '.htaccess' || $lower_name === 'web.config') {
                    $content = @file_get_contents($real_path, false, null, 0, 2048) ?: '';
                    // Legitimate security plugins (Forminator, WooCommerce, WPForms) place protective .htaccess files
                    // to prevent PHP execution (e.g. php_flag engine off, Options -ExecCGI, Deny from all, RemoveHandler).
                    // Flag ONLY if it actually overrides/enables PHP execution for media/non-php files or drops backdoors.
                    $is_malicious_override = (bool) preg_match('/(AddType|AddHandler|SetHandler)\s+application\/x-httpd-php|\b(auto_prepend_file|auto_append_file)\b|php_flag\s+engine\s+(?:on|1)/i', $content);
                    $is_protective = (
                        stripos($content, 'deny from all') !== false ||
                        stripos($content, 'require all denied') !== false ||
                        stripos($content, 'php_flag engine off') !== false ||
                        stripos($content, 'Options -ExecCGI') !== false ||
                        stripos($content, 'Options -Indexes') !== false ||
                        stripos($content, 'RemoveHandler') !== false ||
                        stripos($content, 'SetHandler default-handler') !== false
                    );

                    if ($is_malicious_override || !$is_protective) {
                        $findings[] = new Finding([
                            'engine'       => 'uploads-scanner',
                            'type'         => 'server_override_in_uploads',
                            'severity'     => 'high',
                            'confidence'   => 95,
                            'file_path'    => $real_path,
                            'code_snippet' => self::sanitize_utf8(substr($content, 0, 250)),
                            'description'  => "Server configuration file '{$basename}' found inside uploads folder. Often used by attackers to override PHP execution restrictions.",
                            'evidence'     => "Found {$basename} with potential execution override in {$rel_path}"
                        ]);
                    }
                    continue;
                }

                // 3. Double extension check (e.g. image.php.jpg, photo.jpg.php, document.pdf.sh)
                if (preg_match('/\.(php[0-9]?|phtml|pht|phar|suspected|sh|bash|cgi|pl|py|exe)\.([a-z0-9]+)$/i', $lower_name, $m)) {
                    $snippet = $this->extract_preview_snippet($real_path);
                    $findings[] = new Finding([
                        'engine'       => 'uploads-scanner',
                        'type'         => 'double_extension_in_uploads',
                        'severity'     => 'critical',
                        'confidence'   => 100,
                        'file_path'    => $real_path,
                        'code_snippet' => $snippet,
                        'description'  => "Disguised double-extension file found inside uploads: {$basename}. May bypass media validation on vulnerable web servers.",
                        'evidence'     => "Embedded script extension '.{$m[1]}' disguised with secondary extension '.{$m[2]}'"
                    ]);
                    continue;
                }

                // 4. Binary Executable Magic Bytes Spoofing (e.g. Windows PE or Linux ELF disguised as an image)
                if (in_array($ext, $this->image_extensions, true) || in_array($ext, $this->document_extensions, true)) {
                    $magic_finding = $this->check_binary_magic_bytes($real_path, $basename, $ext, $rel_path);
                    if ($magic_finding) {
                        $findings[] = $magic_finding;
                        continue;
                    }
                }

                // 5. SVG Image Security Audit (XSS, JavaScript, embedded PHP)
                if ($ext === 'svg' || $ext === 'svgz') {
                    $svg_finding = $this->check_svg_file($real_path, $basename, $rel_path, $file_size);
                    if ($svg_finding) {
                        $findings[] = $svg_finding;
                        continue;
                    }
                }

                // 6. Deep Forensic Inspection for Disguised PHP Code / Image Polyglots
                if (in_array($ext, $this->image_extensions, true) || in_array($ext, $this->document_extensions, true)) {
                    $polyglot_finding = $this->check_embedded_php_payload($real_path, $basename, $ext, $rel_path, $file_size);
                    if ($polyglot_finding) {
                        $findings[] = $polyglot_finding;
                        continue;
                    }
                }
            }
        } catch (\Throwable $e) {
            // Suppress media inspection exceptions silently and return collected findings
        }

        return $findings;
    }

    /**
     * Checks if a media/image file is actually a raw compiled binary executable.
     */
    private function check_binary_magic_bytes($real_path, $basename, $ext, $rel_path) {
        $header = @file_get_contents($real_path, false, null, 0, 16);
        if ($header === false || strlen($header) < 2) {
            return null;
        }

        // Windows PE executable (MZ header)
        if (substr($header, 0, 2) === "MZ") {
            return new Finding([
                'engine'       => 'uploads-scanner',
                'type'         => 'spoofed_binary_in_uploads',
                'severity'     => 'critical',
                'confidence'   => 100,
                'file_path'    => $real_path,
                'code_snippet' => 'Magic Header: MZ (Windows PE Executable / DLL)',
                'description'  => "Binary executable disguised as media file '{$basename}' in uploads directory.",
                'evidence'     => "File begins with Windows PE executable signature 'MZ' but uses '.{$ext}' extension."
            ]);
        }

        // Linux ELF binary executable (\x7FELF)
        if (substr($header, 0, 4) === "\x7fELF") {
            return new Finding([
                'engine'       => 'uploads-scanner',
                'type'         => 'spoofed_binary_in_uploads',
                'severity'     => 'critical',
                'confidence'   => 100,
                'file_path'    => $real_path,
                'code_snippet' => 'Magic Header: 7F 45 4C 46 (\x7fELF Linux Executable / Shared Object)',
                'description'  => "Linux ELF binary executable disguised as media file '{$basename}' in uploads directory.",
                'evidence'     => "File begins with Linux ELF binary signature '\\x7fELF' but uses '.{$ext}' extension."
            ]);
        }

        // macOS Mach-O binaries (\xCA\xFE\xBA\xBE, \xCF\xFA\xED\xFE, \xCE\xFA\xED\xFE)
        $macho_signatures = ["\xca\xfe\xba\xbe", "\xcf\xfa\xed\xfe", "\xce\xfa\xed\xfe"];
        if (in_array(substr($header, 0, 4), $macho_signatures, true)) {
            return new Finding([
                'engine'       => 'uploads-scanner',
                'type'         => 'spoofed_binary_in_uploads',
                'severity'     => 'critical',
                'confidence'   => 100,
                'file_path'    => $real_path,
                'code_snippet' => 'Magic Header: Mach-O Binary Executable',
                'description'  => "Mach-O binary executable disguised as media file '{$basename}' in uploads directory.",
                'evidence'     => "File begins with Mach-O binary signature but uses '.{$ext}' extension."
            ]);
        }

        // Shell script shebang in an image file (e.g. #!/bin/bash, #!/bin/sh, #!/usr/bin/env)
        if (substr($header, 0, 2) === '#!' && preg_match('/^#!\s*\/(bin|usr)/i', $header)) {
            return new Finding([
                'engine'       => 'uploads-scanner',
                'type'         => 'spoofed_binary_in_uploads',
                'severity'     => 'critical',
                'confidence'   => 100,
                'file_path'    => $real_path,
                'code_snippet' => trim($header),
                'description'  => "Shell script shebang discovered in media file '{$basename}' in uploads directory.",
                'evidence'     => "File begins with Unix shell script shebang '#!' but uses '.{$ext}' extension."
            ]);
        }

        return null;
    }

    /**
     * Inspects SVG vector image files for embedded XSS scripts and malicious executable handlers.
     */
    private function check_svg_file($real_path, $basename, $rel_path, $file_size) {
        if ($file_size > 2 * 1024 * 1024) { // Limit to 2MB
            return null;
        }

        $content = @file_get_contents($real_path);
        if ($content === false || empty($content)) {
            return null;
        }

        // Decompress if svgz (gzipped SVG)
        if (substr($content, 0, 2) === "\x1f\x8b" && function_exists('gzdecode')) {
            $decompressed = @gzdecode($content);
            if ($decompressed !== false) {
                $content = $decompressed;
            }
        }

        // Decode HTML entities so &#106;avascript: or &#x6a;avascript: cannot evade protocol checks
        $decoded_svg = html_entity_decode($content, ENT_QUOTES | ENT_HTML5, 'UTF-8');

        // Check for embedded active PHP (including comment-separated <?php/*...*/ and short echo <?=)
        if (preg_match('/(<\?php\b|<\?php\/\*|<\?=)/i', $content, $m)) {
            return new Finding([
                'engine'       => 'uploads-scanner',
                'type'         => 'disguised_php_in_uploads',
                'severity'     => 'critical',
                'confidence'   => 100,
                'file_path'    => $real_path,
                'code_snippet' => $this->extract_context_snippet($content, $m[0]),
                'description'  => "SVG image '{$basename}' contains active PHP execution code tags.",
                'evidence'     => "Embedded PHP opening tag '{$m[0]}' found inside SVG XML structure."
            ]);
        }

        // Check for script tags in SVG content
        if (preg_match('/<script\b[^>]*>/i', $decoded_svg, $m)) {
            return new Finding([
                'engine'       => 'uploads-scanner',
                'type'         => 'malicious_svg_in_uploads',
                'severity'     => 'critical',
                'confidence'   => 98,
                'file_path'    => $real_path,
                'code_snippet' => substr($m[0], 0, 200),
                'description'  => "SVG image '{$basename}' contains executable script element leading to Stored Cross-Site Scripting (XSS).",
                'evidence'     => "Found active script element in SVG vector image file."
            ]);
        }

        // Check for javascript:/vbscript:/data:text/html or base64 SVG URI in href, src, xlink:href, values, to, from (quoted or unquoted)
        if (preg_match('/(?:href|src|xlink:href|to|from|values)\s*=\s*[\'"]?\s*(?:javascript|vbscript|data\s*:\s*(?:text\/html|image\/svg\+xml\s*;\s*base64))\s*:/i', $decoded_svg, $m)) {
            return new Finding([
                'engine'       => 'uploads-scanner',
                'type'         => 'malicious_svg_in_uploads',
                'severity'     => 'critical',
                'confidence'   => 95,
                'file_path'    => $real_path,
                'code_snippet' => substr($m[0], 0, 200),
                'description'  => "SVG image '{$basename}' contains executable URI protocol handler.",
                'evidence'     => "Found executable URI payload in SVG attribute."
            ]);
        }

        // Check for inline DOM & SMIL animation event handlers (quoted OR unquoted: onload=alert(1), onbegin=..., ontoggle=...)
        if (preg_match('/[\s"\'\/](on(?:load|error|click|mouseover|mouseenter|mousemove|focus|blur|begin|end|repeat|toggle|animationstart|transitionend))\s*=\s*(?:[\'"][^\'"]+|[^\s>]+)/i', $decoded_svg, $m)) {
            return new Finding([
                'engine'       => 'uploads-scanner',
                'type'         => 'malicious_svg_in_uploads',
                'severity'     => 'high',
                'confidence'   => 94,
                'file_path'    => $real_path,
                'code_snippet' => substr(trim($m[0]), 0, 200),
                'description'  => "SVG image '{$basename}' contains inline DOM/SMIL event handler ({$m[1]}).",
                'evidence'     => "Found active inline event handler '{$m[1]}' in SVG file."
            ]);
        }

        // Check for dangerous remote embedding or SMIL href-mutation tags: <foreignObject>, <iframe>, <embed>, <object>
        if (preg_match('/<(foreignObject|iframe|embed|object)\b[^>]*>/i', $decoded_svg, $m)) {
            return new Finding([
                'engine'       => 'uploads-scanner',
                'type'         => 'malicious_svg_in_uploads',
                'severity'     => 'high',
                'confidence'   => 90,
                'file_path'    => $real_path,
                'code_snippet' => substr($m[0], 0, 200),
                'description'  => "SVG image '{$basename}' contains HTML embedding tag (<{$m[1]}>).",
                'evidence'     => "Found '<{$m[1]}>' container inside SVG vector graphic."
            ]);
        }

        return null;
    }

    /**
     * Inspects media and image files for embedded or trailing PHP code polyglots.
     */
    private function check_embedded_php_payload($real_path, $basename, $ext, $rel_path, $file_size) {
        // Skip files > 10MB to maintain scanner speed and prevent memory issues
        if ($file_size > 10 * 1024 * 1024) {
            return null;
        }

        // True PHP polyglot webshells in images contain <?php (with whitespace or /* comment) or <?= followed by printable ASCII executable syntax.
        $php_pattern = '/<\?(?:php(?:\s+|\/\*[\s\S]{0,120}?\*\/)[\x20-\x7E\r\n\t]{0,500}?(?:\b(?:eval|assert|system|passthru|shell_exec|exec|popen|proc_open|base64_decode|gzinflate|gzdecode|include|require)\b|\$_[A-Z]+|\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)|\=\s*\(?\s*(?:\b(?:eval|assert|system|passthru|shell_exec|exec|base64_decode)\b|\$_[A-Z]+|\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*))/i';
        $phar_stub_pattern = '/\b__HALT_COMPILER\s*\(\s*\)/i';

        $detected_pattern = null;
        $snippet = '';

        // Stream the ENTIRE file in 64 KB sliding chunks (with 1 KB overlap) so payloads hidden in the middle (>8KB) are NEVER missed
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen
        $fp = @fopen($real_path, 'rb');
        if (!$fp) {
            return null;
        }
        $carry = '';
        $is_first_chunk = true;
        try {
            while (!feof($fp)) {
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread
                $chunk = @fread($fp, 65536);
                if ($chunk === false || $chunk === '') {
                    break;
                }
                $window = $carry . $chunk;

                if ($is_first_chunk && $file_size <= 128 * 1024 && preg_match('/^\s*<\?php\b/i', $window, $m_head)) {
                    $detected_pattern = $m_head[0];
                    $snippet = $this->extract_context_snippet($window, $m_head[0]);
                    break;
                }
                $is_first_chunk = false;

                if (preg_match($phar_stub_pattern, $window, $m_phar)) {
                    return new Finding([
                        'engine'       => 'uploads-scanner',
                        'type'         => 'phar_polyglot_in_uploads',
                        'severity'     => 'critical',
                        'confidence'   => 100,
                        'file_path'    => $real_path,
                        'code_snippet' => $this->extract_context_snippet($window, $m_phar[0]),
                        'description'  => "Media file '{$basename}' contains a PHP Phar archive stub (__HALT_COMPILER), enabling phar:// deserialization attacks.",
                        'evidence'     => "Found '__HALT_COMPILER()' Phar polyglot stub inside .{$ext} file.",
                    ]);
                }

                // Fast-path check before running full PCRE on pure binary chunk
                if (str_contains($window, '<?') && preg_match($php_pattern, $window, $m)) {
                    $detected_pattern = $m[0];
                    $snippet = $this->extract_context_snippet($window, $m[0]);
                    break;
                }

                $carry = strlen($chunk) > 1024 ? substr($chunk, -1024) : $chunk;
            }
        } finally {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
            @fclose($fp);
        }

        if ($detected_pattern) {
            return new Finding([
                'engine'       => 'uploads-scanner',
                'type'         => 'disguised_php_in_uploads',
                'severity'     => 'critical',
                'confidence'   => 98,
                'file_path'    => $real_path,
                'code_snippet' => $snippet,
                'description'  => "Media file {$basename} in uploads contains embedded active PHP code or shell execution tokens.",
                'evidence'     => "Found active PHP execution token '{$detected_pattern}' inside .{$ext} media file."
            ]);
        }

        return null;
    }

    /**
     * Extracts a clean contextual snippet surrounding a pattern match.
     */
    private function extract_context_snippet($content, $match) {
        $pos = strpos($content, $match);
        if ($pos === false) {
            return self::sanitize_utf8(substr($content, 0, 200));
        }
        $start = max(0, $pos - 40);
        $length = min(strlen($content) - $start, 200);
        return self::sanitize_utf8(substr($content, $start, $length));
    }

    /**
     * Safely read a small text snippet from file for findings reporting.
     *
     * @param string $path
     * @return string|null
     */
    private function extract_preview_snippet($path) {
        $content = @file_get_contents($path, false, null, 0, 300);
        if ($content === false) {
            return null;
        }
        return self::sanitize_utf8(substr($content, 0, 300));
    }

    /**
     * Sanitize any binary or malformed string into valid UTF-8 for JSON encoding and REST responses.
     *
     * @param mixed $input
     * @return string
     */
    public static function sanitize_utf8($input): string {
        if (!is_string($input) || $input === '') {
            return '';
        }

        // Convert non-printable bytes or invalid characters to UTF-8
        if (function_exists('mb_convert_encoding')) {
            $cleaned = mb_convert_encoding($input, 'UTF-8', 'UTF-8');
        } elseif (function_exists('iconv')) {
            $cleaned = @iconv('UTF-8', 'UTF-8//IGNORE', $input);
        } else {
            $cleaned = $input;
        }

        // Strip non-printable binary control codes except standard tabs/newlines
        $cleaned = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', ' ', (string) $cleaned);

        return trim((string) $cleaned);
    }
}
