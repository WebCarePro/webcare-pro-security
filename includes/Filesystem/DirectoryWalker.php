<?php
namespace WebCareProScanner\Filesystem;

if (!defined('ABSPATH')) {
    exit;
}

class DirectoryWalker {

    private const CACHE_SCAN_MAX_ENTRIES = 10000;
    private const CACHE_SCAN_MAX_FINDINGS = 500;
    private const CACHE_SCAN_BUDGET_SECONDS = 2.0;

    /** Directories we never enter */
    private array $exclude_dirs = [
        '.git',
        '.svn',
        '.hg',
        'node_modules',
        'vendor',
        'cache',
        'caches',
        'wfcache',
        'w3tc-cache',
        'et-cache',
        'wpo-cache',
        'litespeed',
        'breeze',
        'wp-rocket',
        'autoptimize',
        'sg-cachepress',
        'siteground-cache',
        'hummingbird-assets',
        'fast-velocity-minify',
        'borlabs-cookie',
        'wp-fastest-cache',
        'supercache',
        'comet-cache',
        'updraft',
        'webcare-pro-security',
        'webcare-pro-quarantine',
        'webcare-vault',
        'webcare-waf',
        'webcare-quarantine',
        '.vault',
        '.backups',
        '.logs',
        'object-cache-pro',
        'wp-content/cache',
        'wp-content/litespeed',
        'wp-content/et-cache',
        'wp-content/wpo-cache',
        'wp-content/breeze',
        'wp-content/wp-rocket',
        'wp-content/autoptimize',
        'wp-content/upgrade',
        'wp-content/uploads/webcare-pro-security',
    ];

    /** Safe media/document extensions we skip early during deep code inspection */
    private array $skip_extensions = [
        'jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'ico',
        'mp4', 'mov', 'avi', 'webm', 'mp3', 'wav',
        'zip', 'gz', 'tar', 'rar', '7z',
        'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
        'woff', 'woff2', 'ttf', 'eot',
    ];

    /**
     * Get a batch of files from the filesystem using an opaque hierarchical cursor.
     *
     * @param string $root Root directory path
     * @param array $cursor Hierarchical state cursor
     * @param int $batch_size Maximum files per batch
     * @return array
     */
    public function get_batch(string $root, array $cursor = [], int $batch_size = 25): array {
        $root = rtrim(str_replace('\\', '/', $root), '/');
        $last_rel_path = $cursor['last_rel_path'] ?? ($cursor['last_file'] ?? null);
        $phase = $cursor['phase'] ?? 'filesystem';

        $files = [];
        $new_cursor = $cursor;
        $exhausted = false;

        if (!is_dir($root)) {
            return [
                'files'     => [],
                'cursor'    => $cursor,
                'exhausted' => true,
            ];
        }

        $found_resume_point = ($last_rel_path === null || $last_rel_path === '');

        try {
            $iterator = $this->create_iterator($root);

            foreach ($iterator as $fileinfo) {
                /** @var \SplFileInfo $fileinfo */
                $pathname = str_replace('\\', '/', $fileinfo->getPathname());
                $basename = $fileinfo->getFilename();

                if ($fileinfo->isDir()) {
                    continue;
                }

                if (!$fileinfo->isFile()) {
                    continue;
                }

                if ($this->is_in_excluded_dir($pathname, $root)) {
                    continue;
                }

                $rel_path = ltrim(substr($pathname, strlen($root)), '/');

                // Skip until resume point is found
                if (!$found_resume_point) {
                    if ($rel_path === $last_rel_path || $basename === $last_rel_path) {
                        $found_resume_point = true;
                    }
                    continue;
                }

                // Fast path for harmless static media (unless double extension e.g. photo.jpg.php)
                if ($this->should_skip_file($basename)) {
                    $new_cursor = $this->make_cursor($phase, $root, $pathname);
                    continue;
                }

                $files[] = $pathname;
                $new_cursor = $this->make_cursor($phase, $root, $pathname);

                if (count($files) >= $batch_size) {
                    break;
                }
            }
        } catch (\Throwable $e) {
            // Suppress iterator access errors gracefully
        }

        if (count($files) < $batch_size) {
            $exhausted = true;
        }

        return [
            'files'     => $files,
            'cursor'    => $new_cursor,
            'exhausted' => $exhausted,
        ];
    }

    private function create_iterator(string $dir): \RecursiveIteratorIterator {
        $root_norm = rtrim(str_replace('\\', '/', $dir), '/');
        $flags = \FilesystemIterator::SKIP_DOTS
               | \FilesystemIterator::CURRENT_AS_FILEINFO
               | \FilesystemIterator::UNIX_PATHS;

        $inner = new \RecursiveDirectoryIterator($dir, $flags);

        $filter = new \RecursiveCallbackFilterIterator(
            $inner,
            function (\SplFileInfo $current) use ($root_norm): bool {
                $pathname = str_replace('\\', '/', $current->getPathname());
                $basename = $current->getFilename();

                if ($current->isLink()) {
                    return false;
                }

                if ($current->isDir()) {
                    return !$this->should_exclude_dir($basename, $pathname, $root_norm);
                }

                return !$this->is_in_excluded_dir($pathname, $root_norm);
            }
        );

        return new \RecursiveIteratorIterator(
            $filter,
            \RecursiveIteratorIterator::SELF_FIRST,
            \RecursiveIteratorIterator::CATCH_GET_CHILD
        );
    }

    public function is_in_excluded_dir(string $pathname, string $root): bool {
        $root_norm = rtrim(str_replace('\\', '/', $root), '/');
        $path_norm = str_replace('\\', '/', $pathname);
        $relative  = substr($path_norm, strlen($root_norm));
        $relative  = strtolower(trim($relative, '/'));

        foreach ($this->exclude_dirs as $excluded) {
            $excluded = strtolower(trim($excluded, '/'));
            if ($relative === $excluded || str_starts_with($relative, $excluded . '/') || str_contains($relative, '/' . $excluded . '/')) {
                return true;
            }
        }

        // Check user-configured excluded paths and patterns
        if (class_exists('\\WebCareProScanner\\System\\SettingsManager') && \WebCareProScanner\System\SettingsManager::is_path_excluded($path_norm)) {
            return true;
        }

        return false;
    }

    public function should_exclude_dir(string $basename, string $pathname, string $root): bool {
        $basename_lower = strtolower($basename);
        $root_norm      = rtrim(str_replace('\\', '/', $root), '/');
        $path_norm      = str_replace('\\', '/', $pathname);

        foreach ($this->exclude_dirs as $excluded) {
            $excluded_lower = strtolower(trim($excluded, '/'));
            if ($basename_lower === $excluded_lower) {
                return true;
            }
        }

        $relative = strtolower(trim(substr($path_norm, strlen($root_norm)), '/'));
        foreach ($this->exclude_dirs as $excluded) {
            $excluded_lower = strtolower(trim($excluded, '/'));
            if ($relative === $excluded_lower || str_starts_with($relative, $excluded_lower . '/') || str_contains($relative, '/' . $excluded_lower . '/')) {
                return true;
            }
        }

        if (class_exists('\\WebCareProScanner\\System\\SettingsManager') && \WebCareProScanner\System\SettingsManager::is_path_excluded($path_norm)) {
            return true;
        }

        return false;
    }

    /**
     * Inspect known cache directories specifically for dropped executable scripts (.php, .phtml, .phar, etc.)
     * using a bounded recursive traversal that inspects nested subdirectories without reading or analyzing
     * thousands of minified .js/.css asset files.
     *
     * @param string $root Root path (e.g. ABSPATH)
     * @param int $max_depth Maximum directory depth to inspect (default: 5)
     * @param array|null $scan_meta Optional scan metadata populated with entry counts and truncation status
     * @return array List of suspicious executable file paths found inside cache directories
     */
    public function scan_cache_dirs_for_executables(string $root, int $max_depth = 5, ?array &$scan_meta = null): array {
        $root = rtrim(str_replace('\\', '/', $root), '/');
        $found = [];
        $entries_examined = 0;
        $truncated = false;
        $deadline = microtime(true) + self::CACHE_SCAN_BUDGET_SECONDS;
        $exec_exts = ['php', 'phtml', 'phar', 'php5', 'php7', 'php8', 'inc', 'cgi', 'pl', 'py', 'sh', 'bash'];

        $cache_dirs_to_check = [
            $root . '/wp-content/cache',
            $root . '/wp-content/litespeed',
            $root . '/wp-content/et-cache',
            $root . '/wp-content/wpo-cache',
            $root . '/wp-content/breeze',
            $root . '/wp-content/wp-rocket',
            $root . '/wp-content/autoptimize',
            $root . '/wp-content/wfcache',
            $root . '/wp-content/w3tc-cache',
            $root . '/wp-content/sg-cachepress',
            $root . '/wp-content/wp-fastest-cache',
        ];

        foreach ($cache_dirs_to_check as $cache_dir) {
            if ($truncated) {
                break;
            }
            if (!is_dir($cache_dir)) {
                continue;
            }
            $this->traverse_cache_dir_bounded($cache_dir, $exec_exts, $found, $entries_examined, $deadline, $truncated, 1, $max_depth);
        }

        $scan_meta = [
            'entries_examined' => $entries_examined,
            'files_found'      => count($found),
            'truncated'        => $truncated,
        ];

        return $found;
    }

    /**
     * Helper to perform depth-bounded search for rogue executables inside cache trees.
     *
     * @param string $dir
     * @param array $exec_exts
     * @param array &$found
     * @param int &$entries_examined
     * @param float $deadline
     * @param bool &$truncated
     * @param int $current_depth
     * @param int $max_depth
     * @return void
     */
    private function traverse_cache_dir_bounded(string $dir, array $exec_exts, array &$found, int &$entries_examined, float $deadline, bool &$truncated, int $current_depth, int $max_depth): void {
        if ($current_depth > $max_depth || $truncated) {
            return;
        }

        try {
            $flags = \FilesystemIterator::SKIP_DOTS | \FilesystemIterator::CURRENT_AS_FILEINFO | \FilesystemIterator::UNIX_PATHS;
            $iterator = new \FilesystemIterator($dir, $flags);

            foreach ($iterator as $item) {
                if (
                    $entries_examined >= self::CACHE_SCAN_MAX_ENTRIES ||
                    count($found) >= self::CACHE_SCAN_MAX_FINDINGS ||
                    microtime(true) >= $deadline
                ) {
                    $truncated = true;
                    return;
                }
                $entries_examined++;

                if ($item->isLink()) {
                    continue;
                }

                $pathname = str_replace('\\', '/', $item->getPathname());

                if ($item->isDir()) {
                    $this->traverse_cache_dir_bounded($pathname, $exec_exts, $found, $entries_examined, $deadline, $truncated, $current_depth + 1, $max_depth);
                    if ($truncated) {
                        return;
                    }
                } elseif ($item->isFile()) {
                    $ext = strtolower($item->getExtension());
                    if (in_array($ext, $exec_exts, true)) {
                        $found[] = $pathname;
                    }
                }
            }
        } catch (\Throwable $e) {
            // Gracefully ignore filesystem access errors
        }
    }

    private function should_skip_file(string $basename): bool {
        $ext = strtolower(pathinfo($basename, PATHINFO_EXTENSION));
        if (in_array($ext, $this->skip_extensions, true)) {
            // Guard against hidden PHP extensions like shell.jpg.php
            if (substr_count($basename, '.') > 1) {
                return false;
            }
            return true;
        }
        return false;
    }

    private function build_path(string $root, array $stack): string {
        if (empty($stack)) {
            return $root;
        }
        return $root . '/' . implode('/', $stack);
    }

    private function make_cursor(string $phase, string $root, string $filepath): array {
        $dir = dirname($filepath);
        $relative = substr($dir, strlen($root));
        $relative = trim(str_replace('\\', '/', $relative), '/');

        $dir_stack = $relative === '' ? [] : explode('/', $relative);
        $rel_path = ltrim(substr($filepath, strlen($root)), '/');

        return [
            'phase'         => $phase,
            'dir_stack'     => $dir_stack,
            'last_file'     => basename($filepath),
            'last_rel_path' => $rel_path,
        ];
    }
}
