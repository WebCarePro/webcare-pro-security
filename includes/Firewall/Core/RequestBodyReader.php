<?php
declare(strict_types=1);

namespace WebCareProScanner\Firewall\Core;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * RequestBodyReader
 *
 * Single-read, bounded reader for php://input with truncation awareness.
 * Protects memory allocation against unbounded payload DOS while providing
 * deterministic payload streams to RequestContext and WAF evaluators.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
final class RequestBodyReader {

    public const DEFAULT_MAX_BYTES = 262144; // 256 KB

    private static ?string $cached_raw_body = null;
    private static ?int $configured_max_bytes = null;
    private static int $bytes_read = 0;
    private static bool $is_truncated = false;
    private static bool $read_failed = false;
    private static string $sha256 = '';

    /**
     * Optional mock body for unit testing.
     */
    public static ?string $mock_raw_body = null;

    /**
     * Read and return bounded php://input body stream.
     * Guaranteed to execute at most once per HTTP request lifecycle.
     *
     * @param int $max_bytes Maximum bytes to read (default 262144 / 256 KB)
     * @return string Bounded raw body string
     */
    public static function get_bounded_body(int $max_bytes = self::DEFAULT_MAX_BYTES): string {
        if (self::$cached_raw_body !== null) {
            return self::$cached_raw_body;
        }

        self::$configured_max_bytes = $max_bytes;

        if (self::$mock_raw_body !== null) {
            $raw = self::$mock_raw_body;
            $len = strlen($raw);
            if ($len > $max_bytes) {
                self::$is_truncated = true;
                self::$bytes_read = $max_bytes + 1;
                self::$cached_raw_body = substr($raw, 0, $max_bytes);
            } else {
                self::$is_truncated = false;
                self::$bytes_read = $len;
                self::$cached_raw_body = $raw;
            }
            self::$read_failed = false;
            self::$sha256 = hash('sha256', self::$cached_raw_body);
            return self::$cached_raw_body;
        }

        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Bounded streaming of php://input
        $raw_read = @file_get_contents('php://input', false, null, 0, $max_bytes + 1);

        if ($raw_read === false) {
            self::$read_failed = true;
            self::$is_truncated = false;
            self::$bytes_read = 0;
            self::$cached_raw_body = '';
            self::$sha256 = hash('sha256', '');
            return '';
        }

        self::$read_failed = false;
        $read = (string) $raw_read;
        $len = strlen($read);

        if ($len > $max_bytes) {
            self::$is_truncated = true;
            self::$bytes_read = $len;
            self::$cached_raw_body = substr($read, 0, $max_bytes);
        } else {
            self::$is_truncated = false;
            self::$bytes_read = $len;
            self::$cached_raw_body = $read;
        }

        self::$sha256 = hash('sha256', self::$cached_raw_body);
        return self::$cached_raw_body;
    }

    /**
     * Check if reading the request body failed.
     *
     * @return bool
     */
    public static function has_read_failed(): bool {
        if (self::$cached_raw_body === null) {
            self::get_bounded_body();
        }
        return self::$read_failed;
    }

    /**
     * Check if the request body stream exceeded max_bytes.
     *
     * @return bool
     */
    public static function is_truncated(): bool {
        if (self::$cached_raw_body === null) {
            self::get_bounded_body();
        }
        return self::$is_truncated;
    }

    /**
     * Get the count of bytes read from php://input.
     *
     * @return int
     */
    public static function get_bytes_read(): int {
        if (self::$cached_raw_body === null) {
            self::get_bounded_body();
        }
        return self::$bytes_read;
    }

    /**
     * Get SHA256 checksum of the bounded body.
     *
     * @return string
     */
    public static function get_sha256(): string {
        if (self::$cached_raw_body === null) {
            self::get_bounded_body();
        }
        return self::$sha256;
    }

    /**
     * Get the configured max_bytes limit established on first read.
     *
     * @return int
     */
    public static function get_configured_max_bytes(): int {
        return self::$configured_max_bytes ?? self::DEFAULT_MAX_BYTES;
    }

    /**
     * Stream an uploaded file or temp path in bounded rolling chunks with an overlap buffer.
     * Guarantees that inspection runs in strict constant memory (window_bytes + overlap_bytes)
     * without accumulating the file in memory.
     *
     * The callback signature: `function(string $window_chunk, int $offset): ?array`
     * If the callback returns an array (e.g. ['matched' => true, ...]), streaming stops immediately
     * and that verdict array is returned.
     *
     * @param string $file_path Path to uploaded temp file on disk.
     * @param callable $chunk_handler Callback invoked for each rolling chunk window.
     * @param int $window_bytes Rolling chunk window size (default 65536 / 64 KB).
     * @param int $overlap_bytes Number of bytes from previous chunk tail to prepend (default 4096 / 4 KB).
     * @param int $max_bytes Maximum total bytes to read from file (default 134217728 / 128 MB).
     * @return array{completed: bool, bytes_streamed: bool|int, truncated: bool, result: mixed}
     */
    public static function stream_file_windowed(
        string $file_path,
        callable $chunk_handler,
        int $window_bytes = 65536,
        int $overlap_bytes = 4096,
        int $max_bytes = 134217728
    ): array {
        if (!file_exists($file_path) || !is_readable($file_path)) {
            return [
                'completed'      => false,
                'read_failed'    => true,
                'bytes_streamed' => 0,
                'truncated'      => false,
                'result'         => null,
            ];
        }

        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Bounded streaming of uploaded file
        $fp = @fopen($file_path, 'rb');
        if (!is_resource($fp)) {
            return [
                'completed'      => false,
                'read_failed'    => true,
                'bytes_streamed' => 0,
                'truncated'      => false,
                'result'         => null,
            ];
        }

        $overlap = '';
        $bytes_streamed = 0;
        $truncated = false;
        $read_failed = false;
        $result = null;

        while (!feof($fp)) {
            $bytes_to_read = min($window_bytes, $max_bytes - $bytes_streamed);
            if ($bytes_to_read <= 0) {
                $truncated = true;
                break;
            }

            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread -- Bounded chunked streaming
            $chunk = @fread($fp, $bytes_to_read);
            if ($chunk === false) {
                $read_failed = true;
                break;
            }
            if ($chunk === '') {
                break;
            }

            $chunk_len = strlen($chunk);
            $bytes_streamed += $chunk_len;

            $inspect_window = $overlap . $chunk;
            $res = $chunk_handler($inspect_window, $bytes_streamed);
            if ($res !== null) {
                $result = $res;
                break;
            }

            $overlap = $chunk_len >= $overlap_bytes ? substr($chunk, -$overlap_bytes) : $chunk;
        }

        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
        @fclose($fp);

        return [
            'completed'      => (!$read_failed && !$truncated),
            'read_failed'    => $read_failed,
            'bytes_streamed' => $bytes_streamed,
            'truncated'      => $truncated,
            'result'         => $result,
        ];
    }

    /**
     * Reset cached body (strictly for unit tests).
     */
    public static function reset(): void {
        self::$cached_raw_body = null;
        self::$configured_max_bytes = null;
        self::$bytes_read = 0;
        self::$is_truncated = false;
        self::$sha256 = '';
        self::$mock_raw_body = null;
    }
}
