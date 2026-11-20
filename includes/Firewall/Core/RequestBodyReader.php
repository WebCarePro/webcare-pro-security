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
    private static int $bytes_read = 0;
    private static bool $is_truncated = false;
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
            self::$sha256 = hash('sha256', self::$cached_raw_body);
            return self::$cached_raw_body;
        }

        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Bounded streaming of php://input
        $read = (string) @file_get_contents('php://input', false, null, 0, $max_bytes + 1);
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
     * Reset cached body (strictly for unit tests).
     */
    public static function reset(): void {
        self::$cached_raw_body = null;
        self::$bytes_read = 0;
        self::$is_truncated = false;
        self::$sha256 = '';
        self::$mock_raw_body = null;
    }
}
