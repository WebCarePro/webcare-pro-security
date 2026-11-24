<?php
declare(strict_types=1);

namespace WebCareProScanner\Auth;

use InvalidArgumentException;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Strict RFC 8949 CBOR Decoder for WebAuthn / FIDO2 artifacts.
 *
 * Enforces:
 * - Deterministic parsing of major types 0-5.
 * - Recursion depth limit <= 8 (prevents stack overflow).
 * - Rejection of indefinite-length items (prohibited by WebAuthn Level 2/3 deterministic profiles).
 * - Rejection of duplicate map keys (RFC 8949 section 5.6).
 *
 * @package WebCareProScanner\Auth
 * @author  Mir Alamin (WebCare Pro)
 */
final class StrictCborDecoder {

    private const MAX_DEPTH = 8;

    /**
     * Decode a CBOR binary string into PHP native structures.
     *
     * @param string $data
     * @return mixed
     * @throws InvalidArgumentException
     */
    public static function decode(string $data): mixed {
        $offset = 0;
        $length = strlen($data);
        if ($length === 0) {
            throw new InvalidArgumentException('CBOR data is empty.');
        }

        $result = self::parse_item($data, $offset, $length, 0);

        if ($offset < $length) {
            throw new InvalidArgumentException(sprintf('Extraneous trailing bytes after CBOR item at offset %d/%d.', $offset, $length));
        }

        return $result;
    }

    /**
     * Parse a single CBOR item from buffer.
     *
     * @param string $data
     * @param int    $offset
     * @param int    $length
     * @param int    $depth
     * @return mixed
     * @throws InvalidArgumentException
     */
    private static function parse_item(string $data, int &$offset, int $length, int $depth): mixed {
        if ($depth > self::MAX_DEPTH) {
            throw new InvalidArgumentException(sprintf('CBOR recursion depth exceeded limit of %d.', self::MAX_DEPTH));
        }

        if ($offset >= $length) {
            throw new InvalidArgumentException('Unexpected end of CBOR buffer.');
        }

        $initial_byte = ord($data[$offset++]);
        $major_type   = $initial_byte >> 5;
        $additional   = $initial_byte & 0x1F;

        // Reject indefinite length (additional info 31 / 0x1F)
        if ($additional === 31) {
            throw new InvalidArgumentException('Indefinite-length CBOR items are rejected in WebAuthn strict mode.');
        }

        $value = self::read_length_or_value($data, $offset, $length, $additional);

        return match ($major_type) {
            0 => $value, // Unsigned integer
            1 => -1 - $value, // Negative integer
            2 => self::read_bytes($data, $offset, $length, $value), // Byte string
            3 => self::read_utf8_string($data, $offset, $length, $value), // Text string
            4 => self::read_array($data, $offset, $length, $value, $depth), // Array
            5 => self::read_map($data, $offset, $length, $value, $depth), // Map
            default => throw new InvalidArgumentException(sprintf('Unsupported CBOR major type: %d.', $major_type)),
        };
    }

    /**
     * Read additional argument integer or length.
     *
     * @param string $data
     * @param int    $offset
     * @param int    $length
     * @param int    $additional
     * @return int
     * @throws InvalidArgumentException
     */
    private static function read_length_or_value(string $data, int &$offset, int $length, int $additional): int {
        if ($additional < 24) {
            return $additional;
        }

        $bytes_to_read = match ($additional) {
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            default => throw new InvalidArgumentException(sprintf('Invalid CBOR additional information: %d.', $additional)),
        };

        if ($offset + $bytes_to_read > $length) {
            throw new InvalidArgumentException('CBOR buffer underflow while reading length argument.');
        }

        $raw = substr($data, $offset, $bytes_to_read);
        $offset += $bytes_to_read;

        if ($bytes_to_read === 1) {
            return ord($raw[0]);
        }
        if ($bytes_to_read === 2) {
            $unpacked = unpack('n', $raw);
            return (int) ($unpacked[1] ?? 0);
        }
        if ($bytes_to_read === 4) {
            $unpacked = unpack('N', $raw);
            return (int) ($unpacked[1] ?? 0);
        }

        // 8 bytes (64-bit integer)
        $unpacked = unpack('J', $raw);
        $val = (int) ($unpacked[1] ?? 0);
        if ($val < 0) {
            throw new InvalidArgumentException('64-bit integer overflow in 64-bit PHP runtime.');
        }
        return $val;
    }

    /**
     * Read raw byte string.
     */
    private static function read_bytes(string $data, int &$offset, int $length, int $byte_len): string {
        if ($offset + $byte_len > $length) {
            throw new InvalidArgumentException('CBOR buffer underflow reading byte string.');
        }
        $str = substr($data, $offset, $byte_len);
        $offset += $byte_len;
        return $str;
    }

    /**
     * Read and validate UTF-8 text string.
     */
    private static function read_utf8_string(string $data, int &$offset, int $length, int $byte_len): string {
        $str = self::read_bytes($data, $offset, $length, $byte_len);
        if (!mb_check_encoding($str, 'UTF-8')) {
            throw new InvalidArgumentException('CBOR text string contains invalid UTF-8 sequence.');
        }
        return $str;
    }

    /**
     * Read CBOR array.
     */
    private static function read_array(string $data, int &$offset, int $length, int $item_count, int $depth): array {
        $arr = [];
        for ($i = 0; $i < $item_count; $i++) {
            $arr[] = self::parse_item($data, $offset, $length, $depth + 1);
        }
        return $arr;
    }

    /**
     * Read CBOR map, enforcing unique keys.
     */
    private static function read_map(string $data, int &$offset, int $length, int $pair_count, int $depth): array {
        $map = [];
        $seen_keys = [];

        for ($i = 0; $i < $pair_count; $i++) {
            $key = self::parse_item($data, $offset, $length, $depth + 1);
            if (!is_int($key) && !is_string($key)) {
                throw new InvalidArgumentException('CBOR map key must be an integer or string.');
            }

            $key_str = (string) $key;
            if (isset($seen_keys[$key_str])) {
                throw new InvalidArgumentException(sprintf('Duplicate key "%s" detected in CBOR map (RFC 8949 violation).', $key_str));
            }
            $seen_keys[$key_str] = true;

            $map[$key] = self::parse_item($data, $offset, $length, $depth + 1);
        }

        return $map;
    }
}
