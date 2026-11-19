<?php
namespace WebCareProScanner\Scan;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Exception thrown when an active scan lease is lost, expired, or superseded by another worker.
 */
class ScanLeaseLostException extends \RuntimeException {
}
