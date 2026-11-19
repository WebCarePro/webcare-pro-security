<?php
declare(strict_types=1);

namespace WebCareProScanner\Api\Controllers;

use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * AbstractApiController
 *
 * Base controller providing standardized permissions, nonces, and response formatting.
 *
 * Author: Mir Alamin (WebCare Pro)
 */
abstract class AbstractApiController {

    /**
     * Standard permission callback requiring manage_options.
     */
    public static function check_admin_permission(): bool {
        return current_user_can('manage_options');
    }

    /**
     * Helper to wrap data into a standardized WP_REST_Response.
     *
     * @param mixed $data Response payload.
     * @param int   $status HTTP status code.
     */
    protected static function success(mixed $data, int $status = 200): WP_REST_Response {
        return new WP_REST_Response([
            'success' => true,
            'data'    => $data,
        ], $status);
    }

    /**
     * Helper to wrap errors into a standardized WP_Error.
     *
     * @param string $code Error code.
     * @param string $message User-facing message.
     * @param int    $status HTTP status code.
     */
    protected static function error(string $code, string $message, int $status = 400): WP_Error {
        return new WP_Error($code, $message, ['status' => $status]);
    }
}
