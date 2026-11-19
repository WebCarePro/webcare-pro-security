<?php
declare(strict_types=1);

namespace WebCareProScanner\Contracts;

if (!defined('ABSPATH')) {
    exit;
}

enum RouteClass: string {
    case PublicGet   = 'public_get';
    case AuthLogin   = 'auth_login';
    case Commerce    = 'commerce';
    case Membership  = 'membership';
    case RestApi     = 'rest_api';
    case GraphQL     = 'graphql';
    case AdminAjax   = 'admin_ajax';
    case AdminUi     = 'admin_ui';
}
