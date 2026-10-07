<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Api\Traits\ApiControllerHelpers;
use App\Http\Controllers\Controller;

/**
 * Base API controller with common functionality
 */
abstract class BaseApiController extends Controller
{
    use ApiControllerHelpers;
}
