<?php

namespace OAuth\OAuth2\Service;

use OAuth\Common\Service\ServiceInterface as BaseServiceInterface;
use OAuth\Common\Token\TokenInterface;

/**
 * Defines the common methods across OAuth 2 services.
 */
interface ServiceInterface extends BaseServiceInterface
{
    /**
     * Authorization methods for various services.
     */
    public const AUTHORIZATION_METHOD_HEADER_OAUTH = 0;
    public const AUTHORIZATION_METHOD_HEADER_BEARER = 1;
    public const AUTHORIZATION_METHOD_QUERY_STRING = 2;
    public const AUTHORIZATION_METHOD_QUERY_STRING_V2 = 3;
    public const AUTHORIZATION_METHOD_QUERY_STRING_V3 = 4;
    public const AUTHORIZATION_METHOD_QUERY_STRING_V4 = 5;
    public const AUTHORIZATION_METHOD_HEADER_TOKEN = 6;
    public const AUTHORIZATION_METHOD_QUERY_STRING_V5 = 7;

    /**
     * Retrieves and stores/returns the OAuth2 access token after a successful authorization.
     *
     * @param string $code the access code from the callback
     * @param string $state
     *
     * @return TokenInterface $token
     */
    public function requestAccessToken($code, $state = null);
}
