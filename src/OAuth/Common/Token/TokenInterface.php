<?php

namespace OAuth\Common\Token;

/**
 * Base token interface for any OAuth version.
 */
interface TokenInterface
{
    /**
     * Denotes an unknown end of life time.
     */
    public const EOL_UNKNOWN = -9001;

    /**
     * Denotes a token which never expires, should only happen in OAuth1.
     */
    public const EOL_NEVER_EXPIRES = -9002;

    /**
     * @return string
     */
    public function getAccessToken();

    /**
     * @return int
     */
    public function getEndOfLife();

    /**
     * @return array
     */
    public function getExtraParams();

    /**
     * @param string $accessToken
     */
    public function setAccessToken($accessToken);

    /**
     * @param int $endOfLife
     */
    public function setEndOfLife($endOfLife);

    /**
     * @param int $lifetime
     */
    public function setLifetime($lifetime);

    public function setExtraParams(array $extraParams);

    /**
     * @return string
     */
    public function getRefreshToken();

    /**
     * @param string $refreshToken
     */
    public function setRefreshToken($refreshToken);
}
