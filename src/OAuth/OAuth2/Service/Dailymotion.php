<?php

namespace OAuth\OAuth2\Service;

use OAuth\Common\Consumer\CredentialsInterface;
use OAuth\Common\Http\Client\ClientInterface;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\Uri;
use OAuth\Common\Http\Uri\UriInterface;
use OAuth\Common\Storage\TokenStorageInterface;
use OAuth\OAuth2\Token\StdOAuth2Token;

/**
 * Dailymotion service.
 *
 * @author Mouhamed SEYE <mouhamed@seye.pro>
 *
 * @see http://www.dailymotion.com/doc/api/authentication.html
 */
class Dailymotion extends AbstractService
{
    /**
     * Scopes.
     *
     * @var string
     */
    public const SCOPE_EMAIL = 'email';
    public const SCOPE_PROFILE = 'userinfo';
    public const SCOPE_VIDEOS = 'manage_videos';
    public const SCOPE_COMMENTS = 'manage_comments';
    public const SCOPE_PLAYLIST = 'manage_playlists';
    public const SCOPE_TILES = 'manage_tiles';
    public const SCOPE_SUBSCRIPTIONS = 'manage_subscriptions';
    public const SCOPE_FRIENDS = 'manage_friends';
    public const SCOPE_FAVORITES = 'manage_favorites';
    public const SCOPE_GROUPS = 'manage_groups';

    /**
     * Dialog form factors.
     *
     * @var string
     */
    public const DISPLAY_PAGE = 'page';
    public const DISPLAY_POPUP = 'popup';
    public const DISPLAY_MOBILE = 'mobile';

    /**
     * {@inheritdoc}
     */
    public function __construct(
        CredentialsInterface $credentials,
        ClientInterface $httpClient,
        TokenStorageInterface $storage,
        $scopes = [],
        ?UriInterface $baseApiUri = null
    ) {
        parent::__construct($credentials, $httpClient, $storage, $scopes, $baseApiUri);

        if (null === $baseApiUri) {
            $this->baseApiUri = new Uri('https://api.dailymotion.com/');
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthorizationEndpoint()
    {
        return new Uri('https://api.dailymotion.com/oauth/authorize');
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessTokenEndpoint()
    {
        return new Uri('https://api.dailymotion.com/oauth/token');
    }

    /**
     * {@inheritdoc}
     */
    protected function getAuthorizationMethod()
    {
        return static::AUTHORIZATION_METHOD_HEADER_OAUTH;
    }

    /**
     * {@inheritdoc}
     */
    protected function parseAccessTokenResponse($responseBody)
    {
        $data = json_decode($responseBody, true);

        if (null === $data || !is_array($data)) {
            throw new TokenResponseException('Unable to parse response.');
        } elseif (isset($data['error_description']) || isset($data['error'])) {
            throw new TokenResponseException(
                sprintf(
                    'Error in retrieving token: "%s"',
                    $data['error_description'] ?? $data['error']
                )
            );
        }

        $token = new StdOAuth2Token();
        $token->setAccessToken($data['access_token']);
        $token->setLifeTime($data['expires_in']);

        if (isset($data['refresh_token'])) {
            $token->setRefreshToken($data['refresh_token']);
            unset($data['refresh_token']);
        }

        unset($data['access_token'], $data['expires_in']);

        $token->setExtraParams($data);

        return $token;
    }

    /**
     * {@inheritdoc}
     */
    protected function getExtraOAuthHeaders()
    {
        return ['Accept' => 'application/json'];
    }
}
