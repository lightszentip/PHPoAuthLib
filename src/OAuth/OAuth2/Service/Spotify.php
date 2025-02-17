<?php

namespace OAuth\OAuth2\Service;

use OAuth\Common\Consumer\CredentialsInterface;
use OAuth\Common\Http\Client\ClientInterface;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\Uri;
use OAuth\Common\Http\Uri\UriInterface;
use OAuth\Common\Storage\TokenStorageInterface;
use OAuth\OAuth2\Token\StdOAuth2Token;

class Spotify extends AbstractService
{
    /**
     * Scopes.
     *
     * @var string
     */
    public const SCOPE_PLAYLIST_MODIFY_PUBLIC = 'playlist-modify-public';
    public const SCOPE_PLAYLIST_MODIFY_PRIVATE = 'playlist-modify-private';
    public const SCOPE_PLAYLIST_READ_PRIVATE = 'playlist-read-private';
    public const SCOPE_PLAYLIST_READ_COLABORATIVE = 'playlist-read-collaborative';
    public const SCOPE_STREAMING = 'streaming';
    public const SCOPE_USER_LIBRARY_MODIFY = 'user-library-modify';
    public const SCOPE_USER_LIBRARY_READ = 'user-library-read';
    public const SCOPE_USER_READ_PRIVATE = 'user-read-private';
    public const SCOPE_USER_READ_EMAIL = 'user-read-email';
    public const SCOPE_USER_READ_BIRTHDAY = 'user-read-birthdate';
    public const SCOPE_USER_READ_FOLLOW = 'user-follow-read';

    public function __construct(
        CredentialsInterface $credentials,
        ClientInterface $httpClient,
        TokenStorageInterface $storage,
        $scopes = [],
        ?UriInterface $baseApiUri = null
    ) {
        parent::__construct($credentials, $httpClient, $storage, $scopes, $baseApiUri, true);

        if (null === $baseApiUri) {
            $this->baseApiUri = new Uri('https://api.spotify.com/v1/');
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthorizationEndpoint()
    {
        return new Uri('https://accounts.spotify.com/authorize');
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessTokenEndpoint()
    {
        return new Uri('https://accounts.spotify.com/api/token');
    }

    /**
     * {@inheritdoc}
     */
    protected function getAuthorizationMethod()
    {
        return static::AUTHORIZATION_METHOD_HEADER_BEARER;
    }

    /**
     * {@inheritdoc}
     */
    protected function parseAccessTokenResponse($responseBody)
    {
        $data = json_decode($responseBody, true);

        if (null === $data || !is_array($data)) {
            throw new TokenResponseException('Unable to parse response.');
        } elseif (isset($data['error'])) {
            throw new TokenResponseException('Error in retrieving token: "' . $data['error'] . '"');
        }

        $token = new StdOAuth2Token();
        $token->setAccessToken($data['access_token']);

        if (isset($data['expires_in'])) {
            $token->setLifetime($data['expires_in']);
            unset($data['expires_in']);
        }

        if (isset($data['refresh_token'])) {
            $token->setRefreshToken($data['refresh_token']);
            unset($data['refresh_token']);
        }

        unset($data['access_token']);

        $token->setExtraParams($data);

        return $token;
    }

    /**
     * {@inheritdoc}
     */
    protected function getExtraOAuthHeaders()
    {
        return ['Authorization' => 'Basic ' .
            base64_encode($this->credentials->getConsumerId() . ':' . $this->credentials->getConsumerSecret()), ];
    }
}
