<?php

namespace OAuth\OAuth2\Service;

use OAuth\Common\Consumer\CredentialsInterface;
use OAuth\Common\Http\Client\ClientInterface;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\Uri;
use OAuth\Common\Http\Uri\UriInterface;
use OAuth\Common\Storage\TokenStorageInterface;
use OAuth\OAuth2\Token\StdOAuth2Token;

class Reddit extends AbstractService
{
    /**
     * Defined scopes.
     *
     * @see http://www.reddit.com/dev/api/oauth
     */
    // User scopes
    public const SCOPE_EDIT = 'edit';
    public const SCOPE_HISTORY = 'history';
    public const SCOPE_IDENTITY = 'identity';
    public const SCOPE_MYSUBREDDITS = 'mysubreddits';
    public const SCOPE_PRIVATEMESSAGES = 'privatemessages';
    public const SCOPE_READ = 'read';
    public const SCOPE_SAVE = 'save';
    public const SCOPE_SUBMIT = 'submit';
    public const SCOPE_SUBSCRIBE = 'subscribe';
    public const SCOPE_VOTE = 'vote';
    // Mod Scopes
    public const SCOPE_MODCONFIG = 'modconfig';
    public const SCOPE_MODFLAIR = 'modflair';
    public const SCOPE_MODLOG = 'modlog';
    public const SCOPE_MODPOST = 'modpost';

    public function __construct(
        CredentialsInterface $credentials,
        ClientInterface $httpClient,
        TokenStorageInterface $storage,
        $scopes = [],
        ?UriInterface $baseApiUri = null
    ) {
        parent::__construct($credentials, $httpClient, $storage, $scopes, $baseApiUri, true);

        if (null === $baseApiUri) {
            $this->baseApiUri = new Uri('https://oauth.reddit.com');
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthorizationEndpoint()
    {
        return new Uri('https://ssl.reddit.com/api/v1/authorize');
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessTokenEndpoint()
    {
        return new Uri('https://ssl.reddit.com/api/v1/access_token');
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
        // Reddit uses a Basic OAuth header
        return ['Authorization' => 'Basic ' .
            base64_encode($this->credentials->getConsumerId() . ':' . $this->credentials->getConsumerSecret()), ];
    }
}
