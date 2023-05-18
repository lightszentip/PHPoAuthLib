<?php

namespace OAuth\OAuth2\Service;

use OAuth\Common\Consumer\CredentialsInterface;
use OAuth\Common\Http\Client\ClientInterface;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\Uri;
use OAuth\Common\Http\Uri\UriInterface;
use OAuth\Common\Storage\TokenStorageInterface;
use OAuth\OAuth2\Token\StdOAuth2Token;

class Vkontakte extends AbstractService
{
    /**
     * Defined scopes.
     *
     * @see http://vk.com/dev/permissions
     */
    public const SCOPE_EMAIL = 'email';
    public const SCOPE_NOTIFY = 'notify';
    public const SCOPE_FRIENDS = 'friends';
    public const SCOPE_PHOTOS = 'photos';
    public const SCOPE_AUDIO = 'audio';
    public const SCOPE_VIDEO = 'video';
    public const SCOPE_DOCS = 'docs';
    public const SCOPE_NOTES = 'notes';
    public const SCOPE_PAGES = 'pages';
    public const SCOPE_APP_LINK = '';
    public const SCOPE_STATUS = 'status';
    public const SCOPE_OFFERS = 'offers';
    public const SCOPE_QUESTIONS = 'questions';
    public const SCOPE_WALL = 'wall';
    public const SCOPE_GROUPS = 'groups';
    public const SCOPE_MESSAGES = 'messages';
    public const SCOPE_NOTIFICATIONS = 'notifications';
    public const SCOPE_STATS = 'stats';
    public const SCOPE_ADS = 'ads';
    public const SCOPE_OFFLINE = 'offline';
    public const SCOPE_NOHTTPS = 'nohttps';

    public function __construct(
        CredentialsInterface $credentials,
        ClientInterface $httpClient,
        TokenStorageInterface $storage,
        $scopes = [],
        ?UriInterface $baseApiUri = null
    ) {
        parent::__construct($credentials, $httpClient, $storage, $scopes, $baseApiUri);

        if (null === $baseApiUri) {
            $this->baseApiUri = new Uri('https://api.vk.com/method/');
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthorizationEndpoint()
    {
        return new Uri('https://oauth.vk.com/authorize');
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessTokenEndpoint()
    {
        return new Uri('https://oauth.vk.com/access_token');
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
    protected function getAuthorizationMethod()
    {
        return static::AUTHORIZATION_METHOD_QUERY_STRING;
    }

    /**
     * {@inheritdoc}
     */
    public function requestAccessToken($code, $state = null)
    {
        if (null !== $state) {
            $this->validateAuthorizationState($state);
        }

        $bodyParams = [
            'code' => $code,
            'client_id' => $this->credentials->getConsumerId(),
            'client_secret' => $this->credentials->getConsumerSecret(),
            'redirect_uri' => $this->credentials->getCallbackUrl(),
            'grant_type' => 'client_credentials',

        ];

        $responseBody = $this->httpClient->retrieveResponse(
            $this->getAccessTokenEndpoint(),
            $bodyParams,
            $this->getExtraOAuthHeaders()
        );

        $token = $this->parseAccessTokenResponse($responseBody);
        $this->storage->storeAccessToken($this->service(), $token);

        return $token;
    }
}
