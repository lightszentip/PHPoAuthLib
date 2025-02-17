<?php

namespace OAuth\OAuth2\Service;

use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\Uri;
use OAuth\OAuth2\Token\StdOAuth2Token;

class Bitrix24 extends AbstractService
{
    public const SCOPE_DEPARTMENT = 'department';
    public const SCOPE_CRM = 'crm';
    public const SCOPE_CALENDAR = 'calendar';
    public const SCOPE_USER = 'user';
    public const SCOPE_ENTITY = 'entity';
    public const SCOPE_TASK = 'task';
    public const SCOPE_TASKS_EXTENDED = 'tasks_extended';
    public const SCOPE_IM = 'im';
    public const SCOPE_LOG = 'log';
    public const SCOPE_SONET_GROUP = 'sonet_group';

    /**
     * {@inheritdoc}
     */
    public function getAuthorizationEndpoint()
    {
        return new Uri(sprintf('%s/oauth/authorize/', $this->baseApiUri));
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessTokenEndpoint()
    {
        return new Uri(sprintf('%s/oauth/token/', $this->baseApiUri));
    }

    /**
     * {@inheritdoc}
     */
    protected function getAuthorizationMethod()
    {
        return static::AUTHORIZATION_METHOD_QUERY_STRING_V4;
    }

    /**
     * {@inheritdoc}
     */
    public function requestAccessToken($code, $state = null)
    {
        if (null !== $state) {
            $this->validateAuthorizationState($state);
        }

        $responseBody = $this->httpClient->retrieveResponse(
            $this->getAccessTokenUri($code),
            [],
            $this->getExtraOAuthHeaders(),
            'GET'
        );

        $token = $this->parseAccessTokenResponse($responseBody);
        $this->storage->storeAccessToken($this->service(), $token);

        return $token;
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessTokenUri($code)
    {
        $parameters = [
            'code' => $code,
            'client_id' => $this->credentials->getConsumerId(),
            'client_secret' => $this->credentials->getConsumerSecret(),
            'redirect_uri' => $this->credentials->getCallbackUrl(),
            'grant_type' => 'authorization_code',
            'scope' => $this->scopes,
        ];

        $parameters['scope'] = implode(' ', $this->scopes);

        // Build the url
        $url = $this->getAccessTokenEndpoint();
        foreach ($parameters as $key => $val) {
            $url->addToQuery($key, $val);
        }

        return $url;
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
        $token->setLifetime($data['expires_in']);

        if (isset($data['refresh_token'])) {
            $token->setRefreshToken($data['refresh_token']);
            unset($data['refresh_token']);
        }

        unset($data['access_token'], $data['expires_in']);

        $token->setExtraParams($data);

        return $token;
    }
}
