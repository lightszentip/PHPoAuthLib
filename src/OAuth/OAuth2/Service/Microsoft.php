<?php

namespace OAuth\OAuth2\Service;

use OAuth\Common\Consumer\CredentialsInterface;
use OAuth\Common\Http\Client\ClientInterface;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\Uri;
use OAuth\Common\Http\Uri\UriInterface;
use OAuth\Common\Storage\TokenStorageInterface;
use OAuth\OAuth2\Token\StdOAuth2Token;

class Microsoft extends AbstractService
{
    public const SCOPE_BASIC = 'wl.basic';
    public const SCOPE_OFFLINE = 'wl.offline_access';
    public const SCOPE_SIGNIN = 'wl.signin';
    public const SCOPE_BIRTHDAY = 'wl.birthday';
    public const SCOPE_CALENDARS = 'wl.calendars';
    public const SCOPE_CALENDARS_UPDATE = 'wl.calendars_update';
    public const SCOPE_CONTACTS_BIRTHDAY = 'wl.contacts_birthday';
    public const SCOPE_CONTACTS_CREATE = 'wl.contacts_create';
    public const SCOPE_CONTACTS_CALENDARS = 'wl.contacts_calendars';
    public const SCOPE_CONTACTS_PHOTOS = 'wl.contacts_photos';
    public const SCOPE_CONTACTS_SKYDRIVE = 'wl.contacts_skydrive';
    public const SCOPE_EMAILS = 'wl.emails';
    public const SCOPE_EVENTS_CREATE = 'wl.events_create';
    public const SCOPE_MESSENGER = 'wl.messenger';
    public const SCOPE_PHONE_NUMBERS = 'wl.phone_numbers';
    public const SCOPE_PHOTOS = 'wl.photos';
    public const SCOPE_POSTAL_ADDRESSES = 'wl.postal_addresses';
    public const SCOPE_SHARE = 'wl.share';
    public const SCOPE_SKYDRIVE = 'wl.skydrive';
    public const SCOPE_SKYDRIVE_UPDATE = 'wl.skydrive_update';
    public const SCOPE_WORK_PROFILE = 'wl.work_profile';
    public const SCOPE_APPLICATIONS = 'wl.applications';
    public const SCOPE_APPLICATIONS_CREATE = 'wl.applications_create';
    public const SCOPE_IMAP = 'wl.imap';

    /**
     * MS uses some magical not officialy supported scope to get even moar info like full emailaddresses.
     * They agree that giving 3rd party apps access to 3rd party emailaddresses is a pretty lame thing to do so in all
     * their wisdom they added this scope because fuck you that's why.
     *
     * https://github.com/Lusitanian/PHPoAuthLib/issues/214
     * http://social.msdn.microsoft.com/Forums/live/en-US/c6dcb9ab-aed4-400a-99fb-5650c393a95d/how-retrieve-users-
     *                                  contacts-email-address?forum=messengerconnect
     *
     * Considering this scope is not officially supported: use with care
     */
    public const SCOPE_CONTACTS_EMAILS = 'wl.contacts_emails';

    public function __construct(
        CredentialsInterface $credentials,
        ClientInterface $httpClient,
        TokenStorageInterface $storage,
        $scopes = [],
        ?UriInterface $baseApiUri = null
    ) {
        parent::__construct($credentials, $httpClient, $storage, $scopes, $baseApiUri);

        if (null === $baseApiUri) {
            $this->baseApiUri = new Uri('https://apis.live.net/v5.0/');
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthorizationEndpoint()
    {
        return new Uri('https://login.live.com/oauth20_authorize.srf');
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessTokenEndpoint()
    {
        return new Uri('https://login.live.com/oauth20_token.srf');
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthorizationMethod()
    {
        return static::AUTHORIZATION_METHOD_QUERY_STRING;
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
