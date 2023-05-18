<?php

namespace OAuth\OAuth2\Service;

use OAuth\Common\Consumer\CredentialsInterface;
use OAuth\Common\Exception\Exception;
use OAuth\Common\Http\Client\ClientInterface;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\Uri;
use OAuth\Common\Http\Uri\UriInterface;
use OAuth\Common\Storage\TokenStorageInterface;
use OAuth\OAuth2\Token\StdOAuth2Token;

class Facebook extends AbstractService
{
    /**
     * Facebook www url - used to build dialog urls.
     */
    public const WWW_URL = 'https://www.facebook.com/';

    /**
     * Defined scopes.
     *
     * If you don't think this is scary you should not be allowed on the web at all
     *
     * @see https://developers.facebook.com/docs/reference/login/
     * @see https://developers.facebook.com/tools/explorer For a list of permissions use 'Get Access Token'
     */
    // Default scope
    public const SCOPE_PUBLIC_PROFILE = 'public_profile';
    // Email scopes
    public const SCOPE_EMAIL = 'email';
    // Extended permissions
    public const SCOPE_READ_FRIENDLIST = 'read_friendlists';
    public const SCOPE_READ_INSIGHTS = 'read_insights';
    public const SCOPE_READ_MAILBOX = 'read_mailbox';
    public const SCOPE_READ_PAGE_MAILBOXES = 'read_page_mailboxes';
    public const SCOPE_READ_REQUESTS = 'read_requests';
    public const SCOPE_READ_STREAM = 'read_stream';
    public const SCOPE_VIDEO_UPLOAD = 'video_upload';
    public const SCOPE_XMPP_LOGIN = 'xmpp_login';
    public const SCOPE_USER_ONLINE_PRESENCE = 'user_online_presence';
    public const SCOPE_FRIENDS_ONLINE_PRESENCE = 'friends_online_presence';
    public const SCOPE_ADS_MANAGEMENT = 'ads_management';
    public const SCOPE_ADS_READ = 'ads_read';
    public const SCOPE_CREATE_EVENT = 'create_event';
    public const SCOPE_CREATE_NOTE = 'create_note';
    public const SCOPE_EXPORT_STREAM = 'export_stream';
    public const SCOPE_MANAGE_FRIENDLIST = 'manage_friendlists';
    public const SCOPE_MANAGE_NOTIFICATIONS = 'manage_notifications';
    public const SCOPE_PHOTO_UPLOAD = 'photo_upload';
    public const SCOPE_PUBLISH_ACTIONS = 'publish_actions';
    public const SCOPE_PUBLISH_CHECKINS = 'publish_checkins';
    public const SCOPE_PUBLISH_STREAM = 'publish_stream';
    public const SCOPE_RSVP_EVENT = 'rsvp_event';
    public const SCOPE_SHARE_ITEM = 'share_item';
    public const SCOPE_SMS = 'sms';
    public const SCOPE_STATUS_UPDATE = 'status_update';
    // Extended Profile Properties
    public const SCOPE_USER_POSTS = 'user_posts';
    public const SCOPE_USER_FRIENDS = 'user_friends';
    public const SCOPE_USER_ABOUT = 'user_about_me';
    public const SCOPE_USER_TAGGED_PLACES = 'user_tagged_places';
    public const SCOPE_FRIENDS_ABOUT = 'friends_about_me';
    public const SCOPE_USER_ACTIVITIES = 'user_activities';
    public const SCOPE_FRIENDS_ACTIVITIES = 'friends_activities';
    public const SCOPE_USER_BIRTHDAY = 'user_birthday';
    public const SCOPE_FRIENDS_BIRTHDAY = 'friends_birthday';
    public const SCOPE_USER_CHECKINS = 'user_checkins';
    public const SCOPE_FRIENDS_CHECKINS = 'friends_checkins';
    public const SCOPE_USER_EDUCATION = 'user_education_history';
    public const SCOPE_FRIENDS_EDUCATION = 'friends_education_history';
    public const SCOPE_USER_EVENTS = 'user_events';
    public const SCOPE_FRIENDS_EVENTS = 'friends_events';
    public const SCOPE_USER_GROUPS = 'user_groups';
    public const SCOPE_USER_MANAGED_GROUPS = 'user_managed_groups';
    public const SCOPE_FRIENDS_GROUPS = 'friends_groups';
    public const SCOPE_USER_HOMETOWN = 'user_hometown';
    public const SCOPE_FRIENDS_HOMETOWN = 'friends_hometown';
    public const SCOPE_USER_INTERESTS = 'user_interests';
    public const SCOPE_FRIEND_INTERESTS = 'friends_interests';
    public const SCOPE_USER_LIKES = 'user_likes';
    public const SCOPE_FRIENDS_LIKES = 'friends_likes';
    public const SCOPE_USER_LOCATION = 'user_location';
    public const SCOPE_FRIENDS_LOCATION = 'friends_location';
    public const SCOPE_USER_NOTES = 'user_notes';
    public const SCOPE_FRIENDS_NOTES = 'friends_notes';
    public const SCOPE_USER_PHOTOS = 'user_photos';
    public const SCOPE_USER_PHOTO_VIDEO_TAGS = 'user_photo_video_tags';
    public const SCOPE_FRIENDS_PHOTOS = 'friends_photos';
    public const SCOPE_FRIENDS_PHOTO_VIDEO_TAGS = 'friends_photo_video_tags';
    public const SCOPE_USER_QUESTIONS = 'user_questions';
    public const SCOPE_FRIENDS_QUESTIONS = 'friends_questions';
    public const SCOPE_USER_RELATIONSHIPS = 'user_relationships';
    public const SCOPE_FRIENDS_RELATIONSHIPS = 'friends_relationships';
    public const SCOPE_USER_RELATIONSHIPS_DETAILS = 'user_relationship_details';
    public const SCOPE_FRIENDS_RELATIONSHIPS_DETAILS = 'friends_relationship_details';
    public const SCOPE_USER_RELIGION = 'user_religion_politics';
    public const SCOPE_FRIENDS_RELIGION = 'friends_religion_politics';
    public const SCOPE_USER_STATUS = 'user_status';
    public const SCOPE_FRIENDS_STATUS = 'friends_status';
    public const SCOPE_USER_SUBSCRIPTIONS = 'user_subscriptions';
    public const SCOPE_FRIENDS_SUBSCRIPTIONS = 'friends_subscriptions';
    public const SCOPE_USER_VIDEOS = 'user_videos';
    public const SCOPE_FRIENDS_VIDEOS = 'friends_videos';
    public const SCOPE_USER_WEBSITE = 'user_website';
    public const SCOPE_FRIENDS_WEBSITE = 'friends_website';
    public const SCOPE_USER_WORK = 'user_work_history';
    public const SCOPE_FRIENDS_WORK = 'friends_work_history';
    // Open Graph Permissions
    public const SCOPE_USER_MUSIC = 'user_actions.music';
    public const SCOPE_FRIENDS_MUSIC = 'friends_actions.music';
    public const SCOPE_USER_NEWS = 'user_actions.news';
    public const SCOPE_FRIENDS_NEWS = 'friends_actions.news';
    public const SCOPE_USER_VIDEO = 'user_actions.video';
    public const SCOPE_FRIENDS_VIDEO = 'friends_actions.video';
    public const SCOPE_USER_APP = 'user_actions:APP_NAMESPACE';
    public const SCOPE_FRIENDS_APP = 'friends_actions:APP_NAMESPACE';
    public const SCOPE_USER_GAMES = 'user_games_activity';
    public const SCOPE_FRIENDS_GAMES = 'friends_games_activity';
    //Page Permissions
    public const SCOPE_PAGES = 'manage_pages';
    public const SCOPE_PAGES_MESSAGING = 'pages_messaging';
    public const SCOPE_PUBLISH_PAGES = 'publish_pages';

    public function __construct(
        CredentialsInterface $credentials,
        ClientInterface $httpClient,
        TokenStorageInterface $storage,
        $scopes = [],
        ?UriInterface $baseApiUri = null,
        $apiVersion = ''
    ) {
        parent::__construct($credentials, $httpClient, $storage, $scopes, $baseApiUri, true, $apiVersion);

        if (null === $baseApiUri) {
            $this->baseApiUri = new Uri('https://graph.facebook.com' . $this->getApiVersionString() . '/');
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthorizationEndpoint()
    {
        return new Uri('https://www.facebook.com' . $this->getApiVersionString() . '/dialog/oauth');
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessTokenEndpoint()
    {
        return new Uri('https://graph.facebook.com' . $this->getApiVersionString() . '/oauth/access_token');
    }

    /**
     * {@inheritdoc}
     */
    protected function parseAccessTokenResponse($responseBody)
    {
        $data = @json_decode($responseBody, true);

        // Facebook gives us a query string on old api (v2.0)
        if (!$data) {
            parse_str($responseBody, $data);
        }

        if (null === $data || !is_array($data)) {
            throw new TokenResponseException('Unable to parse response.');
        } elseif (isset($data['error'])) {
            throw new TokenResponseException('Error in retrieving token: "' . $data['error'] . '"');
        }

        $token = new StdOAuth2Token();
        $token->setAccessToken($data['access_token']);

        if (isset($data['expires'])) {
            $token->setLifeTime($data['expires']);
        }

        if (isset($data['refresh_token'])) {
            $token->setRefreshToken($data['refresh_token']);
            unset($data['refresh_token']);
        }

        unset($data['access_token'], $data['expires']);

        $token->setExtraParams($data);

        return $token;
    }

    public function getDialogUri($dialogPath, array $parameters)
    {
        if (!isset($parameters['redirect_uri'])) {
            throw new Exception('Redirect uri is mandatory for this request');
        }
        $parameters['app_id'] = $this->credentials->getConsumerId();
        $baseUrl = self::WWW_URL . $this->getApiVersionString() . '/dialog/' . $dialogPath;
        $query = http_build_query($parameters);

        return new Uri($baseUrl . '?' . $query);
    }

    /**
     * {@inheritdoc}
     */
    protected function getApiVersionString()
    {
        return empty($this->apiVersion) ? '' : '/v' . $this->apiVersion;
    }

    /**
     * {@inheritdoc}
     */
    protected function getScopesDelimiter()
    {
        return ',';
    }
}
