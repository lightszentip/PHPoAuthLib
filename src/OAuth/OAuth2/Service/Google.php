<?php

namespace OAuth\OAuth2\Service;

use OAuth\Common\Consumer\CredentialsInterface;
use OAuth\Common\Http\Client\ClientInterface;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\Uri;
use OAuth\Common\Http\Uri\UriInterface;
use OAuth\Common\Storage\TokenStorageInterface;
use OAuth\OAuth2\Service\Exception\InvalidAccessTypeException;
use OAuth\OAuth2\Token\StdOAuth2Token;

class Google extends AbstractService
{
    /**
     * Defined scopes - More scopes are listed here:
     * https://developers.google.com/oauthplayground/.
     *
     * Make a pull request if you need more scopes.
     */

    // Basic
    public const SCOPE_EMAIL = 'email';
    public const SCOPE_PROFILE = 'profile';

    public const SCOPE_USERINFO_EMAIL = 'https://www.googleapis.com/auth/userinfo.email';
    public const SCOPE_USERINFO_PROFILE = 'https://www.googleapis.com/auth/userinfo.profile';

    // Google+
    public const SCOPE_GPLUS_ME = 'https://www.googleapis.com/auth/plus.me';
    public const SCOPE_GPLUS_LOGIN = 'https://www.googleapis.com/auth/plus.login';
    public const SCOPE_GPLUS_CIRCLES_READ = 'https://www.googleapis.com/auth/plus.circles.read';
    public const SCOPE_GPLUS_CIRCLES_WRITE = 'https://www.googleapis.com/auth/plus.circles.write';
    public const SCOPE_GPLUS_STREAM_READ = 'https://www.googleapis.com/auth/plus.stream.read';
    public const SCOPE_GPLUS_STREAM_WRITE = 'https://www.googleapis.com/auth/plus.stream.write';
    public const SCOPE_GPLUS_MEDIA = 'https://www.googleapis.com/auth/plus.media.upload';
    public const SCOPE_EMAIL_PLUS = 'https://www.googleapis.com/auth/plus.profile.emails.read';

    // Google Drive
    public const SCOPE_DOCUMENTSLIST = 'https://docs.google.com/feeds/';
    public const SCOPE_SPREADSHEETS = 'https://spreadsheets.google.com/feeds/';
    public const SCOPE_GOOGLEDRIVE = 'https://www.googleapis.com/auth/drive';
    public const SCOPE_DRIVE_APPS = 'https://www.googleapis.com/auth/drive.appdata';
    public const SCOPE_DRIVE_APPS_READ_ONLY = 'https://www.googleapis.com/auth/drive.apps.readonly';
    public const SCOPE_GOOGLEDRIVE_FILES = 'https://www.googleapis.com/auth/drive.file';
    public const SCOPE_DRIVE_METADATA_READ_ONLY = 'https://www.googleapis.com/auth/drive.metadata.readonly';
    public const SCOPE_DRIVE_READ_ONLY = 'https://www.googleapis.com/auth/drive.readonly';
    public const SCOPE_DRIVE_SCRIPTS = 'https://www.googleapis.com/auth/drive.scripts';

    // Adwords
    public const SCOPE_ADSENSE = 'https://www.googleapis.com/auth/adsense';
    public const SCOPE_ADWORDS = 'https://www.googleapis.com/auth/adwords';
    public const SCOPE_ADWORDS_DEPRECATED = 'https://www.googleapis.com/auth/adwords/'; //deprecated in v201406 API version
    public const SCOPE_GAN = 'https://www.googleapis.com/auth/gan'; // google affiliate network...?

    //Doubleclick for Publishers
    public const SCOPE_DFP = 'https://www.googleapis.com/auth/dfp';
    public const SCOPE_DFP_TRAFFICKING = 'https://www.googleapis.com/auth/dfatrafficking';
    public const SCOPE_DFP_REPORTING = 'https://www.googleapis.com/auth/dfareporting';

    // Google Analytics
    public const SCOPE_ANALYTICS = 'https://www.googleapis.com/auth/analytics';
    public const SCOPE_ANALYTICS_EDIT = 'https://www.googleapis.com/auth/analytics.edit';
    public const SCOPE_ANALYTICS_MANAGE_USERS = 'https://www.googleapis.com/auth/analytics.manage.users';
    public const SCOPE_ANALYTICS_READ_ONLY = 'https://www.googleapis.com/auth/analytics.readonly';

    //Gmail
    public const SCOPE_GMAIL_MODIFY = 'https://www.googleapis.com/auth/gmail.modify';
    public const SCOPE_GMAIL_READONLY = 'https://www.googleapis.com/auth/gmail.readonly';
    public const SCOPE_GMAIL_COMPOSE = 'https://www.googleapis.com/auth/gmail.compose';
    public const SCOPE_GMAIL_SEND = 'https://www.googleapis.com/auth/gmail.send';
    public const SCOPE_GMAIL_INSERT = 'https://www.googleapis.com/auth/gmail.insert';
    public const SCOPE_GMAIL_LABELS = 'https://www.googleapis.com/auth/gmail.labels';
    public const SCOPE_GMAIL_FULL = 'https://mail.google.com/';

    // Other services
    public const SCOPE_BOOKS = 'https://www.googleapis.com/auth/books';
    public const SCOPE_BLOGGER = 'https://www.googleapis.com/auth/blogger';
    public const SCOPE_CALENDAR = 'https://www.googleapis.com/auth/calendar';
    public const SCOPE_CALENDAR_READ_ONLY = 'https://www.googleapis.com/auth/calendar.readonly';
    public const SCOPE_CONTACT = 'https://www.google.com/m8/feeds/';
    public const SCOPE_CONTACTS_RO = 'https://www.googleapis.com/auth/contacts.readonly';
    public const SCOPE_CHROMEWEBSTORE = 'https://www.googleapis.com/auth/chromewebstore.readonly';
    public const SCOPE_GMAIL = 'https://mail.google.com/mail/feed/atom';
    public const SCOPE_GMAIL_IMAP_SMTP = 'https://mail.google.com';
    public const SCOPE_PICASAWEB = 'https://picasaweb.google.com/data/';
    public const SCOPE_SITES = 'https://sites.google.com/feeds/';
    public const SCOPE_URLSHORTENER = 'https://www.googleapis.com/auth/urlshortener';
    public const SCOPE_WEBMASTERTOOLS = 'https://www.google.com/webmasters/tools/feeds/';
    public const SCOPE_TASKS = 'https://www.googleapis.com/auth/tasks';

    // Cloud services
    public const SCOPE_CLOUDSTORAGE = 'https://www.googleapis.com/auth/devstorage.read_write';
    public const SCOPE_CONTENTFORSHOPPING = 'https://www.googleapis.com/auth/structuredcontent'; // what even is this
    public const SCOPE_USER_PROVISIONING = 'https://apps-apis.google.com/a/feeds/user/';
    public const SCOPE_GROUPS_PROVISIONING = 'https://apps-apis.google.com/a/feeds/groups/';
    public const SCOPE_NICKNAME_PROVISIONING = 'https://apps-apis.google.com/a/feeds/alias/';

    // Old
    public const SCOPE_ORKUT = 'https://www.googleapis.com/auth/orkut';
    public const SCOPE_GOOGLELATITUDE =
        'https://www.googleapis.com/auth/latitude.all.best https://www.googleapis.com/auth/latitude.all.city';
    public const SCOPE_OPENID = 'openid';

    // YouTube
    public const SCOPE_YOUTUBE_GDATA = 'https://gdata.youtube.com';
    public const SCOPE_YOUTUBE_ANALYTICS_MONETARY = 'https://www.googleapis.com/auth/yt-analytics-monetary.readonly';
    public const SCOPE_YOUTUBE_ANALYTICS = 'https://www.googleapis.com/auth/yt-analytics.readonly';
    public const SCOPE_YOUTUBE = 'https://www.googleapis.com/auth/youtube';
    public const SCOPE_YOUTUBE_READ_ONLY = 'https://www.googleapis.com/auth/youtube.readonly';
    public const SCOPE_YOUTUBE_UPLOAD = 'https://www.googleapis.com/auth/youtube.upload';
    public const SCOPE_YOUTUBE_PARTNER = 'https://www.googleapis.com/auth/youtubepartner';
    public const SCOPE_YOUTUBE_PARTNER_AUDIT = 'https://www.googleapis.com/auth/youtubepartner-channel-audit';

    // Google Glass
    public const SCOPE_GLASS_TIMELINE = 'https://www.googleapis.com/auth/glass.timeline';
    public const SCOPE_GLASS_LOCATION = 'https://www.googleapis.com/auth/glass.location';

    // Android Publisher
    public const SCOPE_ANDROID_PUBLISHER = 'https://www.googleapis.com/auth/androidpublisher';

    // Google Classroom
    public const SCOPE_CLASSROOM_COURSES = 'https://www.googleapis.com/auth/classroom.courses';
    public const SCOPE_CLASSROOM_COURSES_READONLY = 'https://www.googleapis.com/auth/classroom.courses.readonly';
    public const SCOPE_CLASSROOM_PROFILE_EMAILS = 'https://www.googleapis.com/auth/classroom.profile.emails';
    public const SCOPE_CLASSROOM_PROFILE_PHOTOS = 'https://www.googleapis.com/auth/classroom.profile.photos';
    public const SCOPE_CLASSROOM_ROSTERS = 'https://www.googleapis.com/auth/classroom.rosters';
    public const SCOPE_CLASSROOM_ROSTERS_READONLY = 'https://www.googleapis.com/auth/classroom.rosters.readonly';

    protected $accessType = 'online';

    public function __construct(
        CredentialsInterface $credentials,
        ClientInterface $httpClient,
        TokenStorageInterface $storage,
        $scopes = [],
        ?UriInterface $baseApiUri = null
    ) {
        parent::__construct($credentials, $httpClient, $storage, $scopes, $baseApiUri, true);

        if (null === $baseApiUri) {
            $this->baseApiUri = new Uri('https://www.googleapis.com/oauth2/v1/');
        }
    }

    public function setAccessType($accessType): void
    {
        if (!in_array($accessType, ['online', 'offline'], true)) {
            throw new InvalidAccessTypeException('Invalid accessType, expected either online or offline');
        }
        $this->accessType = $accessType;
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthorizationEndpoint()
    {
        return new Uri('https://accounts.google.com/o/oauth2/auth?access_type=' . $this->accessType);
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessTokenEndpoint()
    {
        return new Uri('https://oauth2.googleapis.com/token');
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
