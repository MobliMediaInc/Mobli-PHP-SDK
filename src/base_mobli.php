<?php
/**
 * Copyright 2011 Mobli, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

if (!function_exists('curl_init'))
{
  throw new Exception('Mobli needs the CURL PHP extension.');
}
if (!function_exists('json_decode'))
{
  throw new Exception('Mobli needs the JSON PHP extension.');
}

/**
 * Thrown when an API call returns an exception.
 *
 * @author Naitik Shah <naitik@facebook.com>
 */
class MobliApiException extends Exception
{
  /**
   * The result from the API server that represents the exception information.
   */
  protected $result;

  /**
   * Make a new API Exception with the given result.
   *
   * @param array $result The result from the API server
   */
  public function __construct($result, $code)
  {
    $this->result = $result;

    if (isset($result->error_description))
    {
      // OAuth 2.0 Draft 10 style
      $msg = $result->error_description;
    }
    else if (isset($result->code))
    {
      $code = $result->code;
      if (is_array($result->userInfo))
      {
        $msg = implode('. ', $result->userInfo);
      }
      else
      {
        $msg = $result->userInfo;
      }
    }
    else
    {
      $msg = 'Unknown Error.';
    }

    parent::__construct($msg, $code);
  }

  /**
   * Return the associated result object returned by the API server.
   *
   * @return array The result from the API server
   */
  public function getResult() {
    return $this->result;
  }
}

/**
 * Provides access to the Mobli Platform.  This class provides
 * a majority of the functionality needed, but the class is abstract
 * because it is designed to be sub-classed.  The subclass must
 * implement the four abstract methods listed at the bottom of
 * the file.
 *
 * @author Naitik Shah <naitik@facebook.com>
 */
abstract class BaseMobli
{
  /**
   * Version.
   */
  const VERSION = '2.1.0';

  const MOBLI_ACCESS_TOKEN_TYPE_USER   = 'mobli_user_related';

  const MOBLI_ACCESS_TOKEN_TYPE_PUBLIC = 'mobli_shared';

  const MOBLI_GET_TOKEN_MODE_USER      = 0;
  
  const MOBLI_GET_TOKEN_MODE_PUBLIC    = 1;
  
  const MOBLI_GET_TOKEN_MODE_AUTO      = 2;
  
  /**
   * Default options for curl.
   */
  public static $CURL_OPTS = array(
    CURLOPT_CONNECTTIMEOUT => 10,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT        => 60,
    CURLOPT_USERAGENT      => 'mobli-php-2.1.0',
  );

  /**
   * List of query parameters that get automatically dropped when rebuilding
   * the current URL.
   */
  protected static $DROP_QUERY_PARAMS = array(
    'code',
    'state',
  );

  /**
   * Maps aliases to Mobli domains.
   */
  public static $DOMAIN_MAP = array(
    'oauth'     => 'https://oauth.mobli.com/',
    'api'       => 'https://api.mobli.com/',
  );

  /**
   * The Client ID.
   *
   * @var string
   */
  protected $clientId;

  /**
   * The Client Secret.
   *
   * @var string
   */
  protected $clientSecret;

  /**
   * The ID of the Mobli user, or 0 if the user is logged out.
   *
   * @var integer
   */
  protected $userId = 0;

  /**
   * The last valid code used to assist in preventing code reuse
   */
  protected $code = false;
  
  /**
   * A CSRF state variable to assist in the defense against CSRF attacks.
   */
  protected $state = false;

  /**
   * The OAuth access token type.
   * May be mobli_user_related or mobli_shared
   *
   * @var string
   */
  protected $accessTokenType = false;

  /**
   * The OAuth access token received in exchange for a valid authorization
   * code.  null means the access token has yet to be determined.
   *
   * @var string
   */
  protected $accessToken = false;

  /**
   * The OAuth refresh token for a valid access token.
   *
   * @var string
   */
  protected $refreshToken = false;

  /**
   * The expiry time of a valid access token.
   *
   * @var time
   */
  protected $expirationTime = false;

  /**
   * The OAuth data received in exchange for a valid authorization.
   * It comes either from the user authenticating interactively or
   * by requesting a public access token.
   *
   * @var array
   */
  protected $accessTokenData = false;

  /**
   * Initialize a Mobli Application.
   *
   * The configuration:
   * - clientId: the client ID
   * - clientSecret: the client secret
   *
   * @param array $config The application configuration
   */
  public function __construct($clientId, $clientSecret)
  {
    $this->setClientId($clientId);
    $this->setClientSecret($clientSecret);
    $this->restoreFromPersistentStore();
  }

  protected function saveToPersistentStore()
  {
    $this->setPersistentData('user_id', $this->userId);
    $this->setPersistentData('code', $this->code);
    $this->setPersistentData('state', $this->state);
    $this->setPersistentData('access_token_type', $this->accessTokenType);
    $this->setPersistentData('access_token', $this->accessToken);
    $this->setPersistentData('refresh_token', $this->refreshToken);
    $this->setPersistentData('expiration_time', $this->expirationTime);
  }
  
  protected function restoreFromPersistentStore()
  {
    $this->userId = $this->getPersistentData('user_id');
    $this->code = $this->getPersistentData('code');
    $this->state = $this->getPersistentData('state');
    $this->accessTokenType = $this->getPersistentData('access_token_type');
    $this->accessToken = $this->getPersistentData('access_token');
    $this->refreshToken = $this->getPersistentData('refresh_token');
    $this->expirationTime = $this->getPersistentData('expiration_time');
  }
  
  protected function resetAndClearPersistentStore()
  {
    $this->clearAllPersistentData();
    $this->userId = 0;
    $this->code = false;
    $this->state = false;
    $this->accessTokenType = false;
    $this->accessToken = false;
    $this->refreshToken = false;
    $this->expirationTime = false;
  }
  
  /**
   * Set the Client ID.
   *
   * @param string $clientId The Client ID
   * @return BaseMobli
   */
  public function setClientId($clientId)
  {
    $this->clientId = $clientId;
    return $this;
  }

  /**
   * Get the Client ID.
   *
   * @return string the Client ID
   */
  public function getClientId()
  {
    return $this->clientId;
  }

  /**
   * Set the Client Secret.
   *
   * @param string $clientSecret The Client Secret
   * @return BaseMobli
   */
  public function setClientSecret($clientSecret)
  {
    $this->clientSecret = $clientSecret;
    return $this;
  }

  /**
   * Get the Client Secret.
   *
   * @return string the Client Secret
   */
  public function getClientSecret()
  {
    return $this->clientSecret;
  }

  /**
   * Get the Access Token Type.
   *
   * @return string the Access Token Type
   */
  public function getAccessTokenType()
  {
    return $this->accessTokenType;
  }

  /**
   * Sets the access token for api calls.  Use this if you get
   * your access token by other means and just want the SDK
   * to use it.
   *
   * @param string $access_token an access token.
   * @return BaseMobli
   */
  public function setAccessToken($access_token)
  {
    $this->accessToken = $access_token;
    return $this;
  }

  /**
   * Determines the access token that should be used for API calls.
   *
   * @return string The access token
   */
  public function getAccessToken($mode = self::MOBLI_GET_TOKEN_MODE_USER)
  {
    switch ($mode)
    {
      case self::MOBLI_GET_TOKEN_MODE_USER:
        return $this->getUserAccessToken();
      case self::MOBLI_GET_TOKEN_MODE_PUBLIC:
        return $this->getPublicAccessToken();
      case self::MOBLI_GET_TOKEN_MODE_AUTO:
        if (!$this->getUserAccessToken())
        {
          return $this->getPublicAccessToken();
        }
    }
    return $this->accessToken;
  }

  /**
   * Get the UID of the connected user, or 0
   * if the user is not connected.
   *
   * @return string the UID if available.
   */
  public function getUserId()
  {
    return $this->userId;
  }      

  /**
   * Obtains a user access token
   * 
   * @return mixed The access token or false if no access token was granted
   */
  protected function getUserAccessToken()
  {
    if ($this->accessTokenType != self::MOBLI_ACCESS_TOKEN_TYPE_USER)
    {
      $code = $this->getCode();
      if ($code && $code != $this->code)
      {
        list($response_code, $access_token_data) = $this->getAccessTokenDataFromCode($code);
        if ($access_token_data)
        {
          if ($response_code != 200)
          {
            $this->throwAPIException($access_token_data, $response_code);
          }
          $this->accessToken = $access_token_data->access_token;
          $this->refreshToken = $access_token_data->refresh_token;
          $this->expirationTime = time() + $access_token_data->expires_in;
          $this->accessTokenType = $access_token_data->token_type;
          $this->userId = $access_token_data->user->id;
          $this->code = $code;
          $this->saveToPersistentStore();
        }
      }
    }
    return $this->accessToken;
  }
  
  /**
   * Obtains a public access token
   * 
   * @scope: array or space separated list of requested permissions
   *
   * @return mixed The access token or false if no access token was granted
   */
  protected function getPublicAccessToken()
  {
    if ($this->accessTokenType != self::MOBLI_ACCESS_TOKEN_TYPE_PUBLIC)
    {
      list($response_code, $access_token_response) =
        $this->sendRequest(
          $this->getUrl(
            'oauth',
            'shared'),
          'POST',
          $params = array(
            'client_id' => $this->getClientId(),
            'client_secret' => $this->getClientSecret(),
            'grant_type' => 'client_credentials',
            'scope' => 'shared'));
      
      if ($access_token_response)
      {
        $access_token_data = json_decode($access_token_response);
        if ($access_token_data)
        {
          if ($response_code != 200)
          {
            $this->throwAPIException($access_token_data, $response_code);
          }
          $this->accessToken = $access_token_data->access_token;
          $this->refreshToken = $access_token_data->refresh_token;
          $this->expirationTime = time() + $access_token_data->expires_in;
          $this->accessTokenType = $access_token_data->token_type;
          $this->userId = 0;
          $this->saveToPersistentStore();
        }
      }
    }
    return $this->accessToken;
  }

  /**
   * Get a Login URL for use with redirects.
   *
   * The parameters:
   * @scope: array or space separated list of requested permissions
   * @redirect_uri: the url to go to after a successful login
   *
   * @return string The URL for the login flow
   */
  public function getLoginUrl($scope, $redirect_url = null)
  {
    $this->establishCSRFTokenState();
    $redirect_url = ($redirect_url ? $redirect_url : $this->getCurrentUrl());

    // if 'scope' is passed as an array, convert to comma separated list
    if (is_array($scope))
    {
      $scope = implode(' ', $scope);
    }

    return $this->getUrl(
      'oauth',
      'authorize',
      array(
        'client_id' => $this->getClientId(),
				'response_type' => 'code',
        'state' => $this->state,
        'redirect_uri' => $redirect_url,
        'scope' => $scope));
  }

  /**
   * Get a Logout URL suitable for use with redirects.
   *
   * The parameters:
   * - next_url: the url to go to after a successful logout
   *
   * @param array $params Provide custom parameters
   * @return string The URL for the logout flow
   */
  public function getLogoutUrl($next_url = null)
  {
    $next_url = ($next_url ? $next_url : $this->getCurrentUrl());
    return $this->getUrl(
      'api',
      'logout',
      array(
        'next' => $next_url));
  }

  public function get($path, $params=array())
  {
    list($response_code, $response) =
      $this->api($path, 'GET', $params);
    
    return $response;
  }
  
  public function post($path, $params=array())
  {
    list($response_code, $response) =
      $this->api($path, 'POST', $params);
    
    return $response;
  }
  
  public function post_image($path, $params=array(), $image_path)
  {
    list($response_code, $response) =
      $this->api($path, 'POST', $params, array('file'=>"@$image_path"));
    
    return $response;
  }
  
  public function delete($path, $params=array())
  {
    list($response_code, $response) =
      $this->api($path, 'DELETE', $params);
    
    return $response;
  }
  
  /**
   * Get the authorization code from the query parameters, if it exists,
   * and otherwise return false to signal no authorization code was
   * discoverable.
   *
   * @return mixed The authorization code, or false if the authorization
   * code could not be determined.
   */
  protected function getCode()
  {
    if (isset($_REQUEST['code']))
    {
      if ($this->state &&
          isset($_REQUEST['state']) &&
          $this->state === $_REQUEST['state'])
      {
        // CSRF state has done its job, so clear it
        $this->state = false;
        $this->clearPersistentData('state');
        return $_REQUEST['code'];
      }
      else
      {
        self::errorLog('CSRF state token does not match one provided.');
        return false;
      }
    }

    return false;
  }

  /**
   * Retrieves an access token for the given authorization code
   * (previously generated from oauth.mobli.com on behalf of
   * a specific user).  The authorization code is sent to oauth.mobli.com
   * and a legitimate access token is generated provided the access token
   * and the user for which it was generated all match, and the user is
   * either logged in to Mobli.
   *
   * @param string $code An authorization code.
   * @return mixed An access token exchanged for the authorization code, or
   * false if an access token could not be generated.
   */
  protected function getAccessTokenDataFromCode($code, $redirect_uri = null)
  {
    if (empty($code))
    {
      return false;
    }

    if ($redirect_uri === null)
    {
      $redirect_uri = $this->getCurrentUrl();
    }

    list($response_code, $access_token_response) =
      $this->sendRequest(
        $this->getUrl(
          'oauth',
          '/code_exchange'),
        'POST',
        $params = array('client_id' => $this->getClientId(),
          'client_secret' => $this->getClientSecret(),
          'grant_type' => 'authorization_code',
          'redirect_uri' => $redirect_uri,
          'code' => $code));

    if (empty($access_token_response))
    {
      return false;
    }

    return array($response_code, json_decode($access_token_response));
  }

  /**
   * Lays down a CSRF state token for this process.
   *
   * @return void
   */
  protected function establishCSRFTokenState()
  {
    if (!$this->state)
    {
      $this->state = md5(uniqid(mt_rand(), true));
      $this->setPersistentData('state', $this->state);
    }
  }

  /**
   * Make an API call.
   *
   * @return mixed The decoded response
   */
  protected function api($path, $method = 'GET', $params = array(), $files = null)
  {
    if (!isset($params['access_token']))
    {
      $access_token = $this->getAccessToken();
    }
    else
    {
      $access_token = $params['access_token'];
      unset($params['access_token']);
    }
    if ($access_token)
    {
      $path.= (strpos($path, '?') ? '&' : '?').'access_token='.$access_token;
    }
    
    if ($method != 'GET' && $method != 'POST')
    {
      $params['http_method'] = $method;
      $method = 'POST';
    }
    
    $url = $this->getUrl('api', $path);
    list($response_code, $result) =
      $this->sendRequest(
        $this->getUrl('api', $path),
        $method,
        $params,
        $files);

    if ($result)
    {
      $result = json_decode($result);
      if ($result)
      {
        $success = (isset($result->success) ? $result->success : false);
        $payload = (isset($result->payload) ? $result->payload : false);
        if (!$payload)
        {
          $success = false;
          $payload = new stdClass();
          $payload->code = 500;
          $payload->userInfo = "Unknown error";
        }
        if ($response_code != 200 || !$success)
        {
          $this->throwAPIException($payload, 500);
        }
      }
      $result = $payload;
    }

    return array($response_code, $result);
  }

  /**
   * Makes an HTTP request. This method can be overridden by subclasses if
   * developers want to do fancier things or use something other than curl to
   * make the request.
   *
   * @param string $url The URL to make the request to
   * @param array $params The parameters to use for the POST body
   * @param array $files The parameters to use to upload files
   *
   * @return string The response text
   */
  protected function sendRequest($url, $http_method, $params, $files = null)
  {
    $ch = curl_init();

    $opts = self::$CURL_OPTS;
    // json_encode all params values that are not strings
    foreach ($params as $key => $value)
    {
      if (!is_string($value))
      {
        $params[$key] = json_encode($value);
      }
    }
    // Build the request
    // If the request is GET then build the query string
    // Otherwise fill the POST body
    if ($http_method == 'GET')
    {
      $query_string = http_build_query($params, null, '&');
      if ($query_string)
      {
        $url.= (strpos($url, '?') ? '&' : '?').$query_string;
      }
    }
    else
    {
      if (!$files || !count($files))
      {
        $opts[CURLOPT_POST] = true;
        $opts[CURLOPT_POSTFIELDS] = http_build_query($params, null, '&');
      }
      else
      {
        $opts[CURLOPT_POST] = false;
        $opts[CURLOPT_POSTFIELDS] = array_merge($params, $files);
      }
    }
    $opts[CURLOPT_URL] = $url;

    // disable the 'Expect: 100-continue' behaviour. This causes CURL to wait
    // for 2 seconds if the server does not support this header.
    if (isset($opts[CURLOPT_HTTPHEADER]))
    {
      $existing_headers = $opts[CURLOPT_HTTPHEADER];
      $existing_headers[] = 'Expect:';
      $opts[CURLOPT_HTTPHEADER] = $existing_headers;
    }
    else
    {
      $opts[CURLOPT_HTTPHEADER] = array('Expect:');
    }

    curl_setopt_array($ch, $opts);
    $result = curl_exec($ch);

    $response_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    if ($result === false)
    {
      $e = new MobliApiException(array(
        'error_code' => curl_errno($ch),
        'error' => array(
          'message' => curl_error($ch),
          'type' => 'CurlException',
          ),
      ));
      curl_close($ch);
      throw $e;
    }
    curl_close($ch);
    return array($response_code, $result);
  }

  /**
   * Build the URL for given domain alias, path and parameters.
   *
   * @param $name string The name of the domain
   * @param $path string Optional path (without a leading slash)
   * @param $params array Optional query parameters
   *
   * @return string The URL for the given parameters
   */
  protected function getUrl($name, $path='', $params=array())
  {
    $url = self::$DOMAIN_MAP[$name];
    if ($path)
    {
      if ($path[0] === '/')
      {
        $path = substr($path, 1);
      }
      $url .= $path;
    }
    if ($params)
    {
      $url.= (strpos($path, '?') ? '&' : '?') . http_build_query($params, null, '&');
    }

    return $url;
  }

  /**
   * Returns the Current URL, stripping it of known FB parameters that should
   * not persist.
   *
   * @return string The current URL
   */
  protected function getCurrentUrl()
  {
    if (isset($_SERVER['HTTPS']) &&
        ($_SERVER['HTTPS'] == 'on' || $_SERVER['HTTPS'] == 1) ||
        isset($_SERVER['HTTP_X_FORWARDED_PROTO']) &&
        $_SERVER['HTTP_X_FORWARDED_PROTO'] == 'https')
    {
      $protocol = 'https://';
    }
    else
    {
      $protocol = 'http://';
    }
    $currentUrl = $protocol . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
    $parts = parse_url($currentUrl);

    $query = '';
    if (!empty($parts['query'])) {
      // drop known mb params
      $params = explode('&', $parts['query']);
      $retained_params = array();
      foreach ($params as $param)
      {
        if ($this->shouldRetainParam($param))
        {
          $retained_params[] = $param;
        }
      }

      if (!empty($retained_params))
      {
        $query = '?'.implode($retained_params, '&');
      }
    }

    // use port if non default
    $port =
      isset($parts['port']) &&
      (($protocol === 'http://' && $parts['port'] !== 80) ||
       ($protocol === 'https://' && $parts['port'] !== 443))
      ? ':' . $parts['port'] : '';

    // rebuild
    return $protocol . $parts['host'] . $port . $parts['path'] . $query;
  }

  /**
   * Returns true if and only if the key or key/value pair should
   * be retained as part of the query string.  This amounts to
   * a brute-force search of the very small list of Mobli-specific
   * params that should be stripped out.
   *
   * @param string $param A key or key/value pair within a URL's query (e.g.
   *                     'foo=a', 'foo=', or 'foo'.
   *
   * @return boolean
   */
  protected function shouldRetainParam($param)
  {
    foreach (self::$DROP_QUERY_PARAMS as $drop_query_param)
    {
      if (strpos($param, $drop_query_param.'=') === 0)
      {
        return false;
      }
    }

    return true;
  }

  /**
   * Analyzes the supplied result to see if it was thrown
   * because the access token is no longer valid.  If that is
   * the case, then we destroy the session.
   *
   * @param $result array A record storing the error message returned
   *                      by a failed API call.
   */
  protected function throwAPIException($result, $code=200)
  {
    $e = new MobliApiException($result, $code);
    throw $e;
  }


  /**
   * Prints to the error log if you aren't in command line mode.
   *
   * @param string $msg Log message
   */
  protected static function errorLog($msg)
  {
    // disable error log if we are running in a CLI environment
    // @codeCoverageIgnoreStart
    if (php_sapi_name() != 'cli')
    {
      error_log($msg);
    }
    // uncomment this if you want to see the errors on the page
    // print 'error_log: '.$msg."\n";
    // @codeCoverageIgnoreEnd
  }

  /**
   * Destroy the current session
   */
  public function destroySession()
  {
    $this->resetAndClearPersistentStore();
  }

  /**
   * Each of the following four methods should be overridden in
   * a concrete subclass, as they are in the provided Mobli class.
   * The Mobli class uses PHP sessions to provide a primitive
   * persistent store, but another subclass--one that you implement--
   * might use a database, memcache, or an in-memory cache.
   *
   * @see Mobli
   */

  /**
   * Stores the given ($key, $value) pair, so that future calls to
   * getPersistentData($key) return $value. This call may be in another request.
   *
   * @param string $key
   * @param array $value
   *
   * @return void
   */
  abstract protected function setPersistentData($key, $value);

  /**
   * Get the data for $key, persisted by BaseMobli::setPersistentData()
   *
   * @param string $key The key of the data to retrieve
   * @param boolean $default The default value to return if $key is not found
   *
   * @return mixed
   */
  abstract protected function getPersistentData($key, $default = false);

  /**
   * Clear the data with $key from the persistent storage
   *
   * @param string $key
   * @return void
   */
  abstract protected function clearPersistentData($key);

  /**
   * Clear all data from the persistent storage
   *
   * @return void
   */
  abstract protected function clearAllPersistentData();
}
