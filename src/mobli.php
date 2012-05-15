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

require_once "base_mobli.php";

/**
 * Extends the BaseMobli class with the intent of using
 * PHP sessions to store user ids and access tokens.
 */
class Mobli extends BaseMobli
{
  /**
   * Identical to the parent constructor, except that
   * we start a PHP session to store the user ID and
   * access token if during the course of execution
   * we discover them.
   *
   * @param Array $config the application configuration.
   * @see BaseMobli::__construct in mobli.php
   */
  public function __construct($clientId, $clientSecret)
  {
    if (!session_id())
    {
      session_start();
    }
    parent::__construct($clientId, $clientSecret);
  }

  protected static $kSupportedKeys = array('user_id', 'code', 'state', 'access_token_type', 'access_token', 'refresh_token', 'expiration_time');

  /**
   * Provides the implementations of the inherited abstract
   * methods.  The implementation uses PHP sessions to maintain
   * a store for authorization codes, user ids, CSRF states, and
   * access tokens.
   */
  protected function setPersistentData($key, $value)
  {
    if (!in_array($key, self::$kSupportedKeys))
    {
      self::errorLog('Unsupported key passed to setPersistentData.');
      return;
    }

    $session_var_name = $this->constructSessionVariableName($key);
    $_SESSION[$session_var_name] = $value;
  }

  protected function getPersistentData($key, $default = false)
  {
    if (!in_array($key, self::$kSupportedKeys))
    {
      self::errorLog('Unsupported key passed to getPersistentData.');
      return $default;
    }

    $session_var_name = $this->constructSessionVariableName($key);
    return isset($_SESSION[$session_var_name]) ?
      $_SESSION[$session_var_name] : $default;
  }

  protected function clearPersistentData($key)
  {
    if (!in_array($key, self::$kSupportedKeys))
    {
      self::errorLog('Unsupported key passed to clearPersistentData.');
      return;
    }

    $session_var_name = $this->constructSessionVariableName($key);
    unset($_SESSION[$session_var_name]);
  }

  protected function clearAllPersistentData()
  {
    foreach (self::$kSupportedKeys as $key)
    {
      $this->clearPersistentData($key);
    }
  }

  protected function constructSessionVariableName($key)
  {
    return implode('_', array('mb', $this->getClientId(), $key));
  }
}
