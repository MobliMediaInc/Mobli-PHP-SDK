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

require '../src/mobli.php';

define('ClientId', '<YOUR_CLIENT_ID>');
define('ClientSecret', 'YOUR_CLIENT_SECRET');

// Create our Application instance (replace this with your clientId and secret).
$mobli = new Mobli(ClientId, ClientSecret);

if (isset($_GET['logout']))
{
  $mobli->destroySession();
  header('Location: index.php');
  exit;
}
try
{
  $mobli->getAccessToken(Mobli::MOBLI_GET_TOKEN_MODE_AUTO);
}
catch(Exception $e)
{
  echo $e->getMessage();
}
// Get User ID
$user_id = $mobli->getUserId();

// We may or may not have this data based on whether the user is logged in.
//
// If we have a $user_id id here, it means we know the user is logged into
// Mobli, but we don't know if the access token is valid. An access
// token is invalid if the user logged out of Mobli.

if ($user_id)
{
  try
  {
    // Proceed knowing you have a logged in user who's authenticated.
    $private_profile = $mobli->get('/me');
  }
  catch (MobliApiException $e)
  {
    echo $e->getMessage();
  }  
}

try
{
  // Get a public profile.
  $public_profile = $mobli->get('/user/1');
}
catch (MobliApiException $e)
{
  echo $e->getMessage();
}
// Login or logout url will be needed depending on current user state.
if ($user_id)
{
  $logoutUrl = "?logout";
}
else
{
  $loginUrl = $mobli->getLoginUrl(array('scope'=>'shared basic'));
}

?>
<!doctype html>
<html xmlns:mb="http://www.mobli.com/2012/mbml">
  <head>
    <title>php-sdk</title>
    <style>
      body {
        font-family: 'Lucida Grande', Verdana, Arial, sans-serif;
      }
      h1 a {
        text-decoration: none;
        color: #3b5998;
      }
      h1 a:hover {
        text-decoration: underline;
      }
    </style>
  </head>
  <body>
    <h1>php-sdk</h1>

    <?php if ($user_id): ?>
      <a href="<?php echo $logoutUrl; ?>">Logout</a>
    <?php else: ?>
      <div>
        Login using OAuth 2.0 handled by the PHP SDK:
        <a href="<?php echo $loginUrl; ?>">Login with Mobli</a>
      </div>
    <?php endif ?>

    <h3>PHP Session</h3>
    <pre><?php print_r($_SESSION); ?></pre>

    <table>
      <tbody>
        <tr>
          <td>
            <h3>You</h3>
          </td>
          <td>
            <h3>Me</h3>
          </td>
        </tr>
        <tr>
          <td>
            <?php if ($private_profile): ?>
              <img src="<?php echo $private_profile->thumbnails->prefix.$private_profile->thumbnails->sizes[0].'.'.$private_profile->thumbnails->ext; ?>">
        
              <h3>Your User Object (/me)</h3>
              <pre><?php print_r($private_profile); ?></pre>
            <?php else: ?>
              <strong><em>You are not Connected.</em></strong>
            <?php endif ?>
          </td>
          <td>
            <?php if ($public_profile): ?>
              <img src="<?php echo $public_profile->thumbnails->prefix.$public_profile->thumbnails->sizes[0].'.'.$public_profile->thumbnails->ext; ?>">
      
              <h3>My User Object (/user/1)</h3>
              <pre><?php print_r($public_profile); ?></pre>
            <?php else: ?>
              <strong><em>You don't have a public token.</em></strong>
            <?php endif ?>
          </td>
        </tr>
      </tbody>
    </table>
  </body>
</html>
