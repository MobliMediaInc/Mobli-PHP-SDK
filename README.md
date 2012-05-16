
Mobli PHP SDK (v.1.0)
==========================

The [Mobli API](http://developers.mobli.com/) is
a set of APIs that allows you to perform GET requests in order to view photos and videos uploaded to mobli, 
and POST requests for uploading photos, commenting, sharing on other social media networks and more..

This repository contains the open source PHP SDK that allows you to access Mobli from your PHP app. Except as otherwise noted, the Mobli PHP SDK
is licensed under the Apache Licence, Version 2.0
(http://www.apache.org/licenses/LICENSE-2.0.html)

You can perform requests as either a guest or as a logged in user.
as a guest user you will be able to GET media such as popular photos, live media, etc..
as a logged in user you will be able also to upload media, comment, love photos etc..

Usage
-----

    require 'Mobli-SDK-PHP/src/mobli.php';

    $mobli = new Mobli(array(
      'appId'  => 'YOUR_APP_ID',
      'secret' => 'YOUR_APP_SECRET',
    ));

    // Get User ID
    $user_id = $mobli->getUserId();

To make [API][API] calls:

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
  

Login or logout url will be needed depending on current user state.

    if ($user_id) {
      $logoutUrl = $mobli->getLogoutUrl();
    } else {
      $loginUrl = $mobli->getLoginUrl();
    }

[API]: http://developers.mobli.com/documentation

As a guest you can for example GET popular:

$mobli->get('/explore/popular/media')

as a logged in user you can perform GET or POST requests like this:

GET: $mobli->get('/me/feed')

POST: 

posting an image:

$mobli->post_image('/media',
  	array(
		 'extension' => 'jpg',
		 'type' => 'photo' // <-- this was missing
		), 'image.jpg');

posting a comment:

$mobli->post("/media/7118158/Comments", 
  	array(
		 'text'  => "Nice!"
		));