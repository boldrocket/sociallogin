# Social Login #

Social login is a library that integrates several passportJS auth provider libraries in a unified way. You just need to provide your specific credentials for each provider and your website url.

List of available providers and urls to create authentication keys
* facebook    https://developers.facebook.com/
* twitter     https://apps.twitter.com/
* github      https://github.com/settings/applications
* google      https://console.developers.google.com/project
* linkedin    https://www.linkedin.com/secure/developer
* amazon      http://login.amazon.com/manageApps
* bitbucket   https://bitbucket.org/account/user/USERNAME/api
* dropbox     https://www.dropbox.com/developers/apps
* evernote    https://dev.evernote.com/key.php
* fitbit      https://dev.fitbit.com/apps
* flickr      https://www.flickr.com/services/apps/
* foursquare  https://foursquare.com/developers/apps
* instagram   http://instagram.com/developer/clients/manage/
* meetup      https://secure.meetup.com/meetup_api/oauth_consumers/
* spotify     https://developer.spotify.com/my-applications/#!/applications
* trello      https://trello.com/1/appKey/generate
* tumblr      https://www.tumblr.com/oauth/apps
* vimeo       https://developer.vimeo.com/apps
* windowslive https://account.live.com/developers/applications/index
* wordpress   https://developer.wordpress.com/apps/
* yahoo       https://developer.apps.yahoo.com/projects

## install ##
`npm install sociallogin`

## setup ##
```

// Initialise package
var sociallogin = require('sociallogin');

// Add Strategies function call
sociallogin.addPassportStategies(passportModule, config, userAuthenticationCallback, siteUrl);
* passportModule - an instance of the passportJS module
* config - a json object that holds the configured providers and their credentials
The following will only activate the windowslive, wordpress and yahoo providers for your application
windowslive: {
    clientID: 'XXXXXXXXXXXXXXXXXXXXX',
    clientSecret: 'XXXXXXXXXXXXXXXXXXXXX'
},
wordpress: {
    clientID: 'XXXXXXXXXXXXXXXXXXXXX',
    clientSecret: 'XXXXXXXXXXXXXXXXXXXXX'
},
yahoo: {
    clientID: 'XXXXXXXXXXXXXXXXXXXXX--',
    clientSecret: 'XXXXXXXXXXXXXXXXXXXXX'
}
* userAuthenticationCallback(providerId,providerName,displayName,emailAddress,username,passportDone) - callback function that gives user information to register or login a user . Implement your own based on the user needed for your application.
// providerId - the unique identifier based on the oauth provider
// providerName - the provider name based on the above list e.g google
// displayName - display name from the provider (might be undefined)
// emailAddress - email address from the provider (might be undefined)
// username - username from the provider (might be undefined)
// passportDone(err,user) - passportJS function that you need to call when the user is created or when an error occured
e.g
function addUser(providerId,providerName,displayName,emailAddress,username,passportDone){
      User.findOne({
          'providerId': providerId,
          'providerName': providerName
      }, function(err, user) {
          if (err) {
              return passportDone(err);
          }
          if (!user) {
              user = new User({
                  name: displayName,
                  username: username || emailAddress.split('@')[0],
                  providerName: providerName,
                  providerId: providerId,
                  email: emailAddress,
                  roles: ['authenticated']
              });
              user.save(function(err) {
                  if (err) console.log(err);
                  return passportDone(err, user);
              });
          } else {
              return passportDone(err, user);
          }
      });
  }
* siteUrl - the website url and protocol (https is recomended) that uses this plugin e.g https://sociallogin.heroku.com

// Add authentication urls
sociallogin.addAuthenticationUrls(passportModule, expressModule,signInController, authenticationController, failureRedirectUrl, config);
* passportModule - an instance of the passportJS module
* expressModule - an instance of the express app
* signInController(req,res) - check if user is authenticated and redirect
e.g
function(req, res) {
  if (req.isAuthenticated()) {
    return res.redirect('/');
  }
  res.redirect('#!/login');
};
* authenticationController(req,res) - authenticated user callback
function(req, res) {
  res.redirect('/');
};
* failureRedirectUrl - url to redirect to if authentication fails
e.g '#!/login'
* config - a json object that holds the configured providers and their credentials. Same as above

// Add urls for provider specific authentication to your views. All the configured providers will be accessible with your applicationUrl/oauth/providerName
e.g
<a href="/auth/yahoo" class="button">
    <span>Log In With Yahoo</span>
</a>

```
