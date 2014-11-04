/**
 * Created by Antonis on 19/10/2014.
 */
var TwitterStrategy = require('passport-twitter').Strategy,
    FacebookStrategy = require('passport-facebook').Strategy,
    GitHubStrategy = require('passport-github').Strategy,
    GoogleStrategy = require('passport-google-oauth').OAuth2Strategy,
    LinkedinStrategy = require('passport-linkedin').Strategy,
    AmazonStrategy = require('passport-amazon').Strategy,
    BitbucketStrategy = require('passport-bitbucket').Strategy,
    DropboxOAuth2Strategy = require('passport-dropbox-oauth2').Strategy,
    EvernoteStrategy = require('passport-evernote').Strategy,
    FitbitStrategy = require('passport-fitbit').Strategy,
    FlickrStrategy = require('passport-flickr').Strategy,
    FoursquareStrategy = require('passport-foursquare').Strategy,
    InstagramStrategy = require('passport-instagram').Strategy,
    MeetupStrategy = require('passport-meetup').Strategy,
    SpotifyStrategy = require('passport-spotify').Strategy,
    TrelloStrategy = require('passport-trello').Strategy,
    TumblrStrategy = require('passport-tumblr').Strategy,
    VimeoStrategy = require('passport-vimeo-oauth2').Strategy,
    WindowsLiveStrategy = require('passport-windowslive').Strategy,
    WordpressStrategy = require('passport-wordpress').Strategy,
    YahooStrategy = require('passport-yahoo-oauth').Strategy;

exports.addPassportStategies = function(passportModule, config, userAuthenticationCallback, siteUrl) {
    // Use twitter strategy

    if(config.twitter) {

        checkCredentialsExists('twitter', config.twitter);
        passportModule.use(new TwitterStrategy({
                consumerKey: config.twitter.clientID,
                consumerSecret: config.twitter.clientSecret,
                callbackURL: siteUrl + '/auth/twitter/callback'
            },
            function (token, tokenSecret, profile, done) {
                console.log(profile);
                userAuthenticationCallback(profile.id, profile.provider, profile.displayName, '', profile.username, done);
            }
        ));
    }

    if(config.facebook) {

        checkCredentialsExists('facebook', config.facebook);
        // Use facebook strategy
        passportModule.use(new FacebookStrategy({
                clientID: config.facebook.clientID,
                clientSecret: config.facebook.clientSecret,
                callbackURL: siteUrl + '/auth/facebook/callback'
            },
            function (accessToken, refreshToken, profile, done) {
                console.log(profile);
                var emailAddress = '';
                if (profile.emails.length > 0) {
                    emailAddress = profile.emails[0].value;
                }

                userAuthenticationCallback(profile.id, profile.provider, profile.displayName, emailAddress, profile.username, done);

            }
        ));
    }

    if(config.github) {

        checkCredentialsExists('github', config.github);
        // Use github strategy
        passportModule.use(new GitHubStrategy({
                clientID: config.github.clientID,
                clientSecret: config.github.clientSecret,
                callbackURL: siteUrl + '/auth/github/callback'
            },
            function (accessToken, refreshToken, profile, done) {
                console.log(profile);
                var emailAddress = '';
                if (profile.emails.length > 0) {
                    emailAddress = profile.emails[0].value;
                }
                userAuthenticationCallback(profile.id, profile.provider, profile.displayName, emailAddress, profile.username, done);
            }
        ));
    }

    if(config.google) {

        checkCredentialsExists('google', config.google);
        // Use google strategy
        passportModule.use(new GoogleStrategy({
                clientID: config.google.clientID,
                clientSecret: config.google.clientSecret,
                callbackURL: siteUrl + '/auth/google/callback'
            },
            function (accessToken, refreshToken, profile, done) {
                console.log(profile);
                var emailAddress = '';
                if (profile.emails.length > 0) {
                    emailAddress = profile.emails[0].value;
                }
                userAuthenticationCallback(profile.id, profile.provider, profile.displayName, emailAddress, '', done);
            }
        ));
    }

    if(config.linkedin) {

        checkCredentialsExists('linkedin', config.linkedin);
        // use linkedin strategy
        passportModule.use(new LinkedinStrategy({
                consumerKey: config.linkedin.clientID,
                consumerSecret: config.linkedin.clientSecret,
                callbackURL: siteUrl + '/auth/linkedin/callback',
                profileFields: ['id', 'first-name', 'last-name', 'email-address']
            },
            function (accessToken, refreshToken, profile, done) {
                console.log(profile);
                var emailAddress = '';
                if (profile.emails.length > 0) {
                    emailAddress = profile.emails[0].value;
                }
                userAuthenticationCallback(profile.id, profile.provider, profile.displayName, emailAddress, '', done);
            }
        ));
    }

    if(config.amazon) {

        checkCredentialsExists('amazon', config.amazon);
        // Use amazon strategy
        passportModule.use(new AmazonStrategy({
                clientID: config.amazon.clientID,
                clientSecret: config.amazon.clientSecret,
                callbackURL: siteUrl + '/auth/amazon/callback'
            },
            function (accessToken, refreshToken, profile, done) {
                console.log(profile);
                var emailAddress = '';
                if (profile.emails.length > 0) {
                    emailAddress = profile.emails[0].value;
                }
                userAuthenticationCallback(profile.id, profile.provider, profile.displayName, emailAddress, '', done);
            }
        ));
    }

    if(config.bitbucket) {

        checkCredentialsExists('bitbucket', config.bitbucket);
        passportModule.use(new BitbucketStrategy({
                consumerKey: config.bitbucket.clientID,
                consumerSecret: config.bitbucket.clientSecret,
                callbackURL: siteUrl + '/auth/bitbucket/callback'
            },
            function (token, tokenSecret, profile, done) {
                console.log(profile);
                userAuthenticationCallback(profile.username, profile.provider, profile.displayName, '', profile.username, done);
            }
        ));
    }

    if(config.dropbox) {

        checkCredentialsExists('dropbox', config.dropbox);
        passportModule.use(new DropboxOAuth2Strategy({
                clientID: config.dropbox.clientID,
                clientSecret: config.dropbox.clientSecret,
                callbackURL: siteUrl + '/auth/dropbox/callback'
            },
            function (accessToken, refreshToken, profile, done) {
                console.log(profile);
                var emailAddress = '';
                if (profile.emails.length > 0) {
                    emailAddress = profile.emails[0].value;
                }
                userAuthenticationCallback(profile.id, profile.provider, profile.displayName, emailAddress, '', done);
            }
        ));
    }

    if(config.evernote) {

        checkCredentialsExists('evernote', config.evernote);
        passportModule.use(new EvernoteStrategy({
                consumerKey: config.evernote.clientID,
                consumerSecret: config.evernote.clientSecret,
                callbackURL: siteUrl + '/auth/evernote/callback'
            },
            function (accessToken, refreshToken, profile, done) {
                console.log(profile);
                userAuthenticationCallback(profile.id, profile.provider, '', '', '', done);
            }
        ));
    }

    if(config.fitbit) {

        checkCredentialsExists('fitbit', config.fitbit);
        passportModule.use(new FitbitStrategy({
                consumerKey: config.fitbit.clientID,
                consumerSecret: config.fitbit.clientSecret,
                callbackURL: siteUrl + '/auth/fitbit/callback'
            },
            function (accessToken, refreshToken, profile, done) {
                console.log(profile);
                userAuthenticationCallback(profile.id, profile.provider, profile.displayName, '', '', done);
            }
        ));
    }

    if(config.flickr) {

        checkCredentialsExists('flickr', config.flickr);
        passportModule.use(new FlickrStrategy({
                consumerKey: config.flickr.clientID,
                consumerSecret: config.flickr.clientSecret,
                callbackURL: siteUrl + '/auth/flickr/callback'
            },
            function (accessToken, refreshToken, profile, done) {
                console.log(profile);
                userAuthenticationCallback(profile.id, profile.provider, profile.displayName, '', '', done);
            }
        ));
    }

    if(config.foursquare) {

        checkCredentialsExists('foursquare', config.foursquare);
        passportModule.use(new FoursquareStrategy({
                clientID: config.foursquare.clientID,
                clientSecret: config.foursquare.clientSecret,
                callbackURL: siteUrl + '/auth/foursquare/callback'
            },
            function (accessToken, refreshToken, profile, done) {
                console.log(profile);
                var emailAddress = '';
                if (profile.emails.length > 0) {
                    emailAddress = profile.emails[0].value;
                }
                userAuthenticationCallback(profile.id, profile.provider, profile.name.givenName + ' ' + profile.name.familyName, emailAddress, '', done);
            }
        ));
    }

    if(config.instagram) {

        checkCredentialsExists('instagram', config.instagram);
        passportModule.use(new InstagramStrategy({
                clientID: config.instagram.clientID,
                clientSecret: config.instagram.clientSecret,
                callbackURL: siteUrl + '/auth/instagram/callback'
            },
            function (accessToken, refreshToken, profile, done) {
                console.log(profile);
                userAuthenticationCallback(profile.id, profile.provider, profile.displayName, '', profile.username, done);
            }
        ));
    }

    if(config.meetup) {

        checkCredentialsExists('meetup', config.meetup);
        passportModule.use(new MeetupStrategy({
                consumerKey: config.meetup.clientID,
                consumerSecret: config.meetup.clientSecret,
                callbackURL: siteUrl + '/auth/meetup/callback'
            },
            function (accessToken, refreshToken, profile, done) {
                console.log(profile);
                userAuthenticationCallback(profile.id, profile.provider, profile.displayName, '', '', done);
            }
        ));
    }

    if(config.spotify) {

        checkCredentialsExists('spotify', config.spotify);
        passportModule.use(new SpotifyStrategy({
                clientID: config.spotify.clientID,
                clientSecret: config.spotify.clientSecret,
                callbackURL: siteUrl + '/auth/spotify/callback'
            },
            function (accessToken, refreshToken, profile, done) {
                console.log(profile);
                userAuthenticationCallback(profile.id, profile.provider, profile.displayName, '', profile.username, done);
            }
        ));
    }

    if(config.trello) {

        checkCredentialsExists('trello', config.trello);
        passportModule.use(new TrelloStrategy({
                consumerKey: config.trello.clientID,
                consumerSecret: config.trello.clientSecret,
                callbackURL: siteUrl + '/auth/trello/callback',
                passReqToCallback: true,
                trelloParams: {
                    scope: 'read,write',
                    expiration: 'never'
                }
            },
            function (req, token, tokenSecret, profile, done) {
                console.log(profile);
                userAuthenticationCallback(profile.id, profile.provider, profile.displayName, profile._json.email, profile._json.username, done);
            }
        ));
    }

    if(config.tumblr) {

        checkCredentialsExists('tumblr', config.tumblr);
        passportModule.use(new TumblrStrategy({
                consumerKey: config.tumblr.clientID,
                consumerSecret: config.tumblr.clientSecret,
                callbackURL: siteUrl + '/auth/tumblr/callback'
            },
            function (accessToken, refreshToken, profile, done) {
                console.log(profile);
                userAuthenticationCallback(profile.username, profile.provider, '', '', profile.username, done);
            }
        ));
    }

    if(config.vimeo) {

        checkCredentialsExists('vimeo', config.vimeo);
        passportModule.use(new VimeoStrategy({
                clientID: config.vimeo.clientID,
                clientSecret: config.vimeo.clientSecret,
                callbackURL: siteUrl + '/auth/vimeo/callback'
            },
            function (accessToken, refreshToken, profile, done) {
                console.log(profile);
                userAuthenticationCallback(profile.id, profile.provider, profile.displayName, '', profile.username, done);
            }
        ));
    }

    if(config.windowslive) {

        checkCredentialsExists('windowslive', config.windowslive);
        passportModule.use(new WindowsLiveStrategy({
                clientID: config.windowslive.clientID,
                clientSecret: config.windowslive.clientSecret,
                callbackURL: siteUrl + '/auth/windowslive/callback'
            },
            function (accessToken, refreshToken, profile, done) {
                console.log(profile);
                userAuthenticationCallback(profile.id, profile.provider, profile.displayName, '', profile.username, done);
            }
        ));
    }

    if(config.wordpress) {

        checkCredentialsExists('wordpress', config.wordpress);
        passportModule.use(new WordpressStrategy({
                clientID: config.wordpress.clientID,
                clientSecret: config.wordpress.clientSecret,
                callbackURL: siteUrl + '/auth/wordpress/callback'
            },
            function (accessToken, refreshToken, profile, done) {
                console.log(profile);
                userAuthenticationCallback(profile._json.id, profile.provider, profile.displayName, profile._json.email, '', done);
            }
        ));
    }

    if(config.yahoo) {

        YahooStrategy.prototype.userProfile = function(token, tokenSecret, params, done) {
            this._oauth.get('https://social.yahooapis.com/v1/user/' + params.xoauth_yahoo_guid + '/profile?format=json', token, tokenSecret, function (err, body, res) {
                if (err) { return done(err); }

                try {
                    var json = JSON.parse(body);

                    var profile = { provider: 'yahoo' };
                    profile.id = json.profile.guid;
                    profile.displayName = json.profile.givenName + ' ' + json.profile.familyName;
                    profile.name = { familyName: json.profile.familyName,
                        givenName: json.profile.givenName };

                    profile._raw = body;
                    profile._json = json;
                    done(null, profile);
                } catch(e) {
                    done(e);
                }
            });
        };

        checkCredentialsExists('yahoo', config.yahoo);
        passportModule.use(new YahooStrategy({
                consumerKey: config.yahoo.clientID,
                consumerSecret: config.yahoo.clientSecret,
                callbackURL: siteUrl + '/auth/yahoo/callback'
            },
            function (accessToken, refreshToken, profile, done) {
                console.log(profile);
                userAuthenticationCallback(profile.id, profile.provider, profile.displayName, '', '', done);
            }
        ));
    }

}

exports.addAuthenticationUrls = function(passportModule, expressModule,signInController, authenticationController, failureRedirectUrl, config) {

    if(config.twitter) {
        // Setting the twitter oauth routes
        expressModule.route('/auth/twitter')
            .get(passportModule.authenticate('twitter', {
                failureRedirect: failureRedirectUrl
            }), signInController);

        expressModule.route('/auth/twitter/callback')
            .get(passportModule.authenticate('twitter', {
                failureRedirect: failureRedirectUrl
            }), authenticationController);
    }

    if(config.facebook) {
        expressModule.route('/auth/facebook')
            .get(passportModule.authenticate('facebook', {
                scope: ['email', 'user_about_me'],
                failureRedirect: failureRedirectUrl
            }), signInController);

        expressModule.route('/auth/facebook/callback')
            .get(passportModule.authenticate('facebook', {
                failureRedirect: failureRedirectUrl
            }), authenticationController);
    }

    if(config.github) {
        // Setting the github oauth routes
        expressModule.route('/auth/github')
            .get(passportModule.authenticate('github', {
                failureRedirect: failureRedirectUrl
            }), signInController);

        expressModule.route('/auth/github/callback')
            .get(passportModule.authenticate('github', {
                failureRedirect: failureRedirectUrl
            }), authenticationController);
    }

    if(config.linkedin) {
        // Setting the linkedin oauth routes
        expressModule.route('/auth/linkedin')
            .get(passportModule.authenticate('linkedin', {
                failureRedirect: failureRedirectUrl,
                scope: ['r_emailaddress']
            }), signInController);

        expressModule.route('/auth/linkedin/callback')
            .get(passportModule.authenticate('linkedin', {
                failureRedirect: failureRedirectUrl
            }), authenticationController);
    }

    if(config.google) {
        // Setting the google oauth routes
        expressModule.route('/auth/google')
            .get(passportModule.authenticate('google', {
                failureRedirect: failureRedirectUrl,
                scope: [
                    'https://www.googleapis.com/auth/userinfo.profile',
                    'https://www.googleapis.com/auth/userinfo.email'
                ]
            }), signInController);

        expressModule.route('/auth/google/callback')
            .get(passportModule.authenticate('google', {
                failureRedirect: failureRedirectUrl
            }), authenticationController);
    }

    if(config.dropbox) {
        // Setting the dropbox auth routes
        expressModule.get('/auth/dropbox',
            passportModule.authenticate('dropbox-oauth2', {
                failureRedirect: failureRedirectUrl
            }), signInController);

        expressModule.get('/auth/dropbox/callback',
            passportModule.authenticate('dropbox-oauth2', {
                failureRedirect: failureRedirectUrl
            }), authenticationController);
    }

    if(config.amazon) {
        // Setting the amazon oauth routes
        expressModule.route('/auth/amazon')
            .get(passportModule.authenticate('amazon', {
                failureRedirect: failureRedirectUrl,
                scope: ['profile', 'postal_code']
            }), signInController);


        expressModule.route('/auth/amazon/callback')
            .get(passportModule.authenticate('amazon', {
                failureRedirect: failureRedirectUrl
            }), authenticationController);
    }

    if(config.bitbucket) {
        // Setting the bitbucket oauth routes
        expressModule.route('/auth/bitbucket')
            .get(passportModule.authenticate('bitbucket', {
                failureRedirect: failureRedirectUrl
            }), signInController);

        expressModule.route('/auth/bitbucket/callback')
            .get(passportModule.authenticate('bitbucket', {
                failureRedirect: failureRedirectUrl
            }), authenticationController);
    }

    if(config.evernote) {
        expressModule.get('/auth/evernote',
            passportModule.authenticate('evernote', {
                failureRedirect: failureRedirectUrl
            }), signInController);

        expressModule.get('/auth/evernote/callback',
            passportModule.authenticate('evernote', {
                failureRedirect: failureRedirectUrl
            }), authenticationController);
    }

    if(config.fitbit) {
        expressModule.get('/auth/fitbit',
            passportModule.authenticate('fitbit', {
                failureRedirect: failureRedirectUrl
            }), signInController);

        expressModule.get('/auth/fitbit/callback',
            passportModule.authenticate('fitbit', {
                failureRedirect: failureRedirectUrl
            }), authenticationController);
    }

    if(config.flickr) {
        expressModule.get('/auth/flickr',
            passportModule.authenticate('flickr', {
                failureRedirect: failureRedirectUrl
            }), signInController);

        expressModule.get('/auth/flickr/callback',
            passportModule.authenticate('flickr', {
                failureRedirect: failureRedirectUrl
            }), authenticationController);
    }

    if(config.foursquare) {
        expressModule.get('/auth/foursquare',
            passportModule.authenticate('foursquare', {
                failureRedirect: failureRedirectUrl
            }), signInController);

        expressModule.get('/auth/foursquare/callback',
            passportModule.authenticate('foursquare', {
                failureRedirect: failureRedirectUrl
            }), authenticationController);
    }

    if(config.instagram) {
        expressModule.get('/auth/instagram',
            passportModule.authenticate('instagram', {
                failureRedirect: failureRedirectUrl
            }), signInController);

        expressModule.get('/auth/instagram/callback',
            passportModule.authenticate('instagram', {
                failureRedirect: failureRedirectUrl
            }), authenticationController);
    }

    if(config.meetup) {
        expressModule.get('/auth/meetup',
            passportModule.authenticate('meetup', {
                failureRedirect: failureRedirectUrl
            }), signInController);

        expressModule.get('/auth/meetup/callback',
            passportModule.authenticate('meetup', {
                failureRedirect: failureRedirectUrl
            }), authenticationController);
    }

    if(config.spotify) {
        expressModule.get('/auth/spotify',
            passportModule.authenticate('spotify', {
                failureRedirect: failureRedirectUrl
            }), signInController);

        expressModule.get('/auth/spotify/callback',
            passportModule.authenticate('spotify', {
                failureRedirect: failureRedirectUrl
            }), authenticationController);
    }

    if(config.trello) {
        expressModule.get('/auth/trello',
            passportModule.authenticate('trello', {
                failureRedirect: failureRedirectUrl
            }), signInController);

        expressModule.get('/auth/trello/callback',
            passportModule.authenticate('trello', {
                failureRedirect: failureRedirectUrl
            }), authenticationController);
    }

    if(config.tumblr) {
        expressModule.get('/auth/tumblr',
            passportModule.authenticate('tumblr', {
                failureRedirect: failureRedirectUrl
            }), signInController);

        expressModule.get('/auth/tumblr/callback',
            passportModule.authenticate('tumblr', {
                failureRedirect: failureRedirectUrl
            }), authenticationController);
    }

    if(config.vimeo) {
        expressModule.get('/auth/vimeo',
            passportModule.authenticate('vimeo', {
                failureRedirect: failureRedirectUrl
            }), signInController);

        expressModule.get('/auth/vimeo/callback',
            passportModule.authenticate('vimeo', {
                failureRedirect: failureRedirectUrl
            }), authenticationController);
    }

    if(config.windowslive) {
        expressModule.get('/auth/windowslive',
            passportModule.authenticate('windowslive', { scope: ['wl.signin', 'wl.basic'] }, {
                failureRedirect: failureRedirectUrl
            }), signInController);

        expressModule.get('/auth/windowslive/callback',
            passportModule.authenticate('windowslive', {
                failureRedirect: failureRedirectUrl
            }), authenticationController);
    }

    if(config.wordpress) {
        expressModule.get('/auth/wordpress',
            passportModule.authenticate('wordpress', {
                failureRedirect: failureRedirectUrl
            }), signInController);

        expressModule.get('/auth/wordpress/callback',
            passportModule.authenticate('wordpress', {
                failureRedirect: failureRedirectUrl
            }), authenticationController);
    }

    if(config.yahoo) {
        expressModule.get('/auth/yahoo',
            passportModule.authenticate('yahoo', {
                failureRedirect: failureRedirectUrl
            }), signInController);

        expressModule.get('/auth/yahoo/callback',
            passportModule.authenticate('yahoo', {
                failureRedirect: failureRedirectUrl
            }), authenticationController);
    }
}

function checkCredentialsExists(provider, config){
    if(!config.clientID || !config.clientSecret){
        throw new Error(provider + ' missing credentials. Please provide client id and secret');
    }
}