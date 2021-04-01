'use strict';

// N.B. Encoding problems are being caused by jsonwebtoken
// https://github.com/auth0/node-jsonwebtoken/pull/59

var app = require('express')(),
    cookieParser = require('cookie-parser'),
    jwt = require('jsonwebtoken'),
    passport = require('passport'),
    OAuth2Strategy = require('passport-oauth').OAuth2Strategy,
    axios = require('axios').default,
    https = require('https');


// ADFS Configuration
const adfsMetadataUrl = "https://example.adfs.com/adfs/.well-known/openid-configuration",
    adfsClientID = "example_client_id",
    adfsClientSecret = "example_client_secret",
    adfsRedirectUrl = "http://example.application.com/callback",
    adfsResourceID = "example_resource_id";


//console.warn('Not verifying HTTPS certificates');
https.globalAgent.options.rejectUnauthorized = false;

function validateAccessToken(accessToken, adfsSigningPublicKey) {
    var payload = null;
    try {
        payload = jwt.verify(accessToken, adfsSigningPublicKey);
    }
    catch (e) {
        console.warn('Dropping unverified accessToken', e);
    }
    return payload;
}

async function getAdfsMetadata(url) {
    const response = await axios.get(url);
    //console.log(response.data);
    return response.data;
}

async function getAdfsPublicKey(url) {
    const response = await axios.get(url);
    //console.log(response.data);
    var key = "-----BEGIN CERTIFICATE-----\n" + response.data.keys[0].x5c[0] + "\n-----END CERTIFICATE-----";
    return key;
}

const main = async () => {

    var adfsMetadata = await getAdfsMetadata(adfsMetadataUrl);
    var publicKey = await getAdfsPublicKey(adfsMetadata.jwks_uri);

    // Default response_type : 'code'
    // Default grant_type : 'authorization_code'
    var strategy = new OAuth2Strategy({
        authorizationURL: adfsMetadata.authorization_endpoint,
        tokenURL: adfsMetadata.token_endpoint,
        clientID: adfsClientID, // This is just a UID I generated and registered
        clientSecret: adfsClientSecret, // This is ignored but required by the OAuth2Strategy
        callbackURL: adfsRedirectUrl,
        scope: 'allatclaims'
    },
        function (accessToken, refreshToken, profile, done) {
            if (refreshToken) {
                console.log('Received but ignoring refreshToken (truncated)', refreshToken.substr(0, 25));
            } else {
                console.log('No refreshToken received');
            }
            done(null, profile);
        });
    strategy.authorizationParams = function (options) {
        return {
            resource: adfsResourceID // An identifier corresponding to the RPT
        };
    };

    strategy.userProfile = function (accessToken, done) {
        done(null, accessToken);
    };
    passport.use('provider', strategy);
    passport.serializeUser(function (user, done) {
        done(null, user);
    });
    passport.deserializeUser(function (user, done) {
        done(null, user);
    });

    // Configure express app
    app.use(cookieParser());
    app.use(passport.initialize());

    app.get('/login', passport.authenticate('provider'));
    app.get('/callback', passport.authenticate('provider'), function (req, res) {
        // Beware XSRF...
        res.cookie('accessToken', req.user);
        res.redirect('/');
    });
    app.get('/', function (req, res) {
        req.user = validateAccessToken(req.cookies['accessToken'], publicKey);
        res.send(
            !req.user ? '<h1>Example NodeJS Authentication with "ADFS OpenID Connect".</h1><a href="/login">Log In</a><br/>' : '<a href="/logout">Log Out</a><br/>' +
                '<h1>Authentication sucess.</h1><span>User info: </span><pre>' + JSON.stringify(req.user, null, 2) + '</pre>');
    });
    app.get('/logout', function (req, res) {
        res.clearCookie('accessToken');
        res.redirect(adfsMetadata.end_session_endpoint + '?post_logout_redirect_uri=' + adfsRedirectUrl);
    });

    app.listen(3000);
    console.log('Express server started on port 3000');
}

main();