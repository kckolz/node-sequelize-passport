/**
 * Module dependencies.
 */
 var oauth2orize = require('oauth2orize'),
 passport = require('passport'),
 login = require('connect-ensure-login'),
 models = require('./models'),
 utils = require('./utils'),
 bcrypt = require('bcrypt');

// create OAuth 2.0 server
var server = oauth2orize.createServer();

// Register serialialization and deserialization functions.
//
// When a client redirects a user to user authorization endpoint, an
// authorization transaction is initiated.  To complete the transaction, the
// user must authenticate and approve the authorization request.  Because this
// may involve multiple HTTP request/response exchanges, the transaction is
// stored in the session.
//
// An application must supply serialization functions, which determine how the
// client object is serialized into the session.  Typically this will be a
// simple matter of serializing the client's ID, and deserializing by finding
// the client by ID from the database.

server.serializeClient(function(client, done) {
  return done(null, client.id);
});

server.deserializeClient(function(id, done) {
  models.Clients.findById(id).then(function(client) {
    return done(null, client);
  }, function(error) {
    return done(err); 
  });
});

// Register supported grant types.
//
// OAuth 2.0 specifies a framework that allows users to grant client
// applications limited access to their protected resources.  It does this
// through a process of the user granting access, and the client exchanging
// the grant for an access token.

// Grant authorization codes.  The callback takes the `client` requesting
// authorization, the `redirectURI` (which is used as a verifier in the
// subsequent exchange), the authenticated `user` granting access, and
// their response, which contains approved scope, duration, etc. as parsed by
// the application.  The application issues a code, which is bound to these
// values, and will be exchanged for an access token.

server.grant(oauth2orize.grant.code(function(client, redirectURI, user, ares, done) {
  var code = utils.uid(16);
  models.AuthorizationCodes.create({
    code: code,
    clientId: client.id,
    redirectURI: redirectURI,
    userId: user.id
  }).then(function(authorizationCode) {
    done(null, authorizationCode);
  });
}));

// Exchange authorization codes for access tokens.  The callback accepts the
// `client`, which is exchanging `code` and any `redirectURI` from the
// authorization request for verification.  If these values are validated, the
// application issues an access token on behalf of the user who authorized the
// code.

server.exchange(oauth2orize.exchange.code(function(client, code, redirectURI, done) {
  models.AuthorizationCodes.findOne({ where: {code: code} }).then(function(authorizationCode) {
    if (client.id !== authCode.clientID) { return done(null, false); }
    if (redirectURI !== authCode.redirectURI) { return done(null, false); }

    models.AuthorizationCodes.destroy({ where: {code: code} }).then(function() {
      var token = utils.uid(256);
      models.AccessTokens.create({token: token, clientId: client.id, userId: authCode.userID}).then(function(token) {
        done(null, token);
      })
    })
  });
}));

// user authorization endpoint
//
// `authorization` middleware accepts a `validate` callback which is
// responsible for validating the client making the authorization request.  In
// doing so, is recommended that the `redirectURI` be checked against a
// registered value, although security requirements may vary accross
// implementations.  Once validated, the `done` callback must be invoked with
// a `client` instance, as well as the `redirectURI` to which the user will be
// redirected after an authorization decision is obtained.
//
// This middleware simply initializes a new authorization transaction.  It is
// the application's responsibility to authenticate the user and render a dialog
// to obtain their approval (displaying details about the client requesting
// authorization).  We accomplish that here by routing through `ensureLoggedIn()`
// first, and rendering the `dialog` view. 

exports.authorization = [
  login.ensureLoggedIn(),
  server.authorization(function(clientID, redirectURI, done) {

    models.Clients.findOne({ 
      where: {clientId: clientId} 
    }).then(function(client) {
      if(!client) return done(null, false);
      return done(null, client, redirectURI);
    }).catch(function(error) {
      return done(error);
    });

    db.clients.findByClientId(clientID, function(err, client) {
      if (err) { return done(err); }
        // WARNING: For security purposes, it is highly advisable to check that
        //          redirectURI provided by the client matches one registered with
        //          the server.  For simplicity, this example does not.  You have
        //          been warned.
        return done(null, client, redirectURI);
      });
  }),
  function(req, res) {
    res.render('decision', { transactionID: req.oauth2.transactionID, user: req.user, client: req.oauth2.client })
  }
]

// user decision endpoint
//
// `decision` middleware processes a user's decision to allow or deny access
// requested by a client application.  Based on the grant type requested by the
// client, the above grant middleware configured above will be invoked to send
// a response.

exports.decision = [
  login.ensureLoggedIn(),
  server.decision()
];


// PASSWORD GRANT TYPE
// Exchange user id and password for access tokens.  The callback accepts the
// `client`, which is exchanging the user's name and password from the
// authorization request for verification. If these values are validated, the
// application issues an access token on behalf of the user who authorized the code.

server.exchange(oauth2orize.exchange.password(function(client, username, password, scope, done) {
  models.Clients.findOne({ 
    where: {clientId: client.dataValues.clientId} 
  }).then(function(localClient) {
    if(localClient === null) return done(null, false);
    if(localClient.clientSecret !== client.clientSecret) return done(null, false);
    models.Athletes.findOne({ where: {userName: username} }).then(function(athlete) {
      if (!athlete) return done(null, false);
      bcrypt.compare(password, athlete.dataValues.password, function (err, res) {
        if (!res) return done(null, false);
        var token = utils.uid(256);
        models.AccessTokens.create({
          token: token,
          userId: athlete.dataValues.id,
          clientId: client.dataValues.id
        }).then(function(accessToken) {
          return done(null, token);
        }).catch(function(error) {
          return done(error);
        })
      })
    }).catch(function(error) {
      return done(error);
    });
  }).catch(function(error) {
    return done(error);
  });
}));

// CLIENT CREDENTIAL GRANT TYPE
// Exchange the client id and password/secret for an access token.  The callback accepts the
// `client`, which is exchanging the client's id and password/secret from the
// authorization request for verification. If these values are validated, the
// application issues an access token on behalf of the client who authorized the code.

server.exchange(oauth2orize.exchange.clientCredentials(function(client, scope, done) {

  models.Clients.findOne({ 
    where: {clientId: client.dataValues.clientId} 
  }).then(function(localClient) {
    if(localClient === null) return done(null, false);
    if(localClient.clientSecret !== client.clientSecret) return done(null, false);
    var token = utils.uid(256);
    models.AccessTokens.create({
      token: token,
      userId: athlete.dataValues.id,
      clientId: client.dataValues.id
    }).then(function(accessToken) {
      return done(null, token);
    }).catch(function(error) {
      return done(error);
    })
  }).catch(function(error) {
    return done(error);
  });
}));

// token endpoint
//
// `token` middleware handles client requests to exchange authorization grants
// for access tokens.  Based on the grant type being exchanged, the above
// exchange middleware will be invoked to handle the request.  Clients must
// authenticate when making requests to this endpoint.

exports.token = [
  passport.authenticate(['basic', 'oauth2-client-password'], { session: false }),
  server.token(),
  server.errorHandler()
];
