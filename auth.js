/**
 * Module dependencies.
 */
var passport = require('passport')
  , LocalStrategy = require('passport-local').Strategy
  , BasicStrategy = require('passport-http').BasicStrategy
  , ClientPasswordStrategy = require('passport-oauth2-client-password').Strategy
  , BearerStrategy = require('passport-http-bearer').Strategy
  , models = require('./models')
  , bcrypt = require('bcrypt');


/**
 * LocalStrategy
 *
 * This strategy is used to authenticate users based on a username and password.
 * Anytime a request is made to authorize an application, we must ensure that
 * a user is logged in before asking them to approve the request.
 */
passport.use(new LocalStrategy(
  function(userName, password, done) {
    models.Athletes.findOne({ where: {userName: userName} }).then(function(athlete) {
      if (!athlete) { return done(null, false); }
      bcrypt.compare(password, athlete.dataValues.password, function (err, res) {
        if (!res) return done(null, false)
          return done(null, athlete);
      })
    }).catch(function(error) {
      return done(error);
    });
  }
));

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  models.Athletes.findById(id).then(function(athlete) {
    done(null, athlete);
  })
});


/**
 * BasicStrategy & ClientPasswordStrategy
 *
 * These strategies are used to authenticate registered OAuth clients.  They are
 * employed to protect the `token` endpoint, which consumers use to obtain
 * access tokens.  The OAuth 2.0 specification suggests that clients use the
 * HTTP Basic scheme to authenticate.  Use of the client password strategy
 * allows clients to send the same credentials in the request body (as opposed
 * to the `Authorization` header).  While this approach is not recommended by
 * the specification, in practice it is quite common.
 */
passport.use(new BasicStrategy(
  function(clientId, clientSecret, done) {
    models.Clients.findOne({ 
      where: {clientId: clientId} 
    }).then(function(client) {
      if(!client) return done(null, false);
      if (!bcrypt.compareSync(clientSecret, client.dataValues.clientSecret)) return done(null, false);
      return done(null, client);
    }).catch(function(error) {
      return done(error);
    });
  }
));

passport.use(new ClientPasswordStrategy(
  function(clientId, clientSecret, done) {
    models.Clients.findOne({ 
      where: {clientId: clientId} 
    }).then(function(client) {
      if(!client) return done(null, false);
      if (!bcrypt.compareSync(clientSecret, client.dataValues.clientSecret)) return done(null, false);
      return done(null, client);
    }).catch(function(error) {
      return done(error);
    });
  }
));

/**
 * BearerStrategy
 *
 * This strategy is used to authenticate users based on an access token (aka a
 * bearer token).  The user must have previously authorized a client
 * application, which is issued an access token to make requests on behalf of
 * the authorizing user.
 */
passport.use(new BearerStrategy(
  function(token, done) {
    models.AccessTokens.findOne({where: {token: token}})
    .then(function(token) {
      models.Athletes.findById(token.userId)
      .then(function(athlete) {
        return done(null, athlete);
      }).catch(function(error) {
        return done(error);
      });
    }).catch(function(error) {
      return done(error);
    });
  }
));
