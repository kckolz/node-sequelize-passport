'use strict';

var epilogue = require('epilogue'),
bcrypt = require('bcrypt'),
models = require('../models');

var clientResource = epilogue.resource({
  model: models.Clients,
  endpoints: ['/clients', '/clients/:id']
});


// hash the secret before persisting
clientResource.create.write.before(function(req, res, context) {
  req.body.clientSecret = hashSecret(req.body.clientSecret);
  return context.continue;
});

function hashSecret(secret) {
  var salt = bcrypt.genSaltSync(10);
  return bcrypt.hashSync(secret, salt);  
}

module.exports = clientResource;