'use strict';

var epilogue = require('epilogue'),
    db = require('../models');

var initialize = function(app) {
  epilogue.initialize({
    app: app,
    base: '/api/1',
    sequelize: db.sequelize
  });

  return {
    clientResource: require('./clients')
  };
};

module.exports = {
  initialize: initialize
};