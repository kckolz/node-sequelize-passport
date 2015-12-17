'use strict';
module.exports = function(sequelize, DataTypes) {
  var AccessTokens = sequelize.define('AccessTokens', {
    token: DataTypes.STRING(1234),
    userId: DataTypes.STRING,
    clientId: DataTypes.STRING
  }, {
    classMethods: {
      associate: function(models) {
        // associations can be defined here
      }
    }
  });
  return AccessTokens;
};