'use strict';
module.exports = function(sequelize, DataTypes) {
  var AuthorizationCodes = sequelize.define('AuthorizationCodes', {
    code: DataTypes.STRING,
    redirectURI: DataTypes.STRING,
    clientId: DataTypes.STRING,
    userId: DataTypes.STRING
  }, {
    classMethods: {
      associate: function(models) {
        // associations can be defined here
      }
    }
  });
  return AuthorizationCodes;
};