'use strict';
module.exports = function(sequelize, DataTypes) {
  var Clients = sequelize.define('Clients', {
    clientId: { type: DataTypes.STRING, allowNull: false },
    clientSecret: { type: DataTypes.STRING, allowNull: false }
  }, {
    classMethods: {
      associate: function(models) {
        // associations can be defined here
      }
    }
  });
  return Clients;
};