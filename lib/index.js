var Promise = require('bluebird')
  , bcrypt = require('bcrypt-nodejs')
  , utility = require('@ftbl/utility');

module.exports = {
  encrypt: function(password) {
    var salt = bcrypt.genSaltSync(9)
      , hash = bcrypt.hashSync(password, salt);

    return { hash: hash, salt: salt }
  }

, authenticate: function(compareTo, password) {
    return bcrypt.compareSync(password, compareTo);
  }

, generateToken: function() {
    var token = utility.token(10)
      , salt = bcrypt.genSaltSync(6)
      , hash = bcrypt.hashSync(token, salt);

    return { token: token, hashedToken: hash };
  }

, generateAuthCode: function() {
    var code = (utility.random(899999) + 100000).toString()
      , salt = bcrypt.genSaltSync(6)
      , hash = bcrypt.hashSync(code, salt)

    return { authCode: code, hashedAuthCode: hash };
  }
};