var chai = require('chai')
  , should = chai.should()
  , bcrypt = require('bcrypt-nodejs')
  , sut = require('../lib');

describe('When using the Authenticator service', function() {
  var suite = this;

  describe('When encrypting a password', function() {

    before(function() {
      var result = sut.encrypt('password');
      
      suite.hashedPassword = result.hash;
      suite.salt = result.salt;
    });

    it('should not return the same value', function() {
      suite.hashedPassword.should.not.equal('password');
    });

    it('should hash the password', function() {
      suite.hashedPassword.should.equal(bcrypt.hashSync('password', suite.salt));
    });

    describe('When authenticating with a valid password', function() {

      before(function() {
        suite.matches = sut.authenticate(suite.hashedPassword, 'password');
      });

      it('should succeed', function() {
        suite.matches.should.be.true;
      });
    });

    describe('When generating a token', function() {

      before(function() {
        var result = sut.generateToken();
        suite.token = result.token;
        suite.hashedToken = result.hashedToken;
      });

      it('should return a token and a hash of that token', function() {
        suite.token.should.exist;
        suite.hashedToken.should.not.equal(suite.token);
      });

      describe('When validating the token', function() {

        before(function() {
          suite.matches = sut.authenticate(suite.hashedToken, suite.token);
        });

        it('should succeed', function() {
          suite.matches.should.be.true;
        });

      });

      describe('When validating an invalid token', function() {

        before(function() {
          suite.matches = sut.authenticate(suite.hashedToken, 'invalid');
        });

        it('should fail', function() {
          suite.matches.should.be.false;
        });

      });
    });

    describe('When generating an authcode', function() {

      before(function() {
        var result = sut.generateAuthCode();
        suite.authCode = result.authCode;
        suite.hashedAuthCode = result.hashedAuthCode;
      });

      it('should return an authcode and a hash of that authcode', function() {
        suite.authCode.should.exist;
        suite.hashedAuthCode.should.not.equal(suite.token);
      });

      it('should return a numeric authcode', function() {
        suite.authCode.should.be.a.number;
      });

      it('should return an authcode with the correct length', function() {
        suite.authCode.should.have.length(6);
      });

      describe('When validating the authcode', function() {

        before(function() {
          suite.matches = sut.authenticate(suite.hashedAuthCode, suite.authCode);
        });

        it('should succeed', function() {
          suite.matches.should.be.true;
        });

      });

      describe('When validating an invalid code', function() {

        before(function() {
          suite.matches = sut.authenticate(suite.hashedAuthCode, 'invalid');
        });

        it('should fail', function() {
          suite.matches.should.be.false;
        });

      });
    });

    describe('When authenticating with an invalid password', function() {
      before(function() {
        suite.matches = sut.authenticate(suite.hashedPassword, 'invalid');
      });

      it('should not match', function() {
        suite.matches.should.be.false;
      });
    });
  });

});