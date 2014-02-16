/* global describe */
/* global it */
var assert = require("assert")
var crypto = require('../crypto.js')
var auth = require('../auth.js')

var aliceK = {
	public: new Buffer("QdhMKiMKIAeAJsdhpyIoWThdbMIqkIDbzP+SYb6JcV0=", 'base64'),
	private: new Buffer("H0D8ktokFpR1CXnubPWC8tXX0o4YM13gWrxU0FYOD1M=", 'base64')
}
var bobK = {
	public: new Buffer("sZ+uMFsK4ZNChDZRGZshFYhK7IP/g82URlRlddnR03I=", 'base64'),
	private: new Buffer("Umd2iCLuYk1I/OFexcp5y9YCy39MIVelFlVpkfIu+Mc=", 'base64')
}

describe('auth', function() {
	it('should not throw', function() {
		var authMsg = auth.makeUserAuth(aliceK, bobK.public)
		assert(auth.verifyUserAuth(authMsg, bobK, aliceK.public))
	})
	it('should not work on the wrong server', function() {
		var authMsg = auth.makeUserAuth(aliceK, crypto.make_keypair().public)
		assert(!auth.verifyUserAuth(authMsg, bobK, aliceK.public))
	})
	it('should not work from the wrong client', function() {
		var authMsg = auth.makeUserAuth(crypto.make_keypair(), bobK.public)
		assert(!auth.verifyUserAuth(authMsg, bobK, aliceK.public))
	})
})
