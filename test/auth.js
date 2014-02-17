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
var secret = new Buffer("KeputHe5jy7UJST6HxSPCHYht5KyV5n9Ju73SrwmBJM=", 'base64')

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
describe('puzzle', function() {
	var TID = crypto.random_Int64()
	describe('making', function() {
		it('should not throw', function() {
			auth.makePuzzle(aliceK.public, bobK.public, secret, TID, 3)
		})
		it('is of the correct length', function() {
			var puzzle = auth.makePuzzle(aliceK.public, bobK.public, secret, TID, 3)
			assert.equal(puzzle.length, 121)
		})
	})
	describe('solving', function() {
		it('should not throw', function() {
			var puzzle = auth.makePuzzle(aliceK.public, bobK.public, secret, TID, 3)
			var puzzSol = auth.solvePuzzle(TID, puzzle)
		})
		it('can find a solution', function() {
			var puzzle = auth.makePuzzle(aliceK.public, bobK.public, secret, TID, 10)
			var puzzSol = auth.solvePuzzle(TID, puzzle)
			assert.notEqual(puzzSol, null)
		})
	})
	describe('solving', function() {
		it('should not throw', function() {
			var puzzle = auth.makePuzzle(aliceK.public, bobK.public, secret, TID, 3)
			var puzzSol = auth.solvePuzzle(TID, puzzle)
			var res = auth.checkPuzzle(aliceK.public, bobK.public, secret, TID, puzzSol)
		})
		it('should verify a correct solution', function() {
			var puzzle = auth.makePuzzle(aliceK.public, bobK.public, secret, TID, 10)
			var puzzSol = auth.solvePuzzle(TID, puzzle)
			var res = auth.checkPuzzle(aliceK.public, bobK.public, secret, TID, puzzSol)
			assert(res)
		})
		it('should not verify a wrong solution', function() {
			var puzzle = auth.makePuzzle(aliceK.public, bobK.public, secret, TID, 3)
			var puzzSol = auth.solvePuzzle(TID, puzzle)
			puzzSol[80] = 42
			var res = auth.checkPuzzle(aliceK.public, bobK.public, secret, TID, puzzSol)
			assert(!res)
		})
		it('should not verify a solution to the wrong server', function() {
			var puzzle = auth.makePuzzle(bobK.public, bobK.public, secret, TID, 3)
			var puzzSol = auth.solvePuzzle(TID, puzzle)
			var res = auth.checkPuzzle(aliceK.public, bobK.public, secret, TID, puzzSol)
			assert(!res)
		})
		it('should not verify a solution to the wrong client', function() {
			var puzzle = auth.makePuzzle(aliceK.public, aliceK.public, secret, TID, 3)
			var puzzSol = auth.solvePuzzle(TID, puzzle)
			var res = auth.checkPuzzle(aliceK.public, bobK.public, secret, TID, puzzSol)
			assert(!res)
		})
	})
})