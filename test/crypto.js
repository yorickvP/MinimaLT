/* global describe */
/* global it */
var assert = require("assert")
var crypto = require('../crypto.js')

describe('crypto', function(){
	describe('.generate_nonce', function(){
		it('should generate proper nonces', function(){
			assert.equal(crypto.generate_nonce(true, 1391776785060).toOctetString(), '0000028818b8c549')
		})
	})
})
