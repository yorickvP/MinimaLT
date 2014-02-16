/* global describe */
/* global it */
var assert = require("assert")
var crypto = require('../crypto.js')
var Int64 = require('../Int64.js')

var aliceK = {
	public: new Buffer("QdhMKiMKIAeAJsdhpyIoWThdbMIqkIDbzP+SYb6JcV0=", 'base64'),
	private: new Buffer("H0D8ktokFpR1CXnubPWC8tXX0o4YM13gWrxU0FYOD1M=", 'base64')
}
var bobK = {
	public: new Buffer("sZ+uMFsK4ZNChDZRGZshFYhK7IP/g82URlRlddnR03I=", 'base64'),
	private: new Buffer("Umd2iCLuYk1I/OFexcp5y9YCy39MIVelFlVpkfIu+Mc=", 'base64')
}
var signK = {
	public: new Buffer("Tvpur+Tq0mPQFmlJkl6JRswFAjmmf3vkcpZl8/4irxk=", 'base64'),
	private: new Buffer("9JEA8kRsuG+OdHhKo1ywvuDt5tqtyCZxsIx5BhI6DV5O+m6v5OrSY9AWaUmSXolGzAUCOaZ/e+RylmXz/iKvGQ==", 'base64')
}
var secret = new Buffer("KeputHe5jy7UJST6HxSPCHYht5KyV5n9Ju73SrwmBJM=", 'base64')
var encrypted_hello = new Buffer("0gg0FLPlbFA7x7IvYZezFR+OjXDm", "base64")
var signed_hello = new Buffer("6g6nLajpD/AFHdMhl+Xvjc6fGDPtBj5EMn7UUJfMkjvGWDCJHd8JFs6nB2UuCPsg2nAo6+oFUD7N2qqx2mqEC2hlbGxv", 'base64')
var nonce = new Buffer(24)
nonce.fill(42)
describe('crypto', function(){
	describe('.make_keypair', function(){
		it('should be buffers', function(){
			var keypair = crypto.make_keypair()
			assert(Buffer.isBuffer(keypair.public))
			assert(Buffer.isBuffer(keypair.private))
		})
		it('should be the correct length', function(){
			var keypair = crypto.make_keypair()
			assert.equal(keypair.public.length, 32)
			assert.equal(keypair.private.length, 32)
		})
	})
	describe('.shared_secret', function(){
		it('should compute the correct secret', function(){
			assert.deepEqual(crypto.shared_secret(aliceK.public, bobK.private), secret)
		})
		it('should be the same both ways', function(){
			assert.deepEqual(crypto.shared_secret(aliceK.public, bobK.private),
				crypto.shared_secret(bobK.public, aliceK.private))
		})
		it('should be a buffer', function(){
			assert(Buffer.isBuffer(crypto.shared_secret(aliceK.public, bobK.private)))
		})
		it('should error on wrong argument #1', function(){
			assert.throws(function(){
				crypto.shared_secret("aliceK.public", bobK.private)
			})
			assert.throws(function(){
				crypto.shared_secret(10, bobK.private)
			})
			assert.throws(function(){
				crypto.shared_secret(new Buffer(10), bobK.private)
			})
		})
		it('should error on wrong argument #2', function(){
			assert.throws(function(){
				crypto.shared_secret(aliceK.public, "bobK.private")
			})
			assert.throws(function(){
				crypto.shared_secret(aliceK.public, 10)
			})
			assert.throws(function(){
				crypto.shared_secret(aliceK.public, new Buffer(10))
			})
		})
	})
	describe('.box', function(){
		it('should be a buffer', function(){
			assert(Buffer.isBuffer(crypto.box(new Buffer("hello"), nonce, secret)))
		})
		it('should compute the correct message', function(){
			assert.deepEqual(crypto.box(new Buffer("hello"), nonce, secret), encrypted_hello)
		})
		it('should error on wrong argument #1', function(){
			var m = new Buffer('hello'), n = nonce, s = secret
			m = "hello"
			assert.throws(function(){
				crypto.box(m, n, s)
			})
			m = 10
			assert.throws(function(){
				crypto.box(m, n, s)
			})
			// XXX: allow empty string to work?
		})
		it('should error on wrong argument #2', function(){
			var m = new Buffer('hello'), n = nonce, s = secret
			n = "nonce"
			assert.throws(function(){
				crypto.box(m, n, s)
			})
			n = 10
			assert.throws(function(){
				crypto.box(m, n, s)
			})
			n = new Buffer(1)
			assert.throws(function(){
				crypto.box(m, n, s)
			})
		})
		it('should error on wrong argument #3', function(){
			var m = new Buffer('hello'), n = nonce, s = secret
			s = "secret"
			assert.throws(function(){
				crypto.box(m, n, s)
			})
			s = 10
			assert.throws(function(){
				crypto.box(m, n, s)
			})
			s = new Buffer(10)
			assert.throws(function(){
				crypto.box(m, n, s)
			})
		})
	})
	describe('.unbox', function(){
		it('should be a buffer', function(){
			assert(Buffer.isBuffer(crypto.unbox(encrypted_hello, nonce, secret)))
		})
		it('should decrypt a message', function(){
			var nonce = new Buffer(24)
			nonce.fill(42)
			var secret = new Buffer("KeputHe5jy7UJST6HxSPCHYht5KyV5n9Ju73SrwmBJM=", 'base64')
			var encrypted_hello = new Buffer("0gg0FLPlbFA7x7IvYZezFR+OjXDm", "base64")
			assert.deepEqual(crypto.unbox(encrypted_hello, nonce, secret), new Buffer("hello"))
		})
		it('should error on wrong argument #1', function(){
			var m = encrypted_hello, n = nonce, s = secret
			m = "encrypted_hello"
			assert.throws(function(){
				crypto.unbox(m, n, s)
			})
			m = 10
			assert.throws(function(){
				crypto.unbox(m, n, s)
			})
			// XXX: allow empty string to work?
		})
		it('should error on wrong argument #2', function(){
			var m = encrypted_hello, n = nonce, s = secret
			n = "nonce"
			assert.throws(function(){
				crypto.unbox(m, n, s)
			})
			n = 10
			assert.throws(function(){
				crypto.unbox(m, n, s)
			})
			n = new Buffer(1)
			assert.throws(function(){
				crypto.unbox(m, n, s)
			})
		})
		it('should error on wrong argument #3', function(){
			var m = encrypted_hello, n = nonce, s = secret
			s = "secret"
			assert.throws(function(){
				crypto.unbox(m, n, s)
			})
			s = 10
			assert.throws(function(){
				crypto.unbox(m, n, s)
			})
			s = new Buffer(10)
			assert.throws(function(){
				crypto.unbox(m, n, s)
			})
		})
	})
	describe('.boxWithKeys', function(){
		it('should be a buffer', function(){
			assert(Buffer.isBuffer(crypto.boxWithKeys(new Buffer("hello"), nonce, aliceK.public, bobK.private)))
		})
		it('should compute the correct message', function(){
			assert.deepEqual(crypto.boxWithKeys(new Buffer("hello"), nonce, aliceK.public, bobK.private), encrypted_hello)
		})
		it('should error on wrong argument #1', function(){
			var m = new Buffer('hello'), n = nonce, p = aliceK.public, s = bobK.private
			m = "hello"
			assert.throws(function(){
				crypto.boxWithKeys(m, n, p, s)
			})
			m = 10
			assert.throws(function(){
				crypto.boxWithKeys(m, n, p, s)
			})
			// XXX: allow empty string to work?
		})
		it('should error on wrong argument #2', function(){
			var m = new Buffer('hello'), n = nonce, p = aliceK.public, s = bobK.private
			n = "nonce"
			assert.throws(function(){
				crypto.boxWithKeys(m, n, p, s)
			})
			n = 10
			assert.throws(function(){
				crypto.boxWithKeys(m, n, p, s)
			})
			n = new Buffer(1)
			assert.throws(function(){
				crypto.boxWithKeys(m, n, p, s)
			})
		})
		it('should error on wrong argument #3', function(){
			var m = new Buffer('hello'), n = nonce, p = aliceK.public, s = bobK.private
			p = "aliceK.public"
			assert.throws(function(){
				crypto.boxWithKeys(m, n, p, s)
			})
			p = 10
			assert.throws(function(){
				crypto.boxWithKeys(m, n, p, s)
			})
			p = new Buffer(10)
			assert.throws(function(){
				crypto.boxWithKeys(m, n, p, s)
			})
		})
		it('should error on wrong argument #4', function(){
			var m = new Buffer('hello'), n = nonce, p = aliceK.public, s = bobK.private
			s = "bobK.private"
			assert.throws(function(){
				crypto.boxWithKeys(m, n, p, s)
			})
			s = 10
			assert.throws(function(){
				crypto.boxWithKeys(m, n, p, s)
			})
			s = new Buffer(10)
			assert.throws(function(){
				crypto.boxWithKeys(m, n, p, s)
			})
		})
	})
	describe('.unboxWithKeys', function() {
		it('should be a buffer', function(){
			assert(Buffer.isBuffer(crypto.unboxWithKeys(encrypted_hello, nonce, aliceK.public, bobK.private)))
		})
		it('should decrypt a message', function(){
			assert.deepEqual(crypto.unboxWithKeys(encrypted_hello, nonce, aliceK.public, bobK.private), new Buffer("hello"))
		})
		it('should error on wrong argument #1', function(){
			var m = encrypted_hello, n = nonce, p = aliceK.public, s = bobK.private
			m = "encrypted_hello"
			assert.throws(function(){
				crypto.unboxWithKeys(m, n, p, s)
			})
			m = 10
			assert.throws(function(){
				crypto.unboxWithKeys(m, n, p, s)
			})
			// XXX: allow empty string to work?
		})
		it('should error on wrong argument #2', function(){
			var m = encrypted_hello, n = nonce, p = aliceK.public, s = bobK.private
			n = "nonce"
			assert.throws(function(){
				crypto.unboxWithKeys(m, n, p, s)
			})
			n = 10
			assert.throws(function(){
				crypto.unboxWithKeys(m, n, p, s)
			})
			n = new Buffer(1)
			assert.throws(function(){
				crypto.unboxWithKeys(m, n, p, s)
			})
		})
		it('should error on wrong argument #3', function(){
			var m = encrypted_hello, n = nonce, p = aliceK.public, s = bobK.private
			p = "aliceK.public"
			assert.throws(function(){
				crypto.unboxWithKeys(m, n, p, s)
			})
			p = 10
			assert.throws(function(){
				crypto.unboxWithKeys(m, n, p, s)
			})
			p = new Buffer(10)
			assert.throws(function(){
				crypto.unboxWithKeys(m, n, p, s)
			})
		})
		it('should error on wrong argument #4', function(){
			var m = encrypted_hello, n = nonce, p = aliceK.public, s = bobK.private
			s = "bobK.private"
			assert.throws(function(){
				crypto.unboxWithKeys(m, n, p, s)
			})
			s = 10
			assert.throws(function(){
				crypto.unboxWithKeys(m, n, p, s)
			})
			s = new Buffer(10)
			assert.throws(function(){
				crypto.unboxWithKeys(m, n, p, s)
			})
		})
	})
	describe('.make_nonce', function(){
		it('should be a buffer', function(){
			assert(Buffer.isBuffer(crypto.make_nonce(new Int64(123456, 123456), new Int64(new Buffer('0011aabbccddeeff')))))
		})
		it('should compose the correct nonces', function(){
			assert.deepEqual(crypto.make_nonce(
				new Int64(new Buffer('0011223300112233', 'hex')),
				new Int64(new Buffer('0011223300112233', 'hex'))),
				new Buffer('6d696e696d614c5400112233001122330011223300112233', 'hex'))
		})
	})
	describe('.generate_nonce', function(){
		it('should generate proper nonces', function(){
			assert.equal(crypto.generate_nonce(true, 1391776785060).toOctetString(), '0000028818b8c549')
		})
	})
	describe('.random_Int64', function(){
		it('should not be zero', function(){
			assert.notEqual(crypto.random_Int64.valueOf(), 0)
		})
	})
	describe('.random_nonce', function(){
		it('should be a buffer', function() {
			assert(Buffer.isBuffer(crypto.random_nonce()))
		})
		it('should not be zero', function(){
			var b = new Buffer(24)
			b.fill(0)
			assert.notDeepEqual(crypto.random_nonce(), b)
		})
		it('should be 24 bytes long', function() {
			assert.equal(crypto.random_nonce().length, 24)
		})
	})
	describe('.random_UInt32', function(){
		it('should not be zero', function(){
			assert.notEqual(crypto.random_UInt32(), 0)
		})
		it('should be in range', function(){
			assert.ok(crypto.random_UInt32() > 0)
			assert.ok(crypto.random_UInt32() < (1<<30)*4)
		})
	})
//	sign: function(msgBin, privKey) {
//	verify: function(msgBin, pubKey) {
	describe('.make_signing_keypair', function() {
		it('should be buffers', function(){
			var keypair = crypto.make_signing_keypair()
			assert(Buffer.isBuffer(keypair.public))
			assert(Buffer.isBuffer(keypair.private))
		})
		it('should be the correct length', function(){
			var keypair = crypto.make_signing_keypair()
			assert.equal(keypair.public.length, 32)
			assert.equal(keypair.private.length, 64)
		})
	})
	describe('.sign', function() {
		it('should be a buffer', function(){
			assert(Buffer.isBuffer(crypto.sign(new Buffer("hello"), signK.private)))
		})
		it('should compute the correct message', function(){
			assert.deepEqual(crypto.sign(new Buffer("hello"), signK.private), signed_hello)
		})
		it('should error on wrong argument #1', function(){
			var m = new Buffer('hello'), s = signK.private
			m = "hello"
			assert.throws(function(){
				crypto.sign(m, s)
			})
			m = 10
			assert.throws(function(){
				crypto.sign(m, s)
			})
			// XXX: allow empty string to work?
		})
		it('should error on wrong argument #2', function(){
			var m = new Buffer('hello'), s = signK.private
			s = "secret"
			assert.throws(function(){
				crypto.sign(m, s)
			})
			s = 10
			assert.throws(function(){
				crypto.sign(m, s)
			})
			s = new Buffer(1)
			assert.throws(function(){
				crypto.sign(m, s)
			})
		})
	})
	describe('.verify', function() {
		it('should be a buffer', function(){
			assert(Buffer.isBuffer(crypto.verify(signed_hello, signK.public)))
		})
		it('should compute the correct message', function(){
			assert.deepEqual(crypto.verify(signed_hello, signK.public), new Buffer('hello'))
		})
		it('should error on wrong argument #1', function(){
			var m = signed_hello, s = signK.public
			m = "hello"
			assert.throws(function(){
				crypto.verify(m, s)
			})
			m = 10
			assert.throws(function(){
				crypto.verify(m, s)
			})
			// XXX: allow empty string to work?
		})
		it('should error on wrong argument #2', function(){
			var m = signed_hello, s = signK.public
			s = "public"
			assert.throws(function(){
				crypto.verify(m, s)
			})
			s = 10
			assert.throws(function(){
				crypto.verify(m, s)
			})
			s = new Buffer(1)
			assert.throws(function(){
				crypto.verify(m, s)
			})
		})
		it('should error on the wrong key', function() {
			var false_hello = crypto.sign(new Buffer('hello'), crypto.make_signing_keypair().private)
			assert.equal(crypto.verify(false_hello, signK.public), null)
		})
	})
})
