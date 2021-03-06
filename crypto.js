"use strict";
var nacl = require('js-nacl').instantiate()
var Int64 = require('./Int64.js')

var nonce_pad = new Buffer("minimaLT")

var crypto = {
	make_keypair: function() {
		var pair = nacl.crypto_box_keypair()
		return {public: pair.boxPk, private: pair.boxSk}
	},
	shared_secret: function(theirpub, mypriv) {
		return nacl.crypto_box_precompute(theirpub, mypriv).boxK
	},
	box: function(msgBin, nonceBin, secret) {
		if (!Buffer.isBuffer(msgBin))
			throw new Error("message should be a buffer")
		return nacl.crypto_box_precomputed(msgBin, nonceBin, {boxK: secret})
	},
	unbox: function(msgBin, nonceBin, secret) {
		// ommitting this check actually makes it throw
		// in a way that trashes its memory management
		// so all later results would be wrong
		if (!Buffer.isBuffer(msgBin))
			throw new Error("message should be a buffer")
		return nacl.crypto_box_open_precomputed(msgBin, nonceBin, {boxK: secret})
	},
	boxWithKeys: function(msgBin, nonceBin, theirpub, mypriv) {
		if (!Buffer.isBuffer(msgBin))
			throw new Error("message should be a buffer")
		return nacl.crypto_box(msgBin, nonceBin, theirpub, mypriv)
	},
	unboxWithKeys: function(msgBin, nonceBin, theirpub, mypriv) {
		if (!Buffer.isBuffer(msgBin))
			throw new Error("message should be a buffer")
		return nacl.crypto_box_open(msgBin, nonceBin, theirpub, mypriv)
	},
	secretUnbox: function(msgBin, nonceBin, secret) {
		if (!Buffer.isBuffer(msgBin))
			throw new Error("message should be a buffer")
		return nacl.crypto_secretbox_open(msgBin, nonceBin, secret)
	},
	secretBox: function(msgBin, nonceBin, secret) {
		if (!Buffer.isBuffer(msgBin))
			throw new Error("message should be a buffer")
		return nacl.crypto_secretbox(msgBin, nonceBin, secret)
	},
	make_nonce: function(TID, nonce) {
		var res = new Buffer(24)
		// the first 8 bytes spell minimaLT for now
		nonce_pad.copy(res)
		TID.getBuffer().copy(res, 8)
		nonce.getBuffer().copy(res, 16)
		return res
	},
	generate_nonce: function(is_client, date) {
		var x = new Int64(date)
		x.shiftLeft(1)
		if (is_client) x.buffer[x.offset+7] |= 1
		return x
	},
	random_Int64: function() {
		return new Int64(nacl.random_bytes(8))
	},
	random_UInt32: function() {
		return nacl.random_bytes(4).readUInt32BE(0)
	},
	random_nonce: function() {
		return nacl.crypto_box_random_nonce()
	},
	make_signing_keypair: function() {
		var pair = nacl.crypto_sign_keypair()
		return {public: pair.signPk, private: pair.signSk}
	},
	sign: function(msgBin, privKey) {
		if (!Buffer.isBuffer(msgBin))
			throw new Error("message should be a buffer")
		return nacl.crypto_sign(msgBin, privKey)
	},
	verify: function(msgBin, pubKey) {
		if (!Buffer.isBuffer(msgBin))
			throw new Error("message should be a buffer")
		return nacl.crypto_sign_open(msgBin, pubKey)
	},
	hashSecret: function(secret) {
		// XXX: should this be scrypt/PBKDF2 instead?
		return nacl.crypto_hash_sha256(secret)
	},
	hashPuzzle: function(r) {
		// TODO: this shoud *really* be scrypt.
		// thanks bitcoin.
		return nacl.crypto_hash_sha256(r)
	}
}

module.exports = crypto
