var nacl = require('js-nacl').instantiate()
var Int64 = require('./Int64.js')



var crypto = (function() {
	"use strict";
	return {
		make_keypair: function() {
			var pair = nacl.crypto_box_keypair()
			return {public: pair.boxPk, secret: pair.boxSk}
		},
		shared_secret: function(theirpub, mysecret) {
			return nacl.crypto_box_precompute(theirpub, mysecret).boxK
		},
		box: function(msgBin, nonceBin, secret) {
			return nacl.crypto_box_precomputed(msgBin, nonceBin, {boxK: secret})
		},
		unbox: function(msgBin, nonceBin, secret) {
			return nacl.crypto_box_open_precomputed(msgBin, nonceBin, {boxK: secret})
		},
		make_nonce: function(TID, nonce) {
			var res = new Buffer(24)
			// the first 8 bytes spell minimaLT for now
			void (new Buffer("minimaLT")).copy(res)
			TID.copy(res, 8)
			nonce.copy(res, 16)
			return res
		},
		generate_nonce: function(is_client, date) {
			var x = new Int64(date)
			x.shiftLeft(1)
			if (is_client) x.buffer[x.offset+7] |= 1
			return x
		}
	}
})()

module.exports = crypto
