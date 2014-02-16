var crypto = require('./crypto')
var assert = require('assert')

function memcmp(a, b) {
	if (a.length != b.length) return false
	for (var i = 0; i < a.length; i++) {
		if (a[i] != b[i]) return false
	}
	return true
}

module.exports.makeUserAuth = function(myboxing, theirboxing) {
	var nonce = crypto.random_nonce()
	var boxed_S = crypto.boxWithKeys(theirboxing, nonce,
		theirboxing, myboxing.private)
	return Buffer.concat([nonce, boxed_S])
}
module.exports.verifyUserAuth = function(msg, myboxing, theirboxing) {
	var nonce = msg.slice(0, 24), unboxed_S
	try {
		unboxed_S = crypto.unboxWithKeys(msg.slice(24), nonce, theirboxing, myboxing.private)
	} catch(e) {
		return false
	}

	return memcmp(unboxed_S, myboxing.public)
}
