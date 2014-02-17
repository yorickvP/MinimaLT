var crypto = require('./crypto')
var Int64 = require('./Int64')
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
module.exports.makePuzzle = function(serverKey, clientKey, k, TID, w) {
	var n = new Int64(Date.now())
	var nonce = crypto.make_nonce(TID, n)
	var r = crypto.secretBox(Buffer.concat([serverKey, clientKey]), nonce, k)
	var q = new Buffer(r)
	// zero the rightmost w bits
	//q[q.length - 1] = (q[q.length - 1] >> w) << w
	zero_bits(q, w, 0)
	var H_r = crypto.hashPuzzle(r)
	return Buffer.concat([q, H_r, new Buffer([w]), n.getBuffer()])
}
module.exports.checkPuzzle = function(serverKey, clientKey, k, TID, puzzleResp) {
	var r = puzzleResp.slice(0, puzzleResp.length - 8)
	var n_ = new Int64(puzzleResp, puzzleResp.length - 8)
	if (Date.now() - n_ > 3e5) {
		// too long in the past
		return false
	}
	var nonce = crypto.make_nonce(TID, n_)
	var r_unb
	try {
		r_unb = crypto.secretUnbox(r, nonce, k)
	} catch(e) {
		return false
	}
	if (r_unb.length != 64) return false
	var S_ = r_unb.slice(0, 32)
	var C_ = r_unb.slice(32, 64)
	if (!memcmp(C_, clientKey) || !memcmp(S_, serverKey)) {
		return false
	}
	return true
}
module.exports.solvePuzzle = function(TID, puzzle) {
	if (puzzle.length != 121) return null
	//  puzzles should be 121 bytes, really
	var q = puzzle.slice(0, 80)
	var H_r = puzzle.slice(80, 112)
	var w = puzzle[112]
	var n_ = new Int64(puzzle, 113)
	for(var x = 0; x < Math.pow(2, w); x++) {
		zero_bits(q, w, x)
		if (memcmp(crypto.hashPuzzle(q), H_r)) {
			return Buffer.concat([q, n_.getBuffer()])
		}
	}
	// not found for some reason
	return null
}
function zero_bits(b, w, add) {
	var o = b.length - 1
	if (!add) add = 0
	while(w >= 8) {
		b[o] = add & 0xFF
		add >>= 8
		w -= 8
		o--
	}
	b[o] = ((b[o] >> w) << w) | (add & 0xFF)
}
