"use strict";
var orig_int64 = require('node-int64')
function Int64(a1, a2) {
	orig_int64.apply(this, arguments)
}
Int64.prototype = Object.create(orig_int64.prototype)
Int64.prototype.constructor = Int64
Int64.prototype.shiftLeft = function(x) {
	if(x < 0) throw new Error("can't shift to negative amounts")
	var o = this.offset, b = this.buffer, carry = 0
	for (var i = o + 7; i >= o; i--) {
		var v = (b[i] << x) + carry
		b[i] = v & 0xff;
		carry = v >> 8;
	}
	return this
}
Int64.prototype.getBuffer = function() {
	return this.buffer.slice(this.offset, this.offset + 8)
}
Int64.prototype.equal = function(that) {
	return that instanceof Int64 && this.toOctetString() == that.toOctetString()
}

Int64.MAX_INT = orig_int64.MAX_INT
Int64.MIN_INT = orig_int64.MIN_INT

module.exports = Int64
