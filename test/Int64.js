/* global describe */
/* global it */
var assert = require("assert")
var Int64 = require('../Int64.js')

describe('Int64', function(){
	it("should work like the module it's based on", function(){
		var x = new Int64(1e18)
		assert.equal(x.toOctetString(), '0de0b6b3a7640000')
		assert.equal(x.toNumber(true), 1e18)
	})
	describe('.shiftLeft', function(){
		it('should work', function() {
			var x = new Int64(0xff12345, 0x654321)
			x.shiftLeft(4)
			assert.equal(x.toOctetString(), 'ff12345006543210')
			x = new Int64(0xff12345, 0x654321)
			x.shiftLeft(16)
			assert.equal(x.toOctetString(), '2345006543210000')
		})
		it('should error when trying to shift to the rignt', function(){
			assert.throws(function(){
				var x = new Int64(0xff12345, 0x654321)
				x.shiftLeft(-1)
			}, function(err) {
				return err instanceof Error && err.message == "can't shift to negative amounts"
			})
		})
	})
	describe('.getBuffer', function(){
		it('should return a buffer containing the number', function(){
			var x = new Int64(0xff12345, 0x654321)
			assert.deepEqual(x.getBuffer(), new Buffer('0ff1234500654321', 'hex'))
		})
		it('should return a buffer with the number even with an offset', function(){
			var x = new Int64(new Buffer('000ff1234500654321', 'hex'), 1)
			assert.deepEqual(x.getBuffer(), new Buffer('0ff1234500654321', 'hex'))
		})
		it('should always be length 8', function(){
			var x = new Int64(new Buffer('000ff1234500654321aabbccdd', 'hex'), 1)
			assert.deepEqual(x.getBuffer(), new Buffer('0ff1234500654321', 'hex'))
		})
	})
})
