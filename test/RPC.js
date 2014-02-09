/* global describe */
/* global it */
var assert = require("assert")
var Int64 = require('../Int64.js')
var RPC = require('../RPC.js')

var data = [[1,2,3], ["this", "is", "a", "list"],
 1, "Hello, World!", new Buffer("Hello World!"),
 new Int64(0xff12345, 0x654321)]
var serialized_data = new Buffer(
"bGxkAAAAAWQAAAACZAAAAANlbHMABHRoaXNzAAJpc3MAAWFzAARsaXN0ZWQA" +
"AAABcwANSGVsbG8sIFdvcmxkIWIADEhlbGxvIFdvcmxkIXEP8SNFAGVDIWU=", 'base64')

describe('RPC', function(){
	it('should serialize/deserialize correctly', function(){
		var data2 = RPC.deserialize(serialized_data, 0)[0]
		var serialized_data2 = RPC.serialize_complete(data)
		assert.deepEqual(data2, data)
		assert.deepEqual(serialized_data2, serialized_data)
	})
	describe('.calculateLength', function(){
		it('should calculate the correct lengths', function(){
			assert.equal(RPC.calculateLength(data), 89)
		})
		it('should fail on negative or too big ints', function(){
			assert.throws(function(){
				RPC.calculateLength(-1)
			})
			assert.throws(function(){
				RPC.calculateLength(1e89)
			})
		})
		it('should fail on too long buffers and strings', function(){
			assert.throws(function(){
				var a = new Buffer(1024)
				a.fill(0x20)
				RPC.calculateLength(a.toString())
			})
			assert.throws(function(){
				var a = new Buffer(1024)
				RPC.calculateLength(a)
			})
		})
		it('should fail on invalid data', function(){
			assert.throws(function(){
				RPC.calculateLength()
			})
			assert.throws(function(){
				RPC.calculateLength({a: 10})
			})
		})
	})
	describe('.serialize', function(){
		var b = new Buffer(1024)
		it('should fail on negative or too big ints', function(){
			assert.throws(function(){
				RPC.serialize(-1, b, 0)
			})
			assert.throws(function(){
				RPC.serialize(1e89, b, 0)
			})
		})
		it('should fail on too long buffers and strings', function(){
			assert.throws(function(){
				var a = new Buffer(1024)
				a.fill(0x20)
				RPC.serialize(a.toString(), b, 0)
			})
			assert.throws(function(){
				var a = new Buffer(1024)
				RPC.serialize(a, b, 0)
			})
		})
		it('should fail on invalid data', function(){
			assert.throws(function(){
				RPC.serialize(undefined, b, 0)
			})
			assert.throws(function(){
				RPC.serialize({a: 10}, b, 0)
			})
		})
		it('should fail when not given a big enough buffer', function(){
			assert.throws(function(){
				RPC.serialize(data, new Buffer(10), 0)
			})
			assert.throws(function(){
				RPC.serialize(data, new Buffer(88), 0)
			})
			assert.throws(function(){
				RPC.serialize(data, new Buffer(80), 0)
			})
		})
	})
	describe('.deserialize', function(){
		it('should fail on insufficient or invalid data', function(){
			assert.throws(function(){
				RPC.deserialize(new Buffer(""), 0)
			})
			assert.throws(function(){
				RPC.deserialize(data, 1)
			})
			assert.throws(function(){
				RPC.deserialize(data.slice(0, 88), 0)
			})
			assert.throws(function(){
				RPC.deserialize(data.slice(0, 10), 0)
			})
		})
	})
})
