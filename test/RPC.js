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

var testPubKey = new Buffer("ac308e7b6e369b67ffa631feea383d50ca9e2fcf280547091ebc4ee26b8e9204", 'hex')
var testRPC = Buffer.concat([new Buffer("000000006c7300076e65787454696471206e65775f544944620020", 'hex'), testPubKey, new Buffer([0x65]),
	new Buffer("000000006c7300076e65787454696471206e65775f544944620020", 'hex'), testPubKey, new Buffer([0x65])])
var testTID = new Int64(new Buffer(" new_TID"))
var testRPCdata = [[0, ["nextTid", testTID, testPubKey]], [0, ["nextTid", testTID, testPubKey]]]

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
	describe('.deserialize_rpc_payload', function() {
		it('should work', function(){
			assert.deepEqual(RPC.deserialize_rpc_payload(testRPC), testRPCdata)
		})
		it('should fail on a wrong parameter', function(){
			assert.throws(function(){
				RPC.deserialize_rpc_payload(new Buffer(10))
			})
		})
		it('should fail on too much data', function(){
			assert.throws(function(){
				RPC.deserialize_rpc_payload(Buffer.concat([testRPC, new Buffer("hello there")]))
			})
		})
	})
	describe('.rpc_payload_length', function(){
		it('should work', function(){
			assert.equal(RPC.rpc_payload_length(testRPCdata), testRPC.length)
		})
		it('should fail on a wrong input', function(){
			assert.throws(function(){
				RPC.rpc_payload_length([[0, -1]])
			})
		})
	})
	describe('.serialize_rpc_payload', function(){
		it('should work', function(){
			var b = new Buffer(RPC.rpc_payload_length(testRPCdata))
			var offs = RPC.serialize_rpc_payload(testRPCdata, b, 0)
			assert.equal(offs, b.length)
			assert.deepEqual(b, testRPC)
		})
		it('should fail on a wrong input', function(){
			var b = new Buffer(100)
			assert.throws(function(){
				RPC.serialize_rpc_payload([[0, -1]], b, 0)
			})
		})
		it('should fail when not given a big enough buffer', function(){
			var b = new Buffer(100)
			assert.throws(function(){
				RPC.serialize_rpc_payload(testRPCdata, b, 0)
			})
		})
	})
})


var testRPC = Buffer.concat([new Buffer("000000006c7300076e65787454696471206e65775f544944620020", 'hex'), testPubKey, new Buffer([0x65]),
	new Buffer("000000006c7300076e65787454696471206e65775f544944620020", 'hex'), testPubKey, new Buffer([0x65])])
var testPubKey = new Buffer("ac308e7b6e369b67ffa631feea383d50ca9e2fcf280547091ebc4ee26b8e9204", 'hex')
var testTID = new Int64(new Buffer(" new_TID"))
var testRPCdata = [[0, ["nextTid", testTID, testPubKey]], [0, ["nextTid", testTID, testPubKey]]]
