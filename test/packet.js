/* global describe */
/* global it */
var assert = require("assert")
var packet = require('../packet.js')
var crypto = require('../crypto.js')
var Int64  = require('../Int64.js')

var testPkt = new Buffer(" the_TIDnonnonce")
var testPub = new Buffer("169d20312f66ac799959b7470a23fd4dd186c5308ff9b41a91a8637aac94d752", 'hex')
/* not implemented anytime soon */
var testPuz = new Buffer(148)
testPuz[0] = 255
var testPubKey = new Buffer("ac308e7b6e369b67ffa631feea383d50ca9e2fcf280547091ebc4ee26b8e9204", 'hex')
var testTID = new Int64(new Buffer(" new_TID"))
var testRPC = Buffer.concat([new Buffer("000000006c7300076e65787454696471206e65775f544944620020", 'hex'), testPubKey, new Buffer([0x65])])
var testPayload = Buffer.concat([new Buffer("2a2b2c2d1a1b1c1d", "hex"), testRPC])

describe('packet', function(){
	describe('.parsePacket()', function(){
		it('should error on insufficient data', function(){
			assert.throws(function(){
				packet.parsePacket(new Buffer(5))
			}, function(err) {
				return err instanceof Error && err.message == "invalid packet length"
			})
		})
		it('should parse regular packets', function() {
			var res = packet.parsePacket(Buffer.concat([testPkt, testPayload]))
			assert.equal(res.TID.toOctetString(),   '207468655f544944')
			assert.equal(res.nonce.toOctetString(), '6e6f6e6e6f6e6365')
			assert.equal(res.hasPubKey, false)
			assert.equal(res.hasPuzzle, false)
			assert.deepEqual(res.payload, testPayload)
		})
		it('should parse packets with pubkey and puzzle', function() {
			var pkt = new Buffer(16)
			// set the first two bits of the TID field
			testPkt.copy(pkt)
			pkt[0] |= (1<<7) | (1<<6)
			var res = packet.parsePacket(Buffer.concat([pkt, testPub, testPuz, testPayload]))
			assert.equal(res.TID.toOctetString(),   '207468655f544944')
			assert.equal(res.nonce.toOctetString(), '6e6f6e6e6f6e6365')
			assert.equal(res.hasPubKey, true)
			assert.equal(res.hasPuzzle, true)
			assert.deepEqual(res.pubKey, testPub)
			assert.deepEqual(res.puzzle, testPuz)
			assert.deepEqual(res.payload, testPayload)
		})
	})
	describe('.makePacket()', function(){
		it('should reconstruct parsed packets', function(){
			var input = Buffer.concat([testPkt, testPayload])
			var res = packet.parsePacket(input)
			var reconstructed = packet.makePacket(res)
			assert.deepEqual(reconstructed, input)
		})
		it('should reconstruct complicated parsed packets', function(){
			var pkt = new Buffer(16)
			// set the first two bits of the TID field
			testPkt.copy(pkt)
			pkt[0] |= (1<<7) | (1<<6)
			var input = Buffer.concat([pkt, testPub, testPuz, testPayload])
			// parsePacket modifies two bits, so this is needed
			var res = packet.parsePacket(Buffer.concat([pkt, testPub, testPuz, testPayload]))
			var reconstructed = packet.makePacket(res)
			assert.deepEqual(reconstructed, input)
		})
		it('should not change any of the input buffers')
	})
	describe('.parsePayload()', function(){
		it('should error on insufficient data', function(){
			assert.throws(function(){
				packet.parsePayload(new Buffer(5))
			}, function(err) {
				return err instanceof Error && err.message == "invalid packet length"
			})
		})
		it('should work', function(){
			var res = packet.parsePayload(testPayload)
			assert.equal(res.sequence, 0x2a2b2c2d)
			assert.equal(res.acknowledge, 0x1a1b1c1d)
			assert.deepEqual(res.RPC, [[0, ["nextTid", testTID, testPubKey]]])
			res = packet.parsePayload(Buffer.concat([testPayload, testRPC]))
			assert.deepEqual(res.RPC, [[0, ["nextTid", testTID, testPubKey]], [0, ["nextTid", testTID, testPubKey]]])
		})
		it('should error on too much data', function(){
			assert.throws(function(){
				packet.parsePayload(Buffer.concat([testPayload, new Buffer("hello there")]))
			})
		})
	})
})

