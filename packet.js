"use strict";
var assert = require('assert')
var Int64 = require('./Int64')
var RPC = require('./RPC')

var packet = {
	/** parsePacket: parse the non-encrypted parts of a minimaLT packet
		be aware this modifies the source buffer a(two) bit(s) so you only do it once */
	parsePacket: function(buf) {
		if (buf.length < 40) throw new Error("invalid packet length")
		var TID = new Int64(buf, 0)
		// the first two bits are important
		var hasPubKey = !!(TID.buffer[0] & (1<<7))
		var hasPuzzle = !!(TID.buffer[0] & (1<<6))
		TID.buffer[0] &= (1<<6)-1
		// calculate the minimum packet length
		if (buf.length < (40 + (hasPubKey ? 32 : 0) + (hasPuzzle ? 148 : 0)))
			throw new Error("invalid packet length")
		var nonce = new Int64(buf, 8)
		var ret = {
			TID: TID,
			nonce: nonce,
			hasPubKey: hasPubKey,
			hasPuzzle: hasPuzzle
		}
		var offset = 16
		if (hasPubKey) {
			ret.pubKey = buf.slice(offset, offset + 32)
			offset += 32
		}
		if (hasPuzzle) {
			ret.puzzle = buf.slice(offset, offset + 148)
			offset += 148
		}
		ret.payload = buf.slice(offset)
		return ret
	},
	makePacket: function(res) {
		// pre-allocate the buffer instead?
		var TID = new Buffer(res.TID.getBuffer())
		var list = [TID, res.nonce.getBuffer()]
		var length = 16
		if (res.hasPubKey) {
			assert.equal(res.pubKey.length, 32)
			TID[0] |= (1 << 7)
			list.push(res.pubKey)
			length += 32
		}
		if (res.hasPuzzle) {
			assert.equal(res.puzzle.length, 148)
			TID[0] |= (1 << 6)
			list.push(res.puzzle)
			length += 148
		}
		list.push(res.payload)
		length += res.payload.length
		return Buffer.concat(list, length)
	},
	parsePayload: function(payload) {
		if (payload.length < 8) throw new Error("invalid packet length")
		var sequence = payload.readUInt32BE(0)
		var acknowledge = payload.readUInt32BE(4)
		var RPCs = RPC.deserialize_rpc_payload(payload.slice(8))
		return {
			sequence: sequence,
			acknowledge: acknowledge,
			RPC: RPCs
		}
	},
	makePayload: function(payload) {
		// pre-allocate this instead?
		var res = new Buffer(8 + RPC.rpc_payload_length(payload.RPC))
		res.writeUInt32BE(payload.sequence, 0)
		res.writeUInt32BE(payload.acknowledge, 4)
		RPC.serialize_rpc_payload(payload.RPC, res, 8)
		return res
	}
}

module.exports = packet
