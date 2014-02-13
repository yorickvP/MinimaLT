"use strict";
var Int64 = require('./Int64.js')

var RPC = {
	calculateLength: function(x) {
		if (typeof x === 'number' && (x|0 === x) && x >= 0) {
			return 5
		}
		else if (typeof x === 'string') {
			var len = Buffer.byteLength(x, 'utf8')
			if (len > 512) throw new Error("string too long")
			return len + 3
		}
		else if (typeof x === 'object') {
			if (x instanceof Int64) {
				return 9
			} else if (Array.isArray(x)) {
				return 2 + x.reduce(function(p, c) {
					return p + RPC.calculateLength(c)
				}, 0)
			} else if (Buffer.isBuffer(x)) {
				if (x.length > 512) throw new Error("string too long")
				return x.length + 3
			}
		}
		throw new Error("unknown thing to serialize", x)
	},
	serialize: function serialize(x, buffer, offset) {
		if (typeof x === 'number' && (x|0 === x) && x >= 0) {
			check_buffer(5)
			buffer[offset++] = 'd'.charCodeAt(0)
			buffer.writeUInt32BE(x, offset)
			offset += 4
			return offset
		}
		else if (typeof x === 'string') {
			var len = Buffer.byteLength(x, 'utf8')
			if (len > 512) throw new Error("string too long")
			check_buffer(len + 3)
			buffer[offset++] = 's'.charCodeAt(0)
			buffer.writeUInt16BE(len, offset)
			offset += 2
			buffer.write(x, offset, len, 'utf8')
			offset += len
			return offset
		}
		else if (typeof x === 'object') {
			if (x instanceof Int64) {
				check_buffer(9)
				buffer[offset++] = 'q'.charCodeAt(0)
				x.getBuffer().copy(buffer, offset)
				offset += 8
				return offset
			} else if (Array.isArray(x)) {
				check_buffer(1)
				buffer[offset++] = 'l'.charCodeAt(0)
				x.forEach(function(y) {
					offset = serialize(y, buffer, offset)
				})
				check_buffer(1)
				buffer[offset++] = 'e'.charCodeAt(0)
				return offset
			} else if (Buffer.isBuffer(x)) {
				if (x.length > 512) throw new Error("buffer too long")
				check_buffer(x.length + 3)
				buffer[offset++] = 'b'.charCodeAt(0)
				buffer.writeUInt16BE(x.length, offset)
				offset += 2
				x.copy(buffer, offset)
				offset += x.length
				return offset
			}
		}
		throw new Error("unknown thing to serialize", x)
		function check_buffer(l) {
			if (buffer.length-offset < l) throw new Error("insufficient buffer space")
		}
	},
	deserialize: function deserialize(buffer, offset) {
		var x, len
		check_data(1)
		switch(buffer[offset++]) {
			case 'd'.charCodeAt(0):
				check_data(4)
				x = buffer.readUInt32BE(offset)
				offset += 4
				break
			case 'q'.charCodeAt(0):
				check_data(8)
				// don't copy but slice?
				x = new Int64(new Buffer(buffer.slice(offset, offset + 8)))
				offset += 8
				break
			case 'l'.charCodeAt(0):
				x = []
				check_data(1)
				while(buffer[offset] != 'e'.charCodeAt(0)) {
					var d = deserialize(buffer, offset)
					x.push(d.data)
					offset = d.offset
					check_data(1)
				}
				offset++
				break
			case 's'.charCodeAt(0):
				check_data(2)
				len = buffer.readUInt16BE(offset)
				offset += 2
				check_data(len)
				x = buffer.toString('utf8', offset, offset+len)
				offset += len
				break
			case 'b'.charCodeAt(0):
				check_data(2)
				len = buffer.readUInt16BE(offset)
				offset += 2
				check_data(len)
				x = buffer.slice(offset, offset+len)
				if (len < buffer.length / 1.5) x = new Buffer(x)
				offset += len
				break
			default: throw new Error("malformed data")
		}
		return {data: x, offset: offset}

		function check_data(l) {
			if (buffer.length-offset < l) throw new Error("insufficient data")
		}
	},
	serialize_complete: function(x) {
		var buffer = new Buffer(RPC.calculateLength(x))
		RPC.serialize(x, buffer, 0)
		return buffer
	},
	deserialize_rpc_payload: function(buffer) {
		var RPCs = [], offset = 0, connection, d
		while(buffer.length - offset > 4) {
			connection = buffer.readUInt32BE(offset)
			offset += 4
			d = RPC.deserialize(buffer, offset)
			RPCs.push({cid: connection, rpc: d.data})
			offset = d.offset
		}
		if (offset != buffer.length) throw new Error("trailing data")
		return RPCs
	},
	rpc_payload_length: function(x) {
		return x.reduce(function(p, c) {
			return p + 4 + RPC.calculateLength(c.rpc)
		}, 0)
	},
	serialize_rpc_payload: function(x, buffer, offset) {
		x.forEach(function(rpc){
			check_buffer(4)
			buffer.writeUInt32BE(rpc.cid, offset)
			offset += 4
			offset = RPC.serialize(rpc.rpc, buffer, offset)
		})
		return offset
		function check_buffer(l) {
			if (buffer.length-offset < l) throw new Error("insufficient buffer space")
		}
	}
}

module.exports = RPC
