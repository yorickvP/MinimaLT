"use strict";
var crypto = require('./crypto.js')
var packet = require('./packet.js')
var util = require('util')
var events = require('events')
var stream = require('stream')
var RPC = require('./RPC')


function DEBUG(tun, str) {
	console.log.apply(console, ["Tunnel ", tun.TID.getBuffer().toString('hex'), tun.client ? '(client):' : '(server):'].concat(
		[].slice.call(arguments, 1)))
}

// rtt code from Richard Stevens - Unix Network Programming, adapted using some RFCs
var constants = {
	RTT_RXTMIN: 1000, /* min retransmit timeout value */
	RTT_RXTMAX: 60000, /* max retransmit timeout value, in microseconds */
	RTT_MAXNREXMT: 5 /* max # times to retransmit */
}

function RTT_RTOCALC(ptr) {
	// clock granularity
	return ptr.rtt_srtt + Math.max(15, 4 * ptr.rtt_rttvar)
}
function clamp_rto(rto) {
	return Math.max(constants.RTT_RXTMIN, Math.min(constants.RTT_RXTMAX, rto))
}
function RPCOutStream(tunnel) {
	this.seq = crypto.random_UInt32()
	this.ack = 0
	this.ackd = 0
	this.tun = tunnel
	this.MTU = 1472
	// the paper specifies a nonce that increases with time
	// but JS clocks aren't that accurate, so we risk having duplicates
	// and that is apparently a VERY BAD THING, so stick to a counter for now
	// TODO: handle overflows, make a UInt64?
	this.nonce = crypto.random_UInt32()*2
	this.pending = []
	this.window = []
	this.window_size = 0
	this.initial_window = this.cwnd =
		this.MTU > 2190 ? 2 :
		this.MTU <=1095 ? 4 : 3
	// start out the slow start threshold arbitrarily high
	this.ssthresh = 128
	this.cwnd_ack = 0
	this.rtt_rtt = 0
	this.rtt_srtt = 0
	this.rtt_rttvar = 750
	this.rtt_rto = 3000
	this.last_send = 0
	this.rtt_timer = null
	this.duplicate_acks = 0
	this.T_last = Date.now()
	this.T_prev = Date.now()
	this.W_used = 0
	this.active = true
	stream.Writable.call(this, {
		objectMode: true
	})
	this.do_flush_soon = false
}
util.inherits(RPCOutStream, stream.Writable)
RPCOutStream.prototype._write = function(chunk, encoding, callback) {
	chunk.size = RPC.rpc_payload_length([chunk])
	chunk.TID = this.tun.TID
	if (!this.active) return callback()
	// TODO: count this in bytes?
	if (this.window.length < this.cwnd) {
		this.pending.push(chunk)
		this.flushSoon()
		callback()
	} else {
		var self = this
		self.resumeWrite = function() {
			self.resumeWrite = null
			if (!this.active) return callback()
			self.pending.push(chunk)
			self.flushSoon()
			callback()
		}
	}
}
RPCOutStream.prototype.flushSoon = function() {
	if (this.do_flush_soon) return
	else {
		this.do_flush_soon = true
		setImmediate(this.flush.bind(this))
	}
}
RPCOutStream.prototype.updateRTT = function(measuredRTT) {
	// see RFC 2988
	if (this.rtt_rtt == 0) {
		this.rtt_rtt = measuredRTT
		this.rtt_srtt = measuredRTT
		this.rtt_rttvar = measuredRTT / 2
	} else {
		this.rtt_rtt = measuredRTT
		var delta = Math.abs(this.rtt_srtt - this.rtt_rtt)
		this.rtt_rttvar = (1 - (1/4)) * this.rtt_rttvar + (1/4) * delta
		this.rtt_srtt = (1 - (1/8)) * this.rtt_srtt + (1/8) * measuredRTT
	}
	this.rtt_rto = clamp_rto(RTT_RTOCALC(this))
}
RPCOutStream.prototype.RFC2861 = function() {
	var tcpnow = Date.now()
	if (tcpnow - this.T_Last >= this.rtt_rto) {
		// the sender has been idle
		this.ssthresh = Math.max(this.ssthresh, 3 * this.cwnd / 4)
		for (var i = 0; i < (tcpnow - this.T_last)/this.rtt_rto; i++) {
			this.cwnd = Math.max(this.cwnd / 2, 1)
		}
		this.T_prev = tcpnow
		this.W_used = 0
	}
	this.T_last = tcpnow
	if (this.window.length >= this.cwnd) {
		// window is full
		this.T_prev = tcpnow
		this.W_used = 0
	} else {
		if (!(this.pending.length || this.resumeWrite)) {
			// no more data is available to send
			this.W_used = this.window.length
			if (tcpnow - this.T_prev >= this.rtt_rto) {
				// the sender has been application limited
				this.ssthresh = Math.max(this.ssthresh, 3*this.cwnd/4)
				this.cwnd = Math.max((this.cwnd + this.W_used) / 2, 1)
				this.T_prev = tcpnow
				this.W_used = 0
			}
		}
	}
}
RPCOutStream.prototype.flush = function() {
	this.do_flush_soon = false
	var out_size = this.MTU - 32
	var outPacket = {
		TID: this.tun.TID,
		nonce: crypto.generate_nonce(this.tun.client, this.nonce++),
		hasPubKey: false,
		hasPuzzle: false
	}
	var to_send = []
	while(this.pending.length > 0 && out_size >= this.pending[0].size) {
		var rpc = this.pending.shift()
		out_size -= RPC.rpc_payload_length([rpc])
		if (rpc.pubkey) {
			out_size -= rpc.pubkey.length
			outPacket.hasPubKey = true
			outPacket.pubKey = rpc.pubkey
		}
		to_send.push(rpc)
		if (out_size < 0) {
			throw new Error('packet too big')
		}
	}
	var seq = to_send.length ? this.seq++ : 0
	DEBUG(this.tun, "sending a packet (seq "+seq+" ack "+this.ack+") containing",  to_send.map(function(x) { return x.cid + ',' + x.rpc[0]}))
	outPacket.payload = packet.makePayload({
		RPC: to_send,
		sequence: seq,
		acknowledge: this.ack
	})
	outPacket.payload = new Buffer(crypto.box(outPacket.payload, crypto.make_nonce(this.tun.TID, outPacket.nonce), this.tun.secret))
	outPacket = packet.makePacket(outPacket)
	this.tun.emit('sendpacket', outPacket)
	// do not do fancy things with ack packets.
	if (seq != 0) {
		this.window.push({time: Date.now(), seq: seq, pkt: outPacket,
			rtt_nrexmt: 0,
			size: this.MTU - out_size,
			connections: to_send.map(function(x) {return x.cid})
		})
		this.last_send = Date.now()
		this.RFC2861()
	}
	this.ack = 0
	if(this.rtt_timer == null) this.setTimer()
	if (this.pending.length) this.flush()
}
RPCOutStream.prototype.windowShift = function(ack) {
	var ws, tun = this.tun
	while(this.window.length && this.window[0].seq <= ack) {
		ws = this.window.shift()
		if (!ws.discount) this.updateRTT(Date.now() - ws.time)
		for(var i = 0; i < ws.connections.length; i++) {
			tun.connections[ws.connections[i]].ackRPC()
		}
		this.cwnd_ack += ws.size
	}
	if (ws) {
		// new data was acknowledged
		this.setTimer()
		if(this.cwnd <= this.ssthresh) {
			// slow start
			this.cwnd += 1
			this.cwnd_ack = 0
		} else if (this.cwnd_ack > this.cwnd * this.MTU){
			// congestion avoidance
			this.cwnd += 1
			this.cwnd_ack = 0
		}
		console.log('cwnd', this.cwnd, this.ssthresh)
	}
	// resume writing now
	// TODO: count window in bytes?
	if (this.resumeWrite && this.window.length < this.cwnd) this.resumeWrite()
}
RPCOutStream.prototype.retransmit = function() {
	DEBUG(this.tun, 'retransmitting packet', this.window[0].seq)
	this.tun.emit('sendpacket', this.window[0].pkt)
	this.window[0].time = Date.now()
	// don't count lost packets in our RTT calculations
	this.window[0].discount = true
	this.setTimer()
}
RPCOutStream.prototype.timeout = function() {
	this.rtt_rto *= 2 // backoff exponentially
	this.rtt_timer = null
	if (this.window[0].rtt_nrexmt == 0) {
		// adjust ssthresh
		this.ssthresh = Math.max(this.window.length / 2, 2)
		this.cwnd = 1
	}
	if (++this.window[0].rtt_nrexmt > constants.RTT_MAXNREXMT) {
		this.emit('timeout', "retransmit count reached")
		return
	}
	// don't count lost packets
	this.window[0].discount = true
	this.retransmit()
}
RPCOutStream.prototype.setTimer = function() {
	if (this.rtt_timer != null) {
		clearTimeout(this.rtt_timer)
		this.rtt_timer = null
	}
	if (this.window.length == 0) return
	this.rtt_timer = setTimeout(this.timeout.bind(this), this.rtt_rto)
}
RPCOutStream.prototype.gotPacket = function(seq, ack) {
	if (ack != 0) {
		if (this.window[0] && this.window[0].seq == ack - 1) {
			// fast retransmit
			this.duplicate_acks++
			if (this.duplicate_acks < 3) {
				// RFC 3042
				if (this.resumeWrite) this.resumeWrite()
			}
			if (this.duplicate_acks == 3) {
				this.retransmit()
				this.ssthresh = Math.max(this.window.length / 2, 2)
				this.duplicate_acks = 0
				this.cwnd = this.ssthresh + 3
			}
			if (this.duplicate_acks > 3) {
				this.cwnd += 1
			}
			// TODO: count window in bytes?
			if (this.resumeWrite && this.window.length < this.cwnd) this.resumeWrite()
		} else {
			if (this.duplicate_acks >= 3) {
				// "deflate" the window
				this.cwnd = this.ssthresh
			}
			this.duplicate_acks = 0
			this.windowShift(ack)
		}
	}
	if (seq != 0) {
		if (seq <= this.ackd) {
			// this is a duplicate packet, we already confirmed it once
			// should we confirm it again? I think so, because duplicates
			// can be sent when the ack packet is lost
			this.ackPacket(seq)
			return false
		}
		if (seq != this.ackd + 1 && this.ackd != 0) {
			// there was a missing packet before this one,
			// send a duplicate ack on the packet before it
			this.ackPacket(this.ackd)
			return false
		}
		if (seq == this.ackd + 1 || this.ackd == 0) {
			this.ackPacket(seq)
		}
	}
	return true
}
RPCOutStream.prototype.ackPacket = function(seq) {
	this.ack = seq
	this.ackd = Math.max(this.ackd, seq)
	this.flushSoon()
}
RPCOutStream.prototype.teardown = function() {
	this.end()
	this.active = false
	this.pending = []
}
module.exports = RPCOutStream
