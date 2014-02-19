"use strict";
var crypto = require('./crypto.js')
var packet = require('./packet.js')
var Int64 = require('./Int64.js')
var Connection = require('./Connection.js')
var auth = require('./auth.js')
var assert = require('assert')
var util = require('util')
var events = require('events')
var stream = require('stream')
var RPC = require('./RPC')

var constants = {
	RTT_RXTMIN: 1000, /* min retransmit timeout value */
	RTT_RXTMAX: 60000, /* max retransmit timeout value, in microseconds */
	RTT_MAXNREXMT: 3 /* max # times to retransmit */
}

function DEBUG(tun, str) {
	console.log.apply(console, ["Tunnel ", tun.TID.getBuffer().toString('hex'), tun.client ? '(client):' : '(server):'].concat(
		[].slice.call(arguments, 1)))
}

function fmt_rpc(con, rpc) {
	return con + " " + rpc[0]
}
// rtt code from Richard Stevens - Unix Network Programming
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
	this.duplicate_acks = 0
	stream.Writable.call(this, {
		objectMode: true
	})
	this.do_flush_soon = false
}
util.inherits(RPCOutStream, stream.Writable)
RPCOutStream.prototype._write = function(chunk, encoding, callback) {
	chunk.size = RPC.rpc_payload_length([chunk])
	if (this.last_send != 0 && Date.now() - this.last_send > this.rtt_rto) {
		// connection idle, restart slow start
		this.cwnd = Math.min(this.initial_window, this.cwnd)
	}
	// TODO: count this in bytes?
	if (this.window.length < this.cwnd) {
		this.pending.push(chunk)
		this.flushSoon()
		callback()
	} else {
		var self = this
		self.resumeWrite = function() {
			self.pending.push(chunk)
			self.flushSoon()
			callback()
			self.resumeWrite = null
		}
	}
}
RPCOutStream.prototype.flushSoon = function() {
	if (this.do_flush_soon) return
	else {
		this.do_flush_soon = true
		process.nextTick(this.flush.bind(this))
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
RPCOutStream.prototype.flush = function() {
	this.do_flush_soon = false
	var out_size = this.MTU - 32
	var outPacket = {
		TID: this.tun.TID,
		nonce: crypto.generate_nonce(this.tun.client, this.nonce++),
		hasPubKey: false,
		hasPuzzle: false
		// TODO sequencing happens here
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
			rtt_nrexmt: 0, timer: null,
			size: this.MTU - out_size
		})
		this.last_send = Date.now()
	}
	this.ack = 0
	this.setTimer()
	if (this.pending.length) this.flush()
}
RPCOutStream.prototype.windowShift = function(ack) {
	var ws
	while(this.window.length && this.window[0].seq <= ack) {
		ws = this.window.shift()
		if (ws.timer != null) clearTimeout(ws.timer)
		if (!ws.discount) this.updateRTT(Date.now() - ws.time)
		this.cwnd_ack += ws.size
	}
	if (ws) {
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
	this.window[0].timer = null
	if (this.window[0].rtt_nrexmt == 0) {
		// adjust ssthresh
		this.ssthresh = Math.max(this.window.length / 2, 2)
		this.cwnd = 1
	}
	if (++this.window[0].rtt_nrexmt > constants.RTT_MAXNREXMT) {
		this.emit('error', "retransmit count reached")
		return
	}
	// don't count lost packets
	this.window[0].discount = true
	this.retransmit()
}
RPCOutStream.prototype.setTimer = function() {
	if (this.window.length == 0) return
	if (this.window[0].timer) clearTimeout(this.window[0].timer)
	this.window[0].timer = setTimeout(this.timeout.bind(this), this.rtt_rto)
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

function Tunnel(remote_pubkey, own_keys, TID) {
	events.EventEmitter.call(this)
	if (TID) {
		this.TID = TID
	} else {
		this.TID = crypto.random_Int64()
		this.TID.buffer[0] &= 0x3F // leave out the two upper bits, we're using those
	}
	this.remote_pubkey = remote_pubkey
	if (own_keys) {
		this.client = false
		this.generate_secret(own_keys.private)
		this.own_pubkey = own_keys.public
	} else {
		this.client = true
		this.make_key()
	}
	this.connections = []
	this.RPCOutStream = new RPCOutStream(this)
	this.connections[0] = this.control = controlConnection(0, this)
}
util.inherits(Tunnel, events.EventEmitter)
Tunnel.prototype.make_key = function() {
	DEBUG(this, "generating C'")
	var keypair = crypto.make_keypair()
	this.own_pubkey = keypair.public
	// XXX: should use a clock that doesn't
	// change when the system one does
	this.key_time = Date.now()
	this.generate_secret(keypair.private)
	// throw away the private key, we don't need it
	for(var i = 0; i < keypair.private.length; i++) {
		keypair.private[i] = 0
	}
}
Tunnel.prototype.generate_secret = function(privkey) {
	this.secret = crypto.shared_secret(this.remote_pubkey, privkey)
}
Tunnel.prototype.hash_secret = function() {
	this.secret = crypto.hashSecret(this.secret)
}
Tunnel.prototype.recv_packet = function(recv_pkt, rinfo) {
	recv_pkt.payload = crypto.unbox(recv_pkt.payload, crypto.make_nonce(recv_pkt.TID, recv_pkt.nonce), this.secret)
	this.recv_decrypted_packet(recv_pkt, rinfo)
}
Tunnel.prototype.recv_decrypted_packet = function(recv_pkt) {
	var self = this
	recv_pkt.payload = packet.parsePayload(recv_pkt.payload)
	if (!this.RPCOutStream.gotPacket(recv_pkt.payload.sequence, recv_pkt.payload.acknowledge)) return
	DEBUG(self, "received", recv_pkt.payload.RPC.map(function(x) { return x.cid + ',' + x.rpc[0]}))
	recv_pkt.payload.RPC.forEach(function(rpc) {
		self.connections[rpc.cid].receive(rpc.rpc)
	})
}
Tunnel.prototype.send_connect = function() {
	this.control.callAdv(this.own_pubkey, null, "nextTid", this.TID, this.own_pubkey)
}
Tunnel.prototype.create = function(servicename, rpcs) {
	var con = new Connection(this.connections.length, this)
	if (rpcs) con.setRPCs(rpcs)
	this.control.call('create', con.cid, servicename)
	this.connections[con.cid] = con
	return con
}
Tunnel.prototype.createAuth = function(servicename, authkey, auth_msg, rpcs) {
	var con = new Connection(this.connections.length, this)
	if (rpcs) con.setRPCs(rpcs)
	this.control.call('createAuth', con.cid, servicename, authkey, auth_msg)
	this.connections[con.cid] = con
	return con
}
Tunnel.prototype.reKey = function() {
	DEBUG(this, 'doing a rekey')
	var TID = crypto.random_Int64()
	TID.buffer[0] &= 0x3F // leave out the two upper bits, we're using those
	var pubkey = crypto.make_keypair().public
	this.control.call('nextTid', TID, pubkey)
	//this.flush_rpcs()
	// TODO: don't lose everything the server sends
	// between now and when it recieves the packet
	// maybe keep this tunnel open for a while?
	// or resend...
	this.TID = TID
	this.hash_secret()
	this.control.callAdv(pubkey, null, 'nextTid', TID, pubkey)
}
Tunnel.prototype.requestRekey = function() {
	this.control.call('rekeyNow')
}
Tunnel.prototype.posePuzzle = function(puzzle_key, difficulty, cb) {
	var puzzle = auth.makePuzzleDecoded(this.own_pubkey, this.remote_pubkey, puzzle_key, this.TID, difficulty)
	this.control.call('puzz', puzzle[0], puzzle[1], puzzle[2], puzzle[3].getBuffer())
	var self = this
	this.once('puzzSoln', function(r, n_) {
		if (auth.checkPuzzleDecoded(self.own_pubkey, self.remote_pubkey, puzzle_key, self.TID, r, new Int64(n_))) {
			cb(true)
		} else {
			cb(false)
		}
	})
}


Tunnel.fromFirstPacket = function(sock, recv_pkt, rinfo, own_keys) {
	assert.ok(recv_pkt.hasPubKey)
	var tun, err = new Error("no keys to decrypt packet")
	var key
	if(own_keys.some(function(k) {
		try {
			recv_pkt.payload = crypto.unboxWithKeys(recv_pkt.payload,
				crypto.make_nonce(recv_pkt.TID, recv_pkt.nonce), recv_pkt.pubKey, k.private)
			key = k
		} catch(e) {
			err = e
			return false
		}
		return true
	}))	{
		tun = new Tunnel(recv_pkt.pubKey, key, recv_pkt.TID)
		return tun
	}
	else throw err
}

module.exports = Tunnel

function controlConnection(id, tunnel) {
	var connection = new Connection(id, tunnel)
	connection.setRPCs({
		nextTid: function(t, C_) {
			assert.equal(connection.tunnel.client, false)
			assert.ok(t instanceof Int64)
			assert.ok(Buffer.isBuffer(C_))
			if (t.equal(connection.tunnel.TID)) {
				// TODO compare the C_ with the one in the packet
				void 0
			} else {
				// do not flush rpcs here, client already changed TID
				tunnel.TID = t
				tunnel.hash_secret()
			}
		},
		rekeyNow: function() {
			tunnel.reKey()
		},
		create: function(c, y) {
			assert(typeof c == 'number')
			assert(typeof y == 'string')
			var con = new Connection(c, tunnel)
			tunnel.connections[c] = con
			tunnel.emit('create', con, y, null, function(err, rpcs) {
				con.init_cb(err, rpcs)
			})
		},
		createAuth: function(c, y, U, x) {
			assert(typeof c == 'number')
			assert(typeof y == 'string')
			assert(Buffer.isBuffer(U))
			assert(Buffer.isBuffer(x))
			var con = new Connection(c, tunnel)
			tunnel.connections[c] = con
			tunnel.emit('createAuth', con, y, U, x, function(err, rpcs) {
				con.init_cb(err, rpcs)
			})
		},
		ack: function(c) {
			tunnel.connections[c].emit('ack')
		},
		refuse: function(c) {
			tunnel.connections[c].emit('refuse')
		},
		close: function(c) {
			tunnel.connections[c].emit('close')
		},
		requestCert: function(S) {
			assert(Buffer.isBuffer(S))
			tunnel.emit('requestCert', S, function(err, cert, eCert) {
				if (err) {
					// TODO: handle error
					void 0
				} else {
					// TODO: S -> cert
					connection.call('giveCert', cert, eCert)
				}
			})
		},
		giveCert: function(certS, ecertS) {
			// TODO: certS -> S
			tunnel.emit('giveCert', certS, ecertS, function(err) {
				if (!err) connection.call('ok')
			})
		},
		ok: function() {
			tunnel.emit('ok')
		},
		puzz: function(q, H_r, w, n_) {
			var In_ = new Int64(n_)
			var r = auth.solvePuzzleDecoded(tunnel.TID, q, H_r, w, In_)
			connection.call('puzzSoln', r, n_)
		},
		puzzSoln: function(r, n_) {
			this.tunnel.emit('puzzSoln', r, n_)
		}
	})
	return connection
}
