"use strict";
var crypto = require('./crypto.js')
var packet = require('./packet.js')
var Int64 = require('./Int64.js')
var Connection = require('./Connection.js')
var assert = require('assert')
var util = require('util')
var events = require('events')

function DEBUG(tun, str) {
	console.log.apply(console, ["Tunnel ", tun.TID.getBuffer().toString('hex'), tun.client ? '(client):' : '(server):'].concat(
		[].slice.call(arguments, 1)))
}

function fmt_rpc(con, rpc) {
	return con + " " + rpc[0]
}

function Tunnel(remote_pubkey, own_keys, TID) {
	events.EventEmitter.call(this)
	if (TID) {
		this.TID = TID
	} else {
		this.TID = crypto.random_Int64()
		this.TID.buffer[0] &= 0x3F // leave out the two upper bits, we're using those
	}
	this.sequence = crypto.random_UInt32()
	this.remote_pubkey = remote_pubkey
	if (own_keys) {
		this.client = false
		this.generate_secret(own_keys.private)
		this.own_pubkey = own_keys.public
	} else {
		this.client = true
		this.make_key()
	}
	// the paper specifies a nonce that increases with time
	// but JS clocks aren't that accurate, so we risk having duplicates
	// and that is apparently a VERY BAD THING, so stick to a counter for now
	// TODO: handle overflows, make a UInt64?
	this.nonce = crypto.random_UInt32()*2
	this.pending_rpcs = []
	this.pending_pubkey = null
	this.connections = []
	this.connections[0] = controlConnection(0, this)
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
Tunnel.prototype.recv_packet = function(recv_pkt, rinfo) {
	recv_pkt.payload = crypto.unbox(recv_pkt.payload, crypto.make_nonce(recv_pkt.TID, recv_pkt.nonce), this.secret)
	this.recv_decrypted_packet(recv_pkt, rinfo)
}
Tunnel.prototype.recv_decrypted_packet = function(recv_pkt) {
	var self = this
	recv_pkt.payload = packet.parsePayload(recv_pkt.payload)
	// TODO sequencing happens here
	DEBUG(self, "received", recv_pkt.payload.RPC.map(function(x) { return x.cid + ',' + x.rpc[0]}))
	recv_pkt.payload.RPC.forEach(function(rpc) {
		self.connections[rpc.cid].receive(rpc.rpc)
	})
}
Tunnel.prototype.do_rpc = function(connection, rpc, pubkey) {
	var self = this
	if (this.pending_rpcs.length === 0) setImmediate(function(){
		self.flush_rpcs()
	})
	this.pending_rpcs.push({cid: connection, rpc: rpc})
	if (pubkey) {
		// TODO: check if there's already a pubkey waiting to be sent out 
		this.pending_pubkey = pubkey
	}
}
Tunnel.prototype.flush_rpcs = function() {
	if (this.pending_rpcs.length < 1) return
	var outPacket = {
		TID: this.TID,
		nonce: crypto.generate_nonce(this.client, this.nonce++),
		hasPubKey: false,
		hasPuzzle: false,
		// TODO sequencing happens here
		payload: packet.makePayload({
			RPC: this.pending_rpcs,
			sequence: this.sequence++,
			acknowledge: 42
		})
	}
	if (this.pending_pubkey) {
		outPacket.hasPubKey = true
		outPacket.pubKey = this.pending_pubkey
		this.pending_pubkey = null
	}
	DEBUG(this, "sending a packet containing", this.pending_rpcs.map(function(x) { return x.cid + ',' + x.rpc[0]}))
	outPacket.payload = new Buffer(crypto.box(outPacket.payload, crypto.make_nonce(this.TID, outPacket.nonce), this.secret))
	outPacket = packet.makePacket(outPacket)
	this.pending_rpcs = []
	this.emit('sendpacket', outPacket)
	//console.log("outputting packet", outPacket.toString('hex'))
}
Tunnel.prototype.send_connect = function() {
	this.do_rpc(0, ["nextTid", this.TID, this.own_pubkey], this.own_pubkey)
}
Tunnel.prototype.create = function(servicename, authkey, rpcs) {
	var con = new Connection(this.connections.length, this)
	if (rpcs) con.setRPCs(rpcs)
	this.connections[0].call('create', con.cid, servicename)
	this.connections[con.cid] = con
	return con
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
				// TODO change the tunnel ID and hash the secret
				void 0
			}
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
		}
	})
	return connection
}
