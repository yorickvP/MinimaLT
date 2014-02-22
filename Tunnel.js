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
var CongestionStream = require('./CongestionStream')

function DEBUG(tun, str) {
	console.log.apply(console, ["Tunnel ", tun.TID.getBuffer().toString('hex'), tun.client ? '(client):' : '(server):'].concat(
		[].slice.call(arguments, 1)))
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
	this.RPCOutStream = new CongestionStream(this)
	this.control = controlConnection(0, this)
	this.addConnection(this.control)
	this.active = true
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
	// do not receive any more packets on dead tunnnels
	if (!this.active) return
	recv_pkt.payload = packet.parsePayload(recv_pkt.payload)
	if (!this.RPCOutStream.gotPacket(recv_pkt.payload.sequence, recv_pkt.payload.acknowledge)) return
	DEBUG(self, "received", recv_pkt.payload.RPC.map(function(x) { return x.cid + ',' + x.rpc[0]}))
	recv_pkt.payload.RPC.forEach(function(rpc) {
		self.connections[rpc.cid].instream.write(rpc.rpc)
	})
}
Tunnel.prototype.send_connect = function() {
	this.control.callAdv(this.own_pubkey, null, "nextTid", this.TID, this.own_pubkey)
}
Tunnel.prototype.addConnection = function(connection) {
	connection.outstream.pipe(this.RPCOutStream)
	this.connections[connection.cid] = connection
}
Tunnel.prototype.create = function(servicename, rpcs) {
	var con = new Connection(this.connections.length, this)
	this.addConnection(con)
	if (rpcs) con.setRPCs(rpcs)
	this.control.call('create', con.cid, servicename)
	return con
}
Tunnel.prototype.createAuth = function(servicename, authkey, auth_msg, rpcs) {
	var con = new Connection(this.connections.length, this)
	this.addConnection(con)
	if (rpcs) con.setRPCs(rpcs)
	this.control.call('createAuth', con.cid, servicename, authkey, auth_msg)
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
Tunnel.prototype.teardown = function() {
	this.active = false
	this.emit('teardown')
	var self = this
	this.connections.forEach(function(connection) {
		connection.outstream.unpipe(self.RPCOutStream)
	})
	this.RPCOutStream.teardown()
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
	var connection = new Connection(id, tunnel, true)
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
			tunnel.addConnection(con)
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
			tunnel.addConnection(con)
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
		},
		windowSize: function(c, n) {
			tunnel.connections[c].setWindowSize(n)
		}
	})
	return connection
}
