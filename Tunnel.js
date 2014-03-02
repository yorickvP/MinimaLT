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

function memcmp(a, b) {
	if (a.length != b.length) return false
	for (var i = 0; i < a.length; i++) {
		if (a[i] != b[i]) return false
	}
	return true
}

function Tunnel(is_client, remote_pubkey, own_pubkey, secret, TID) {
	events.EventEmitter.call(this)
	if (TID) {
		this.TID = TID
	} else {
		this.TID = crypto.random_Int64()
		this.TID.buffer[0] &= 0x3F // leave out the two upper bits, we're using those
	}
	this.remote_pubkey = remote_pubkey
	this.own_pubkey = own_pubkey
	this.client = is_client
	this.secret = secret
	this.connections = []
	this.RPCOutStream = new CongestionStream(this)
	this.control = controlConnection(0, this)
	this.addConnection(this.control)
	this.active = true
	this.RPCOutStream.on('timeout', this.teardown.bind(this))
}
util.inherits(Tunnel, events.EventEmitter)
function make_client_key(remote_pubkey) {
	var keypair = crypto.make_keypair()
	var own_pubkey = keypair.public
	var secret = crypto.shared_secret(remote_pubkey, keypair.private)
	// throw away the private key, we don't need it
	for(var i = 0; i < keypair.private.length; i++) {
		keypair.private[i] = 0
	}
	return {own_pubkey: own_pubkey, secret: secret}
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
	this.emit('gotpacket', recv_pkt)
	recv_pkt.payload.RPC.forEach(function(rpc) {
		rpc.rpc.TID = recv_pkt.TID
		if (recv_pkt.pubKey) rpc.rpc.pubKey = recv_pkt.pubKey
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
	this.RPCOutStream.write({
		cid: this.control.cid,
		rpc: ['nextTid', TID, pubkey]
	})
	var oldTun = this
	var was_empty = false
	var oldOUT = this.RPCOutStream
	this.connections.forEach(function(con) {
		con.outstream.unpipe(oldOUT)
	})
	var newTun = Tunnel.fromRekey(this, crypto.hashSecret(this.secret), TID)
	// replace its connections with the new tunnel
	newTun.control.outstream.unpipe(newTun.RPCOutStream)
	newTun.control = oldTun.control
	newTun.connections = oldTun.connections
	oldTun.emit('rekey', newTun)
	// do not send any data yet
	newTun.RPCOutStream.cwnd = 0
	this.connections.forEach(function(con) {
		con.tunnel = newTun
		newTun.addConnection(con)
	})
	newTun.control = oldTun.control
	newTun.control.callAdv(pubkey, null, 'nextTid', TID, pubkey)
	// we just wrote to it, so it can't be empty now
	oldOUT.once('empty', function() {
		was_empty = true
		oldTun.teardown()
		// this cannot be the old cwnd, because that would allow
		// a reflection attack where the client changes IPs during
		// a rekey just before requesting a big amount of data
		// while the window is big.
		newTun.RPCOutStream.cwnd = 2
		// XXX copy RTT info?
		// do not check if there's a resumeWrite, there should be
		// if there's not something is really wrong
		newTun.RPCOutStream.resumeWrite()
	})
	oldOUT.once('teardown', function() {
		if (!was_empty) {
			newTun.teardown()
		}
	})
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
		tun = new Tunnel(false, recv_pkt.pubKey, key.public, crypto.shared_secret(recv_pkt.pubKey, key.private), recv_pkt.TID)
		return tun
	}
	else throw err
}
Tunnel.clientTunnel = function(key) {
	var keys = make_client_key(key)
	return new Tunnel(true, key, keys.own_pubkey, keys.secret)
}
Tunnel.fromRekey = function(oldTun, secret, TID) {
	var newTun = new Tunnel(oldTun.client, oldTun.remote_pubkey, oldTun.own_pubkey, secret, TID)
	return newTun
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
				if (!memcmp(this.last_recv_pubKey, C_)) {
					// ignore packet, it's fake
					return
				}
				this.tunnel.emit('confirmTid')
			} else {
				var oldTun = this.tunnel
				var was_empty = false
				var was_confirmed = false
				var oldOUT = oldTun.RPCOutStream
				oldTun.connections.forEach(function(con) {
					con.outstream.unpipe(oldOUT)
				})
				var newTun = Tunnel.fromRekey(oldTun, crypto.hashSecret(oldTun.secret), t)
				// replace its connections with the new tunnel
				newTun.control.outstream.unpipe(newTun.RPCOutStream)
				newTun.control = oldTun.control
				newTun.connections = oldTun.connections
				oldTun.emit('rekey', newTun)
				// do not send any data yet
				newTun.RPCOutStream.cwnd = 0
				//newTun.control.callAdv(pubkey, null, 'nextTid', TID, pubkey)
				oldTun.connections.forEach(function(con) {
					con.tunnel = newTun
					newTun.addConnection(con)
				})
				newTun.control = oldTun.control
				// we just wrote to it, so it can't be empty now
				oldOUT.once('empty', function() {
					was_empty = true
					oldTun.teardown()
					onemptyconfirm()
				})
				if (oldOUT.window.length == 0) {
					was_empty = true
					oldTun.teardown()
					onemptyconfirm()
				}
				oldOUT.once('teardown', function() {
					if (!was_empty || !was_confirmed) {
						newTun.teardown()
					}
				})
				newTun.once('confirmTid', function() {
					was_confirmed = true
					onemptyconfirm()
				})
			}
			function onemptyconfirm() {
				if (was_empty && was_confirmed) {
					// this cannot be the old cwnd, because that would allow
					// a reflection attack where the client changes IPs during
					// a rekey just before requesting a big amount of data
					// while the window is big.
					newTun.RPCOutStream.cwnd = 2
					// XXX copy RTT info?
					if (newTun.RPCOutStream.resumeWrite) newTun.RPCOutStream.resumeWrite()
				}
			}
		},
		rekeyNow: function() {
			this.tunnel.reKey()
		},
		create: function(c, y) {
			assert(typeof c == 'number')
			assert(typeof y == 'string')
			var con = new Connection(c, this.tunnel)
			this.tunnel.addConnection(con)
			this.tunnel.emit('create', con, y, null, function(err, rpcs) {
				con.init_cb(err, rpcs)
			})
		},
		createAuth: function(c, y, U, x) {
			assert(typeof c == 'number')
			assert(typeof y == 'string')
			assert(Buffer.isBuffer(U))
			assert(Buffer.isBuffer(x))
			var con = new Connection(c, this.tunnel)
			this.tunnel.addConnection(con)
			this.tunnel.emit('createAuth', con, y, U, x, function(err, rpcs) {
				con.init_cb(err, rpcs)
			})
		},
		ack: function(c) {
			this.tunnel.connections[c].emit('ack')
		},
		refuse: function(c) {
			this.tunnel.connections[c].emit('refuse')
		},
		close: function(c) {
			this.tunnel.connections[c].emit('close')
		},
		requestCert: function(S) {
			assert(Buffer.isBuffer(S))
			this.tunnel.emit('requestCert', S, function(err, cert, eCert) {
				if (err) {
					// TODO: handle error
					void 0
				} else {
					connection.call('giveCert', cert, eCert)
				}
			})
		},
		giveCert: function(certS, ecertS) {
			this.tunnel.emit('giveCert', certS, ecertS, function(err) {
				if (!err) connection.call('ok')
			})
		},
		ok: function() {
			this.tunnel.emit('ok')
		},
		puzz: function(q, H_r, w, n_) {
			var In_ = new Int64(n_)
			var r = auth.solvePuzzleDecoded(this.last_recv_TID, q, H_r, w, In_)
			connection.call('puzzSoln', r, n_)
		},
		puzzSoln: function(r, n_) {
			this.tunnel.emit('puzzSoln', r, n_)
		},
		windowSize: function(c, n) {
			this.tunnel.connections[c].setWindowSize(n)
		}
	})
	return connection
}
