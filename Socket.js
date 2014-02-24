"use strict";
var dgram = require('dgram')
var Tunnel = require('./Tunnel')
var packet = require('./packet')
var crypto = require('./crypto')
var util = require('util')
var events = require('events')
var assert = require('assert')
var certificate = require('./certificate')
var auth = require('./auth')

function DEBUG(str) {
	console.log.apply(console, ["Socket:"].concat([].slice.call(arguments)))
}

function memcmp(a, b) {
	if (a.length != b.length) return false
	for (var i = 0; i < a.length; i++) {
		if (a[i] != b[i]) return false
	}
	return true
}

function Socket(port, ext_ip) {
	events.EventEmitter.call(this)
	this.tunnels = []
	this.socket  = dgram.createSocket('udp4')
	if (port) this.port = port
	else this.port = ((Math.random()*(1<<15)) + (1<<15) - 1)|0
	DEBUG("making new socket @ port", this.port)
	var self = this
	this.socket.bind(this.port)
	this.acceptUnknown = false
	this.decoding_keys = []
	this.socket.on('message', function(msg, rinfo) {
		var pkt = packet.parsePacket(msg)
		if (!self.tunnels.some(function(tun){
			if (tun.TID.equal(pkt.TID)) {
				tun.recv_packet(pkt, rinfo)
				return true
			}
			return false
		})){
			if(self.acceptUnknown && pkt.hasPubKey) {
				// check if the pubkey isn't used anywhere
				if (self.tunnels.some(function(tun) {
					return tun.remote_pubkey && memcmp(tun.remote_pubkey, pkt.pubKey)
				})) return
				DEBUG("accepting new tunnel from", rinfo)
				var tun = Tunnel.fromFirstPacket(self, pkt, rinfo, self.decoding_keys)
				self.addTunnel(tun, rinfo.address, rinfo.port)
				// fromFirstPacket decrypts the packet
				tun.recv_decrypted_packet(pkt, rinfo)
			}
		}
	})
}
util.inherits(Socket, events.EventEmitter)
Socket.prototype.addTunnel = function(tun, ip, port) {
	DEBUG('binding tunnel', tun.TID.getBuffer().toString('hex'))
	tun.on('sendpacket', make_sendpacket(this.socket, ip, port))
	var self = this
	tun.on('create', function() {
		self.emit.apply(self, ['create'].concat([].slice.call(arguments)))
	})
	tun.on('createAuth', function(con, y, U, x, cb) {
		if (auth.verifyUserAuth(x, self.long_boxing, U)) {
			self.emit('create', con, y, U, cb)
		}
	})
	tun.on('requestCert', function() {
		self.emit.apply(self, ['requestCert'].concat([].slice.call(arguments)))
	})
	tun.on('giveCert', function(brec_certD, brec_ecertD, cb) {
		var rec_certD, rec_ecertD
		try {
			rec_certD = certificate.Cert.fromBufferNoKey(brec_certD)
			rec_ecertD = certificate.ECert.fromBuffer(rec_certD.signing, brec_ecertD)
			assert(rec_certD.matches(rec_ecertD))
		} catch(e) { return }
		self.emit('giveCert', rec_certD, rec_ecertD, cb)
	})
	tun.on('teardown', function() {
		self.tunnels = self.tunnels.filter(function(x) { return x != tun })
	})
	this.tunnels.push(tun)
}
Socket.prototype.makeTunECert = function(eCert) {
	assert.equal(eCert.version, 0)
	assert.equal(eCert.padding, 0)
	DEBUG('connecting to', eCert.ip, ':', eCert.port, '(eCert)')
	var tun = new Tunnel(eCert.eBoxing)
	this.addTunnel(tun, eCert.ip, eCert.port)
	tun.send_connect()
	return tun
}
Socket.prototype.lookupIdent = function(ident, cb) {
	DEBUG('looking up', ident.hostname)
	var self = this
	function givecert_cb(brec_certD, brec_ecertD) {
		var rec_certD, rec_ecertD
		try {
			rec_certD = certificate.Cert.fromBuffer(ident.signing, brec_certD)
			rec_ecertD = certificate.ECert.fromBuffer(ident.signing, brec_ecertD)
			assert(rec_certD.matches(rec_ecertD))
			assert(ident.matches(rec_ecertD))
		} catch(e) { return }
		self.domain_T2.removeListener('giveCert', givecert_cb)
		cb(rec_certD, rec_ecertD)
	}
	if (this.domain_T2) {
		this.domain_T2.control.call('requestCert', ident.toBuffer())
		this.domain_T2.on('giveCert', givecert_cb)
	} else {
		this.once('domainservice', function() {
			self.lookupIdent(ident, cb)
		})
	}
}
Socket.prototype.connect = function(ident, servicename, own_auth_key, cb) {
	var self = this
	this.lookupIdent(ident, function(cert, ecert) {
		var con = self.connectECert(cert, ecert, servicename, own_auth_key)
		con.setRPCs(cb(con))
	})
}
Socket.prototype.connectECert = function(cert, eCert, servicename, own_auth_key, rpcs) {
	var tun = this.makeTunECert(eCert)
	if (own_auth_key != null) {
		var auth_msg = auth.makeUserAuth(own_auth_key, cert.boxing)
		return tun.createAuth(servicename, own_auth_key.public, auth_msg, rpcs)
	} else {
		return tun.create(servicename, rpcs)
	}
}
Socket.prototype.listen = function(ext_ip, cert, signing, boxing, accept) {
	DEBUG('accepting connections')
	this.acceptUnknown = true
	this.ext_ip = ext_ip
	// if accept, allow connections to be encrypted using the long-term
	// server key
	if (accept) {
		this.decoding_keys.push(boxing)
	}
	this.long_signing = signing
	this.long_boxing  = boxing
	this.certificate = cert
	// these values should be configurable
	this.rotateECert(1200, 150)
	this.puzzle_key = crypto.make_keypair().private
	setTimeout(this.garbageCollect.bind(this), 120*1e3)
}
// make a new ECert, delete the old one after dns_ttl seconds
// and do it again after `lifetime` seconds
Socket.prototype.rotateECert = function(lifetime, dns_ttl) {
	var self = this
	if (this.ephemeral_certificate) {
		var old_decoding = this.current_ephemeral_decoding
		setTimeout(function() {
			// remove the old key after the DNS TTL
			self.decoding_keys = self.decoding_keys.filter(function(key) {
				return !memcmp(old_decoding, key)
			})
		}, dns_ttl*1e3)
	}
	DEBUG('generating eCert')
	var ecert = this.certificate.generateECert(this.long_signing, this.ext_ip, this.port, 0, 0, lifetime*1e3)
	this.decoding_keys.push(ecert.eBoxing)
	this.current_ephemeral_decoding = ecert.eBoxing
	this.ephemeral_certificate = ecert.eCert
	this.emit('ecert', ecert.eCert)
	setTimeout(function() {
		self.rotateECert(lifetime, dns_ttl)
	}, lifetime*1e3)
}
Socket.prototype.advertise = function(name_service, cb) {
	var self = this
	this.lookupIdent(name_service, function(cert, eCert) {
		var tun = self.makeTunECert(eCert)
		tun.control.call('giveCert', self.certificate.toBuffer(), self.ephemeral_certificate.toBuffer())
		tun.once('ok', cb)
		self.on('ecert', function(ecert) {
			tun.control.call('giveCert', self.certificate.toBuffer(), self.ephemeral_certificate.toBuffer())
		})
	})
}
Socket.prototype.setDomainService = function(ip, port, certD) {
	DEBUG('connecting to domain service', ip, ':', port)
	var T1 = new Tunnel(certD.boxing)
	this.addTunnel(T1, ip, port)
	T1.control.callAdv(T1.own_pubkey, null, 'requestCert', certD.toIdentity().toBuffer())
	var self = this
	T1.once('giveCert', function(brec_certD, brec_ecertD) {
		T1.teardown()
		var rec_certD = certificate.Cert.fromBuffer(certD.signing, brec_certD)
		var rec_ecertD = certificate.ECert.fromBuffer(certD.signing, brec_ecertD)
		assert(certD.matches(rec_certD))
		assert(certD.matches(rec_ecertD))
		self.domain_T2 = self.makeTunECert(rec_ecertD)
		self.emit('domainservice')
	})
}
// TODO: vary difficulty and interval based on server load
Socket.prototype.garbageCollect = function() {
	var self = this
	this.tunnels.forEach(function(tun) {
		var solved = false
		// give the client a minute
		var timeout = setTimeout(function() {
			tun.teardown()
		}, 60*1e3)
		tun.posePuzzle(self.puzzle_key, 8, function(res) {
			clearTimeout(timeout)
			if (!res) return tun.teardown()
		})
	})
	setTimeout(this.garbageCollect.bind(this), 120*1e3)
}

function make_sendpacket(socket, ip, port) {
	return function(packet) {
		socket.send(packet, 0, packet.length, port, ip, function(err, bytes) {
			// TODO: handle error
			// TODO: ip mobility
		})
	}
}

module.exports = Socket
