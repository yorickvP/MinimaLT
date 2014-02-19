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

function Socket(port, ext_ip) {
	events.EventEmitter.call(this)
	this.tunnels = []
	this.socket  = dgram.createSocket('udp4')
	if (port) this.port = port
	else this.port = ((Math.random()*(1<<15)) + (1<<15) - 1)|0
	DEBUG("making new socket @ port", this.port)
	this.socket.bind(this.port)
	this.acceptUnknown = false
	var self = this
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
			if(self.acceptUnknown) {
				DEBUG("accepting new tunnel from", rinfo)
				var tun = Tunnel.fromFirstPacket(self, pkt, rinfo, self.decoding_keys)
				self.addTunnel(tun, rinfo.ip, rinfo.port)
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
	this.rotateECert()
}
Socket.prototype.rotateECert = function() {
	// TODO: actually rotate
	DEBUG('generating eCert')
	var ecert = this.certificate.generateECert(this.long_signing, this.ext_ip, this.port, 0, 0, 12e5)
	this.decoding_keys.push(ecert.eBoxing)
	this.ephemeral_certificate = ecert.eCert
}
Socket.prototype.advertise = function(name_service, cb) {
	var self = this
	this.lookupIdent(name_service, function(cert, eCert) {
		var tun = self.makeTunECert(eCert)
		tun.control.call('giveCert', self.certificate.toBuffer(), self.ephemeral_certificate.toBuffer())
		tun.once('ok', cb)
		// TODO: update on new ecert
	})
}
Socket.prototype.setDomainService = function(ip, port, certD) {
	DEBUG('connecting to domain service', ip, ':', port)
	var T1 = new Tunnel(certD.boxing)
	this.addTunnel(T1, ip, port)
	T1.control.callAdv(T1.own_pubkey, null, 'requestCert', certD.toIdentity().toBuffer())
	var self = this
	T1.once('giveCert', function(brec_certD, brec_ecertD) {
		var rec_certD = certificate.Cert.fromBuffer(certD.signing, brec_certD)
		var rec_ecertD = certificate.ECert.fromBuffer(certD.signing, brec_ecertD)
		assert(certD.matches(rec_certD))
		assert(certD.matches(rec_ecertD))
		self.domain_T2 = self.makeTunECert(rec_ecertD)
		self.emit('domainservice')
	})
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
