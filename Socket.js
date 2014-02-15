"use strict";
var dgram = require('dgram')
var Tunnel = require('./Tunnel')
var packet = require('./packet')
var crypto = require('./crypto')
var util = require('util')
var events = require('events')
var assert = require('assert')

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
	this.tunnels.push(tun)
}
Socket.prototype.connectECert = function(eCert, servicename, own_auth_key, rpcs) {
	assert.equal(eCert.version, 0)
	assert.equal(eCert.padding, 0)
	DEBUG('connecting to', eCert.ip, ':', eCert.port, '(eCert)')
	var tun = new Tunnel(eCert.eBoxing)
	this.addTunnel(tun, eCert.ip, eCert.port)
	tun.send_connect()
	return tun.create(servicename, own_auth_key, rpcs)
}
Socket.prototype.listen = function(ext_ip, cert, signing, boxing, accept) {
	DEBUG('accepting unknown connections, generating key')
	this.acceptUnknown = true
	this.ext_ip = ext_ip
	// if accept, allow connections to be encrypted using the long-term
	// server key
	if (accept) {
		this.decoding_keys.push(boxing)
	}
	this.long_signing = signing
	this.certificate = cert
	this.rotateECert()
}
Socket.prototype.rotateECert = function() {
	// TODO: actually rotate
	DEBUG('generating ECert')
	var ecert = this.certificate.generateECert(this.long_signing, this.ext_ip, this.port, 0, 0, 12e5)
	this.decoding_keys.push(ecert.eBoxing)
	this.ephemeral_certificate = ecert.eCert
}
Socket.prototype.setDomainService = function(ip, port, certD) {
	DEBUG('setting domain service to', ip, ':', port)
	// certS -> key
	var key = certD
	var D = certD
	var T1 = new Tunnel(key)
	this.addTunnel(T1, ip, port)
	T1.do_rpc(0, ['requestCert', D], certD.toIdentity().toBuffer())
	T1.on('giveCert', function(rec_certD, rec_ecertD) {
		//assert.equal(certS, rec_certS)
		//verify(rec_ecertS)
		DEBUG('got ecertD')
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
