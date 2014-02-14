"use strict";
var crypto = require('./crypto')
var Int64 = require('./Int64')
var assert = require('assert')


// cert:
// - signed
// -signing key
// -boxing key
// -hostname?
function Cert(signed_message, signing, boxing, hostname) {
	this.signing = signing
	this.boxing = boxing
	this.hostname = hostname
	this.signed_message = signed_message
}
Cert.makeSign = function(signing_key, signing, boxing, hostname) {
	var signed = crypto.sign(Cert.encode(signing, boxing, hostname), signing_key)
	return new Cert(signed, signing, boxing, hostname)
}
Cert.encode = function(signing, boxing, hostname) {
	assert(Buffer.isBuffer(signing) && signing.length < 256)
	assert(Buffer.isBuffer(boxing) && boxing.length < 256)
	assert.equal(typeof hostname, 'string')
	var hostname_length = Buffer.byteLength(hostname)
	assert(hostname_length < 256)
	var buf = new Buffer(signing.length + boxing.length + hostname_length + 3)
	var offset = 0
	// write signing key
	buf.writeUInt8(signing.length, offset++)
	signing.copy(buf, offset)
	offset += signing.length

	// write boxing key
	buf.writeUInt8(boxing.length, offset++)
	boxing.copy(buf, offset)
	offset += boxing.length

	// write hostname
	buf.writeUInt8(hostname_length, offset++)
	buf.write(hostname, offset)
	return buf
}
Cert.fromBuffer = function(signing_key, signed_message) {
	var message = crypto.verify(signed_message, signing_key)
	if (message === null) throw new Error("invalid signature")
	var offset = 0
	// read signing key
	var signing_length = message.readUInt8(offset++)
	assert(message.length - offset >= signing_length)
	var signing = message.slice(offset, offset + signing_length)
	offset += signing_length

	// read boxing key
	var boxing_length = message.readUInt8(offset++)
	assert(message.length - offset >= boxing_length)
	var boxing = message.slice(offset, offset + boxing_length)
	offset += boxing_length

	// read hostname
	var hostname_length = message.readUInt8(offset++)
	assert(message.length - offset >= hostname_length)
	var hostname = message.toString('utf8', offset, offset + hostname_length)
	offset += hostname_length

	return new Cert(signed_message, signing, boxing, hostname)
}
Cert.prototype.toBuffer = function() {
	return this.signed_message
}
Cert.prototype.toIdentity = function() {
	return Identity.make(this.signing, this.hostname)
}
Cert.prototype.matches = function(other) {
	if (other instanceof Identity || other instanceof ECert) {
		return memcmp(this.signing, other.signing)
		// TODO: match hostname?
	} else if (other instanceof Cert) {
		return memcmp(this.signing, other.signing) &&
				this.hostname == other.hostname &&
				memcmp(this.boxing, other.boxing)
	} else {
		return false
	}
}


// identifier:
// -signing key
// -hostname (signed?)
function Identity(message, signing, hostname) {
	this.signing = signing
	this.hostname = hostname
	this.message = message
}
Identity.make = function(signing, hostname) {
	assert(Buffer.isBuffer(signing) && signing.length < 256)
	assert.equal(typeof hostname, 'string')
	var hostname_length = Buffer.byteLength(hostname)
	assert(hostname_length < 256)
	var buf = new Buffer(signing.length + hostname_length + 2)
	var offset = 0
	// write signing key
	buf.writeUInt8(signing.length, offset++)
	signing.copy(buf, offset)
	offset += signing.length

	// write hostname
	buf.writeUInt8(hostname_length, offset++)
	buf.write(hostname, offset)
	return new Identity(buf, signing, hostname)
}
Identity.fromBuffer = function(message) {
	var offset = 0
	// read signing key
	var signing_length = message.readUInt8(offset++)
	assert(message.length - offset >= signing_length)
	var signing = message.slice(offset, offset + signing_length)
	offset += signing_length


	// read hostname
	var hostname_length = message.readUInt8(offset++)
	assert(message.length - offset >= hostname_length)
	var hostname = message.toString('utf8', offset, offset + hostname_length)
	offset += hostname_length

	return new Identity(message, signing, hostname)
}
Identity.prototype.toBuffer = function() {
	return this.message
}
Identity.prototype.matches = function(other) {
	if (other instanceof Cert || other instanceof ECert) {
		return memcmp(this.signing, other.signing)
		// TODO: match hostname?
	} else if (other instanceof Identity) {
		return memcmp(this.signing, other.signing) && this.hostname == other.hostname
	} else {
		return false
	}
}


// eCert:
// -signed by signing key
// -IP
// -port
// -version
// -padding
// -signing key
// -boxing key?
// - ephemeral boxing key
// -lifetime (UTC start+end?)

function ECert(signed_message, ip, port, version, padding, signing, eBoxing, lifetime) {
	this.signed_message = signed_message
	this.ip = ip
	this.port = port
	this.version = version
	this.padding = padding
	this.signing = signing
	this.eBoxing = eBoxing
	this.lifetime = lifetime
}
ECert.makeSign = function(signing_key, ip, port, version, padding, signing, eBoxing, lifetime) {
	var signed = crypto.sign(ECert.encode(ip, port, version, padding, signing, eBoxing, lifetime), signing_key)
	return new ECert(signed, ip, port, version, padding, signing, eBoxing, lifetime)
}
ECert.encode = function(ip, port, version, padding, signing, eBoxing, lifetime) {
	assert(Buffer.isBuffer(signing) && signing.length < 256)
	assert(Buffer.isBuffer(eBoxing) && eBoxing.length < 256)

	var buf = new Buffer(signing.length + eBoxing.length + 16)
	var offset = 0
	// write IP
	buf.writeUInt32BE(convertIPtoUInt32(ip), offset)
	offset += 4
	// write port
	buf.writeUInt16BE(port, offset)
	offset += 2
	// write version
	buf.writeUInt16BE(version, offset)
	offset += 2
	// write padding
	buf.writeUInt16BE(padding, offset)
	offset += 2
	// write signing key
	buf.writeUInt8(signing.length, offset++)
	signing.copy(buf, offset)
	offset += signing.length

	// write ephemeral boxing key
	buf.writeUInt8(eBoxing.length, offset++)
	eBoxing.copy(buf, offset)
	offset += eBoxing.length


	// write lifetime
	void (new Int64(lifetime)).getBuffer().copy(offset)
	offset += 8
	assert.equal(offset, buf.length)
	return buf
}
ECert.fromBuffer = function(signing_key, signed_message) {
	var message = crypto.verify(signed_message, signing_key)
	if (message === null) throw new Error("invalid signature")
	var offset = 0

	// write IP
	var ip = convertIPtoUInt32(message.readUint32BE(offset))
	offset += 4
	// write port
	var port = message.readUInt16BE(offset)
	offset += 2
	// write version
	var version = message.readUInt16BE(offset)
	offset += 2
	// write padding
	var padding = message.readUInt16BE(offset)
	offset += 2

	// read signing key
	var signing_length = message.readUInt8(offset++)
	assert(message.length - offset >= signing_length)
	var signing = message.slice(offset, offset + signing_length)
	offset += signing_length
	if (!memcmp(signing_key, signing))
		throw new Error("signature doesn't match signing key")

	// read eBoxing key
	var eBoxing_length = message.readUInt8(offset++)
	assert(message.length - offset >= eBoxing_length)
	var eBoxing = message.slice(offset, offset + eBoxing_length)
	offset += eBoxing_length

	// read lifetime
	var lifetime = (new Int64(message, offset)).toNumber(false)
	offset += 8

	assert.equal(offset, message.length)

	return new ECert(signed_message, ip, port, version, padding, signing, eBoxing, lifetime)
}
ECert.prototype.toBuffer = function() {
	return this.signed_message
}
ECert.prototype.matches = function(other) {
	if (other instanceof Cert || other instanceof Identity) {
		return memcmp(this.signing, other.signing)
		// TODO: match hostname?
	} else if (other instanceof ECert) {
		return memcmp(this.signing, other.signing) &&
				memcmp(this.eBoxing, other.eBoxing) &&
				this.ip == other.ip &&
				this.port == other.port &&
				this.version == other.version &&
				this.padding == other.padding &&
				this.lifetime == other.lifetime
	} else {
		return false
	}
}

module.exports.Identity = Identity
module.exports.Cert = Cert
module.exports.ECert = ECert

function convertIPtoUInt32(IP) {
	assert(typeof IP == 'string' && IP.length <= 15)
	var d = IP.split('.');
	return ((((((+d[0])*256)+(+d[1]))*256)+(+d[2]))*256)+(+d[3])
}

function convertUInt32toIP(num) {
	var d = num%256
	for (var i = 3; i > 0; i--) {
		num = Math.floor(num/256)
		d = num%256 + '.' + d
	}
	return d
}

function memcmp(a, b) {
	if (a.length != b.length) return false
	for (var i = 0; i < a.length; i++) {
		if (a[i] != b[i]) return false
	}
	return true
}
