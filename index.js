var Socket = require('./Socket.js')
var crypto = require('./crypto.js')
var certificate = require('./certificate.js')

module.exports.listen = function(ext_ip, port, key, cb) {
	var server = new Socket(port)
	server.listen(ext_ip, key.cert, key.signing, key.boxing, false)
	server.on('create', cb)
	return server
}
module.exports.client = function(ip, port, domain_service) {
	var client = new Socket()
	if (arguments.length >= 3) {
		client.setDomainService(ip, port, domain_service)
	}
	return client
}
module.exports.domainservice = function(ext_ip, port, key, cb) {
	var server = new Socket(port)
	server.listen(ext_ip, key.cert, key.signing, key.boxing, true)
	server.on('requestCert', function(bident, cert_cb) {
		var ident = certificate.Identity.fromBuffer(bident)
		if (ident.matches(server.ephemeral_certificate)) {
			cert_cb(null, server.certificate.toBuffer(), server.ephemeral_certificate.toBuffer())
		} else {
			cb(ident, cert_cb)
		}
	})
	return server
}
module.exports.nameservice = function(ext_ip, port, key, cb) {
	var server = new Socket(port)
	server.listen(ext_ip, key.cert, key.signing, key.boxing, false)
	server.on('giveCert', cb)
	return server
}
module.exports.generate_servercert = function(hostname) {
	var signing = crypto.make_signing_keypair()
	var boxing  = crypto.make_keypair()
	var cert = certificate.Cert.makeSign(signing.private, signing.public, boxing.public, hostname)
	return {
		cert: cert,
		signing: signing,
		boxing: boxing
	}
}
