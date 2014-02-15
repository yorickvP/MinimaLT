var Socket = require('./Socket.js')
var crypto = require('./crypto.js')
var certificate = require('./certificate.js')

module.exports.listen = function(ext_ip, port, key, cb) {
	var server = new Socket(port)
	server.listen(ext_ip, key.cert, key.signing, key.boxing, false)
	server.on('create', cb)
	return server
}
module.exports.client = function(domain_service, ip, port) {
	var client = new Socket()
	if (arguments.length >= 3) {
		client.setDomainService(domain_service, ip, port)
	}
	return client
}
module.exports.domainservice = function(key, port, cb) {
	var server = new Socket(port)
	server.listen(key.cert, key.signing, key.boxing, true)
	server.on('requestCert', function(cert, cert_cb) {
		if (cert == key.public) {
			cb(null, server.getECert(key))
		} else {
			cb(cert, cert_cb)
		}
	})
	return server
}
module.exports.nameservice = function(port, cb) {
	var server = new Socket(port)
	server.listen()
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
