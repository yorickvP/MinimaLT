

var minimaLT = require('./index.js')
var server_cert = minimaLT.generate_servercert('a.localhost')
var server = minimaLT.listen('127.0.0.1', 21398, server_cert, function(con, servicename, auth, cb){

	if (servicename == 'my_thing') {
		cb(null, {
			ping: function(x) {
				console.log('OMG PING:', x)
				con.call('pong', x)
			}
		})
	}
})

//var connection = client.connectECert(server.ephemeral_certificate, "my_thing", null, {
//	pong: function(x) {
//		console.log("OMG PONG:", x)
//	}
//})
//connection.call('ping', 42)

var known_certs = []


var name_cert = minimaLT.generate_servercert('name.localhost')
var nameservice = minimaLT.nameservice('127.0.0.1', 21397, name_cert, function(cert, eCert, cb) {
	console.log('got certificate from client')
	known_certs.push([cert, eCert])
	cb(null)
})

known_certs.push([name_cert.cert, nameservice.ephemeral_certificate])
//known_certs.push([server_cert.cert, server.ephemeral_certificate])

var domain_cert = minimaLT.generate_servercert('domain.localhost')
var domainservice = minimaLT.domainservice('127.0.0.1', 21396, domain_cert, function(ident, cb) {
	console.log("got domain service request", ident)
	known_certs.some(function(certpair) {
		if (ident.matches(certpair[0])) {
			cb(null, certpair[0].toBuffer(), certpair[1].toBuffer())
		}
	})
	// if (ident.matches(name_cert.cert)) {
})

server.setDomainService('127.0.0.1', 21396, domain_cert.cert)
server.advertise(name_cert.cert.toIdentity(), function() {

	var client = minimaLT.client('127.0.0.1', 21396, domain_cert.cert)

	client.connect(server_cert.cert.toIdentity(), "my_thing", null, function(connection) {
		connection.call('ping', 42)
		return {
			pong: function(x) {
				console.log("OMG PONG:", x)
			}
		}
	})
})
