

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

var domain_cert = minimaLT.generate_servercert('domain.localhost')
var domainservice = minimaLT.domainservice('127.0.0.1', 21396, domain_cert, function(ident, cb) {
	console.log("got domain service request", ident)
	if (ident.matches(server_cert.cert)) {
		cb(null, server_cert.cert.toBuffer(), server.ephemeral_certificate.toBuffer())
	}
})

var client = minimaLT.client('127.0.0.1', 21396, domain_cert.cert)

client.connect(server_cert.cert.toIdentity(), "my_thing", null, function(connection) {
	connection.call('ping', 42)
	return {
		pong: function(x) {
			console.log("OMG PONG:", x)
		}
	}
})
