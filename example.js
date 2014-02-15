

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

var client = minimaLT.client()
var connection = client.connectECert(server.ephemeral_certificate, "my_thing", null, {
	pong: function(x) {
		console.log("OMG PONG:", x)
	}
})
connection.call('ping', 42)
