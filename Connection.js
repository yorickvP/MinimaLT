var events = require('events')
var util = require('util')

function DEBUG(con, str) {
	console.log.apply(console, ["Connection:", con.cid].concat([].slice.call(arguments, 1)))
}

function Connection(id, tunnel) {
	events.EventEmitter.call(this)
	this.tunnel = tunnel
	this.cid = id
	this.initialized = false
	this.recv_queue = []
	this.on('refuse', function() {
		delete this.tunnel.connections[this.cid]
	})
	this.on('close', function() {
		delete this.tunnel.connections[this.cid]
	})
}
util.inherits(Connection, events.EventEmitter)
Connection.prototype.init_cb = function(err, rpcs) {
	DEBUG(this, 'sending connection response', err)
	if (err) this.refuse()
	else {
		this.ack()
		this.setRPCs(rpcs)
	}
}
Connection.prototype.ack = function() {
	this.tunnel.connections[0].call('ack', this.cid)
	this.tunnel.connections[this.cid] = this
}
Connection.prototype.refuse = function() {
	this.tunnel.connections[0].call('refuse', this.cid)
}
Connection.prototype.close = function() {
	this.tunnel.connections[0].call('close', this.cid)
	delete this.tunnel.connections[this.cid]
}
Connection.prototype.setRPCs = function(rpcs) {
	this.rpc = rpcs
	this.initialized = true
	var self = this
	this.recv_queue.forEach(function(rpc) {
		self.receive(rpc)
	})
}

Connection.prototype.receive = function(rpc){
	//DEBUG(this, "got rpc", rpc)
	if (this.initialized) {
		var name = rpc[0]
		var args = rpc.slice(1)
		if (this.rpc[name]) this.rpc[name].apply(this, args)
		// else fail?
	} else {
		this.recv_queue.push(rpc)
	}
}
Connection.prototype.call = function(name, args) {
	this.tunnel.do_rpc(this.cid, [].slice.call(arguments))
}

module.exports = Connection
