var events = require('events')
var util = require('util')
var stream = require('stream')

function DEBUG(con, str) {
	console.log.apply(console, ["Connection:", con.cid].concat([].slice.call(arguments, 1)))
}

function Connection(id, tunnel, noflow) {
	events.EventEmitter.call(this)
	this.tunnel = tunnel
	this.cid = id
	this.initialized = false
	this.recv_queue = []
	this.outstream = new (noflow ? stream.PassThrough : WindowedOutStream)({objectMode: true})
	this.instream = new (noflow ? stream.PassThrough : WindowedInStream)({objectMode: true})
	this.noflow = !!noflow
	this.on('refuse', function() {
		delete this.tunnel.connections[this.cid]
	})
	this.on('close', function() {
		delete this.tunnel.connections[this.cid]
	})
	var self = this
	this.instream.on('window', function(x) {
		self.windowSize(16 - x)
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
	this.tunnel.control.call('ack', this.cid)
	this.tunnel.connections[this.cid] = this
}
Connection.prototype.refuse = function() {
	this.tunnel.control.call('refuse', this.cid)
}
Connection.prototype.close = function() {
	this.tunnel.control.call('close', this.cid)
	delete this.tunnel.connections[this.cid]
}
Connection.prototype.setRPCs = function(rpcs) {
	this.rpc = rpcs
	this.initialized = true
	var self = this
	this.instream.on('data', function(rpc) {
		self.receive(rpc)
	})
}
Connection.prototype.setWindowSize = function(windowsize) {
	if (!this.noflow) this.outstream.setWnd(windowsize)
}
Connection.prototype.windowSize = function(windowSize) {
	this.tunnel.control.call('windowSize', this.cid, windowSize)
}

Connection.prototype.receive = function(rpc){
	//DEBUG(this, "got rpc", rpc)
	if (this.initialized) {
		var name = rpc[0]
		var args = rpc.slice(1)
		if (this.rpc[name]) this.rpc[name].apply(this, args)
		// else fail?
	} else {
		throw new Error("you should be writing to con.instream")
	}
}
Connection.prototype.call = function(name, args) {
	this.callAdv.apply(this, [null, null].concat([].slice.call(arguments)))
}
Connection.prototype.callAdv = function(pubkey, puzzle, name, args) {
	this.outstream.write({
		cid: this.cid,
		pubkey: pubkey,
		rpc: [].slice.call(arguments, 2)
	})
}
Connection.prototype.ackRPC = function() {
	if (!this.noflow) this.outstream.ackRPC()
}

module.exports = Connection
util.inherits(WindowedOutStream, stream.Transform);

function WindowedOutStream(options) {
	if (!(this instanceof WindowedOutStream))
		return new WindowedOutStream(options)

	stream.Transform.call(this, options)
	this.window_size = 4
}

WindowedOutStream.prototype._transform = function(chunk, encoding, cb) {
	var self = this 
	function checkwrite() {
		if (self.window_size > 0) {
			cb(null, chunk)
			self.window_size--;
			self.resume_write = null
		} else {
			console.log('queuing')
			self.resume_write = checkwrite
		}
	}
	checkwrite()
}
WindowedOutStream.prototype.setWnd = function(window) {
	this.window_size = window
	if (this.resume_write) this.resume_write()
}
WindowedOutStream.prototype.ackRPC = function() {
	this.window_size++
	if (this.resume_write) this.resume_write()
}
util.inherits(WindowedInStream, stream.PassThrough);

function WindowedInStream(options) {
	if (!(this instanceof WindowedInStream))
		return new WindowedInStream(options)

	stream.PassThrough.call(this, options)
	this.window_size = 0
	this.set_window_size = false
}
WindowedInStream.prototype.sendWindowSize = function() {
	if (this.set_window_size) return
	var self = this
	this.set_window_size = true
	process.nextTick(function(){
		this.set_window_size = false
		self.emit('window', self.window_size)
	})
}

WindowedInStream.prototype.write = function() {
	this.window_size++
	this.sendWindowSize()
	return stream.PassThrough.prototype.write.apply(this, arguments)
}
WindowedInStream.prototype.read = function() {
	var ret = stream.PassThrough.prototype.read.apply(this, arguments)
	if (ret != null) {
		this.window_size--
		this.sendWindowSize()
	}
	return ret
}
