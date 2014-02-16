MinimaLT-experimental
========

This is an approximation of the MinimaLT protocol, described in [MinimaLT: Minimal-latency Networking Through Better Security, CCS'13, Nov, 2013 (W. Michael Petullo, Xu Zhang, Jon A. Solworth, Daniel J. Bernstein, Tanja Lange).][1]
Some changes had to be made to accomodate a node.js userspace implementation, and some guesses had to be made to the meaning of the things described in the paper.

For now, this module is very incomplete. The absolute basics are there, but right now, there is no resistance against packet loss, errors, and no congestion control. Furthermore, there is no protection against sending packets bigger than the MTU, which will silently be dropped. I am not at all sure that the encryption is correct. You should probably not use this anywhere near practice.

## Getting it to work

The installation should be simple, an `npm install` call should suffice. Afterwards, , replace the extractbytes function in `node_modules/js-nacl/lib/nacl_factory.js` with

    function extractBytes(address, length) {
        var result = new Buffer(nacl_raw.HEAPU8.subarray(address, address + length));
	    return result;
    }


## Running the tests

The tests use mocha, so run `mocha`.

[1]: http://www.ethos-os.org/~solworth/minimalt-20131031.pdf
