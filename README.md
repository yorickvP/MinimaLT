after you get js-nacl to work, replace the extractbytes function in lib/nacl_factory.js with

    function extractBytes(address, length) {
        var result = new Buffer(nacl_raw.HEAPU8.subarray(address, address + length));
	    return result;
    }


this module is very very incomplete, the only thing it can do now is connect-by-ecert and only over a lossless link with a high enough MTU and be careful not to specify more than 512 bytes of arguments over rpcs.
