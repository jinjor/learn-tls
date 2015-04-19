var net = require('net');
var fs = require('fs');
var assert = require('assert');

var b = {
	uint8: function(num) {
		var buf = new Buffer(1);
		buf.writeUInt8(num);
		return buf;
	},
	uint16: function(num) {
		var buf = new Buffer(2);
		buf.writeUInt16BE(num);
		return buf;
	},
	uint24: function(num) {
		var buf = new Buffer(3);
		buf.writeUInt8(num >> 16);
		buf.writeUInt16BE(num, 1);
		return buf;
	},
	uint32: function(num) {
		var buf = new Buffer(4);
		buf.writeUInt32BE(num);
		return buf;
	}
};

function assertEquals(a, b) {
	if (a !== b) {
		throw new Error('not the same: ' + a + ', ' + b);
	}
}


var server = net.createServer(function(c) { //'connection' listener
	console.log('client connected');
	var context = {
		key: fs.readFileSync('ssl/server.key'),
		cert: fs.readFileSync('ssl/server.crt')
	};
	c.on('end', function() {
		console.log('client disconnected');
	});
	c.on('data', function(buf) {
		console.log('------------------------------');
		var type = buf[0];
		buf = buf.slice(1);
		var protocolVersion = readProtocolVersion(buf);
		buf = buf.slice(protocolVersion._length);
		var length = buf.readUInt16BE();
		buf = buf.slice(2);
		console.log(protocolVersion);
		// if(protocolVersion.minor !== 3) {
		// 	return;
		// }

		if (type === 20) {
			console.log('change_cipher_spec');
		} else if (type === 21) {
			console.log('alert');
			var alert = readAlert(context, buf);
			console.log(alert);
		} else if (type === 22) {
			console.log('handshake');
			var handshake = readHandshake(context, buf);

			// TODO: TLS_FALLBACK_SCSV
			// inappropriate_fallback alert for TLS/1.1, 1.0

			// console.log(handshake.body);
			buf = buf.slice(handshake._length);
			sendServerHello(c, context, handshake.body);
			sendCertificate(c, context);
			// sendServerKeyExchange(c, context);
			// sendCertificateRequest(c, context);
			// sendServerHelloDone(c, context);
		} else if (type === 23) {
			console.log('application_data');
		} else {
			console.log('?');
		}

		// c.write('HTTP/1.1 200 OK\r\n');
		// // c.write('Connection: close\r\n');
		// c.write('\r\n');
		// c.write('hello\r\n');
		// c.end();
	});
	// c.end();

});



// struct {
//   HandshakeType msg_type;    /* handshake type */
//   uint24 length;             /* bytes in message */
//   select (HandshakeType) {
//       case hello_request:       HelloRequest;
//       case client_hello:        ClientHello;
//       case server_hello:        ServerHello;
//       case certificate:         Certificate;
//       case server_key_exchange: ServerKeyExchange;
//       case certificate_request: CertificateRequest;
//       case server_hello_done:   ServerHelloDone;
//       case certificate_verify:  CertificateVerify;
//       case client_key_exchange: ClientKeyExchange;
//       case finished:            Finished;
//   } body;
// } Handshake;
function readHandshake(context, buf) {
	var msg_type = buf[0];
	var length = buf.readUInt32BE(1) >> 8;
	// console.log(msg_type, length);
	buf = buf.slice(4);
	var body;
	if (msg_type === 1) {
		console.log('ClientHello');
		var clientHello = readClientHello(buf, length);
		console.log(clientHello.client_version);
		logExtensions(clientHello.extensions);
		body = clientHello;
		clientHello.cipher_suites.forEach(function(pair) {
			var name = nameOfCipherSuite(pair);
			console.log(name || pair);
		});
	} else if (msg_type === 11) {
		console.log('certificate');
	} else {
		console.log('msg_type = ' + msg_type);
		//TODO: unexpected_message alert.
	}
	return {
		msg_type: msg_type,
		body: body,
		_length: length
	};
}


// struct {
//     AlertLevel level;
//     AlertDescription description;
// } Alert;
function readAlert(context, buf) {
	var alert = {
		level: buf[0],
		description: buf[1]
	};
	return alert;
}


// struct {
//     ProtocolVersion client_version;
//     Random random;
//     SessionID session_id;
//     CipherSuite cipher_suites<2..2^16-2>;
//     CompressionMethod compression_methods<1..2^8-1>;
//     select (extensions_present) {
//         case false:
//             struct {};
//         case true:
//             Extension extensions<0..2^16-1>;
//     };
// } ClientHello;
function readClientHello(buf, length) {
	var client_version = readProtocolVersion(buf);
	buf = buf.slice(client_version._length);
	var random = readRandom(buf);
	buf = buf.slice(random._length);
	var sessionIdLength = buf[0];
	var session_id;
	if (sessionIdLength) {
		console.log('sessionIdLength: ' + sessionIdLength);
		// assert(false); //not implemented
	}
	buf = buf.slice(1 + sessionIdLength);

	var cipherSuitesLength = buf.readUInt16BE();
	buf = buf.slice(2);
	var cipher_suites = [];
	for (var i = 0; i < cipherSuitesLength / 2; i++) {
		cipher_suites.push([buf.readUInt8(), buf.readUInt8(1)])
		buf = buf.slice(2);
	}
	var compressionMethodsLength = buf[0];
	// console.log('compressionMethodsLength', compressionMethodsLength);
	buf = buf.slice(1);
	var compression_methods = buf.slice(0, compressionMethodsLength);
	buf = buf.slice(compressionMethodsLength);

	var extensions = readExtensions(buf);


	return {
		client_version: client_version,
		random: random,
		cipher_suites: cipher_suites,
		compression_methods: compression_methods,
		extensions: extensions
	};
}

// http://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
// 0	server_name	[RFC6066]
// 1	max_fragment_length	[RFC6066]
// 2	client_certificate_url	[RFC6066]
// 3	trusted_ca_keys	[RFC6066]
// 4	truncated_hmac	[RFC6066]
// 5	status_request	[RFC6066]
// 6	user_mapping	[RFC4681]
// 7	client_authz	[RFC5878]
// 8	server_authz	[RFC5878]
// 9	cert_type	[RFC6091]
// 10	elliptic_curves	[RFC4492]
// 11	ec_point_formats	[RFC4492]
// 12	srp	[RFC5054]
// 13	signature_algorithms	[RFC5246]
// 14	use_srtp	[RFC5764]
// 15	heartbeat	[RFC6520]
// 16	application_layer_protocol_negotiation	[RFC7301]
// 17	status_request_v2	[RFC6961]
// 18	signed_certificate_timestamp	[RFC6962]
// 19	client_certificate_type	[RFC7250]
// 20	server_certificate_type	[RFC7250]
// 21	padding (TEMPORARY - registered 2014-03-12, expires 2016-03-12)	[draft-ietf-tls-padding]
// 22	encrypt_then_mac	[RFC7366]
// 23	extended_master_secret (TEMPORARY - registered 2014-09-26, expires 2015-09-26)	[draft-ietf-tls-session-hash]
// 24-34	Unassigned	
// 35	SessionTicket TLS	[RFC4507]
// 36-65280	Unassigned	
// 65281	renegotiation_info	[RFC5746]
// 65282-65535	Unassigned

// 67    next_protocol
// 13172 next_protocol_negotiation
// 30032 TLS Channel ID?

function readExtensions(buf) {
	var length = buf.readUInt16BE();
	buf = buf.slice(2);
	var extensions = [];
	while (buf.length) {
		var extension_type = buf.readUInt16BE();
		var extension_dataLength = buf.readUInt16BE(2);
		var extension_data = buf.slice(4, 4 + extension_dataLength);
		extensions.push({
			extension_type: extension_type,
			extension_data: extension_data
		});
		buf = buf.slice(4 + extension_dataLength);
	}
	return extensions;
}

function logExtensions(extensions) {
	extensions.forEach(function(ext) {
		if (ext.extension_type === 0) {
			console.log(readServerNameList(ext.extension_data));
		} else if (ext.extension_type === 16) {
			var protocolNameList = readProtocolNameList(ext.extension_data);
			console.log(protocolNameList);
		}
	});
}

// struct {
//     NameType name_type;
//     select (name_type) {
//         case host_name: HostName;
//     } name;
// } ServerName;
// enum {
//     host_name(0), (255)
// } NameType;
// opaque HostName<1..2^16-1>;
// struct {
//     ServerName server_name_list<1..2^16-1>
// } ServerNameList;
function readServerNameList(buf) {
	var length = buf.readUInt16BE();
	buf = buf.slice(2);
	var server_name_list = [];
	while (buf.length) {
		var name_type = buf[0];
		var host_nameLength = buf.readUInt16BE(1);
		var host_name = buf.slice(3, 3 + host_nameLength);
		server_name_list.push({
			name_type: name_type,
			host_name: host_name.toString()
		});
		buf = buf.slice(3 + host_nameLength);
	}
	return {
		server_name_list: server_name_list
	};
}

// struct {
//    ProtocolName protocol_name_list<2..2^16-1>
// } ProtocolNameList;
function readProtocolNameList(buf) {
	var length = buf.readUInt16BE();
	buf = buf.slice(2);
	var protocol_name_list = [];
	while (buf.length) {
		var length = buf[0];
		var name = buf = buf.slice(1, 1 + length);
		protocol_name_list.push(name.toString());
		buf = buf.slice(1 + length);
	}
	return {
		protocol_name_list: protocol_name_list
	};
}



function readRandom(buf) {
	var gmt_unix_time = buf.readUInt32BE();
	// console.log(new Date(gmt_unix_time * 1000));
	var random_bytes = buf.slice(4, 32);
	return {
		gmt_unix_time: gmt_unix_time,
		random_bytes: random_bytes,
		_length: 32
	};
}

// struct {
//   ProtocolVersion server_version;
//   Random random;
//   SessionID session_id;
//   CipherSuite cipher_suite;
//   CompressionMethod compression_method;
//   select (extensions_present) {
//       case false:
//           struct {};
//       case true:
//           Extension extensions<0..2^16-1>;
//   };
// } ServerHello;
function sendServerHello(c, context, clientHello) {
	var serverHello = createServerHello(context, clientHello);
	var handshake = createHandshake(2, serverHello);
	var record = createRecord(22, handshake);
	console.log(record);
	c.write(recordToBuffer(record));
}

function sendCertificate(c, context) {
	var certificate = createCertificate(c, context);
	var handshake = createHandshake(11, certificate);
	var record = createRecord(22, handshake);
	console.log(record);
	c.write(recordToBuffer(record));
}

function sendServerKeyExchange(c, context) {
	var serverKeyExchange = createServerKeyExchange(c, context);
	var handshake = createHandshake(12, serverKeyExchange);
	var record = createRecord(22, handshake);
	console.log(record);
	c.write(recordToBuffer(record));
}

function sendCertificateRequest(c, context) {
	var certificate = createCertificateRequest(c, context);
	var certificateRequest = createHandshake(13, certificateRequest);
	var record = createRecord(22, handshake);
	console.log(record);
	c.write(recordToBuffer(record));
}

function sendServerHelloDone(c, context) {
	var serverHelloDone = createServerHelloDone(c, context);
	var handshake = createHandshake(14, serverHelloDone);
	var record = createRecord(22, handshake);
	console.log(record);
	c.write(recordToBuffer(record));
}


// opaque ASN.1Cert<1..2^24-1>;

// struct {
//     ASN.1Cert certificate_list<0..2^24-1>;
// } Certificate;
function createCertificate(c, context) {
	var certificate_list = [];
	certificate_list.push(context.cert);
	return {
		'ASN.1Cert': certificate_list,
		_length: certificate_list.reduce(function(memo, cert) {
			return memo + 3 + cert.length;
		}, 3)
	};
}

function certificateToBuffer(certificate) {
	var allCertBuf = Buffer.concat(certificate['ASN.1Cert'].map(function(cert) {
		var lengthBuf = b.uint24(cert.length);
		return Buffer.concat([lengthBuf, cert]);
	}));
	console.log(allCertBuf.length);
	return Buffer.concat([
		b.uint24(allCertBuf.length),
		allCertBuf
	]);
}



function recordToBuffer(record) {
	var lengthBuf = new Buffer(record);
	var fragmentBuf;
	if (record.type === 22) {
		fragmentBuf = handshakeToBuffer(record.fragment);
	} else {
		assert(false);
	}
	// console.log(record);
	// console.log(record.fragment._length, fragmentBuf.length);
	assertEquals(record.fragment._length, fragmentBuf.length);
	return Buffer.concat([
		new Buffer([record.type]),
		new Buffer([record.version.major, record.version.minor]),
		b.uint16(record.fragment._length),
		fragmentBuf
	]);
}

// struct {
//   HandshakeType msg_type;    /* handshake type */
//   uint24 length;             /* bytes in message */
//   select (HandshakeType) {
//       case hello_request:       HelloRequest;
//       case client_hello:        ClientHello;
//       case server_hello:        ServerHello;
//       case certificate:         Certificate;
//       case server_key_exchange: ServerKeyExchange;
//       case certificate_request: CertificateRequest;
//       case server_hello_done:   ServerHelloDone;
//       case certificate_verify:  CertificateVerify;
//       case client_key_exchange: ClientKeyExchange;
//       case finished:            Finished;
//   } body;
// } Handshake;
function handshakeToBuffer(handshake) {
	var bodyBuf;
	if (handshake.msg_type === 2) {
		bodyBuf = serverHelloToBuffer(handshake.body);
	} else if (handshake.msg_type === 11) {
		bodyBuf = certificateToBuffer(handshake.body);
	} else if (handshake.msg_type === 12) {
		bodyBuf = serverKeyExchangeToBuffer(handshake.body);
	} else if (handshake.msg_type === 13) {
		bodyBuf = certificateRequestToBuffer(handshake.body);
	} else if (handshake.msg_type === 14) {
		bodyBuf = serverHelloDoneToBuffer(handshake.body);
	} else {
		assert(false);
	}
	assertEquals(handshake.length, bodyBuf.length);
	return Buffer.concat([
		new Buffer([handshake.msg_type]),
		b.uint24(handshake.length),
		bodyBuf
	]);
}


// struct {
//   ProtocolVersion server_version;
//   Random random;
//   SessionID session_id;
//   CipherSuite cipher_suite;
//   CompressionMethod compression_method;
//   select (extensions_present) {
//       case false:
//           struct {};
//       case true:
//           Extension extensions<0..2^16-1>;
//   };
// } ServerHello;
function serverHelloToBuffer(serverHello) {
	var serverHelloBuffer = Buffer.concat([
		new Buffer([serverHello.server_version.major, serverHello.server_version.minor]),
		Buffer.concat([b.uint32(serverHello.random.gmt_unix_time), serverHello.random.random_bytes]),
		Buffer.concat([new Buffer([1]), new Buffer([50])]), //TODO
		new Buffer(serverHello.cipher_suite),
		new Buffer([serverHello.compression_method])
	]);
	assertEquals(serverHello._length, serverHelloBuffer.length);
	return serverHelloBuffer;
}


// struct {
//   ContentType type;
//   ProtocolVersion version;
//   uint16 length;
//   opaque fragment[TLSPlaintext.length];
// } TLSPlaintext;
function createRecord(type, fragment) {
	return {
		type: type,
		version: {
			major: 3,
			minor: 3
		},
		length: fragment._length,
		fragment: fragment
	};
}

function createHandshake(msg_type, body) {
	var handshake = {
		msg_type: msg_type,
		length: body._length, // uint24
		body: body,
		_length: 1 + 3 + body._length
	};
	return handshake;
}


function createServerHello(context, clientHello) {
	var server_version = clientHello.client_version; // support highest
	var random = createRandom();
	var session_id = null; //TODO
	var cipher_suite = chooseCipherSuite(clientHello.cipher_suites);
	console.log('select: ' + nameOfCipherSuite(cipher_suite));
	var compression_method = 0;

	var serverHello = {
		server_version: server_version,
		random: random,
		session_id: session_id,
		cipher_suite: cipher_suite,
		compression_method: compression_method,
		_length: 2 + 32 + (1 + 1) + 2 + 1
	};
	return serverHello;
}

function createRandom() {
	var random_bytes = [];
	for (var i = 0; i < 28; i++) {
		random_bytes.push(Math.random() * 127);
	}
	return {
		gmt_unix_time: Math.floor(new Date().getTime() / 1000),
		random_bytes: new Buffer(random_bytes)
	};
}



// struct {
//   uint8 major;
//   uint8 minor;
// } ProtocolVersion;
function readProtocolVersion(buf) {
	return {
		major: buf.readUInt8(0),
		minor: buf.readUInt8(1),
		_length: 2
	};
}



server.listen(8080, function() { //'listening' listener
	console.log('server bound');
});


function nameOfCipherSuite(pair) {
	var keys = Object.keys(CipherSuites);
	var ret = null;
	for (var i = 0; i < keys.length; i++) {
		var key = keys[i];
		var value = CipherSuites[key];
		if (value[0] === pair[0] && value[1] === pair[1]) {
			ret = key;
			break;
		}
	}
	return ret;
}



var CipherSuites = {};
// https://www.ietf.org/rfc/rfc5246.txt
CipherSuites.TLS_RSA_WITH_NULL_MD5 = [0x00, 0x01];
CipherSuites.TLS_RSA_WITH_NULL_SHA = [0x00, 0x02];
CipherSuites.TLS_RSA_WITH_NULL_SHA256 = [0x00, 0x3B];
CipherSuites.TLS_RSA_WITH_RC4_128_MD5 = [0x00, 0x04];
CipherSuites.TLS_RSA_WITH_RC4_128_SHA = [0x00, 0x05];
CipherSuites.TLS_RSA_WITH_3DES_EDE_CBC_SHA = [0x00, 0x0A];
CipherSuites.TLS_RSA_WITH_AES_128_CBC_SHA = [0x00, 0x2F];
CipherSuites.TLS_RSA_WITH_AES_256_CBC_SHA = [0x00, 0x35];
CipherSuites.TLS_RSA_WITH_AES_128_CBC_SHA256 = [0x00, 0x3C];
CipherSuites.TLS_RSA_WITH_AES_256_CBC_SHA256 = [0x00, 0x3D];

CipherSuites.TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA = [0x00, 0x0D];
CipherSuites.TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA = [0x00, 0x10];
CipherSuites.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = [0x00, 0x13];
CipherSuites.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = [0x00, 0x16];
CipherSuites.TLS_DH_DSS_WITH_AES_128_CBC_SHA = [0x00, 0x30];
CipherSuites.TLS_DH_RSA_WITH_AES_128_CBC_SHA = [0x00, 0x31];
CipherSuites.TLS_DHE_DSS_WITH_AES_128_CBC_SHA = [0x00, 0x32];
CipherSuites.TLS_DHE_RSA_WITH_AES_128_CBC_SHA = [0x00, 0x33];
CipherSuites.TLS_DH_DSS_WITH_AES_256_CBC_SHA = [0x00, 0x36];
CipherSuites.TLS_DH_RSA_WITH_AES_256_CBC_SHA = [0x00, 0x37];
CipherSuites.TLS_DHE_DSS_WITH_AES_256_CBC_SHA = [0x00, 0x38];
CipherSuites.TLS_DHE_RSA_WITH_AES_256_CBC_SHA = [0x00, 0x39];
CipherSuites.TLS_DH_DSS_WITH_AES_128_CBC_SHA256 = [0x00, 0x3E];
CipherSuites.TLS_DH_RSA_WITH_AES_128_CBC_SHA256 = [0x00, 0x3F];
CipherSuites.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 = [0x00, 0x40];
CipherSuites.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = [0x00, 0x67];
CipherSuites.TLS_DH_DSS_WITH_AES_256_CBC_SHA256 = [0x00, 0x68];
CipherSuites.TLS_DH_RSA_WITH_AES_256_CBC_SHA256 = [0x00, 0x69];
CipherSuites.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 = [0x00, 0x6A];
CipherSuites.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = [0x00, 0x6B];

CipherSuites.TLS_DH_anon_WITH_RC4_128_MD5 = [0x00, 0x18];
CipherSuites.TLS_DH_anon_WITH_3DES_EDE_CBC_SHA = [0x00, 0x1B];
CipherSuites.TLS_DH_anon_WITH_AES_128_CBC_SHA = [0x00, 0x34];
CipherSuites.TLS_DH_anon_WITH_AES_256_CBC_SHA = [0x00, 0x3A];
CipherSuites.TLS_DH_anon_WITH_AES_128_CBC_SHA256 = [0x00, 0x6C];
CipherSuites.TLS_DH_anon_WITH_AES_256_CBC_SHA256 = [0x00, 0x6D];

// https://tools.ietf.org/html/rfc5288
CipherSuites.TLS_RSA_WITH_AES_128_GCM_SHA256 = [0x00, 0x9C];
CipherSuites.TLS_RSA_WITH_AES_256_GCM_SHA384 = [0x00, 0x9D];
CipherSuites.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = [0x00, 0x9E];
CipherSuites.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = [0x00, 0x9F];
CipherSuites.TLS_DH_RSA_WITH_AES_128_GCM_SHA256 = [0x00, 0xA0];
CipherSuites.TLS_DH_RSA_WITH_AES_256_GCM_SHA384 = [0x00, 0xA1];
CipherSuites.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 = [0x00, 0xA2];
CipherSuites.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 = [0x00, 0xA3];
CipherSuites.TLS_DH_DSS_WITH_AES_128_GCM_SHA256 = [0x00, 0xA4];
CipherSuites.TLS_DH_DSS_WITH_AES_256_GCM_SHA384 = [0x00, 0xA5];
CipherSuites.TLS_DH_anon_WITH_AES_128_GCM_SHA256 = [0x00, 0xA6];
CipherSuites.TLS_DH_anon_WITH_AES_256_GCM_SHA384 = [0x00, 0xA7];

// https://tools.ietf.org/html/rfc5746
CipherSuites.TLS_EMPTY_RENEGOTIATION_INFO_SCSV = [0x00, 0xFF];

// https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-05
CipherSuites.TLS_FALLBACK_SCSV = [0x56, 0x00];

// https://www.ietf.org/rfc/rfc4492.txt
CipherSuites.TLS_ECDH_ECDSA_WITH_NULL_SHA = [0xC0, 0x01];
CipherSuites.TLS_ECDH_ECDSA_WITH_RC4_128_SHA = [0xC0, 0x02];
CipherSuites.TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA = [0xC0, 0x03];
CipherSuites.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA = [0xC0, 0x04];
CipherSuites.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA = [0xC0, 0x05];
CipherSuites.TLS_ECDHE_ECDSA_WITH_NULL_SHA = [0xC0, 0x06];
CipherSuites.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA = [0xC0, 0x07];
CipherSuites.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA = [0xC0, 0x08];
CipherSuites.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = [0xC0, 0x09];
CipherSuites.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = [0xC0, 0x0A];
CipherSuites.TLS_ECDH_RSA_WITH_NULL_SHA = [0xC0, 0x0B];
CipherSuites.TLS_ECDH_RSA_WITH_RC4_128_SHA = [0xC0, 0x0C];
CipherSuites.TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA = [0xC0, 0x0D];
CipherSuites.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA = [0xC0, 0x0E];
CipherSuites.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA = [0xC0, 0x0F];
CipherSuites.TLS_ECDHE_RSA_WITH_NULL_SHA = [0xC0, 0x10];
CipherSuites.TLS_ECDHE_RSA_WITH_RC4_128_SHA = [0xC0, 0x11];
CipherSuites.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA = [0xC0, 0x12];
CipherSuites.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = [0xC0, 0x13];
CipherSuites.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = [0xC0, 0x14];
CipherSuites.TLS_ECDH_anon_WITH_NULL_SHA = [0xC0, 0x15];
CipherSuites.TLS_ECDH_anon_WITH_RC4_128_SHA = [0xC0, 0x16];
CipherSuites.TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA = [0xC0, 0x17];
CipherSuites.TLS_ECDH_anon_WITH_AES_128_CBC_SHA = [0xC0, 0x18];
CipherSuites.TLS_ECDH_anon_WITH_AES_256_CBC_SHA = [0xC0, 0x19];

//https://tools.ietf.org/html/rfc5289
CipherSuites.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = [0xC0, 0x23];
CipherSuites.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = [0xC0, 0x24];
CipherSuites.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 = [0xC0, 0x25];
CipherSuites.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 = [0xC0, 0x26];
CipherSuites.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = [0xC0, 0x27];
CipherSuites.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = [0xC0, 0x28];
CipherSuites.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 = [0xC0, 0x29];
CipherSuites.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 = [0xC0, 0x2A];
CipherSuites.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = [0xC0, 0x2B];
CipherSuites.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = [0xC0, 0x2C];
CipherSuites.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 = [0xC0, 0x2D];
CipherSuites.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 = [0xC0, 0x2E];
CipherSuites.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = [0xC0, 0x2F];
CipherSuites.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = [0xC0, 0x30];
CipherSuites.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 = [0xC0, 0x31];
CipherSuites.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 = [0xC0, 0x32];
CipherSuites.TLS_ECDHE_PSK_WITH_RC4_128_SHA = [0xC0, 0x33];
CipherSuites.TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA = [0xC0, 0x34];
CipherSuites.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA = [0xC0, 0x35];
CipherSuites.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA = [0xC0, 0x36];
CipherSuites.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 = [0xC0, 0x37];
CipherSuites.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 = [0xC0, 0x38];
CipherSuites.TLS_ECDHE_PSK_WITH_NULL_SHA = [0xC0, 0x39];
CipherSuites.TLS_ECDHE_PSK_WITH_NULL_SHA256 = [0xC0, 0x3A];
CipherSuites.TLS_ECDHE_PSK_WITH_NULL_SHA384 = [0xC0, 0x3B];

// https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04
CipherSuites.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = [0xcc, 0x13];
CipherSuites.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = [0xcc, 0x14];
CipherSuites.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = [0xcc, 0x15];


// "ECDHE-RSA-AES128-SHA256",
// "DHE-RSA-AES128-SHA256",
// "AES128-GCM-SHA256",

var supportedCipherSuites = [
	CipherSuites.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,//Firefox
	//
	// CipherSuites.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, //'ECDHE-ECDSA-AES128-GCM-SHA256',
	// CipherSuites.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, //'ECDHE-RSA-AES256-GCM-SHA384',
	// CipherSuites.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, //  'ECDHE-ECDSA-AES256-GCM-SHA384',
	// CipherSuites.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, //  'DHE-RSA-AES128-GCM-SHA256',
	// CipherSuites.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256, // 'DHE-DSS-AES128-GCM-SHA256',
	// CipherSuites.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, // 'ECDHE-RSA-AES128-SHA256',
	CipherSuites.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, //  'ECDHE-ECDSA-AES128-SHA256',
	CipherSuites.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, // 'ECDHE-RSA-AES128-SHA',
	// CipherSuites.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, // 'ECDHE-ECDSA-AES128-SHA',
	// CipherSuites.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, // 'ECDHE-RSA-AES256-SHA384',
	// CipherSuites.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, // 'ECDHE-ECDSA-AES256-SHA384',
	CipherSuites.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, // 'ECDHE-RSA-AES256-SHA',
	// CipherSuites.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, // 'ECDHE-ECDSA-AES256-SHA',
	// CipherSuites.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256, // 'DHE-RSA-AES128-SHA256',
	CipherSuites.TLS_DHE_RSA_WITH_AES_128_CBC_SHA, // 'DHE-RSA-AES128-SHA',
	// CipherSuites.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256, // 'DHE-DSS-AES128-SHA256',
	// CipherSuites.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256, // 'DHE-RSA-AES256-SHA256',
	// CipherSuites.TLS_DHE_DSS_WITH_AES_256_CBC_SHA, // 'DHE-DSS-AES256-SHA',
	CipherSuites.TLS_DHE_RSA_WITH_AES_256_CBC_SHA, // 'DHE-RSA-AES256-SHA',
	// CipherSuites.TLS_RSA_WITH_AES_128_GCM_SHA256, // 'kEDH+AESGCM',
	// CipherSuites.TLS_RSA_WITH_AES_128_GCM_SHA256, // 'AES128-GCM-SHA256',
	// CipherSuites.TLS_RSA_WITH_AES_256_GCM_SHA384, // 'AES256-GCM-SHA384',
	CipherSuites.TLS_ECDHE_RSA_WITH_RC4_128_SHA, // 'ECDHE-RSA-RC4-SHA',
	CipherSuites.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, // 'ECDHE-ECDSA-RC4-SHA',

];


function chooseCipherSuite(suites) {
	var chosen = null;
	loop: for (var i = 0; i < suites.length; i++) {
		var suite = suites[i];
		for (var j = 0; j < supportedCipherSuites.length; j++) {
			if (suite[0] === supportedCipherSuites[j][0] &&
				suite[1] === supportedCipherSuites[j][1]) {
				chosen = suite;
				break loop;
			}
		}
	}
	if (!chosen) {
		chosen = suites[0];
		console.log('chosen is ' + chosen + ' for debug');
	}
	return chosen;
}