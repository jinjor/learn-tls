var tls = require('tls');
var fs = require('fs');
var assert = require('assert');

var options = {
	key: fs.readFileSync('ssl/server.key'),
	cert: fs.readFileSync('ssl/server.crt'),
};
var server = tls.createServer(options);
server.on('secureConnection', function(s) {
	console.log('secureConnection');
	s.write('hello');
	s.end();
});
server.listen(8080, function() {
  console.log('server bound');
});