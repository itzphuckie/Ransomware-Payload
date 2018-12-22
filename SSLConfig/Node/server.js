//In case you aren't using a proxy server like Nginx, you can follow these tutorials:
https://www.npmjs.com/package/strict-transport-security
https://nodejs.org/api/tls.html
//An example of what to include in your server.js (Do NOT copy-paste but instead type them):

var express = require('express');
var httpApp = express();
var httpsApp = express();
var http = require('http');
var https = require('https');
var fs = require('fs');
var helmet = require('helmet');
var ONE_YEAR = 31536000000;

httpsApp.use(helmet.hsts({
maxAge: ONE_YEAR,
includeSubdomains: true,
force: true
}));

var cipher = ['ECDHE-ECDSA-AES256-GCM-SHA384',
'ECDHE-RSA-AES256-GCM-SHA384',
'ECDHE-RSA-AES256-CBC-SHA384',
'ECDHE-RSA-AES256-CBC-SHA256',
'ECDHE-ECDSA-AES128-GCM-SHA256',
'ECDHE-RSA-AES128-GCM-SHA256',
'DHE-RSA-AES128-GCM-SHA256',
'DHE-RSA-AES256-GCM-SHA384',
'!aNULL',
'!MD5',
'!DSS'].join(':');

httpApp.get("*", function(req, res, next){
res.redirect('https://' + req.headers.host + req.url);
});

httpsApp.get('/', function(req, res){
res.send('You are in the right place.');
});

var options = {
key: fs.readFileSync('privkey.pem'),
cert: fs.readFileSync('fullchain.pem'),
ciphers: cipher
};

http.createServer(httpApp).listen(8080);
https.createServer(options, httpsApp).listen(3000);
