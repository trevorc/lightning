var events = require('events');
var http = require('http');
var https = require('https');
var querystring = require('querystring');
var url = require('url');
var util = require('util');


var REQUEST_TIMEOUT = 10 * 1000;
var ACCEPT_CHARSET = 'UTF-8,ISO-8859-1;q=0.5,*;q=0.3';
var USER_AGENT = 'Lightning <https://github.com/trevorc/lightning>';

function HttpError(statusCode) {
  this.name = 'HttpError';
  this.statusCode = statusCode;
  this.message = http.STATUS_CODES[statusCode];
  return Error.captureStackTrace(this);
};
util.inherits(HttpError, Error);

HttpError.prototype = Error.__proto__;
HttpError.prototype.toString = function() {
  return '' + this.statusCode + ' ' + this.message;
};

function bufferStream(rs, callback) {
  var buf = '';
  rs.on('data', function(chunk) { buf += chunk; });
  rs.on('error', callback);
  rs.on('end', function() { callback(null, buf); });
};

function decodeJSON(response, callback) {
  return bufferStream(response, function(err, responseBody) {
    console.log(responseBody);
    if (err) return callback(err);
    try { callback(null, response, JSON.parse(responseBody)); }
    catch (e) { callback(e, response); }
  });
};

function clone(o) {
  var copy = {};
  if (o) for (k in o) if (o.hasOwnProperty(k)) copy[k] = o[k];
  return copy;
}

function setDefaultHeaders(headers, host, port, secure) {
  var headers = clone(headers);
  var defaultPort = secure ? 443 : 80;
  var canonHeaders = {};

  for (k in headers) {
    v = headers[k];
    canonHeaders[k.toLowerCase()] = v;
  }
  function hasHeader(header) {
    return canonHeaders[header.toLowerCase()] != null;
  };

  if (!hasHeader('Accept-Charset')) {
    headers['Accept-Charset'] = ACCEPT_CHARSET;
  }
  if (!hasHeader('User-Agent')) headers['User-Agent'] = USER_AGENT;
  if (!hasHeader('Host')) {
    headers['Host'] = host;
    if (port !== defaultPort) headers['Host'] += ':' + port;
  }
  return headers;
};

function prepareRequestBody(body, headers, encoding, encoder) {
  if (encoder) switch (encoder) {
    case 'querystring':
      body = querystring.stringify(body);
      headers['Content-Type'] = 'application/x-www-form-urlencoded';
      break;
    case 'json':
      body = JSON.stringify(body);
      headers['Content-Type'] = 'application/json';
      break;
    default:
      throw new Error('unknown encoder ' + encoder);
  }
  if (typeof body === 'string') {
    body = new Buffer(body, encoding || 'UTF-8');
  }
  return body;
};

function addBodyHeaders(headers, method, body) {
  if ((method === 'POST' || method === 'PUT') &&
      headers['content-length'] == null) {
    if (body instanceof Buffer) {
      headers['Content-Length'] = body.length;
    } else if (body instanceof events.EventEmitter) {
      headers['Transfer-Encoding'] = 'chunked';
    } else if (!body) {
      headers['Content-Length'] = 0;
    }
  }
};

function makeResponseHandler(callback, req, options) {
  return function(response) {
    var timeout = options.timeout == null ?
      REQUEST_TIMEOUT : options.timeout;
    req.socket.setTimeout(function() {
      req.socket.close();
      callback(new HttpError(503, response));
    }, timeout);
    if (response.statusCode >= 400) {
      return callback(new HttpError(response.statusCode, response));
    }
    if (options.json) return decodeJSON(response, callback);
    callback(null, response);
  };
};

function endRequest(req, body) {
  if (body == null) return req.end();
  if (body instanceof Buffer) return req.end(body);
  if (!(body instanceof events.EventEmitter)) {
    throw new TypeError('options.body must be a Buffer or EventEmitter');
  }
  body.on('data', function(chunk) { return req.write(chunk); });
  body.once('error', function() { return callback(new HttpError); });
  body.once('end', function() { return req.end(); });
};

function makeRequest(method, uri, options, callback) {
  var body, headers, host, parsed, path, port, redirect, req, secure;

  if (!method) throw TypeError('needs method');
  if (!uri) throw TypeError('needs uri');
  if (!options) throw TypeError('needs callback');
  if (!callback) {
    callback = options;
    options = {};
  }

  parsed = url.parse(uri);
  secure = parsed.protocol === 'https:';
  host = parsed.hostname;
  port = parsed.port || (secure ? 443 : 80);
  redirect = options.followRedirects;
  path = parsed.pathname ? parsed.pathname : '/';
  if (parsed.search) path += parsed.search;
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('unknown protocol ' + parsed.protocol);
  }
  if (!parsed.hostname) {
    throw new Error('invalid url ' + uri + ' (missing hostname)');
  }
  headers = setDefaultHeaders(options.headers, host, port, secure);
  body = prepareRequestBody(options.body, headers, options.encoding,
      options.encoder);
  addBodyHeaders(headers, method, body);

  req = (secure ? https : http)['request']({
    host: host
  , port: port
  , headers: headers
  , method: method
  , path: path
  });
  req.once('response', makeResponseHandler(callback, req, {
    json: options.json
  , timeout: options.timeout
  }));
  endRequest(req, body);
};

[ 'get'
, 'head'
, 'put'
, 'post'
, 'delete'
, 'options'
, 'trace'
].forEach(function(method) {
  exports[method] = function(uri, options, callback) {
    return makeRequest(method.toUpperCase(), uri, options, callback);
  };
});
