'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});

exports.default = function (config) {
  assertProps(config, ['method', 'path', 'region', 'endpoint', 'accessKey', 'secretKey', 'sessionToken']);
  assertValue(config, 'data', {});
  assertValue(config, 'serviceName', 'execute-api');
  assertValue(config, 'defaultAcceptType', 'application/json');
  assertValue(config, 'defaultContentType', 'application/json');

  /* Init */
  var headers = {};
  var queryParams = {};
  config.method = config.method.toUpperCase();
  var datetime = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z').replace(/[:\-]|\.\d{3}/g, '');

  /* Set headers */
  headers['Accept'] = config.defaultAcceptType;
  headers[X_AMZ_DATE] = datetime;
  headers[HOST] = hostname(config.endpoint);

  /* GET
   * Payload in queryParams,
   * data = ''
   */
  if (config.method === 'GET') {
    headers['Content-Type'] = config.defaultContentType;
    queryParams = config.data;
    config.data = '';
  } else {
    config.data = JSON.stringify(config.data);
  }

  /* Perform SigV4 steps */
  var canonicalRequest = buildCanonicalRequest(config.method, config.path, queryParams, headers, config.data);
  console.log(canonicalRequest);
  var hashedCanonicalRequest = hashCanonicalRequest(canonicalRequest);
  var credentialScope = buildCredentialScope(datetime, config.region, config.serviceName);
  var stringToSign = buildStringToSign(datetime, credentialScope, hashedCanonicalRequest);
  console.log(stringToSign);
  var signingKey = calculateSigningKey(config.secretKey, datetime, config.region, config.serviceName);
  var signature = calculateSignature(signingKey, stringToSign);

  headers[AUTHORIZATION] = buildAuthorizationHeader(config.accessKey, credentialScope, headers, signature);
  headers[X_AMZ_SECURITY_TOKEN] = config.sessionToken;
  headers['Content-Type'] = config.defaultContentType;

  return headers;
};

var _cryptoJs = require('crypto-js');

var AWS_SHA_256 = 'AWS4-HMAC-SHA256';
var AWS4_REQUEST = 'aws4_request';
var AWS4 = 'AWS4';
var X_AMZ_DATE = 'x-amz-date';
var X_AMZ_SECURITY_TOKEN = 'x-amz-security-token';
var HOST = 'host';
var AUTHORIZATION = 'Authorization';

var assertProps = function assertProps(config, props) {
  var _iteratorNormalCompletion = true;
  var _didIteratorError = false;
  var _iteratorError = undefined;

  try {
    for (var _iterator = props[Symbol.iterator](), _step; !(_iteratorNormalCompletion = (_step = _iterator.next()).done); _iteratorNormalCompletion = true) {
      var prop = _step.value;

      if (typeof config[prop] === 'undefined') throw '[SigV4]: missing config property \'' + prop + '\'';
    }
  } catch (err) {
    _didIteratorError = true;
    _iteratorError = err;
  } finally {
    try {
      if (!_iteratorNormalCompletion && _iterator.return) {
        _iterator.return();
      }
    } finally {
      if (_didIteratorError) {
        throw _iteratorError;
      }
    }
  }

  return null;
};

var assertValue = function assertValue(config, prop, val) {
  if (typeof config[prop] === 'undefined') config[prop] = val;
};

var hostname = function hostname(endpoint) {
  var match = endpoint.match(/^(https?\:)\/\/(([^:\/?#]*)(?:\:([0-9]+))?)([\/]{0,1}[^?#]*)(\?[^#]*|)(#.*|)$/);
  return match && match[3];
};

var hash = function hash(value) {
  return (0, _cryptoJs.SHA256)(value);
};

var hexEncode = function hexEncode(value) {
  return value.toString(_cryptoJs.enc.Hex);
};

var hmac = function hmac(secret, value) {
  return (0, _cryptoJs.HmacSHA256)(value, secret, { asBytes: true });
};

var buildCanonicalQueryString = function buildCanonicalQueryString(queryParams) {
  if (Object.keys(queryParams).length < 1) return '';

  var sortedQueryParams = [];
  for (var property in queryParams) {
    if (queryParams.hasOwnProperty(property)) sortedQueryParams.push(property);
  }
  sortedQueryParams.sort();

  var canonicalQueryString = '';
  for (var i = 0; i < sortedQueryParams.length; i++) {
    canonicalQueryString += sortedQueryParams[i] + '=' + fixedEncodeURIComponent(queryParams[sortedQueryParams[i]]) + '&';
  }

  return canonicalQueryString.substr(0, canonicalQueryString.length - 1);
};

var fixedEncodeURIComponent = function fixedEncodeURIComponent(str) {
  return encodeURIComponent(str).replace(/[!'()*]/g, function (c) {
    return '%' + c.charCodeAt(0).toString(16);
  });
};

var buildCanonicalHeaders = function buildCanonicalHeaders(headers) {
  var canonicalHeaders = '';
  var sortedKeys = [];
  for (var property in headers) {
    if (headers.hasOwnProperty(property)) sortedKeys.push(property);
  }
  sortedKeys.sort();

  for (var i = 0; i < sortedKeys.length; i++) {
    canonicalHeaders += sortedKeys[i].toLowerCase() + ':' + headers[sortedKeys[i]] + '\n';
  }

  return canonicalHeaders;
};

var buildCanonicalSignedHeaders = function buildCanonicalSignedHeaders(headers) {
  var sortedKeys = [];
  for (var property in headers) {
    if (headers.hasOwnProperty(property)) sortedKeys.push(property.toLowerCase());
  }
  sortedKeys.sort();

  return sortedKeys.join(';');
};

/* ---------- */

var buildCanonicalRequest = function buildCanonicalRequest(method, path, queryParams, headers, payload) {
  return method + '\n' + encodeURI(path) + '\n' + buildCanonicalQueryString(queryParams) + '\n' + buildCanonicalHeaders(headers) + '\n' + buildCanonicalSignedHeaders(headers) + '\n' + hexEncode(hash(payload));
};

var hashCanonicalRequest = function hashCanonicalRequest(request) {
  return hexEncode(hash(request));
};

var buildCredentialScope = function buildCredentialScope(datetime, region, service) {
  return datetime.substr(0, 8) + '/' + region + '/' + service + '/' + AWS4_REQUEST;
};

var buildStringToSign = function buildStringToSign(datetime, credentialScope, hashedCanonicalRequest) {
  return AWS_SHA_256 + '\n' + datetime + '\n' + credentialScope + '\n' + hashedCanonicalRequest;
};

var calculateSigningKey = function calculateSigningKey(secretKey, datetime, region, service) {
  return hmac(hmac(hmac(hmac(AWS4 + secretKey, datetime.substr(0, 8)), region), service), AWS4_REQUEST);
};

var calculateSignature = function calculateSignature(key, stringToSign) {
  return hexEncode(hmac(key, stringToSign));
};

var buildAuthorizationHeader = function buildAuthorizationHeader(accessKey, credentialScope, headers, signature) {
  return AWS_SHA_256 + ' Credential=' + accessKey + '/' + credentialScope + ', SignedHeaders=' + buildCanonicalSignedHeaders(headers) + ', Signature=' + signature;
};

/* ---------- */