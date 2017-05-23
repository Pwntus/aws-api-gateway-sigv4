import {
  HmacSHA256,
  SHA256,
  enc
} from 'crypto-js'

const AWS_SHA_256          = 'AWS4-HMAC-SHA256'
const AWS4_REQUEST         = 'aws4_request'
const AWS4                 = 'AWS4'
const X_AMZ_DATE           = 'x-amz-date'
const X_AMZ_SECURITY_TOKEN = 'x-amz-security-token'
const HOST                 = 'host'
const AUTHORIZATION        = 'Authorization'

const assertProps = (config, props) => {
  for (let prop of props) {
    if (typeof config[prop] === 'undefined')
      throw `[SigV4]: missing config property '${prop}'`
  }
  return null
}

const assertValue = (config, prop, val) => {
  if (typeof config[prop] === 'undefined')
    config[prop] = val
}

const hostname = (endpoint) => {
  var match = endpoint.match(/^(https?\:)\/\/(([^:\/?#]*)(?:\:([0-9]+))?)([\/]{0,1}[^?#]*)(\?[^#]*|)(#.*|)$/)
  return match && match[3]
}

const hash = (value) => {
  return SHA256(value)
}

const hexEncode = (value) => {
  return value.toString(enc.Hex)
}

const hmac = (secret, value) => {
  return HmacSHA256(value, secret, { asBytes: true })
}

const buildCanonicalQueryString = (queryParams) => {
  if (Object.keys(queryParams).length < 1) return ''
  
  let sortedQueryParams = []
  for (let property in queryParams) {
    if (queryParams.hasOwnProperty(property))
      sortedQueryParams.push(property)
  }
  sortedQueryParams.sort()

  let canonicalQueryString = ''
  for (let i = 0; i < sortedQueryParams.length; i++) {
    canonicalQueryString += sortedQueryParams[i] + '=' + fixedEncodeURIComponent(queryParams[sortedQueryParams[i]]) + '&'
  }
  
  return canonicalQueryString.substr(0, canonicalQueryString.length - 1)
}

const fixedEncodeURIComponent = (str) => {
  return encodeURIComponent(str).replace(/[!'()*]/g, (c) => {
    return '%' + c.charCodeAt(0).toString(16)
  })
}

const buildCanonicalHeaders = (headers) => {
  let canonicalHeaders = ''
  let sortedKeys = []
  for (let property in headers) {
    if (headers.hasOwnProperty(property))
        sortedKeys.push(property)
  }
  sortedKeys.sort()

  for (var i = 0; i < sortedKeys.length; i++) {
    canonicalHeaders += sortedKeys[i].toLowerCase() + ':' + headers[sortedKeys[i]] + '\n'
  }
  
  return canonicalHeaders
}

const buildCanonicalSignedHeaders = (headers) => {
  let sortedKeys = []
  for (let property in headers) {
    if (headers.hasOwnProperty(property))
      sortedKeys.push(property.toLowerCase())
  }
  sortedKeys.sort()

  return sortedKeys.join(';')
}

/* ---------- */

const buildCanonicalRequest = (method, path, queryParams, headers, payload) => {
  return  method + '\n' +
          encodeURI(path) + '\n' +
          buildCanonicalQueryString(queryParams) + '\n' +
          buildCanonicalHeaders(headers) + '\n' +
          buildCanonicalSignedHeaders(headers) + '\n' +
          hexEncode(hash(payload))
}

const hashCanonicalRequest = (request) => {
  return hexEncode(hash(request))
}

const buildCredentialScope = (datetime, region, service) => {
  return `${datetime.substr(0, 8)}/${region}/${service}/${AWS4_REQUEST}`
}

const buildStringToSign = (datetime, credentialScope, hashedCanonicalRequest) => {
  return  AWS_SHA_256 + '\n' +
          datetime + '\n' +
          credentialScope + '\n' +
          hashedCanonicalRequest
}

const calculateSigningKey = (secretKey, datetime, region, service) => {
  return hmac(hmac(hmac(hmac(AWS4 + secretKey, datetime.substr(0, 8)), region), service), AWS4_REQUEST)
}

const calculateSignature = (key, stringToSign) =>{
  return hexEncode(hmac(key, stringToSign))
}

const buildAuthorizationHeader = (accessKey, credentialScope, headers, signature) => {
  return  AWS_SHA_256 + ' Credential=' + accessKey + '/' + credentialScope + ', SignedHeaders=' +
          buildCanonicalSignedHeaders(headers) + ', Signature=' + signature
}

/* ---------- */

export default function (config) {
  assertProps(config, ['method', 'path', 'region', 'endpoint', 'accessKey', 'secretKey', 'sessionToken'])
  assertValue(config, 'data', {})
  assertValue(config, 'serviceName', 'execute-api')
  assertValue(config, 'defaultAcceptType', 'application/json')
  assertValue(config, 'defaultContentType', 'application/json')

  /* Init */
  let headers = {}
  let queryParams = {}
  config.method = config.method.toUpperCase()
  const datetime = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z').replace(/[:\-]|\.\d{3}/g, '')

  /* Set headers */
  headers['Accept'] = config.defaultAcceptType
  headers[X_AMZ_DATE] = datetime
  headers[HOST] = hostname(config.endpoint)

  /* GET
   * Payload in queryParams,
   * data = ''
   */
  if (config.method === 'GET') {
    headers['Content-Type'] = config.defaultContentType
    queryParams = config.data
    config.data = ''
  } else {
    config.data = JSON.stringify(config.data)
  }

  /* Perform SigV4 steps */
  const canonicalRequest = buildCanonicalRequest(config.method, config.path, queryParams, headers, config.data)
  console.log(canonicalRequest)
  const hashedCanonicalRequest = hashCanonicalRequest(canonicalRequest)
  const credentialScope = buildCredentialScope(datetime, config.region, config.serviceName)
  const stringToSign = buildStringToSign(datetime, credentialScope, hashedCanonicalRequest)
  console.log(stringToSign)
  const signingKey = calculateSigningKey(config.secretKey, datetime, config.region, config.serviceName)
  const signature = calculateSignature(signingKey, stringToSign)

  headers[AUTHORIZATION] = buildAuthorizationHeader(config.accessKey, credentialScope, headers, signature)
  headers[X_AMZ_SECURITY_TOKEN] = config.sessionToken
  headers['Content-Type'] = config.defaultContentType

  return headers
}
