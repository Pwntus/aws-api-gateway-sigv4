import SigV4 from './index'

const config = {
  method: 'POST',
  path: '/dev/foo/bar',
  data: { foo: 'bar' },

  region: 'us-east-1',
  endpoint: 'https://123abc.execute-api.us-east-1.amazonaws.com',
  accessKey: 'X',
  secretKey: 'Y',
  sessionToken: 'Z'
}

console.log(SigV4(config))
