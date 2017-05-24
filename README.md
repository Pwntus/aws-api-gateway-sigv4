# sigv4
Tiny helper for performing necessary SigV4 steps to be used by a client.

```javascript
import axios from 'axios'
import SigV4 from 'sigv4'

const config = {
  
  // Required properties
  method: 'POST',
  path: '/dev/foo/bar',
  region: 'us-east-1',
  endpoint: 'https://123abc.execute-api.us-east-1.amazonaws.com',
  accessKey: 'X',
  secretKey: 'Y',
  sessionToken: 'Z',

  // Optional properties and their default values
  data: {},
  serviceName: 'execute-api',
  defaultAcceptType: 'application/json',
  defaultContentType: 'application/json'
}

const headers = SigV4(config)

axios({
  headers: headers,
  method: config.method,
  url: config.endpoint + config.path,
  data: data
})

```
