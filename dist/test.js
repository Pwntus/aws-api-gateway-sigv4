'use strict';

var _index = require('./index');

var _index2 = _interopRequireDefault(_index);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var config = {
  method: 'POST',
  path: '/dev/foo/bar',
  data: { foo: 'bar' },

  region: 'us-east-1',
  endpoint: 'https://123abc.execute-api.us-east-1.amazonaws.com',
  accessKey: 'X',
  secretKey: 'Y',
  sessionToken: 'Z'
};

console.log((0, _index2.default)(config));