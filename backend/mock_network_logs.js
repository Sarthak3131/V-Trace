const http = require('http');

const payload = JSON.stringify({
  email: 'user1@test.com',
  password: 'password123'
});

const options = {
  hostname: '127.0.0.1',
  port: 5000,
  path: '/api/auth/login',
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(payload),
    'Origin': 'http://127.0.0.1:3000',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
  }
};

console.log('--- BROWSER NETWORK INSPECTOR SIMULATION ---');
console.log('Request URL:', `http://${options.hostname}:${options.port}${options.path}`);
console.log('Request Method:', options.method);
console.log('Request Headers:', JSON.stringify(options.headers, null, 2));
console.log('Request Payload:', payload);
console.log('--------------------------------------------');

const req = http.request(options, (res) => {
  console.log('Response Status:', res.statusCode, res.statusMessage);
  console.log('Response Headers:', JSON.stringify(res.headers, null, 2));
  
  let data = '';
  res.on('data', (chunk) => {
    data += chunk;
  });
  
  res.on('end', () => {
    console.log('Response Body:', data);
    console.log('--------------------------------------------');
    process.exit(0);
  });
});

req.on('error', (e) => {
  console.error('Network Error:', e.message);
  process.exit(1);
});

req.write(payload);
req.end();
