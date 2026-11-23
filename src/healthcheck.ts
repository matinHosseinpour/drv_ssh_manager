import http from 'node:http';
const request = http.get('http://127.0.0.1:3080/healthz', {
  headers: { Host: new URL(process.env.PUBLIC_URL!).host },
}, response => { response.resume(); process.exit(response.statusCode === 200 ? 0 : 1); });
request.on('error', () => process.exit(1));
request.setTimeout(4000, () => { request.destroy(); process.exit(1); });
