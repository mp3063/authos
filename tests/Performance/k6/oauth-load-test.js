import http from 'k6/http';
import { check, group, sleep } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const tokenGenerationTime = new Trend('token_generation_time');
const tokensGenerated = new Counter('tokens_generated');

// OAuth load test configuration
export const options = {
  stages: [
    { duration: '30s', target: 20 },   // Ramp up to 20 users
    { duration: '1m', target: 50 },    // Ramp up to 50 users
    { duration: '2m', target: 100 },   // Ramp up to 100 users
    { duration: '2m', target: 100 },   // Stay at 100 users
    { duration: '1m', target: 0 },     // Ramp down
  ],
  thresholds: {
    token_generation_time: ['p(95)<200'], // 95% should be under 200ms
    http_req_failed: ['rate<0.05'],
    errors: ['rate<0.05'],
  },
};

const BASE_URL = __ENV.BASE_URL || 'http://authos.test';

// OAuth client credentials - these should be set up in your test environment
const CLIENT_ID = __ENV.CLIENT_ID || '1';
const CLIENT_SECRET = __ENV.CLIENT_SECRET || 'test-secret';
const USERNAME = __ENV.USERNAME || 'admin@authservice.com';
const PASSWORD = __ENV.PASSWORD || 'password123';

export default function () {
  group('OAuth Password Grant', function () {
    const startTime = new Date();

    const tokenRes = http.post(`${BASE_URL}/api/v1/oauth/token`, JSON.stringify({
      grant_type: 'password',
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      username: USERNAME,
      password: PASSWORD,
    }), {
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
    });

    const duration = new Date() - startTime;
    tokenGenerationTime.add(duration);

    const success = check(tokenRes, {
      'token generation status 200': (r) => r.status === 200,
      'access_token present': (r) => JSON.parse(r.body).access_token !== undefined,
      'refresh_token present': (r) => JSON.parse(r.body).refresh_token !== undefined,
      'token generation < 200ms': (r) => r.timings.duration < 200,
    });

    if (success) {
      tokensGenerated.add(1);
      const body = JSON.parse(tokenRes.body);
      const accessToken = body.access_token;

      // Test token introspection
      group('Token Introspection', function () {
        const introspectRes = http.post(`${BASE_URL}/api/v1/oauth/introspect`, JSON.stringify({
          token: accessToken,
          token_type_hint: 'access_token',
        }), {
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
          },
        });

        check(introspectRes, {
          'introspection status 200': (r) => r.status === 200,
          'token is active': (r) => JSON.parse(r.body).active === true,
        });
      });

      // Use the token
      group('Token Usage', function () {
        const useRes = http.get(`${BASE_URL}/api/v1/profile`, {
          headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Accept': 'application/json',
          },
        });

        check(useRes, {
          'token usage successful': (r) => r.status === 200,
        });
      });
    } else {
      errorRate.add(1);
    }
  });

  sleep(1);
}

export function setup() {
  console.log('Starting OAuth load test');
  console.log(`Base URL: ${BASE_URL}`);
  console.log(`Client ID: ${CLIENT_ID}`);
  return { startTime: new Date() };
}

export function teardown(data) {
  const endTime = new Date();
  const duration = (endTime - data.startTime) / 1000;
  console.log(`OAuth load test completed in ${duration} seconds`);
}
