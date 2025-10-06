import http from 'k6/http';
import { check, group, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const apiResponseTime = new Trend('api_response_time');
const authResponseTime = new Trend('auth_response_time');

// Stress test configuration
export const options = {
  stages: [
    { duration: '1m', target: 100 },    // Ramp up to 100 users
    { duration: '2m', target: 500 },    // Ramp up to 500 users
    { duration: '3m', target: 1000 },   // Ramp up to 1000 users
    { duration: '2m', target: 1000 },   // Stay at 1000 users
    { duration: '2m', target: 100 },    // Ramp down to 100 users
    { duration: '1m', target: 0 },      // Ramp down to 0 users
  ],
  thresholds: {
    http_req_duration: ['p(95)<500', 'p(99)<1000'],
    http_req_failed: ['rate<0.1'],
    errors: ['rate<0.1'],
    api_response_time: ['p(95)<300'],
    auth_response_time: ['p(95)<150'],
  },
};

const BASE_URL = __ENV.BASE_URL || 'http://authos.test';
const ACCESS_TOKEN = __ENV.ACCESS_TOKEN || '';

export default function () {
  let token = ACCESS_TOKEN;

  // If no token provided, authenticate first
  if (!token) {
    group('Authentication', function () {
      const startAuth = new Date();
      const loginRes = http.post(`${BASE_URL}/api/v1/auth/login`, JSON.stringify({
        email: 'admin@authservice.com',
        password: 'password123',
      }), {
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
      });

      authResponseTime.add(new Date() - startAuth);

      const loginSuccess = check(loginRes, {
        'login successful': (r) => r.status === 200,
      });

      if (loginSuccess) {
        token = JSON.parse(loginRes.body).data.access_token;
      } else {
        errorRate.add(1);
        return;
      }
    });
  }

  // Test various API endpoints
  group('User Management', function () {
    const startTime = new Date();
    const res = http.get(`${BASE_URL}/api/v1/users`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/json',
      },
    });

    apiResponseTime.add(new Date() - startTime);

    const success = check(res, {
      'users list status 200': (r) => r.status === 200,
      'users list has data': (r) => JSON.parse(r.body).data !== undefined,
    });

    errorRate.add(!success);
  });

  group('Applications', function () {
    const startTime = new Date();
    const res = http.get(`${BASE_URL}/api/v1/applications`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/json',
      },
    });

    apiResponseTime.add(new Date() - startTime);

    const success = check(res, {
      'applications list status 200': (r) => r.status === 200,
    });

    errorRate.add(!success);
  });

  group('Profile', function () {
    const startTime = new Date();
    const res = http.get(`${BASE_URL}/api/v1/profile`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/json',
      },
    });

    apiResponseTime.add(new Date() - startTime);

    const success = check(res, {
      'profile status 200': (r) => r.status === 200,
    });

    errorRate.add(!success);
  });

  sleep(Math.random() * 2 + 1); // Random think time between 1-3 seconds
}

export function setup() {
  console.log('Starting API stress test');
  console.log(`Base URL: ${BASE_URL}`);
  console.log(`Target: 1000 concurrent users`);
  return { startTime: new Date() };
}

export function teardown(data) {
  const endTime = new Date();
  const duration = (endTime - data.startTime) / 1000;
  console.log(`Stress test completed in ${duration} seconds`);
}
