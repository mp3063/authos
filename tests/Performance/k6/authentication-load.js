import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');

// Load test configuration
export const options = {
  stages: [
    { duration: '30s', target: 10 },   // Ramp up to 10 users
    { duration: '1m', target: 50 },    // Ramp up to 50 users
    { duration: '2m', target: 100 },   // Ramp up to 100 users
    { duration: '2m', target: 100 },   // Stay at 100 users
    { duration: '1m', target: 0 },     // Ramp down to 0 users
  ],
  thresholds: {
    http_req_duration: ['p(95)<200'],  // 95% of requests should be below 200ms
    http_req_failed: ['rate<0.05'],    // Error rate should be less than 5%
    errors: ['rate<0.05'],
  },
};

// Base URL - update this for your environment
const BASE_URL = __ENV.BASE_URL || 'http://authos.test';

// Test data
const users = [
  { email: 'admin@authservice.com', password: 'password123' },
  { email: 'test@example.com', password: 'password123' },
];

export default function () {
  // Select random user
  const user = users[Math.floor(Math.random() * users.length)];

  // Login request
  const loginRes = http.post(`${BASE_URL}/api/v1/auth/login`, JSON.stringify({
    email: user.email,
    password: user.password,
  }), {
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
  });

  // Check response
  const loginSuccess = check(loginRes, {
    'login status is 200': (r) => r.status === 200,
    'login returns token': (r) => JSON.parse(r.body).data?.access_token !== undefined,
    'login response time < 100ms': (r) => r.timings.duration < 100,
  });

  errorRate.add(!loginSuccess);

  if (loginSuccess) {
    const token = JSON.parse(loginRes.body).data.access_token;

    // Make authenticated request
    const profileRes = http.get(`${BASE_URL}/api/v1/profile`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/json',
      },
    });

    const profileSuccess = check(profileRes, {
      'profile status is 200': (r) => r.status === 200,
      'profile has data': (r) => JSON.parse(r.body).data !== undefined,
    });

    errorRate.add(!profileSuccess);
  }

  sleep(1); // Think time between iterations
}

// Setup function - runs once at the beginning
export function setup() {
  console.log('Starting authentication load test');
  console.log(`Base URL: ${BASE_URL}`);
  return { startTime: new Date() };
}

// Teardown function - runs once at the end
export function teardown(data) {
  const endTime = new Date();
  const duration = (endTime - data.startTime) / 1000;
  console.log(`Test completed in ${duration} seconds`);
}
