const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');

const server = path.join(__dirname, '..', 'server.js');
const baseEnv = { PATH: process.env.PATH, NODE_ENV: 'test' };

function runWith(env) {
  return spawnSync(process.execPath, [server], {
    env: { ...baseEnv, ...env },
    encoding: 'utf8',
    timeout: 5000
  });
}

test('server refuses to start when required database/JWT configuration is missing', () => {
  const result = runWith({});
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Missing required environment variables/);
});

test('server refuses weak or placeholder JWT secrets before opening a listener', () => {
  const result = runWith({
    SUPABASE_URL: 'https://example.supabase.co',
    SUPABASE_SERVICE_KEY: 'test-service-key',
    JWT_SECRET: 'replace_with_a_short_secret'
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /JWT_SECRET must be a unique random secret/);
});

test('production startup requires an explicit frontend origin allowlist', () => {
  const result = runWith({
    NODE_ENV: 'production',
    SUPABASE_URL: 'https://example.supabase.co',
    SUPABASE_SERVICE_KEY: 'test-service-key',
    JWT_SECRET: 'a'.repeat(64)
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /FRONTEND_URL must contain the exact deployed frontend origin/);
});
