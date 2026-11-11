import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createAuthenticatedTransport } from './grpc-transport.js';

// The SDK ships as an ES module, where `require` does not exist: the gRPC-Web
// transport must load through a normal import or every browser app breaks.
test('creates a gRPC-Web transport in a browser environment', (t) => {
  globalThis.window = {};
  t.after(() => { delete globalThis.window; });
  const transport = createAuthenticatedTransport('http://localhost:8081', async () => 'token');
  assert.equal(typeof transport.unary, 'function');
});

test('refuses to run outside a browser', () => {
  assert.throws(() => createAuthenticatedTransport('http://localhost:8081', async () => 't'), /only available in browsers/);
});
