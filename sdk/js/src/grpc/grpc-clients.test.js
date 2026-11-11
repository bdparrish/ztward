import { test } from 'node:test';
import assert from 'node:assert/strict';
import { KeyAccessGrpcClient } from './key-access-grpc.js';
import { KeyManagerGrpcClient } from './key-manager-grpc.js';
import { PlatformGrpcClient } from './platform-grpc.js';

// These classes used to load their transport with require(), which does not
// exist in an ES module, so the constructors always threw.
for (const Client of [KeyAccessGrpcClient, KeyManagerGrpcClient, PlatformGrpcClient]) {
  test(`${Client.name} constructs in a browser environment`, (t) => {
    globalThis.window = {};
    t.after(() => { delete globalThis.window; });
    const client = new Client('http://localhost:8081', async () => 'token');
    assert.ok(client.client, 'expected an underlying Connect client');
  });
}
