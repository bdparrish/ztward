import { test } from 'node:test';
import assert from 'node:assert/strict';
import { KeyStatus } from '../generated/services/key-manager/key-manager_pb.js';
import { isClientKeyUsable } from './key-registration.js';

const clientAnswering = (answer) => ({ getClientKey: async () => answer() });
const found = (status) => ({ found: true, key: { keyId: 'k1', status } });

test('active key is usable', async () => {
  assert.equal(await isClientKeyUsable('c1', 'k1', { client: clientAnswering(() => found(KeyStatus.ACTIVE)) }), true);
});

test('unknown key is not usable', async () => {
  assert.equal(await isClientKeyUsable('c1', 'k1', { client: clientAnswering(() => ({ found: false })) }), false);
});

test('revoked key is not usable', async () => {
  assert.equal(await isClientKeyUsable('c1', 'k1', { client: clientAnswering(() => found(KeyStatus.REVOKED)) }), false);
});

test('RPC failure is an error, not a verdict', async () => {
  const failing = clientAnswering(() => { throw new Error('unavailable'); });
  await assert.rejects(isClientKeyUsable('c1', 'k1', { client: failing }), /unavailable/);
});
