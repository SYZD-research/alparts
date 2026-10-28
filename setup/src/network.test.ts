import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer, type AddressInfo } from 'node:net';
import { test } from 'node:test';
import { busyPorts, chooseEdgeSubnet, EDGE_SUBNET_CANDIDATES, edgeNetworkLayout, overlaps, parseCidr, parseProcRoutes } from './network.ts';

test('CIDR parsing normalizes the base and rejects malformed input', () => {
  assert.deepEqual(parseCidr('10.0.0.7/24'), { base: 10 * 2 ** 24, prefix: 24 });
  assert.deepEqual(parseCidr('192.168.1.1'), { base: 3232235777, prefix: 32 });
  assert.equal(parseCidr('10.0.0.0/33'), null);
  assert.equal(parseCidr('fd00::/8'), null);
  assert.equal(parseCidr('nonsense'), null);
});

test('overlap compares at the shorter prefix', () => {
  assert.equal(overlaps(parseCidr('10.0.0.0/8')!, parseCidr('10.199.73.0/28')!), true);
  assert.equal(overlaps(parseCidr('10.199.73.16/28')!, parseCidr('10.199.73.0/28')!), false);
  assert.equal(overlaps(parseCidr('0.0.0.0/0')!, parseCidr('192.168.0.0/16')!), true);
});

test('the edge subnet skips candidates that collide with routes or networks', () => {
  assert.equal(chooseEdgeSubnet([]), EDGE_SUBNET_CANDIDATES[0]);
  assert.equal(chooseEdgeSubnet([parseCidr('10.0.0.0/8')!]), '172.29.199.0/28');
  assert.equal(chooseEdgeSubnet(EDGE_SUBNET_CANDIDATES.map((candidate) => parseCidr(candidate)!)), null);
});

test('the edge layout keeps the proxy outside the range Docker assigns from', () => {
  assert.deepEqual(edgeNetworkLayout('10.199.73.0/28'), {
    subnet: '10.199.73.0/28',
    gateway: '10.199.73.1',
    proxyAddress: '10.199.73.2',
    dynamicRange: '10.199.73.8/29',
  });
  assert.throws(() => edgeNetworkLayout('10.199.73.0/30'));
});

test('kernel routes are read from little-endian hex, without the default route', () => {
  const table = [
    'Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT',
    'eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0',
    'eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0',
    'docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0',
  ].join('\n');
  assert.deepEqual(parseProcRoutes(table), [parseCidr('192.168.1.0/24'), parseCidr('172.17.0.0/16')]);
});

test('a port in use is reported busy and a free one is not', async () => {
  const server = createServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address() as AddressInfo;
  try {
    assert.deepEqual(await busyPorts([{ port, protocol: 'tcp', host: '127.0.0.1' }]), [{ port, protocol: 'tcp', host: '127.0.0.1' }]);
  } finally {
    server.close();
  }
  await once(server, 'close');
  assert.deepEqual(await busyPorts([{ port, protocol: 'tcp', host: '127.0.0.1' }]), []);
});
