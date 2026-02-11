import { describe, it, expect } from 'vitest';
import {
  resolveSpfIncludes,
  splitMechanismsIntoChunks,
} from '../../src/lib/spf.js';

describe('resolveSpfIncludes', () => {
  it('should parse basic SPF mechanisms', async () => {
    const spf = 'v=spf1 a mx ip4:192.168.1.1 -all';
    const result = await resolveSpfIncludes(spf);

    // Plain 'a' and 'mx' are filtered out during flattening
    expect(result.mechanisms).not.toContain('a');
    expect(result.mechanisms).not.toContain('mx');
    expect(result.mechanisms).toContain('ip4:192.168.1.1');
    expect(result.modifiers).toContain('-all');
  });

  it('should extract all modifier', async () => {
    const spf = 'v=spf1 a mx -all';
    const result = await resolveSpfIncludes(spf);

    expect(result.modifiers).toContain('-all');
  });

  it('should extract redirect modifier', async () => {
    const spf = 'v=spf1 redirect=example.com';
    const result = await resolveSpfIncludes(spf);

    expect(result.modifiers).toContain('redirect=example.com');
  });

  it('should handle all variations (~all, +all, ?all)', async () => {
    const spf1 = 'v=spf1 a ~all';
    const result1 = await resolveSpfIncludes(spf1);
    expect(result1.modifiers).toContain('~all');

    const spf2 = 'v=spf1 a +all';
    const result2 = await resolveSpfIncludes(spf2);
    expect(result2.modifiers).toContain('+all');

    const spf3 = 'v=spf1 a ?all';
    const result3 = await resolveSpfIncludes(spf3);
    expect(result3.modifiers).toContain('?all');
  });

  it('should not resolve plain a or mx mechanisms', async () => {
    const spf = 'v=spf1 a mx -all';
    const result = await resolveSpfIncludes(spf);

    // Plain 'a' and 'mx' should be skipped during flattening for shared records
    expect(result.mechanisms).not.toContain('a');
    expect(result.mechanisms).not.toContain('mx');
    expect(result.mechanisms).toEqual([]);
  });

  it('should stop at max recursion depth', async () => {
    const spf = 'v=spf1 a mx -all';
    const visited = new Set();
    const result = await resolveSpfIncludes(spf, visited, 11);

    expect(result.mechanisms).toEqual([]);
    expect(result.modifiers).toEqual([]);
  });

  it('should handle empty SPF record', async () => {
    const spf = 'v=spf1';
    const result = await resolveSpfIncludes(spf);

    expect(result.mechanisms).toEqual([]);
    expect(result.modifiers).toEqual([]);
  });

  it('should handle multiple IP mechanisms', async () => {
    const spf = 'v=spf1 ip4:192.168.1.1 ip4:10.0.0.1 ip6:2001:db8::1 -all';
    const result = await resolveSpfIncludes(spf);

    expect(result.mechanisms).toContain('ip4:192.168.1.1');
    expect(result.mechanisms).toContain('ip4:10.0.0.1');
    expect(result.mechanisms).toContain('ip6:2001:db8::1');
  });
});

describe('splitMechanismsIntoChunks', () => {
  it('should not split small records', () => {
    const mechanisms = ['ip4:192.168.1.1', 'ip4:10.0.0.1', 'mx'];
    const chunks = splitMechanismsIntoChunks(mechanisms, 450);

    expect(chunks).toHaveLength(1);
    expect(chunks[0]).toEqual(mechanisms);
  });

  it('should split large records into multiple chunks', () => {
    // Create many mechanisms that will exceed 450 bytes
    const mechanisms = [];
    for (let i = 0; i < 50; i++) {
      mechanisms.push(`ip4:192.168.1.${i}`);
    }

    const chunks = splitMechanismsIntoChunks(mechanisms, 450);

    expect(chunks.length).toBeGreaterThan(1);

    // Verify each chunk is under the limit
    chunks.forEach((chunk) => {
      const recordSize = 'v=spf1 '.length + chunk.join(' ').length;
      expect(recordSize).toBeLessThanOrEqual(450);
    });
  });

  it('should respect custom chunk size', () => {
    const mechanisms = [];
    for (let i = 0; i < 20; i++) {
      mechanisms.push(`ip4:192.168.1.${i}`);
    }

    const chunks = splitMechanismsIntoChunks(mechanisms, 100);

    expect(chunks.length).toBeGreaterThan(1);

    chunks.forEach((chunk) => {
      const recordSize = 'v=spf1 '.length + chunk.join(' ').length;
      expect(recordSize).toBeLessThanOrEqual(100);
    });
  });

  it('should handle single very long mechanism', () => {
    const longMechanism = `ip4:${  '192.168.1.1/24'.repeat(50)}`;
    const mechanisms = [longMechanism];

    const chunks = splitMechanismsIntoChunks(mechanisms, 450);

    // Should still create chunk even if single mechanism exceeds limit
    expect(chunks).toHaveLength(1);
    expect(chunks[0]).toEqual([longMechanism]);
  });

  it('should preserve mechanism order', () => {
    const mechanisms = ['a', 'mx', 'ip4:1.2.3.4', 'ip4:5.6.7.8'];
    const chunks = splitMechanismsIntoChunks(mechanisms, 450);

    // Flatten chunks and verify order
    const flattened = chunks.flat();
    expect(flattened).toEqual(mechanisms);
  });
});
