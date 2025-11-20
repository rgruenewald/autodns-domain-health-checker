import { describe, it, expect } from 'vitest';
import { resolveSpfIncludes } from '../../src/lib/spf.js';

describe('resolveSpfIncludes', () => {
  it('should parse basic SPF mechanisms', async () => {
    const spf = 'v=spf1 a mx ip4:192.168.1.1 -all';
    const result = await resolveSpfIncludes(spf);

    expect(result.mechanisms).toContain('a');
    expect(result.mechanisms).toContain('mx');
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

    expect(result.mechanisms).toContain('a');
    expect(result.mechanisms).toContain('mx');
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
