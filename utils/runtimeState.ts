// In-memory runtime state shared across trace executions in a single
// process: SpikeArrest / Quota counters and a simple TTL cache backing the
// ResponseCache / PopulateCache / LookupCache policies. This is process-local
// (resets on server restart) which is appropriate for an interview-practice
// simulator - it demonstrates the *behavior* of these policies without
// needing Redis/Memcached.

interface Window {
  windowStart: number;
  count: number;
}

const spikeArrestWindows = new Map<string, Window>();
const quotaWindows = new Map<string, Window>();
const cacheStore = new Map<string, { value: any; expiresAt: number }>();

interface IssuedToken {
  clientId: string;
  developerAppId: string;
  scope: string;
  expiresAt: number;
}
const tokenStore = new Map<string, IssuedToken>();

export function parseRate(rate: string): { count: number; windowMs: number } {
  const match = /^(\d+)(ps|pm|ph)$/i.exec(rate.trim());
  if (!match) return { count: 100, windowMs: 1000 };
  const count = parseInt(match[1], 10);
  const unit = match[2].toLowerCase();
  const windowMs = unit === "ps" ? 1000 : unit === "pm" ? 60000 : 3600000;
  return { count, windowMs };
}

export function checkSpikeArrest(key: string, rate: string): { allowed: boolean; count: number; limit: number } {
  const { count: limit, windowMs } = parseRate(rate);
  const now = Date.now();
  let w = spikeArrestWindows.get(key);
  if (!w || now - w.windowStart > windowMs) {
    w = { windowStart: now, count: 0 };
    spikeArrestWindows.set(key, w);
  }
  w.count += 1;
  return { allowed: w.count <= limit, count: w.count, limit };
}

const TIME_UNIT_MS: Record<string, number> = {
  minute: 60000,
  hour: 3600000,
  day: 86400000,
  month: 2592000000,
};

export function checkQuota(
  key: string,
  allowCount: number,
  interval: number,
  timeUnit: string
): { allowed: boolean; count: number; limit: number; resetsInMs: number } {
  const windowMs = (TIME_UNIT_MS[timeUnit] || 3600000) * Math.max(interval, 1);
  const now = Date.now();
  let w = quotaWindows.get(key);
  if (!w || now - w.windowStart > windowMs) {
    w = { windowStart: now, count: 0 };
    quotaWindows.set(key, w);
  }
  w.count += 1;
  return {
    allowed: w.count <= allowCount,
    count: w.count,
    limit: allowCount,
    resetsInMs: windowMs - (now - w.windowStart),
  };
}

export function cacheSet(key: string, value: any, ttlSeconds: number) {
  cacheStore.set(key, { value, expiresAt: Date.now() + ttlSeconds * 1000 });
}

export function cacheGet(key: string): { hit: boolean; value?: any } {
  const entry = cacheStore.get(key);
  if (!entry) return { hit: false };
  if (Date.now() > entry.expiresAt) {
    cacheStore.delete(key);
    return { hit: false };
  }
  return { hit: true, value: entry.value };
}

export function issueToken(clientId: string, developerAppId: string, scope: string, ttlSeconds = 3600): { token: string; expiresIn: number } {
  const token = "sim_at_" + Math.random().toString(36).slice(2, 10) + Math.random().toString(36).slice(2, 10);
  tokenStore.set(token, { clientId, developerAppId, scope, expiresAt: Date.now() + ttlSeconds * 1000 });
  return { token, expiresIn: ttlSeconds };
}

export function verifyIssuedToken(token: string): { valid: boolean; expired?: boolean; clientId?: string; developerAppId?: string; scope?: string } {
  const entry = tokenStore.get(token);
  if (!entry) return { valid: false };
  if (Date.now() > entry.expiresAt) {
    tokenStore.delete(token);
    return { valid: false, expired: true };
  }
  return { valid: true, clientId: entry.clientId, developerAppId: entry.developerAppId, scope: entry.scope };
}

export function resetRuntimeState() {
  spikeArrestWindows.clear();
  quotaWindows.clear();
  cacheStore.clear();
  tokenStore.clear();
}
