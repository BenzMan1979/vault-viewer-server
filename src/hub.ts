// All server logic, independent of Cloudflare so it can be unit-tested and self-hosted.
// The Durable Object (index.ts) just passes its storage in; there is exactly one Hub, so every
// counter update is serialised and strongly consistent.

export const SERVER_VERSION = 1;

export interface Store {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
  delete(key: string): Promise<boolean>;
  list<T>(options: { prefix: string; limit?: number; reverse?: boolean }): Promise<Map<string, T>>;
}

export interface Env {
  ADMIN_PASSWORD?: string;
}

export interface VaultPolicy {
  notBefore: string | null;
  expiresAt: string | null;
  maxOpens: number | null;
  maxFailures: number;
  sessionMinutes: number;
}

interface VaultRecord {
  id: string;
  batchId: string;
  title: string;
  recipient: string;
  authKey: string;
  share: string;
  policy: VaultPolicy;
  opens: number;
  failures: number;
  locked: boolean;
  revoked: boolean;
  createdAt: string;
  lastOpenAt: string | null;
}

export interface LogEntry {
  t: string;
  ev: 'open' | 'resume' | 'bad_proof' | 'locked' | 'denied';
  detail?: string;
  ip?: string;
  country?: string;
  ua?: string;
}

const NONCE_MS = 2 * 60 * 1000;
const ADMIN_SESSION_MS = 12 * 60 * 60 * 1000;
const ADMIN_MAX_FAILURES = 5;
const ADMIN_LOCK_MS = 15 * 60 * 1000;
// Workers' free plan allows ~10 ms CPU per request, so the admin hash stays light; brute force
// is stopped by the login lockout instead.
const PBKDF2_ITERATIONS = 5000;

const enc = new TextEncoder();
type Bytes = Uint8Array<ArrayBuffer>;

const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));
const unb64 = (s: string): Bytes => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

function randomToken(bytes = 24): string {
  const b = new Uint8Array(bytes);
  crypto.getRandomValues(b);
  return b64(b).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

async function sha256(s: string): Promise<Bytes> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(s)));
}

async function pbkdf2(password: string, salt: Bytes, iterations: number): Promise<Bytes> {
  const k = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, k, 256));
}

async function hmac(key: Bytes, msg: Bytes): Promise<Bytes> {
  const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, msg));
}

/** Must match openProofMessage() in the client core. */
const openProofMessage = (vaultId: string, nonce: string) => enc.encode(`vault-viewer/v1/open:${vaultId}:${nonce}`) as Bytes;

const CORS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, POST, PATCH, DELETE, OPTIONS',
  'access-control-allow-headers': 'content-type, authorization',
  'access-control-max-age': '86400',
};

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...CORS },
  });
}

const fail = (status: number, code: string, message: string, extra: object = {}) =>
  json({ ok: false, code, message, ...extra }, status);

const isStr = (v: unknown, max = 500): v is string => typeof v === 'string' && v.length > 0 && v.length <= max;

function cleanPolicy(p: Partial<VaultPolicy> | undefined): VaultPolicy {
  const date = (v: unknown) => (typeof v === 'string' && !Number.isNaN(Date.parse(v)) ? new Date(v).toISOString() : null);
  const int = (v: unknown, d: number, min: number, max: number) =>
    typeof v === 'number' && Number.isFinite(v) ? Math.min(max, Math.max(min, Math.round(v))) : d;
  return {
    notBefore: date(p?.notBefore),
    expiresAt: date(p?.expiresAt),
    maxOpens: p?.maxOpens == null ? null : int(p.maxOpens, 1, 1, 1_000_000),
    maxFailures: int(p?.maxFailures, 5, 0, 1000),
    sessionMinutes: int(p?.sessionMinutes, 30, 0, 24 * 60),
  };
}

function publicVault(v: VaultRecord) {
  const { authKey: _a, share: _s, ...rest } = v;
  return rest;
}

export class Hub {
  constructor(
    private store: Store,
    private env: Env,
    private now: () => number = Date.now,
  ) {}

  async handle(req: Request): Promise<Response> {
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
    try {
      return await this.route(req);
    } catch (e) {
      if (e instanceof BadRequest) return fail(400, 'bad_request', e.message);
      throw e;
    }
  }

  private async route(req: Request): Promise<Response> {
    const path = new URL(req.url).pathname.replace(/\/+$/, '');
    {
      if (path === '/api/info' && req.method === 'GET') return this.info();
      if (path === '/api/open/challenge' && req.method === 'POST') return this.challenge(await body(req));
      if (path === '/api/open' && req.method === 'POST') return this.open(req, await body(req));
      if (path === '/api/admin/setup' && req.method === 'POST') return this.setup(await body(req));
      if (path === '/api/admin/login' && req.method === 'POST') return this.login(await body(req));
      if (path.startsWith('/api/admin/')) {
        const token = req.headers.get('authorization')?.replace(/^Bearer\s+/i, '') ?? '';
        if (!(await this.checkAdmin(token))) return fail(401, 'unauthorized', '登入已過期，請重新登入管理員');
        if (path === '/api/admin/logout' && req.method === 'POST') {
          await this.store.delete(`admin:sess:${token}`);
          return json({ ok: true });
        }
        if (path === '/api/admin/password' && req.method === 'POST') return this.changePassword(await body(req));
        if (path === '/api/admin/vaults' && req.method === 'POST') return this.register(await body(req));
        if (path === '/api/admin/vaults' && req.method === 'GET') return this.listVaults();
        const m = path.match(/^\/api\/admin\/vaults\/([a-z0-9]{1,64})(\/logs)?$/);
        if (m && m[2] && req.method === 'GET') return this.logs(m[1]);
        if (m && !m[2] && req.method === 'PATCH') return this.update(m[1], await body(req));
        if (m && !m[2] && req.method === 'DELETE') return this.remove(m[1]);
      }
      return fail(404, 'not_found', '找不到這個功能');
    }
  }

  private async info() {
    return json({ ok: true, app: 'vault-viewer-server', version: SERVER_VERSION, adminConfigured: await this.adminConfigured(), serverTime: new Date(this.now()).toISOString() });
  }

  // ---------- opening a vault ----------

  private async challenge(b: Record<string, unknown>) {
    if (!isStr(b.vaultId, 64)) throw new BadRequest('vaultId');
    const v = await this.store.get<VaultRecord>(`vault:${b.vaultId}`);
    if (!v) return fail(404, 'unknown', '伺服器上找不到這份封存檔（可能已被刪除）');
    const now = this.now();
    for (const [k, exp] of await this.store.list<number>({ prefix: `nonce:${v.id}:` })) {
      if (exp < now) await this.store.delete(k);
    }
    const nonce = randomToken(18);
    await this.store.put(`nonce:${v.id}:${nonce}`, now + NONCE_MS);
    return json({ ok: true, nonce });
  }

  private async open(req: Request, b: Record<string, unknown>) {
    if (!isStr(b.vaultId, 64) || !isStr(b.nonce, 64) || !isStr(b.proof, 100)) throw new BadRequest('vaultId/nonce/proof');
    const key = `vault:${b.vaultId}`;
    const v = await this.store.get<VaultRecord>(key);
    if (!v) return fail(404, 'unknown', '伺服器上找不到這份封存檔（可能已被刪除）');
    const now = this.now();
    const meta = { ip: req.headers.get('x-vv-ip') ?? undefined, country: req.headers.get('x-vv-country') ?? undefined, ua: req.headers.get('user-agent')?.slice(0, 200) };
    const deny = async (status: number, code: string, message: string, extra: object = {}) => {
      await this.log(v.id, { ev: 'denied', detail: code, ...meta });
      return fail(status, code, message, extra);
    };

    if (v.revoked) return deny(403, 'revoked', '這份封存檔已被發送者收回');
    if (v.locked) return deny(423, 'locked', '密碼錯誤次數過多，已鎖定。請聯絡發送者解除');

    const nonceKey = `nonce:${v.id}:${b.nonce}`;
    const nonceExp = await this.store.get<number>(nonceKey);
    await this.store.delete(nonceKey);
    if (!nonceExp || nonceExp < now) return fail(400, 'bad_nonce', '驗證逾時，請再試一次');

    const expected = await hmac(unb64(v.authKey), openProofMessage(v.id, b.nonce));
    if (!sameBytes(expected, unb64(b.proof))) {
      v.failures += 1;
      const max = v.policy.maxFailures;
      if (max > 0 && v.failures >= max) v.locked = true;
      await this.store.put(key, v);
      await this.log(v.id, { ev: v.locked ? 'locked' : 'bad_proof', ...meta });
      if (v.locked) return fail(423, 'locked', '密碼錯誤次數過多，已鎖定。請聯絡發送者解除');
      return fail(401, 'bad_proof', '密碼或金鑰不正確', { remainingAttempts: max > 0 ? max - v.failures : null });
    }
    v.failures = 0;

    if (v.policy.notBefore && now < Date.parse(v.policy.notBefore)) {
      await this.store.put(key, v);
      return deny(403, 'not_yet', `這份封存檔要到 ${v.policy.notBefore} 之後才能開啟`, { notBefore: v.policy.notBefore });
    }
    if (v.policy.expiresAt && now >= Date.parse(v.policy.expiresAt)) {
      await this.store.put(key, v);
      return deny(403, 'expired', '這份封存檔已過期', { expiresAt: v.policy.expiresAt });
    }

    // A still-valid session (re-unlock after an idle lock) does not use up another open.
    let resumed = false;
    if (isStr(b.session, 64)) {
      const s = await this.store.get<{ vaultId: string; expires: number }>(`sess:${b.session}`);
      resumed = !!s && s.vaultId === v.id && s.expires > now;
      if (!resumed) await this.store.delete(`sess:${b.session}`);
    }
    if (!resumed) {
      if (v.policy.maxOpens != null && v.opens >= v.policy.maxOpens) {
        await this.store.put(key, v);
        return deny(403, 'exhausted', '可開啟次數已用完');
      }
      v.opens += 1;
    }
    v.lastOpenAt = new Date(now).toISOString();
    await this.store.put(key, v);

    const session = resumed ? (b.session as string) : randomToken();
    const sessionExpires = now + v.policy.sessionMinutes * 60 * 1000;
    if (v.policy.sessionMinutes > 0) await this.store.put(`sess:${session}`, { vaultId: v.id, expires: sessionExpires });
    await this.log(v.id, { ev: resumed ? 'resume' : 'open', ...meta });
    return json({
      ok: true,
      share: v.share,
      session: v.policy.sessionMinutes > 0 ? session : null,
      status: {
        opens: v.opens,
        maxOpens: v.policy.maxOpens,
        expiresAt: v.policy.expiresAt,
        serverTime: new Date(now).toISOString(),
      },
    });
  }

  private async log(vaultId: string, e: Omit<LogEntry, 't'>) {
    const t = new Date(this.now()).toISOString();
    const seq = ((await this.store.get<number>('logseq')) ?? 0) + 1;
    await this.store.put('logseq', seq);
    await this.store.put(`log:${vaultId}:${String(seq).padStart(12, '0')}`, { t, ...e });
  }

  // ---------- admin ----------

  private async adminConfigured() {
    return !!(this.env.ADMIN_PASSWORD || (await this.store.get('admin:pw')));
  }

  private async setup(b: Record<string, unknown>) {
    if (await this.adminConfigured()) return fail(409, 'already_configured', '管理員密碼已經設定過了');
    if (!isStr(b.password, 200) || b.password.length < 8) throw new BadRequest('管理員密碼至少 8 個字元');
    await this.savePassword(b.password);
    return this.issueAdminToken();
  }

  private async savePassword(password: string) {
    const salt = new Uint8Array(16);
    crypto.getRandomValues(salt);
    const hash = await pbkdf2(password, salt, PBKDF2_ITERATIONS);
    await this.store.put('admin:pw', { salt: b64(salt), hash: b64(hash), iterations: PBKDF2_ITERATIONS });
  }

  private async verifyPassword(password: string): Promise<boolean> {
    const stored = await this.store.get<{ salt: string; hash: string; iterations: number }>('admin:pw');
    if (stored) return sameBytes(await pbkdf2(password, unb64(stored.salt), stored.iterations), unb64(stored.hash));
    if (this.env.ADMIN_PASSWORD) return sameBytes(await sha256(password), await sha256(this.env.ADMIN_PASSWORD));
    return false;
  }

  private async login(b: Record<string, unknown>) {
    if (!isStr(b.password, 200)) throw new BadRequest('password');
    if (!(await this.adminConfigured())) return fail(409, 'not_configured', '伺服器還沒有設定管理員密碼');
    const now = this.now();
    const lock = (await this.store.get<{ failures: number; until: number }>('admin:lock')) ?? { failures: 0, until: 0 };
    if (lock.until > now) {
      return fail(429, 'admin_locked', `登入失敗太多次，請 ${Math.ceil((lock.until - now) / 60000)} 分鐘後再試`);
    }
    if (!(await this.verifyPassword(b.password))) {
      lock.failures += 1;
      if (lock.failures >= ADMIN_MAX_FAILURES) {
        lock.failures = 0;
        lock.until = now + ADMIN_LOCK_MS;
      }
      await this.store.put('admin:lock', lock);
      return fail(401, 'bad_password', '管理員密碼不正確');
    }
    await this.store.delete('admin:lock');
    return this.issueAdminToken();
  }

  private async issueAdminToken() {
    const token = randomToken();
    const expires = this.now() + ADMIN_SESSION_MS;
    await this.store.put(`admin:sess:${token}`, expires);
    return json({ ok: true, token, expiresAt: new Date(expires).toISOString() });
  }

  private async checkAdmin(token: string) {
    if (!token || token.length > 100) return false;
    const exp = await this.store.get<number>(`admin:sess:${token}`);
    if (!exp) return false;
    if (exp < this.now()) {
      await this.store.delete(`admin:sess:${token}`);
      return false;
    }
    return true;
  }

  private async changePassword(b: Record<string, unknown>) {
    if (!isStr(b.current, 200) || !isStr(b.next, 200)) throw new BadRequest('current/next');
    if (b.next.length < 8) throw new BadRequest('新密碼至少 8 個字元');
    if (!(await this.verifyPassword(b.current))) return fail(401, 'bad_password', '目前的管理員密碼不正確');
    await this.savePassword(b.next);
    for (const k of (await this.store.list({ prefix: 'admin:sess:' })).keys()) await this.store.delete(k);
    return this.issueAdminToken();
  }

  private async register(b: Record<string, unknown>) {
    if (!Array.isArray(b.vaults) || b.vaults.length === 0 || b.vaults.length > 500) throw new BadRequest('vaults');
    const now = new Date(this.now()).toISOString();
    const records: VaultRecord[] = [];
    for (const raw of b.vaults as Record<string, unknown>[]) {
      if (!isStr(raw.id, 64) || !/^[a-z0-9]+$/.test(raw.id)) throw new BadRequest('id');
      if (!isStr(raw.authKey, 100) || unb64(raw.authKey).length !== 32) throw new BadRequest('authKey');
      if (!isStr(raw.share, 100) || unb64(raw.share).length !== 32) throw new BadRequest('share');
      if (await this.store.get(`vault:${raw.id}`)) return fail(409, 'exists', `封存檔 ${raw.id} 已經登記過了`);
      records.push({
        id: raw.id,
        batchId: isStr(raw.batchId, 64) ? raw.batchId : raw.id,
        title: isStr(raw.title, 200) ? raw.title : '',
        recipient: isStr(raw.recipient, 200) ? raw.recipient : '',
        authKey: raw.authKey,
        share: raw.share,
        policy: cleanPolicy(raw.policy as Partial<VaultPolicy>),
        opens: 0,
        failures: 0,
        locked: false,
        revoked: false,
        createdAt: now,
        lastOpenAt: null,
      });
    }
    for (const r of records) await this.store.put(`vault:${r.id}`, r);
    return json({ ok: true, count: records.length });
  }

  private async listVaults() {
    const all = await this.store.list<VaultRecord>({ prefix: 'vault:' });
    const vaults = [...all.values()].map(publicVault).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    return json({ ok: true, vaults, serverTime: new Date(this.now()).toISOString() });
  }

  private async logs(id: string) {
    const all = await this.store.list<LogEntry>({ prefix: `log:${id}:`, reverse: true, limit: 500 });
    return json({ ok: true, logs: [...all.values()] });
  }

  private async update(id: string, b: Record<string, unknown>) {
    const key = `vault:${id}`;
    const v = await this.store.get<VaultRecord>(key);
    if (!v) return fail(404, 'unknown', '找不到這份封存檔');
    if (typeof b.revoked === 'boolean') v.revoked = b.revoked;
    if (b.unlock === true) {
      v.locked = false;
      v.failures = 0;
    }
    if (b.resetOpens === true) v.opens = 0;
    if (b.policy && typeof b.policy === 'object') v.policy = cleanPolicy({ ...v.policy, ...(b.policy as object) });
    await this.store.put(key, v);
    if (v.revoked) {
      for (const [k, s] of await this.store.list<{ vaultId: string }>({ prefix: 'sess:' })) {
        if (s.vaultId === id) await this.store.delete(k);
      }
    }
    return json({ ok: true, vault: publicVault(v) });
  }

  private async remove(id: string) {
    if (!(await this.store.delete(`vault:${id}`))) return fail(404, 'unknown', '找不到這份封存檔');
    for (const k of (await this.store.list({ prefix: `log:${id}:` })).keys()) await this.store.delete(k);
    return json({ ok: true });
  }
}

class BadRequest extends Error {}

async function body(req: Request): Promise<Record<string, unknown>> {
  try {
    const b = await req.json();
    if (b && typeof b === 'object' && !Array.isArray(b)) return b as Record<string, unknown>;
  } catch {
    /* fall through */
  }
  throw new BadRequest('請求格式錯誤');
}

/** In-memory Store for tests and quick local runs. */
export class MemoryStore implements Store {
  private m = new Map<string, unknown>();
  async get<T>(key: string) {
    const v = this.m.get(key);
    return v === undefined ? undefined : (structuredClone(v) as T);
  }
  async put<T>(key: string, value: T) {
    this.m.set(key, structuredClone(value));
  }
  async delete(key: string) {
    return this.m.delete(key);
  }
  async list<T>(o: { prefix: string; limit?: number; reverse?: boolean }) {
    let keys = [...this.m.keys()].filter((k) => k.startsWith(o.prefix)).sort();
    if (o.reverse) keys.reverse();
    if (o.limit) keys = keys.slice(0, o.limit);
    return new Map(keys.map((k) => [k, structuredClone(this.m.get(k)) as T]));
  }
}
