// Núcleo da API do Painel de Fretes Expressos (login + dados compartilhados).
// Independente do Netlify para poder ser testado com um armazenamento em memória.
import crypto from 'node:crypto';

const ROLES = { admin: 'Administrador', operacao: 'Operação' };
const COOKIE = 'ilc_session';
const SHORT_TTL = 12 * 60 * 60;          // 12 h
const LONG_TTL = 30 * 24 * 60 * 60;      // 30 dias ("manter conectado")
const MAX_FAILS = 8, LOCK_MS = 15 * 60 * 1000;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

class HttpError extends Error { constructor(status, message) { super(message); this.status = status; } }
const fail = (status, message) => { throw new HttpError(status, message); };

const json = (status, body, headers = {}) => new Response(JSON.stringify(body), {
  status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers },
});

// ---------- senhas ----------
const scrypt = (pw, salt) => new Promise((res, rej) =>
  crypto.scrypt(pw, salt, 64, { N: 16384, r: 8, p: 1 }, (e, k) => (e ? rej(e) : res(k.toString('hex')))));
async function makePassword(pw) { const salt = crypto.randomBytes(16).toString('hex'); return { algo: 'scrypt', salt, hash: await scrypt(pw, salt) }; }
const safeEq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };
async function checkPassword(u, pw) {
  if (!u || typeof pw !== 'string') return false;
  if (u.algo === 'scrypt') return safeEq(await scrypt(pw, u.salt), u.hash);
  // formato antigo do painel (SHA-256 de "salt:login:senha"), aceito só para migração
  const legacy = crypto.createHash('sha256').update(`${u.salt}:${u.login}:${pw}`).digest('hex');
  return safeEq(legacy, u.hash);
}
function validPassword(pw) { if (typeof pw !== 'string' || pw.length < 6) fail(400, 'A senha precisa ter pelo menos 6 caracteres.'); }
const publicUser = u => ({ login: u.login, name: u.name, role: u.role });

// ---------- armazenamento com controle de concorrência ----------
async function readKey(store, key) {
  const r = await store.getWithMetadata(key, { type: 'json' });
  return r ? { data: r.data, etag: r.etag } : { data: null, etag: null };
}
// Lê, altera e grava com etag; repete se outra pessoa gravou ao mesmo tempo.
async function mutate(store, key, fn) {
  for (let i = 0; i < 6; i++) {
    const { data, etag } = await readKey(store, key);
    const out = await fn(data);
    const opts = etag ? { onlyIfMatch: etag } : { onlyIfNew: true };
    const w = await store.setJSON(key, out.next, opts);
    if (w && w.modified === false) continue;
    return { ...out, etag: w?.etag ?? null };
  }
  fail(409, 'Muitas alterações ao mesmo tempo. Tente novamente.');
}

// ---------- sessão (cookie HttpOnly assinado) ----------
async function getSecret(store, env) {
  if (env.SESSION_SECRET && env.SESSION_SECRET.length >= 16) return env.SESSION_SECRET;
  let s = await store.get('session-secret', { type: 'text' });
  if (!s) {
    await store.set('session-secret', crypto.randomBytes(32).toString('hex'), { onlyIfNew: true });
    s = await store.get('session-secret', { type: 'text' });
  }
  return s;
}
const b64u = s => Buffer.from(s).toString('base64url');
const sign = (payload, secret) => crypto.createHmac('sha256', secret).update(payload).digest('base64url');
function makeToken(user, ttl, secret) {
  const p = b64u(JSON.stringify({ l: user.login, v: user.salt.slice(0, 12), e: Date.now() + ttl * 1000 }));
  return `${p}.${sign(p, secret)}`;
}
function readToken(token, secret) {
  if (!token || !token.includes('.')) return null;
  const [p, sig] = token.split('.');
  if (!safeEq(sign(p, secret), sig)) return null;
  try { const d = JSON.parse(Buffer.from(p, 'base64url').toString()); return d.e > Date.now() ? d : null; } catch { return null; }
}
function cookieHeader(value, maxAge, secure) {
  // maxAge null = cookie de sessão (some ao fechar o navegador)
  return `${COOKIE}=${value}; Path=/; HttpOnly; SameSite=Strict${secure ? '; Secure' : ''}${maxAge === null ? '' : `; Max-Age=${maxAge}`}`;
}
function getCookie(req, name) {
  const raw = req.headers.get('cookie') || '';
  for (const part of raw.split(';')) { const [k, ...v] = part.trim().split('='); if (k === name) return v.join('='); }
  return null;
}

// ---------- usuários ----------
async function loadUsers(store) { const { data } = await readKey(store, 'users'); return Array.isArray(data) ? data : []; }

async function currentUser(req, store, env) {
  const d = readToken(getCookie(req, COOKIE), await getSecret(store, env));
  if (!d) return null;
  const u = (await loadUsers(store)).find(x => x.login === d.l);
  return u && u.salt.slice(0, 12) === d.v ? u : null;
}

// ---------- dados do painel ----------
function validDb(d) {
  return d && d.version === 3 && Array.isArray(d.opps) && Array.isArray(d.requests) &&
    d.opps.every(o => o && typeof o.id === 'string' && typeof o.status === 'string');
}
function nextOpId(opps) {
  const n = Math.max(0, ...opps.filter(o => /^OP-\d+$/.test(o.id)).map(o => Number(o.id.split('-')[1])));
  return 'OP-' + String(n + 1).padStart(6, '0');
}
const sameRecord = (a, b) => JSON.stringify(a) === JSON.stringify(b);

// Insere ou atualiza um registro. Se for novo e o ID já existir (outro computador criou), gera outro ID.
function upsertRecord(db, record, isNew) {
  const opps = db.opps.slice();
  let rec = { ...record };
  const i = opps.findIndex(o => o.id === rec.id);
  if (isNew && i >= 0) {
    if (sameRecord(opps[i], rec)) return { db, record: opps[i] };
    rec.id = nextOpId(opps);
    opps.unshift(rec);
  } else if (i >= 0) opps[i] = rec;
  else opps.unshift(rec);
  const clients = [...new Set([...(db.clients || []), rec.client].filter(Boolean))];
  return { db: { ...db, opps, clients }, record: rec };
}

// ---------- roteador ----------
export function createApi({ getStore, env = {} }) {
  return async function handle(req) {
    const store = getStore();
    const url = new URL(req.url);
    const path = url.pathname.replace(/^\/(\.netlify\/functions\/api|api)/, '') || '/';
    const method = req.method.toUpperCase();
    const secure = url.protocol === 'https:';
    try {
      if (method !== 'GET' && method !== 'HEAD') {
        // proteção extra contra envio de formulário de outro site
        const origin = req.headers.get('origin');
        if (origin && origin !== url.origin) fail(403, 'Origem não permitida.');
        if (!(req.headers.get('content-type') || '').includes('application/json')) fail(415, 'Formato inválido.');
      }
      const body = method === 'GET' || method === 'HEAD' ? {} : await req.json().catch(() => ({}));

      // ---- login ----
      if (path === '/login' && method === 'POST') {
        const login = String(body.login || '').trim().toLowerCase(), pw = String(body.password || '');
        if (!login || !pw) fail(400, 'Informe e-mail e senha.');
        const failKey = 'fail-' + crypto.createHash('sha256').update(login).digest('hex').slice(0, 24);
        const f = (await store.get(failKey, { type: 'json' })) || { n: 0, t: 0 };
        if (f.n >= MAX_FAILS && Date.now() - f.t < LOCK_MS) fail(429, 'Muitas tentativas. Aguarde 15 minutos e tente novamente.');

        let users = await loadUsers(store);
        let user = users.find(u => u.login === login);
        // Primeiro acesso: nenhum usuário no servidor -> administrador definido nas variáveis do Netlify.
        if (!users.length) {
          const adminEmail = String(env.ILC_ADMIN_EMAIL || 'matheus.fernandes@ilclog.com.br').trim().toLowerCase();
          const adminPw = env.ILC_ADMIN_PASSWORD || '';
          if (!adminPw) fail(503, 'Primeiro acesso não configurado. Defina ILC_ADMIN_PASSWORD no Netlify.');
          if (login === adminEmail && safeEq(pw, adminPw)) {
            const created = { login, name: env.ILC_ADMIN_NAME || 'Matheus Fernandes', role: 'admin', ...(await makePassword(pw)) };
            await mutate(store, 'users', cur => ({ next: Array.isArray(cur) && cur.length ? cur : [created] }));
            users = await loadUsers(store); user = users.find(u => u.login === login);
          }
        }
        if (!user || !(await checkPassword(user, pw))) {
          await store.setJSON(failKey, { n: (Date.now() - f.t < LOCK_MS ? f.n : 0) + 1, t: Date.now() });
          fail(401, 'E-mail ou senha incorretos.');
        }
        if (f.n) await store.delete(failKey);
        if (user.algo !== 'scrypt') { // converte senha antiga para o formato seguro
          const upgraded = { ...user, ...(await makePassword(pw)) };
          await mutate(store, 'users', cur => ({ next: (cur || []).map(u => (u.login === login ? upgraded : u)) }));
          user = upgraded;
        }
        const ttl = body.keep ? LONG_TTL : SHORT_TTL;
        const token = makeToken(user, ttl, await getSecret(store, env));
        return json(200, { user: publicUser(user) }, { 'set-cookie': cookieHeader(token, body.keep ? ttl : null, secure) });
      }
      if (path === '/logout' && method === 'POST') return json(200, { ok: true }, { 'set-cookie': cookieHeader('', 0, secure) });

      // ---- daqui para baixo exige sessão ----
      const me = await currentUser(req, store, env);
      if (!me) fail(401, 'Sessão expirada. Entre novamente.');
      const isAdmin = me.role === 'admin';
      const needAdmin = () => { if (!isAdmin) fail(403, 'Apenas administradores podem fazer isso.'); };

      if (path === '/me' && method === 'GET') return json(200, { user: publicUser(me) });

      if (path === '/password' && method === 'POST') {
        if (!(await checkPassword(me, String(body.current || '')))) fail(400, 'A senha atual está incorreta.');
        validPassword(body.next);
        const upd = await makePassword(body.next);
        const r = await mutate(store, 'users', cur => {
          const next = (cur || []).map(u => (u.login === me.login ? { ...u, ...upd } : u));
          return { next, user: next.find(u => u.login === me.login) };
        });
        const token = makeToken(r.user, SHORT_TTL, await getSecret(store, env));
        return json(200, { ok: true }, { 'set-cookie': cookieHeader(token, null, secure) });
      }

      // ---- usuários (administração) ----
      if (path === '/users' && method === 'GET') { needAdmin(); return json(200, { users: (await loadUsers(store)).map(publicUser) }); }
      if (path === '/users' && method === 'POST') {
        needAdmin();
        const name = String(body.name || '').trim(), login = String(body.login || '').trim().toLowerCase();
        const role = ROLES[body.role] ? body.role : 'operacao';
        if (!name) fail(400, 'Informe o nome.');
        if (!EMAIL_RE.test(login)) fail(400, 'Informe um e-mail válido.');
        validPassword(body.password);
        const cred = await makePassword(body.password);
        await mutate(store, 'users', cur => {
          const list = cur || [];
          if (list.some(u => u.login === login)) fail(409, 'Já existe um usuário com este e-mail.');
          return { next: [...list, { login, name, role, ...cred }] };
        });
        return json(200, { users: (await loadUsers(store)).map(publicUser) });
      }
      // importação dos usuários que estavam salvos no navegador (formato antigo)
      if (path === '/users/import' && method === 'POST') {
        needAdmin();
        const incoming = Array.isArray(body.users) ? body.users : [];
        const valid = incoming.filter(u => u && EMAIL_RE.test(String(u.login || '')) && u.name && ROLES[u.role] &&
          /^[0-9a-f]{8,64}$/i.test(String(u.salt || '')) && /^[0-9a-f]{64,128}$/i.test(String(u.hash || '')));
        let added = [];
        await mutate(store, 'users', cur => {
          const list = cur || [];
          added = valid.filter(u => !list.some(x => x.login === String(u.login).toLowerCase()))
            .map(u => ({ login: String(u.login).toLowerCase(), name: String(u.name).slice(0, 120), role: u.role, salt: u.salt, hash: u.hash, ...(u.algo === 'scrypt' ? { algo: 'scrypt' } : {}) }));
          return { next: [...list, ...added] };
        });
        return json(200, { added: added.map(publicUser), users: (await loadUsers(store)).map(publicUser) });
      }
      const um = path.match(/^\/users\/([^/]+)$/);
      if (um && (method === 'PATCH' || method === 'DELETE')) {
        needAdmin();
        const login = decodeURIComponent(um[1]).toLowerCase();
        const cred = method === 'PATCH' && body.password !== undefined ? (validPassword(body.password), await makePassword(body.password)) : null;
        await mutate(store, 'users', cur => {
          const list = cur || [];
          const u = list.find(x => x.login === login);
          if (!u) fail(404, 'Usuário não encontrado.');
          if (method === 'DELETE') {
            if (login === me.login) fail(400, 'Você não pode remover o seu próprio acesso.');
            if (u.role === 'admin' && list.filter(x => x.role === 'admin').length < 2) fail(400, 'É preciso manter pelo menos um administrador.');
            return { next: list.filter(x => x !== u) };
          }
          const next = { ...u };
          if (body.role !== undefined) {
            if (!ROLES[body.role]) fail(400, 'Permissão inválida.');
            if (login === me.login && body.role !== 'admin') fail(400, 'Você não pode remover a sua própria permissão de administrador.');
            if (u.role === 'admin' && body.role !== 'admin' && list.filter(x => x.role === 'admin').length < 2) fail(400, 'É preciso manter pelo menos um administrador.');
            next.role = body.role;
          }
          if (cred) Object.assign(next, cred);
          return { next: list.map(x => (x === u ? next : x)) };
        });
        return json(200, { users: (await loadUsers(store)).map(publicUser) });
      }

      // ---- dados do painel ----
      if (path === '/data' && method === 'GET') {
        const { data, etag } = await readKey(store, 'db-base');
        return json(200, { db: data, etag });
      }
      if (path === '/data' && method === 'PUT') { // substitui a base inteira (primeira carga, troca de revisão ou backup)
        if (!validDb(body.db)) fail(400, 'Dados inválidos.');
        if (body.onlyIfEmpty) {
          const w = await store.setJSON('db-base', body.db, { onlyIfNew: true });
          const cur = await readKey(store, 'db-base');
          return json(200, { db: cur.data, etag: cur.etag, created: w?.modified !== false });
        }
        if (body.restore && !isAdmin) fail(403, 'Apenas administradores podem restaurar backups.');
        const opts = body.etag ? { onlyIfMatch: body.etag } : {};
        const w = await store.setJSON('db-base', body.db, opts);
        if (w && w.modified === false) fail(409, 'Os dados foram alterados por outra pessoa. Atualize a página e tente novamente.');
        const cur = await readKey(store, 'db-base');
        return json(200, { db: cur.data, etag: cur.etag });
      }
      if (path === '/records' && method === 'POST') { // cria ou atualiza um registro
        const rec = body.record;
        if (!rec || typeof rec.id !== 'string' || typeof rec.status !== 'string') fail(400, 'Registro inválido.');
        const r = await mutate(store, 'db-base', cur => {
          if (!validDb(cur)) fail(409, 'Base ainda não carregada. Atualize a página.');
          const out = upsertRecord(cur, rec, !!body.isNew);
          return { next: out.db, record: out.record };
        });
        return json(200, { db: r.next, etag: r.etag, record: r.record });
      }
      if (path === '/records/bulk' && method === 'POST') { // envio dos registros que estavam só no navegador
        const recs = Array.isArray(body.records) ? body.records.filter(x => x && typeof x.id === 'string' && typeof x.status === 'string') : [];
        let changed = [];
        const r = await mutate(store, 'db-base', cur => {
          if (!validDb(cur)) fail(409, 'Base ainda não carregada. Atualize a página.');
          let db = cur; changed = [];
          for (const rec of recs) { const out = upsertRecord(db, rec, true); if (out.db !== db) changed.push(out.record.id); db = out.db; }
          return { next: db };
        });
        return json(200, { db: r.next, etag: r.etag, added: changed });
      }
      const rm = path.match(/^\/records\/([^/]+)$/);
      if (rm && method === 'DELETE') {
        const id = decodeURIComponent(rm[1]);
        const r = await mutate(store, 'db-base', cur => {
          if (!validDb(cur)) fail(409, 'Base ainda não carregada. Atualize a página.');
          if (!cur.opps.some(o => o.id === id)) fail(404, 'Registro não encontrado (talvez já tenha sido excluído).');
          return { next: { ...cur, opps: cur.opps.filter(o => o.id !== id), deletedIds: [...new Set([...(cur.deletedIds || []), id])] } };
        });
        return json(200, { db: r.next, etag: r.etag });
      }
      if (path === '/settings' && method === 'POST') {
        const user = String(body.user || '').trim();
        if (!user) fail(400, 'Informe o responsável.');
        const r = await mutate(store, 'db-base', cur => { if (!validDb(cur)) fail(409, 'Base ainda não carregada.'); return { next: { ...cur, user } }; });
        return json(200, { db: r.next, etag: r.etag });
      }
      fail(404, 'Rota não encontrada.');
    } catch (e) {
      if (e instanceof HttpError) return json(e.status, { error: e.message });
      console.error(e);
      return json(500, { error: 'Erro interno no servidor. Tente novamente.' });
    }
  };
}
