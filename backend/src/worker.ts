/* eslint-disable @typescript-eslint/no-explicit-any */
import type { D1Database, KVNamespace, DurableObjectNamespace } from "@cloudflare/workers-types";
// Re-export ChatRoom class (minimal stub) so deploys that still have existing
// Durable Object instances depending on the class name can succeed. The
// actual application uses D1 for anonymous chat; this export keeps the
// Cloudflare script's exported symbols compatible with previous deployments.
export { ChatRoom } from "./worker_durable";
import { Database } from "./Database";
import { Result, ThrowErrorIfFailed } from "./Result";
import { Output } from "./Output";
import { genRandomKeyBase64, encryptString as aesEncryptString, encryptKeyWithPublicKey, decryptString as aesDecryptString } from "./AES";
export interface Env {
  DB: D1Database;
  WORDS?: KVNamespace; // KV for large sensitive-word list (key: "bad_words", newline-separated)
  STORAGE_SECRET?: string; // optional base64-encoded 16-byte key for server-side at-rest encryption
  ADMIN_TOKEN?: string; // simple admin auth token
  // Durable Object namespace for chat rooms (optional)
  ROOM?: DurableObjectNamespace;
  // Cloudflare Analytics Engine dataset binding (optional)
  feeling?: any;
  BIGMODEL_API_KEY?: string; // optional API key for external AI provider (open.bigmodel.cn)
}

type JsonValue = any;
let CURRENT_ORIGIN = '*';

function jsonResponse(data: JsonValue, init: ResponseInit = {}) {
  // support init.headers where 'Set-Cookie' may be an array of strings
  const headers = new Headers();
  if (init.headers) {
    const inHeaders: any = init.headers as any;
    for (const k of Object.keys(inHeaders)) {
      if (k.toLowerCase() === 'set-cookie') continue; // handle separately
      try { headers.set(k, inHeaders[k]); } catch (e) {}
    }
    const sc = (inHeaders as any)['Set-Cookie'] || (inHeaders as any)['set-cookie'];
    if (Array.isArray(sc)) {
      for (const v of sc) headers.append('Set-Cookie', v);
    } else if (sc) {
      headers.append('Set-Cookie', sc as string);
    }
  }
  headers.set("content-type", "application/json; charset=utf-8");
  // CORS: echo request origin when present and allow credentials
  const origin = CURRENT_ORIGIN || '*';
  headers.set("access-control-allow-origin", origin);
  headers.set("access-control-allow-methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS");
  headers.set("access-control-allow-headers", "content-type, authorization, x-admin-token");
  // no CSRF header handling (CSRF removed)
  headers.set('access-control-allow-credentials', 'true');
  return new Response(JSON.stringify(data), { ...init, headers });
}

function corsPreflightResponse(req: Request) {
  const origin = req.headers.get("origin") || "*";
  const reqHeaders = req.headers.get("access-control-request-headers") || "content-type, authorization, x-admin-token";
  const headers = new Headers();
  headers.set("access-control-allow-origin", origin);
  headers.set("access-control-allow-methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS");
  headers.set("access-control-allow-headers", reqHeaders);
  // no CSRF header handling in preflight (CSRF removed)
  headers.set('access-control-allow-credentials', 'true');
  // Optional: cache preflight for 1 hour
  headers.set("access-control-max-age", "3600");
  return new Response(null, { status: 200, headers });
}
function errorResponse(message: string, status = 400) {
  return jsonResponse({ ok: false, error: message }, { status });
}
function successResponse(data: JsonValue = {}, status = 200) {
  return jsonResponse({ ok: true, data }, { status });
}

function todayIsoDate() {
  const d = new Date();
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd}`;
}

function makeRoomId(a: string, b: string) {
  const [x, y] = [a, b].sort();
  return `${x}|${y}`;
}

function nowIso() {
  return new Date().toISOString();
}

function isoMinusMs(ms: number): string {
  const d = new Date(Date.now() - ms);
  return d.toISOString();
}

function sleep(ms: number) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

const BUILTIN_BAD_WORDS: string[] = [
  '傻', '笨', '滚', '垃圾', '畜生', '去死', '废物', '蠢', '闭嘴', '白痴',
  '自杀', '自残', '爆炸', '炸弹', '枪', '毒品',
];

const PATTERNS: { re: RegExp }[] = [
  // 中国大陆手机号
  { re: /\b1[3-9]\d{9}\b/g },
  // 电子邮箱
  { re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
  // URL
  { re: /https?:\/\/[^\s]+/g },
];

function maskSameLength(s: string) {
  return "*".repeat(s.length);
}
// --- Dynamic sensitive-word list from KV ---
let wordsLoaded = false;
let badRegexChunks: RegExp[] = [];
const REGEX_CHUNK_SIZE = 300; // split to avoid overly long regex

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

async function loadBadWordRegexes(env: Env) {
  if (wordsLoaded) return;
  const list: string[] = [...BUILTIN_BAD_WORDS];
  try {
    // 优先读取索引，支持大词库分块
    const indexJson = await env.WORDS?.get("bad_words_index");
    if (indexJson) {
      let keys: string[] = [];
      try { keys = JSON.parse(indexJson as string); } catch { keys = []; }
      for (const key of Array.isArray(keys) ? keys : []) {
        const part = await env.WORDS?.get(key);
        if (part) {
          part.split(/\r?\n/).forEach(line => {
            const w = line.trim();
            if (w) list.push(w);
          });
        }
      }
    } else {
      const text = await env.WORDS?.get("bad_words");
      if (text) {
        text.split(/\r?\n/).forEach(line => {
          const w = line.trim();
          if (w) list.push(w);
        });
      }
    }
    const appended = await env.WORDS?.get("bad_words_append");
    if (appended) {
      appended.split(/\r?\n/).forEach(line => {
        const w = line.trim();
        if (w) list.push(w);
      });
    }
  } catch {}
  // de-dup and escape
  const uniq = Array.from(new Set(list.map(w => w.toLowerCase())));
  const escaped = uniq.map(escapeRegex).filter(s => s.length > 0);
  // chunk compile
  badRegexChunks = [];
  for (let i = 0; i < escaped.length; i += REGEX_CHUNK_SIZE) {
    const slice = escaped.slice(i, i + REGEX_CHUNK_SIZE);
    badRegexChunks.push(new RegExp(slice.join("|"), "giu"));
  }
  wordsLoaded = true;
}

async function sanitizeMessageAsync(msg: string, env: Env): Promise<string> {
  let out = msg || "";
  // Respect admin-controlled KV flag `filter_bad_words` (default: enabled).
  // If disabled, skip all filtering (bad words and pattern-based masking).
  try {
    const enableRaw = await env.WORDS?.get('filter_bad_words');
    const enabled = enableRaw === undefined || enableRaw === null ? true : !(String(enableRaw).trim() === '0' || String(enableRaw).toLowerCase().trim() === 'false');
    if (!enabled) {
      // admin explicitly disabled filtering — return original message
      return out;
    }
    // enabled: apply bad-word masking and pattern masking
    await loadBadWordRegexes(env);
    for (const re of badRegexChunks) {
      out = out.replace(re, (m) => maskSameLength(m));
    }
    for (const { re } of PATTERNS) {
      out = out.replace(re, (m) => maskSameLength(m));
    }
  } catch (e) {
    // if KV lookup or loading fails, fall back to enabling filtering
    await loadBadWordRegexes(env);
    for (const re of badRegexChunks) {
      out = out.replace(re, (m) => maskSameLength(m));
    }
    for (const { re } of PATTERNS) {
      out = out.replace(re, (m) => maskSameLength(m));
    }
  }
  return out;
}

async function readJson<T>(req: Request): Promise<T | null> {
  try {
    const text = await req.text();
    if (!text) return {} as T;
    return JSON.parse(text);
  } catch {
    return null;
  }
}

async function handleRegister(env: Env, req: Request) {
  const body = await readJson<{ username: string; password_sha: string; hobby?: string; sex?: number }>(req);
  if (!body) return errorResponse("Invalid JSON", 400);
  const { username, password_sha, hobby = null, sex = null } = body as any;
  if (!username || !password_sha) return errorResponse("username and password_sha are required");
  const db = new Database(env.DB);
  const existsRes = await db.Select("user_table", ["username"], { username });
  const existsRows = (ThrowErrorIfFailed(existsRes) as any[]) || [];
  if (existsRows.length > 0) return errorResponse("用户名已存在", 409);

  await db.Insert("user_table", {
    username,
    password_sha,
    hobby: (env.STORAGE_SECRET && hobby ? await aesEncryptString(String(hobby), env.STORAGE_SECRET) : hobby),
    sex,
    mood: null,
    last_mood_date: null,
    chatting: 0,
  });
  return successResponse("注册成功");
}

async function handleLogin(env: Env, req: Request) {
  const ctx = await getAdminContext(env, req);
  if (!ctx) return errorResponse('未授权', 401);
  const allowed = await getAdminAllowedGroups(env, ctx);
  const url = new URL(req.url);
  const q = (url.searchParams.get('q') || '').trim();
  const limitStr = url.searchParams.get('limit');
  const offsetStr = url.searchParams.get('offset');
  let limit = parseInt(String(limitStr || '200'), 10);
  let offset = parseInt(String(offsetStr || '0'), 10);
  if (!Number.isFinite(limit) || limit <= 0 || limit > 1000) limit = 200;
  if (!Number.isFinite(offset) || offset < 0) offset = 0;
  const db = new Database(env.DB);
  // If allowed is empty array => user has no groups -> return empty
  if (Array.isArray(allowed) && allowed.length === 0) return successResponse({ visits: [], total: 0 });
  let res;
  let total = 0;
  if (q) {
    if (allowed === null) {
      res = await db.Query(
        `SELECT id, username, page, title, referrer, ua, time FROM page_visits
         WHERE username LIKE ? OR page LIKE ? OR title LIKE ?
         ORDER BY time DESC LIMIT ? OFFSET ?`,
        [`%${q}%`, `%${q}%`, `%${q}%`, limit, offset]
      );
      const cntRes = await db.Query(`SELECT COUNT(1) as total FROM page_visits WHERE username LIKE ? OR page LIKE ? OR title LIKE ?`, [`%${q}%`, `%${q}%`, `%${q}%`]);
      total = ((ThrowErrorIfFailed(cntRes) as any).results || [])[0]?.total || 0;
    } else {
      const placeholders = allowed.map(() => '?').join(',');
      const params = [`%${q}%`, `%${q}%`, `%${q}%`, ...allowed, limit, offset];
      res = await db.Query(
        `SELECT p.id, p.username, p.page, p.title, p.referrer, p.ua, p.time FROM page_visits p JOIN user_groups ug ON p.username = ug.username WHERE (p.username LIKE ? OR p.page LIKE ? OR p.title LIKE ?) AND ug.group_name IN (${placeholders}) ORDER BY p.time DESC LIMIT ? OFFSET ?`,
        params
      );
      const cntRes = await db.Query(`SELECT COUNT(1) as total FROM page_visits p JOIN user_groups ug ON p.username = ug.username WHERE (p.username LIKE ? OR p.page LIKE ? OR p.title LIKE ?) AND ug.group_name IN (${placeholders})`, [`%${q}%`, `%${q}%`, `%${q}%`, ...allowed]);
      total = ((ThrowErrorIfFailed(cntRes) as any).results || [])[0]?.total || 0;
    }
  } else {
    if (allowed === null) {
      res = await db.Query(
        `SELECT id, username, page, title, referrer, ua, time FROM page_visits
         ORDER BY time DESC LIMIT ? OFFSET ?`,
        [limit, offset]
      );
      const cntRes = await db.Query(`SELECT COUNT(1) as total FROM page_visits`, []);
      total = ((ThrowErrorIfFailed(cntRes) as any).results || [])[0]?.total || 0;
    } else {
      const placeholders = allowed.map(() => '?').join(',');
      const params = [...allowed, limit, offset];
      res = await db.Query(
        `SELECT p.id, p.username, p.page, p.title, p.referrer, p.ua, p.time FROM page_visits p JOIN user_groups ug ON p.username = ug.username WHERE ug.group_name IN (${placeholders}) ORDER BY p.time DESC LIMIT ? OFFSET ?`,
        params
      );
      const cntRes = await db.Query(`SELECT COUNT(1) as total FROM page_visits p JOIN user_groups ug ON p.username = ug.username WHERE ug.group_name IN (${placeholders})`, allowed);
      total = ((ThrowErrorIfFailed(cntRes) as any).results || [])[0]?.total || 0;
    }
  }
  const rows = ((ThrowErrorIfFailed(res) as any).results as any[]) || [];
  try {
    return successResponse({ visits: rows, total });
  } catch (e) {
    return successResponse({ visits: rows, total: 0 });
  }
}

async function handleWhoami(env: Env, req: Request) {
  const user = await getUsernameFromSession(env, req);
  if (!user) return successResponse({ username: null });
  return successResponse({ username: user });
}

// Get username from regular user session (cookie `session_id` or header `x-session`)
async function getUsernameFromSession(env: Env, req: Request): Promise<string | null> {
  const cookie = req.headers.get('cookie') || '';
  const match = cookie.split(';').map(s=>s.trim()).find(s=>s.startsWith('session_id='));
  const sessionId = req.headers.get('x-session') || (match ? match.split('=')[1] : null);
  if (!sessionId) return null;
  const db = new Database(env.DB);
  try {
    await db.Query(`CREATE TABLE IF NOT EXISTS sessions (session_id TEXT PRIMARY KEY, username TEXT, expires TEXT, created_at TEXT DEFAULT (datetime('now')))`, []);
    const res = await db.Query(`SELECT username, expires FROM sessions WHERE session_id = ?`, [sessionId]);
    const rows = ((ThrowErrorIfFailed(res) as any).results as any[]) || [];
    if (rows.length === 0) return null;
    const row = rows[0];
    if (row.expires && new Date(row.expires) < new Date()) {
      try { await db.Query(`DELETE FROM sessions WHERE session_id = ?`, [sessionId]); } catch (e) {}
      return null;
    }
    return row.username || null;
  } catch (e) {
    return null;
  }
}


async function handleLogout(env: Env, req: Request) {
  const cookie = req.headers.get('cookie') || '';
  const match = cookie.split(';').map(s=>s.trim()).find(s=>s.startsWith('session_id='));
  if (match) {
    const sessionId = match.split('=')[1];
    try { await new Database(env.DB).Query(`DELETE FROM sessions WHERE session_id = ?`, [sessionId]); } catch (e) {}
  }
  // Clear session cookie
  const headers: any = { 'Set-Cookie': [`session_id=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax`] };
  return jsonResponse({ ok: true, data: 'logged out' }, { status: 200, headers });
}

async function handleRecordMood(env: Env, req: Request) {
  // CSRF removed: no server-side CSRF validation
  const body = await readJson<{ username: string; mood: string; date?: string }>(req);
  if (!body) return errorResponse("Invalid JSON", 400);
  const { username, mood } = body;
  let { date } = body;
  if (!username || !mood) return errorResponse("username and mood are required");
  if (!date) date = todayIsoDate();
  const db = new Database(env.DB);
  // Prevent duplicate submissions for the same date
  const existsRes = await db.Select("mood_log", ["date"], { username, date });
  // feature gate: mood
  const flagRes = await db.Select("user_table", ["disabled", "disable_mood"], { username });
  const flagRow = ((ThrowErrorIfFailed(flagRes) as any[]) || [])[0] as any;
  if (!flagRow) return errorResponse("用户不存在", 404);
  if (flagRow.disabled) return errorResponse("账户已被禁用", 403);
  if (flagRow.disable_mood) return errorResponse("心情记录功能已被禁用", 403);
  const existsRows = (ThrowErrorIfFailed(existsRes) as any[]) || [];
  if (existsRows.length > 0) return errorResponse("今日已记录", 409);
  const updateRes = await db.Update("user_table", { mood, last_mood_date: date }, { username });
  const meta = (ThrowErrorIfFailed(updateRes) as any).meta || {};
  if (!meta || Number(meta.changes || 0) === 0) return errorResponse("用户不存在", 404);
  // Insert into mood_log for monthly statistics (no overwrite)
  await db.Query(
    `INSERT INTO mood_log (username, date, mood) VALUES (?, ?, ?)`,
    [username, date, mood]
  );
  return successResponse("心情记录成功");
}

async function handleGetMoodMonth(env: Env, req: Request) {
  const url = new URL(req.url);
  const username = url.searchParams.get("username");
  const yearStr = url.searchParams.get("year");
  const monthStr = url.searchParams.get("month");
  if (!username || !yearStr || !monthStr) return errorResponse("username, year, month are required");
  const year = parseInt(yearStr, 10);
  const month = parseInt(monthStr, 10); // 1-12
  if (Number.isNaN(year) || Number.isNaN(month) || month < 1 || month > 12) return errorResponse("invalid year or month");
  const start = `${year}-${String(month).padStart(2, "0")}-01`;
  const nextMonth = month === 12 ? 1 : month + 1;
  const nextYear = month === 12 ? year + 1 : year;
  const end = `${nextYear}-${String(nextMonth).padStart(2, "0")}-01`;
  const db = new Database(env.DB);
  const res = await db.Query(
    `SELECT date, mood FROM mood_log WHERE username = ? AND date >= ? AND date < ? ORDER BY date ASC`,
    [username, start, end]
  );
  const rows = ((ThrowErrorIfFailed(res) as any).results as any[]) || [];
  const days = rows.map(r => ({ day: parseInt(String((r as any).date).slice(8, 10), 10), mood: (r as any).mood }));
  return successResponse({ year, month, days });
}

async function handleGetUserInfo(env: Env, req: Request) {
  const url = new URL(req.url);
  const username = url.searchParams.get("username");
  const clientPubPem = req.headers.get('x-client-pub-pem') || url.searchParams.get('client_pub_pem') || null;
  if (!username) return errorResponse("username is required");
  const db = new Database(env.DB);
  const res = await db.Select(
    "user_table",
    ["username", "hobby", "sex", "mood", "last_mood_date", "chatting"],
    { username }
  );
  const rows = (ThrowErrorIfFailed(res) as any[]) || [];
  if (rows.length === 0) return errorResponse("用户不存在", 404);
  const user = rows[0] as any;
  // try to decrypt hobby if stored encrypted
  let hobbyVal: any = user.hobby;
  if (hobbyVal && env.STORAGE_SECRET && typeof hobbyVal === 'string') {
    try { hobbyVal = await aesDecryptString(hobbyVal, env.STORAGE_SECRET); } catch { /* keep raw */ }
  }
  if (clientPubPem) {
    // wrap hobby for client
    const sym = genRandomKeyBase64();
    const cipher = await aesEncryptString(String(hobbyVal || ''), sym);
    let wrapped = '';
    try { wrapped = await encryptKeyWithPublicKey(sym, clientPubPem as string); } catch { wrapped = ''; }
    user.hobby = { cipher, wrapped_key: wrapped };
    return successResponse(user);
  }
  user.hobby = hobbyVal;
  return successResponse(user);
}

async function handleChangePassword(env: Env, req: Request) {
  const body = await readJson<{ username: string; old_password_sha: string; new_password_sha: string }>(req);
  if (!body) return errorResponse("Invalid JSON", 400);
  const { username, old_password_sha, new_password_sha } = body;
  if (!username || !old_password_sha || !new_password_sha) return errorResponse("missing fields");
  const db = new Database(env.DB);
  const check = await db.Select("user_table", ["username"], { username, password_sha: old_password_sha });
  const rows = (ThrowErrorIfFailed(check) as any[]) || [];
  if (rows.length === 0) return errorResponse("原密码错误", 400);
  await db.Update("user_table", { password_sha: new_password_sha }, { username });
  return successResponse("密码修改成功");
}

async function handleMatchAnonymous(env: Env, req: Request) {
  const body = await readJson<{ username: string }>(req);
  if (!body) return errorResponse("Invalid JSON", 400);
  const { username } = body;
  if (!username) return errorResponse("username is required");
  const db = new Database(env.DB);
  const TIMEOUT_MS = 45_000; // 心跳超时阈值 45s
  // 乐观并发控制：不使用 SQL 事务。通过 chatting=0 条件原子更新，失败则回滚自身标记。
  try {
  const selfRes = await db.Select("user_table", ["username", "chatting", "disabled", "disable_anon_chat"], { username });
    const selfRows = (ThrowErrorIfFailed(selfRes) as any[]) || [];
    const self = selfRows[0];
    if (!self) return errorResponse("用户不存在", 404);
  if ((self as any).disabled) return errorResponse("账户已被禁用", 403);
    if ((self as any).disable_anon_chat) return errorResponse("匿名聊天功能已被禁用", 403);
    if ((self as any).chatting) {
      // 如果已经在聊天中，优先返回已建立的会话信息（如果存在）
      const infoRes = await db.Select("user_table", ["partner_username", "current_room_id"], { username });
      const info = ((ThrowErrorIfFailed(infoRes) as any[]) || [])[0] as any;
      let partner = info?.partner_username as string | undefined;
      let room_id = info?.current_room_id as string | undefined;
      if (partner && room_id) {
        const otherRes = await db.Select("user_table", ["hobby", "sex", "mood", "last_heartbeat"], { username: partner });
        const otherRow = ((ThrowErrorIfFailed(otherRes) as any[]) || [])[0] as any;
        // 如果对方超时，则自动结束聊天并重置，再继续匹配流程
        const hb = otherRow?.last_heartbeat as string | null | undefined;
        if (hb && hb < isoMinusMs(TIMEOUT_MS)) {
          await db.Update("user_table", { chatting: 0, partner_username: null, current_room_id: null }, { username });
          await db.Update("user_table", { chatting: 0, partner_username: null, current_room_id: null }, { username: partner });
          // 删除房间聊天内容
          await db.Query(`DELETE FROM anon_chat WHERE room_id = ?`, [room_id]);
        } else {
        return successResponse({
          room_id,
          other_username: partner,
          other_hobby: otherRow?.hobby ?? null,
          other_sex: otherRow?.sex ?? null,
          other_mood: otherRow?.mood ?? null,
        });
        }
      }
      // 自愈逻辑：尝试反向查找是否有人把我设为 partner
      const reverseRes = await db.Select("user_table", ["username", "current_room_id", "last_heartbeat"], { partner_username: username });
      const reverseRow = ((ThrowErrorIfFailed(reverseRes) as any[]) || [])[0] as any;
      if (reverseRow && reverseRow.username && reverseRow.current_room_id) {
        partner = reverseRow.username as string;
        room_id = reverseRow.current_room_id as string;
        // 检查对方是否超时
        const hb = reverseRow?.last_heartbeat as string | null | undefined;
        if (hb && hb < isoMinusMs(TIMEOUT_MS)) {
          await db.Update("user_table", { chatting: 0, partner_username: null, current_room_id: null }, { username });
          await db.Update("user_table", { chatting: 0, partner_username: null, current_room_id: null }, { username: partner });
          await db.Query(`DELETE FROM anon_chat WHERE room_id = ?`, [room_id]);
        } else {
        // 补齐我的 partner/room 以恢复会话
        await db.Update("user_table", { partner_username: partner, current_room_id: room_id }, { username });
        const otherInfoRes = await db.Select("user_table", ["hobby", "sex", "mood"], { username: partner });
        const otherInfo = ((ThrowErrorIfFailed(otherInfoRes) as any[]) || [])[0] as any;
        return successResponse({
          room_id,
          other_username: partner,
          other_hobby: otherInfo?.hobby ?? null,
          other_sex: otherInfo?.sex ?? null,
          other_mood: otherInfo?.mood ?? null,
        });
        }
      }
      // 若仍缺失会话信息，则把自身重置为未聊天，继续进入正常匹配流程
      await db.Update("user_table", { chatting: 0, partner_username: null, current_room_id: null }, { username });
      // 不 return，继续往下执行匹配流程
    }

    // Only match with users who have a recent heartbeat (online)
    const cutoff = isoMinusMs(TIMEOUT_MS);
    const otherRes = await db.Query(
      `SELECT username, hobby, sex, mood, last_heartbeat FROM user_table
       WHERE username != ? AND mood IS NOT NULL AND chatting = 0 AND last_heartbeat > ?
       ORDER BY last_mood_date DESC
       LIMIT 1`,
      [username, cutoff]
    );
    const otherRows = ((ThrowErrorIfFailed(otherRes) as any).results as any[]) || [];
    const other = otherRows[0];
  if (!other) return errorResponse("无聊天对象", 404);

    const otherUsername = (other as any).username as string;
    // 先将自己置为 chatting=1（仅当当前为0）
    const updSelf = await db.Update("user_table", { chatting: 1 }, { username, chatting: 0 });
    const selfChanged = Number(((ThrowErrorIfFailed(updSelf) as any).meta?.changes) || 0);
    if (selfChanged < 1) return errorResponse("匹配失败，请重试", 409);

    // 再将对方置为 chatting=1（仅当当前为0）
    const updOther = await db.Update("user_table", { chatting: 1 }, { username: otherUsername, chatting: 0 });
    const otherChanged = Number(((ThrowErrorIfFailed(updOther) as any).meta?.changes) || 0);
    if (otherChanged < 1) {
      // 回滚自己的标记
      await db.Update("user_table", { chatting: 0 }, { username });
      return errorResponse("匹配失败，请重试", 409);
    }

    const room_id = makeRoomId(username, otherUsername);
    // 保存双方的 partner 和 room_id，便于另一方轮询到会话
    await db.Update("user_table", { partner_username: otherUsername, current_room_id: room_id }, { username });
    await db.Update("user_table", { partner_username: username, current_room_id: room_id }, { username: otherUsername });
  // bump room state so listeners searching the room see initial version
  try { await bumpRoomState(db, room_id); } catch (e) {}
    // 初始化双方心跳时间
    const now = nowIso();
    await db.Update("user_table", { last_heartbeat: now }, { username });
    await db.Update("user_table", { last_heartbeat: now }, { username: otherUsername });
    return successResponse({
      room_id,
      other_username: otherUsername,
      other_hobby: (other as any).hobby,
      other_sex: (other as any).sex,
      other_mood: (other as any).mood,
    });
  } catch (e) {
    return errorResponse(`匹配错误: ${(e as Error).message}`);
  }
}

// --- Admin helpers ---
function requireAdmin(req: Request, env: Env): string | null {
  const token = req.headers.get('x-admin-token');
  if (!env.ADMIN_TOKEN || !token || token !== env.ADMIN_TOKEN) return null;
  return token;
}

// Admin: compute SHA-256 hex of a string (used to compare admin password hash)
async function adminSha256(text: string): Promise<string> {
  const enc = new TextEncoder();
  const data = enc.encode(text);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Return admin context from header cookie or env.ADMIN_TOKEN.
// Result: { username, is_super: boolean, token }
async function getAdminContext(env: Env, req: Request): Promise<{ username: string; is_super: boolean; token: string } | null> {
  // super-admin via ADMIN_TOKEN in header
  const headerToken = req.headers.get('x-admin-token');
  if (env.ADMIN_TOKEN && headerToken && headerToken === env.ADMIN_TOKEN) {
    return { username: 'admin', is_super: true, token: headerToken };
  }
  // session token from header or cookie
  const sessionToken = req.headers.get('x-admin-session') || (() => {
    const cookie = req.headers.get('cookie') || '';
    const match = cookie.split(';').map(s=>s.trim()).find(s=>s.startsWith('admin_session='));
    if (!match) return null;
    return match.split('=')[1];
  })();
  if (!sessionToken) return null;
  const db = new Database(env.DB);
  try {
    await db.Query(`CREATE TABLE IF NOT EXISTS admin_sessions (session_id TEXT PRIMARY KEY, username TEXT, expires TEXT, created_at TEXT DEFAULT (datetime('now')))`, []);
    await db.Query(`CREATE TABLE IF NOT EXISTS admin_users (username TEXT PRIMARY KEY, password_sha TEXT, is_super INTEGER DEFAULT 0, groups TEXT, permissions TEXT, created_at TEXT DEFAULT (datetime('now')))`, []);
    const res = await db.Query(`SELECT username, expires FROM admin_sessions WHERE session_id = ?`, [sessionToken]);
    const rows = ((ThrowErrorIfFailed(res) as any).results as any[]) || [];
    if (rows.length === 0) return null;
    const row = rows[0];
    if (row.expires && new Date(row.expires) < new Date()) {
      try { await db.Query(`DELETE FROM admin_sessions WHERE session_id = ?`, [sessionToken]); } catch (e) {}
      return null;
    }
    const username = row.username as string || null;
    if (!username) return null;
    const ures = await db.Query(`SELECT username, is_super, groups FROM admin_users WHERE username = ?`, [username]);
    const urows = ((ThrowErrorIfFailed(ures) as any).results as any[]) || [];
    if (urows.length === 0) return null;
    const u = urows[0];
    return { username: u.username, is_super: Boolean(u.is_super), token: sessionToken };
  } catch (e) {
    return null;
  }
}

// Return allowed groups for an admin context.
// If ctx.is_super === true, returns null to indicate no restriction (all groups).
async function getAdminAllowedGroups(env: Env, ctx: { username: string; is_super: boolean; token: string } | null): Promise<string[] | null> {
  if (!ctx) return [];
  if (ctx.is_super) return null;
  try {
    const db = new Database(env.DB);
    await db.Query(`CREATE TABLE IF NOT EXISTS admin_users (username TEXT PRIMARY KEY, password_sha TEXT, is_super INTEGER DEFAULT 0, groups TEXT, permissions TEXT, created_at TEXT DEFAULT (datetime('now')))`, []);
    const res = await db.Query(`SELECT groups FROM admin_users WHERE username = ?`, [ctx.username]);
    const rows = ((ThrowErrorIfFailed(res) as any).results as any[]) || [];
    if (rows.length === 0) return [];
    const g = rows[0].groups;
    if (!g) return [];
    try { const parsed = JSON.parse(String(g)); return Array.isArray(parsed) ? parsed.map(String) : []; } catch (e) { return [] }
  } catch (e) {
    return [];
  }
}

// Admin login: supports super-admin (username 'admin' + password equal to ENV ADMIN_TOKEN)
async function handleAdminLogin(env: Env, req: Request) {
  const body = await readJson<{ username?: string; password_sha?: string; password?: string }>(req);
  if (!body || !body.username) return errorResponse('Invalid JSON', 400);
  const username = String(body.username);
  const db = new Database(env.DB);
  try {
    await db.Query(`CREATE TABLE IF NOT EXISTS admin_users (username TEXT PRIMARY KEY, password_sha TEXT, is_super INTEGER DEFAULT 0, groups TEXT, permissions TEXT, created_at TEXT DEFAULT (datetime('now')))`, []);
    await db.Query(`CREATE TABLE IF NOT EXISTS admin_sessions (session_id TEXT PRIMARY KEY, username TEXT, expires TEXT, created_at TEXT DEFAULT (datetime('now')))`, []);
  } catch (e) {}

  // Super admin: password is ADMIN_TOKEN (compare sha)
  if (username === 'admin') {
    if (!env.ADMIN_TOKEN) return errorResponse('ADMIN_TOKEN not configured', 500);
    const provided = body.password_sha || body.password || '';
    // if provided is plain password, compare directly; if provided is hex, compare sha
    const adminTokenSha = await adminSha256(String(env.ADMIN_TOKEN));
    const ok = (provided === env.ADMIN_TOKEN) || (String(provided).toLowerCase() === adminTokenSha);
    if (!ok) return errorResponse('用户名或密码错误', 401);
    // create ephemeral admin session token
    const sessionId = crypto.randomUUID();
    const expires = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
    try { await db.Query(`INSERT INTO admin_sessions (session_id, username, expires, created_at) VALUES (?, ?, ?, datetime('now'))`, [sessionId, 'admin', expires]); } catch (e) {}
    const headers: any = { 'Set-Cookie': [`admin_session=${sessionId}; Path=/; Max-Age=${24*3600}; HttpOnly; SameSite=Lax`] };
    await writeAdminAudit(new Database(env.DB), env.ADMIN_TOKEN || null, 'admin_login', 'admin', null, null);
    return jsonResponse({ ok: true, username: 'admin', is_super: true, session_id: sessionId }, { status: 200, headers });
  }

  // Sub-admin: validate against admin_users
  const providedSha = String(body.password_sha || '');
  if (!providedSha) return errorResponse('password_sha required for sub-admin', 400);
  try {
    const sel = await db.Query(`SELECT username, is_super FROM admin_users WHERE username = ? AND password_sha = ?`, [username, providedSha]);
    const srows = ((ThrowErrorIfFailed(sel) as any).results as any[]) || [];
    if (srows.length === 0) return errorResponse('用户名或密码错误', 401);
    const is_super = Boolean(srows[0].is_super);
    const sessionId = crypto.randomUUID();
    const expires = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
    try { await db.Query(`INSERT INTO admin_sessions (session_id, username, expires, created_at) VALUES (?, ?, ?, datetime('now'))`, [sessionId, username, expires]); } catch (e) {}
    const headers: any = { 'Set-Cookie': [`admin_session=${sessionId}; Path=/; Max-Age=${24*3600}; HttpOnly; SameSite=Lax`] };
    await writeAdminAudit(new Database(env.DB), req.headers.get('x-admin-token'), 'subadmin_login', username, null, null);
    return jsonResponse({ ok: true, username, is_super, session_id: sessionId }, { status: 200, headers });
  } catch (e) {
    return errorResponse('db error', 500);
  }
}

// Create a sub-admin (super-admin only)
async function handleAdminCreateSubadmin(env: Env, req: Request) {
  const ctx = await getAdminContext(env, req);
  if (!ctx || !ctx.is_super) return errorResponse('未授权', 401);
  const body = await readJson<{ username?: string; password_sha?: string; groups?: string[]; permissions?: any }>(req);
  if (!body || !body.username || !body.password_sha) return errorResponse('username and password_sha required', 400);
  const username = String(body.username).trim();
  const pwd = String(body.password_sha).trim();
  const groupsJson = body.groups && Array.isArray(body.groups) ? JSON.stringify(body.groups) : null;
  const permsJson = body.permissions ? JSON.stringify(body.permissions) : null;
  const db = new Database(env.DB);
  try {
    await db.Query(`CREATE TABLE IF NOT EXISTS admin_users (username TEXT PRIMARY KEY, password_sha TEXT, is_super INTEGER DEFAULT 0, groups TEXT, permissions TEXT, created_at TEXT DEFAULT (datetime('now')))`, []);
    await db.Query(`INSERT OR REPLACE INTO admin_users (username, password_sha, is_super, groups, permissions) VALUES (?, ?, ?, ?, ?)`, [username, pwd, 0, groupsJson, permsJson]);
    await writeAdminAudit(db, req.headers.get('x-admin-token'), 'create_subadmin', username, null, { groups: body.groups || [] });
    return successResponse({ ok: true });
  } catch (e) {
    return errorResponse('db error', 500);
  }
}

// Admin logout: clear admin_session cookie and remove session row if any
async function handleAdminLogout(env: Env, req: Request) {
  const cookie = req.headers.get('cookie') || '';
  const match = cookie.split(';').map(s=>s.trim()).find(s=>s.startsWith('admin_session='));
  if (match) {
    const sessionId = match.split('=')[1];
    try { await new Database(env.DB).Query(`DELETE FROM admin_sessions WHERE session_id = ?`, [sessionId]); } catch (e) {}
  }
  const headers: any = { 'Set-Cookie': [`admin_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax`] };
  return jsonResponse({ ok: true }, { status: 200, headers });
}

async function handleAdminListUsers(env: Env, req: Request) {
  const ctx = await getAdminContext(env, req);
  if (!ctx) return errorResponse('未授权', 401);
  const allowed = await getAdminAllowedGroups(env, ctx);
  const url = new URL(req.url);
  const q = (url.searchParams.get('q') || '').trim();
  const limitStr = url.searchParams.get('limit');
  const offsetStr = url.searchParams.get('offset');
  let limit = parseInt(String(limitStr || '200'), 10);
  let offset = parseInt(String(offsetStr || '0'), 10);
  if (!Number.isFinite(limit) || limit <= 0 || limit > 1000) limit = 200;
  if (!Number.isFinite(offset) || offset < 0) offset = 0;
  const db = new Database(env.DB);
  let res;
  let total = 0;
  // If allowed is empty array => user has no groups -> return empty
  if (Array.isArray(allowed) && allowed.length === 0) return successResponse({ users: [], total: 0 });
  if (q) {
    if (allowed === null) {
      res = await db.Query(`SELECT u.username, u.hobby, u.sex, u.mood, u.last_mood_date, u.chatting, u.disabled, u.disable_anon_chat, u.disable_mood, u.disable_ai, ug.group_name FROM user_table u LEFT JOIN user_groups ug ON u.username = ug.username WHERE u.username LIKE ? ORDER BY u.username ASC LIMIT ? OFFSET ?`, [`%${q}%`, limit, offset]);
      const cntRes = await db.Query(`SELECT COUNT(1) as total FROM user_table WHERE username LIKE ?`, [`%${q}%`]);
      total = ((ThrowErrorIfFailed(cntRes) as any).results || [])[0]?.total || 0;
    } else {
      const placeholders = allowed.map(() => '?').join(',');
      const params = [`%${q}%`, ...allowed, limit, offset];
      res = await db.Query(`SELECT u.username, u.hobby, u.sex, u.mood, u.last_mood_date, u.chatting, u.disabled, u.disable_anon_chat, u.disable_mood, u.disable_ai, ug.group_name FROM user_table u JOIN user_groups ug ON u.username = ug.username WHERE u.username LIKE ? AND ug.group_name IN (${placeholders}) ORDER BY u.username ASC LIMIT ? OFFSET ?`, params);
      const cntRes = await db.Query(`SELECT COUNT(1) as total FROM user_table u JOIN user_groups ug ON u.username = ug.username WHERE u.username LIKE ? AND ug.group_name IN (${placeholders})`, [`%${q}%`, ...allowed]);
      total = ((ThrowErrorIfFailed(cntRes) as any).results || [])[0]?.total || 0;
    }
  } else {
    if (allowed === null) {
      res = await db.Query(`SELECT u.username, u.hobby, u.sex, u.mood, u.last_mood_date, u.chatting, u.disabled, u.disable_anon_chat, u.disable_mood, u.disable_ai, ug.group_name FROM user_table u LEFT JOIN user_groups ug ON u.username = ug.username ORDER BY u.username ASC LIMIT ? OFFSET ?`, [limit, offset]);
      const cntRes = await db.Query(`SELECT COUNT(1) as total FROM user_table`, []);
      total = ((ThrowErrorIfFailed(cntRes) as any).results || [])[0]?.total || 0;
    } else {
      const placeholders = allowed.map(() => '?').join(',');
      const params = [...allowed, limit, offset];
      res = await db.Query(`SELECT u.username, u.hobby, u.sex, u.mood, u.last_mood_date, u.chatting, u.disabled, u.disable_anon_chat, u.disable_mood, u.disable_ai, ug.group_name FROM user_table u JOIN user_groups ug ON u.username = ug.username WHERE ug.group_name IN (${placeholders}) ORDER BY u.username ASC LIMIT ? OFFSET ?`, params);
      const cntRes = await db.Query(`SELECT COUNT(1) as total FROM user_table u JOIN user_groups ug ON u.username = ug.username WHERE ug.group_name IN (${placeholders})`, allowed);
      total = ((ThrowErrorIfFailed(cntRes) as any).results || [])[0]?.total || 0;
    }
  }
  const rows = ((ThrowErrorIfFailed(res) as any).results as any[]) || [];
  return successResponse({ users: rows, total });
}

async function handleAdminSetDisabled(env: Env, req: Request) {
  if (!requireAdmin(req, env)) return errorResponse('未授权', 401);
  const body = await readJson<{ username: string; disabled: boolean }>(req);
  if (!body) return errorResponse('Invalid JSON', 400);
  const { username, disabled } = body;
  if (!username) return errorResponse('username required');
  const db = new Database(env.DB);
  await db.Update('user_table', { disabled: disabled ? 1 : 0 }, { username });
  await writeAdminAudit(db, req.headers.get('x-admin-token'), 'set_disabled', username, disabled ? 'disabled by admin' : 'enabled by admin', { disabled });
  return successResponse('ok');
}

async function handleAdminResetPassword(env: Env, req: Request) {
  if (!requireAdmin(req, env)) return errorResponse('未授权', 401);
  const body = await readJson<{ username: string; new_password_sha: string }>(req);
  if (!body) return errorResponse('Invalid JSON', 400);
  const { username, new_password_sha } = body;
  if (!username || !new_password_sha) return errorResponse('missing fields');
  const db = new Database(env.DB);
  await db.Update('user_table', { password_sha: new_password_sha }, { username });
  await writeAdminAudit(db, req.headers.get('x-admin-token'), 'reset_password', username, null, {});
  return successResponse('ok');
}

async function handleAdminWordsAdd(env: Env, req: Request) {
  if (!requireAdmin(req, env)) return errorResponse('未授权', 401);
  // 支持追加到一个临时 key，之后脚本可合并；这里直接追加到 bad_words_001 也可，但建议走脚本。
  const body = await readJson<{ words: string[] }>(req);
  if (!body) return errorResponse('Invalid JSON', 400);
  const { words } = body;
  if (!Array.isArray(words) || words.length === 0) return errorResponse('words required');
  const payload = (words as string[]).map(w => String(w || '').trim()).filter(Boolean).join('\n');
  if (!env.WORDS) return errorResponse('KV 未配置', 500);
  await env.WORDS.put('bad_words_append', payload);
  // 置位缓存重新加载（简单处理：下次进程重启或提供另一个刷新端点）
  wordsLoaded = false;
  await writeAdminAudit(new Database(env.DB), req.headers.get('x-admin-token'), 'words_add', null, null, { count: (words||[]).length });
  return successResponse('ok');
}

// Admin: get/set runtime settings (stored in KV). Currently supports:
//  - filter_bad_words: '1'|'0' or 'true'|'false' (default enabled)
async function handleAdminGetSettings(env: Env, req: Request) {
  if (!requireAdmin(req, env)) return errorResponse('未授权', 401);
  try {
    const raw = await env.WORDS?.get('filter_bad_words');
    const enabled = raw === undefined || raw === null ? true : !(String(raw).trim() === '0' || String(raw).toLowerCase().trim() === 'false');
    return successResponse({ filter_bad_words: enabled });
  } catch (e) {
    return errorResponse('kv error', 500);
  }
}

async function handleAdminSetSettings(env: Env, req: Request) {
  if (!requireAdmin(req, env)) return errorResponse('未授权', 401);
  const body = await readJson<{ filter_bad_words?: boolean }>(req);
  if (!body) return errorResponse('Invalid JSON', 400);
  if (typeof body.filter_bad_words === 'undefined') return errorResponse('no settings provided', 400);
  if (!env.WORDS) return errorResponse('KV 未配置', 500);
  try {
    const v = body.filter_bad_words ? '1' : '0';
    await env.WORDS.put('filter_bad_words', v);
    // reset loaded cache so changes take effect immediately
    wordsLoaded = false;
    await writeAdminAudit(new Database(env.DB), req.headers.get('x-admin-token'), 'set_setting', null, null, { filter_bad_words: body.filter_bad_words });
    return successResponse({ ok: true });
  } catch (e) {
    return errorResponse('kv error', 500);
  }
}

// Admin: force refresh of bad-word in-memory cache (useful after manual KV updates)
async function handleAdminRefreshWords(env: Env, req: Request) {
  if (!requireAdmin(req, env)) return errorResponse('未授权', 401);
  try {
    wordsLoaded = false;
    await writeAdminAudit(new Database(env.DB), req.headers.get('x-admin-token'), 'refresh_words', null, null, {});
    return successResponse({ ok: true });
  } catch (e) {
    return errorResponse('failed to refresh', 500);
  }
}

// Admin: list groups and members count
async function handleAdminListGroups(env: Env, req: Request) {
  const ctx = await getAdminContext(env, req);
  if (!ctx) return errorResponse('未授权', 401);
  const allowed = await getAdminAllowedGroups(env, ctx);
  const url = new URL(req.url);
  const returnAll = url.searchParams.get('all') === '1';
  const db = new Database(env.DB);
  try {
    // ensure tables exist
    await db.Query(`CREATE TABLE IF NOT EXISTS user_groups (username TEXT PRIMARY KEY, group_name TEXT)`, []);
    await db.Query(`CREATE TABLE IF NOT EXISTS groups (group_name TEXT PRIMARY KEY, created_at TEXT DEFAULT (datetime('now')))`, []);
    // groups from groups table
    const gRes = await db.Query(`SELECT group_name, 0 as cnt FROM groups ORDER BY group_name ASC`, []);
    const gRows = ((ThrowErrorIfFailed(gRes) as any).results as any[]) || [];
    // counts from user_groups
    const cRes = await db.Query(`SELECT group_name, COUNT(1) as cnt FROM user_groups GROUP BY group_name`, []);
    const cRows = ((ThrowErrorIfFailed(cRes) as any).results as any[]) || [];
    // merge: groups list from groups table, with counts from user_groups
    const counts: Record<string, number> = {};
    for (const r of cRows) counts[r.group_name] = Number(r.cnt || 0);
    const out: any[] = [];
    for (const g of gRows) {
      out.push({ group_name: g.group_name, cnt: counts[g.group_name] || 0 });
      delete counts[g.group_name];
    }
    // any remaining groups that exist only as user_groups
    for (const k of Object.keys(counts)) out.push({ group_name: k, cnt: counts[k] || 0 });
    // If returnAll requested, include an `allowed` flag per group rather than filtering
    if (returnAll) {
      const allowSet = allowed === null ? null : new Set((allowed||[]).map(String));
      const annotated = out.map(g => ({ group_name: g.group_name, cnt: g.cnt || 0, allowed: allowSet === null ? true : allowSet.has(String(g.group_name)) }));
      annotated.sort((a,b)=>String(a.group_name).localeCompare(String(b.group_name)));
      return successResponse({ groups: annotated });
    }
    // If sub-admin: filter groups to allowed set
    if (Array.isArray(allowed)) {
      const allowSet = new Set(allowed.map(String));
      for (let i = out.length - 1; i >= 0; i--) {
        if (!allowSet.has(String(out[i].group_name))) out.splice(i, 1);
      }
    }
    // sort by name
    out.sort((a,b)=>String(a.group_name).localeCompare(String(b.group_name)));
    return successResponse({ groups: out });
  } catch (e) {
    return errorResponse('db error', 500);
  }
}

// Admin: create group
async function handleAdminCreateGroup(env: Env, req: Request) {
  if (!requireAdmin(req, env)) return errorResponse('未授权', 401);
  const body = await readJson<{ group_name?: string }>(req);
  if (!body || !body.group_name) return errorResponse('group_name required', 400);
  const name = String(body.group_name).trim();
  if (!name) return errorResponse('group_name required', 400);
  const db = new Database(env.DB);
  try {
    await db.Query(`CREATE TABLE IF NOT EXISTS groups (group_name TEXT PRIMARY KEY, created_at TEXT DEFAULT (datetime('now')))`, []);
    await db.Query(`INSERT OR REPLACE INTO groups (group_name) VALUES (?)`, [name]);
    await writeAdminAudit(db, req.headers.get('x-admin-token'), 'create_group', null, null, { group_name: name });
    return successResponse({ ok: true });
  } catch (e) {
    return errorResponse('db error', 500);
  }
}

// Admin: set user group (upsert into user_groups). To clear group, send group_name = null or empty string.
async function handleAdminSetGroup(env: Env, req: Request) {
  if (!requireAdmin(req, env)) return errorResponse('未授权', 401);
  const body = await readJson<{ username?: string; group_name?: string }>(req);
  if (!body || !body.username) return errorResponse('username required', 400);
  const username = String(body.username);
  const group = typeof body.group_name === 'string' ? (body.group_name.trim() || null) : null;
  const db = new Database(env.DB);
  try {
    await db.Query(`CREATE TABLE IF NOT EXISTS user_groups (username TEXT PRIMARY KEY, group_name TEXT)`, []);
    if (!group) {
      await db.Query(`DELETE FROM user_groups WHERE username = ?`, [username]);
    } else {
      // insert or replace
      await db.Query(`INSERT INTO user_groups (username, group_name) VALUES (?, ?) ON CONFLICT(username) DO UPDATE SET group_name = excluded.group_name`, [username, group]);
    }
    await writeAdminAudit(db, req.headers.get('x-admin-token'), 'set_group', username, null, { group_name: group });
    return successResponse({ ok: true });
  } catch (e) {
    return errorResponse('db error', 500);
  }
}

// Admin: group analysis — compute per-user average score in given date range for group
async function handleAdminGroupAnalysis(env: Env, req: Request) {
  const ctx = await getAdminContext(env, req);
  if (!ctx) return errorResponse('未授权', 401);
  const url = new URL(req.url);
  const group = url.searchParams.get('group');
  const allowed = await getAdminAllowedGroups(env, ctx);
  if (!group) return errorResponse('group required', 400);
  if (Array.isArray(allowed) && allowed.length > 0 && !allowed.includes(group)) return errorResponse('未授权查看该组', 401);
  const start = url.searchParams.get('start');
  const end = url.searchParams.get('end');
  // default: last 30 days
  const db = new Database(env.DB);
  try {
    await db.Query(`CREATE TABLE IF NOT EXISTS user_groups (username TEXT PRIMARY KEY, group_name TEXT)`, []);
    // group param already validated above
    // get members
    const memRes = await db.Query(`SELECT username FROM user_groups WHERE group_name = ? ORDER BY username ASC`, [group]);
    const memRows = ((ThrowErrorIfFailed(memRes) as any).results as any[]) || [];
    const members = memRows.map(r => r.username).filter(Boolean);
    if (members.length === 0) return successResponse({ group, total: 0, members: [], counts: { healthy: 0, moderate: 0, unhealthy: 0 } });
    // build date filters
    let startDate = start;
    let endDate = end;
    if (!startDate || !endDate) {
      const now = new Date();
      const e = new Date(now.getTime());
      const s = new Date(now.getTime() - 30 * 24 * 3600 * 1000);
      const pad = (d: Date) => `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
      startDate = pad(s);
      endDate = pad(e);
    }
    // prepare placeholders
    const placeholders = members.map(()=>'?').join(',');
    // Map mood to score per rules
    const scoreExpr = `CASE mood WHEN '1' THEN 5 WHEN '2' THEN 4 WHEN '6' THEN 3 WHEN '7' THEN 2 WHEN '4' THEN 2 WHEN '5' THEN 1 WHEN '3' THEN 1 ELSE NULL END`;
    // Query per-user average
    const sql = `SELECT username, AVG(${scoreExpr}) as avg_score FROM mood_log WHERE date >= ? AND date <= ? AND username IN (${placeholders}) GROUP BY username`;
    const params: any[] = [startDate, endDate, ...members];
    const res = await db.Query(sql, params);
    const rows = ((ThrowErrorIfFailed(res) as any).results as any[]) || [];
    // normalize and categorize
    const memberMap: Record<string, any> = {};
    for (const m of members) memberMap[m] = { username: m, avg_score: null };
    for (const r of rows) {
      memberMap[r.username] = { username: r.username, avg_score: typeof r.avg_score === 'number' ? Number(r.avg_score) : (r.avg_score ? Number(r.avg_score) : null) };
    }
    const membersOut = Object.values(memberMap) as any[];
    const counts = { healthy: 0, moderate: 0, unhealthy: 0 };
    const lists: Record<string, any[]> = { healthy: [], moderate: [], unhealthy: [] };
    for (const m of membersOut) {
      const v = m.avg_score;
      if (v === null || typeof v !== 'number' || Number.isNaN(v)) {
        // treat as unhealthy (no data)
        counts.unhealthy++;
        lists.unhealthy.push(m);
        continue;
      }
      if (v >= 4.0) { counts.healthy++; lists.healthy.push(m); }
      else if (v >= 3.0) { counts.moderate++; lists.moderate.push(m); }
      else { counts.unhealthy++; lists.unhealthy.push(m); }
    }
    return successResponse({ group, total: members.length, members: membersOut, counts, lists, start: startDate, end: endDate });
  } catch (e) {
    return errorResponse('db error', 500);
  }
}

// Return encrypted bad_words payload. If client_pub_pem is provided (POST JSON), the server
// generates a random symmetric key, encrypts the payload with AES-CTR, and returns the ciphertext
// and the symmetric key encrypted with client's RSA public key (base64). If client_pub_pem not
// provided, returns plaintext payload.
async function handleGetEncryptedBadWords(env: Env, req: Request) {
  if (!env.WORDS) return errorResponse('KV 未配置', 500);
  const body = await readJson<{ client_pub_pem?: string }>(req);
  // read bad_words (or assembled chunks)
  let text = await env.WORDS.get('bad_words');
  if (!text) {
    // maybe index
    const idx = await env.WORDS.get('bad_words_index');
    if (idx) {
      let keys: string[] = [];
      try { keys = JSON.parse(idx as string); } catch { keys = []; }
      const parts: string[] = [];
      for (const k of keys) {
        const p = await env.WORDS.get(k);
        if (p) parts.push(p);
      }
      text = parts.join('\n');
    }
  }
  text = text || '';
  if (!body || !body.client_pub_pem) {
    return successResponse({ data: text });
  }
  // generate symmetric key
  const sym = genRandomKeyBase64();
  const cipher = await aesEncryptString(text, sym);
  let wrapped = '';
  try {
    wrapped = await encryptKeyWithPublicKey(sym, body.client_pub_pem as string);
  } catch (e) {
    return errorResponse('invalid client public key', 400);
  }
  return successResponse({ cipher, wrapped_key: wrapped });
}

async function handleAdminSetFlags(env: Env, req: Request) {
  if (!requireAdmin(req, env)) return errorResponse('未授权', 401);
  const body = await readJson<{ username: string; disable_anon_chat?: boolean; disable_mood?: boolean; disable_ai?: boolean }>(req);
  if (!body) return errorResponse('Invalid JSON', 400);
  const { username, disable_anon_chat, disable_mood, disable_ai } = body;
  if (!username) return errorResponse('username required');
  const update: Record<string, number> = {};
  if (typeof disable_anon_chat === 'boolean') update.disable_anon_chat = disable_anon_chat ? 1 : 0;
  if (typeof disable_mood === 'boolean') update.disable_mood = disable_mood ? 1 : 0;
  if (typeof disable_ai === 'boolean') update.disable_ai = disable_ai ? 1 : 0;
  if (Object.keys(update).length === 0) return errorResponse('no flags provided');
  const db = new Database(env.DB);
  await db.Update('user_table', update, { username });
  await writeAdminAudit(db, req.headers.get('x-admin-token'), 'set_flags', username, null, update);
  return successResponse('ok');
}

function aiAnalyzeReason(mood: string | null, interest: string | null): string {
  if (!mood) return "暂无心情数据";
  const m = String(mood);
  if (/^(1|开心|happy)$/i.test(m)) return "近期获得了积极反馈或享受了兴趣相关活动";
  if (/^(2|平静|calm)$/i.test(m)) return "作息规律、压力较小，情绪稳定";
  if (/^(3|焦虑|anx)\w*/i.test(m)) return "任务压力或不确定性导致的情绪紧张";
  if (/^(4|难过|sad)$/i.test(m)) return "社交受挫或学习瓶颈可能引起低落";
  if (/^(5|愤怒|angry)$/i.test(m)) return "期望与现实不符引发的挫败感";
  if (/^(6|疲惫|tired)$/i.test(m)) return "睡眠不足或过度投入需要恢复";
  if (/^(7|孤独|lonely)$/i.test(m)) return "社交联系不足，建议与同伴建立连接";
  return `与${interest ?? "兴趣"}相关的近期事件影响了心情`;
}

function aiGenerateSuggestion(mood: string | null, interest: string | null): string[] {
  const items: string[] = [];
  switch (String(mood)) {
    case "1":
      items.push("保持良好状态，尝试在兴趣方向上设定一个小目标");
      break;
    case "3":
      items.push("进行4-7-8呼吸法，列出可控事项逐一推进");
      break;
    case "4":
      items.push("联系一位信任的朋友聊聊，安排一次与兴趣相关的小活动");
      break;
    case "6":
      items.push("保证7-8小时睡眠，进行15分钟轻量运动");
      break;
    default:
      items.push("记录触发情绪的事件，观察情绪变化");
  }
  if (interest) items.push(`安排30分钟做关于“${interest}”的放松活动`);
  return items;
}

function typeNumberFromMood(mood: string | null): number {
  const m = String(mood || "0");
  const n = parseInt(m, 10);
  if (!Number.isNaN(n) && n >= 1 && n <= 7) return n;
  return 0;
}

async function handleAiChatData(env: Env, req: Request) {
  const url = new URL(req.url);
  const username = url.searchParams.get("username");
  if (!username) return errorResponse("username is required");
  const db = new Database(env.DB);
  const res = await db.Select("user_table", ["username", "hobby", "mood", "disabled", "disable_ai"], { username });
  const rows = (ThrowErrorIfFailed(res) as any[]) || [];
  const user = rows[0];
  if (!user) return errorResponse("用户不存在", 404);
  if ((user as any).disabled) return errorResponse("账户已被禁用", 403);
  if ((user as any).disable_ai) return errorResponse("AI 功能已被禁用", 403);
  const mood = (user as any).mood as string | null;
  const hobby = (user as any).hobby as string | null;

  const type_number = typeNumberFromMood(mood);
  const chief_reason = aiAnalyzeReason(mood, hobby);
  const other_contents = aiGenerateSuggestion(mood, hobby);

  return successResponse({
    type_number,
    present_mood: mood,
    interest: hobby,
    chief_reason,
    other_contents,
  });
}

async function handleAiChatMessage(env: Env, req: Request) {
  // CSRF removed: no server-side CSRF validation
  const body = await readJson<{ username: string; message?: string; use_framework?: boolean; framework_prompt?: string; conversation?: Array<{ role: string; content: string }> }>(req);
  if (!body) return errorResponse("Invalid JSON", 400);
  const { username, message = '', use_framework = false, framework_prompt = '', conversation = null } = body as any;
  if (!username) return errorResponse("username is required");
  // Allow empty message when using the framework (initial invisible apply). Otherwise require message text.
  if (!use_framework && (!message || String(message).trim() === '')) return errorResponse("message is required for free chat", 400);
  if (use_framework && !framework_prompt) return errorResponse("framework_prompt is required when use_framework is true", 400);
  const db = new Database(env.DB);
  const userRes = await db.Select("user_table", ["username", "mood", "last_mood_date", "hobby", "disabled", "disable_ai"], { username });
  const rows = (ThrowErrorIfFailed(userRes) as any[]) || [];
  const user = rows[0];
  if (!user) return errorResponse("用户不存在", 404);
  if ((user as any).disabled) return errorResponse("账户已被禁用", 403);
  if ((user as any).disable_ai) return errorResponse("AI 功能已被禁用", 403);

  const last = (user as any).last_mood_date as string | null;
  if (!last || last !== todayIsoDate()) return errorResponse("请先记录今天的心情", 400);

  const mood = (user as any).mood as string | null;
  const hobby = (user as any).hobby as string | null;

  // Build messages array for external model (include a concise system instruction)
  const sys = '你是一个情绪调节小助手。你的任务是：综合我的以下概况，安慰一下我当下的情绪，对我当下情绪的来源分析（注意不要照抄原因，要挖掘这些原因背后的申请心理机制、影响因素，但不要过于专业化，要求通俗易懂），并给出调节建议格式要求：整合为一段文字，不要有小标题，也不要把我的几个要素的内容列出，只需要给出对应的答案，安慰100字，来源分析和建议各150字.';
  const messages: Array<{ role: string; content: string }> = [ { role: 'system', content: sys } ];
  // If user opted into the framework, include the framework prompt as a separate user message (keeps it out of visible chat history)
  if (use_framework && framework_prompt) {
    // limit framework prompt length to prevent abuse
    const safeFramework = String(framework_prompt).slice(0, 2000);
    messages.push({ role: 'user', content: `提示词框架：${safeFramework}` });
  }
  // If the client provided a conversation context, sanitize and include it (bounded)
  try {
    if (conversation && Array.isArray(conversation)) {
      const MAX_CONV_ITEMS = 20;
      const MAX_CONTENT_LEN = 2000; // per item
      const sanitized: Array<{ role: string; content: string }> = [];
      for (const item of conversation.slice(-MAX_CONV_ITEMS)) {
        if (!item || typeof item !== 'object') continue;
        const r = String(item.role || '').toLowerCase();
        if (!(r === 'user' || r === 'assistant' || r === 'system')) continue;
        const c = String(item.content || '').slice(0, MAX_CONTENT_LEN);
        if (!c.trim()) continue;
        sanitized.push({ role: r, content: c });
      }
      if (sanitized.length) messages.push(...sanitized);
    }
  } catch (e) {
    // ignore malformed conversation but continue
    console.warn('invalid conversation field', e);
  }

  // Always include the user's concise context and question (message may be empty when framework is used for initial apply)
  // Avoid duplicating if conversation already contains an identical final user message
  const constructedUserMsg = `用户的当前心情是：${mood || '未知'}；兴趣：${hobby || '未知'}。用户问：${message || ''}`;
  const lastConvIsSameUser = (messages.length > 0 && messages[messages.length - 1].role === 'user' && String(messages[messages.length - 1].content || '').trim() === constructedUserMsg.trim());
  if (!lastConvIsSameUser) {
    messages.push({ role: 'user', content: constructedUserMsg });
  }

  let reply = '';
  try {
    reply = await callBigmodelChat(env, messages, 'glm-4', 0.7);
  } catch (e) {
    const errText = (e as Error).message || String(e);
    reply = `AI请求失败：${errText}`;
    // include the raw error in response data as well for client display
    await db.Insert("chat_history", { username, message, reply });
    return successResponse({ reply, error_detail: errText });
  }

  await db.Insert("chat_history", { username, message, reply });

  return successResponse({ reply });
}

// Call the external bigmodel chat completion API (compatible with AIchat.py)
// Supports either a `prompt` string (converted to a single user message) or a `messages` array
// (e.g. [{role: 'system', content: '...'}, {role:'user', content:'...'}]).
async function callBigmodelChat(env: Env, promptOrMessages: string | Array<{ role: string; content: string }>, model = 'glm-4', temperature = 0.7) {
  const key = env.BIGMODEL_API_KEY;
  if (!key) throw new Error('BIGMODEL_API_KEY not configured');
  const url = 'https://open.bigmodel.cn/api/paas/v4/chat/completions';
  let payload: any;
  if (Array.isArray(promptOrMessages)) {
    payload = { model, messages: promptOrMessages, temperature };
  } else {
    // default to a helpful system message + the user prompt
    payload = {
      model,
      messages: [
        { role: 'system', content: '你是一个有用的AI助手。' },
        { role: 'user', content: String(promptOrMessages || '') }
      ],
      temperature,
    };
  }
  const body = JSON.stringify(payload);
  const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${key}` }, body } as any);
  if (!res.ok) {
    const txt = await res.text().catch(()=>'<no body>');
    throw new Error(`bigmodel API error ${res.status}: ${txt}`);
  }
  const j: any = await res.json();
  // Expecting structure: choices[0].message.content or choices[0].text
  const content = (j && j.choices && j.choices[0] && (j.choices[0].message?.content || j.choices[0].message || j.choices[0].text)) || '';
  return String(content || '');
}

async function handleEndAnonymous(env: Env, req: Request) {
  // CSRF removed: no server-side CSRF validation
  const body = await readJson<{ username: string; other_username?: string }>(req);
  if (!body) return errorResponse("Invalid JSON", 400);
  const { username, other_username } = body as any;
  if (!username) return errorResponse("username is required", 400);
  const db = new Database(env.DB);
  // Try to derive current room and partner from DB to be robust against inconsistent client state
  const meRes = await db.Select('user_table', ['partner_username', 'current_room_id'], { username });
  const me = ((ThrowErrorIfFailed(meRes) as any[]) || [])[0] as any;
  let room_id: string | null = null;
  const partners = new Set<string>();
  partners.add(username);
  if (other_username) partners.add(String(other_username));
  if (me) {
    if (me.current_room_id) room_id = me.current_room_id as string;
    if (me.partner_username) partners.add(String(me.partner_username));
  }
  // If still don't have room_id but have other_username, compute room id deterministically
  if (!room_id && other_username) room_id = makeRoomId(username, other_username);

  // Delete chat history for the room if known
  let _roomEndMeta: any = null;
  if (room_id) {
    // Clear DB-backed chat history for this room
    try { await db.Query(`DELETE FROM anon_chat WHERE room_id = ?`, [room_id]); } catch (e) { /* ignore */ }
    // notify listeners via room state bump
    try { await bumpRoomState(db, room_id); } catch (e) {}
  }

  // Clear chatting state for all involved usernames we gathered
  const list = Array.from(partners).filter(Boolean);
  if (list.length > 0) {
    // Build placeholders
    const placeholders = list.map(() => '?').join(', ');
    const sql = `UPDATE user_table SET chatting = 0, partner_username = NULL, current_room_id = NULL WHERE username IN (${placeholders})`;
    await db.Query(sql, list);
  }

  return successResponse({ message: '聊天已结束', room_end: _roomEndMeta });
}

async function handleAnonSend(env: Env, req: Request) {
  // CSRF removed: no server-side CSRF validation
  const body = await readJson<{ room_id: string; sender: string; recipient: string; message: string }>(req);
  if (!body) return errorResponse("Invalid JSON", 400);
  const { room_id, sender, recipient, message } = body;
  if (!room_id || !sender || !recipient || !message) return errorResponse("missing fields");
  const db = new Database(env.DB);
  // feature gate: anon chat
  const sRes = await db.Select("user_table", ["disabled", "disable_anon_chat"], { username: sender });
  const sRow = ((ThrowErrorIfFailed(sRes) as any[]) || [])[0] as any;
  if (!sRow) return errorResponse("用户不存在", 404);
  if (sRow.disabled) return errorResponse("账户已被禁用", 403);
  if (sRow.disable_anon_chat) return errorResponse("匿名聊天功能已被禁用", 403);
  const safe = await sanitizeMessageAsync(message, env);
  // rate limit per sender to prevent spam
  try {
    const rl = await rateLimitCheck(db, `anon_msg:${sender}`, 5, 40); // ~40 messages per 5s window
    if (!rl.ok) return jsonResponse({ ok: false, error: '发送过于频繁' }, { status: 429 });
  } catch (e) {}
  // If ROOM is configured, send exclusively to Durable Object and do not persist to D1.
  // Persist to DB (DB-only behavior)
  let storedMessage = safe;
  try {
    if (env.STORAGE_SECRET) {
      storedMessage = await aesEncryptString(safe, env.STORAGE_SECRET);
    }
  } catch (e) {
    storedMessage = safe;
  }
  await db.Insert("anon_chat", { room_id, sender, recipient, message: storedMessage });
  await db.Update("user_table", { last_heartbeat: nowIso() }, { username: sender });
  try { await bumpRoomState(db, room_id); } catch (e) {}
  return successResponse({ ok: true });
}

async function handleAnonFetch(env: Env, req: Request) {
  const url = new URL(req.url);
  const room_id = url.searchParams.get("room_id");
  const since = url.searchParams.get("since"); // ISO datetime string
  const clientPubPem = req.headers.get('x-client-pub-pem') || url.searchParams.get('client_pub_pem') || null;
  if (!room_id) return errorResponse("room_id is required");
  const db = new Database(env.DB);

  // If client requests per-message wrapping using their public key, keep DB path (wrapping logic relies on server-side STORAGE_SECRET)
  if (clientPubPem && env.STORAGE_SECRET) {
    const sql = since
      ? `SELECT id, room_id, sender, recipient, message, timestamp FROM anon_chat WHERE room_id = ? AND timestamp > ? ORDER BY id ASC`
      : `SELECT id, room_id, sender, recipient, message, timestamp FROM anon_chat WHERE room_id = ? ORDER BY id ASC`;
    const res = since ? await db.Query(sql, [room_id, since]) : await db.Query(sql, [room_id]);
    const messages = ((ThrowErrorIfFailed(res) as any).results as any[]) || [];
    // If client provided public key, re-wrap each message for that client
    if (clientPubPem && env.STORAGE_SECRET) {
      const out: any[] = [];
      for (const m of messages) {
        const stored = String((m as any).message || '');
        let plain = stored;
        try {
          // attempt to decrypt using server storage secret
          plain = await aesDecryptString(stored, env.STORAGE_SECRET);
        } catch (e) {
          // if decryption fails, assume stored is plaintext
          plain = stored;
        }
        // generate ephemeral symmetric key and wrap for client
        const sym = genRandomKeyBase64();
        const cipher = await aesEncryptString(plain, sym);
        let wrapped = '';
        try { wrapped = await encryptKeyWithPublicKey(sym, clientPubPem as string); } catch (e) { wrapped = ''; }
        out.push({ ...m, message: { cipher, wrapped_key: wrapped } });
      }
      return successResponse({ messages: out });
    }
    return successResponse({ messages });
  }

  // DB-only fetch path
  const sql = since
    ? `SELECT id, room_id, sender, recipient, message, timestamp FROM anon_chat WHERE room_id = ? AND timestamp > ? ORDER BY id ASC`
    : `SELECT id, room_id, sender, recipient, message, timestamp FROM anon_chat WHERE room_id = ? ORDER BY id ASC`;
  const res = since ? await db.Query(sql, [room_id, since]) : await db.Query(sql, [room_id]);
  const messages = ((ThrowErrorIfFailed(res) as any).results as any[]) || [];
  // If client provided public key, re-wrap each message for that client
  if (clientPubPem && env.STORAGE_SECRET) {
    const out: any[] = [];
    for (const m of messages) {
      const stored = String((m as any).message || '');
      let plain = stored;
      try {
        // attempt to decrypt using server storage secret
        plain = await aesDecryptString(stored, env.STORAGE_SECRET);
      } catch (e) {
        // if decryption fails, assume stored is plaintext
        plain = stored;
      }
      // generate ephemeral symmetric key and wrap for client
      const sym = genRandomKeyBase64();
      const cipher = await aesEncryptString(plain, sym);
      let wrapped = '';
      try { wrapped = await encryptKeyWithPublicKey(sym, clientPubPem as string); } catch (e) { wrapped = ''; }
      out.push({ ...m, message: { cipher, wrapped_key: wrapped } });
    }
    return successResponse({ messages: out });
  }
  return successResponse({ messages });
}

// --- BBS (message board) ---
async function handleBbsPost(env: Env, req: Request) {
  const body = await readJson<{ nickname?: string; content: string; mood?: string }>(req);
  if (!body) return errorResponse("Invalid JSON", 400);
  let { nickname = "匿名", content, mood = null } = body as any;
  nickname = String(nickname || "匿名").slice(0, 16);
  content = String(content || "").trim();
  if (!content) return errorResponse("content is required");
  if (String(content).length > 200) return errorResponse("内容过长，最多 200 字");
  if (mood) mood = String(mood).slice(0, 10);
  const safe = await sanitizeMessageAsync(content, env);
  const db = new Database(env.DB);
  // rate limit per nickname or IP
  try {
    const key = `bbs:${nickname || req.headers.get('x-real-ip')||req.headers.get('x-forwarded-for')||'anon'}`;
    const rl = await rateLimitCheck(db, key, 60, 6); // max 6 posts per minute
    if (!rl.ok) return jsonResponse({ ok: false, error: '发布过于频繁' }, { status: 429 });
  } catch (e) {}
  await db.Insert("bbs_messages", { nickname, content: safe, mood });
  return successResponse("ok");
}

async function handleBbsList(env: Env, req: Request) {
  const url = new URL(req.url);
  const limitStr = url.searchParams.get("limit");
  const offsetStr = url.searchParams.get("offset");
  let limit = parseInt(String(limitStr || "50"), 10);
  let offset = parseInt(String(offsetStr || "0"), 10);
  if (!Number.isFinite(limit) || limit <= 0 || limit > 200) limit = 50;
  if (!Number.isFinite(offset) || offset < 0) offset = 0;
  const db = new Database(env.DB);
  const res = await db.Query(
    `SELECT id, nickname, content, mood, time FROM bbs_messages ORDER BY time DESC, id DESC LIMIT ? OFFSET ?`,
    [limit, offset]
  );
  const rows = ((ThrowErrorIfFailed(res) as any).results as any[]) || [];
  return successResponse({ messages: rows });
}

// Long-poll endpoint to wait for new BBS messages after last_id
async function handleBbsSubscribe(env: Env, req: Request) {
  const url = new URL(req.url);
  const lastIdStr = url.searchParams.get('last_id') || '0';
  let lastId = parseInt(lastIdStr, 10) || 0;
  const db = new Database(env.DB);
  const start = Date.now();
  const timeoutMs = 25000;
  while (Date.now() - start < timeoutMs) {
    const res = await db.Query(`SELECT id, nickname, content, mood, time FROM bbs_messages WHERE id > ? ORDER BY id ASC LIMIT 100`, [lastId]);
    const rows = ((ThrowErrorIfFailed(res) as any).results as any[]) || [];
    if (rows.length > 0) return successResponse({ messages: rows });
    await sleep(1000);
  }
  return successResponse({ messages: [] });
}

// Long-poll for session updates (server-driven close) for a username
async function handleAnonWait(env: Env, req: Request) {
  const url = new URL(req.url);
  const username = url.searchParams.get('username');
  if (!username) return errorResponse('username required', 400);
  const db = new Database(env.DB);
  const start = Date.now();
  const timeoutMs = 25000;
  // If ROOM is configured, poll the DO instance for room changes (message count) to implement wait.
  // Otherwise fall back to DB polling (original behavior).
  const infoRes = await db.Select('user_table', ['chatting', 'partner_username', 'current_room_id'], { username });
  const infoRow = ((ThrowErrorIfFailed(infoRes) as any[]) || [])[0] as any;
  const prevChatting = infoRow?.chatting || 0;
  const prevRoom = infoRow?.current_room_id || null;

  // DB polling (original behavior)
  const start2 = Date.now();
  while (Date.now() - start2 < timeoutMs) {
    await sleep(1000);
    const nowRes2 = await db.Select('user_table', ['chatting', 'partner_username', 'current_room_id'], { username });
    const nowRow2 = ((ThrowErrorIfFailed(nowRes2) as any[]) || [])[0] as any;
    const nowChatting = nowRow2?.chatting || 0;
    const nowRoom = nowRow2?.current_room_id || null;
    if (nowChatting !== prevChatting || nowRoom !== prevRoom) {
      return successResponse({ chatting: nowChatting, current_room_id: nowRoom, partner_username: nowRow2?.partner_username || null });
    }
  }
  return successResponse({});
}

// Lightweight endpoint to read the room state (version) for clients that prefer to poll directly
async function handleRoomState(env: Env, req: Request) {
  const url = new URL(req.url);
  const room_id = url.searchParams.get('room_id');
  if (!room_id) return errorResponse('room_id required', 400);
  const db = new Database(env.DB);
  try {
    const res = await db.Query(`SELECT version, last_update FROM room_states WHERE room_id = ?`, [room_id]);
    const rows = ((ThrowErrorIfFailed(res) as any).results as any[]) || [];
    if (rows.length === 0) return successResponse({ room_id, version: null, last_update: null });
    return successResponse({ room_id, version: Number(rows[0].version || 0), last_update: rows[0].last_update || null });
  } catch (e) {
    return errorResponse('db error', 500);
  }
}

// --- Page visit tracking ---
async function handleTrackVisit(env: Env, req: Request) {
  const body = await readJson<{ username?: string; page: string; title?: string; referrer?: string; ua?: string }>(req);
  if (!body) return errorResponse("Invalid JSON", 400);
  let { username = null, page, title = null, referrer = null, ua = null } = body as any;
  page = String(page || '').slice(0, 300);
  if (!page) return errorResponse('page is required');
  if (username) username = String(username).slice(0, 64);
  if (title) title = String(title).slice(0, 200);
  if (referrer) referrer = String(referrer).slice(0, 300);
  if (ua) ua = String(ua).slice(0, 300);
  const db = new Database(env.DB);
  try {
    // soft rate-limit per IP to avoid floods
    await rateLimitCheck(db, `visit:${req.headers.get('x-real-ip')||req.headers.get('x-forwarded-for')||'anon'}`, 10, 200);
  } catch (e) {}
  await db.Insert('page_visits', { username, page, title, referrer, ua });
  return successResponse('ok');
}

async function handleAdminListVisits(env: Env, req: Request) {
  if (!requireAdmin(req, env)) return errorResponse('未授权', 401);
  const url = new URL(req.url);
  const q = (url.searchParams.get('q') || '').trim();
  const limitStr = url.searchParams.get('limit');
  const offsetStr = url.searchParams.get('offset');
  let limit = parseInt(String(limitStr || '200'), 10);
  let offset = parseInt(String(offsetStr || '0'), 10);
  if (!Number.isFinite(limit) || limit <= 0 || limit > 1000) limit = 200;
  if (!Number.isFinite(offset) || offset < 0) offset = 0;
  const db = new Database(env.DB);
  let res;
  let total = 0;
  if (q) {
    res = await db.Query(
      `SELECT id, username, page, title, referrer, ua, time FROM page_visits
       WHERE username LIKE ? OR page LIKE ? OR title LIKE ?
       ORDER BY time DESC, id DESC LIMIT ? OFFSET ?`,
      [`%${q}%`, `%${q}%`, `%${q}%`, limit, offset]
    );
    const cntRes = await db.Query(`SELECT COUNT(1) as total FROM page_visits WHERE username LIKE ? OR page LIKE ? OR title LIKE ?`, [`%${q}%`, `%${q}%`, `%${q}%`]);
    total = ((ThrowErrorIfFailed(cntRes) as any).results || [])[0]?.total || 0;
  } else {
    res = await db.Query(
      `SELECT id, username, page, title, referrer, ua, time FROM page_visits
       ORDER BY time DESC, id DESC LIMIT ? OFFSET ?`,
      [limit, offset]
    );
    const cntRes = await db.Query(`SELECT COUNT(1) as total FROM page_visits`, []);
    total = ((ThrowErrorIfFailed(cntRes) as any).results || [])[0]?.total || 0;
  }
  const rows = ((ThrowErrorIfFailed(res) as any).results as any[]) || [];
  // attach total (if computed above)
  try {
    return successResponse({ visits: rows, total });
  } catch (e) {
    return successResponse({ visits: rows, total: 0 });
  }
}

// --- Rate limiting helper (simple sliding window per key using DB) ---
async function rateLimitCheck(db: Database, key: string, windowSeconds: number, maxCount: number) {
  const now = new Date();
  const windowStart = new Date(Math.floor(now.getTime() / (windowSeconds * 1000)) * windowSeconds * 1000).toISOString();
  // Try to find existing counter
  const res = await db.Query(`SELECT id, count, window_start FROM rate_limits WHERE key = ?`, [key]);
  const rows = ((ThrowErrorIfFailed(res) as any).results as any[]) || [];
  if (rows.length === 0) {
    await db.Query(`INSERT INTO rate_limits (key, window_start, count) VALUES (?, ?, 1)`, [key, windowStart]);
    return { ok: true };
  }
  const row = rows[0];
  if (row.window_start !== windowStart) {
    // reset window
    await db.Query(`UPDATE rate_limits SET window_start = ?, count = 1 WHERE id = ?`, [windowStart, row.id]);
    return { ok: true };
  }
  if (row.count + 1 > maxCount) return { ok: false, remaining: 0 };
  await db.Query(`UPDATE rate_limits SET count = count + 1 WHERE id = ?`, [row.id]);
  return { ok: true };
}

// --- Room state helper: lightweight per-room version to notify listeners with a single-row read ---
async function bumpRoomState(db: Database, room_id: string) {
  if (!room_id) return;
  try {
    // Upsert: insert new row or increment version
    await db.Query(
      `INSERT INTO room_states (room_id, version, last_update) VALUES (?, 1, datetime('now'))
       ON CONFLICT(room_id) DO UPDATE SET version = version + 1, last_update = datetime('now')`,
      [room_id]
    );
  } catch (e) {
    // ignore any room-state failures — non-critical
  }
}

// --- Reporting endpoints ---
async function handleReport(env: Env, req: Request) {
  // CSRF removed: no server-side CSRF validation
  const body = await readJson<{ reporter?: string; target_username?: string; target_room_id?: string; reason?: string; details?: string }>(req);
  if (!body) return errorResponse('Invalid JSON', 400);
  const { reporter = null, target_username = null, target_room_id = null, reason = null, details = null } = body as any;
  const db = new Database(env.DB);
  // Rate limit per reporter (if provided) or per IP
  const key = reporter ? `report:${reporter}` : `report:ip:${req.headers.get('x-real-ip') || req.headers.get('x-forwarded-for') || 'anon'}`;
  const rl = await rateLimitCheck(db, key, 60, 10); // 10 reports/min per reporter
  if (!rl.ok) return jsonResponse({ ok: false, error: 'Too many reports' }, { status: 429 });
  await db.Insert('user_reports', { reporter, target_username, target_room_id, reason, details });
  return successResponse('ok');
}

async function handleAdminListReports(env: Env, req: Request) {
  const ctx = await getAdminContext(env, req);
  if (!ctx) return errorResponse('未授权', 401);
  const allowed = await getAdminAllowedGroups(env, ctx);
  const url = new URL(req.url);
  const q = (url.searchParams.get('q') || '').trim();
  const limitStr = url.searchParams.get('limit');
  const offsetStr = url.searchParams.get('offset');
  let limit = parseInt(String(limitStr || '200'), 10);
  let offset = parseInt(String(offsetStr || '0'), 10);
  if (!Number.isFinite(limit) || limit <= 0 || limit > 1000) limit = 200;
  if (!Number.isFinite(offset) || offset < 0) offset = 0;
  const db = new Database(env.DB);
  if (Array.isArray(allowed) && allowed.length === 0) return successResponse({ reports: [], total: 0 });
  let res;
  let total = 0;
  if (q) {
    if (allowed === null) {
      res = await db.Query(`SELECT id, reporter, target_username, target_room_id, reason, details, time FROM user_reports WHERE reporter LIKE ? OR target_username LIKE ? ORDER BY time DESC LIMIT ? OFFSET ?`, [`%${q}%`, `%${q}%`, limit, offset]);
      const cntRes = await db.Query(`SELECT COUNT(1) as total FROM user_reports WHERE reporter LIKE ? OR target_username LIKE ?`, [`%${q}%`, `%${q}%`]);
      total = ((ThrowErrorIfFailed(cntRes) as any).results || [])[0]?.total || 0;
    } else {
      const placeholders = allowed.map(() => '?').join(',');
      const params = [`%${q}%`, `%${q}%`, ...allowed, limit, offset];
      res = await db.Query(`SELECT r.id, r.reporter, r.target_username, r.target_room_id, r.reason, r.details, r.time FROM user_reports r JOIN user_groups ug ON r.target_username = ug.username WHERE (r.reporter LIKE ? OR r.target_username LIKE ?) AND ug.group_name IN (${placeholders}) ORDER BY r.time DESC LIMIT ? OFFSET ?`, params);
      const cntRes = await db.Query(`SELECT COUNT(1) as total FROM user_reports r JOIN user_groups ug ON r.target_username = ug.username WHERE (r.reporter LIKE ? OR r.target_username LIKE ?) AND ug.group_name IN (${placeholders})`, [`%${q}%`, `%${q}%`, ...allowed]);
      total = ((ThrowErrorIfFailed(cntRes) as any).results || [])[0]?.total || 0;
    }
  } else {
    if (allowed === null) {
      res = await db.Query(`SELECT id, reporter, target_username, target_room_id, reason, details, time FROM user_reports ORDER BY time DESC LIMIT ? OFFSET ?`, [limit, offset]);
      const cntRes = await db.Query(`SELECT COUNT(1) as total FROM user_reports`, []);
      total = ((ThrowErrorIfFailed(cntRes) as any).results || [])[0]?.total || 0;
    } else {
      const placeholders = allowed.map(() => '?').join(',');
      const params = [...allowed, limit, offset];
      res = await db.Query(`SELECT r.id, r.reporter, r.target_username, r.target_room_id, r.reason, r.details, r.time FROM user_reports r JOIN user_groups ug ON r.target_username = ug.username WHERE ug.group_name IN (${placeholders}) ORDER BY r.time DESC LIMIT ? OFFSET ?`, params);
      const cntRes = await db.Query(`SELECT COUNT(1) as total FROM user_reports r JOIN user_groups ug ON r.target_username = ug.username WHERE ug.group_name IN (${placeholders})`, allowed);
      total = ((ThrowErrorIfFailed(cntRes) as any).results || [])[0]?.total || 0;
    }
  }
  const rows = ((ThrowErrorIfFailed(res) as any).results as any[]) || [];
  return successResponse({ reports: rows, total });
}

// Helper to write admin audit log
async function writeAdminAudit(db: Database, adminToken: string | null, action: string, target: string | null, reason: string | null, meta: any = null) {
  try {
    await db.Insert('admin_audit', { admin_token: adminToken, action, target, reason, meta: meta ? JSON.stringify(meta) : null });
  } catch (e) { /* ignore logging failures */ }
}

// Admin: resolve report (optionally disable user or force-end session)
async function handleAdminResolveReport(env: Env, req: Request) {
  if (!requireAdmin(req, env)) return errorResponse('未授权', 401);
  const body = await readJson<{ report_id: number; action?: 'resolve' | 'disable' | 'force_end'; reason?: string }>(req);
  if (!body) return errorResponse('Invalid JSON', 400);
  const { report_id, action = 'resolve', reason = null } = body as any;
  const db = new Database(env.DB);
  // fetch report
  const repRes = await db.Query(`SELECT reporter, target_username, target_room_id FROM user_reports WHERE id = ?`, [report_id]);
  const repRows = ((ThrowErrorIfFailed(repRes) as any).results as any[]) || [];
  if (repRows.length === 0) return errorResponse('report not found', 404);
  const rep = repRows[0];
  const targets: string[] = [];
  if (rep.target_username) targets.push(rep.target_username);
  if (action === 'disable' && rep.target_username) {
    await db.Update('user_table', { disabled: 1 }, { username: rep.target_username });
    await writeAdminAudit(db, req.headers.get('x-admin-token'), 'disable_user', rep.target_username, reason, { report_id });
  }
  if (action === 'force_end') {
    // reuse force end logic by deleting room and clearing users
    if (rep.target_room_id) {
      await db.Query(`DELETE FROM anon_chat WHERE room_id = ?`, [rep.target_room_id]);
      await db.Query(`UPDATE user_table SET chatting = 0, partner_username = NULL, current_room_id = NULL WHERE current_room_id = ?`, [rep.target_room_id]);
      await writeAdminAudit(db, req.headers.get('x-admin-token'), 'force_end_room', rep.target_room_id, reason, { report_id });
    }
  }
  // mark report as resolved by deleting or adding a resolved flag (simpler: delete)
  await db.Query(`DELETE FROM user_reports WHERE id = ?`, [report_id]);
  await writeAdminAudit(db, req.headers.get('x-admin-token'), 'resolve_report', rep.target_username || rep.target_room_id || String(report_id), reason, { report_id });
  return successResponse('ok');
}

// Admin analytics: simple aggregates
async function handleAdminAnalytics(env: Env, req: Request) {
  if (!requireAdmin(req, env)) return errorResponse('未授权', 401);
  // Prefer Cloudflare Analytics GraphQL when credentials are provided (better accuracy and lower DB load)
  const cfToken = (env as any).CF_API_TOKEN as string | undefined;
  const cfZone = (env as any).CF_ZONE_ID as string | undefined;
  // Prefer Analytics Engine dataset binding if available (low-latency, edge-native)
  if ((env as any).feeling && typeof (env as any).feeling.query === 'function') {
    try {
      // Example AE query: count page views per day for last 30 days and uniques last 24h
      const ae = (env as any).feeling;
      const now = new Date();
      const since = new Date(now.getTime() - 30 * 24 * 3600 * 1000).toISOString();
      const until = now.toISOString();
      // Query: group by date(date_trunc('day', time)) and count
      const q1 = `SELECT date_trunc('day', time) as day, count() as cnt FROM ${ae.dataset || 'feeling'} WHERE time >= parse_datetime('${since}') AND time <= parse_datetime('${until}') GROUP BY day ORDER BY day DESC LIMIT 30`;
      const r1 = await ae.query(q1);
    const visits = (r1?.results || []).map((row: any) => ({ day: row.day, cnt: row.cnt }));
    const since24 = new Date(now.getTime() - 24 * 3600 * 1000).toISOString();
    const q2 = `SELECT uniq(user) as uniques FROM ${ae.dataset || 'feeling'} WHERE time >= parse_datetime('${since24}')`;
    const r2 = await ae.query(q2);
    const uniques = r2?.results?.[0]?.uniques || 0;
    return successResponse({ visits, active_users_last_24h: uniques, analytics_source: 'analytics_engine' });
    } catch (e) {
      // fall through to CF GraphQL or DB fallback
    }
  }
  if (cfToken && cfZone) {
    try {
      // Query timeseries for pageviews per day for last 30 days and unique visitors last 24h
      const gql = `query($zoneTag: string!, $since: String!, $until: String!) { viewer { zones(filter: { zoneTag: $zoneTag }) { httpRequests1dGroups(filter: {datetime_geq: $since, datetime_leq: $until}, limit: 30) { dimensions { date } sum { pageViews } } httpRequests1hGroups(filter: {datetime_geq: $since, datetime_leq: $until}, limit: 24) { sum { uniques } } } } }`;
      const sinceDate = new Date(Date.now() - 30 * 24 * 3600 * 1000).toISOString().slice(0, 10) + 'T00:00:00Z';
      const untilDate = new Date().toISOString();
      const body = JSON.stringify({ query: gql, variables: { zoneTag: cfZone, since: sinceDate, until: untilDate } });
      const res = await fetch('https://api.cloudflare.com/client/v4/graphql', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${cfToken}` }, body });
  const json: any = await res.json();
  // Safely extract
  const viewer = json && json.data && json.data.viewer ? json.data.viewer : null;
  const zone = viewer && Array.isArray(viewer.zones) && viewer.zones.length > 0 ? viewer.zones[0] : null;
  const groups = zone && zone.httpRequests1dGroups ? zone.httpRequests1dGroups : [];
  const visits = (groups || []).map((g: any) => ({ day: (g && g.dimensions && g.dimensions.date) || null, cnt: (g && g.sum && g.sum.pageViews) || 0 }));
  const uniquesGroups = zone && zone.httpRequests1hGroups ? zone.httpRequests1hGroups : [];
  const uniques = uniquesGroups && uniquesGroups[0] && uniquesGroups[0].sum ? uniquesGroups[0].sum.uniques || 0 : 0;
  return successResponse({ visits, active_users_last_24h: uniques, analytics_source: 'cloudflare_graphql' });
    } catch (e) {
      // fall back to DB
    }
  }
  const db = new Database(env.DB);
  const visitsRes = await db.Query(`SELECT date(time) as day, count(1) as cnt FROM page_visits GROUP BY date(time) ORDER BY day DESC LIMIT 30`, []);
  const visits = ((ThrowErrorIfFailed(visitsRes) as any).results as any[]) || [];
  // anon_chat stores sender and recipient (no 'username' column). Count distinct users active in last 24h
  const activeRes = await db.Query(
    `SELECT COUNT(DISTINCT user) as active_users FROM (
       SELECT sender as user FROM anon_chat WHERE timestamp >= datetime('now', '-1 day')
       UNION
       SELECT recipient as user FROM anon_chat WHERE timestamp >= datetime('now', '-1 day')
     ) AS u`,
    []
  );
  const activeRow = ((ThrowErrorIfFailed(activeRes) as any).results as any[]) || [];
  const activeCount = activeRow[0]?.active_users || 0;
  return successResponse({ visits, active_users_last_24h: activeCount, analytics_source: 'db' });
}

// Admin-only: test Bigmodel connectivity and return raw response for diagnostics.
async function handleAdminAiTest(env: Env, req: Request) {
  if (!requireAdmin(req, env)) return errorResponse('未授权', 401);
  const body = await readJson<{ prompt?: string; model?: string; temperature?: number; messages?: Array<{ role: string; content: string }> }>(req);
  if (!body) return errorResponse('Invalid JSON', 400);
  const { prompt = '测试 Bigmodel 连接', model = 'glm-4', temperature = 0.7, messages = null } = body as any;
  const key = env.BIGMODEL_API_KEY;
  if (!key) return errorResponse('BIGMODEL_API_KEY not configured', 500);
  const url = 'https://open.bigmodel.cn/api/paas/v4/chat/completions';
  // If messages provided, forward as-is; otherwise wrap prompt into a single user message (preserve previous behavior)
  const payloadObj = messages && Array.isArray(messages) && messages.length > 0 ? { model, messages, temperature } : { model, messages: [{ role: 'user', content: prompt }], temperature };
  const payload = JSON.stringify(payloadObj);
  try {
    const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${key}` }, body: payload } as any);
    const txt = await res.text().catch(() => '<no body>');
    let parsed = null;
    try { parsed = JSON.parse(txt); } catch { parsed = null; }
    return jsonResponse({ ok: true, status: res.status, body_text: txt, body_json: parsed }, { status: 200 });
  } catch (e) {
    return jsonResponse({ ok: false, error: 'fetch_error', detail: (e as Error).message || String(e) }, { status: 500 });
  }
}

// --- Health: DB connectivity check ---
async function handleHealthDb(env: Env, req: Request) {
  const start = Date.now();
  const db = new Database(env.DB);
  try {
    // simple lightweight query
    await db.Query(`SELECT 1` , []);
    const timeMs = Date.now() - start;
    return successResponse({ ok: true, time_ms: timeMs });
  } catch (e) {
    const timeMs = Date.now() - start;
    const err = e as any;
    return jsonResponse({ ok: false, error: 'db_error', time_ms: timeMs, error_detail: err?.message || String(err), stack: err?.stack || null }, { status: 500 });
  }
}

// Public aggregated health check for commonly-accessible APIs.
// Returns a JSON object with per-check results: /api/health, /api/_health/db, /api/bbs (list), /api/maintenance
async function handlePublicApiHealth(env: Env, req: Request) {
  const results: Record<string, any> = {};
  let overallOk = true;
  try {
    // root health (quick local check)
    try {
      results.root = { ok: true };
    } catch (e) {
      results.root = { ok: false, error: String(e) };
      overallOk = false;
    }

    // DB health
    try {
      const r = await handleHealthDb(env, req);
      const j: any = await r.json().catch(() => ({ ok: false }));
      results.db = j;
      if (!j || !j.ok) overallOk = false;
    } catch (e) {
      results.db = { ok: false, error: (e as Error).message || String(e) };
      overallOk = false;
    }

    // BBS list (public)
    try {
      const r = await handleBbsList(env, req);
      const j: any = await r.json().catch(() => ({ ok: false }));
      results.bbs = j;
      if (!j || !j.ok) overallOk = false;
    } catch (e) {
      results.bbs = { ok: false, error: (e as Error).message || String(e) };
      overallOk = false;
    }

    // Maintenance list (public)
    try {
      const r = await handlePublicMaintenanceList(env, req);
      const j: any = await r.json().catch(() => ({ ok: false }));
      results.maintenance = j;
      if (!j || !j.ok) overallOk = false;
    } catch (e) {
      results.maintenance = { ok: false, error: (e as Error).message || String(e) };
      overallOk = false;
    }
  } catch (e) {
    return errorResponse('internal health check failed', 500);
  }
  return successResponse({ ok: overallOk, checks: results, time: new Date().toISOString() });
}

// --- Maintenance / planned issues (admin) ---
// Public: list maintenance entries
async function handlePublicMaintenanceList(env: Env, req: Request) {
  const db = new Database(env.DB);
  try {
    const res = await db.Query(`SELECT id, title, details, start_time, end_time, created_by, active, created_at FROM maintenance ORDER BY start_time DESC`, []);
    const rows = ((ThrowErrorIfFailed(res) as any).results as any[]) || [];
    return successResponse({ maintenance: rows });
  } catch (e) {
    return errorResponse('db error', 500);
  }
}

// Admin: create maintenance entry
async function handleAdminCreateMaintenance(env: Env, req: Request) {
  if (!requireAdmin(req, env)) return errorResponse('未授权', 401);
  const body = await readJson<{ title: string; details?: string; start_time?: string; end_time?: string; active?: boolean }>(req);
  if (!body || !body.title) return errorResponse('title required', 400);
  const { title, details = null, start_time = null, end_time = null, active = true } = body as any;
  const db = new Database(env.DB);
  try {
    await db.Query(`INSERT INTO maintenance (title, details, start_time, end_time, created_by, active, created_at) VALUES (?, ?, ?, ?, ?, ?, datetime('now'))`, [title, details, start_time, end_time, req.headers.get('x-admin-token') || null, active ? 1 : 0]);
    return successResponse({ ok: true });
  } catch (e) {
    return errorResponse('db error', 500);
  }
}

// Admin: delete maintenance entry
async function handleAdminDeleteMaintenance(env: Env, req: Request) {
  if (!requireAdmin(req, env)) return errorResponse('未授权', 401);
  const body = await readJson<{ id?: number }>(req);
  if (!body || !body.id) return errorResponse('id required', 400);
  const db = new Database(env.DB);
  try {
    await db.Query(`DELETE FROM maintenance WHERE id = ?`, [body.id]);
    return successResponse({ ok: true });
  } catch (e) {
    return errorResponse('db error', 500);
  }
}

// Admin: update maintenance entry
async function handleAdminUpdateMaintenance(env: Env, req: Request) {
  if (!requireAdmin(req, env)) return errorResponse('未授权', 401);
  const body = await readJson<{ id?: number; title?: string; details?: string; start_time?: string; end_time?: string; active?: boolean }>(req);
  if (!body || !body.id) return errorResponse('id required', 400);
  const { id, title, details = null, start_time = null, end_time = null, active = undefined } = body as any;
  const db = new Database(env.DB);
  try {
    const updates: string[] = [];
    const params: any[] = [];
    if (typeof title === 'string' && title.length > 0) { updates.push('title = ?'); params.push(title); }
    if (typeof details === 'string') { updates.push('details = ?'); params.push(details); }
    if (typeof start_time === 'string') { updates.push('start_time = ?'); params.push(start_time); }
    if (typeof end_time === 'string') { updates.push('end_time = ?'); params.push(end_time); }
    if (typeof active === 'boolean') { updates.push('active = ?'); params.push(active ? 1 : 0); }
    if (updates.length === 0) return errorResponse('no fields to update', 400);
    const sql = `UPDATE maintenance SET ${updates.join(', ')} WHERE id = ?`;
    params.push(id);
    await db.Query(sql, params);
    return successResponse({ ok: true });
  } catch (e) {
    return errorResponse('db error', 500);
  }
}

async function handleAdminAuditList(env: Env, req: Request) {
  if (!requireAdmin(req, env)) return errorResponse('未授权', 401);
  const url = new URL(req.url);
  const limitStr = url.searchParams.get('limit');
  const offsetStr = url.searchParams.get('offset');
  let limit = parseInt(String(limitStr || '200'), 10);
  let offset = parseInt(String(offsetStr || '0'), 10);
  if (!Number.isFinite(limit) || limit <= 0 || limit > 1000) limit = 200;
  if (!Number.isFinite(offset) || offset < 0) offset = 0;
  const db = new Database(env.DB);
  const res = await db.Query(`SELECT id, admin_token, action, target, reason, meta, time FROM admin_audit ORDER BY time DESC LIMIT ? OFFSET ?`, [limit, offset]);
  const rows = ((ThrowErrorIfFailed(res) as any).results as any[]) || [];
  const cntRes = await db.Query(`SELECT COUNT(1) as total FROM admin_audit`, []);
  const total = ((ThrowErrorIfFailed(cntRes) as any).results || [])[0]?.total || 0;
  return successResponse({ audits: rows, total });
}

// Admin: fetch a single BBS message by id
async function handleAdminGetBbsMessage(env: Env, req: Request) {
  if (!requireAdmin(req, env)) return errorResponse('未授权', 401);
  const url = new URL(req.url);
  const id = url.searchParams.get('id');
  if (!id) return errorResponse('id required', 400);
  const db = new Database(env.DB);
  const res = await db.Query(`SELECT id, nickname, content, mood, time FROM bbs_messages WHERE id = ?`, [id]);
  const rows = ((ThrowErrorIfFailed(res) as any).results as any[]) || [];
  if (rows.length === 0) return errorResponse('not found', 404);
  return successResponse({ message: rows[0] });
}

// Admin: delete a BBS message by id
async function handleAdminDeleteBbsMessage(env: Env, req: Request) {
  if (!requireAdmin(req, env)) return errorResponse('未授权', 401);
  const body = await readJson<{ id?: number }>(req);
  if (!body || !body.id) return errorResponse('id required', 400);
  const db = new Database(env.DB);
  // fetch the message first so we can store its content in audit meta
  const getRes = await db.Query(`SELECT id, nickname, content, mood, time FROM bbs_messages WHERE id = ?`, [body.id]);
  const getRows = ((ThrowErrorIfFailed(getRes) as any).results as any[]) || [];
  const msg = getRows[0] || null;
  await db.Query(`DELETE FROM bbs_messages WHERE id = ?`, [body.id]);
  await writeAdminAudit(db, req.headers.get('x-admin-token'), 'delete_bbs', String(body.id), null, { deleted: msg });
  return successResponse('ok');
}

// Admin: export anon_chat rows for a room (JSON)
async function handleAdminExportChat(env: Env, req: Request) {
  if (!requireAdmin(req, env)) return errorResponse('未授权', 401);
  const url = new URL(req.url);
  const room_id = url.searchParams.get('room_id');
  if (!room_id) return errorResponse('room_id required', 400);
  const db = new Database(env.DB);
  const res = await db.Query(`SELECT id, room_id, sender, recipient, message, timestamp FROM anon_chat WHERE room_id = ? ORDER BY id ASC`, [room_id]);
  const rows = ((ThrowErrorIfFailed(res) as any).results as any[]) || [];
  return successResponse({ room_id, messages: rows });
}

// Admin: force end a user's anonymous chat session (clears both sides and deletes room)
async function handleAdminForceEnd(env: Env, req: Request) {
  if (!requireAdmin(req, env)) return errorResponse('未授权', 401);
  const body = await readJson<{ username?: string; room_id?: string }>(req);
  if (!body) return errorResponse('Invalid JSON', 400);
  const { username, room_id } = body as any;
  if (!username && !room_id) return errorResponse('username or room_id required', 400);
  const db = new Database(env.DB);
  // If room_id provided, delete anon_chat by room_id and clear users with that room
  if (room_id) {
    await db.Query(`DELETE FROM anon_chat WHERE room_id = ?`, [room_id]);
    await db.Query(`UPDATE user_table SET chatting = 0, partner_username = NULL, current_room_id = NULL WHERE current_room_id = ?`, [room_id]);
    try { await bumpRoomState(db, room_id); } catch (e) {}
    return successResponse('ok');
  }
  // If username provided, try to find their current_room_id and partner
  const meRes = await db.Select('user_table', ['partner_username', 'current_room_id'], { username });
  const me = ((ThrowErrorIfFailed(meRes) as any[]) || [])[0] as any;
  const room = me?.current_room_id as string | null | undefined;
  const partner = me?.partner_username as string | null | undefined;
  const toClear = [username];
  if (partner) toClear.push(partner);
  // Delete room if known
  if (room) await db.Query(`DELETE FROM anon_chat WHERE room_id = ?`, [room]);
  try { if (room) await bumpRoomState(db, room); } catch (e) {}
  // Clear both user's flags
  const placeholders = toClear.map(() => '?').join(',');
  await db.Query(`UPDATE user_table SET chatting = 0, partner_username = NULL, current_room_id = NULL WHERE username IN (${placeholders})`, toClear);
  return successResponse('ok');
}

// 心跳上报：更新当前用户心跳，如对方超时则自动关闭并返回状态
async function handleAnonHeartbeat(env: Env, req: Request) {
  // CSRF removed: no server-side CSRF validation
  const body = await readJson<{ username: string }>(req);
  if (!body) return errorResponse("Invalid JSON", 400);
  const { username } = body;
  if (!username) return errorResponse("username is required");
  const db = new Database(env.DB);
  const TIMEOUT_MS = 45_000;
  // close if user/feature disabled mid-session
  const meRes = await db.Select("user_table", ["disabled", "disable_anon_chat", "partner_username", "current_room_id"], { username });
  const me = ((ThrowErrorIfFailed(meRes) as any[]) || [])[0] as any;
  if (!me) return errorResponse("用户不存在", 404);
  if (me.disabled || me.disable_anon_chat) {
    if (me.partner_username && me.current_room_id) {
      await db.Update("user_table", { chatting: 0, partner_username: null, current_room_id: null }, { username });
      await db.Update("user_table", { chatting: 0, partner_username: null, current_room_id: null }, { username: me.partner_username });
      await db.Query(`DELETE FROM anon_chat WHERE room_id = ?`, [me.current_room_id]);
    }
    return successResponse({ status: "closed", reason: me.disabled ? "user_disabled" : "feature_disabled" });
  }
  // 更新自己的心跳
  await db.Update("user_table", { last_heartbeat: nowIso() }, { username });
  // No Durable Object present; operate using DB only. room_meta remains null.
  const _doRoomMeta: any = null;
  // 查询会话伙伴
  const infoRes = await db.Select("user_table", ["partner_username", "current_room_id"], { username });
  const infoRow = ((ThrowErrorIfFailed(infoRes) as any[]) || [])[0] as any;
  if (!infoRow) return errorResponse("用户不存在", 404);
  const partner = infoRow?.partner_username as string | null | undefined;
  const room_id = infoRow?.current_room_id as string | null | undefined;
  if (!partner) return successResponse({ status: "idle", room_meta: _doRoomMeta });
  const otherRes = await db.Select("user_table", ["last_heartbeat"], { username: partner });
  const otherRow = ((ThrowErrorIfFailed(otherRes) as any[]) || [])[0] as any;
  const hb = otherRow?.last_heartbeat as string | null | undefined;
  const timedOut = hb && hb < isoMinusMs(TIMEOUT_MS);
  if (timedOut) {
    await db.Update("user_table", { chatting: 0, partner_username: null, current_room_id: null }, { username });
    await db.Update("user_table", { chatting: 0, partner_username: null, current_room_id: null }, { username: partner });
    if (room_id) await db.Query(`DELETE FROM anon_chat WHERE room_id = ?`, [room_id]);
    return successResponse({ status: "closed", reason: "peer_timeout", room_meta: _doRoomMeta });
  }
  return successResponse({ status: "ok", room_meta: _doRoomMeta });
}

// --- User scoring system ---
// admin get score
async function handleScoreGet(env: Env, req: Request) {
  if(!requireAdmin(req, env)) return errorResponse("未授权", 401);
  const url = new URL(req.url);
  const q = (url.searchParams.get('q') || '').trim();
  const limitStr = url.searchParams.get('limit');
  const offsetStr = url.searchParams.get('offset');
  let limit = parseInt(String(limitStr || '200'), 10);
  let offset = parseInt(String(offsetStr || '0'), 10);
  if (!Number.isFinite(limit) || limit <= 0 || limit > 1000) limit = 200;
  if (!Number.isFinite(offset) || offset < 0) offset = 0;
  const db = new Database(env.DB);
  const cols = `username,details,time`;
  let res;
  let total = 0;
  res = await db.Query(`SELECT ${cols} FROM scoring ORDER BY username ASC LIMIT ? OFFSET ?`, [limit, offset]);
  const cntRes = await db.Query(`SELECT COUNT(1) as total FROM scoring`, []);
  total = ((ThrowErrorIfFailed(cntRes) as any).results || [])[0]?.total || 0;
  const rows = ((ThrowErrorIfFailed(res) as any).results as any[]) || [];
  // Normalize `details` field: if stored as JSON like { username, details }, extract inner details for display
  const normalized = (rows || []).map((r: any) => {
    const out: any = { ...r };
    try {
      if (typeof out.details === 'string') {
        const parsed = JSON.parse(out.details);
        if (parsed && typeof parsed === 'object' && typeof parsed.details !== 'undefined') {
          out.details = parsed.details;
        }
      }
    } catch (e) {
      // leave as-is if parsing fails
    }
    return out;
  });
  return successResponse({ users: normalized, total });
  
}
// user upload score
async function handleScoreUpload(env: Env, req: Request){
  const body = await readJson<{ username?: string; details?: string }>(req);
  if (!body) return errorResponse("Invalid JSON", 400);
  const { username, details } = body as any;
  if (!details || String(details).trim().length === 0) return errorResponse("details is required", 400);
  const db = new Database(env.DB);
  await db.Insert("scoring", {
    username: username || null,
    details: String(details),
    time: nowIso()
  });
  return successResponse({ status: "ok" });
}
async function route(env: Env, req: Request): Promise<Response> {
  const url = new URL(req.url);
  const { pathname } = url;
  // Capture Origin for CORS echoing when credentials are used
  const originHeader = req.headers.get('origin') || '*';
  CURRENT_ORIGIN = originHeader;
  if (req.method === "OPTIONS") return corsPreflightResponse(req);

  if (pathname === "/api/health") return successResponse({ status: "ok", now: new Date().toISOString() });

  if (pathname === "/api/register" && req.method === "POST") return handleRegister(env, req);
  if (pathname === "/api/login" && req.method === "POST") return handleLogin(env, req);
  if (pathname === "/api/record_mood" && req.method === "POST") return handleRecordMood(env, req);
  if (pathname === "/api/user_info" && req.method === "GET") return handleGetUserInfo(env, req);
  if (pathname === "/api/change_password" && req.method === "POST") return handleChangePassword(env, req);
  if (pathname === "/api/match_anonymous_chat" && req.method === "POST") return handleMatchAnonymous(env, req);
  if (pathname === "/api/ai_chat_data" && req.method === "GET") return handleAiChatData(env, req);
  if (pathname === "/api/ai_chat_message" && req.method === "POST") return handleAiChatMessage(env, req);
  if (pathname === "/api/end_anonymous_chat" && req.method === "POST") return handleEndAnonymous(env, req);
  if (pathname === "/api/anon/send" && req.method === "POST") return handleAnonSend(env, req);
  if (pathname === "/api/anon/fetch" && req.method === "GET") return handleAnonFetch(env, req);
  if (pathname === "/api/anon/wait" && req.method === "GET") return handleAnonWait(env, req);
  if (pathname === "/api/anon/heartbeat" && req.method === "POST") return handleAnonHeartbeat(env, req);
  if (pathname === "/api/room_state" && req.method === "GET") return handleRoomState(env, req);
  if (pathname === "/api/mood_month" && req.method === "GET") return handleGetMoodMonth(env, req);
  // bbs (message board)
  if (pathname === "/api/bbs" && req.method === "GET") return handleBbsList(env, req);
  if (pathname === "/api/bbs/subscribe" && req.method === "GET") return handleBbsSubscribe(env, req);
  if (pathname === "/api/bbs" && req.method === "POST") return handleBbsPost(env, req);
  // visit tracking
  if (pathname === "/api/visit" && req.method === "POST") return handleTrackVisit(env, req);
  if (pathname === "/api/report" && req.method === "POST") return handleReport(env, req);
  // admin
  if (pathname === "/api/enc/bad_words" && req.method === "POST") return handleGetEncryptedBadWords(env, req);
  if (pathname === "/api/admin/users" && req.method === "GET") return handleAdminListUsers(env, req);
  if (pathname === "/api/admin/login" && req.method === "POST") return handleAdminLogin(env, req);
  if (pathname === "/api/admin/subadmins" && req.method === "POST") return handleAdminCreateSubadmin(env, req);
  if (pathname === "/api/admin/logout" && req.method === "POST") return handleAdminLogout(env, req);
  if (pathname === "/api/admin/reports" && req.method === "GET") return handleAdminListReports(env, req);
  if (pathname === "/api/admin/resolve_report" && req.method === "POST") return handleAdminResolveReport(env, req);
  if (pathname === "/api/admin/set_disabled" && req.method === "POST") return handleAdminSetDisabled(env, req);
  if (pathname === "/api/admin/reset_password" && req.method === "POST") return handleAdminResetPassword(env, req);
  if (pathname === "/api/admin/words_add" && req.method === "POST") return handleAdminWordsAdd(env, req);
  if (pathname === "/api/admin/set_flags" && req.method === "POST") return handleAdminSetFlags(env, req);
  if (pathname === "/api/admin/settings" && req.method === "GET") return handleAdminGetSettings(env, req);
  if (pathname === "/api/admin/settings" && req.method === "PUT") return handleAdminSetSettings(env, req);
  if (pathname === "/api/admin/refresh_words" && req.method === "POST") return handleAdminRefreshWords(env, req);
  if (pathname === "/api/admin/visits" && req.method === "GET") return handleAdminListVisits(env, req);
  if (pathname === "/api/admin/force_end" && req.method === "POST") return handleAdminForceEnd(env, req);
  if (pathname === "/api/admin/analytics" && req.method === "GET") return handleAdminAnalytics(env, req);
  if (pathname === "/api/admin/audit" && req.method === "GET") return handleAdminAuditList(env, req);
  if (pathname === "/api/admin/bbs" && req.method === "GET") return handleAdminGetBbsMessage(env, req);
  if (pathname === "/api/admin/bbs" && req.method === "DELETE") return handleAdminDeleteBbsMessage(env, req);
  if (pathname === "/api/admin/ai_test" && req.method === "POST") return handleAdminAiTest(env, req);
  if (pathname === "/api/admin/groups" && req.method === "GET") return handleAdminListGroups(env, req);
  if (pathname === "/api/admin/set_group" && req.method === "POST") return handleAdminSetGroup(env, req);
  if (pathname === "/api/admin/create_group" && req.method === "POST") return handleAdminCreateGroup(env, req);
  if (pathname === "/api/admin/group_analysis" && req.method === "GET") return handleAdminGroupAnalysis(env, req);
  if (pathname === "/api/whoami" && req.method === "GET") return handleWhoami(env, req);
  if (pathname === "/api/logout" && req.method === "POST") return handleLogout(env, req);

  // Health endpoints
  if (pathname === "/api/_health/db" && req.method === "GET") return handleHealthDb(env, req);
  if (pathname === "/api/_health/public" && req.method === "GET") return handlePublicApiHealth(env, req);
  if (pathname === "/api/maintenance" && req.method === "GET") return handlePublicMaintenanceList(env, req);

  // Admin maintenance management
  if (pathname === "/api/admin/maintenance" && req.method === "POST") return handleAdminCreateMaintenance(env, req);
  if (pathname === "/api/admin/maintenance" && req.method === "DELETE") return handleAdminDeleteMaintenance(env, req);
  if (pathname === "/api/admin/maintenance" && req.method === "PUT") return handleAdminUpdateMaintenance(env, req);

  // Score System — accept with or without trailing slash
  if ((pathname === "/api/score" || pathname === "/api/score/") && req.method === "GET") return handleScoreGet(env, req);
  if ((pathname === "/api/score" || pathname === "/api/score/") && req.method === "POST") return handleScoreUpload(env, req);
  return errorResponse("Not Found", 404);
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    try {
      return await route(env, req);
    } catch (e) {
      return errorResponse((e as Error).message || "Internal Error", 500);
    }
  },
  // 每日定时清理：在北京时间 00:00（UTC 16:00）删除“昨天”的匿名聊天记录
  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext) {
    const db = new Database(env.DB);
    // 计算北京时间“昨天”的日期字符串 YYYY-MM-DD
    const now = new Date();
    const chinaNow = new Date(now.getTime() + 8 * 60 * 60 * 1000);
    const y = new Date(chinaNow.getTime() - 24 * 60 * 60 * 1000);
    const yyyy = y.getUTCFullYear();
    const mm = String(y.getUTCMonth() + 1).padStart(2, "0");
    const dd = String(y.getUTCDate()).padStart(2, "0");
    const yesterdayChina = `${yyyy}-${mm}-${dd}`;
    // 使用 SQLite 时间函数，将 timestamp 偏移 +8 小时，再取 date 与目标日期相等的全部删除
    await db.Query(`DELETE FROM anon_chat WHERE date(timestamp, '+8 hours') = ?`, [yesterdayChina]);
  },
};
