/**
 * 拾光 · 校园失物招领 —— 后端服务（Supabase 版）
 * ============================================================
 * 账号系统：Supabase Auth（手机号 + 密码，内部映射为 <手机号>@phone.shiguang.local，
 *           通过 admin API 创建用户并直接标记已确认 —— 无需短信 / 邮箱验证）
 * 数据库：  Supabase Postgres（profiles / posts / comments / notifications / claims，
 *           经 PostgREST 访问，服务端密钥绕过 RLS）
 * 图片：    Supabase Storage（public bucket "uploads"）
 *
 * 启动：node server.js   （需环境变量 SUPABASE_URL / SUPABASE_SECRET_KEY）
 * 端口：process.env.PORT || 3000
 *
 * 双角色体系：
 *   - admin 管理员：用户管理（封禁/解封/授权）、删任意帖子评论、平台统计、处理认领
 *   - user  普通用户：发帖/编辑自己的帖子、评论、点赞、发起认领
 *
 * 鉴权：直接透传 Supabase 的 accessToken / refreshToken，
 *   - accessToken  1 小时，请求头 Authorization: Bearer <token>
 *   - refreshToken 过期后前端拿它调 POST /api/auth/refresh 静默续期
 *   - 过期返回 code=40102（触发前端刷新重放），无效返回 40101（触发跳登录）
 *
 * 响应信封：{ code, message, data, meta? }，成功 code 恒为 0
 * 首次启动自动播种演示数据（4 个手机号演示账号 + 10 条帖子 + 评论/认领/通知）
 */

import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 3000);

/* ============================================================
 * Supabase 接入配置
 * ============================================================ */

const SB_URL = (process.env.SUPABASE_URL || '').replace(/\/+$/, '');
const SB_KEY = process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_SERVICE_ROLE || '';

if (!SB_URL || !SB_KEY) {
  console.error('[fatal] 缺少环境变量 SUPABASE_URL / SUPABASE_SECRET_KEY，无法启动。');
  console.error('        本地开发可在项目根目录创建 .env 或在启动命令前设置这两个变量。');
  process.exit(1);
}

/** Supabase REST/Auth/Storage 统一请求封装 */
async function sbFetch(url, { method = 'GET', body, headers = {}, raw = false } = {}) {
  const resp = await fetch(url, {
    method,
    headers: {
      apikey: SB_KEY,
      Authorization: `Bearer ${SB_KEY}`,
      'Content-Type': 'application/json',
      ...headers,
    },
    body: body === undefined ? undefined : (raw ? body : JSON.stringify(body)),
  });
  if (!resp.ok) {
    const text = await resp.text().catch(() => '');
    let msg = text;
    try { msg = JSON.parse(text).message || text; } catch {}
    const err = new Error(msg || `Supabase ${resp.status}`);
    err.status = resp.status;
    err.body = text;
    throw err;
  }
  return resp;
}

/** PostgREST 表查询：sbTable('posts', '?select=*&limit=10') */
function tableUrl(table, query = '') {
  return `${SB_URL}/rest/v1/${table}${query.startsWith('?') ? query : `?${query}`}`;
}
async function sbSelect(table, query) {
  const r = await sbFetch(tableUrl(table, query));
  return r.json();
}
async function sbInsert(table, rows) {
  const r = await sbFetch(tableUrl(table, '?select=*'), {
    method: 'POST',
    headers: { Prefer: 'return=representation' },
    body: Array.isArray(rows) ? rows : [rows],
  });
  return r.json();
}
/** PostgREST 过滤值自动补操作符：{ id: 'p_1' } -> id=eq.p_1；已带操作符的原样保留 */
function withOps(match) {
  return Object.fromEntries(Object.entries(match).map(([k, v]) =>
    [/^(eq|neq|gt|gte|lt|lte|like|ilike|is|in|contains|contained|or)\./.test(String(v)) ? v : `eq.${v}`].map((nv) => [k, nv])[0]
  ));
}
async function sbUpdate(table, match, patch) {
  const qs = new URLSearchParams(withOps(match)).toString();
  const r = await sbFetch(tableUrl(table, `?${qs}&select=*`), {
    method: 'PATCH',
    headers: { Prefer: 'return=representation' },
    body: patch,
  });
  return r.json();
}
async function sbDelete(table, match) {
  const qs = new URLSearchParams(withOps(match)).toString();
  await sbFetch(tableUrl(table, `?${qs}`), { method: 'DELETE' });
}
/** 精确计数（Prefer: count=exact + limit=0，读 content-range 的总数段） */
async function sbCount(table, match = {}) {
  const qs = new URLSearchParams(withOps(match)).toString();
  const r = await sbFetch(tableUrl(table, `?${qs}&limit=0`), {
    headers: { Prefer: 'count=exact' },
  });
  const range = r.headers.get('content-range') || '*/0';
  return Number(range.split('/')[1]) || 0;
}

/* ---------- GoTrue（Supabase Auth） ---------- */

const phoneEmail = (phone) => `${phone}@phone.shiguang.local`;

/** admin 创建用户并直接标记已确认（免邮箱/短信验证） */
async function authCreateUser(phone, password, nickname, studentId, role) {
  const r = await sbFetch(`${SB_URL}/auth/v1/admin/users`, {
    method: 'POST',
    body: {
      email: phoneEmail(phone),
      password,
      email_confirm: true,
      user_metadata: { phone, nickname, studentId: studentId || '', role: role || 'user' },
    },
  });
  return r.json(); // { id, email, ... }
}
async function authDeleteUser(id) {
  await sbFetch(`${SB_URL}/auth/v1/admin/users/${id}`, { method: 'DELETE' }).catch(() => {});
}
/** 密码登录，返回 { session } 或 null（凭据错误） */
async function authLogin(phone, password) {
  const r = await fetch(`${SB_URL}/auth/v1/token?grant_type=password`, {
    method: 'POST',
    headers: { apikey: SB_KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: phoneEmail(phone), password }),
  });
  if (!r.ok) return null;
  return r.json(); // { access_token, refresh_token, user, ... }
}
/** 刷新令牌，返回新 session 或 null */
async function authRefresh(refreshToken) {
  const r = await fetch(`${SB_URL}/auth/v1/token?grant_type=refresh_token`, {
    method: 'POST',
    headers: { apikey: SB_KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify({ refresh_token: refreshToken }),
  });
  if (!r.ok) return null;
  return r.json();
}
/** 校验 accessToken，返回 auth 用户 { id } 或 { expired } */
async function authVerify(token) {
  const r = await fetch(`${SB_URL}/auth/v1/user`, {
    headers: { apikey: SB_KEY, Authorization: `Bearer ${token}` },
  }).catch(() => null);
  if (!r || !r.ok) {
    const text = r ? await r.text().catch(() => '') : '';
    return /expired/i.test(text) ? { expired: true } : null;
  }
  return r.json();
}

/* ============================================================
 * 工具函数
 * ============================================================ */

const uid = (prefix) => `${prefix}_${Date.now().toString(36)}_${crypto.randomBytes(4).toString('hex')}`;
const nowISO = () => new Date().toISOString();

/* ============================================================
 * 行 <-> 业务对象 映射（数据库 snake_case -> 前端驼峰契约）
 * ============================================================ */

const rowToUser = (p) => ({
  id: p.id, username: p.phone, phone: p.phone, nickname: p.nickname,
  role: p.role, status: p.status, studentId: p.student_id || '', createdAt: p.created_at,
});
const PUBLIC_USER = (u) => ({
  id: u.id, username: u.username, phone: u.phone, nickname: u.nickname,
  role: u.role, status: u.status, studentId: u.studentId || '', createdAt: u.createdAt,
});
const rowToPost = (r) => ({
  id: r.id, type: r.type, title: r.title, description: r.description,
  category: r.category, location: r.location, locationDetail: r.location_detail,
  eventTime: r.event_time, contact: r.contact, images: r.images || [], tags: r.tags || [],
  status: r.status, authorId: r.author_id, authorName: r.author_name,
  likedBy: r.liked_by || [], viewCount: r.view_count || 0,
  createdAt: r.created_at, updatedAt: r.updated_at, resolvedAt: r.resolved_at,
  lng: r.lng ?? null, lat: r.lat ?? null,
});

/** 经纬度合法值：有限数字且在合理范围内，否则 null */
const toLngLat = (v) => (Number.isFinite(+v) && Math.abs(+v) <= 180 ? +v : null);

/** 按 id 查用户资料；joinBanned 判断在调用处做 */
async function getProfile(id) {
  const rows = await sbSelect('profiles', new URLSearchParams({ id: `eq.${id}`, select: '*' }).toString());
  return rows[0] ? rowToUser(rows[0]) : null;
}

/** 联系方式脱敏：未登录只能看到打码的手机号 / "登录后查看" */
function maskContact(post, me){
  if (!post.contact) return null;
  if (me) return { ...post.contact, masked: false };
  const { method, value } = post.contact;
  return {
    method,
    value: method === 'phone' ? String(value).replace(/^(\d{3})\d{4}(\d{4})$/, '$1****$2') : '登录后查看',
    masked: true,
  };
}

/* ============================================================
 * 鉴权：请求 token -> Supabase 校验 -> profiles 资料装配
 * ============================================================ */

/** 收集请求中所有可能的 token 来源（兼容网关合并/改名/查询串降级） */
function extractTokens(req) {
  const list = [];
  const push = (v) => {
    v = String(v || '').trim().replace(/^Bearer\s+/i, '');
    if (v && !list.includes(v)) list.push(v);
  };
  push(req.headers['authorization']);
  for (const k of ['x-authorization', 'x-access-token', 'x-token']) push(req.headers[k]);
  try {
    const qs = new URL(req.url, 'http://localhost').searchParams;
    push(qs.get('_t'));
    push(qs.get('token'));
  } catch {}
  const auth = String(req.headers['authorization'] || '');
  for (const m of auth.matchAll(/Bearer\s+([^\s,]+)/gi)) push(m[1]);
  return list;
}

/** token -> 用户 的短缓存（避免每个请求都打一次 Supabase） */
const tokenCache = new Map(); // token -> { user, exp }
const TOKEN_CACHE_TTL = 30 * 1000;

async function getAuth(req) {
  let expired = false;
  for (const token of extractTokens(req)) {
    if (token.length > 1000) continue;
    const hit = tokenCache.get(token);
    if (hit && hit.exp > Date.now()) return { user: hit.user };
    const authUser = await authVerify(token);
    if (!authUser) { expired = expired || false; continue; }
    if (authUser.expired) { expired = true; continue; }
    const profile = await getProfile(authUser.id);
    if (!profile) continue;
    if (tokenCache.size > 800) tokenCache.clear();
    tokenCache.set(token, { user: profile, exp: Date.now() + TOKEN_CACHE_TTL });
    return { user: profile };
  }
  return { error: expired ? 'expired' : 'invalid' };
}

/** 需要登录的统一入口：校验 token + 封禁状态 */
async function requireAuth(req, res) {
  const auth = await getAuth(req);
  if (auth.error === 'expired') {
    fail(res, ...ERR.TOKEN_EXPIRED);
    return null;
  }
  if (auth.error || !auth.user) {
    fail(res, ...ERR.UNAUTHORIZED);
    return null;
  }
  if (auth.user.status === 'banned') {
    fail(res, ...ERR.BANNED);
    return null;
  }
  return auth.user;
}

async function requireAdmin(req, res) {
  const user = await requireAuth(req, res);
  if (!user) return null;
  if (user.role !== 'admin') {
    fail(res, ...ERR.FORBIDDEN);
    return null;
  }
  return user;
}

async function notify(userId, type, content, postId = null) {
  await sbInsert('notifications', {
    id: uid('n'), user_id: userId, type, content, post_id: postId, read: false, created_at: nowISO(),
  }).catch((e) => console.error('[notify]', e.message));
}

/* ============================================================
 * HTTP 基础设施
 * ============================================================ */

function send(res, status, code, message, data = null, meta = undefined) {
  const body = { code, message, data };
  if (meta !== undefined) body.meta = meta;
  const text = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, x-authorization, x-access-token, x-token',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
  });
  res.end(text);
}
const ok = (res, data = null, meta) => send(res, 200, 0, 'ok', data, meta);
const fail = (res, status, code, message, data) => send(res, status, code, message, data);

const ERR = {
  BAD_PARAM: [400, 40001, '参数错误'],
  UNAUTHORIZED: [401, 40101, '请先登录'],
  TOKEN_EXPIRED: [401, 40102, '登录已过期'],
  FORBIDDEN: [403, 40301, '没有权限'],
  BANNED: [403, 40302, '账号已被封禁，请联系管理员'],
  NOT_FOUND: [404, 40401, '资源不存在'],
};

function readBody(req) {
  return new Promise((resolve) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > 8 * 1024 * 1024) { req.destroy(); resolve(null); return; } // 上限 8MB（图片 base64）
      chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch { resolve(null); }
    });
    req.on('error', () => resolve(null));
  });
}

/* ============================================================
 * 路由表
 * ============================================================ */

const routes = [];
function route(method, pattern, handler) {
  const keys = [];
  const regex = new RegExp('^' + pattern.replace(/:[a-zA-Z]+/g, (m) => {
    keys.push(m.slice(1));
    return '([^/]+)';
  }) + '$');
  routes.push({ method, regex, keys, handler });
}

/* ---------- 认证 ---------- */

route('POST', '/api/auth/register', async (req, res, params, query, body) => {
  const { phone, password, nickname, studentId } = body || {};
  if (!phone || !/^1\d{10}$/.test(String(phone))) {
    return fail(res, 400, 40001, '请输入 11 位手机号');
  }
  // 6-20 位（演示环境放宽：纯数字密码 123456 也可用）
  if (!password || !/^\S{6,20}$/.test(String(password))) {
    return fail(res, 400, 40001, '密码需 6-20 位');
  }
  if (studentId && !/^\d{6,20}$/.test(String(studentId))) {
    return fail(res, 400, 40001, '学号为 6-20 位数字');
  }
  // 手机号唯一性：auth.users 里 pseudo email 唯一，直接尝试创建
  let authUser;
  try {
    authUser = await authCreateUser(String(phone), String(password), String(nickname || `用户${phone.slice(-4)}`), studentId, 'user');
  } catch (e) {
    if (/already|registered|duplicate|unique/i.test(e.message + (e.body || ''))) {
      return fail(res, 400, 40001, '该手机号已注册，请直接登录');
    }
    console.error('[register]', e.message);
    return fail(res, 500, 50001, '注册失败，请稍后再试');
  }
  await sbInsert('profiles', {
    id: authUser.id, phone: String(phone),
    nickname: String(nickname || `用户${phone.slice(-4)}`),
    role: 'user', status: 'active', student_id: String(studentId || ''), created_at: nowISO(),
    client_id: String(body?.clientId || '').slice(0, 64),
  });
  // 注册完成直接登录，把 Supabase 会话令牌发给前端
  const session = await authLogin(String(phone), String(password));
  const profile = await getProfile(authUser.id);
  ok(res, {
    user: PUBLIC_USER(profile),
    accessToken: session?.access_token,
    refreshToken: session?.refresh_token,
  });
});

route('POST', '/api/auth/login', async (req, res, params, query, body) => {
  const phone = String(body?.phone || body?.username || '').trim();
  const password = String(body?.password || '');
  if (!phone || !password) return fail(res, 400, 40001, '请输入手机号和密码');
  const session = await authLogin(phone, password);
  if (!session) return fail(res, 400, 40001, '手机号或密码错误');
  const profile = await getProfile(session.user.id);
  if (!profile) return fail(res, 401, 40101, '账号数据异常，请联系管理员');
  if (profile.status === 'banned') {
    return fail(res, 403, 40302, '账号已被封禁，请联系管理员');
  }
  ok(res, {
    user: PUBLIC_USER(profile),
    accessToken: session.access_token,
    refreshToken: session.refresh_token,
  });
});

route('POST', '/api/auth/refresh', async (req, res, params, query, body) => {
  const refreshToken = String(body?.refreshToken || '');
  if (!refreshToken) return fail(res, ...ERR.UNAUTHORIZED);
  const session = await authRefresh(refreshToken);
  if (!session) return fail(res, ...ERR.UNAUTHORIZED);
  ok(res, {
    accessToken: session.access_token,
    refreshToken: session.refresh_token,
  });
});

route('GET', '/api/auth/me', async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  ok(res, { user: PUBLIC_USER(user) });
});

/* 诊断端点：查看反代之后服务器实际收到的鉴权凭据 */
route('GET', '/api/debug-headers', (req, res) => {
  let queryToken = false;
  try {
    const qs = new URL(req.url, 'http://localhost').searchParams;
    queryToken = !!(qs.get('_t') || qs.get('token'));
  } catch {}
  ok(res, {
    hasAuth: !!req.headers['authorization'],
    authPreview: String(req.headers['authorization'] || '').slice(0, 40),
    fallbackAuth: {
      'x-authorization': !!req.headers['x-authorization'],
      'x-access-token': !!req.headers['x-access-token'],
      'x-token': !!req.headers['x-token'],
    },
    queryToken,
    headerNames: Object.keys(req.headers),
  });
});

/* ---------- 帖子 ---------- */

/** 列表：公开可读；支持 type/status/category/keyword 筛选 + 分页 */
route('GET', '/api/posts', async (req, res, params, query) => {
  const page = Math.max(1, Number(query.get('page')) || 1);
  const pageSize = Math.min(50, Math.max(1, Number(query.get('pageSize')) || 10));
  const keyword = (query.get('keyword') || '').trim();
  const type = query.get('type');
  const status = query.get('status');
  const category = query.get('category');

  const qs = new URLSearchParams({ select: '*', order: 'created_at.desc' });
  if (type === 'lost' || type === 'found') qs.set('type', `eq.${type}`);
  if (status === 'open' || status === 'resolved') qs.set('status', `eq.${status}`);
  if (category) qs.set('category', `eq.${category}`);
  if (keyword) {
    const k = keyword.replace(/[,()]/g, ' ').trim();
    qs.set('or', `(title.ilike.*${k}*,description.ilike.*${k}*,location.ilike.*${k}*)`);
  }
  qs.set('limit', String(pageSize));
  qs.set('offset', String((page - 1) * pageSize));

  const rows = await sbSelect('posts', `?${qs}`);
  const total = rows.length === pageSize || page > 1
    ? await sbCount('posts', Object.fromEntries([...qs.entries()].filter(([k]) => ['type','status','category','or'].includes(k))))
    : rows.length;

  const auth = await getAuth(req);
  const me = auth.user || null;
  // 批量取评论数
  const ids = rows.map((r) => r.id);
  let commentCounts = {};
  if (ids.length) {
    const cs = await sbSelect('comments', `?post_id=in.(${ids.join(',')})&select=post_id`);
    for (const c of cs) commentCounts[c.post_id] = (commentCounts[c.post_id] || 0) + 1;
  }
  ok(res, {
    list: rows.map((r) => {
      const p = rowToPost(r);
      return {
        ...p, likedBy: undefined,
        likeCount: p.likedBy.length,
        commentCount: commentCounts[p.id] || 0,
        isLiked: me ? p.likedBy.includes(me.id) : false,
        isMine: me ? p.authorId === me.id : false,
      };
    }),
  }, { page, pageSize, total });
});

/** 详情：公开可读，浏览量 +1 */
route('GET', '/api/posts/:id', async (req, res, params) => {
  const rows = await sbSelect('posts', new URLSearchParams({ id: `eq.${params.id}`, select: '*' }).toString());
  if (!rows[0]) return fail(res, ...ERR.NOT_FOUND);
  sbUpdate('posts', { id: params.id }, { view_count: (rows[0].view_count || 0) + 1 }).catch(() => {});
  const auth = await getAuth(req);
  const me = auth.user || null;
  const post = rowToPost(rows[0]);
  const commentCount = await sbCount('comments', { post_id: `eq.${post.id}` });
  ok(res, {
    ...post, likedBy: undefined,
    likeCount: post.likedBy.length,
    commentCount,
    contact: maskContact(post, me),
    isLiked: me ? post.likedBy.includes(me.id) : false,
    isMine: me ? post.authorId === me.id : false,
  });
});

/** 相似推荐：类型相反、状态未解决，分类/关键词/地点重合度打分取前 5 */
route('GET', '/api/posts/:id/matches', async (req, res, params) => {
  const rows = await sbSelect('posts', new URLSearchParams({ id: `eq.${params.id}`, select: '*' }).toString());
  if (!rows[0]) return fail(res, ...ERR.NOT_FOUND);
  const post = rowToPost(rows[0]);
  const opposite = post.type === 'lost' ? 'found' : 'lost';
  const candidates = (await sbSelect('posts', `?type=eq.${opposite}&status=eq.open&select=*`)).map(rowToPost);
  const words = (post.title + post.description).replace(/[（）()【】\s，。、：:？！?!,.]/g, ' ').split(' ').filter((w) => w.length >= 2);
  const scored = candidates
    .filter((p) => p.id !== post.id)
    .map((p) => {
      let score = 0;
      if (p.category === post.category) score += 3;
      const hay = p.title + p.description;
      for (const w of words) if (hay.includes(w)) score += 1;
      if (p.location && p.location === post.location) score += 2;
      return { post: p, score };
    })
    .filter((x) => x.score >= 2)
    .sort((a, b) => b.score - a.score)
    .slice(0, 5);
  const ids = scored.map((x) => x.post.id);
  const cs = ids.length ? await sbSelect('comments', `?post_id=in.(${ids.join(',')})&select=post_id`) : [];
  const commentCounts = {};
  for (const c of cs) commentCounts[c.post_id] = (commentCounts[c.post_id] || 0) + 1;
  ok(res, scored.map((x) => ({
    ...x.post, likedBy: undefined,
    likeCount: x.post.likedBy.length,
    commentCount: commentCounts[x.post.id] || 0,
    score: x.score,
  })));
});

/** 图片上传：dataURL(base64) -> Supabase Storage public bucket "uploads" */
route('POST', '/api/upload', async (req, res, params, query, body) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  const dataURL = String(body?.image || '');
  const m = dataURL.match(/^data:image\/(png|jpe?g|webp);base64,(.+)$/);
  if (!m) return fail(res, 400, 40001, '仅支持 png/jpg/webp 图片');
  const ext = m[1] === 'jpeg' ? 'jpg' : m[1];
  const buf = Buffer.from(m[2], 'base64');
  if (buf.length > 5 * 1024 * 1024) return fail(res, 400, 40001, '单张图片不能超过 5MB');
  const name = `up_${Date.now().toString(36)}_${crypto.randomBytes(5).toString('hex')}.${ext}`;
  try {
    await sbFetch(`${SB_URL}/storage/v1/object/uploads/${name}`, {
      method: 'POST',
      headers: { 'Content-Type': `image/${ext === 'jpg' ? 'jpeg' : ext}` },
      body: buf,
      raw: true,
    });
  } catch (e) {
    console.error('[upload]', e.message);
    return fail(res, 500, 50001, '图片上传失败，请稍后再试');
  }
  ok(res, { url: `${SB_URL}/storage/v1/object/public/uploads/${name}` });
});

route('POST', '/api/posts', async (req, res, params, query, body) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  const { type, title, description, category, location, locationDetail, eventTime, contact, images, tags } = body || {};
  if (type !== 'lost' && type !== 'found') return fail(res, 400, 40001, 'type 必须是 lost 或 found');
  if (!title || !String(title).trim()) return fail(res, 400, 40001, '请输入标题');
  if (String(title).length > 30) return fail(res, 400, 40001, '标题最多 30 个字');
  if (!description || !String(description).trim()) return fail(res, 400, 40001, '请输入描述');
  if (String(description).length > 500) return fail(res, 400, 40001, '描述最多 500 个字');
  if (!category) return fail(res, 400, 40001, '请选择分类');
  if (contact && contact.value && contact.method === 'phone' && !/^1\d{10}$/.test(String(contact.value))) {
    return fail(res, 400, 40001, '请输入 11 位手机号');
  }
  const imgs = Array.isArray(images) ? images.slice(0, 3) : [];

  const t = nowISO();
  const row = {
    id: uid('p'),
    type, title: String(title).trim(),
    description: String(description).trim(),
    category,
    location: location || '',
    location_detail: locationDetail || '',
    event_time: eventTime || t,
    contact: contact && contact.value ? { method: contact.method === 'wechat' ? 'wechat' : 'phone', value: String(contact.value) } : null,
    images: imgs,
    tags: Array.isArray(tags) ? tags.slice(0, 5).map(String) : [],
    status: 'open', author_id: user.id, author_name: user.nickname,
    liked_by: [], view_count: 0,
    lng: toLngLat(body.lng), lat: toLngLat(body.lat),
    created_at: t, updated_at: t, resolved_at: null,
  };
  const saved = await sbInsert('posts', row);
  ok(res, rowToPost(Array.isArray(saved) ? saved[0] : saved));
});

/** 编辑：作者本人或管理员 */
route('PUT', '/api/posts/:id', async (req, res, params, query, body) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  const rows = await sbSelect('posts', new URLSearchParams({ id: `eq.${params.id}`, select: '*' }).toString());
  if (!rows[0]) return fail(res, ...ERR.NOT_FOUND);
  const post = rowToPost(rows[0]);
  if (post.authorId !== user.id && user.role !== 'admin') return fail(res, ...ERR.FORBIDDEN);

  const patch = { updated_at: nowISO() };
  const map = {
    title: 'title', description: 'description', category: 'category',
    location: 'location', locationDetail: 'location_detail', eventTime: 'event_time',
    contact: 'contact', type: 'type', status: 'status', tags: 'tags', images: 'images',
  };
  for (const [from, to] of Object.entries(map)) {
    if (body && body[from] !== undefined) patch[to] = body[from];
  }
  if (body && body.lng !== undefined) patch.lng = toLngLat(body.lng);
  if (body && body.lat !== undefined) patch.lat = toLngLat(body.lat);
  if (patch.status === 'resolved') patch.resolved_at = nowISO();
  const updated = await sbUpdate('posts', { id: params.id }, patch);
  ok(res, rowToPost(Array.isArray(updated) ? updated[0] : updated));
});

/** 删除：作者本人或管理员；管理员删除会给作者发通知 */
route('DELETE', '/api/posts/:id', async (req, res, params) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  const rows = await sbSelect('posts', new URLSearchParams({ id: `eq.${params.id}`, select: '*' }).toString());
  if (!rows[0]) return fail(res, ...ERR.NOT_FOUND);
  const post = rowToPost(rows[0]);
  if (post.authorId !== user.id && user.role !== 'admin') return fail(res, ...ERR.FORBIDDEN);

  await sbDelete('posts', { id: post.id }); // comments/claims 由 FK 级联删除
  await sbDelete('notifications', { post_id: `eq.${post.id}` }).catch(() => {});
  if (user.role === 'admin' && post.authorId !== user.id) {
    await notify(post.authorId, 'admin', `管理员删除了你的帖子「${post.title}」`);
  }
  ok(res, { id: post.id });
});

/** 点赞/取消点赞（toggle） */
route('POST', '/api/posts/:id/like', async (req, res, params) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  const rows = await sbSelect('posts', new URLSearchParams({ id: `eq.${params.id}`, select: '*' }).toString());
  if (!rows[0]) return fail(res, ...ERR.NOT_FOUND);
  const post = rowToPost(rows[0]);
  const i = post.likedBy.indexOf(user.id);
  let isLiked;
  if (i >= 0) { post.likedBy.splice(i, 1); isLiked = false; }
  else {
    post.likedBy.push(user.id); isLiked = true;
    if (post.authorId !== user.id) {
      await notify(post.authorId, 'like', `${user.nickname} 赞了你的帖子「${post.title}」`, post.id);
    }
  }
  await sbUpdate('posts', { id: post.id }, { liked_by: post.likedBy });
  ok(res, { isLiked, likeCount: post.likedBy.length });
});

/* ---------- 评论 ---------- */

route('GET', '/api/posts/:id/comments', async (req, res, params) => {
  const rows = await sbSelect('posts', new URLSearchParams({ id: `eq.${params.id}`, select: 'id' }).toString());
  if (!rows[0]) return fail(res, ...ERR.NOT_FOUND);
  const list = await sbSelect('comments', `?post_id=eq.${params.id}&select=*&order=created_at.asc`);
  ok(res, list.map((c) => ({
    id: c.id, postId: c.post_id, authorId: c.author_id, authorName: c.author_name,
    content: c.content, replyTo: c.reply_to || null, createdAt: c.created_at,
  })));
});

route('POST', '/api/posts/:id/comments', async (req, res, params, query, body) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  const rows = await sbSelect('posts', new URLSearchParams({ id: `eq.${params.id}`, select: '*' }).toString());
  if (!rows[0]) return fail(res, ...ERR.NOT_FOUND);
  const post = rowToPost(rows[0]);
  const content = String(body?.content || '').trim();
  if (!content) return fail(res, 400, 40001, '请输入评论内容');
  if (content.length > 500) return fail(res, 400, 40001, '评论不能超过 500 字');

  // 回复：可携带被回复的评论 id 与作者名，前端展示「回复 @某人」
  let replyTo = null;
  if (body?.replyTo) {
    const targets = await sbSelect('comments', new URLSearchParams({ id: `eq.${body.replyTo.id}`, post_id: `eq.${post.id}`, select: '*' }).toString());
    if (targets[0]) replyTo = { id: targets[0].id, name: targets[0].author_name };
  }
  const row = {
    id: uid('c'), post_id: post.id,
    author_id: user.id, author_name: user.nickname,
    content, reply_to: replyTo, created_at: nowISO(),
  };
  const saved = await sbInsert('comments', row);
  const comment = {
    id: row.id, postId: row.post_id, authorId: row.author_id, authorName: row.author_name,
    content: row.content, replyTo, createdAt: row.created_at,
  };
  if (post.authorId !== user.id) {
    await notify(post.authorId, 'comment', `${user.nickname} 评论了你的帖子「${post.title}」`, post.id);
  } else if (replyTo && replyTo.name !== user.nickname) {
    const target = await sbSelect('comments', new URLSearchParams({ id: `eq.${replyTo.id}`, select: 'author_id' }).toString());
    if (target[0] && target[0].author_id !== user.id) {
      await notify(target[0].author_id, 'reply', `${user.nickname} 回复了你的评论`, post.id);
    }
  }
  ok(res, comment);
});

route('DELETE', '/api/comments/:id', async (req, res, params) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  const rows = await sbSelect('comments', new URLSearchParams({ id: `eq.${params.id}`, select: '*' }).toString());
  if (!rows[0]) return fail(res, ...ERR.NOT_FOUND);
  if (rows[0].author_id !== user.id && user.role !== 'admin') return fail(res, ...ERR.FORBIDDEN);
  await sbDelete('comments', { id: params.id });
  ok(res, { id: params.id });
});

/* ---------- 认领 ---------- */

/** 发起认领：不能认领自己的帖子，一个帖子一人只能有一笔待处理认领 */
route('POST', '/api/posts/:id/claims', async (req, res, params, query, body) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  const rows = await sbSelect('posts', new URLSearchParams({ id: `eq.${params.id}`, select: '*' }).toString());
  if (!rows[0]) return fail(res, ...ERR.NOT_FOUND);
  const post = rowToPost(rows[0]);
  if (post.status !== 'open') return fail(res, 400, 40001, '该帖子已完成认领');
  if (post.authorId === user.id) return fail(res, 400, 40001, '不能认领自己发布的帖子');
  const answer = String(body?.answer || '').trim();
  if (!answer) return fail(res, 400, 40001, '请填写物品特征以便核实');

  const dup = await sbSelect('claims', `?post_id=eq.${post.id}&claimant_id=eq.${user.id}&status=eq.pending&select=id`);
  if (dup.length) return fail(res, 400, 40001, '你已提交过认领申请，等待对方处理');

  const row = {
    id: uid('cl'), post_id: post.id, claimant_id: user.id, claimant_name: user.nickname,
    answer, status: 'pending', created_at: nowISO(),
  };
  await sbInsert('claims', row);
  await notify(post.authorId, 'claim', `${user.nickname} 申请认领你的帖子「${post.title}」，请核实处理`, post.id);
  ok(res, {
    id: row.id, postId: row.post_id, claimantId: row.claimant_id, claimantName: row.claimant_name,
    answer, status: 'pending', createdAt: row.created_at,
  });
});

/** 我相关认领：received = 我作为发布者收到的；sent = 我发起的 */
route('GET', '/api/claims/mine', async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  const myPosts = await sbSelect('posts', `?author_id=eq.${user.id}&select=id,title,type`);
  const myPostIds = myPosts.map((p) => p.id);
  const all = await sbSelect('claims', '?select=*&order=created_at.desc');
  const postMap = new Map(myPosts.map((p) => [p.id, p]));
  const withPost = (c) => {
    const p = postMap.get(c.post_id);
    return {
      id: c.id, postId: c.post_id, claimantId: c.claimant_id, claimantName: c.claimant_name,
      answer: c.answer, status: c.status, createdAt: c.created_at, resolvedAt: c.resolved_at,
      postTitle: p?.title || '(已删除)', postType: p?.type,
    };
  };
  ok(res, {
    received: all.filter((c) => myPostIds.includes(c.post_id)).map(withPost),
    sent: all.filter((c) => c.claimant_id === user.id).map(withPost),
  });
});

/** 处理认领：approve / reject，仅发布者或管理员 */
route('POST', '/api/claims/:id/resolve', async (req, res, params, query, body) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  const rows = await sbSelect('claims', new URLSearchParams({ id: `eq.${params.id}`, select: '*' }).toString());
  if (!rows[0]) return fail(res, ...ERR.NOT_FOUND);
  const claim = rows[0];
  const posts0 = await sbSelect('posts', new URLSearchParams({ id: `eq.${claim.post_id}`, select: '*' }).toString());
  if (!posts0[0]) return fail(res, ...ERR.NOT_FOUND);
  const post = rowToPost(posts0[0]);
  if (post.authorId !== user.id && user.role !== 'admin') return fail(res, ...ERR.FORBIDDEN);
  if (claim.status !== 'pending') return fail(res, 400, 40001, '该认领已处理过');

  const action = body?.action;
  if (action !== 'approve' && action !== 'reject') {
    return fail(res, 400, 40001, 'action 必须是 approve 或 reject');
  }
  const status = action === 'approve' ? 'approved' : 'rejected';
  await sbUpdate('claims', { id: claim.id }, { status, resolved_at: nowISO() });
  if (action === 'approve') {
    await sbUpdate('posts', { id: post.id }, { status: 'resolved', resolved_at: nowISO() });
    // 同帖其他待处理申请自动关闭
    await sbUpdate('claims', { post_id: `eq.${post.id}`, status: 'eq.pending' }, { status: 'closed' });
    await notify(claim.claimant_id, 'claim', `你的认领申请已通过：「${post.title}」，请联系发布者领取`, post.id);
  } else {
    await notify(claim.claimant_id, 'claim', `你的认领申请未通过：「${post.title}」`, post.id);
  }
  ok(res, {
    id: claim.id, postId: claim.post_id, claimantId: claim.claimant_id, claimantName: claim.claimant_name,
    answer: claim.answer, status, createdAt: claim.created_at, resolvedAt: nowISO(),
  });
});

/* ---------- 通知 ---------- */

route('GET', '/api/notifications', async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  const list = await sbSelect('notifications', `?user_id=eq.${user.id}&select=*&order=created_at.desc&limit=50`);
  const all = await sbCount('notifications', { user_id: `eq.${user.id}`, read: 'eq.false' });
  ok(res, list.map((n) => ({
    id: n.id, userId: n.user_id, type: n.type, content: n.content,
    postId: n.post_id, read: n.read, createdAt: n.created_at,
  })), { unread: all });
});

route('POST', '/api/notifications/read', async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  await sbUpdate('notifications', { user_id: `eq.${user.id}`, read: 'eq.false' }, { read: true });
  ok(res);
});

/* ---------- 管理员（admin 专属） ---------- */

route('GET', '/api/admin/users', async (req, res, params, query) => {
  if (!await requireAdmin(req, res)) return;
  const keyword = (query.get('keyword') || '').trim().toLowerCase();
  let list = (await sbSelect('profiles', '?select=*&order=created_at.desc')).map(rowToUser);
  if (keyword) {
    list = list.filter((u) => String(u.username).toLowerCase().includes(keyword) || String(u.nickname).toLowerCase().includes(keyword));
  }
  const authorRows = await sbSelect('posts', '?select=author_id');
  const counts = {};
  for (const r of authorRows) counts[r.author_id] = (counts[r.author_id] || 0) + 1;
  for (const u of list) u.postCount = counts[u.id] || 0;
  ok(res, list.map(PUBLIC_USER).map((u) => ({ ...u, postCount: list.find((x) => x.id === u.id)?.postCount || 0 })));
});

/** 用户管理：封禁/解封（status）、授权/撤销管理员（role） */
route('PATCH', '/api/admin/users/:id', async (req, res, params, query, body) => {
  const admin = await requireAdmin(req, res);
  if (!admin) return;
  const target = await getProfile(params.id);
  if (!target) return fail(res, ...ERR.NOT_FOUND);
  if (target.id === admin.id) return fail(res, 400, 40001, '不能操作自己的账号');

  const { status, role } = body || {};
  const patch = {};
  if (status !== undefined) {
    if (status !== 'active' && status !== 'banned') return fail(res, 400, 40001, 'status 必须是 active 或 banned');
    if (status === 'banned' && target.role === 'admin') return fail(res, 400, 40001, '不能封禁管理员账号');
    patch.status = status;
    await notify(target.id, 'admin', status === 'banned' ? '你的账号已被管理员封禁' : '你的账号已解除封禁');
  }
  if (role !== undefined) {
    if (role !== 'admin' && role !== 'user') return fail(res, 400, 40001, 'role 必须是 admin 或 user');
    if (role !== 'admin') {
      const adminCount = await sbCount('profiles', { role: 'eq.admin', status: 'eq.active' });
      if (target.role === 'admin' && adminCount <= 1) return fail(res, 400, 40001, '至少保留一名管理员');
    }
    patch.role = role;
    await notify(target.id, 'admin', role === 'admin' ? '你已被授权为管理员' : '你的管理员权限已被撤销');
  }
  if (Object.keys(patch).length) await sbUpdate('profiles', { id: target.id }, patch);
  ok(res, PUBLIC_USER(await getProfile(target.id)));
});

/** 删除用户：连同其帖子/评论一并清理（FK 级联 + 删 auth 用户）；不能删自己，最后一个管理员不可删 */
route('DELETE', '/api/admin/users/:id', async (req, res, params) => {
  const admin = await requireAdmin(req, res);
  if (!admin) return;
  const target = await getProfile(params.id);
  if (!target) return fail(res, ...ERR.NOT_FOUND);
  if (target.id === admin.id) return fail(res, 400, 40001, '不能删除自己的账号');
  if (target.role === 'admin') return fail(res, 400, 40001, '请先撤销其管理员权限再删除');

  await authDeleteUser(target.id); // auth.users 删除 -> 全业务表 FK 级联
  await sbDelete('profiles', { id: target.id }).catch(() => {});
  ok(res, { id: target.id });
});

/** 平台统计：管理员首页仪表盘 */
route('GET', '/api/admin/stats', async (req, res) => {
  if (!await requireAdmin(req, res)) return;
  const [users, bannedUsers, admins, posts, lost, found, resolved, pendingClaims, comments] = await Promise.all([
    sbCount('profiles'),
    sbCount('profiles', { status: 'eq.banned' }),
    sbCount('profiles', { role: 'eq.admin' }),
    sbCount('posts'),
    sbCount('posts', { type: 'eq.lost' }),
    sbCount('posts', { type: 'eq.found' }),
    sbCount('posts', { status: 'eq.resolved' }),
    sbCount('claims', { status: 'eq.pending' }),
    sbCount('comments'),
  ]);
  ok(res, { users, bannedUsers, admins, posts, lost, found, resolved, pendingClaims, comments });
});

/** 待处理认领列表（管理员快速处理入口） */
route('GET', '/api/admin/claims', async (req, res) => {
  if (!await requireAdmin(req, res)) return;
  const pend = await sbSelect('claims', '?status=eq.pending&select=*&order=created_at.desc');
  const ids = [...new Set(pend.map((c) => c.post_id))];
  const posts = ids.length
    ? await sbSelect('posts', `?id=in.(${ids.join(',')})&select=id,title,type`)
    : [];
  const postMap = new Map(posts.map((p) => [p.id, p]));
  ok(res, pend.map((c) => {
    const p = postMap.get(c.post_id);
    return {
      id: c.id, postId: c.post_id, claimantId: c.claimant_id, claimantName: c.claimant_name,
      answer: c.answer, status: c.status, createdAt: c.created_at, resolvedAt: c.resolved_at,
      postTitle: p?.title || '(已删除)', postType: p?.type,
    };
  }));
});

/* ---------- 行为统计（埋点 + 分析） ---------- */

/** 埋点上报：公开接口，未注册访客也统计 */
route('POST', '/api/track', async (req, res, params, query, body) => {
  const events = Array.isArray(body?.events) ? body.events.slice(0, 20) : [];
  if (!events.length) return fail(res, 400, 40001, '没有事件');
  // 请求若带合法登录态，则把事件关联到用户（关联失败不报错，访客事件照常收）
  let userId = null;
  try { userId = (await getAuth(req)).user?.id || null; } catch {}
  const rows = [];
  for (const ev of events) {
    const clientId = String(ev?.clientId || '').slice(0, 64);
    const event = String(ev?.event || '').slice(0, 32);
    if (!clientId || !event) continue;
    rows.push({
      client_id: clientId,
      sid: String(ev?.sid || '').slice(0, 64),
      user_id: userId,
      page: String(ev?.page || '').slice(0, 32),
      event,
      created_at: nowISO(),
    });
  }
  if (!rows.length) return fail(res, 400, 40001, '事件格式错误');
  await sbInsert('track_events', rows);
  ok(res, { saved: rows.length });
});

/** 本地日期（Asia/Shanghai）-> 'YYYY-MM-DD' */
const localDate = (iso) => new Date(iso).toLocaleDateString('sv-SE', { timeZone: 'Asia/Shanghai' });
const addDays = (dateStr, k) => {
  const d = new Date(`${dateStr}T00:00:00+08:00`);
  d.setDate(d.getDate() + k);
  return localDate(d.toISOString());
};

/** 管理端数据分析报表 */
route('GET', '/api/admin/analytics', async (req, res, params, query) => {
  if (!(await requireAdmin(req, res))) return;
  const days = Math.min(60, Math.max(7, Number(query.get('days')) || 14));
  const todayStr = localDate(nowISO());

  // 窗口起点（本地日的零点，往前推 days-1 天）
  const fromDate = new Date(`${addDays(todayStr, -(days - 1))}T00:00:00+08:00`);
  const fromISO = fromDate.toISOString();
  const dateList = [];
  for (let i = 0; i < days; i++) dateList.push(addDays(todayStr, -(days - 1 - i)));

  const [profiles, events] = await Promise.all([
    sbSelect('profiles', `?select=client_id,nickname,created_at&created_at=gte.${fromISO}`),
    sbSelect('track_events', `?select=client_id,page,event,created_at&created_at=gte.${fromISO}&limit=100000`),
  ]);

  // ---- 每日新增用户 ----
  const dailyNewUsers = Object.fromEntries(dateList.map((d) => [d, 0]));
  const cohortCids = {}; // 注册日 -> 该日新用户的 client_id 列表
  for (const p of profiles) {
    const d = localDate(p.created_at);
    if (!(d in dailyNewUsers)) continue;
    dailyNewUsers[d]++;
    if (p.client_id) (cohortCids[d] ||= []).push(p.client_id);
  }

  // ---- 每日活跃设备集合（任意事件）----
  const activeByDate = {};
  for (const e of events) {
    const d = localDate(e.created_at);
    (activeByDate[d] ||= new Set()).add(e.client_id);
  }

  // ---- 每日完整浏览首页（滚动 ≥ 80%）----
  const dailyFullView = Object.fromEntries(dateList.map((d) => [d, new Set()]));
  for (const e of events) {
    if (e.event !== 'home_scroll_80') continue;
    const d = localDate(e.created_at);
    if (dailyFullView[d]) dailyFullView[d].add(e.client_id);
  }

  // ---- 使用时长（心跳 15s 一个 = 0.25 分钟）----
  const HB_MIN = 0.25, HB_CAP = 2400; // 单设备单日心跳上限 2400 个（=10 小时）防异常
  const hbCount = {}; // `${date}|${cid}` -> count
  for (const e of events) {
    if (e.event !== 'heartbeat') continue;
    const d = localDate(e.created_at);
    const key = `${d}|${e.client_id}`;
    hbCount[key] = (hbCount[key] || 0) + 1;
  }
  const nickByCid = {};
  for (const p of profiles) if (p.client_id) nickByCid[p.client_id] = p.nickname;
  const dailyDuration = dateList.map((d) => {
    let totalMin = 0, users = [];
    for (const key in hbCount) {
      if (!key.startsWith(d + '|')) continue;
      const min = Math.min(hbCount[key], HB_CAP) * HB_MIN;
      totalMin += min;
      const cid = key.slice(d.length + 1);
      users.push({ clientId: cid, nickname: nickByCid[cid] || '访客', minutes: Math.round(min * 10) / 10 });
    }
    users.sort((a, b) => b.minutes - a.minutes);
    const activeUsers = (activeByDate[d] || new Set()).size;
    return {
      date: d,
      activeUsers,
      avgMinutes: activeUsers ? Math.round((totalMin / activeUsers) * 10) / 10 : 0,
      totalMinutes: Math.round(totalMin * 10) / 10,
      users,
    };
  });
  const totalMin = dailyDuration.reduce((s, x) => s + x.totalMinutes, 0);
  const personDays = dailyDuration.reduce((s, x) => s + (x.activeUsers ? 1 : 0) * x.activeUsers, 0);

  // ---- 留存：按注册日 cohort，看第 N 天活跃比例 ----
  const RETENTION_KEYS = [1, 3, 7, 15, 30];
  const retention = dateList.map((d) => {
    const cids = cohortCids[d] || [];
    const row = { cohort: d, newUsers: dailyNewUsers[d], tracked: cids.length };
    for (const k of RETENTION_KEYS) {
      const target = addDays(d, k);
      if (target > todayStr || !cids.length) { row[`d${k}`] = null; continue; }
      const active = activeByDate[target] || new Set();
      row[`d${k}`] = cids.filter((c) => active.has(c)).length / cids.length;
    }
    return row;
  });

  // ---- 首页 / 后台 UV PV ----
  const pageStat = (page) => {
    const today = dateList[dateList.length - 1];
    let uvToday = new Set(), pvToday = 0, uvTotal = new Set(), pvTotal = 0;
    for (const e of events) {
      if (e.event !== 'page_view' || e.page !== page) continue;
      const d = localDate(e.created_at);
      uvTotal.add(e.client_id); pvTotal++;
      if (d === today) { uvToday.add(e.client_id); pvToday++; }
    }
    return { uvToday: uvToday.size, pvToday, uvTotal: uvTotal.size, pvTotal };
  };

  ok(res, {
    range: { from: dateList[0], to: todayStr, days },
    dailyNewUsers: dateList.map((d) => ({ date: d, count: dailyNewUsers[d] })),
    dailyFullView: dateList.map((d) => ({ date: d, count: dailyFullView[d].size })),
    retention,
    duration: { daily: dailyDuration, overallAvgMinutes: personDays ? Math.round((totalMin / personDays) * 10) / 10 : 0 },
    pages: { home: pageStat('home'), admin: pageStat('admin') },
  });
});



async function seedIfEmpty() {
  const existing = await sbCount('profiles');
  if (existing > 0) return false;

  console.log('[seed] 数据库为空，正在写入演示数据 ...');
  const t = nowISO();
  const ago = (h) => new Date(Date.now() - h * 3600 * 1000).toISOString();

  const mkUser = async (phone, nickname, role, studentId) => {
    const authUser = await authCreateUser(phone, '123456', nickname, studentId, role);
    await sbInsert('profiles', {
      id: authUser.id, phone, nickname, role, status: 'active',
      student_id: studentId || '', created_at: t,
    });
    return authUser.id;
  };
  const adminId = await mkUser('13800000001', '拾光管理员', 'admin', '');
  const demoId  = await mkUser('13800000002', '王同学', 'user', '20230101');
  const liId    = await mkUser('13800000003', '李同学', 'user', '20230218');
  const zhaoId  = await mkUser('13800000004', '赵同学', 'user', '');
  const U = { u_demo: demoId, u_li: liId, u_zhao: zhaoId, u_admin: adminId };

  const P = (o) => ({
    images: [], tags: [], status: 'open', view_count: 0, liked_by: [], resolved_at: null,
    location_detail: '', event_time: o.created_at, updated_at: o.created_at, ...o,
  });
  const posts = [
    P({ id: 'p_1', type: 'lost', title: '一串钥匙（挂蓝色小熊挂坠）', category: '钥匙',
      description: '主校区体育馆更衣室附近丢失一串钥匙，带蓝色小熊挂坠和一个公交卡扣。有拾到请联系，请帮忙转发！',
      location: '体育馆', contact: { method: 'phone', value: '13812340101' },
      author_id: demoId, author_name: '王同学', created_at: ago(30), view_count: 23, liked_by: [liId] }),
    P({ id: 'p_2', type: 'found', title: '捡到银色 iPhone 14（已交保卫处前先来登记）', category: '电子产品',
      description: '第一食堂一楼靠窗座位捡到银色 iPhone 14，锁屏完好。先在这里登记，失主描述锁屏壁纸即可认领。',
      location: '第一食堂', location_detail: '一楼靠窗', contact: { method: 'wechat', value: 'li_wen_2023' },
      author_id: liId, author_name: '李同学', created_at: ago(26), view_count: 41, liked_by: [demoId, zhaoId] }),
    P({ id: 'p_3', type: 'lost', title: '黑色耐克外套（L 码）', category: '衣物',
      description: '操场东看台看球时把外套落下了，黑色耐克 L 码，袖口有洗旧的白色logo。里面有校园卡一张。',
      location: '操场', location_detail: '东看台', contact: { method: 'phone', value: '15912340303' },
      author_id: zhaoId, author_name: '赵同学', created_at: ago(48), view_count: 9 }),
    P({ id: 'p_4', type: 'lost', title: 'AirPods Pro 充电盒丢失（耳机还在）', category: '电子产品',
      description: '第三教学楼 305 教室下课后丢失 AirPods Pro 充电盒，两只耳机还在身上。盒子底部有贴纸。',
      location: '第三教学楼', location_detail: '305 教室', contact: { method: 'phone', value: '13612340505' },
      author_id: demoId, author_name: '王同学', created_at: ago(70), view_count: 12 }),
    P({ id: 'p_5', type: 'found', title: '捡到校园卡（姓名：李 xx）', category: '卡类证件',
      description: '校医院大门口捡到一张校园卡，姓氏看得到是李。已拍照登记，失主带学生证来核对领取。',
      location: '校医院', location_detail: '大门口', contact: { method: 'phone', value: '18812340606' },
      author_id: demoId, author_name: '王同学', created_at: ago(20), view_count: 15, liked_by: [liId] }),
    P({ id: 'p_6', type: 'found', title: '捡到电动车钥匙（带遥控器）', category: '钥匙',
      description: '北门车棚地上捡的，雅迪的遥控钥匙。放在北门保安亭，失主去保安亭对特征领取。',
      location: '北门', location_detail: '非机动车棚', contact: { method: 'phone', value: '13712340707' },
      author_id: liId, author_name: '李同学', created_at: ago(15), view_count: 18 }),
    P({ id: 'p_7', type: 'lost', title: '丢失校园卡（尾号 3210）', category: '卡类证件',
      description: '图书馆二楼自习区丢的校园卡，尾号 3210。捡到的同学请联系我，有酬谢！',
      location: '图书馆', location_detail: '二楼自习区', contact: { method: 'wechat', value: 'wang_demo_88' },
      author_id: demoId, author_name: '王同学', created_at: ago(56), view_count: 30 }),
    P({ id: 'p_8', type: 'lost', title: '丢失《高等数学（第七版）》，扉页写了名字', category: '书籍',
      description: '第一教学楼三楼阅览室自习后书不见了，扉页有我的名字和班级。书不值钱但笔记很重要！',
      location: '第一教学楼', location_detail: '三楼阅览室', contact: { method: 'phone', value: '15012340808' },
      author_id: zhaoId, author_name: '赵同学', created_at: ago(80), view_count: 11 }),
    P({ id: 'p_9', type: 'found', title: '捡到《线性代数》+ 一本活页笔记', category: '书籍',
      description: '第一教学楼 201 教室放学后收拾到一本线代和活页笔记，笔记主人应该很认真，快来认领。',
      location: '第一教学楼', location_detail: '201 教室', contact: { method: 'wechat', value: 'shiguang_li' },
      author_id: liId, author_name: '李同学', created_at: ago(78), view_count: 14, liked_by: [demoId] }),
    P({ id: 'p_10', type: 'lost', title: '丢失小米手环 8（已找到，谢谢各位）', category: '电子产品',
      description: '周三落在操场器材室，已经找回。感谢帮忙转发和提供线索的同学！',
      location: '操场', location_detail: '器材室', contact: { method: 'phone', value: '13812340101' },
      status: 'resolved', resolved_at: ago(10),
      author_id: demoId, author_name: '王同学', created_at: ago(120), view_count: 35 }),
  ];
  await sbInsert('posts', posts);

  await sbInsert('comments', [
    { id: uid('c'), post_id: 'p_2', author_id: zhaoId, author_name: '赵同学', content: '好人一生平安，我室友正找手机呢，我转告他', created_at: ago(20) },
    { id: uid('c'), post_id: 'p_2', author_id: liId, author_name: '李同学', content: '对，一楼服务台有个本子专门登记这个', created_at: ago(18) },
    { id: uid('c'), post_id: 'p_1', author_id: liId, author_name: '李同学', content: '昨天好像在更衣室门口见过一串钥匙，你去问问管理员？', created_at: ago(24) },
  ]);
  await sbInsert('notifications', [
    { id: uid('n'), user_id: demoId, type: 'comment', content: '李同学 评论了你的帖子「一串钥匙（挂蓝色小熊挂坠）」', post_id: 'p_1', read: false, created_at: ago(24) },
    { id: uid('n'), user_id: liId, type: 'like', content: '王同学 赞了你的帖子「捡到银色 iPhone 14（已交保卫处前先来登记）」', post_id: 'p_2', read: false, created_at: ago(20) },
    { id: uid('n'), user_id: liId, type: 'claim', content: '王同学 申请认领你的帖子「捡到银色 iPhone 14（已交保卫处前先来登记）」，请核实处理', post_id: 'p_2', read: false, created_at: ago(12) },
  ]);
  await sbInsert('claims', [
    { id: uid('cl'), post_id: 'p_2', claimant_id: demoId, claimant_name: '王同学',
      answer: '锁屏壁纸是一只橘猫，手机壳背面夹了一张公交卡', status: 'pending', created_at: ago(12) },
  ]);
  console.log('[seed] 完成：4 个演示账号 + 10 条帖子 + 3 条评论 + 1 笔待处理认领');
  return true;
}

/** 确保 Storage 存在 public bucket "uploads"（存在则跳过） */
async function ensureUploadBucket() {
  try {
    const r = await sbFetch(`${SB_URL}/storage/v1/bucket/uploads`);
    const bucket = await r.json().catch(() => null);
    if (bucket && bucket.public) return;
    if (bucket) {
      await sbFetch(`${SB_URL}/storage/v1/bucket/uploads`, { method: 'PATCH', body: { public: true } });
      return;
    }
  } catch {
    // 404 -> 创建
  }
  await sbFetch(`${SB_URL}/storage/v1/bucket`, { method: 'POST', body: { name: 'uploads', public: true } })
    .then(() => console.log('[storage] 已创建 public bucket "uploads"'))
    .catch((e) => {
      if (!/exists|duplicate/i.test(e.message)) console.error('[storage]', e.message);
    });
}

/* ============================================================
 * 静态文件：托管前端页面
 * ============================================================ */

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
  '.webp': 'image/webp', '.gif': 'image/gif', '.svg': 'image/svg+xml', '.ico': 'image/x-icon',
  '.woff2': 'font/woff2', '.woff': 'font/woff', '.ttf': 'font/ttf',
};

function serveStatic(res, fileName) {
  const filePath = path.join(__dirname, fileName);
  if (!fs.existsSync(filePath)) {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('404 Not Found');
  }
  res.writeHead(200, { 'Content-Type': MIME[path.extname(filePath)] || 'application/octet-stream' });
  fs.createReadStream(filePath).pipe(res);
}

/* ============================================================
 * 请求分发
 * ============================================================ */

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const pathname = decodeURIComponent(url.pathname);

  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, x-authorization, x-access-token, x-token',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
      'Access-Control-Max-Age': '86400',
    });
    return res.end();
  }

  try {
    if (req.method === 'GET' && (pathname === '/' || pathname === '/preview')) {
      return serveStatic(res, '终稿.html');
    }
    if (req.method === 'GET' && (pathname === '/app' || pathname === '/final' || pathname === '/终稿.html')) {
      return serveStatic(res, '终稿.html');
    }
    if (req.method === 'GET' && pathname === '/landing') {
      return serveStatic(res, '落地页.html');
    }
    if (req.method === 'GET' && !pathname.startsWith('/api/')) {
      const safe = path.normalize(pathname).replace(/^([.][.][/\\])+/, '');
      return serveStatic(res, safe);
    }

    const matched = routes.filter((r) => r.regex.test(pathname));
    if (!matched.length) return fail(res, ...ERR.NOT_FOUND);
    const r = matched.find((x) => x.method === req.method);
    if (!r) return send(res, 405, 40501, '方法不被允许');

    const m = pathname.match(r.regex);
    const params = {};
    r.keys.forEach((k, i) => { params[k] = m[i + 1]; });

    let body = {};
    if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
      body = await readBody(req);
      if (body === null) return fail(res, 400, 40001, '请求体不是合法 JSON');
    }
    await r.handler(req, res, params, url.searchParams, body);
  } catch (err) {
    console.error('[error]', err);
    if (!res.writableEnded) fail(res, 500, 50001, '服务器内部错误');
  }
});

/* ============================================================
 * 启动
 * ============================================================ */

(async () => {
  try {
    await seedIfEmpty();
    await ensureUploadBucket();
  } catch (e) {
    console.error('[startup] 初始化失败，请检查 Supabase 配置与建表 SQL：', e.message);
    process.exit(1);
  }
  server.listen(PORT, () => {
    console.log('');
    console.log('  拾光 · 校园失物招领 后端已启动（Supabase 模式）');
    console.log(`  地址:       http://localhost:${PORT}`);
    console.log(`  Supabase:   ${SB_URL}`);
    console.log('');
    console.log('  管理员账号  13800000001 / 123456   （用户管理、删帖、统计、处理认领）');
    console.log('  用户账号    13800000002 / 123456   （王同学 demo）');
    console.log('  用户账号    13800000003 / 123456   （李同学 li）');
    console.log('  用户账号    13800000004 / 123456   （赵同学 zhao）');
    console.log('');
    console.log('  浏览器打开 http://localhost:' + PORT + ' 可直接看前端页面');
    console.log('');
  });
})();
