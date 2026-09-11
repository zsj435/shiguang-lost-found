/**
 * 拾光 · 校园失物招领 —— 后端服务（零依赖版）
 * ============================================================
 * 纯 Node 内置模块实现，无需 MongoDB / npm install。
 *   启动：node server.js   （或双击 start-server.bat）
 *   端口：process.env.PORT || 3000
 *
 * 双角色体系：
 *   - admin 管理员：用户管理（封禁/解封/授权）、删任意帖子评论、平台统计、处理认领
 *   - user  普通用户：发帖/编辑自己的帖子、评论、点赞、发起认领
 *
 * 鉴权：双 token（对齐前端 request.js 的约定）
 *   - accessToken  2 小时，请求头 Authorization: Bearer <token>
 *   - refreshToken 7 天，过期后前端拿它调 POST /api/auth/refresh 静默续期
 *   - 过期返回 code=40102（触发前端刷新重放），无效返回 40101（触发跳登录）
 *
 * 响应信封：{ code, message, data, meta? }，成功 code 恒为 0
 * 存储：data/db.json（首次启动自动写入种子数据与演示账号）
 */

import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || 'shiguang-lost-found-dev-secret';
const ACCESS_TTL = 2 * 60 * 60;        // 2h
const REFRESH_TTL = 7 * 24 * 60 * 60;  // 7d
const DB_FILE = path.join(__dirname, 'data', 'db.json');

/* ============================================================
 * 工具函数
 * ============================================================ */

const b64url = (buf) => Buffer.from(buf).toString('base64url');
const uid = (prefix) => `${prefix}_${crypto.randomBytes(8).toString('hex')}`;
const nowISO = () => new Date().toISOString();

/** HMAC-SHA256 签名 JWT（HS256，base64url 三段式） */
function signToken(payload, ttlSec) {
  const iat = Math.floor(Date.now() / 1000);
  const body = { ...payload, iat, exp: iat + ttlSec };
  const head = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const data = b64url(JSON.stringify(body));
  const sig = crypto.createHmac('sha256', JWT_SECRET).update(`${head}.${data}`).digest('base64url');
  return `${head}.${data}.${sig}`;
}

/**
 * 校验 token。
 * 返回 { ok: true, payload } 或 { ok: false, reason: 'expired' | 'invalid' }
 */
function verifyToken(token) {
  if (!token || typeof token !== 'string') return { ok: false, reason: 'invalid' };
  const parts = token.split('.');
  if (parts.length !== 3) return { ok: false, reason: 'invalid' };
  const [head, data, sig] = parts;
  const expect = crypto.createHmac('sha256', JWT_SECRET).update(`${head}.${data}`).digest('base64url');
  const a = Buffer.from(sig);
  const b = Buffer.from(expect);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return { ok: false, reason: 'invalid' };
  let payload;
  try {
    payload = JSON.parse(Buffer.from(data, 'base64url').toString('utf8'));
  } catch {
    return { ok: false, reason: 'invalid' };
  }
  if (typeof payload.exp !== 'number' || payload.exp * 1000 < Date.now()) return { ok: false, reason: 'expired' };
  return { ok: true, payload };
}

/** scrypt 加盐哈希存密码（不存明文） */
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return { salt, hash };
}
function verifyPassword(password, stored) {
  if (!stored?.salt || !stored?.hash) return false;
  const hash = crypto.scryptSync(String(password), stored.salt, 64).toString('hex');
  const a = Buffer.from(hash);
  const b = Buffer.from(stored.hash);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

const PUBLIC_USER = (u) => ({
  id: u.id, username: u.username, nickname: u.nickname,
  role: u.role, status: u.status, studentId: u.studentId || '', createdAt: u.createdAt,
});

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
 * 数据存储（JSON 文件 + 原子写）
 * ============================================================ */

let db = null;

function loadDB() {
  if (fs.existsSync(DB_FILE)) {
    db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    return;
  }
  db = seedData();
  saveDB();
  console.log('[db] 未发现数据文件，已写入种子数据 ->', DB_FILE);
}

function saveDB() {
  fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
  const tmp = `${DB_FILE}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2), 'utf8');
  fs.renameSync(tmp, DB_FILE); // 先写临时文件再改名，避免写一半损坏
}

/** 种子数据：1 管理员 + 3 用户 + 贴合真实校园场景的帖子/评论/待处理认领 */
function seedData() {
  const t = nowISO();
  const ago = (h) => new Date(Date.now() - h * 3600 * 1000).toISOString();
  const users = [
    { id: 'u_admin', username: 'admin', nickname: '拾光管理员', role: 'admin', status: 'active', studentId: '', createdAt: t, password: hashPassword('123456') },
    { id: 'u_demo', username: 'demo', nickname: '王同学', role: 'user', status: 'active', studentId: '20230101', createdAt: t, password: hashPassword('123456') },
    { id: 'u_li', username: 'li', nickname: '李同学', role: 'user', status: 'active', studentId: '20230218', createdAt: t, password: hashPassword('123456') },
    { id: 'u_zhao', username: 'zhao', nickname: '赵同学', role: 'user', status: 'active', studentId: '', createdAt: t, password: hashPassword('123456') },
  ];
  const P = (o) => ({
    images: [], tags: [], status: 'open', viewCount: 0, likedBy: [], resolvedAt: null,
    locationDetail: '', eventTime: o.createdAt, updatedAt: o.createdAt, ...o,
  });
  const posts = [
    P({ id: 'p_1', type: 'lost', title: '一串钥匙（挂蓝色小熊挂坠）', category: '钥匙',
      description: '主校区体育馆更衣室附近丢失一串钥匙，带蓝色小熊挂坠和一个公交卡扣。有拾到请联系，请帮忙转发！',
      location: '体育馆', contact: { method: 'phone', value: '13812340101' },
      authorId: 'u_demo', authorName: '王同学', createdAt: ago(30), viewCount: 23, likedBy: ['u_li'] }),
    P({ id: 'p_2', type: 'found', title: '捡到银色 iPhone 14（已交保卫处前先来登记）', category: '电子产品',
      description: '第一食堂一楼靠窗座位捡到银色 iPhone 14，锁屏完好。先在这里登记，失主描述锁屏壁纸即可认领。',
      location: '第一食堂', locationDetail: '一楼靠窗', contact: { method: 'wechat', value: 'li_wen_2023' },
      authorId: 'u_li', authorName: '李同学', createdAt: ago(26), viewCount: 41, likedBy: ['u_demo', 'u_zhao'] }),
    P({ id: 'p_3', type: 'lost', title: '黑色耐克外套（L 码）', category: '衣物',
      description: '操场东看台看球时把外套落下了，黑色耐克 L 码，袖口有洗旧的白色logo。里面有校园卡一张。',
      location: '操场', locationDetail: '东看台', contact: { method: 'phone', value: '15912340303' },
      authorId: 'u_zhao', authorName: '赵同学', createdAt: ago(48), viewCount: 9 }),
    P({ id: 'p_4', type: 'lost', title: 'AirPods Pro 充电盒丢失（耳机还在）', category: '电子产品',
      description: '第三教学楼 305 教室下课后丢失 AirPods Pro 充电盒，两只耳机还在身上。盒子底部有贴纸。',
      location: '第三教学楼', locationDetail: '305 教室', contact: { method: 'phone', value: '13612340505' },
      authorId: 'u_demo', authorName: '王同学', createdAt: ago(70), viewCount: 12 }),
    P({ id: 'p_5', type: 'found', title: '捡到校园卡（姓名：李 xx）', category: '卡类证件',
      description: '校医院大门口捡到一张校园卡，姓氏看得到是李。已拍照登记，失主带学生证来核对领取。',
      location: '校医院', locationDetail: '大门口', contact: { method: 'phone', value: '18812340606' },
      authorId: 'u_demo', authorName: '王同学', createdAt: ago(20), viewCount: 15, likedBy: ['u_li'] }),
    P({ id: 'p_6', type: 'found', title: '捡到电动车钥匙（带遥控器）', category: '钥匙',
      description: '北门车棚地上捡的，雅迪的遥控钥匙。放在北门保安亭，失主去保安亭对特征领取。',
      location: '北门', locationDetail: '非机动车棚', contact: { method: 'phone', value: '13712340707' },
      authorId: 'u_li', authorName: '李同学', createdAt: ago(15), viewCount: 18 }),
    P({ id: 'p_7', type: 'lost', title: '丢失校园卡（尾号 3210）', category: '卡类证件',
      description: '图书馆二楼自习区丢的校园卡，尾号 3210。捡到的同学请联系我，有酬谢！',
      location: '图书馆', locationDetail: '二楼自习区', contact: { method: 'wechat', value: 'wang_demo_88' },
      authorId: 'u_demo', authorName: '王同学', createdAt: ago(56), viewCount: 30 }),
    P({ id: 'p_8', type: 'lost', title: '丢失《高等数学（第七版）》，扉页写了名字', category: '书籍',
      description: '第一教学楼三楼阅览室自习后书不见了，扉页有我的名字和班级。书不值钱但笔记很重要！',
      location: '第一教学楼', locationDetail: '三楼阅览室', contact: { method: 'phone', value: '15012340808' },
      authorId: 'u_zhao', authorName: '赵同学', createdAt: ago(80), viewCount: 11 }),
    P({ id: 'p_9', type: 'found', title: '捡到《线性代数》+ 一本活页笔记', category: '书籍',
      description: '第一教学楼 201 教室放学后收拾到一本线代和活页笔记，笔记主人应该很认真，快来认领。',
      location: '第一教学楼', locationDetail: '201 教室', contact: { method: 'wechat', value: 'shiguang_li' },
      authorId: 'u_li', authorName: '李同学', createdAt: ago(78), viewCount: 14, likedBy: ['u_demo'] }),
    P({ id: 'p_10', type: 'lost', title: '丢失小米手环 8（已找到，谢谢各位）', category: '电子产品',
      description: '周三落在操场器材室，已经找回。感谢帮忙转发和提供线索的同学！',
      location: '操场', locationDetail: '器材室', contact: { method: 'phone', value: '13812340101' },
      status: 'resolved', resolvedAt: ago(10),
      authorId: 'u_demo', authorName: '王同学', createdAt: ago(120), viewCount: 35 }),
  ];
  const comments = [
    { id: 'c_1', postId: 'p_2', authorId: 'u_zhao', authorName: '赵同学', content: '好人一生平安，我室友正找手机呢，我转告他', createdAt: ago(20) },
    { id: 'c_2', postId: 'p_2', authorId: 'u_li', authorName: '李同学', content: '对，一楼服务台有个本子专门登记这个', createdAt: ago(18) },
    { id: 'c_3', postId: 'p_1', authorId: 'u_li', authorName: '李同学', content: '昨天好像在更衣室门口见过一串钥匙，你去问问管理员？', createdAt: ago(24) },
  ];
  const notifications = [
    { id: 'n_1', userId: 'u_demo', type: 'comment', content: '李同学 评论了你的帖子「一串钥匙（挂蓝色小熊挂坠）」', postId: 'p_1', read: false, createdAt: ago(24) },
    { id: 'n_2', userId: 'u_li', type: 'like', content: '王同学 赞了你的帖子「捡到银色 iPhone 14（已交保卫处前先来登记）」', postId: 'p_2', read: false, createdAt: ago(20) },
    { id: 'n_3', userId: 'u_li', type: 'claim', content: '王同学 申请认领你的帖子「捡到银色 iPhone 14（已交保卫处前先来登记）」，请核实处理', postId: 'p_2', read: false, createdAt: ago(12) },
  ];
  const claims = [
    { id: 'cl_1', postId: 'p_2', claimantId: 'u_demo', claimantName: '王同学',
      answer: '锁屏壁纸是一只橘猫，手机壳背面夹了一张公交卡', status: 'pending', createdAt: ago(12) },
  ];
  return { users, posts, comments, notifications, claims, counters: { post: 11, comment: 4 } };
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
      if (size > 1024 * 1024) { req.destroy(); resolve(null); return; } // 上限 1MB
      chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch { resolve(null); } // JSON 解析失败按坏请求处理
    });
    req.on('error', () => resolve(null));
  });
}

/** 收集请求中所有可能的 token 来源。
 *  兼容三类场景：
 *   1) 标准 Authorization: Bearer <token>（含网关把重复头合并成逗号串的情况）
 *   2) 反向代理改名的兜底头（x-authorization / x-access-token / x-token）
 *   3) 查询串 ?_t=<token>（网关剥离鉴权头时，前端会自动降级走查询串） */
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
  // "Bearer a, Bearer b" 形式（重复头被网关合并）：逐个拆出来都作为候选
  const auth = String(req.headers['authorization'] || '');
  for (const m of auth.matchAll(/Bearer\s+([^\s,]+)/gi)) push(m[1]);
  return list;
}

/** 从请求解析并校验 accessToken：任一来源合法即通过；全部失败时优先报「过期」而非「无效」，
 *  这样前端会走静默刷新重试，而不是直接把用户踢回登录页 */
function getAuth(req) {
  let expired = false;
  for (const token of extractTokens(req)) {
    const result = verifyToken(token);
    if (!result.ok) {
      if (result.reason === 'expired') expired = true;
      continue;
    }
    const user = db.users.find((u) => u.id === result.payload.sub);
    if (user) return { user };
  }
  return { error: expired ? 'expired' : 'invalid' };
}

/** 需要登录的统一入口：校验 token + 封禁状态 */
function requireAuth(req, res) {
  const auth = getAuth(req);
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

function requireAdmin(req, res) {
  const user = requireAuth(req, res);
  if (!user) return null;
  if (user.role !== 'admin') {
    fail(res, ...ERR.FORBIDDEN);
    return null;
  }
  return user;
}

function notify(userId, type, content, postId = null) {
  db.notifications.unshift({
    id: uid('n'), userId, type, content, postId, read: false, createdAt: nowISO(),
  });
}

/* ============================================================
 * 路由表
 * ============================================================ */

const routes = [];
function route(method, pattern, handler) {
  // '/api/posts/:id' -> { keys: ['id'], regex: /^\/api\/posts\/([^/]+)$/ }
  const keys = [];
  const regex = new RegExp('^' + pattern.replace(/:[a-zA-Z]+/g, (m) => {
    keys.push(m.slice(1));
    return '([^/]+)';
  }) + '$');
  routes.push({ method, regex, keys, handler });
}

/* ---------- 认证 ---------- */

route('POST', '/api/auth/register', async (req, res, params, query, body) => {
  const { username, password, nickname, studentId } = body || {};
  // 对齐前端预览版规则：2-20 位中文/字母/数字/下划线
  if (!username || !/^[\u4e00-\u9fa5a-zA-Z0-9_]{2,20}$/.test(username)) {
    return fail(res, 400, 40001, '用户名需为 2-20 位中文、字母、数字或下划线');
  }
  // 8-20 位，需同时包含字母和数字
  if (!password || !/^(?=.*[a-zA-Z])(?=.*\d)\S{8,20}$/.test(String(password))) {
    return fail(res, 400, 40001, '密码需 8-20 位，且同时包含字母和数字');
  }
  if (studentId && !/^\d{6,20}$/.test(String(studentId))) {
    return fail(res, 400, 40001, '学号为 6-20 位数字');
  }
  if (db.users.some((u) => u.username === username)) {
    return fail(res, 400, 40001, '用户名已被占用');
  }
  // 注册一律是普通用户；管理员只能由已有管理员在后台授权
  const user = {
    id: uid('u'), username, nickname: nickname || username,
    role: 'user', status: 'active', studentId: studentId || '',
    createdAt: nowISO(), password: hashPassword(password),
  };
  db.users.push(user);
  saveDB();
  ok(res, {
    user: PUBLIC_USER(user),
    accessToken: signToken({ sub: user.id, role: user.role }, ACCESS_TTL),
    refreshToken: signToken({ sub: user.id, typ: 'refresh' }, REFRESH_TTL),
  });
});

route('POST', '/api/auth/login', async (req, res, params, query, body) => {
  const { username, password } = body || {};
  const user = db.users.find((u) => u.username === username);
  if (!user || !verifyPassword(password, user.password)) {
    return fail(res, 400, 40001, '用户名或密码错误');
  }
  if (user.status === 'banned') {
    return fail(res, 403, 40302, '账号已被封禁，请联系管理员');
  }
  ok(res, {
    user: PUBLIC_USER(user),
    accessToken: signToken({ sub: user.id, role: user.role }, ACCESS_TTL),
    refreshToken: signToken({ sub: user.id, typ: 'refresh' }, REFRESH_TTL),
  });
});

route('POST', '/api/auth/refresh', async (req, res, params, query, body) => {
  const result = verifyToken(body?.refreshToken);
  if (!result.ok) {
    return fail(res, ...ERR.UNAUTHORIZED);
  }
  const user = db.users.find((u) => u.id === result.payload.sub);
  if (!user || user.status === 'banned') {
    return fail(res, ...ERR.UNAUTHORIZED);
  }
  ok(res, {
    accessToken: signToken({ sub: user.id, role: user.role }, ACCESS_TTL),
    refreshToken: signToken({ sub: user.id, typ: 'refresh' }, REFRESH_TTL),
  });
});

route('GET', '/api/auth/me', (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  ok(res, { user: PUBLIC_USER(user) });
});

/* 诊断端点：查看反代之后服务器实际收到的鉴权凭据（定位鉴权头被剥离问题） */
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
route('GET', '/api/posts', (req, res, params, query) => {
  const page = Math.max(1, Number(query.get('page')) || 1);
  const pageSize = Math.min(50, Math.max(1, Number(query.get('pageSize')) || 10));
  const keyword = (query.get('keyword') || '').trim();

  let list = db.posts.slice().sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  const type = query.get('type');
  const status = query.get('status');
  const category = query.get('category');
  if (type === 'lost' || type === 'found') list = list.filter((p) => p.type === type);
  if (status === 'open' || status === 'resolved') list = list.filter((p) => p.status === status);
  if (category) list = list.filter((p) => p.category === category);
  if (keyword) {
    list = list.filter((p) =>
      [p.title, p.description, p.location].some((s) => (s || '').toLowerCase().includes(keyword.toLowerCase())));
  }

  const total = list.length;
  const items = list.slice((page - 1) * pageSize, page * pageSize);

  // 若带了合法 token，附上 isLiked 方便前端渲染点赞态（没 token 不报错）
  const auth = getAuth(req);
  const me = auth.user || null;
  ok(res, {
    list: items.map((p) => ({
      ...p, likedBy: undefined,
      likeCount: p.likedBy.length,
      commentCount: db.comments.filter((c) => c.postId === p.id).length,
      isLiked: me ? p.likedBy.includes(me.id) : false,
      isMine: me ? p.authorId === me.id : false,
    })),
  }, { page, pageSize, total });
});

/** 详情：公开可读，浏览量 +1 */
route('GET', '/api/posts/:id', (req, res, params) => {
  const post = db.posts.find((p) => p.id === params.id);
  if (!post) return fail(res, ...ERR.NOT_FOUND);
  post.viewCount += 1;
  saveDB();
  const auth = getAuth(req);
  const me = auth.user || null;
  ok(res, {
    ...post, likedBy: undefined,
    likeCount: post.likedBy.length,
    commentCount: db.comments.filter((c) => c.postId === post.id).length,
    contact: maskContact(post, me),
    isLiked: me ? post.likedBy.includes(me.id) : false,
    isMine: me ? post.authorId === me.id : false,
  });
});

/** 相似推荐：类型相反、状态未解决，分类/关键词/地点重合度打分取前 5 */
route('GET', '/api/posts/:id/matches', (req, res, params) => {
  const post = db.posts.find((p) => p.id === params.id);
  if (!post) return fail(res, ...ERR.NOT_FOUND);
  const opposite = post.type === 'lost' ? 'found' : 'lost';
  const words = (post.title + post.description).replace(/[（）()【】\s，。、：:？！?!,.]/g, ' ').split(' ').filter((w) => w.length >= 2);
  const scored = db.posts
    .filter((p) => p.id !== post.id && p.type === opposite && p.status === 'open')
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
  ok(res, scored.map((x) => ({
    ...x.post, likedBy: undefined,
    likeCount: x.post.likedBy.length,
    commentCount: db.comments.filter((c) => c.postId === x.post.id).length,
    score: x.score,
  })));
});

/** 图片上传：dataURL(base64) 存为文件，返回访问地址（最多 3 张、单张 5MB 由前端限制） */
route('POST', '/api/upload', (req, res, params, query, body) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const dataURL = String(body?.image || '');
  const m = dataURL.match(/^data:image\/(png|jpe?g|webp);base64,(.+)$/);
  if (!m) return fail(res, 400, 40001, '仅支持 png/jpg/webp 图片');
  const ext = m[1] === 'jpeg' ? 'jpg' : m[1];
  const buf = Buffer.from(m[2], 'base64');
  if (buf.length > 5 * 1024 * 1024) return fail(res, 400, 40001, '单张图片不能超过 5MB');
  const name = `up_${Date.now().toString(36)}_${crypto.randomBytes(5).toString('hex')}.${ext}`;
  fs.mkdirSync(path.join(__dirname, 'data', 'uploads'), { recursive: true });
  fs.writeFileSync(path.join(__dirname, 'data', 'uploads', name), buf);
  ok(res, { url: `/uploads/${name}` });
});

route('POST', '/api/posts', async (req, res, params, query, body) => {
  const user = requireAuth(req, res);
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
  const post = {
    id: `p_${db.counters.post++}`,
    type, title: String(title).trim(),
    description: String(description).trim(),
    category,
    location: location || '',
    locationDetail: locationDetail || '',
    eventTime: eventTime || t,
    contact: contact && contact.value ? { method: contact.method === 'wechat' ? 'wechat' : 'phone', value: String(contact.value) } : null,
    images: imgs,
    tags: Array.isArray(tags) ? tags.slice(0, 5).map(String) : [],
    status: 'open', authorId: user.id, authorName: user.nickname,
    createdAt: t, updatedAt: t, likedBy: [], viewCount: 0, resolvedAt: null,
  };
  db.posts.unshift(post);
  saveDB();
  ok(res, post);
});

/** 编辑：作者本人或管理员 */
route('PUT', '/api/posts/:id', async (req, res, params, query, body) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const post = db.posts.find((p) => p.id === params.id);
  if (!post) return fail(res, ...ERR.NOT_FOUND);
  if (post.authorId !== user.id && user.role !== 'admin') return fail(res, ...ERR.FORBIDDEN);

  const fields = ['title', 'description', 'category', 'location', 'locationDetail', 'eventTime', 'contact', 'type', 'status', 'tags', 'images'];
  for (const f of fields) {
    if (body && body[f] !== undefined) post[f] = body[f];
  }
  if (body?.status === 'resolved') post.resolvedAt = nowISO();
  post.updatedAt = nowISO();
  saveDB();
  ok(res, post);
});

/** 删除：作者本人或管理员；管理员删除会给作者发通知 */
route('DELETE', '/api/posts/:id', (req, res, params) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const idx = db.posts.findIndex((p) => p.id === params.id);
  if (idx === -1) return fail(res, ...ERR.NOT_FOUND);
  const post = db.posts[idx];
  if (post.authorId !== user.id && user.role !== 'admin') return fail(res, ...ERR.FORBIDDEN);

  db.posts.splice(idx, 1);
  db.comments = db.comments.filter((c) => c.postId !== post.id);
  db.claims = db.claims.filter((c) => c.postId !== post.id);
  if (user.role === 'admin' && post.authorId !== user.id) {
    notify(post.authorId, 'admin', `管理员删除了你的帖子「${post.title}」`);
  }
  saveDB();
  ok(res, { id: post.id });
});

/** 点赞/取消点赞（toggle） */
route('POST', '/api/posts/:id/like', (req, res, params) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const post = db.posts.find((p) => p.id === params.id);
  if (!post) return fail(res, ...ERR.NOT_FOUND);
  const i = post.likedBy.indexOf(user.id);
  if (i >= 0) post.likedBy.splice(i, 1);
  else {
    post.likedBy.push(user.id);
    if (post.authorId !== user.id) {
      notify(post.authorId, 'like', `${user.nickname} 赞了你的帖子「${post.title}」`, post.id);
    }
  }
  saveDB();
  ok(res, { isLiked: i < 0, likeCount: post.likedBy.length });
});

/* ---------- 评论 ---------- */

route('GET', '/api/posts/:id/comments', (req, res, params) => {
  const post = db.posts.find((p) => p.id === params.id);
  if (!post) return fail(res, ...ERR.NOT_FOUND);
  ok(res, db.comments.filter((c) => c.postId === post.id)
    .sort((a, b) => a.createdAt.localeCompare(b.createdAt)));
});

route('POST', '/api/posts/:id/comments', async (req, res, params, query, body) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const post = db.posts.find((p) => p.id === params.id);
  if (!post) return fail(res, ...ERR.NOT_FOUND);
  const content = String(body?.content || '').trim();
  if (!content) return fail(res, 400, 40001, '请输入评论内容');
  if (content.length > 500) return fail(res, 400, 40001, '评论不能超过 500 字');

  // 回复：可携带被回复的评论 id 与作者名，前端展示「回复 @某人」
  let replyTo = null;
  if (body?.replyTo) {
    const target = db.comments.find((c) => c.id === body.replyTo.id && c.postId === post.id);
    if (target) replyTo = { id: target.id, name: target.authorName };
  }
  const comment = {
    id: `c_${db.counters.comment++}`, postId: post.id,
    authorId: user.id, authorName: user.nickname,
    content, replyTo, createdAt: nowISO(),
  };
  db.comments.push(comment);
  if (post.authorId !== user.id) {
    notify(post.authorId, 'comment', `${user.nickname} 评论了你的帖子「${post.title}」`, post.id);
  } else if (replyTo && replyTo.name !== user.nickname) {
    // 楼层被回复：通知被回复人（此处简化：通知帖子作者以外的被回复者需要查其用户）
    const target = db.comments.find((c) => c.id === replyTo.id);
    if (target && target.authorId !== user.id) {
      notify(target.authorId, 'reply', `${user.nickname} 回复了你的评论`, post.id);
    }
  }
  saveDB();
  ok(res, comment);
});

route('DELETE', '/api/comments/:id', (req, res, params) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const idx = db.comments.findIndex((c) => c.id === params.id);
  if (idx === -1) return fail(res, ...ERR.NOT_FOUND);
  if (db.comments[idx].authorId !== user.id && user.role !== 'admin') return fail(res, ...ERR.FORBIDDEN);
  db.comments.splice(idx, 1);
  saveDB();
  ok(res, { id: params.id });
});

/* ---------- 认领 ---------- */

/** 发起认领：不能认领自己的帖子，一个帖子一人只能有一笔待处理认领 */
route('POST', '/api/posts/:id/claims', async (req, res, params, query, body) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const post = db.posts.find((p) => p.id === params.id);
  if (!post) return fail(res, ...ERR.NOT_FOUND);
  if (post.status !== 'open') return fail(res, 400, 40001, '该帖子已完成认领');
  if (post.authorId === user.id) return fail(res, 400, 40001, '不能认领自己发布的帖子');
  const answer = String(body?.answer || '').trim();
  if (!answer) return fail(res, 400, 40001, '请填写物品特征以便核实');

  if (db.claims.some((c) => c.postId === post.id && c.claimantId === user.id && c.status === 'pending')) {
    return fail(res, 400, 40001, '你已提交过认领申请，等待对方处理');
  }
  const claim = {
    id: uid('cl'), postId: post.id, claimantId: user.id, claimantName: user.nickname,
    answer, status: 'pending', createdAt: nowISO(),
  };
  db.claims.push(claim);
  notify(post.authorId, 'claim', `${user.nickname} 申请认领你的帖子「${post.title}」，请核实处理`, post.id);
  saveDB();
  ok(res, claim);
});

/** 我相关认领：received = 我作为发布者收到的；sent = 我发起的 */
route('GET', '/api/claims/mine', (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const myPosts = new Set(db.posts.filter((p) => p.authorId === user.id).map((p) => p.id));
  ok(res, {
    received: db.claims.filter((c) => myPosts.has(c.postId)).map(withPost),
    sent: db.claims.filter((c) => c.claimantId === user.id).map(withPost),
  });
});
function withPost(c) {
  const post = db.posts.find((p) => p.id === c.postId);
  return { ...c, postTitle: post?.title || '(已删除)', postType: post?.type };
}

/** 处理认领：approve / reject，仅发布者或管理员 */
route('POST', '/api/claims/:id/resolve', async (req, res, params, query, body) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const claim = db.claims.find((c) => c.id === params.id);
  if (!claim) return fail(res, ...ERR.NOT_FOUND);
  const post = db.posts.find((p) => p.id === claim.postId);
  if (!post) return fail(res, ...ERR.NOT_FOUND);
  if (post.authorId !== user.id && user.role !== 'admin') return fail(res, ...ERR.FORBIDDEN);
  if (claim.status !== 'pending') return fail(res, 400, 40001, '该认领已处理过');

  const action = body?.action;
  if (action !== 'approve' && action !== 'reject') {
    return fail(res, 400, 40001, 'action 必须是 approve 或 reject');
  }
  claim.status = action === 'approve' ? 'approved' : 'rejected';
  claim.resolvedAt = nowISO();
  if (action === 'approve') {
    post.status = 'resolved';
    post.resolvedAt = nowISO();
    // 同帖其他待处理申请自动关闭
    for (const c of db.claims) {
      if (c.postId === post.id && c.id !== claim.id && c.status === 'pending') {
        c.status = 'closed';
      }
    }
    notify(claim.claimantId, 'claim', `你的认领申请已通过：「${post.title}」，请联系发布者领取`, post.id);
  } else {
    notify(claim.claimantId, 'claim', `你的认领申请未通过：「${post.title}」`, post.id);
  }
  saveDB();
  ok(res, claim);
});

/* ---------- 通知 ---------- */

route('GET', '/api/notifications', (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const list = db.notifications.filter((n) => n.userId === user.id);
  ok(res, list.slice(0, 50), { unread: list.filter((n) => !n.read).length });
});

route('POST', '/api/notifications/read', (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  for (const n of db.notifications) {
    if (n.userId === user.id) n.read = true;
  }
  saveDB();
  ok(res);
});

/* ---------- 管理员（admin 专属） ---------- */

route('GET', '/api/admin/users', (req, res, params, query) => {
  if (!requireAdmin(req, res)) return;
  const keyword = (query.get('keyword') || '').trim().toLowerCase();
  let list = db.users.map(PUBLIC_USER).reverse();
  if (keyword) {
    list = list.filter((u) => u.username.toLowerCase().includes(keyword) || u.nickname.toLowerCase().includes(keyword));
  }
  // 附带每人发帖数，方便管理页展示
  for (const u of list) u.postCount = db.posts.filter((p) => p.authorId === u.id).length;
  ok(res, list);
});

/** 用户管理：封禁/解封（status）、授权/撤销管理员（role） */
route('PATCH', '/api/admin/users/:id', async (req, res, params, query, body) => {
  const admin = requireAdmin(req, res);
  if (!admin) return;
  const target = db.users.find((u) => u.id === params.id);
  if (!target) return fail(res, ...ERR.NOT_FOUND);
  if (target.id === admin.id) return fail(res, 400, 40001, '不能操作自己的账号');

  const { status, role } = body || {};
  if (status !== undefined) {
    if (status !== 'active' && status !== 'banned') return fail(res, 400, 40001, 'status 必须是 active 或 banned');
    if (status === 'banned' && target.role === 'admin') return fail(res, 400, 40001, '不能封禁管理员账号');
    target.status = status;
    notify(target.id, 'admin', status === 'banned' ? '你的账号已被管理员封禁' : '你的账号已解除封禁');
  }
  if (role !== undefined) {
    if (role !== 'admin' && role !== 'user') return fail(res, 400, 40001, 'role 必须是 admin 或 user');
    if (role !== 'admin') {
      const adminCount = db.users.filter((u) => u.role === 'admin' && u.status === 'active').length;
      if (target.role === 'admin' && adminCount <= 1) return fail(res, 400, 40001, '至少保留一名管理员');
    }
    target.role = role;
    notify(target.id, 'admin', role === 'admin' ? '你已被授权为管理员' : '你的管理员权限已被撤销');
  }
  saveDB();
  ok(res, PUBLIC_USER(target));
});

/** 删除用户：连同其帖子/评论一并清理；不能删自己，最后一个管理员不可删 */
route('DELETE', '/api/admin/users/:id', (req, res, params) => {
  const admin = requireAdmin(req, res);
  if (!admin) return;
  const target = db.users.find((u) => u.id === params.id);
  if (!target) return fail(res, ...ERR.NOT_FOUND);
  if (target.id === admin.id) return fail(res, 400, 40001, '不能删除自己的账号');
  if (target.role === 'admin') return fail(res, 400, 40001, '请先撤销其管理员权限再删除');

  const postIds = new Set(db.posts.filter((p) => p.authorId === target.id).map((p) => p.id));
  db.posts = db.posts.filter((p) => !postIds.has(p.id));
  db.comments = db.comments.filter((c) => c.authorId !== target.id && !postIds.has(c.postId));
  db.claims = db.claims.filter((c) => c.claimantId !== target.id && !postIds.has(c.postId));
  db.notifications = db.notifications.filter((n) => n.userId !== target.id);
  db.users = db.users.filter((u) => u.id !== target.id);
  saveDB();
  ok(res, { id: target.id });
});

/** 平台统计：管理员首页仪表盘 */
route('GET', '/api/admin/stats', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const posts = db.posts;
  ok(res, {
    users: db.users.length,
    bannedUsers: db.users.filter((u) => u.status === 'banned').length,
    admins: db.users.filter((u) => u.role === 'admin').length,
    posts: posts.length,
    lost: posts.filter((p) => p.type === 'lost').length,
    found: posts.filter((p) => p.type === 'found').length,
    resolved: posts.filter((p) => p.status === 'resolved').length,
    pendingClaims: db.claims.filter((c) => c.status === 'pending').length,
    comments: db.comments.length,
  });
});

/** 待处理认领列表（管理员快速处理入口） */
route('GET', '/api/admin/claims', (req, res) => {
  if (!requireAdmin(req, res)) return;
  ok(res, db.claims.filter((c) => c.status === 'pending').map(withPost));
});

/* ============================================================
 * 静态文件：托管 预览版.html / 落地页.html
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

  // 浏览器跨域预检
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
    // 静态页：/ 与 /preview 统一进终稿应用（页面内部按设备自动分流 ——
    // PC 首页 = 落地页 1:1 复刻 + 全功能；移动端首页 = 原移动版效果）
    if (req.method === 'GET' && (pathname === '/' || pathname === '/preview')) {
      return serveStatic(res, '终稿.html');
    }
    // 终稿：预览版全量功能 × 落地页海报风 × 真后端
    if (req.method === 'GET' && (pathname === '/app' || pathname === '/final' || pathname === '/终稿.html')) {
      return serveStatic(res, '终稿.html');
    }
    if (req.method === 'GET' && pathname === '/landing') {
      return serveStatic(res, '落地页.html');
    }
    // 上传图片：URL /uploads/... 实际存放在 data/uploads/...
    if (req.method === 'GET' && pathname.startsWith('/uploads/')) {
      const safe = path.normalize(pathname).replace(/^([.][.][/\\])+/, '');
      return serveStatic(res, path.join('data', safe));
    }
    if (req.method === 'GET' && !pathname.startsWith('/api/')) {
      const safe = path.normalize(pathname).replace(/^([.][.][/\\])+/, '');
      return serveStatic(res, safe);
    }

    // API 路由匹配
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

loadDB();
server.listen(PORT, () => {
  console.log('');
  console.log('  拾光 · 校园失物招领 后端已启动');
  console.log(`  地址:     http://localhost:${PORT}`);
  console.log(`  数据文件: ${DB_FILE}`);
  console.log('');
  console.log('  管理员账号  admin   / 123456     （用户管理、删帖、统计、处理认领）');
  console.log('  用户账号    demo    / 123456     （王同学）');
  console.log('  用户账号    li      / 123456     （李同学）');
  console.log('  用户账号    zhao    / 123456     （赵同学）');
  console.log('');
  console.log('  浏览器打开 http://localhost:' + PORT + ' 可直接看前端页面');
  console.log('');
});
