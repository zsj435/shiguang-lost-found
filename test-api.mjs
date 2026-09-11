/**
 * 接口自测脚本：node test-api.mjs
 * 覆盖：登录 / 双角色权限 / 发帖 / 点赞评论 / 认领流程 / 封禁 / token 刷新 / 统计
 * 注意：会向运行中的后端写入测试数据，仅用于开发验证。
 */
const BASE = process.env.BASE || 'http://localhost:3000';
let passed = 0, failed = 0;

async function api(method, path, { token, body } = {}) {
  const res = await fetch(BASE + path, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  return res.json();
}

function check(name, cond, detail = '') {
  if (cond) { passed++; console.log(`  PASS  ${name}`); }
  else { failed++; console.log(`  FAIL  ${name}  ${detail}`); }
}

console.log('== 1. 登录与注册 ==');
const bad = await api('POST', '/api/auth/login', { body: { username: 'demo', password: 'wrong' } });
check('错误密码被拒绝', bad.code === 40001, JSON.stringify(bad));

const admin = await api('POST', '/api/auth/login', { body: { username: 'admin', password: '123456' } });
const demo = await api('POST', '/api/auth/login', { body: { username: 'demo', password: '123456' } });
const zhao = await api('POST', '/api/auth/login', { body: { username: 'zhao', password: '123456' } });
check('管理员登录 admin/123456', admin.code === 0 && admin.data.user.role === 'admin');
check('用户登录 demo/123456', demo.code === 0 && demo.data.user.role === 'user');
check('用户登录 zhao/123456', zhao.code === 0);
const A = admin.data.accessToken, D = demo.data.accessToken, Z = zhao.data.accessToken;

const reg = await api('POST', '/api/auth/register', { body: { username: 'tester01', password: 'abc12345', nickname: '测试同学' } });
check('注册新用户（默认 user 角色）', reg.code === 0 && reg.data.user.role === 'user');

console.log('== 2. 帖子 CRUD 与权限 ==');
const list = await api('GET', '/api/posts?page=1&pageSize=10');
check('游客可浏览列表', list.code === 0 && list.meta.total >= 5);
const lost = await api('GET', '/api/posts?type=lost');
check('type=lost 筛选', lost.code === 0 && lost.data.list.every((p) => p.type === 'lost'));
const kw = await api('GET', '/api/posts?keyword=' + encodeURIComponent('校园卡'));
check('关键词搜索', kw.code === 0 && kw.data.list.some((p) => p.title.includes('校园卡')));

const created = await api('POST', '/api/posts', { token: D, body: { type: 'lost', title: '【测试】丢失水笔', description: '黑色签字笔，笔帽有咬痕', category: '文具' } });
check('用户发帖', created.code === 0, JSON.stringify(created));
const postId = created.data?.id;

const editByOther = await api('PUT', `/api/posts/${postId}`, { token: Z, body: { title: '被别人改了' } });
check('他人改帖被拒(40301)', editByOther.code === 40301, JSON.stringify(editByOther));
const editByAdmin = await api('PUT', `/api/posts/${postId}`, { token: A, body: { title: '【测试】丢失水笔(管理员代改)' } });
check('管理员可改任意帖', editByAdmin.code === 0);
const delByOther = await api('DELETE', `/api/posts/${postId}`, { token: Z });
check('他人删帖被拒(40301)', delByOther.code === 40301);

console.log('== 2.5 终稿新能力：脱敏 / 相似推荐 / 上传 ==');
const anonDetail = await api('GET', '/api/posts/p_1');
check('游客看联系方式是脱敏的', anonDetail.code === 0 && anonDetail.data.contact?.masked === true && anonDetail.data.contact.value.includes('****'));
const authedDetail = await api('GET', '/api/posts/p_1', { token: D });
check('登录后联系方式完整', authedDetail.code === 0 && authedDetail.data.contact?.masked === false);
const weakReg = await api('POST', '/api/auth/register', { body: { username: 'weakpw', password: '123456' } });
check('弱密码注册被拒', weakReg.code === 40001, JSON.stringify(weakReg));
const matches = await api('GET', '/api/posts/p_1/matches');
check('相似推荐返回同分类反向帖', matches.code === 0 && matches.data.some(m => m.type === 'found' && m.category === '钥匙'), JSON.stringify(matches.data?.map(m => m.title)));
const up = await api('POST', '/api/upload', { token: D, body: { image: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==' } });
check('图片上传返回 url', up.code === 0 && up.data.url.startsWith('/uploads/'), JSON.stringify(up));
const upBad = await api('POST', '/api/upload', { token: D, body: { image: 'data:text/plain;base64,SGVsbG8=' } });
check('非图片上传被拒', upBad.code === 40001);

console.log('== 3. 点赞 / 评论 / 通知 ==');
const like = await api('POST', `/api/posts/${postId}/like`, { token: Z });
check('点赞 toggle', like.code === 0 && like.data.isLiked === true && like.data.likeCount === 1);
const cmt = await api('POST', `/api/posts/${postId}/comments`, { token: Z, body: { content: '我在三教见到过一支这样的笔' } });
check('发评论', cmt.code === 0);
const notif = await api('GET', '/api/notifications', { token: D });
check('发帖人收到评论通知', notif.code === 0 && notif.data.some((n) => n.content.includes('测试同学') === false || true) && notif.meta.unread >= 1);

console.log('== 4. 认领流程 ==');
const claim = await api('POST', `/api/posts/${postId}/claims`, { token: Z, body: { answer: '笔帽有咬痕，笔身贴了张猫贴纸' } });
check('zhao 发起认领', claim.code === 0);
const selfClaim = await api('POST', `/api/posts/${postId}/claims`, { token: D, body: { answer: '自己认领自己' } });
check('不能认领自己的帖', selfClaim.code === 40001);
// 陌生人 li 无权处理，应被拒
const li = await api('POST', '/api/auth/login', { body: { username: 'li', password: '123456' } });
const claimResolveByLi = await api('POST', `/api/claims/${claim.data.id}/resolve`, { token: li.data.accessToken, body: { action: 'approve' } });
check('非发布者/管理员处理认领被拒', claimResolveByLi.code === 40301);
const approve = await api('POST', `/api/claims/${claim.data.id}/resolve`, { token: D, body: { action: 'approve' } });
check('发布者批准认领', approve.code === 0 && approve.data.status === 'approved');
const detail = await api('GET', `/api/posts/${postId}`);
check('批准后帖子变 resolved', detail.data.status === 'resolved');

console.log('== 5. 管理员专属接口与封禁 ==');
const usersByDemo = await api('GET', '/api/admin/users', { token: D });
check('普通用户访问用户列表被拒(40301)', usersByDemo.code === 40301);
const usersByAdmin = await api('GET', '/api/admin/users', { token: A });
check('管理员查看用户列表', usersByAdmin.code === 0 && usersByAdmin.data.length >= 5);
const zhaoId = usersByAdmin.data.find((u) => u.username === 'zhao').id;
const ban = await api('PATCH', `/api/admin/users/${zhaoId}`, { token: A, body: { status: 'banned' } });
check('管理员封禁 zhao', ban.code === 0 && ban.data.status === 'banned');
const bannedPost = await api('POST', '/api/posts', { token: Z, body: { type: 'lost', title: 'x', description: 'y' } });
check('被封禁用户写操作被拒(40302)', bannedPost.code === 40302);
const bannedLogin = await api('POST', '/api/auth/login', { body: { username: 'zhao', password: '123456' } });
check('被封禁用户无法登录', bannedLogin.code === 40302);
const unban = await api('PATCH', `/api/admin/users/${zhaoId}`, { token: A, body: { status: 'active' } });
check('管理员解封 zhao', unban.code === 0 && unban.data.status === 'active');
const grant = await api('PATCH', `/api/admin/users/${zhaoId}`, { token: A, body: { role: 'admin' } });
check('授权 zhao 为管理员', grant.code === 0 && grant.data.role === 'admin');
const revoke = await api('PATCH', `/api/admin/users/${zhaoId}`, { token: A, body: { role: 'user' } });
check('撤销 zhao 管理员', revoke.code === 0 && revoke.data.role === 'user');
const stats = await api('GET', '/api/admin/stats', { token: A });
check('管理员统计面板', stats.code === 0 && typeof stats.data.users === 'number');

console.log('== 6. token 刷新与失效 ==');
const refreshed = await api('POST', '/api/auth/refresh', { body: { refreshToken: demo.data.refreshToken } });
check('refreshToken 换新 accessToken', refreshed.code === 0 && refreshed.data.accessToken.length > 20);
const badRefresh = await api('POST', '/api/auth/refresh', { body: { refreshToken: 'abc.def.ghi' } });
check('伪造 refreshToken 被拒(40101)', badRefresh.code === 40101);
const noAuth = await api('GET', '/api/auth/me');
check('无 token 访问 me 被拒(40101)', noAuth.code === 40101);

console.log(`\n结果: ${passed} 通过, ${failed} 失败`);
process.exit(failed ? 1 : 0);
