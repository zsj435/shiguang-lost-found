-- ============================================================
-- 拾光 · 行为统计系统 —— Supabase 增量初始化
-- 使用方法：SQL Editor -> New query -> 粘贴全部 -> Run
-- ============================================================

-- 1) 行为事件表（页面浏览 PV / 访客心跳 / 首页滚动深度）
create table if not exists public.track_events (
  id         bigserial primary key,
  client_id  text not null,                  -- 访客设备ID（未注册也有）
  sid        text not null default '',       -- 会话ID
  user_id    uuid,                           -- 登录用户的资料ID（可为空）
  page       text not null default '',       -- 页面：home / admin / post / ...
  event      text not null,                  -- page_view / heartbeat / home_scroll_80
  created_at timestamptz not null default now()
);
create index if not exists idx_track_created on public.track_events (created_at);
create index if not exists idx_track_client  on public.track_events (client_id, created_at);
create index if not exists idx_track_event   on public.track_events (event, created_at);

-- 2) 用户表补充：注册时的设备ID（用于把"注册用户"和"访客行为"关联起来算留存）
alter table public.profiles add column if not exists client_id text not null default '';

-- 3) 与其他表一致：开启 RLS（后端服务密钥访问，前端匿名不可读写）
alter table public.track_events enable row level security;
