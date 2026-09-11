-- ============================================================
-- 拾光 · 校园失物招领 —— Supabase 初始化脚本
-- 使用方法：Supabase 控制台左侧 SQL Editor -> New query ->
--           粘贴本文件全部内容 -> 点 Run（右下角）
-- 说明：只建表结构，不写数据；演示数据由后端首次启动自动播种
-- ============================================================

-- 1) 用户资料表（关联 Supabase Auth 的 auth.users）
create table if not exists public.profiles (
  id          uuid primary key references auth.users(id) on delete cascade,
  phone       text unique not null,
  nickname    text not null default '',
  role        text not null default 'user' check (role in ('user','admin')),
  status      text not null default 'active' check (status in ('active','banned')),
  student_id  text not null default '',
  created_at  timestamptz not null default now()
);

-- 2) 帖子表（寻物 lost / 招领 found）
create table if not exists public.posts (
  id              text primary key,
  type            text not null check (type in ('lost','found')),
  title           text not null,
  description     text not null default '',
  category        text not null default '',
  location        text not null default '',
  location_detail text not null default '',
  event_time      timestamptz,
  contact         jsonb,
  images          jsonb not null default '[]',
  tags            jsonb not null default '[]',
  status          text not null default 'open' check (status in ('open','resolved')),
  author_id       uuid not null references auth.users(id) on delete cascade,
  author_name     text not null default '',
  liked_by        jsonb not null default '[]',
  view_count      int not null default 0,
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now(),
  resolved_at     timestamptz
);

-- 3) 评论表
create table if not exists public.comments (
  id          text primary key,
  post_id     text not null references public.posts(id) on delete cascade,
  author_id   uuid not null references auth.users(id) on delete cascade,
  author_name text not null default '',
  content     text not null,
  reply_to    jsonb,
  created_at  timestamptz not null default now()
);

-- 4) 通知表
create table if not exists public.notifications (
  id         text primary key,
  user_id    uuid not null references auth.users(id) on delete cascade,
  type       text not null,
  content    text not null,
  post_id    text,
  read       boolean not null default false,
  created_at timestamptz not null default now()
);

-- 5) 认领表
create table if not exists public.claims (
  id            text primary key,
  post_id       text not null references public.posts(id) on delete cascade,
  claimant_id   uuid not null references auth.users(id) on delete cascade,
  claimant_name text not null default '',
  answer        text not null default '',
  status        text not null default 'pending' check (status in ('pending','approved','rejected','closed')),
  created_at    timestamptz not null default now(),
  resolved_at   timestamptz
);

-- 6) 索引（列表/筛选查询加速）
create index if not exists idx_posts_created  on public.posts (created_at desc);
create index if not exists idx_posts_type     on public.posts (type, status);
create index if not exists idx_posts_author   on public.posts (author_id);
create index if not exists idx_comments_post  on public.comments (post_id, created_at);
create index if not exists idx_notif_user     on public.notifications (user_id, created_at desc);
create index if not exists idx_claims_post    on public.claims (post_id);
create index if not exists idx_claims_claimant on public.claims (claimant_id);

-- 7) 行级安全：全表开启 RLS 且不建任何策略。
--    后端使用服务端密钥访问（自动绕过 RLS），匿名/前端直连将无法读写任何数据 —— 双保险。
alter table public.profiles      enable row level security;
alter table public.posts         enable row level security;
alter table public.comments      enable row level security;
alter table public.notifications enable row level security;
alter table public.claims        enable row level security;
