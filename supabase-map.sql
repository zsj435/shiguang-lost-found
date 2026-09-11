-- ============================================================
-- 拾光 · 地图功能 —— 帖子经纬度列
-- 使用方法：SQL Editor -> New query -> 粘贴全部 -> Run
-- ============================================================

alter table public.posts add column if not exists lng double precision;
alter table public.posts add column if not exists lat double precision;
