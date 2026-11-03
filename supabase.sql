-- D.A.H. (Digital Art Hub) database setup.
-- Run this whole file in the Supabase SQL editor. It's safe to run again after an update.
--
-- Anyone can look at the wall. Posting and reporting need an account. These rules are all
-- enforced here on the server, so changing the web page can't get around them:
--   * no picture can overlap another
--   * at most 8 upload attempts per account or network per hour, to slow floods
--     (only a hash of the IP is kept, for 2 days)
--   * banned accounts can't post or report
--   * when admins remove too many of an account's pictures in a set time, it's banned automatically
--
-- Moderating happens on the site: sign in, then open the site with #admin on its address.
-- Become an admin: that page shows the one line of SQL to run.
-- Remove an admin:          delete from public.dah_account_admins where user_id = '...';
-- Change the automatic ban: update public.dah_settings set strike_limit = 3, strike_days = 7;
-- Change the report limit:  update public.dah_settings set report_limit = 3;

create table if not exists public.dah_pieces (
  id uuid primary key,
  x double precision not null,
  y double precision not null,
  w double precision not null,
  h double precision not null,
  img text not null,
  thumb text not null,
  title text not null default 'Untitled',
  artist text not null default '',
  note text not null default '',
  dl boolean not null default false,
  owner text not null,
  created_at timestamptz not null default now()
);
create index if not exists dah_pieces_x_idx on public.dah_pieces (x);
create index if not exists dah_pieces_y_idx on public.dah_pieces (y);
create index if not exists dah_pieces_created_idx on public.dah_pieces (created_at desc);
alter table public.dah_pieces enable row level security;
drop policy if exists "dah pieces are public" on public.dah_pieces;
create policy "dah pieces are public" on public.dah_pieces for select to anon, authenticated using (true);

-- Private tables: row level security with no policies, so only the functions below can touch them.
create table if not exists public.dah_claims (
  id uuid primary key default gen_random_uuid(),
  device_hash text not null,
  ip_hash text not null,
  x double precision not null, y double precision not null,
  w double precision not null, h double precision not null,
  img text not null, thumb text not null,
  title text not null, artist text not null, note text not null, dl boolean not null,
  published boolean not null default false,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null
);
create index if not exists dah_claims_device_idx on public.dah_claims (device_hash, created_at desc);
create index if not exists dah_claims_ip_idx on public.dah_claims (ip_hash, created_at desc);
create index if not exists dah_claims_created_idx on public.dah_claims (created_at);
alter table public.dah_claims enable row level security;

create table if not exists public.dah_hidden (
  id uuid primary key,
  piece jsonb not null,
  hidden_at timestamptz not null default now()
);
alter table public.dah_hidden enable row level security;

create table if not exists public.dah_reports (
  piece_id uuid not null,
  device_hash text not null,
  ip_hash text not null,
  created_at timestamptz not null default now(),
  primary key (piece_id, device_hash)
);
alter table public.dah_reports enable row level security;

create table if not exists public.dah_admins (
  device_hash text primary key,
  created_at timestamptz not null default now()
);
alter table public.dah_admins enable row level security;

create table if not exists public.dah_trash (
  path text primary key,
  created_at timestamptz not null default now()
);
alter table public.dah_trash enable row level security;

-- Image storage: public to read, and uploads only work for an active claim.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('dah', 'dah', true, 10485760, array['image/png','image/jpeg','image/gif','image/webp'])
on conflict (id) do update set public = true, file_size_limit = 10485760,
  allowed_mime_types = array['image/png','image/jpeg','image/gif','image/webp'];

-- Accounts and moderation.
create table if not exists public.dah_profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  username text not null,
  created_at timestamptz not null default now()
);
create unique index if not exists dah_profiles_username_idx on public.dah_profiles (lower(username));
alter table public.dah_profiles enable row level security;

create table if not exists public.dah_account_admins (
  user_id uuid primary key references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);
alter table public.dah_account_admins enable row level security;

create table if not exists public.dah_bans (
  user_id uuid primary key references auth.users(id) on delete cascade,
  reason text not null default '',
  automatic boolean not null default false,
  created_at timestamptz not null default now()
);
alter table public.dah_bans enable row level security;

create table if not exists public.dah_strikes (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  piece_id uuid not null,
  created_at timestamptz not null default now()
);
create index if not exists dah_strikes_user_idx on public.dah_strikes (user_id, created_at desc);
alter table public.dah_strikes enable row level security;

-- Change these with the update line at the top of this file.
create table if not exists public.dah_settings (
  id integer primary key default 1 check (id = 1),
  strike_limit integer not null default 3,
  strike_days integer not null default 7,
  report_limit integer not null default 3
);
insert into public.dah_settings (id) values (1) on conflict (id) do nothing;
alter table public.dah_settings enable row level security;

-- Removes the no-account functions and browser-based admin list from earlier versions.
drop function if exists public.dah_claim(text, double precision, double precision, double precision, double precision, text, text, text, text, text, boolean);
drop function if exists public.dah_publish(uuid, text);
drop function if exists public.dah_take_down(uuid, text);
drop function if exists public.dah_set_download(uuid, text, boolean);
drop function if exists public.dah_report(uuid, text);
drop function if exists public.dah_is_admin(text);
drop function if exists public.dah_restore(uuid);
drop function if exists public.dah_device(text);
drop table if exists public.dah_admins;

create or replace function public.dah_hash(t text) returns text
language sql immutable set search_path = '' as $$
  select encode(pg_catalog.sha256(pg_catalog.convert_to(t, 'UTF8')), 'hex')
$$;

create or replace function public.dah_ip() returns text
language plpgsql stable set search_path = '' as $$
declare h json; ip text;
begin
  begin h := nullif(current_setting('request.headers', true), '')::json;
  exception when others then h := null; end;
  ip := coalesce(h->>'cf-connecting-ip', split_part(coalesce(h->>'x-forwarded-for', ''), ',', 1));
  return public.dah_hash('dah-network:' || coalesce(nullif(trim(ip), ''), 'unknown'));
end $$;

create or replace function public.dah_is_admin_user(p_user uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.dah_account_admins a where a.user_id = p_user)
$$;

-- The signed-in person, or an error. Banned accounts can look around but not post.
create or replace function public.dah_user(p_allow_banned boolean default false) returns uuid
language plpgsql stable security definer set search_path = '' as $$
declare u uuid := auth.uid();
begin
  if u is null or coalesce(auth.jwt()->>'is_anonymous', 'false') = 'true' then raise exception 'DAH:signin'; end if;
  if not p_allow_banned and exists (select 1 from public.dah_bans b where b.user_id = u) then raise exception 'DAH:banned'; end if;
  return u;
end $$;

create or replace function public.dah_require_admin() returns uuid
language plpgsql stable security definer set search_path = '' as $$
declare u uuid := public.dah_user(true);
begin
  if not public.dah_is_admin_user(u) then raise exception 'DAH:notadmin'; end if;
  return u;
end $$;

create or replace function public.dah_profile_name(p_user uuid) returns text
language plpgsql security definer set search_path = '' as $$
declare n text; base text; tries integer := 0; candidate text;
begin
  select username into n from public.dah_profiles where user_id = p_user;
  if found then return n; end if;
  select left(regexp_replace(coalesce(raw_user_meta_data->>'username', ''), '[^a-zA-Z0-9_]', '', 'g'), 24) into base
    from auth.users where id = p_user;
  if base is null or length(base) < 3 then base := 'artist'; end if;
  candidate := base;
  while exists (select 1 from public.dah_profiles where lower(username) = lower(candidate)) loop
    tries := tries + 1;
    candidate := left(base, 18) || floor(random() * 100000)::int::text;
    if tries > 20 then raise exception 'DAH:invalid'; end if;
  end loop;
  insert into public.dah_profiles (user_id, username) values (p_user, candidate);
  return candidate;
end $$;

-- Whether a username is available, shown while someone signs up.
create or replace function public.dah_username_free(p_name text) returns boolean
language sql stable security definer set search_path = '' as $$
  select not exists (select 1 from public.dah_profiles where lower(username) = lower(p_name))
$$;

create or replace function public.dah_me() returns json
language plpgsql security definer set search_path = '' as $$
declare u uuid := public.dah_user(true); b public.dah_bans; n text := public.dah_profile_name(u);
begin
  select * into b from public.dah_bans where user_id = u;
  return json_build_object('id', u, 'username', n, 'admin', public.dah_is_admin_user(u),
    'banned', b.user_id is not null, 'reason', coalesce(b.reason, ''));
end $$;

-- Counts one picture removed by an admin. Enough of them in the time window bans the account.
create or replace function public.dah_strike(p_owner text, p_piece uuid) returns boolean
language plpgsql security definer set search_path = '' as $$
declare u uuid; s public.dah_settings;
begin
  if p_owner !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' then return false; end if;
  u := p_owner::uuid;
  if not exists (select 1 from auth.users where id = u) or public.dah_is_admin_user(u) then return false; end if;
  insert into public.dah_strikes (user_id, piece_id) values (u, p_piece);
  select * into s from public.dah_settings where id = 1;
  if (select count(*) from public.dah_strikes where user_id = u
      and created_at > now() - make_interval(days => s.strike_days)) >= s.strike_limit then
    insert into public.dah_bans (user_id, reason, automatic)
    values (u, s.strike_limit || ' pictures removed within ' || s.strike_days || ' days', true)
    on conflict (user_id) do nothing;
    return true;
  end if;
  return false;
end $$;

create or replace function public.dah_trash_paths(p_img text, p_thumb text) returns text[]
language plpgsql security definer set search_path = '' as $$
declare paths text[] := case when p_img = p_thumb then array[p_img] else array[p_img, p_thumb] end;
begin
  insert into public.dah_trash (path) select unnest(paths) on conflict do nothing;
  return paths;
end $$;

create or replace function public.dah_claim(
  p_x double precision, p_y double precision, p_w double precision, p_h double precision,
  p_img_ext text, p_thumb_ext text, p_title text, p_note text, p_dl boolean
) returns json
language plpgsql security definer set search_path = '' as $$
declare u uuid := public.dah_user(); who text := u::text; ip text := public.dah_ip();
  name text := public.dah_profile_name(u); cid uuid := gen_random_uuid(); img text; thumb text;
begin
  if p_x is null or p_y is null or abs(p_x) > 9e15 or abs(p_y) > 9e15
     or p_w is null or p_h is null or p_w < 8 or p_w > 2000 or p_h < 8 or p_h > 2000
     or p_img_ext is null or p_img_ext not in ('png','jpg','gif','webp')
     or (p_thumb_ext is not null and p_thumb_ext not in ('png','jpg','gif','webp')) then
    raise exception 'DAH:invalid';
  end if;
  -- One claim at a time across the wall, so two people can't take the same spot.
  perform pg_advisory_xact_lock(727001);
  delete from public.dah_claims where created_at < now() - interval '2 days';
  delete from public.dah_trash where created_at < now() - interval '2 days';
  if (select count(*) from public.dah_claims where (ip_hash = ip or device_hash = who) and created_at > now() - interval '1 hour') >= 8 then
    raise exception 'DAH:slow';
  end if;
  if (select count(*) from public.dah_claims where created_at > now() - interval '1 hour') >= 500 then
    raise exception 'DAH:busy';
  end if;
  update public.dah_claims set expires_at = now() where device_hash = who and not published and expires_at > now();
  if exists (select 1 from public.dah_pieces p
      where p.x between p_x - 1100 - p_w/2 and p_x + 1100 + p_w/2
        and abs(p.x - p_x) < (p.w + p_w)/2 + 12 and abs(p.y - p_y) < (p.h + p_h)/2 + 36)
     or exists (select 1 from public.dah_claims c
      where not c.published and c.expires_at > now()
        and abs(c.x - p_x) < (c.w + p_w)/2 + 12 and abs(c.y - p_y) < (c.h + p_h)/2 + 36) then
    raise exception 'DAH:overlap';
  end if;
  img := cid::text || '/full.' || p_img_ext;
  thumb := case when p_thumb_ext is null then img else cid::text || '/thumb.' || p_thumb_ext end;
  insert into public.dah_claims (id, device_hash, ip_hash, x, y, w, h, img, thumb, title, artist, note, dl, expires_at)
  values (cid, who, ip, p_x, p_y, p_w, p_h, img, thumb,
    coalesce(nullif(left(trim(p_title), 120), ''), 'Untitled'), name,
    left(trim(coalesce(p_note, '')), 600), coalesce(p_dl, false), now() + interval '10 minutes');
  return json_build_object('claim', cid, 'img', img, 'thumb', thumb);
end $$;

create or replace function public.dah_upload_ok(p_name text) returns boolean
language sql stable security definer set search_path = '' as $$
  select auth.uid() is not null
    and not exists (select 1 from public.dah_bans b where b.user_id = auth.uid())
    and exists (select 1 from public.dah_claims c
      where c.device_hash = auth.uid()::text and not c.published and c.expires_at > now()
        and (c.img = p_name or c.thumb = p_name))
$$;

create or replace function public.dah_trash_ok(p_name text) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.dah_trash t where t.path = p_name)
$$;

create or replace function public.dah_publish(p_claim uuid) returns json
language plpgsql security definer set search_path = '' as $$
declare u uuid := public.dah_user(); c public.dah_claims; r public.dah_pieces;
begin
  perform pg_advisory_xact_lock(727001);
  select * into c from public.dah_claims
    where id = p_claim and device_hash = u::text and not published and expires_at > now();
  if not found then raise exception 'DAH:expired'; end if;
  if not exists (select 1 from storage.objects o where o.bucket_id = 'dah' and o.name = c.img)
     or not exists (select 1 from storage.objects o where o.bucket_id = 'dah' and o.name = c.thumb) then
    raise exception 'DAH:noimage';
  end if;
  insert into public.dah_pieces (id, x, y, w, h, img, thumb, title, artist, note, dl, owner)
  values (c.id, c.x, c.y, c.w, c.h, c.img, c.thumb, c.title, c.artist, c.note, c.dl, u::text)
  returning * into r;
  update public.dah_claims set published = true where id = c.id;
  return to_json(r);
end $$;

-- Your own picture, or anyone's if you're an admin. An admin removing someone else's counts toward a ban.
create or replace function public.dah_take_down(p_id uuid) returns json
language plpgsql security definer set search_path = '' as $$
declare u uuid := public.dah_user(true); r public.dah_pieces; admin boolean := public.dah_is_admin_user(u);
  banned boolean := false; paths text[];
begin
  select * into r from public.dah_pieces where id = p_id;
  if not found then raise exception 'DAH:notfound'; end if;
  if r.owner <> u::text and not admin then raise exception 'DAH:notyours'; end if;
  delete from public.dah_pieces where id = p_id;
  paths := public.dah_trash_paths(r.img, r.thumb);
  if r.owner <> u::text then banned := public.dah_strike(r.owner, r.id); end if;
  return json_build_object('paths', paths, 'banned', banned);
end $$;

create or replace function public.dah_set_download(p_id uuid, p_dl boolean) returns void
language plpgsql security definer set search_path = '' as $$
begin
  update public.dah_pieces set dl = coalesce(p_dl, false) where id = p_id and owner = public.dah_user()::text;
  if not found then raise exception 'DAH:notyours'; end if;
end $$;

-- Reports from enough different accounts hide a picture until an admin reviews it.
create or replace function public.dah_report(p_id uuid) returns boolean
language plpgsql security definer set search_path = '' as $$
declare u uuid := public.dah_user(); r public.dah_pieces;
begin
  select * into r from public.dah_pieces where id = p_id;
  if not found or r.owner = u::text then return false; end if;
  insert into public.dah_reports (piece_id, device_hash, ip_hash) values (p_id, u::text, public.dah_ip()) on conflict do nothing;
  if (select count(distinct device_hash) from public.dah_reports where piece_id = p_id)
     >= (select report_limit from public.dah_settings where id = 1) then
    insert into public.dah_hidden (id, piece) values (r.id, to_jsonb(r)) on conflict (id) do nothing;
    delete from public.dah_pieces where id = p_id;
    return true;
  end if;
  return false;
end $$;

create or replace function public.dah_admin_ban(p_user uuid, p_reason text, p_remove boolean) returns text[]
language plpgsql security definer set search_path = '' as $$
declare paths text[] := '{}'; r public.dah_pieces; h public.dah_hidden;
begin
  perform public.dah_require_admin();
  if public.dah_is_admin_user(p_user) then raise exception 'DAH:banadmin'; end if;
  insert into public.dah_bans (user_id, reason) values (p_user, left(trim(coalesce(p_reason, '')), 200))
    on conflict (user_id) do update set reason = excluded.reason, automatic = false;
  if p_remove then
    for r in delete from public.dah_pieces where owner = p_user::text returning * loop
      paths := paths || public.dah_trash_paths(r.img, r.thumb);
    end loop;
    for h in delete from public.dah_hidden where piece->>'owner' = p_user::text returning * loop
      paths := paths || public.dah_trash_paths(h.piece->>'img', h.piece->>'thumb');
    end loop;
  end if;
  return paths;
end $$;

-- Unbanning clears past removals too, otherwise the next removal would ban the account again.
create or replace function public.dah_admin_unban(p_user uuid) returns void
language plpgsql security definer set search_path = '' as $$
begin
  perform public.dah_require_admin();
  delete from public.dah_bans where user_id = p_user;
  delete from public.dah_strikes where user_id = p_user;
end $$;

create or replace function public.dah_admin_queue() returns json
language plpgsql stable security definer set search_path = '' as $$
begin
  perform public.dah_require_admin();
  return json_build_object(
    'hidden', coalesce((select json_agg(q) from (select h.id, h.piece, h.hidden_at from public.dah_hidden h order by h.hidden_at desc limit 100) q), '[]'::json),
    'bans', coalesce((select json_agg(q) from (select b.user_id, coalesce(p.username, 'Unknown') as username, b.reason, b.automatic, b.created_at
        from public.dah_bans b left join public.dah_profiles p on p.user_id = b.user_id order by b.created_at desc limit 200) q), '[]'::json));
end $$;

-- Restore a hidden picture, or remove it for good, which counts toward a ban.
create or replace function public.dah_admin_review(p_id uuid, p_keep boolean) returns json
language plpgsql security definer set search_path = '' as $$
declare h public.dah_hidden; paths text[] := '{}'; banned boolean := false;
begin
  perform public.dah_require_admin();
  delete from public.dah_hidden where id = p_id returning * into h;
  if not found then raise exception 'DAH:notfound'; end if;
  delete from public.dah_reports where piece_id = p_id;
  if p_keep then
    insert into public.dah_pieces select * from jsonb_populate_record(null::public.dah_pieces, h.piece);
  else
    paths := public.dah_trash_paths(h.piece->>'img', h.piece->>'thumb');
    banned := public.dah_strike(h.piece->>'owner', p_id);
  end if;
  return json_build_object('paths', paths, 'banned', banned);
end $$;

do $$
declare f text;
begin
  foreach f in array array[
    'public.dah_hash(text)', 'public.dah_ip()', 'public.dah_is_admin_user(uuid)', 'public.dah_user(boolean)',
    'public.dah_require_admin()', 'public.dah_profile_name(uuid)', 'public.dah_strike(text, uuid)', 'public.dah_trash_paths(text, text)'
  ] loop
    execute 'revoke all on function ' || f || ' from public, anon, authenticated';
  end loop;
  foreach f in array array[
    'public.dah_me()', 'public.dah_upload_ok(text)', 'public.dah_trash_ok(text)',
    'public.dah_claim(double precision, double precision, double precision, double precision, text, text, text, text, boolean)',
    'public.dah_publish(uuid)', 'public.dah_take_down(uuid)', 'public.dah_set_download(uuid, boolean)', 'public.dah_report(uuid)',
    'public.dah_admin_ban(uuid, text, boolean)', 'public.dah_admin_unban(uuid)', 'public.dah_admin_queue()', 'public.dah_admin_review(uuid, boolean)'
  ] loop
    execute 'revoke all on function ' || f || ' from public, anon';
    execute 'grant execute on function ' || f || ' to authenticated';
  end loop;
  execute 'revoke all on function public.dah_username_free(text) from public';
  execute 'grant execute on function public.dah_username_free(text) to anon, authenticated';
end $$;
grant select on public.dah_pieces to anon, authenticated;
revoke insert, update, delete, truncate on public.dah_pieces from anon, authenticated;

drop policy if exists "dah upload for active claim" on storage.objects;
create policy "dah upload for active claim" on storage.objects for insert to authenticated
  with check (bucket_id = 'dah' and public.dah_upload_ok(name));
drop policy if exists "dah see trashed" on storage.objects;
create policy "dah see trashed" on storage.objects for select to authenticated
  using (bucket_id = 'dah' and public.dah_trash_ok(name));
drop policy if exists "dah delete trashed" on storage.objects;
create policy "dah delete trashed" on storage.objects for delete to authenticated
  using (bucket_id = 'dah' and public.dah_trash_ok(name));

-- Live updates for everyone looking at the wall.
do $$ begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime'
                     and schemaname = 'public' and tablename = 'dah_pieces') then
    alter publication supabase_realtime add table public.dah_pieces;
  end if;
end $$;
