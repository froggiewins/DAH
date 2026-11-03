-- D.A.H. (Digital Art Hub) database setup.
-- Run this whole file once in the Supabase SQL editor. It's safe to run again after an update.
--
-- Visitors have no accounts. Each browser keeps a random secret ("device") and every rule
-- below is enforced here on the server, so changing the web page can't get around them:
--   * at most 8 upload attempts per network per hour, to slow floods
--     (only a hash of the IP is kept, for 2 days)
--   * no picture can overlap another
--
-- Moderating, in the SQL editor:
--   Remove a picture:   delete from public.dah_pieces where id = '...';
--   See auto-hidden:    select * from public.dah_hidden order by hidden_at desc;
--   Restore one:        select public.dah_restore('...');
--   Pictures reach dah_hidden after reports from 3 different networks.

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

create or replace function public.dah_hash(t text) returns text
language sql immutable set search_path = '' as $$
  select encode(pg_catalog.sha256(pg_catalog.convert_to(t, 'UTF8')), 'hex')
$$;

create or replace function public.dah_device(p_device text) returns text
language plpgsql immutable set search_path = '' as $$
begin
  if p_device is null or p_device !~ '^[0-9a-f]{32,64}$' then raise exception 'DAH:invalid'; end if;
  return public.dah_hash(p_device);
end $$;

create or replace function public.dah_ip() returns text
language plpgsql stable set search_path = '' as $$
declare h json; ip text;
begin
  begin h := nullif(current_setting('request.headers', true), '')::json;
  exception when others then h := null; end;
  ip := coalesce(h->>'cf-connecting-ip', split_part(coalesce(h->>'x-forwarded-for', ''), ',', 1));
  return public.dah_hash('dah-network:' || coalesce(nullif(trim(ip), ''), 'unknown'));
end $$;

-- Removes the old daily limit when this file is run over an earlier version.
drop function if exists public.dah_status(text);
drop function if exists public.dah_wait_for(text, text);

create or replace function public.dah_claim(
  p_device text, p_x double precision, p_y double precision, p_w double precision, p_h double precision,
  p_img_ext text, p_thumb_ext text, p_title text, p_artist text, p_note text, p_dl boolean
) returns json
language plpgsql security definer set search_path = '' as $$
declare dh text := public.dah_device(p_device); ip text := public.dah_ip();
  cid uuid := gen_random_uuid(); img text; thumb text;
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
  if (select count(*) from public.dah_claims where ip_hash = ip and created_at > now() - interval '1 hour') >= 8 then
    raise exception 'DAH:slow';
  end if;
  if (select count(*) from public.dah_claims where created_at > now() - interval '1 hour') >= 500 then
    raise exception 'DAH:busy';
  end if;
  update public.dah_claims set expires_at = now() where device_hash = dh and not published and expires_at > now();
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
  values (cid, dh, ip, p_x, p_y, p_w, p_h, img, thumb,
    coalesce(nullif(left(trim(p_title), 120), ''), 'Untitled'), left(trim(coalesce(p_artist, '')), 80),
    left(trim(coalesce(p_note, '')), 600), coalesce(p_dl, false), now() + interval '10 minutes');
  return json_build_object('claim', cid, 'img', img, 'thumb', thumb);
end $$;

create or replace function public.dah_upload_ok(p_name text) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.dah_claims c
    where not c.published and c.expires_at > now() and (c.img = p_name or c.thumb = p_name))
$$;

create or replace function public.dah_trash_ok(p_name text) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.dah_trash t where t.path = p_name)
$$;

create or replace function public.dah_publish(p_claim uuid, p_device text) returns json
language plpgsql security definer set search_path = '' as $$
declare dh text := public.dah_device(p_device); c public.dah_claims; r public.dah_pieces;
begin
  perform pg_advisory_xact_lock(727001);
  select * into c from public.dah_claims
    where id = p_claim and device_hash = dh and not published and expires_at > now();
  if not found then raise exception 'DAH:expired'; end if;
  if not exists (select 1 from storage.objects o where o.bucket_id = 'dah' and o.name = c.img)
     or not exists (select 1 from storage.objects o where o.bucket_id = 'dah' and o.name = c.thumb) then
    raise exception 'DAH:noimage';
  end if;
  insert into public.dah_pieces (id, x, y, w, h, img, thumb, title, artist, note, dl, owner)
  values (c.id, c.x, c.y, c.w, c.h, c.img, c.thumb, c.title, c.artist, c.note, c.dl, dh)
  returning * into r;
  update public.dah_claims set published = true where id = c.id;
  return to_json(r);
end $$;

create or replace function public.dah_take_down(p_id uuid, p_device text) returns text[]
language plpgsql security definer set search_path = '' as $$
declare dh text := public.dah_device(p_device); r public.dah_pieces; paths text[];
begin
  delete from public.dah_pieces where id = p_id and owner = dh returning * into r;
  if not found then raise exception 'DAH:notyours'; end if;
  paths := case when r.img = r.thumb then array[r.img] else array[r.img, r.thumb] end;
  insert into public.dah_trash (path) select unnest(paths) on conflict do nothing;
  return paths;
end $$;

create or replace function public.dah_set_download(p_id uuid, p_device text, p_dl boolean) returns void
language plpgsql security definer set search_path = '' as $$
begin
  update public.dah_pieces set dl = coalesce(p_dl, false) where id = p_id and owner = public.dah_device(p_device);
  if not found then raise exception 'DAH:notyours'; end if;
end $$;

create or replace function public.dah_report(p_id uuid, p_device text) returns boolean
language plpgsql security definer set search_path = '' as $$
declare dh text := public.dah_device(p_device); ip text := public.dah_ip(); r public.dah_pieces;
begin
  select * into r from public.dah_pieces where id = p_id;
  if not found or r.owner = dh then return false; end if;
  insert into public.dah_reports (piece_id, device_hash, ip_hash) values (p_id, dh, ip) on conflict do nothing;
  if (select count(distinct ip_hash) from public.dah_reports where piece_id = p_id) >= 3 then
    insert into public.dah_hidden (id, piece) values (r.id, to_jsonb(r)) on conflict (id) do nothing;
    delete from public.dah_pieces where id = p_id;
    return true;
  end if;
  return false;
end $$;

-- Dashboard only: not callable from the website.
create or replace function public.dah_restore(p_id uuid) returns void
language plpgsql security definer set search_path = '' as $$
declare j jsonb;
begin
  select piece into j from public.dah_hidden where id = p_id;
  if not found then raise exception 'Not in dah_hidden'; end if;
  insert into public.dah_pieces select * from jsonb_populate_record(null::public.dah_pieces, j);
  delete from public.dah_hidden where id = p_id;
  delete from public.dah_reports where piece_id = p_id;
end $$;

revoke all on function public.dah_hash(text), public.dah_device(text), public.dah_ip(),
  public.dah_restore(uuid) from public, anon, authenticated;
revoke all on function public.dah_upload_ok(text), public.dah_trash_ok(text),
  public.dah_claim(text, double precision, double precision, double precision, double precision, text, text, text, text, text, boolean),
  public.dah_publish(uuid, text), public.dah_take_down(uuid, text),
  public.dah_set_download(uuid, text, boolean), public.dah_report(uuid, text) from public;
grant execute on function public.dah_upload_ok(text), public.dah_trash_ok(text),
  public.dah_claim(text, double precision, double precision, double precision, double precision, text, text, text, text, text, boolean),
  public.dah_publish(uuid, text), public.dah_take_down(uuid, text),
  public.dah_set_download(uuid, text, boolean), public.dah_report(uuid, text) to anon, authenticated;
grant select on public.dah_pieces to anon, authenticated;
revoke insert, update, delete, truncate on public.dah_pieces from anon, authenticated;

drop policy if exists "dah upload for active claim" on storage.objects;
create policy "dah upload for active claim" on storage.objects for insert to anon, authenticated
  with check (bucket_id = 'dah' and public.dah_upload_ok(name));
drop policy if exists "dah see trashed" on storage.objects;
create policy "dah see trashed" on storage.objects for select to anon, authenticated
  using (bucket_id = 'dah' and public.dah_trash_ok(name));
drop policy if exists "dah delete trashed" on storage.objects;
create policy "dah delete trashed" on storage.objects for delete to anon, authenticated
  using (bucket_id = 'dah' and public.dah_trash_ok(name));

-- Live updates for everyone looking at the wall.
do $$ begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime'
                     and schemaname = 'public' and tablename = 'dah_pieces') then
    alter publication supabase_realtime add table public.dah_pieces;
  end if;
end $$;
