-- WorkBuddy reset and access migration. Run once after reviewing the public site.
-- This permanently removes the old members, overtime rows, and drawing.
begin;

create schema if not exists workbuddy_private;
revoke all on schema workbuddy_private from public, anon, authenticated;

create table workbuddy_private.accounts (
  member_id text primary key references public.members(id) on delete cascade,
  pin_hash text not null,
  failed_attempts integer not null default 0,
  locked_until timestamptz
);
create table workbuddy_private.sessions (
  token_hash text primary key,
  member_id text not null references workbuddy_private.accounts(member_id) on delete cascade,
  expires_at timestamptz not null
);
create index on workbuddy_private.sessions (expires_at);
create table workbuddy_private.invite (
  id boolean primary key default true check (id),
  code_hash text not null
);

alter table public.members add column clocked_out_on date;
alter table public.members add column day_schedules jsonb not null default '{}'::jsonb;

create table public.attendance (
  id bigint generated always as identity primary key,
  member_id text not null references public.members(id) on delete cascade,
  work_date date not null,
  started_at timestamptz not null,
  last_seen_at timestamptz not null,
  ended_at timestamptz,
  constraint attendance_times check (last_seen_at >= started_at and (ended_at is null or ended_at >= started_at))
);
create index on public.attendance (member_id, work_date);
create unique index workbuddy_one_open_attendance on public.attendance (member_id) where ended_at is null;

create function public.workbuddy_current_member() returns text
language sql stable security definer set search_path = '' as $$
  select s.member_id from workbuddy_private.sessions s
  where s.token_hash = encode(extensions.digest(
    coalesce((nullif(current_setting('request.headers', true), '')::jsonb)->>'x-workbuddy-session', ''),
    'sha256'), 'hex')
    and s.expires_at > now()
  limit 1;
$$;

create function workbuddy_private.new_session(p_member_id text, p_name text) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare v_token text;
begin
  v_token := encode(extensions.gen_random_bytes(32), 'hex');
  insert into workbuddy_private.sessions(token_hash, member_id, expires_at)
  values (encode(extensions.digest(v_token, 'sha256'), 'hex'), p_member_id, now() + interval '30 days');
  return jsonb_build_object('member_id', p_member_id, 'name', p_name, 'session_token', v_token);
end;
$$;

create function public.workbuddy_register(p_name text, p_pin text, p_invite text) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare v_name text := btrim(p_name); v_id text;
begin
  if p_invite is null or not exists (
    select 1 from workbuddy_private.invite
    where code_hash = encode(extensions.digest(upper(btrim(p_invite)), 'sha256'), 'hex')
  ) then
    return jsonb_build_object('error', '초대코드를 확인해 주세요.');
  end if;
  if v_name is null or length(v_name) < 1 or length(v_name) > 12 then
    return jsonb_build_object('error', '닉네임은 1~12자로 입력해 주세요.');
  end if;
  if p_pin is null or p_pin !~ '^[0-9]{6}$' then
    return jsonb_build_object('error', 'PIN은 숫자 6자리로 입력해 주세요.');
  end if;
  v_id := 'u_' || replace(gen_random_uuid()::text, '-', '');
  insert into public.members(id, name, work_start, work_end, lunch_start, lunch_end, work_days, updated_at)
  values (v_id, v_name, '09:00', '18:00', '12:00', '13:00', array[1,2,3,4,5], now());
  insert into workbuddy_private.accounts(member_id, pin_hash)
  values (v_id, extensions.crypt(p_pin, extensions.gen_salt('bf', 10)));
  return workbuddy_private.new_session(v_id, v_name);
exception when unique_violation then
  return jsonb_build_object('error', '이미 사용 중인 닉네임이에요.');
end;
$$;

create function public.workbuddy_login(p_name text, p_pin text) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare v_id text; v_name text; v_hash text; v_attempts integer; v_locked timestamptz;
begin
  if p_name is null or p_pin is null or p_pin !~ '^[0-9]{6}$' then
    return jsonb_build_object('error', '닉네임 또는 PIN을 확인해 주세요.');
  end if;
  select a.member_id, m.name, a.pin_hash, a.failed_attempts, a.locked_until
    into v_id, v_name, v_hash, v_attempts, v_locked
    from workbuddy_private.accounts a join public.members m on m.id = a.member_id
    where lower(btrim(m.name)) = lower(btrim(p_name)) for update of a;
  if v_id is null then
    return jsonb_build_object('error', '닉네임 또는 PIN을 확인해 주세요.');
  end if;
  if v_locked > now() then
    return jsonb_build_object('error', '잠시 후 다시 시도해 주세요.');
  end if;
  if extensions.crypt(p_pin, v_hash) <> v_hash then
    update workbuddy_private.accounts set failed_attempts = v_attempts + 1,
      locked_until = case when v_attempts + 1 >= 5 then now() + interval '15 minutes' else null end
      where member_id = v_id;
    return jsonb_build_object('error', '닉네임 또는 PIN을 확인해 주세요.');
  end if;
  update workbuddy_private.accounts set failed_attempts = 0, locked_until = null where member_id = v_id;
  delete from workbuddy_private.sessions where expires_at <= now();
  return workbuddy_private.new_session(v_id, v_name);
end;
$$;

create function public.workbuddy_logout() returns void
language sql security definer set search_path = '' as $$
  delete from workbuddy_private.sessions where token_hash = encode(extensions.digest(
    coalesce((nullif(current_setting('request.headers', true), '')::jsonb)->>'x-workbuddy-session', ''),
    'sha256'), 'hex');
$$;

create function public.workbuddy_tick() returns void
language plpgsql security definer set search_path = '' as $$
declare
  v_id text := public.workbuddy_current_member();
  v_date date := (now() at time zone 'Asia/Seoul')::date;
  v_start timestamptz;
  v_member public.members%rowtype;
  v_schedule jsonb;
  v_day integer := extract(dow from (now() at time zone 'Asia/Seoul'))::integer;
  v_active boolean;
  v_start_time time;
  v_end_time time;
  v_open public.attendance%rowtype;
begin
  if v_id is null then raise exception '로그인이 필요합니다.'; end if;
  select * into v_member from public.members where id = v_id for update;
  update public.members set updated_at = now() where id = v_id;
  select * into v_open from public.attendance
    where member_id = v_id and ended_at is null for update;
  if found and (v_open.work_date <> v_date or now() - v_open.last_seen_at > interval '45 seconds') then
    update public.attendance set ended_at = v_open.last_seen_at where id = v_open.id;
    v_open.id := null;
  end if;
  v_schedule := v_member.day_schedules -> (v_day::text);
  v_active := coalesce((v_schedule->>'active')::boolean, v_day = any(v_member.work_days));
  v_start_time := coalesce((v_schedule->>'start')::time, v_member.work_start);
  v_end_time := coalesce((v_schedule->>'end')::time, v_member.work_end);
  if not v_active or v_end_time <= v_start_time or v_member.clocked_out_on = v_date then return; end if;
  v_start := (v_date + v_start_time) at time zone 'Asia/Seoul';
  if now() < v_start then return; end if;
  if v_open.id is null then
    insert into public.attendance(member_id, work_date, started_at, last_seen_at)
    values (v_id, v_date, case when now() - v_start <= interval '30 seconds' then v_start else now() end, now());
  else
    update public.attendance set last_seen_at = now() where id = v_open.id;
  end if;
end;
$$;

create function public.workbuddy_clock_out() returns void
language plpgsql security definer set search_path = '' as $$
declare v_id text := public.workbuddy_current_member();
begin
  if v_id is null then raise exception '로그인이 필요합니다.'; end if;
  update public.members set clocked_out_on = (now() at time zone 'Asia/Seoul')::date
    where id = v_id;
  update public.attendance set ended_at = now(), last_seen_at = now()
    where member_id = v_id and ended_at is null;
end;
$$;

create function public.workbuddy_delete_account() returns void
language plpgsql security definer set search_path = '' as $$
declare v_id text := public.workbuddy_current_member();
begin
  if v_id is null then raise exception '로그인이 필요합니다.'; end if;
  delete from public.overtime where member_id = v_id;
  delete from public.attendance where member_id = v_id;
  delete from public.members where id = v_id;
end;
$$;

revoke all on function public.workbuddy_current_member() from public;
revoke all on function public.workbuddy_register(text,text,text) from public;
revoke all on function public.workbuddy_login(text,text) from public;
revoke all on function public.workbuddy_logout() from public;
revoke all on function public.workbuddy_tick() from public;
revoke all on function public.workbuddy_clock_out() from public;
revoke all on function public.workbuddy_delete_account() from public;
revoke all on function workbuddy_private.new_session(text,text) from public;
grant execute on function public.workbuddy_current_member() to anon;
grant execute on function public.workbuddy_register(text,text,text) to anon;
grant execute on function public.workbuddy_login(text,text) to anon;
grant execute on function public.workbuddy_logout() to anon;
grant execute on function public.workbuddy_tick() to anon;
grant execute on function public.workbuddy_clock_out() to anon;
grant execute on function public.workbuddy_delete_account() to anon;

-- Old, unauthenticated data is intentionally removed at the switchover.
delete from public.overtime;
delete from public.members;
create unique index workbuddy_unique_nickname on public.members (lower(btrim(name)));
update public.doodle_board set drawing = '{"strokes":[],"modes":{},"reactions":{},"deletedIds":[],"customModes":{},"daySchedules":{}}'::jsonb,
  updated_at = now() where id = 1;

drop policy if exists "workbuddy members insert" on public.members;
drop policy if exists "workbuddy members read" on public.members;
drop policy if exists "workbuddy members update" on public.members;
drop policy if exists "workbuddy doodle read" on public.doodle_board;
drop policy if exists "workbuddy doodle update" on public.doodle_board;
drop policy if exists "workbuddy overtime delete" on public.overtime;
drop policy if exists "workbuddy overtime insert" on public.overtime;
drop policy if exists "workbuddy overtime read" on public.overtime;
drop policy if exists "workbuddy overtime update" on public.overtime;

alter table public.attendance enable row level security;
create policy workbuddy_members_read on public.members for select to anon
  using (public.workbuddy_current_member() is not null);
create policy workbuddy_members_update on public.members for update to anon
  using (id = public.workbuddy_current_member()) with check (id = public.workbuddy_current_member());
create policy workbuddy_board_read on public.doodle_board for select to anon
  using (public.workbuddy_current_member() is not null);
create policy workbuddy_board_update on public.doodle_board for update to anon
  using (public.workbuddy_current_member() is not null)
  with check (public.workbuddy_current_member() is not null);
create policy workbuddy_overtime_read on public.overtime for select to anon
  using (public.workbuddy_current_member() is not null);
create policy workbuddy_overtime_insert on public.overtime for insert to anon
  with check (member_id = public.workbuddy_current_member());
create policy workbuddy_overtime_update on public.overtime for update to anon
  using (member_id = public.workbuddy_current_member())
  with check (member_id = public.workbuddy_current_member());
create policy workbuddy_attendance_read on public.attendance for select to anon
  using (public.workbuddy_current_member() is not null);

revoke all on public.members, public.doodle_board, public.overtime, public.attendance from public, anon, authenticated;
grant select on public.members, public.doodle_board, public.overtime, public.attendance to anon;
grant update (work_start, work_end, lunch_start, lunch_end, work_days, survival_message,
  survival_expires_at, day_schedules) on public.members to anon;
grant update (drawing, updated_at) on public.doodle_board to anon;
grant insert, update (ended_at) on public.overtime to anon;

commit;
