begin;

create table if not exists public.expense_app_shared_state (
  id boolean primary key default true check (id = true),
  owner_id uuid not null references auth.users(id) on delete cascade,
  member_id uuid unique references auth.users(id) on delete set null,
  invite_hash text,
  app_state jsonb not null check (jsonb_typeof(app_state) = 'object'),
  updated_at timestamptz not null default now(),
  check (member_id is null or member_id <> owner_id)
);

alter table public.expense_app_shared_state enable row level security;

create table if not exists public.expense_app_setup (
  id boolean primary key default true check (id = true),
  setup_hash text not null,
  claimed boolean not null default false
);
alter table public.expense_app_setup enable row level security;
revoke all on public.expense_app_setup from public, anon, authenticated;
insert into public.expense_app_setup (id, setup_hash, claimed)
values (true, '46222400ed95f985b6ba80baf8584ef75d9f046d4818aec874eb1cb649f53a4f', false)
on conflict (id) do nothing;

revoke all on public.expense_app_shared_state from public, anon, authenticated;
grant select on public.expense_app_shared_state to authenticated;
grant update (app_state, updated_at) on public.expense_app_shared_state to authenticated;

drop policy if exists expense_app_shared_state_read_members on public.expense_app_shared_state;
create policy expense_app_shared_state_read_members
  on public.expense_app_shared_state for select to authenticated
  using (owner_id = (select auth.uid()) or member_id = (select auth.uid()));

drop policy if exists expense_app_shared_state_update_members on public.expense_app_shared_state;
create policy expense_app_shared_state_update_members
  on public.expense_app_shared_state for update to authenticated
  using (owner_id = (select auth.uid()) or member_id = (select auth.uid()))
  with check (owner_id = (select auth.uid()) or member_id = (select auth.uid()));

create or replace function public.expense_app_open(p_initial_state jsonb, p_setup_code_hash text default null)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_row public.expense_app_shared_state%rowtype;
begin
  if auth.uid() is null then
    raise exception 'Authentication required';
  end if;
  if jsonb_typeof(p_initial_state) <> 'object' then
    raise exception 'Initial state must be a JSON object';
  end if;

  select * into v_row
  from public.expense_app_shared_state
  where id = true;

  if not found then
    update public.expense_app_setup
    set claimed = true
    where id = true and claimed = false and setup_hash = p_setup_code_hash;
    if not found then
      return jsonb_build_object('status', 'setup_required');
    end if;
    insert into public.expense_app_shared_state (id, owner_id, app_state)
    values (true, auth.uid(), p_initial_state);
    select * into v_row
    from public.expense_app_shared_state
    where id = true;
  end if;

  if v_row.owner_id <> auth.uid()
     and (v_row.member_id is null or v_row.member_id <> auth.uid()) then
    return jsonb_build_object('status', 'invite_required');
  end if;

  return jsonb_build_object(
    'status', 'ok',
    'app_state', v_row.app_state,
    'updated_at', v_row.updated_at,
    'is_owner', v_row.owner_id = auth.uid(),
    'has_member', v_row.member_id is not null
  );
end;
$$;

create or replace function public.expense_app_set_invite(p_code_hash text)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
begin
  if auth.uid() is null or p_code_hash !~ '^[0-9a-f]{64}$' then
    return false;
  end if;

  update public.expense_app_shared_state
  set invite_hash = p_code_hash
  where id = true and owner_id = auth.uid() and member_id is null;

  return found;
end;
$$;

create or replace function public.expense_app_join(p_code_hash text)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
begin
  if auth.uid() is null or p_code_hash !~ '^[0-9a-f]{64}$' then
    return false;
  end if;

  update public.expense_app_shared_state
  set member_id = auth.uid(), invite_hash = null
  where id = true
    and owner_id <> auth.uid()
    and member_id is null
    and invite_hash = p_code_hash;

  return found;
end;
$$;

revoke all on function public.expense_app_open(jsonb, text) from public, anon;
revoke all on function public.expense_app_set_invite(text) from public, anon;
revoke all on function public.expense_app_join(text) from public, anon;
grant execute on function public.expense_app_open(jsonb, text) to authenticated;
grant execute on function public.expense_app_set_invite(text) to authenticated;
grant execute on function public.expense_app_join(text) to authenticated;

do $$
begin
  if not exists (
    select 1 from pg_publication_tables
    where pubname = 'supabase_realtime'
      and schemaname = 'public'
      and tablename = 'expense_app_shared_state'
  ) then
    alter publication supabase_realtime add table public.expense_app_shared_state;
  end if;
end;
$$;

commit;

