-- ============================================================================
-- Badulaque Central · Fase 1: empleados en línea y permisos por rango
-- Supabase → SQL Editor → New query → pega TODO este archivo → Run.
-- Se puede ejecutar varias veces sin romper nada.
--
-- Quién es Jefe lo decide la base de datos, no la página: un empleado con
-- rango "Jefe" o "Jefe Tribal" y su ID de Discord en la lista. Aunque alguien
-- toque el código de la web, sin ser Jefe no recibe los datos.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- Tablas
-- ---------------------------------------------------------------------------
create table if not exists public.employees (
  id         text primary key default gen_random_uuid()::text,
  name       text not null,
  surname    text not null,
  rank       text not null default '',
  discord    text not null default '',   -- ID de usuario de Discord
  iban       text not null default '',   -- cuenta del banco del servidor (J739745)
  no_pay     boolean not null default false,
  created_at timestamptz not null default now()
);
create index if not exists employees_discord_idx on public.employees (discord);

create table if not exists public.app_settings (
  key   text primary key,
  value jsonb not null
);

-- ---------------------------------------------------------------------------
-- Funciones de permisos (security definer: leen la lista aunque quien
-- pregunta no pueda verla).
-- ---------------------------------------------------------------------------

-- ID de Discord de quien ha iniciado sesión.
create or replace function public.mi_discord()
returns text
language sql stable security definer set search_path = public, auth
as $$
  select coalesce(
    u.raw_user_meta_data ->> 'provider_id',
    u.raw_user_meta_data ->> 'sub',
    (select i.identity_data ->> 'sub' from auth.identities i
      where i.user_id = u.id and i.provider = 'discord' limit 1),
    ''
  )
  from auth.users u
  where u.id = auth.uid();
$$;

create or replace function public.mi_rango()
returns text
language sql stable security definer set search_path = public
as $$
  select e.rank from public.employees e
  where e.discord <> '' and e.discord = public.mi_discord()
  limit 1;
$$;

-- Jefe o Jefe Tribal: ven Pagos, Sorteo, Crafteos y gestionan la plantilla.
create or replace function public.es_jefe()
returns boolean
language sql stable security definer set search_path = public
as $$
  select coalesce(public.mi_rango() in ('Jefe', 'Jefe Tribal'), false);
$$;

-- El dueño: el único que da o quita Jefe / Jefe Tribal y cambia "No cobra".
create or replace function public.es_jefe_tribal()
returns boolean
language sql stable security definer set search_path = public
as $$
  select coalesce(public.mi_rango() = 'Jefe Tribal', false);
$$;

-- Cualquier empleado registrado con su Discord.
create or replace function public.es_empleado()
returns boolean
language sql stable security definer set search_path = public
as $$
  select public.mi_rango() is not null;
$$;

-- Nombre y rango de quien entra (cada uno recibe solo SUS datos).
create or replace function public.mi_perfil()
returns table (name text, surname text, rank text)
language sql stable security definer set search_path = public
as $$
  select e.name, e.surname, e.rank from public.employees e
  where e.discord <> '' and e.discord = public.mi_discord()
  limit 1;
$$;

revoke all on function public.mi_discord(), public.mi_rango(), public.es_jefe(),
  public.es_jefe_tribal(), public.es_empleado(), public.mi_perfil() from public, anon;
grant execute on function public.mi_discord(), public.mi_rango(), public.es_jefe(),
  public.es_jefe_tribal(), public.es_empleado(), public.mi_perfil() to authenticated;

-- ---------------------------------------------------------------------------
-- Rangos protegidos: solo el Jefe Tribal puede dar, cambiar o quitar los
-- rangos Jefe y Jefe Tribal, cambiar el Discord de un Jefe o la casilla
-- "No cobra". Desde el SQL Editor (sin sesión) siempre se puede.
-- ---------------------------------------------------------------------------
create or replace function public.proteger_rangos()
returns trigger
language plpgsql security definer set search_path = public
as $$
declare
  altos text[] := array['Jefe', 'Jefe Tribal'];
begin
  if auth.uid() is null or public.es_jefe_tribal() then
    return coalesce(new, old);
  end if;

  if tg_op = 'INSERT' then
    if new.rank = any(altos) then
      raise exception 'Solo el Jefe Tribal puede dar el rango %', new.rank;
    end if;
    if new.no_pay then
      raise exception 'Solo el Jefe Tribal puede marcar No cobra';
    end if;
  elsif tg_op = 'UPDATE' then
    if (old.rank = any(altos) or new.rank = any(altos)) and new.rank is distinct from old.rank then
      raise exception 'Solo el Jefe Tribal puede dar o quitar los rangos Jefe y Jefe Tribal';
    end if;
    if old.rank = any(altos) and new.discord is distinct from old.discord then
      raise exception 'Solo el Jefe Tribal puede cambiar el Discord de un Jefe';
    end if;
    if new.no_pay is distinct from old.no_pay then
      raise exception 'Solo el Jefe Tribal puede cambiar No cobra';
    end if;
  elsif tg_op = 'DELETE' then
    if old.rank = any(altos) then
      raise exception 'Solo el Jefe Tribal puede quitar a un Jefe';
    end if;
  end if;
  return coalesce(new, old);
end;
$$;

drop trigger if exists proteger_rangos on public.employees;
create trigger proteger_rangos
  before insert or update or delete on public.employees
  for each row execute function public.proteger_rangos();

-- ---------------------------------------------------------------------------
-- Reglas de acceso (RLS)
-- ---------------------------------------------------------------------------
alter table public.employees enable row level security;
alter table public.app_settings enable row level security;

-- Empleados (con IBAN): solo los Jefes los ven y los cambian.
drop policy if exists "employees jefes" on public.employees;
create policy "employees jefes" on public.employees
  for all to authenticated
  using ((select public.es_jefe()))
  with check ((select public.es_jefe()));

-- Ajustes: los lee quien inicia sesión; solo el Jefe Tribal los cambia.
drop policy if exists "settings leer" on public.app_settings;
create policy "settings leer" on public.app_settings
  for select to authenticated using (true);
drop policy if exists "settings jefe tribal" on public.app_settings;
create policy "settings jefe tribal" on public.app_settings
  for all to authenticated
  using ((select public.es_jefe_tribal()))
  with check ((select public.es_jefe_tribal()));

revoke all on public.employees, public.app_settings from anon;
grant select, insert, update, delete on public.employees to authenticated;
grant select, insert, update, delete on public.app_settings to authenticated;

-- ---------------------------------------------------------------------------
-- Tú como Jefe Tribal (el primero de la lista). Cambia los tres valores y
-- quita los dos guiones del principio de las 4 líneas de abajo.
-- ---------------------------------------------------------------------------
-- insert into public.employees (name, surname, rank, discord)
-- values ('TU_NOMBRE', 'TU_APELLIDO', 'Jefe Tribal', 'TU_ID_DE_DISCORD')
-- on conflict (id) do nothing;
-- select * from public.employees;
