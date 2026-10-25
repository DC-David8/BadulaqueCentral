-- ============================================================================
-- Badulaque Central · Despidos
-- Supabase → SQL Editor → New query → pega TODO este archivo → Run.
-- Se puede ejecutar varias veces sin romper nada.
--
-- En vez de borrar a un empleado se le marca como despedido (fecha, motivo y
-- quién lo hizo) y queda en el registro. Un despedido:
--   · ya no sale en la plantilla ni en los pagos,
--   · pierde el acceso a la página aunque inicie sesión con su Discord,
--   · se puede readmitir.
-- Solo el Jefe Tribal puede despedir o readmitir a un Jefe.
-- ============================================================================

alter table public.employees add column if not exists despedido_at     timestamptz;
alter table public.employees add column if not exists despedido_por    text;
alter table public.employees add column if not exists despedido_motivo text;

-- Rango de quien entra: los despedidos ya no cuentan.
create or replace function public.mi_rango()
returns text
language sql stable security definer set search_path = public
as $$
  select e.rank from public.employees e
  where e.discord <> '' and e.discord = public.mi_discord() and e.despedido_at is null
  limit 1;
$$;

create or replace function public.mi_perfil()
returns table (name text, surname text, rank text)
language sql stable security definer set search_path = public
as $$
  select e.name, e.surname, e.rank from public.employees e
  where e.discord <> '' and e.discord = public.mi_discord() and e.despedido_at is null
  limit 1;
$$;

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
    if old.rank = any(altos) and new.despedido_at is distinct from old.despedido_at then
      raise exception 'Solo el Jefe Tribal puede despedir o readmitir a un Jefe';
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
