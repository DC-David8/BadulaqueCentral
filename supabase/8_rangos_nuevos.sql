-- ============================================================================
-- Badulaque Central · Nombres nuevos de los rangos
-- Supabase → SQL Editor → New query → pega TODO este archivo → Run.
-- Se puede ejecutar varias veces sin romper nada.
--
--   En Pruebas            → Reponedor
--   Cajero                → Cajero (igual)
--   Cajero Experimentado  → Cajero Principal
--   Encargado             → Supervisor
--   Jefe                  → Gerente
--   Jefe Tribal           → Jefe Tribal (igual)
--
-- Cambia el rango guardado de cada empleado (también los despedidos) y hace
-- que "Gerente" tenga los permisos que antes tenía "Jefe". El nombre antiguo
-- "Jefe" se sigue aceptando por si queda alguno.
-- ============================================================================

update public.employees set rank = case rank
    when 'En Pruebas' then 'Reponedor'
    when 'Cajero Experimentado' then 'Cajero Principal'
    when 'Encargado' then 'Supervisor'
    when 'Jefe' then 'Gerente'
    else rank end
  where rank in ('En Pruebas', 'Cajero Experimentado', 'Encargado', 'Jefe');

-- Gerente o Jefe Tribal: ven Pagos, Sorteo, Crafteos y gestionan la plantilla.
create or replace function public.es_jefe()
returns boolean
language sql stable security definer set search_path = public
as $$
  select coalesce(public.mi_rango() in ('Gerente', 'Jefe Tribal', 'Jefe'), false);
$$;

create or replace function public.proteger_rangos()
returns trigger
language plpgsql security definer set search_path = public
as $$
declare
  altos text[] := array['Gerente', 'Jefe Tribal', 'Jefe'];
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
      raise exception 'Solo el Jefe Tribal puede dar o quitar los rangos Gerente y Jefe Tribal';
    end if;
    if old.rank = any(altos) and new.discord is distinct from old.discord then
      raise exception 'Solo el Jefe Tribal puede cambiar el Discord de un Gerente';
    end if;
    if old.rank = any(altos) and new.despedido_at is distinct from old.despedido_at then
      raise exception 'Solo el Jefe Tribal puede despedir o readmitir a un Gerente';
    end if;
    if new.no_pay is distinct from old.no_pay then
      raise exception 'Solo el Jefe Tribal puede cambiar No cobra';
    end if;
  elsif tg_op = 'DELETE' then
    if old.rank = any(altos) then
      raise exception 'Solo el Jefe Tribal puede quitar a un Gerente';
    end if;
  end if;
  return coalesce(new, old);
end;
$$;

select rank, count(*) from public.employees group by rank order by rank;
