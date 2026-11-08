-- ============================================================================
-- Badulaque Central · Fechas de cada empleado: ingreso y contratación
-- Supabase → SQL Editor → New query → pega TODO este archivo → Run.
-- Se puede ejecutar varias veces sin romper nada. (Necesita antes el SQL 7.)
--
-- alta_at        = fecha de INGRESO al Badulaque (su primer día; no cambia
--                  aunque le despidan y le readmitan).
-- contratado_at  = fecha de CONTRATACIÓN (la del contrato actual; al readmitir
--                  se pone la del día de la readmisión).
-- Las dos son solo fecha (sin hora). La fecha que ya tuviera cada uno (la de
-- la versión 32) se copia también como fecha de contratación.
-- ============================================================================

alter table public.employees add column if not exists alta_at date;

-- Si alta_at venía del SQL 7 como fecha y hora, se pasa a solo fecha (hora de Guatemala).
do $$
begin
  if (select data_type from information_schema.columns
      where table_schema = 'public' and table_name = 'employees' and column_name = 'alta_at') <> 'date' then
    alter table public.employees alter column alta_at drop default;
    alter table public.employees alter column alta_at type date
      using (alta_at at time zone 'America/Guatemala')::date;
  end if;
end $$;
alter table public.employees alter column alta_at set default current_date;

alter table public.employees add column if not exists contratado_at date;
alter table public.employees alter column contratado_at set default current_date;

update public.employees set contratado_at = alta_at
  where contratado_at is null and alta_at is not null;

select name, surname, rank, alta_at as ingreso, contratado_at as contratacion
  from public.employees where despedido_at is null order by surname, name;
