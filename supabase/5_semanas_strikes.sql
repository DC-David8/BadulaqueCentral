-- ============================================================================
-- Badulaque Central · Fase 4: semanas cerradas y strikes
-- Supabase → SQL Editor → New query → pega TODO este archivo → Run.
-- Se puede ejecutar varias veces sin romper nada.
--
-- Al pulsar "Cerrar semana" en Pagos se guarda lo que vendió y cobró cada
-- empleado y quién se llevó strike (no llegar a $20.000). Así la página
-- cuenta los strikes seguidos: con 3, despido.
-- ============================================================================

create table if not exists public.pagos_semanas (
  semana      date primary key,        -- domingo con el que empieza la semana (hora de España)
  desde       date,
  hasta       date,
  datos       jsonb not null,           -- ventas, pago, bono y strike de cada empleado
  cerrada_por text,
  created_at  timestamptz not null default now()
);

alter table public.pagos_semanas enable row level security;

-- Solo los Jefes ven, cierran y reabren semanas.
drop policy if exists "pagos_semanas jefes" on public.pagos_semanas;
create policy "pagos_semanas jefes" on public.pagos_semanas
  for all to authenticated
  using ((select public.es_jefe()))
  with check ((select public.es_jefe()));

revoke all on public.pagos_semanas from anon;
grant select, insert, update, delete on public.pagos_semanas to authenticated;
