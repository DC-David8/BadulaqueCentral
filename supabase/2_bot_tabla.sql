-- ============================================================================
-- Badulaque Central · Fase 2: bot de facturas (paso 1 de 3)
-- Supabase → SQL Editor → New query → pega todo → Run.
-- Se puede ejecutar varias veces sin romper nada.
-- ============================================================================

create table if not exists public.discord_log (
  id         text primary key,          -- ID del mensaje de Discord
  ts         timestamptz not null,      -- fecha del mensaje
  author     text,
  content    text,
  embeds     jsonb,
  created_at timestamptz not null default now()
);
create index if not exists discord_log_ts_idx on public.discord_log (ts);

alter table public.discord_log enable row level security;

-- Solo los Jefes la leen desde la página. Nadie escribe desde la página:
-- solo el bot (que usa la clave interna de Supabase).
drop policy if exists "discord_log jefes leen" on public.discord_log;
create policy "discord_log jefes leen" on public.discord_log
  for select to authenticated using ((select public.es_jefe()));

revoke all on public.discord_log from anon;
revoke insert, update, delete on public.discord_log from authenticated;
grant select on public.discord_log to authenticated;
