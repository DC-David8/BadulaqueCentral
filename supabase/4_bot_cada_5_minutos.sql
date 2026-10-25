-- ============================================================================
-- Badulaque Central · Fase 2: bot de facturas (paso 3 de 3)
-- Ejecuta la función leer-logs cada 5 minutos, para que las facturas estén
-- siempre al día. Supabase → SQL Editor → New query → pega todo → Run.
-- (Si prefieres, también se puede hacer en Integrations → Cron.)
-- ============================================================================

create extension if not exists pg_cron;
create extension if not exists pg_net;

select cron.unschedule('badu-leer-logs')
where exists (select 1 from cron.job where jobname = 'badu-leer-logs');

select cron.schedule(
  'badu-leer-logs',
  '*/5 * * * *',
  $$
  select net.http_post(
    url     := 'https://aewhpzwksxaqsuwsekcd.supabase.co/functions/v1/leer-logs',
    headers := '{"Content-Type":"application/json"}'::jsonb,
    body    := '{}'::jsonb
  );
  $$
);
