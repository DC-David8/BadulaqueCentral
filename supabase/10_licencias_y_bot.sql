-- Badulaque Central · Licencias, log de empleados y publicar con el bot (paso 10)
-- Pega todo en Supabase → SQL Editor → Run. Se puede ejecutar varias veces.
--
-- licencia    = licencias marcadas en la ficha ("Coche,Moto,Camión,Avión").
-- log_msg_id  = el mensaje de esa persona en el canal del log de empleados,
--               para que el bot edite siempre el mismo en vez de publicar otro.
alter table public.employees add column if not exists licencia   text not null default '';
alter table public.employees add column if not exists log_msg_id text;

-- Imagen de la licencia: una por empleado, en una tabla privada (no es una
-- carpeta pública). Solo la ve la Jefatura y solo el Jefe Tribal la sube,
-- cambia o quita.
create table if not exists public.emp_licencias (
  employee_id text primary key,
  foto        text not null,                 -- imagen comprimida (data:image/jpeg;base64,…)
  updated_at  timestamptz not null default now(),
  por         text
);
alter table public.emp_licencias enable row level security;
grant select, insert, update, delete on public.emp_licencias to authenticated;

drop policy if exists "emp_licencias jefatura lee" on public.emp_licencias;
create policy "emp_licencias jefatura lee" on public.emp_licencias
  for select to authenticated using ((select public.es_jefe()));

drop policy if exists "emp_licencias tribal sube" on public.emp_licencias;
create policy "emp_licencias tribal sube" on public.emp_licencias
  for insert to authenticated with check ((select public.es_jefe_tribal()));

drop policy if exists "emp_licencias tribal cambia" on public.emp_licencias;
create policy "emp_licencias tribal cambia" on public.emp_licencias
  for update to authenticated using ((select public.es_jefe_tribal())) with check ((select public.es_jefe_tribal()));

drop policy if exists "emp_licencias tribal borra" on public.emp_licencias;
create policy "emp_licencias tribal borra" on public.emp_licencias
  for delete to authenticated using ((select public.es_jefe_tribal()));

-- Mensajes de la semana publicados por el bot (pagas, movimientos de
-- personal y strikes), para que «Publicar» edite el mismo y no duplique.
create table if not exists public.pub_msgs (
  semana   date not null,
  clave    text not null,           -- pagas · movs · strikes
  msg_ids  text[] not null default '{}',
  at       timestamptz not null default now(),
  por      text,
  primary key (semana, clave)
);
alter table public.pub_msgs enable row level security;
drop policy if exists "pub_msgs jefatura lee" on public.pub_msgs;
create policy "pub_msgs jefatura lee" on public.pub_msgs
  for select to authenticated using ((select public.es_jefe()));
grant select on public.pub_msgs to authenticated;
-- Solo escribe la función del bot (con su llave de servicio).
