// Badulaque Central · Bot de la página: log de empleados, publicar y roles (paso 11)
// Supabase → Edge Functions → Deploy a new function → Via Editor
// Nombre de la función: log-empleados   ·   Pega todo este archivo y pulsa Deploy.
//
// Usa el MISMO bot que las facturas: el secreto DISCORD_BOT_TOKEN ya está
// puesto (no hay que añadir nada). SUPABASE_URL, SUPABASE_ANON_KEY y
// SUPABASE_SERVICE_ROLE_KEY los pone Supabase solo.
//
// Con { publicar: {clave, semana, content} } publica (o corrige) el mensaje de
// pagas, movimientos de personal o strikes de esa semana en su canal.
// Con { roles: {...} } pone y quita los roles del Badulaque en Discord.
//
// Qué hace: mantiene un mensaje por empleado en el canal del log. La página
// la llama al dar de alta, editar, cambiar de rango, despedir o readmitir, y
// con el botón «📋 Log de Discord». Solo la Jefatura puede usarla.
// Nunca menciona en el log (no salta notificación a nadie al publicar o editar).

const API = "https://discord.com/api/v10";

// ---- IDs del servidor del Badulaque (clic derecho → Copiar ID) -------------
const GUILD = "1364613906890227794";
const CANAL_LOG = "1572706882622324896"; // #log de empleados
const CANALES_PUB: Record<string, string> = {
  pagas: "1364613909272592485", // mejor solo Jefatura
  movs: "1364613908744114213", // ascensos, descensos y empleado de la semana
  strikes: "1364613908744114213",
};
// -----------------------------------------------------------------------------

const ROL_TRABAJADORES = "1563907257073143919";
const ROL_EOW = "1364707155130712195"; // Trabajador Semanal (Empleado de la Semana)
const ROLES_STRIKE: Record<number, string> = { 1: "1364613906890227802", 2: "1364613906890227803", 3: "1571384583054954591" };
const ROLES_RANGO: Record<string, string> = {
  "reponedor": "1364613906915655763",
  "cajero": "1566682203524702218",
  "cajero principal": "1364613906915655764",
  "supervisor": "1364613906915655768",
  "gerente": "1366562494260318322",
};
// El bot solo toca estos roles (nunca Jefatura, Jefe Tribal ni ningún otro).
const ROLES_GESTIONADOS = new Set([ROL_TRABAJADORES, ROL_EOW, ...Object.values(ROLES_STRIKE), ...Object.values(ROLES_RANGO)]);
const idOk = (v: string) => /^\d{17,20}$/.test(v);

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-client-info",
};
const llave = (s: string) =>
  String(s || "").normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase().trim();
const json = (obj: unknown, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { ...cors, "Content-Type": "application/json" } });
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// Rango → color del cuadrado, nombre y orden. Los nombres antiguos (hasta la
// versión 26 de la página) se leen con el nombre nuevo.
const RANGOS: Record<string, { c: string; n: string; o: number }> = {
  "reponedor": { c: "🟩", n: "Reponedor", o: 1 },
  "cajero": { c: "🟦", n: "Cajero", o: 2 },
  "cajero principal": { c: "🟪", n: "Cajero Principal", o: 3 },
  "supervisor": { c: "🟧", n: "Supervisor", o: 4 },
  "gerente": { c: "🟥", n: "Gerente", o: 5 },
  "jefe tribal": { c: "🟨", n: "Jefe Tribal", o: 6 },
};
const ALIAS: Record<string, string> = { "en pruebas": "reponedor", "cajero experimentado": "cajero principal", "encargado": "supervisor", "jefe": "gerente" };
const rk = (rank: unknown) => {
  const k = llave(String(rank || ""));
  return ALIAS[k] || k;
};
const LICENCIAS: [string, string][] = [["coche", "🚗 Coche"], ["moto", "🏍️ Moto"], ["camion", "🚚 Camión"], ["avion", "✈️ Avión"]];
function licencias(v: unknown) {
  const s = llave(String(v || ""));
  if (s === "tiene") return "*Tiene* ✅";
  const tiene = LICENCIAS.filter(([k]) => s.split(/[,;\s]+/).includes(k)).map(([, t]) => t);
  return tiene.length ? tiene.join(" · ") : "*Sin registrar*";
}
// Tipo de baja: igual que la página (parseBaja). Primero el tipo elegido al
// despedir; si el motivo es de antes de los tipos (texto libre), por palabras.
function tipoBaja(motivo: string) {
  const m = String(motivo || "").trim();
  if (!m) return "sin motivo";
  const t = BAJAS.find((x) => llave(m).startsWith(llave(x)));
  if (t) return t;
  const k = llave(m);
  return /\bck\b|fallec|muri|muert/.test(k) ? "CK del personaje"
    : /strike/.test(k) ? "3 strikes"
    : /inactiv|no aparece|no viene|desaparec|ausen/.test(k) ? "Inactividad"
    : /volunt|renunc|dimit|se va|se fue|deja el badulaque|deja la tienda|por su cuenta|decision propia/.test(k) ? "Baja voluntaria"
    : /expuls|conduct|sancion|norma|robo|toxic|falta de respeto|insult/.test(k) ? "Expulsión"
    : "Otro";
}
const BAJAS = ["Baja voluntaria", "Inactividad", "3 strikes", "Expulsión", "CK del personaje", "Otro"];


const limpio = (s: unknown, max = 60) =>
  String(s ?? "").replace(/[@`*_~|>#\n\r]/g, "").replace(/\s+/g, " ").trim().slice(0, max);
const fecha = (d: unknown) => {
  const m = String(d || "").match(/^(\d{4})-(\d{2})-(\d{2})/);
  return m ? `${m[3]}/${m[2]}/${m[1]}` : "Sin fecha";
};

type Emp = Record<string, any>;

function texto(e: Emp) {
  const r = RANGOS[rk(e.rank)];
  const rango = limpio(r?.n || e.rank || "Sin rango", 30);
  const baja = !!e.despedido_at;
  const discord = String(e.discord || "").replace(/\D/g, "");
  const nombre = limpio(`${e.name} ${e.surname}`, 60);
  const motivo = String(e.despedido_motivo || "");
  const tipo = tipoBaja(motivo);
  const estado = baja
    ? `❌ **Baja** · ${tipo} · __${fecha(e.despedido_at)}__`
    : "✅ **Activo**";
  return [
    `### ${baja ? "⬛" : r?.c || "⬜"} ${nombre}${discord ? ` — <@${discord}>` : ""}`,
    `> 🏷️ **Rango:** *${rango}*`,
    `> 💳 **IBAN:** ${e.no_pay ? "*No cobra*" : e.iban ? `\`${limpio(e.iban, 12)}\`` : "*Falta*"}`,
    `> 🪪 **Licencias:** ${licencias(e.licencia)}`,
    `> 📅 **Alta:** __${fecha(e.alta_at || e.contratado_at)}__`,
    `> 📌 **Estado:** ${estado}`,
  ].join("\n");
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  const BOT = Deno.env.get("DISCORD_BOT_TOKEN");
  const SB_URL = Deno.env.get("SUPABASE_URL");
  const SB_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  const ANON = Deno.env.get("SUPABASE_ANON_KEY") || SB_KEY;
  if (!BOT || !SB_URL || !SB_KEY) return json({ ok: false, error: "Falta el secreto DISCORD_BOT_TOKEN" }, 500);

  // 1) ¿Quién llama? Solo la Jefatura (la misma comprobación que usa la página).
  const auth = req.headers.get("Authorization") || "";
  const jefe = await fetch(`${SB_URL}/rest/v1/rpc/es_jefe`, {
    method: "POST",
    headers: { apikey: ANON!, Authorization: auth, "Content-Type": "application/json" },
    body: "{}",
  }).then((r) => (r.ok ? r.json() : false)).catch(() => false);
  if (jefe !== true) return json({ ok: false, error: "Solo la Jefatura puede usar el bot desde la página." }, 403);

  const body = await req.json().catch(() => ({}));
  const ids: string[] = Array.isArray(body.ids) ? body.ids.map(String).slice(0, 60) : [];
  const sync = body.sync === true;
  const reordenar = body.reordenar === true;

  const sb = (path: string, init: RequestInit = {}) =>
    fetch(`${SB_URL}/rest/v1/${path}`, {
      ...init,
      headers: { apikey: SB_KEY, Authorization: `Bearer ${SB_KEY}`, "Content-Type": "application/json", ...(init.headers || {}) },
    });
  const dc = async (path: string, init: RequestInit = {}): Promise<Response> => {
    for (let i = 0; i < 5; i++) {
      const r = await fetch(`${API}${path}`, {
        ...init,
        headers: { Authorization: `Bot ${BOT}`, "Content-Type": "application/json", ...(init.headers || {}) },
      });
      if (r.status !== 429) return r;
      const j = await r.json().catch(() => ({}));
      await sleep(Math.ceil((Number(j.retry_after) || 1) * 1000) + 100);
    }
    return new Response(null, { status: 429 });
  };

  // ------------------------------------------------------------- PUBLICAR ---
  // Trocea en mensajes de 2.000 caracteres como máximo (por bloques y líneas).
  function trozos(t: string) {
    const out: string[] = [];
    let cur = "";
    const push = (piece: string, sep: string) => {
      if (!cur) cur = piece;
      else if ((cur + sep + piece).length <= 1990) cur += sep + piece;
      else {
        out.push(cur);
        cur = piece;
      }
    };
    for (const block of t.split("\n\n")) {
      if (block.length <= 1990) push(block, "\n\n");
      else for (const line of block.split("\n")) push(line.slice(0, 1990), "\n");
    }
    if (cur) out.push(cur);
    return out;
  }
  async function publicar(p: any) {
    const clave = String(p?.clave || "");
    const canal = CANALES_PUB[clave];
    const semana = String(p?.semana || "").slice(0, 10);
    const content = String(p?.content || "").replace(/@(everyone|here)/g, "@\u200b$1").trim();
    if (!canal) return { ok: false, error: "Canal desconocido." };
    if (!idOk(canal)) return { ok: false, error: `Falta poner en la función log-empleados el ID del canal de ${clave === "movs" ? "movimientos" : clave}.` };
    if (!/^\d{4}-\d{2}-\d{2}$/.test(semana)) return { ok: false, error: "Falta la semana." };
    if (!content) return { ok: false, error: "El mensaje está vacío." };
    const prev = await sb(`pub_msgs?select=msg_ids&semana=eq.${semana}&clave=eq.${clave}`).then((r) => (r.ok ? r.json() : null)).catch(() => null);
    if (prev === null) return { ok: false, error: "Falta la tabla de publicaciones (ejecuta el SQL 10 en Supabase)." };
    const old: string[] = Array.isArray(prev?.[0]?.msg_ids) ? prev[0].msg_ids : [];
    const parts = trozos(content);
    const allowed = { parse: ["users", "roles"] };
    const ids: string[] = [];
    let editados = 0;
    let publicados = 0;
    for (let i = 0; i < parts.length; i++) {
      const payload = JSON.stringify({ content: parts[i], allowed_mentions: allowed });
      if (old[i]) {
        const r = await dc(`/channels/${canal}/messages/${old[i]}`, { method: "PATCH", body: payload });
        if (r.ok) {
          ids.push(old[i]);
          editados++;
          await sleep(250);
          continue;
        }
        if (r.status !== 404) return { ok: false, error: `Discord respondió ${r.status} al editar el mensaje.` };
        // Lo borraron: los que siguen se publican de nuevo, en orden.
        for (const id of old.slice(i + 1)) await dc(`/channels/${canal}/messages/${id}`, { method: "DELETE" });
        old.length = i;
      }
      const r = await dc(`/channels/${canal}/messages`, { method: "POST", body: payload });
      if (!r.ok) return { ok: false, error: r.status === 403 ? "El bot no puede escribir en ese canal (permisos Ver canal y Enviar mensajes)." : `Discord respondió ${r.status} al publicar.` };
      ids.push((await r.json()).id);
      publicados++;
      await sleep(400);
    }
    for (const id of old.slice(parts.length)) await dc(`/channels/${canal}/messages/${id}`, { method: "DELETE" });
    await sb("pub_msgs?on_conflict=semana,clave", {
      method: "POST",
      headers: { Prefer: "resolution=merge-duplicates" },
      body: JSON.stringify([{ semana, clave, msg_ids: ids, at: new Date().toISOString(), por: limpio(p?.por, 40) || null }]),
    });
    return { ok: true, publicados, editados, mensajes: ids.length, editado: editados > 0 && !publicados };
  }

  // ---------------------------------------------------------------- ROLES ---
  //  { ids }                     → rango + Mecánicos de esos empleados (o quitar todo si están de baja)
  //  { todos: true }             → lo mismo para toda la plantilla
  //  { semanal: { strikes: {id: nivel}, eow: [ids] } } → roles de strike y de Empleado de la Semana
  //  dry: true                   → solo dice qué cambiaría
  async function roles(q: any) {
    const res = { ok: true, cambios: [] as any[], errores: [] as string[] };
    const dry = q?.dry === true;
    if (!idOk(GUILD)) return { ...res, ok: false, errores: ["Falta poner en la función log-empleados el ID del servidor."] };
    const nombresRol = new Map<string, string>();
    const gr = await dc(`/guilds/${GUILD}/roles`);
    if (gr.ok) for (const r of await gr.json()) nombresRol.set(String(r.id), String(r.name));
    else return { ...res, ok: false, errores: [gr.status === 403 ? "El bot no está en el servidor o no tiene permisos." : `Discord respondió ${gr.status} al leer los roles.`] };
    const faltan = [...ROLES_GESTIONADOS].filter((id) => !nombresRol.has(id));
    const rn = (id: string) => nombresRol.get(id) || id;
    // Qué roles debe tener cada uno (solo entre los gestionados) y cuáles no.
    const plan = new Map<string, { e: Emp; quiere: Set<string>; fuera: Set<string> }>();
    const persona = (e: Emp) => {
      const k = String(e.id);
      if (!plan.has(k)) plan.set(k, { e, quiere: new Set(), fuera: new Set() });
      return plan.get(k)!;
    };
    const esTribal = (e: Emp) => rk(e.rank) === "jefe tribal";
    // Cuentas de Discord con varios personajes en el Badulaque (o con el Jefe
    // Tribal): el bot NO les toca ningún rol, se gestionan a mano.
    const uidDe = (e: Emp) => String(e.discord || "").replace(/\D/g, "");
    const porCuenta = new Map<string, Emp[]>();
    for (const e of emps) {
      const u = uidDe(e);
      if (!u) continue;
      if (!porCuenta.has(u)) porCuenta.set(u, []);
      porCuenta.get(u)!.push(e);
    }
    const intocable = (e: Emp) => {
      const u = uidDe(e);
      const todos = (u && porCuenta.get(u)) || [e];
      if (todos.some(esTribal)) return "jefe";
      const activos = todos.filter((x) => !x.despedido_at);
      if (activos.length > 1) return "varios";
      if (e.despedido_at && activos.length) return "varios"; // sigue en el Badulaque con otro personaje
      return "";
    };
    const saltados = new Map<string, string>();
    const rangoDe = (e: Emp) => {
      const p = persona(e);
      const mio = ROLES_RANGO[rk(e.rank)];
      if (e.despedido_at) {
        [...Object.values(ROLES_RANGO), ROL_TRABAJADORES, ...Object.values(ROLES_STRIKE), ROL_EOW].forEach((r) => p.fuera.add(r));
        return;
      }
      for (const r of Object.values(ROLES_RANGO)) (r === mio ? p.quiere : p.fuera).add(r);
      p.quiere.add(ROL_TRABAJADORES);
    };
    const lista = q?.todos === true ? emps : Array.isArray(q?.ids) ? emps.filter((e) => q.ids.map(String).includes(String(e.id))) : [];
    for (const e of lista) {
      const why = intocable(e);
      if (why) saltados.set(uidDe(e) || String(e.id), why);
      else rangoDe(e);
    }
    if (q?.semanal) {
      // Solo se toca la parte que venga: strikes, Empleado de la Semana o las dos.
      const st = q.semanal.strikes;
      const eow = Array.isArray(q.semanal.eow) ? new Set(q.semanal.eow.map(String)) : null;
      for (const e of emps) {
        if (e.despedido_at || esTribal(e)) continue;
        if (intocable(e)) {
          saltados.set(uidDe(e) || String(e.id), intocable(e));
          continue;
        }
        const p = persona(e);
        if (st && typeof st === "object") {
          const n = Math.max(0, Math.min(3, Number(st[String(e.id)]) || 0));
          for (const [k, r] of Object.entries(ROLES_STRIKE)) (Number(k) === n ? p.quiere : p.fuera).add(r);
        }
        if (eow) (eow.has(String(e.id)) ? p.quiere : p.fuera).add(ROL_EOW);
      }
    }
    for (const { e, quiere, fuera } of plan.values()) {
      const nombre = limpio(`${e.name} ${e.surname}`);
      const uid = uidDe(e);
      if (!uid) {
        if (quiere.size) res.cambios.push({ id: e.id, nombre, sinDiscord: true });
        continue;
      }
      const m = await dc(`/guilds/${GUILD}/members/${uid}`);
      if (m.status === 404) {
        if (!e.despedido_at) res.cambios.push({ id: e.id, nombre, fueraDelServidor: true });
        continue;
      }
      if (!m.ok) {
        res.errores.push(`${nombre}: Discord respondió ${m.status}.`);
        continue;
      }
      const tiene = new Set<string>((await m.json()).roles || []);
      const poner = [...quiere].filter((r) => nombresRol.has(r) && !tiene.has(r));
      const quitar = [...fuera].filter((r) => !quiere.has(r) && tiene.has(r));
      if (!poner.length && !quitar.length) continue;
      const rangoPagina = e.despedido_at ? "de baja" : limpio(RANGOS[rk(e.rank)]?.n || e.rank || "sin rango", 30);
      const c: any = { id: e.id, nombre, rango: rangoPagina, poner: poner.map(rn), quitar: quitar.map(rn), ok: true };
      if (!dry) {
        for (const r of poner) {
          const x = await dc(`/guilds/${GUILD}/members/${uid}/roles/${r}`, { method: "PUT", headers: { "X-Audit-Log-Reason": "Badulaque Central (página de la caja)" } });
          if (!x.ok) c.ok = false;
          await sleep(150);
        }
        for (const r of quitar) {
          const x = await dc(`/guilds/${GUILD}/members/${uid}/roles/${r}`, { method: "DELETE", headers: { "X-Audit-Log-Reason": "Badulaque Central (página de la caja)" } });
          if (!x.ok) c.ok = false;
          await sleep(150);
        }
        if (!c.ok) res.errores.push(`${nombre}: no se pudieron cambiar sus roles (el rol del bot tiene que estar por encima de los rangos en la lista de roles, con «Gestionar roles»).`);
      }
      res.cambios.push(c);
    }
    // Quién se ha saltado por tener varios personajes (para que la página lo diga).
    (res as any).saltados = [...saltados.entries()].filter(([, w]) => w === "varios").map(([u]) =>
      (porCuenta.get(u) || []).filter((x) => !x.despedido_at).map((x) => limpio(`${x.name} ${x.surname}`)).join(" / "),
    ).filter(Boolean);
    const usados = faltan.filter((id) => [...plan.values()].some((x) => x.quiere.has(id)));
    if (usados.length) res.errores.push(`Estos roles no existen en el servidor y se saltan: ${usados.map((id) => Object.entries(ROLES_RANGO).find(([, v]) => v === id)?.[0] || id).join(", ")} (${usados.join(", ")}). Revisa su ID.`);
    return res;
  }

  const emps: Emp[] = await sb(
    "employees?select=id,name,surname,rank,discord,iban,no_pay,alta_at,contratado_at,despedido_at,despedido_motivo,licencia,log_msg_id",
  ).then((r) => r.json());
  if (!Array.isArray(emps)) return json({ ok: false, error: "No se pudo leer la tabla de empleados (¿falta el SQL 10?)." }, 500);

  const yo = await dc("/users/@me").then((r) => r.json()).catch(() => ({}));
  if (body.publicar) return json(await publicar(body.publicar));
  if (body.roles) return json(await roles(body.roles));
  const out = { ok: true, publicados: 0, editados: 0, borrados: 0, sinPermiso: 0, errores: [] as string[] };
  if (!idOk(CANAL_LOG)) {
    // Sin canal del log se siguen poniendo los roles.
    if (!sync && ids.length && body.sinRoles !== true) {
      const r = await roles({ ids });
      return json({ ...out, roles: r.cambios, errores: r.errores || [] });
    }
    return json({ ...out, ok: false, error: "Falta poner en la función log-empleados el ID del canal del log de empleados." });
  }

  // 2) Sincronizar todo: borra los mensajes viejos con la plantilla (los
  //    escritos a mano) y los del bot que ya no son de nadie.
  if (sync) {
    const propios = new Set(emps.map((e) => String(e.log_msg_id || "")).filter(Boolean));
    if (reordenar) {
      propios.clear();
      for (const e of emps) e.log_msg_id = null;
    }
    let antes = "";
    for (let p = 0; p < 20; p++) {
      const r = await dc(`/channels/${CANAL_LOG}/messages?limit=100${antes ? `&before=${antes}` : ""}`);
      if (!r.ok) {
        out.errores.push(r.status === 403 ? "El bot no puede ver el canal del log (permisos Ver canal y Leer el historial)." : `Discord respondió ${r.status} al leer el canal.`);
        break;
      }
      const msgs = await r.json();
      if (!Array.isArray(msgs) || !msgs.length) break;
      for (const m of msgs) {
        const delBot = m.author?.id === yo.id && !propios.has(m.id);
        const plantilla = m.author?.id !== yo.id && /\*\*Rango:\*\*/.test(m.content || "") && /\*\*IBAN:\*\*/.test(m.content || "");
        if (!delBot && !plantilla) continue;
        const d = await dc(`/channels/${CANAL_LOG}/messages/${m.id}`, { method: "DELETE" });
        if (d.ok || d.status === 404) out.borrados++;
        else if (d.status === 403) out.sinPermiso++;
        await sleep(350);
      }
      antes = msgs[msgs.length - 1].id;
      if (msgs.length < 100) break;
    }
  }

  // 3) Publicar o editar el mensaje de cada uno.
  const objetivo = sync ? emps : emps.filter((e) => ids.includes(String(e.id)));
  objetivo.sort((a, b) =>
    (a.despedido_at ? 1 : 0) - (b.despedido_at ? 1 : 0) ||
    (RANGOS[rk(b.rank)]?.o || 0) - (RANGOS[rk(a.rank)]?.o || 0) ||
    `${a.name} ${a.surname}`.localeCompare(`${b.name} ${b.surname}`, "es"));
  for (const e of objetivo) {
    if (!String(e.name || "").trim()) continue;
    const content = texto(e);
    const payload = JSON.stringify({ content, allowed_mentions: { parse: [] } });
    let msgId = e.log_msg_id ? String(e.log_msg_id) : "";
    if (msgId) {
      const r = await dc(`/channels/${CANAL_LOG}/messages/${msgId}`, { method: "PATCH", body: payload });
      if (r.ok) {
        out.editados++;
        await sleep(250);
        continue;
      }
      if (r.status !== 404) {
        out.errores.push(`${e.name} ${e.surname}: Discord respondió ${r.status} al editar.`);
        continue;
      }
      msgId = ""; // lo borraron a mano: se publica otra vez
    }
    const r = await dc(`/channels/${CANAL_LOG}/messages`, { method: "POST", body: payload });
    if (!r.ok) {
      out.errores.push(r.status === 403 ? "El bot no puede escribir en el canal del log (permiso Enviar mensajes)." : `${e.name} ${e.surname}: Discord respondió ${r.status} al publicar.`);
      if (r.status === 403) break;
      continue;
    }
    const m = await r.json();
    await sb(`employees?id=eq.${encodeURIComponent(String(e.id))}`, { method: "PATCH", body: JSON.stringify({ log_msg_id: m.id }) });
    out.publicados++;
    await sleep(400);
  }
  if (out.errores.length) out.ok = out.publicados + out.editados > 0;
  // Roles de los empleados tocados (rango + Trabajadores; quitar todo al despedir).
  if (!sync && ids.length && body.sinRoles !== true) {
    const r = await roles({ ids });
    (out as any).roles = r.cambios;
    if (r.errores?.length) out.errores.push(...r.errores);
  }
  return json(out);
});
