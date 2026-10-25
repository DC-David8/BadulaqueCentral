// ============================================================================
// Badulaque Central · Fase 2: bot de facturas (paso 2 de 3)
// Supabase → Edge Functions → Deploy a new function → Via Editor
// Nombre de la función: leer-logs  ·  pega todo este archivo y pulsa Deploy.
// Después, en los ajustes de la función, DESACTIVA "Verify JWT" (o "Enforce
// JWT verification"): así la puede llamar el aviso cada 5 minutos. La función
// solo copia el canal de facturas a la tabla; no devuelve ningún dato.
//
// Secretos (Edge Functions → Secrets → Add new secret):
//   DISCORD_BOT_TOKEN  → el token del bot (NUNCA lo pegues en otro sitio)
//   LOG_CHANNEL_ID     → el ID del canal de facturas de tu Discord
// SUPABASE_URL y SUPABASE_SERVICE_ROLE_KEY ya los pone Supabase solo.
// ============================================================================

const API = "https://discord.com/api/v10";
const DIAS_PRIMERA_VEZ = 45; // la primera vez trae los últimos 45 días
const MAX_PAGINAS = 60; // tope por ejecución (6.000 mensajes)

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-client-info",
};

function json(obj: unknown, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { ...cors, "Content-Type": "application/json" },
  });
}

// Convierte una fecha en un "snowflake" de Discord para pedir desde ahí.
function snowflakeDe(fechaMs: number) {
  return ((BigInt(fechaMs) - 1420070400000n) << 22n).toString();
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });

  const BOT = Deno.env.get("DISCORD_BOT_TOKEN");
  const CANAL = Deno.env.get("LOG_CHANNEL_ID");
  const SB_URL = Deno.env.get("SUPABASE_URL");
  const SB_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!BOT || !CANAL || !SB_URL || !SB_KEY) {
    return json({ ok: false, error: "Faltan secretos DISCORD_BOT_TOKEN o LOG_CHANNEL_ID" }, 500);
  }

  const sb = (path: string, init: RequestInit = {}) =>
    fetch(`${SB_URL}/rest/v1/${path}`, {
      ...init,
      headers: {
        apikey: SB_KEY,
        Authorization: `Bearer ${SB_KEY}`,
        "Content-Type": "application/json",
        ...(init.headers || {}),
      },
    });

  // ¿Desde dónde seguimos? El último mensaje guardado (o hace 45 días).
  const ult = await sb("discord_log?select=id&order=ts.desc&limit=1").then((r) => r.json());
  let despues: string = Array.isArray(ult) && ult[0]?.id
    ? ult[0].id
    : snowflakeDe(Date.now() - DIAS_PRIMERA_VEZ * 86400000);

  let nuevos = 0;
  for (let pagina = 0; pagina < MAX_PAGINAS; pagina++) {
    const r = await fetch(`${API}/channels/${CANAL}/messages?limit=100&after=${despues}`, {
      headers: { Authorization: `Bot ${BOT}` },
    });
    if (r.status === 429) {
      const espera = Number((await r.json()).retry_after || 1);
      await new Promise((ok) => setTimeout(ok, Math.ceil(espera * 1000) + 100));
      pagina--;
      continue;
    }
    if (!r.ok) {
      return json({ ok: false, error: `Discord respondió ${r.status}: ${await r.text()}`, nuevos }, 502);
    }
    const msgs = (await r.json()) as any[];
    if (!msgs.length) break;

    // Discord los da del más nuevo al más viejo: los ordenamos.
    msgs.sort((a, b) => (BigInt(a.id) < BigInt(b.id) ? -1 : 1));
    const filas = msgs.map((m) => ({
      id: m.id,
      ts: m.timestamp,
      author: m.author?.global_name || m.author?.username || null,
      content: m.content || "",
      embeds: m.embeds || [],
    }));
    const up = await sb("discord_log?on_conflict=id", {
      method: "POST",
      headers: { Prefer: "resolution=ignore-duplicates,return=minimal" },
      body: JSON.stringify(filas),
    });
    if (!up.ok) return json({ ok: false, error: `Supabase: ${await up.text()}`, nuevos }, 500);

    nuevos += filas.length;
    despues = msgs[msgs.length - 1].id;
    if (msgs.length < 100) break;
  }

  return json({ ok: true, nuevos });
});
