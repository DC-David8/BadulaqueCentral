// ============================================================================
// CONTRASEÑAS
// ----------------------------------------------------------------------------
// Cada zona protegida tiene su propia contraseña. No se guardan en texto
// plano: solo su huella SHA-256, para que no se puedan leer mirando el codigo
// en GitHub.
//
// Para cambiar una contraseña:
//   1. Abre la pagina en el navegador, pulsa F12 -> pestaña "Consola".
//   2. Escribe:  await baduHash("tu_nueva_clave")   y pulsa Enter.
//   3. Copia el texto que sale y pegalo en la zona que quieras de abajo.
// Si dos zonas tienen la misma huella, comparten contraseña: Pagos, Crafteos
// y Sorteo usan la de gerencia; Productos y Empleados, la de jefe.
// ============================================================================
const PASSWORD_SALT = "badulaque-central:";
const PASSWORD_HASHES = {
  // Pestaña "Pagos" (incluye Totales empleados)
  facturas: "cb71ca1470c6a2d157fe7afb1c5ea0001baba5410f714a00ff762078071ee3a9",
  // Pestaña "Crafteos / Suministros"
  crafteos: "cb71ca1470c6a2d157fe7afb1c5ea0001baba5410f714a00ff762078071ee3a9",
  // Pestaña "Sorteo" (misma contraseña que Pagos, la de gerencia)
  sorteo: "cb71ca1470c6a2d157fe7afb1c5ea0001baba5410f714a00ff762078071ee3a9",
  // "Gestion de Productos" (precios, suministros, quitar productos)
  productos: "36e9c1f5277f70721e0b9566188e05c00b752bdb10754d90d01017500052ad29",
  // "Gestion empleados" (añadir / eliminar empleados)
  empleados: "36e9c1f5277f70721e0b9566188e05c00b752bdb10754d90d01017500052ad29",
};

// SHA-256 en JS puro, por si crypto.subtle no esta disponible (pagina servida
// por HTTP sin cifrar o webview antiguo).
function sha256HexFallback(str) {
  const bytes = new TextEncoder().encode(str);
  const K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);
  const H = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
  const len = bytes.length;
  const total = Math.ceil((len + 9) / 64) * 64;
  const buf = new Uint8Array(total);
  buf.set(bytes);
  buf[len] = 0x80;
  const dv = new DataView(buf.buffer);
  dv.setUint32(total - 8, Math.floor(len / 0x20000000));
  dv.setUint32(total - 4, (len * 8) >>> 0);
  const W = new Uint32Array(64);
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));
  for (let off = 0; off < total; off += 64) {
    for (let t = 0; t < 16; t++) W[t] = dv.getUint32(off + t * 4);
    for (let t = 16; t < 64; t++) {
      const s0 = rotr(W[t - 15], 7) ^ rotr(W[t - 15], 18) ^ (W[t - 15] >>> 3);
      const s1 = rotr(W[t - 2], 17) ^ rotr(W[t - 2], 19) ^ (W[t - 2] >>> 10);
      W[t] = (W[t - 16] + s0 + W[t - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, h] = H;
    for (let t = 0; t < 64; t++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K[t] + W[t]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0;
      d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e; H[5] += f; H[6] += g; H[7] += h;
  }
  return Array.from(H, (x) => x.toString(16).padStart(8, "0")).join("");
}

async function sha256Hex(str) {
  try {
    if (window.crypto?.subtle) {
      const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
      return Array.from(new Uint8Array(digest), (x) => x.toString(16).padStart(2, "0")).join("");
    }
  } catch {
    // sigue con la version JS
  }
  return sha256HexFallback(str);
}

// Ayuda para generar huellas desde la consola del navegador (ver arriba).
async function baduHash(password) {
  return sha256Hex(PASSWORD_SALT + String(password ?? ""));
}
window.baduHash = baduHash;

async function verifyPassword(zone, password) {
  const expected = PASSWORD_HASHES[zone];
  if (!expected) return false;
  const pass = String(password ?? "");
  if (!pass) return false;
  return (await baduHash(pass)) === expected;
}

const PRODUCTS = [
  { name: "Alitas", price: 1000, image: "alitas.png" },
  { name: "Venda", price: 600, image: "venda.png" },
  { name: "Cerveza", price: 200, image: "cerveza.png" },
  { name: "Bocadillo de Bacon", price: 250, image: "bocadillo_de_bacon.png" },
  { name: "Bocadillo Iberico", price: 250, image: "bocadillo_iberico.png" },
  { name: "Bocadillo de Lomo", price: 250, image: "bocadillo_de_lomo.png" },
  { name: "Bocadillo de Tortilla", price: 250, image: "bocadillo_de_tortilla.png" },
  { name: "Bocadillo Vegetal", price: 250, image: "bocadillo_vegetal.png" },
  { name: "Pan", price: 200, image: "pan.png" },
  { name: "Cortadito", price: 2500, image: "Cortadito.png" },
  { name: "Cerveza Mixta", price: 350, image: "cerveza_mixta.png" },
  { name: "Cimarrona", price: 1000, image: "cimarrona.png" },
  { name: "Donas", price: 150, image: "donas.png" },
  { name: "Energy", price: 100, image: "energy.png" },
  { name: "Granizado", price: 350, image: "granizado.png" },
  { name: "Menu Badulaque", price: 300, image: "menu_badulaque.png" },
  { name: "Michelada", price: 350, image: "michelada.png" },
  { name: "Telefono", price: 900, image: "Telefono.png" },
  { name: "Pizza", price: 100, image: "pizza.png" },
  { name: "Refresco de Cola", price: 100, image: "refresco_de_cola.png" },
  { name: "Refresco de Limon", price: 100, image: "refresco_de_limon.png" },
  { name: "Spray", price: 1000, image: "spray.png" },
  { name: "Spray Remove", price: 150, image: "spray_remove.png" },
  { name: "Tacos de Birria", price: 350, image: "tacos_de_birria.png" },
  { name: "Vaper", price: 1500, image: "vaper.png" },
  { name: "Agua", price: 100, image: "Agua.png" },
  { name: "Bayeta", price: 500, image: "bayeta.png" },
  { name: "Recarga de Cachimba", price: 1000, image: "recarga_de_cachimba.png" },
  { name: "Mochila de Outfits", price: 5000, image: "mochila_de_outfits.png" },
];

// ============================================================================
// Concepto para el datafono (maximo 40 caracteres), igual que en Aguila Motors.
// Si el concepto completo no cabe, se abrevia: "2xAlitas+3xCerv, Bacon+Lomo Boc".
// [abreviatura, grupo]: el grupo (Boc = bocadillos) se escribe una vez al final.
// Las claves van en minusculas y sin tildes.
// ============================================================================
const CONCEPT_MAX = 40;

const PRODUCT_SHORT = {
  "alitas": ["Alitas", ""],
  "venda": ["Venda", ""],
  "cerveza": ["Cerv", ""],
  "bocadillo de bacon": ["Bacon", "Boc"],
  "bocadillo iberico": ["Iber", "Boc"],
  "bocadillo de lomo": ["Lomo", "Boc"],
  "bocadillo de tortilla": ["Tort", "Boc"],
  "bocadillo vegetal": ["Veg", "Boc"],
  "pan": ["Pan", ""],
  "cortadito": ["Cort", ""],
  "cerveza mixta": ["CervMix", ""],
  "cimarrona": ["Cimarr", ""],
  "donas": ["Donas", ""],
  "energy": ["Energy", ""],
  "granizado": ["Graniz", ""],
  "menu badulaque": ["Menu", ""],
  "michelada": ["Mich", ""],
  "telefono": ["Tlf", ""],
  "pizza": ["Pizza", ""],
  "refresco de cola": ["Cola", ""],
  "refresco de limon": ["Limon", ""],
  "spray": ["Spray", ""],
  "spray remove": ["SprayRem", ""],
  "tacos de birria": ["Tacos", ""],
  "vaper": ["Vaper", ""],
  "agua": ["Agua", ""],
  "bayeta": ["Bayeta", ""],
  "recarga de cachimba": ["Cachimba", ""],
  "mochila de outfits": ["Mochila", ""],
};

const CRAFTEO_SUPPLIES = {
  venda: 10,
  cerveza: 2,
  "bocadillo de bacon": 3,
  "bocadillo iberico": 3,
  "bocadillo de lomo": 3,
  "bocadillo de tortilla": 3,
  "bocadillo vegetal": 3,
  "alitas": 3,
  "cerveza mixta": 3,
  "michelada": 3,
  "tacos de birria": 3,
  "cimarrona": 3,
  pan: 1,
  cortadito: 5,
  donas: 1,
  energy: 1,
  granizado: 1,
  "menu badulaque": 3,
  telefono: 5,
  pizza: 1,
  "refresco de cola": 1,
  "refresco de limon": 1,
  spray: 3,
  "spray remove": 3,
  vaper: 3,
  agua: 1,
  "mochila de outfits": 20,
};

const RE_NEW = /^\s*Nueva\s+Factura\s*$/i;
const RE_PAID = /^\s*Factura\s+Pagada\s*$/i;
const RE_ID = /^\s*ID\s*Factura:\s*`?(\d+)`?\s*$/i;
const RE_ISSUER = /^\s*Emitida\s*por:\s*(.+?)\s*$/i;
const RE_TO = /^\s*Para:\s*(.+?)\s*$/i;
const RE_AMOUNT = /^\s*Cantidad:\s*\$?\s*`?([\d.,]+)`?\s*$/i;
const RE_CONCEPT = /^\s*Concepto:\s*(.+?)\s*$/i;
const RE_TS = /^\s*(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s*$/i;
const RE_RASCA = /^[^A-Za-z0-9]*Venta\s+de\s+Rasca\s+y\s+Gana\s*[^A-Za-z0-9]*$/i;
const RE_BUYER = /^\s*Comprador:\s*(.+?)\s*$/i;
const RE_SELLER = /^\s*Vendedor:\s*(.+?)\s*$/i;
const RE_QTY = /^\s*Cantidad:\s*`?(\d+)`?\s*$/i;
const RE_TOTAL = /^\s*Total:\s*\$?\s*`?([\d.,]+)`?\s*€?\s*$/i;
const RE_IGNORE = /^(Haz clic para reaccionar|Anadir reaccion|A\u00f1adir reaccion|Responder|Reenviar|Mas|M\u00e1s|:\w+:)$/i;

// Datafono TPV (formato nuevo). El bloque se abre con la linea del importe
// ("150000\u20ac"), que siempre llega entera al copiar desde Discord; la
// cabecera ("Datafono TPVAPP - HH:MM") suele llegar partida en varias lineas.
const RE_DTF_AMOUNT = /^\s*`?([\d.,]+)`?\s*\u20ac\s*$/;
const RE_DTF_COMERCIO = /^\s*Comercio:\s*(.+?)\s*$/i;
const RE_DTF_COBRADOR = /^\s*Cobrador:\s*(.+?)\s*(?:\(ID:\s*\d+\))?\s*$/i;
const RE_DTF_CLIENTE = /^\s*Cliente:\s*(.+?)\s*(?:\(ID:\s*\d+\))?\s*$/i;
const RE_DTF_AUT = /^\s*AUT:\s*([^\s\u2022]+)\s*\u2022\s*TARJETA:\s*(.+?)\s*\u2022\s*Dat[\u00e1a]fono\s*TPV\s*\u2022\s*(.+?)\s*$/i;
const RE_CRAFTEO = /^\s*(?<who>.+?)\s+crafte(?:o|\u00f3)\s+(?<qty>\d+)x\s+(?<item>.+?)\s*$/i;

const byId = (id) => document.getElementById(id);
// Pestañas protegidas -> zona de contraseña (ver PASSWORD_HASHES).
const TAB_PASSWORD_ZONES = {
  "tab-conta": "facturas",
  "tab-craft": "crafteos",
  "tab-sorteo": "sorteo",
};

const EMPLOYEE_STORAGE_KEY = "badu_employees_v1";

function stripWrap(s) {
  return String(s ?? "").trim().replace(/^`+|`+$/g, "").trim();
}

function escapeHtml(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function safeRandomId() {
  try {
    return crypto.randomUUID();
  } catch {
    return `emp_${Date.now()}_${Math.random().toString(16).slice(2)}`;
  }
}

function loadEmployeesLocal() {
  try {
    const raw = localStorage.getItem(EMPLOYEE_STORAGE_KEY);
    const parsed = JSON.parse(raw || "[]");
    if (!Array.isArray(parsed)) return [];
    return parsed
      .map((e) => ({
        id: String(e?.id || safeRandomId()),
        name: String(e?.name || "").trim(),
        surname: String(e?.surname || "").trim(),
        rank: String(e?.rank || "").trim(),
      }))
      .filter((e) => e.name && e.surname);
  } catch {
    return [];
  }
}

function saveEmployeesLocal(list) {
  localStorage.setItem(EMPLOYEE_STORAGE_KEY, JSON.stringify(list || []));
}

let _pyApiGaveUp = false;

async function waitPyApi(maxMs = 2500) {
  // En la version web (navegador) no existe el backend de escritorio: tras el
  // primer intento fallido no se vuelve a esperar, para no retrasar cada accion.
  if (_pyApiGaveUp) return window?.pywebview?.api || null;
  const start = Date.now();
  while (Date.now() - start < maxMs) {
    const api = window?.pywebview?.api;
    if (api) return api;
    await new Promise((r) => setTimeout(r, 50));
  }
  _pyApiGaveUp = true;
  return null;
}

async function listEmployees() {
  if (cloudOn()) {
    await AUTH_READY;
    if (!isJefe()) return [];
    return (await empCloudLoad()).filter((e) => !e.firedAt).map((e) => ({ id: e.id, name: e.name, surname: e.surname, rank: e.rank }));
  }
  const api = await waitPyApi();
  if (api && typeof api.emp_list === "function") {
    try {
      const data = await api.emp_list();
      const arr = Array.isArray(data) ? data : (Array.isArray(data?.employees) ? data.employees : []);
      return arr.map((e) => ({ ...e, rank: canonRank(e.rank) }));
    } catch {
    }
  }
  return loadEmployeesLocal().map((e) => ({ ...e, rank: canonRank(e.rank) }));
}

// El programa de escritorio (.exe) recibe su propia clave al guardar empleados.
// Se mantiene la antigua para que siga funcionando; la nueva se valida aqui.
const BACKEND_LEGACY_PASSWORD = "0000";

async function addEmployee(payload, password) {
  if (cloudOn()) {
    // Todo en un solo guardado (como Aguila v100): antes Discord e IBAN iban
    // en guardados aparte, sin esperar, y se podian pisar con la recarga.
    const row = { name: payload.name, surname: payload.surname, rank: payload.rank || "", discord: payload.discord || "", iban: payload.iban || "" };
    if (EMP_CLOUD.hasDates) {
      row.alta_at = payload.altaAt || empToday();
      row.contratado_at = payload.contratadoAt || row.alta_at;
    }
    await empCloudInsert(row);
    return true;
  }
  if (!(await verifyPassword("empleados", password))) {
    throw new Error("Contraseña incorrecta");
  }

  const api = await waitPyApi();
  if (api && typeof api.emp_add === "function") {
    await api.emp_add(payload, BACKEND_LEGACY_PASSWORD);
    return true;
  }

  const current = loadEmployeesLocal();
  current.push({ id: safeRandomId(), ...payload });
  saveEmployeesLocal(current);
  return true;
}

async function deleteEmployee(id, password) {
  if (cloudOn()) {
    await empCloudDelete(id);
    return true;
  }
  if (!(await verifyPassword("empleados", password))) {
    throw new Error("Contraseña incorrecta");
  }

  const api = await waitPyApi();
  if (api && typeof api.emp_delete === "function") {
    await api.emp_delete(id, BACKEND_LEGACY_PASSWORD);
    return true;
  }

  const current = loadEmployeesLocal();
  const next = current.filter((e) => String(e.id) !== String(id));
  saveEmployeesLocal(next);
  return true;
}

// ---------------------------------------------------------------------------
// Despidos: en vez de borrar al empleado se le marca como despedido (fecha,
// motivo y quien lo hizo) y queda en el registro de "Despedidos".
// Con la nube son columnas de la tabla employees; sin ella (programa de
// escritorio) el registro se guarda en este equipo y el empleado sale de la
// lista del programa.
// ---------------------------------------------------------------------------
// Quien hace un cambio: el nombre del personaje (o el de Discord si no hay perfil).
function authWho() {
  return (AUTH.profile && fullName(AUTH.profile)) || AUTH.name || "";
}

const EMPLOYEE_FIRED_STORAGE_KEY = "badu_employees_fired_v1";

function loadFiredLocal() {
  try {
    const arr = JSON.parse(localStorage.getItem(EMPLOYEE_FIRED_STORAGE_KEY) || "[]");
    return Array.isArray(arr) ? arr : [];
  } catch {
    return [];
  }
}

function saveFiredLocal(list) {
  try {
    localStorage.setItem(EMPLOYEE_FIRED_STORAGE_KEY, JSON.stringify(list));
  } catch {
    // sin almacenamiento
  }
}

// Despedidos, el mas reciente primero: { id, name, surname, rank, firedAt, firedBy, firedReason }.
function listFired() {
  const list = cloudOn() ? EMP_CLOUD.list.filter((e) => e.firedAt) : loadFiredLocal().map((e) => ({ ...e, rank: canonRank(e.rank) }));
  return [...list].sort((a, b) => String(b.firedAt).localeCompare(String(a.firedAt)));
}

function findFired(fullNameStr) {
  const k = normalizeKeySimple(fullNameStr);
  return listFired().find((e) => normalizeKeySimple(fullName(e)) === k) || null;
}

async function fireEmployee(e, reason, password) {
  const full = fullName(e);
  if (cloudOn()) {
    await empCloudPatch(e.id, { despedido_at: new Date().toISOString(), despedido_por: authWho(), despedido_motivo: reason });
    return true;
  }
  const discord = getEmployeeDiscord(full);
  const iban = getEmployeeIban(full);
  await deleteEmployee(e.id, password); // comprueba la contrasena
  const rec = {
    id: safeRandomId(), name: e.name, surname: e.surname, rank: e.rank || "",
    discord, iban, firedAt: new Date().toISOString(), firedBy: "Gerencia", firedReason: reason,
  };
  saveFiredLocal([rec, ...loadFiredLocal().filter((x) => normalizeKeySimple(fullName(x)) !== normalizeKeySimple(full))]);
  setEmployeeDiscord(full, "");
  setEmployeeIban(full, "");
  setEmployeeNoPay(full, false);
  return true;
}

async function readmitEmployee(rec, password) {
  if (cloudOn()) {
    // Nuevo contrato (la fecha de ingreso no cambia).
    await empCloudPatch(rec.id, { despedido_at: null, despedido_por: null, despedido_motivo: null, ...(EMP_CLOUD.hasDates ? { contratado_at: empToday() } : {}) });
    return true;
  }
  await addEmployee({ name: rec.name, surname: rec.surname, rank: rec.rank || "" }, password);
  const full = fullName(rec);
  if (rec.discord) setEmployeeDiscord(full, rec.discord);
  if (rec.iban) setEmployeeIban(full, rec.iban);
  const dts = loadDatesLocal()[normalizeKeySimple(full)] || {};
  setEmployeeDatesLocal(full, { a: dts.a || rec.altaAt || "", c: empToday() });
  saveFiredLocal(loadFiredLocal().filter((x) => x.id !== rec.id));
  return true;
}

// Cambiar el rango de un empleado. El programa de escritorio no tiene una
// funcion para editar, asi que alli se borra y se vuelve a anadir con el
// rango nuevo (el resto de datos se guarda por nombre, asi que no se pierde).
async function updateEmployee(id, payload, password) {
  if (cloudOn()) {
    await empCloudPatch(id, payload);
    return true;
  }
  if (!(await verifyPassword("empleados", password))) {
    throw new Error("Contraseña incorrecta");
  }

  const api = await waitPyApi();
  if (api && typeof api.emp_update === "function") {
    await api.emp_update(id, payload, BACKEND_LEGACY_PASSWORD);
    return true;
  }
  if (api && typeof api.emp_add === "function" && typeof api.emp_delete === "function") {
    const list = await listEmployees();
    const existing = list.find((e) => String(e.id) === String(id));
    if (!existing) throw new Error("Empleado no encontrado");
    const merged = { name: existing.name, surname: existing.surname, rank: existing.rank || "", ...payload };
    await api.emp_delete(id, BACKEND_LEGACY_PASSWORD);
    await api.emp_add(merged, BACKEND_LEGACY_PASSWORD);
    return true;
  }

  const current = loadEmployeesLocal();
  const idx = current.findIndex((e) => String(e.id) === String(id));
  if (idx === -1) throw new Error("Empleado no encontrado");
  current[idx] = { ...current[idx], ...payload };
  saveEmployeesLocal(current);
  return true;
}

// ============================================================================
// Rangos y comision (% de lo cobrado: facturas pagadas + rascas)
// ============================================================================
const RANKS = [
  { label: "Reponedor", pct: 0.35 },
  { label: "Cajero", pct: 0.40 },
  { label: "Cajero Principal", pct: 0.45 },
  { label: "Supervisor", pct: 0.50 },
  { label: "Gerente", pct: 0.50 },
  { label: "Jefe Tribal", pct: 1.00 }, // solo el dueño
];

// Nombres antiguos de los rangos (hasta la version 26). Si un empleado aun
// los tiene guardados (en la nube o en el programa de escritorio), se leen
// con el nombre nuevo.
const RANK_ALIASES = {
  "en pruebas": "Reponedor",
  "cajero experimentado": "Cajero Principal",
  encargado: "Supervisor",
  jefe: "Gerente",
};
function canonRank(rank) {
  const r = String(rank || "").trim();
  return RANK_ALIASES[normalizeKeySimple(r)] || r;
}

function pctForRank(rank) {
  const key = normalizeKeySimple(canonRank(rank));
  const found = RANKS.find((r) => normalizeKeySimple(r.label) === key);
  return found ? found.pct : 0;
}

const pctText = (pct) => `${Math.round(pct * 100)}%`;

function fullName(e) {
  return `${String(e?.name || "").trim()} ${String(e?.surname || "").trim()}`.replace(/\s+/g, " ").trim();
}

// Rol de Discord del empleado de la semana (quien mas cobra).
const EMPLOYEE_OF_WEEK_TAG = "<@&1364707155130712195>";

// Roles de Discord de cada rango (para el anuncio de ascensos y descensos).
// Vacio = sale el nombre del rango en negrita en vez de etiquetar.
const RANK_ROLE_IDS = {
  Reponedor: "1364613906915655763",
  Cajero: "1566682203524702218",
  "Cajero Principal": "1364613906915655764",
  Supervisor: "1364613906915655768",
  Gerente: "1366562494260318322",
  "Jefe Tribal": "1364613906915655770",
};
const ROLE_TAG_JEFATURA = "<@&1556057218133262336>";
const ROLE_TAG_TRABAJADORES = "<@&1563907257073143919>";
function rankRoleTag(rank) {
  const r = canonRank(rank);
  const id = RANK_ROLE_IDS[r];
  return id ? `<@&${id}>` : `**${r || "sin rango"}**`;
}

// ---------------------------------------------------------------------------
// Fechas de cada empleado (como Aguila Motors v101):
//   alta_at        = INGRESO al Badulaque (su primer dia; no cambia aunque le
//                    despidan y le readmitan).
//   contratado_at  = CONTRATACION (la del contrato actual; al readmitir se
//                    pone la del dia).
// Con la nube son columnas de employees (SQL 9); sin ella se guardan en este
// equipo.
// ---------------------------------------------------------------------------
const EMPLOYEE_ALTA_STORAGE_KEY = "badu_employees_alta_v1";
function loadDatesLocal() {
  try {
    const m = JSON.parse(localStorage.getItem(EMPLOYEE_ALTA_STORAGE_KEY) || "{}") || {};
    // Hasta la v32 solo habia una fecha (la de contratacion): vale para las dos.
    for (const k of Object.keys(m)) if (typeof m[k] === "string") m[k] = { a: m[k], c: m[k] };
    return m;
  } catch {
    return {};
  }
}
function setEmployeeDatesLocal(fullNameStr, dates) {
  const m = loadDatesLocal();
  const k = normalizeKeySimple(fullNameStr);
  if (dates && (dates.a || dates.c)) m[k] = { a: dates.a || "", c: dates.c || "" };
  else delete m[k];
  try {
    localStorage.setItem(EMPLOYEE_ALTA_STORAGE_KEY, JSON.stringify(m));
  } catch {
    // sin almacenamiento
  }
}
// "AAAA-MM-DD" en la hora de este equipo.
function localDay(v) {
  if (!v) return "";
  const t = String(v);
  if (/^\d{4}-\d{2}-\d{2}$/.test(t)) return t;
  const d = new Date(t);
  if (Number.isNaN(d.getTime())) return "";
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}
const empToday = () => localDay(new Date().toISOString());
const fmtDayEs = (day) => (day ? `${day.slice(8, 10)}/${day.slice(5, 7)}/${day.slice(0, 4)}` : "");
const empDate = (iso) => fmtDayEs(localDay(iso));
// "3 meses", "1 año y 2 meses", "12 días"...
function empSeniority(iso) {
  const s = localDay(iso);
  if (!s) return "";
  const a = new Date(`${s}T12:00:00`);
  const b = new Date(`${empToday()}T12:00:00`);
  const days = Math.round((b - a) / 86400000);
  if (days < 0) return "";
  if (days < 31) return `${days} ${days === 1 ? "día" : "días"}`;
  let months = (b.getFullYear() - a.getFullYear()) * 12 + (b.getMonth() - a.getMonth());
  if (b.getDate() < a.getDate()) months--;
  const y = Math.floor(months / 12);
  const m = months % 12;
  if (!y) return `${m} ${m === 1 ? "mes" : "meses"}`;
  return `${y} ${y === 1 ? "año" : "años"}${m ? ` y ${m} ${m === 1 ? "mes" : "meses"}` : ""}`;
}
// Se pueden guardar las dos fechas: sin la nube siempre; con ella, con el SQL 9.
const empHasDates = () => !cloudOn() || !!EMP_CLOUD.hasDates;
// { altaAt, contratadoAt } (AAAA-MM-DD o "").
function empDatesOf(e) {
  if (cloudOn()) {
    const r = EMP_CLOUD.list.find((x) => String(x.id) === String(e.id));
    return { altaAt: r?.altaAt || "", contratadoAt: r?.contratadoAt || "" };
  }
  const d = loadDatesLocal()[normalizeKeySimple(fullName(e))] || {};
  return { altaAt: d.a || "", contratadoAt: d.c || "" };
}

// ---------------------------------------------------------------------------
// Aviso de inactividad (como Aguila Motors v123). Con las facturas que el bot
// copia del Discord del Badulaque (tabla discord_log) se sabe la ultima
// factura de cada empleado (cobrador del datafono). Se miran los ultimos 30
// dias; los dias de cada color los cambia el Jefe Tribal (app_settings
// "inact_dias").
// ---------------------------------------------------------------------------
const INACT_DEFAULT = { aviso: 3, alerta: 5, grave: 7 };
const INACT_VENTANA = 30; // dias hacia atras que se leen
const INACT = { ok: false, at: 0, last: new Map(), desde: 0, dias: { ...INACT_DEFAULT }, loading: null };
async function inactLoad(force = false) {
  if (!cloudOn() || !isJefe() || !cloud.session) return false;
  if (!force && INACT.ok && Date.now() - INACT.at < 5 * 60000) return true;
  if (INACT.loading) return INACT.loading;
  INACT.loading = (async () => {
    try {
      const desde = Date.now() - INACT_VENTANA * 86400000;
      const rows = [];
      for (let off = 0; ; off += 1000) {
        const part = await cloud.req(`/rest/v1/discord_log?select=id,ts,content,embeds&ts=gte.${encodeURIComponent(new Date(desde).toISOString())}&order=ts.asc,id.asc&limit=1000&offset=${off}`);
        if (!Array.isArray(part)) break;
        rows.push(...part);
        if (part.length < 1000) break;
      }
      const last = new Map();
      for (const r of rows) {
        const txt = dlogMessageText(r);
        if (!txt) continue;
        let res;
        try {
          res = processText(txt);
        } catch {
          continue;
        }
        const t = +new Date(r.ts);
        for (const inv of Object.values(res.invoices || {})) {
          if (!inv.issuer) continue;
          const k = normalizeKeySimple(inv.issuer);
          if (!last.has(k) || last.get(k) < t) last.set(k, t);
        }
      }
      let dias = { ...INACT_DEFAULT };
      try {
        const st = await cloud.req("/rest/v1/app_settings?select=value&key=eq.inact_dias");
        if (st?.[0]?.value) dias = { ...dias, ...st[0].value };
      } catch {
        // sin ajustes: los de siempre
      }
      Object.assign(INACT, { ok: true, at: Date.now(), last, desde, dias });
    } catch {
      // sin acceso a las facturas: no se avisa
    } finally {
      INACT.loading = null;
    }
    return INACT.ok;
  })();
  return INACT.loading;
}
async function inactSaveDias(d) {
  const v = { aviso: Math.max(1, Math.round(d.aviso)), alerta: Math.max(1, Math.round(d.alerta)), grave: Math.max(1, Math.round(d.grave)) };
  if (!(v.aviso < v.alerta && v.alerta < v.grave)) throw new Error("Los días tienen que ir de menos a más (aviso < alerta < grave).");
  if (v.grave > INACT_VENTANA) throw new Error(`El máximo es ${INACT_VENTANA} días.`);
  if (!cloudOn() || !AUTH.tribal) throw new Error("Solo el Jefe Tribal puede cambiar los días.");
  await cloud.req("/rest/v1/app_settings?on_conflict=key", {
    method: "POST",
    headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
    body: [{ key: "inact_dias", value: v }],
  });
  INACT.dias = v;
}
// { days, last, level (0-3), more } · more = no facturo en toda la ventana.
// El Jefe Tribal no lleva aviso.
function inactOf(e) {
  if (!INACT.ok || !e || isOwnerRank(e.rank)) return null;
  const now = Date.now();
  const t = INACT.last.get(normalizeKeySimple(fullName(e)));
  const altaDay = empDatesOf(e).altaAt;
  const alta = altaDay ? +new Date(`${altaDay}T00:00:00`) : 0;
  let days;
  let more = false;
  if (t) days = Math.floor((now - t) / 86400000);
  else {
    const base = Math.max(INACT.desde, alta);
    days = Math.floor((now - base) / 86400000);
    more = base === INACT.desde;
  }
  const D = INACT.dias;
  const level = days >= D.grave ? 3 : days >= D.alerta ? 2 : days >= D.aviso ? 1 : 0;
  return { days, last: t || null, level, more };
}
function inactText(x) {
  if (!x) return "";
  if (x.more) return `Sin facturar en más de ${INACT_VENTANA} días`;
  if (!x.last) return x.days ? `Sin facturar desde que entró (hace ${x.days} ${x.days === 1 ? "día" : "días"})` : "Entró hoy";
  return x.days === 0 ? "Ha facturado hoy" : `Sin facturar desde hace ${x.days} ${x.days === 1 ? "día" : "días"}`;
}
// 💤 Etiqueta de inactividad (solo a partir del primer aviso).
function inactChip(e, always = false) {
  const x = inactOf(e);
  if (!x || (!x.level && !always)) return null;
  const c = document.createElement("span");
  c.className = `emp-inact l${x.level}`;
  c.textContent = x.level ? `💤 ${x.more ? `+${INACT_VENTANA}` : x.days} d` : "✅ Activo";
  c.title = `${inactText(x)}${x.last ? ` · última factura ${dlogDate(new Date(x.last).toISOString())}` : ""}`;
  return c;
}

// ---------------------------------------------------------------------------
// Movimientos de personal de la semana para Discord (como Aguila Motors
// v117-v121): ascensos, descensos y bajas en UN solo mensaje. Los ascensos y
// descensos salen del historial (emp_historial, tipo "rango"); las bajas, de
// los despedidos de esa semana. Cierra con una frase y la etiqueta de Jefatura.
// ---------------------------------------------------------------------------
const ASC_MOTIVOS = [
  "por su excelente labor y compromiso con el Badulaque. 🏆",
  "por su gran rendimiento esta semana. 🛒",
  "por su constancia y dedicación. 💪",
  "por estar a la altura y dar siempre el máximo. 🔥",
  "por tener la caja siempre cuadrada al céntimo. 💵",
  "por no soltar el datáfono ni un solo turno. 💳",
  "por atender a cada cliente con una sonrisa. 😄",
  "por ser de los que más venden y mejor atienden. 💰",
  "por su seriedad y profesionalidad en el mostrador. 🤝",
  "por tirar del Badulaque cuando más falta hacía. 🍎",
  "por tener los estantes siempre llenos y en orden. 📦",
  "por despachar más rápido que nadie. ⚡",
  "por ser un ejemplo para sus compañeros de turno. ⭐",
  "por su esfuerzo diario detrás del mostrador. 🧾",
  "por ponerle turbo a las ventas de la tienda. 📈",
  "por vender rascas como nadie. 🎰",
  "por superar con creces lo que se esperaba de su rango. 🚀",
  "por convertir cada venta en un cliente que vuelve. 🔁",
  "por estar siempre disponible cuando el Badulaque lo necesita. 📟",
  "por echar una mano a los nuevos sin que nadie se lo pida. 🫱",
  "por no dejar ni un cliente sin atender en hora punta. ⏱️",
  "por llevar el mostrador como si fuera su propia tienda. 🏪",
  "por su buen rollo con clientes y compañeros. 😎",
  "por cumplir el mínimo con margen semana tras semana. 📊",
  "por su puntualidad y sus turnos sin fallar. ⏰",
  "por mantener la tienda impecable de arriba abajo. 🧽",
  "por saberse el menú y los precios de memoria. 🧠",
  "por recomendar siempre el producto justo a cada cliente. 🥤",
  "por su paciencia hasta con los clientes más difíciles. 🧘",
  "por demostrar que está listo para más responsabilidad. 🎖️",
];
const ASC_FRASES = [
  "Más rango, más responsabilidad: que se note en cada venta. 🛒",
  "El Badulaque crece con gente como vosotros. ¡A por más! 🍎",
  "Caja cuadrada y estantes llenos: ¡enhorabuena por el ascenso! 🏁",
  "Cada cliente que sale contento lleva vuestra firma. ¡Seguid así! 😄",
  "Aquí nadie regala nada: cada ascenso se gana detrás del mostrador. 🏆",
  "Nuevo rango, mismas ganas: a dejar el listón del Badulaque bien alto. 📈",
  "Buen trabajo, mejor equipo. ¡Felicidades y a seguir despachando! 🧾",
  "El orgullo del Badulaque sois vosotros. ¡Que no pare la caja! 💵",
  "De reponer estantes al siguiente escalón: el esfuerzo tiene premio. 📦",
  "Turno a turno se llega lejos. ¡Enhorabuena a los ascendidos! ⭐",
  "El mostrador no se lleva solo: gracias por darlo todo cada turno. 🙌",
  "Un escalón más en el Badulaque. ¡Que se note el nuevo rango! 🎖️",
  "Las ventas hablan por sí solas. ¡Enhorabuena y a por la siguiente semana! 💳",
  "Así se hace tienda: con ganas, constancia y buen trato. 🏪",
  "Os lo habéis ganado a pulso. ¡Felicidades de parte de toda la Jefatura! 🤝",
  "Subir de rango es fácil de decir y difícil de hacer. ¡Bravo! 👏",
  "Donde hay esfuerzo, hay recompensa. ¡Bienvenidos a vuestro nuevo rango! 🚀",
  "Cada venta suma y esta semana habéis sumado de sobra. 📊",
  "El Badulaque abre más fuerte gracias a vosotros. ¡Enhorabuena! 🔑",
  "Con equipo así, la caja nunca descansa. ¡Felicidades! ⚡",
  "Nuevo rango, nuevo reto: ¡a seguir haciendo grande el Badulaque! 🍎",
  "La constancia siempre paga. ¡Enhorabuena por el ascenso! 💰",
  "Gracias por tirar del carro cada turno. ¡Os lo merecéis! 🛒",
  "Que este ascenso sea el primero de muchos. ¡A por más! 🏁",
  "Ejemplo para los nuevos y orgullo para la tienda. ¡Felicidades! ⭐",
];
const pickOne = (arr, prev = "") => {
  const pool = arr.filter((x) => x !== prev);
  return pool[Math.floor(Math.random() * pool.length)] || arr[0];
};
const ascFraseAzar = (prev = "") => pickOne(ASC_FRASES, prev);
// Una felicitacion distinta para cada uno (sin repetir mientras haya).
function ascMotivosAzar(n) {
  const out = [];
  let bag = [];
  for (let i = 0; i < n; i++) {
    if (!bag.length) bag = [...ASC_MOTIVOS].sort(() => Math.random() - 0.5);
    out.push(bag.pop());
  }
  return out;
}
// Tipo de baja: se elige al despedir y se guarda al principio del motivo
// ("Inactividad: nota"). Las notas nunca salen en el mensaje de Discord.
const BAJA_TIPOS = [
  { k: "voluntaria", e: "👋", label: "Baja voluntaria", hint: "Se va del Badulaque por decisión propia" },
  { k: "inactividad", e: "💤", label: "Inactividad", hint: "Deja de aparecer por la tienda" },
  { k: "strikes", e: "⚠️", label: "3 strikes", hint: "No llegó al mínimo de ventas" },
  { k: "expulsion", e: "🚫", label: "Expulsión", hint: "Conducta, normas o sanción" },
  { k: "ck", e: "🕊️", label: "CK del personaje", hint: "El personaje fallece" },
  { k: "otro", e: "📋", label: "Otro", hint: "Cualquier otro motivo" },
];
const BAJA_FRASES = {
  voluntaria: [
    "deja el Badulaque por decisión propia. ¡Gracias por cada turno y mucha suerte en tu camino! 🤝",
    "cuelga el delantal del Badulaque. ¡Gracias por tu esfuerzo, las puertas de la tienda quedan abiertas! 🍎",
    "se despide de la tienda. ¡Gracias por todo lo aportado y suerte en lo que venga! 🍀",
    "nos deja por voluntad propia. ¡Gracias por tu trabajo detrás del mostrador, compañero! 🛒",
    "pone rumbo a nuevos caminos. ¡Gracias por formar parte del Badulaque Central! 🛣️",
    "entrega las llaves de la caja. ¡Gracias por cada venta y por dejar el listón tan alto! 🏁",
  ],
  inactividad: ["causa baja por inactividad.", "causa baja por falta de actividad en la tienda.", "causa baja por inactividad prolongada."],
  strikes: ["sale del Badulaque tras acumular 3 strikes sin llegar al mínimo de ventas.", "queda fuera de la tienda al sumar 3 strikes seguidos."],
  expulsion: ["queda expulsado del Badulaque Central por incumplir las normas de la tienda.", "queda fuera de la tienda por conducta inapropiada."],
  ck: [
    "nos ha dejado para siempre. Descansa en paz, compañero; tu delantal seguirá colgado en la tienda. 🕯️",
    "ha fallecido. Todo el Badulaque Central acompaña a su familia y amigos en este momento tan duro. 🕯️",
    "se ha ido. Hoy la caja suena más bajo. Descanse en paz. 🖤",
    "ya no está con nosotros. Gracias por cada turno; siempre serás parte del Badulaque. 🖤",
  ],
  otro: ["deja de formar parte del Badulaque."],
};
const DESC_MOTIVOS = [
  { k: "minimo", label: "No llegó al mínimo", f: ["por no alcanzar el mínimo de ventas de la semana.", "al quedarse por debajo del mínimo semanal de ventas."] },
  { k: "actividad", label: "Baja actividad", f: ["por su baja actividad en la tienda.", "por falta de presencia en los turnos."] },
  { k: "sancion", label: "Sanción", f: ["como sanción por incumplir las normas de la tienda.", "por una sanción interna de la Jefatura."] },
];
const DESC_CIERRES = [
  "Cada semana es una nueva oportunidad para volver a subir. 💪",
  "El rango se recupera turno a turno detrás del mostrador. 🛒",
  "Aquí cada rango se recupera con trabajo. ¡A por ello! 🍎",
  "Una mala semana no define a nadie. ¡A volver a subir! ⭐",
];
const BAJAS_CIERRES = ["Gracias a todos por vuestro trabajo en el Badulaque. 🍎", "El Badulaque sigue abierto. ¡A seguir despachando! 🛒"];
const bajaTipo = (k) => BAJA_TIPOS.find((t) => t.k === k) || BAJA_TIPOS[BAJA_TIPOS.length - 1];
// Motivo guardado → { tipo, nota }. Los despidos antiguos se clasifican por su texto.
function parseBaja(motivo) {
  const m = String(motivo || "").trim();
  for (const t of BAJA_TIPOS) {
    if (normalizeKeySimple(m.slice(0, t.label.length)) === normalizeKeySimple(t.label)) return { tipo: t.k, nota: m.slice(t.label.length).replace(/^\s*[:·-]\s*/, "") };
  }
  const k = normalizeKeySimple(m);
  const tipo = /\bck\b|fallec|muri|muert/.test(k) ? "ck"
    : /strike/.test(k) ? "strikes"
    : /inactiv|abandon|no aparece|no viene|desaparec|ausen/.test(k) ? "inactividad"
    : /volunt|renunc|dimit|se va|se fue|por su cuenta|decision propia/.test(k) ? "voluntaria"
    : /expuls|conduct|comportamiento|sancion|norma|robo|toxic|falta de respeto|insult/.test(k) ? "expulsion"
    : "otro";
  return { tipo, nota: m };
}
const bajaMotivoText = (tipo, nota) => `${bajaTipo(tipo).label}${nota ? `: ${nota}` : ""}`;
// "⬆️ Ascendido de Cajero a Cajero Principal" → { up, from, to } (acepta nombres antiguos).
function parseRankLog(texto) {
  const m = String(texto || "").match(/(Ascendido|Bajado) de (.+)$/);
  if (!m) return null;
  const known = (t) => {
    if (/^sin rango$/i.test(t.trim())) return "";
    const r = canonRank(t);
    return RANKS.some((x) => x.label === r) ? r : null;
  };
  const parts = m[2].split(" a ");
  for (let i = 1; i < parts.length; i++) {
    const from = known(parts.slice(0, i).join(" a "));
    const to = known(parts.slice(i).join(" a "));
    if (from !== null && to !== null) return { up: m[1] === "Ascendido", from, to };
  }
  return null;
}
// Semanas de domingo a sabado (las mismas de Pagos y los strikes).
const ascDay = (d, add = 0) => new Date(d.getFullYear(), d.getMonth(), d.getDate() + add);
const ascSunday = (d) => ascDay(d, -d.getDay());
const ascDM = (d) => `${String(d.getDate()).padStart(2, "0")}/${String(d.getMonth() + 1).padStart(2, "0")}`;
// Semana que se anuncia por defecto: la ultima cerrada (los cambios se dan al cerrarla).
const ascDefaultWeek = () => ascSunday(ascDay(new Date(), -7));
// Cambios de rango de la semana que empieza el domingo `sun`: los dados desde
// su sabado de cierre hasta el sabado siguiente. Si alguien cambia dos veces
// se junta en uno (de su primer rango al ultimo).
async function rankMovesWeek(sun) {
  const a = ascDay(sun, 6).toISOString();
  const b = ascDay(sun, 14).toISOString();
  const rows = await cloud.req(`/rest/v1/emp_historial?select=employee_id,at,texto&tipo=eq.rango&at=gte.${encodeURIComponent(a)}&at=lt.${encodeURIComponent(b)}&order=at.asc`);
  const by = new Map();
  for (const r of rows || []) {
    const p = parseRankLog(r.texto);
    if (!p) continue;
    const cur = by.get(String(r.employee_id));
    if (cur) cur.to = p.to;
    else by.set(String(r.employee_id), { id: String(r.employee_id), from: p.from, to: p.to, at: r.at });
  }
  return [...by.values()];
}
const discordOf = (e) => String(e?.discord || "").replace(/\D/g, "");
async function ascensosSemana(sun, people) {
  const out = [];
  for (const it of await rankMovesWeek(sun)) {
    if (rankOrder(it.to) <= rankOrder(it.from)) continue;
    const e = people.find((x) => String(x.id) === it.id);
    if (!e || e.firedAt) continue;
    out.push({ ...it, name: fullName(e), discord: discordOf(e) });
  }
  return out.sort((p, q) => rankOrder(q.to) - rankOrder(p.to) || p.name.localeCompare(q.name, "es"));
}
// Descensos y bajas (despidos) de la semana `sun`.
async function descensosSemana(sun, people) {
  const a = ascDay(sun, 6), b = ascDay(sun, 14);
  const inWeek = (iso) => { const t = new Date(iso); return t >= a && t < b; };
  const bajas = people
    .filter((f) => f.firedAt && inWeek(f.firedAt))
    .map((f) => ({ id: String(f.id), name: fullName(f), rank: f.rank, discord: discordOf(f), ...parseBaja(f.firedReason) }))
    .sort((p, q) => BAJA_TIPOS.findIndex((t) => t.k === p.tipo) - BAJA_TIPOS.findIndex((t) => t.k === q.tipo) || p.name.localeCompare(q.name, "es"));
  const gone = new Set(bajas.map((x) => x.id));
  const desc = [];
  for (const it of await rankMovesWeek(sun)) {
    if (gone.has(it.id) || rankOrder(it.to) >= rankOrder(it.from)) continue;
    const e = people.find((x) => String(x.id) === it.id);
    if (!e || e.firedAt) continue;
    desc.push({ ...it, name: fullName(e), discord: discordOf(e), motivo: "minimo" });
  }
  desc.sort((p, q) => rankOrder(q.from) - rankOrder(p.from) || p.name.localeCompare(q.name, "es"));
  return { desc, bajas };
}
// Un solo mensaje con ascensos, descensos y bajas (los apartados vacios no salen).
// Emojis del servidor de Discord del Badulaque (se pegan tal cual).
const DC_EMOJI_AGUILA = "<:aguila:1469892536234414202>";
const DC_EMOJI_MANZANA = "<:manzana:1469893121981677588>";
const DC_EMOJI_SALUDO = "<:pandasaludo:1419702029781045388>";
// Felicitacion al empleado de la semana (se elige una al azar).
const STAR_FRASES = [
  "tu desempeño es impoluto. ¡Sigue así!",
  "has sido el motor del Badulaque esta semana. ¡Enhorabuena!",
  "nadie ha vendido como tú. ¡Gracias por tirar del equipo!",
  "la caja no ha parado contigo detrás. ¡Bien hecho!",
  "trabajo impecable de principio a fin. ¡A por otra semana igual!",
  "eres el ejemplo a seguir esta semana. ¡Sigue así!",
  "trato de diez y ganas de sobra. ¡Gracias por ser así!",
  "has puesto el listón muy alto para todos. ¡Enhorabuena!",
  "cada turno contigo es garantía de buen servicio. ¡Gracias!",
  "el Badulaque es mejor contigo en el mostrador. ¡Sigue así!",
  "constancia, actitud y resultados. ¡Te lo has ganado!",
  "esta semana has sido imparable. ¡Enhorabuena!",
  "los clientes salen contentos y se nota quién atiende. ¡Gracias!",
  "das ejemplo sin necesidad de decir nada. ¡Gran trabajo!",
  "has llevado la tienda como nadie. ¡Bien merecido!",
  "tu esfuerzo no pasa desapercibido. ¡Gracias de parte de la Jefatura!",
  "semana redonda de principio a fin. ¡A por la siguiente!",
  "pocas veces se ve tanta entrega detrás de una caja. ¡Enhorabuena!",
  "eres de los que hacen grande al Badulaque. ¡Sigue así!",
  "el trabajo bien hecho tiene premio y esta semana es tuyo. ¡Felicidades!",
];
const STAR_FRASES_VARIOS = [
  "vuestro desempeño ha sido impoluto. ¡Seguid así!",
  "habéis empatado en lo más alto. ¡Enhorabuena a todos!",
  "sois el ejemplo a seguir esta semana. ¡Gracias por tirar del equipo!",
  "la caja no ha parado con vosotros detrás. ¡Bien hecho!",
  "habéis puesto el listón muy alto para todos. ¡Enhorabuena!",
  "semana redonda para vosotros. ¡A por la siguiente!",
  "el Badulaque es mejor con vosotros en el mostrador. ¡Gracias!",
  "empate de lujo en lo más alto. ¡Felicidades!",
];
function movDiscordText(up, desc, bajas, sun, cierre, star = null) {
  const stars = star?.people?.length ? star.people : [];
  if (!up.length && !desc.length && !bajas.length && !stars.length) return "";
  const role = (r) => rankRoleTag(r);
  const who = (it) => (it.discord && it.mention !== false ? `<@${it.discord}>` : `**${it.name}**`);
  const blocks = [];
  if (up.length || desc.length || bajas.length) {
    const parts = [];
    if (up.length) parts.push(`## 📈 Ascensos\n${up.map((it) => `⬆️ ${who(it)} pasa de ${role(it.from)} a ${role(it.to)} ${it.motivo}`).join("\n")}`);
    if (desc.length) parts.push(`## 📉 Descensos\n${desc.map((it) => `⬇️ ${who(it)} pasa de ${role(it.from)} a ${role(it.to)} ${it.frase}`).join("\n")}`);
    if (bajas.length) parts.push(`## 🚪 Bajas del Badulaque\n${bajas.map((it) => `${bajaTipo(it.tipo).e} ${who(it)}${it.rank ? ` (${role(it.rank)})` : ""} ${it.frase}`).join("\n")}`);
    blocks.push(`# ${DC_EMOJI_AGUILA} MOVIMIENTOS DE PERSONAL DE LA SEMANA - BADULAQUE CENTRAL ${DC_EMOJI_MANZANA}\n-# Semana del ${ascDM(sun)} al ${ascDM(ascDay(sun, 6))}\n\n${parts.join("\n\n")}\n\n${cierre}`);
  }
  if (stars.length) {
    const names = stars.map(who);
    const list = names.length > 1 ? `${names.slice(0, -1).join(", ")} y ${names[names.length - 1]}` : names[0];
    const line = names.length > 1 ? `${list} sois el ${EMPLOYEE_OF_WEEK_TAG}, ${star.frase}` : `${list} eres el ${EMPLOYEE_OF_WEEK_TAG}, ${star.frase}`;
    const head = `# ${DC_EMOJI_SALUDO} RECONOCIMIENTO SEMANAL ${DC_EMOJI_SALUDO}`;
    blocks.push(blocks.length ? `${head}\n\n${line}` : `${head}\n-# Semana del ${ascDM(sun)} al ${ascDM(ascDay(sun, 6))} · Badulaque Central\n\n${line}`);
  }
  return `${blocks.join("\n\n")}\n\n-# — ${ROLE_TAG_JEFATURA} · Badulaque Central`;
}

// Ventana para despedir: tipo de baja + nota opcional. Devuelve el motivo
// listo para guardar ("Inactividad: no aparece desde el 20/10") o null.
function askBaja(label, suggest = "", extra = "") {
  return new Promise((resolve) => {
    const dlg = document.createElement("dialog");
    dlg.className = "baja-dlg";
    const form = document.createElement("form");
    form.method = "dialog";
    form.className = "modal-card";
    const h = document.createElement("h3");
    h.textContent = `🚪 Despedir a ${label}`;
    const p = document.createElement("p");
    p.className = "muted";
    p.textContent = "Sale de la plantilla y de los pagos, pierde el acceso a la página y queda en el registro de Despedidos. Se puede readmitir. ¿Por qué se va?";
    const grid = document.createElement("div");
    grid.className = "baja-tipos";
    BAJA_TIPOS.forEach((t) => {
      const l = document.createElement("label");
      l.className = "baja-tipo";
      const r = document.createElement("input");
      r.type = "radio";
      r.name = "baja";
      r.value = t.k;
      if (t.k === suggest) r.checked = true;
      const txt = document.createElement("span");
      const b = document.createElement("b");
      b.textContent = `${t.e} ${t.label}`;
      const sm = document.createElement("small");
      sm.textContent = t.hint;
      txt.append(b, sm);
      l.append(r, txt);
      grid.append(l);
    });
    const nl = document.createElement("label");
    nl.className = "baja-nota";
    nl.textContent = "Nota (opcional, no sale en Discord)";
    const nota = document.createElement("input");
    nota.type = "text";
    nota.className = "text-input";
    nota.maxLength = 160;
    nota.placeholder = "Ej. no aparece desde el 20/10";
    nl.append(nota);
    const acts = document.createElement("div");
    acts.className = "emp-acts";
    const ok = document.createElement("button");
    ok.type = "submit";
    ok.className = "danger";
    ok.textContent = "Despedir";
    const no = document.createElement("button");
    no.type = "button";
    no.className = "ghost";
    no.textContent = "Cancelar";
    acts.append(ok, no);
    form.append(h, p);
    if (extra) {
      const x = document.createElement("p");
      x.className = "baja-extra";
      x.textContent = extra;
      form.append(x);
    }
    form.append(grid, nl, acts);
    dlg.append(form);
    let result = null;
    form.addEventListener("submit", (ev) => {
      const sel = form.querySelector('input[name="baja"]:checked');
      if (!sel) {
        ev.preventDefault();
        alert("Elige el tipo de baja.");
        return;
      }
      result = bajaMotivoText(sel.value, nota.value.trim());
    });
    no.addEventListener("click", () => dlg.close());
    dlg.addEventListener("close", () => {
      dlg.remove();
      resolve(result);
    });
    (document.querySelector("dialog[open]") || document.body).appendChild(dlg);
    dlg.showModal();
  });
}

// ===================== Reglas de la semana =====================
// Minimo semanal (facturas pagadas + rascas): quien cobra y no llega se lleva
// un strike. Los strikes se acumulan semana a semana (semanas cerradas en
// Pagos, tabla pagos_semanas) y se borran en cuanto llega al minimo.
// Con STRIKE_MAX strikes seguidos toca despido.
const WEEK_MIN = 20000;
const WEEK_BONUS = 10000; // bono del empleado de la semana (quien mas cobra)
const STRIKE_MAX = 3;
let STRIKE_HIST = []; // semanas cerradas, la mas reciente primero (solo con la nube)
// El Jefe Tribal (el dueño, 100 %) no compite: ni bono del empleado de la semana ni strikes.
const isOwnerRank = (rank) => normalizeKeySimple(rank || "") === normalizeKeySimple("Jefe Tribal");

async function loadStrikeHist() {
  if (!cloudOn() || !isJefe()) {
    STRIKE_HIST = [];
    STRIKE_ADJ = {};
    return;
  }
  try {
    const r = await cloud.req("/rest/v1/pagos_semanas?select=semana,desde,hasta,datos,cerrada_por,created_at&order=semana.desc&limit=30");
    STRIKE_HIST = Array.isArray(r) ? r : [];
  } catch {
    STRIKE_HIST = [];
  }
  try {
    const rows = await cloud.req("/rest/v1/app_settings?select=value&key=eq.strike_adj");
    const v = rows?.[0]?.value;
    STRIKE_ADJ = v && typeof v === "object" ? v : {};
  } catch {
    STRIKE_ADJ = {};
  }
}

// Strikes puestos o quitados a mano por el Jefe Tribal (app_settings "strike_adj"):
// { "AAAA-MM-DD" (domingo de la semana): { "id:abc": { s: true|false, m: "motivo", por, at } } }
// s:true = strike puesto a mano (aunque llegara al minimo). s:false = strike
// quitado: esa semana ni suma ni corta la cuenta de strikes seguidos.
let STRIKE_ADJ = {};
function strikeKey(id, name) {
  return id != null && id !== "" ? `id:${id}` : `n:${normalizeKeySimple(name)}`;
}
function strikeAdjFor(wk, id, name) {
  const w = wk ? STRIKE_ADJ[wk] : null;
  if (!w) return null;
  return w[strikeKey(id, name)] || w[`n:${normalizeKeySimple(name)}`] || null;
}

// Strike de una semana para una persona: el automatico (no llegar al minimo)
// salvo que el Jefe Tribal lo haya puesto o quitado a mano. Quien no cobra y
// el Jefe Tribal nunca llevan strike.
function weekStrike(wk, id, name, gross, noPay, rank = "") {
  const exempt = noPay || isOwnerRank(rank);
  const auto = !exempt && gross < WEEK_MIN;
  const adj = exempt ? null : strikeAdjFor(wk, id, name);
  if (!adj) return { on: auto, auto, reason: auto ? strikeReason(gross) : "" };
  if (adj.s) return { on: true, auto, manual: true, reason: adj.m || "puesto por el Jefe Tribal" };
  return { on: false, auto, forgiven: true, reason: adj.m || "" };
}

async function saveStrikeAdj(wk, id, name, value) {
  return saveStrikeAdjMany([{ wk, value }], id, name);
}

// Varios cambios de una persona de una vez: [{ wk, value }] (value null = como lo calcula la pagina).
async function saveStrikeAdjMany(changes, id, name) {
  if (!cloudOn() || !AUTH.tribal) throw new Error("Solo el Jefe Tribal puede poner o quitar strikes.");
  const next = JSON.parse(JSON.stringify(STRIKE_ADJ || {}));
  for (const { wk, value } of changes) {
    const w = next[wk] || (next[wk] = {});
    delete w[`n:${normalizeKeySimple(name)}`];
    if (value) w[strikeKey(id, name)] = { ...value, por: authWho(), at: new Date().toISOString() };
    else delete w[strikeKey(id, name)];
    if (!Object.keys(w).length) delete next[wk];
  }
  await cloud.req("/rest/v1/app_settings?on_conflict=key", {
    method: "POST",
    headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
    body: [{ key: "strike_adj", value: next }],
  });
  STRIKE_ADJ = next;
  const dm = (iso) => `${String(iso).slice(8, 10)}/${String(iso).slice(5, 7)}`;
  for (const { wk, value } of changes) {
    if (value?.s) empLog(id, "strike", `⚠️ Strike puesto (semana del ${dm(wk)})${value.m ? `: ${value.m}` : ""}`);
    else if (value) empLog(id, "strike", `✅ Strike quitado (semana del ${dm(wk)})${value.m ? `: ${value.m}` : ""}`);
    else empLog(id, "strike", `↺ Strike de la semana del ${dm(wk)} vuelve a lo que calcula la página`);
  }
}

function strikeRowIn(week, id, name) {
  const key = normalizeKeySimple(name);
  return (week?.datos?.rows || []).find((r) => (id != null && r.id != null && String(r.id) === String(id)) || normalizeKeySimple(r.name) === key);
}

// Strikes seguidos en semanas cerradas anteriores a "beforeWeek" (AAAA-MM-DD;
// vacio = todas). Una semana en la que llego al minimo corta la cuenta; un
// strike quitado por el Jefe Tribal ni suma ni corta.
function strikesBefore(id, name, beforeWeek = "") {
  let n = 0;
  for (const w of STRIKE_HIST) {
    if (beforeWeek && String(w.semana) >= beforeWeek) continue;
    const r = strikeRowIn(w, id, name);
    if (!r || r.noPay) continue;
    const adj = strikeAdjFor(String(w.semana), id, name);
    if (adj && !adj.s) continue;
    if (r.strike || adj?.s) n++;
    else break;
  }
  return n;
}

// Ultima semana cerrada cuyo strike cuenta en la racha (para quitarlo con "−1").
function lastCountedStrikeWeek(id, name, beforeWeek = "") {
  for (const w of STRIKE_HIST) {
    if (beforeWeek && String(w.semana) >= beforeWeek) continue;
    const r = strikeRowIn(w, id, name);
    if (!r || r.noPay) continue;
    const adj = strikeAdjFor(String(w.semana), id, name);
    if (adj && !adj.s) continue;
    if (r.strike || adj?.s) return String(w.semana);
    break;
  }
  return "";
}

// Historial de strikes de una persona en las semanas cerradas (la mas reciente primero).
function strikeHistoryOf(id, name) {
  const out = [];
  let streak = true;
  for (const w of STRIKE_HIST) {
    const r = strikeRowIn(w, id, name);
    if (!r || r.noPay) continue;
    const wk = String(w.semana);
    const adj = strikeAdjFor(wk, id, name);
    const auto = !!r.strike;
    const on = adj ? !!adj.s : auto;
    const forgiven = !!(adj && !adj.s);
    const counted = streak && on;
    if (streak && !on && !forgiven) streak = false;
    out.push({ wk, hasta: String(w.hasta || ""), auto, on, forgiven, manual: !!adj?.s && !auto, motivo: adj?.m || r.strikeMotivo || (auto ? strikeReason(r.gross || 0) : ""), counted, gross: Number(r.gross || 0) });
  }
  return out;
}

// A que semana va un ＋1 y cual quita un −1 (mismas reglas que el editor).
function strikePlusWeek(emp) {
  return strikeHistoryOf(emp.id, fullName(emp)).find((h) => !h.on) || null;
}
function strikeMinusWeek(emp) {
  return strikeHistoryOf(emp.id, fullName(emp)).find((h) => h.counted) || null;
}
// Valor para que una semana quede como "want": si coincide con lo automatico, se borra el ajuste.
const strikeValueFor = (h, want, motivo) => (want === h.auto ? null : { s: want, m: motivo });

// Sin la nube (programa de escritorio) no hay historial: solo "Strike".
function strikeLabel(n) {
  if (!cloudOn()) return "Strike";
  n = Math.min(n, STRIKE_MAX); // con mas de 3 sigue siendo despido: se muestra 3/3
  return n >= STRIKE_MAX ? `Strike ${n}/${STRIKE_MAX} · despido` : `Strike ${n}/${STRIKE_MAX}`;
}

function strikeReason(gross) {
  return gross > 0 ? `no llegó al mínimo: ${fmtMoney(gross)} de ${fmtMoney(WEEK_MIN)}` : "no vendió nada";
}

function strikeText(n, gross = 0, why = "") {
  return `${n >= STRIKE_MAX && cloudOn() ? "🚫" : "⚠️"} **${strikeLabel(n)}** (${why || strikeReason(gross)})`;
}

// ---------------------------------------------------------------------------
// Historial de cada empleado (tabla emp_historial, SQL 7). Se guarda sin
// esperar: si la tabla no existe todavia, simplemente no se apunta nada.
// ---------------------------------------------------------------------------
function empLog(empId, tipo, texto) {
  if (!empId || !cloudOn() || !cloud.session || !isJefe()) return;
  cloud
    .req("/rest/v1/emp_historial", {
      method: "POST",
      headers: { Prefer: "return=minimal" },
      body: [{ employee_id: String(empId), tipo, texto, por: authWho() }],
    })
    .catch(() => {});
}
async function empHistory(empId) {
  return cloud.req(`/rest/v1/emp_historial?select=at,tipo,texto,por&employee_id=eq.${encodeURIComponent(empId)}&order=at.desc&limit=60`);
}

// Lo facturado esta semana por persona (lo deja Pagos al procesar).
let PAGOS_WEEK_GROSS = null;

// ---------------------------------------------------------------------------
// Avatar por rango: icono del rango sobre un circulo de su color y estrellas
// debajo con el nivel. El Jefe Tribal lleva el logo del Badulaque. Sin rango:
// iniciales.
// ---------------------------------------------------------------------------
const EMP_RANK_CLS = {
  reponedor: "r-pruebas",
  cajero: "r-cajero",
  "cajero principal": "r-exp",
  supervisor: "r-encargado",
  gerente: "r-jefe",
  "jefe tribal": "r-tribal",
};
const empRankCls = (rank) => EMP_RANK_CLS[normalizeKeySimple(rank || "")] || "r-none";
const empInitials = (e) => `${String(e.name || "").trim().charAt(0)}${String(e.surname || "").trim().charAt(0)}`.toUpperCase() || "?";
const RANK_ICON_SVG = {
  // etiqueta de "nuevo"
  reponedor: '<path d="M20.6 13.4l-7.2 7.2a2 2 0 0 1-2.8 0L3 13V3h10l7.6 7.6a2 2 0 0 1 0 2.8z"/><circle cx="7.5" cy="7.5" r="1.6" fill="currentColor"/><path d="M11.5 11.5l3 3M14.5 11.5l-3 3"/>',
  // caja registradora
  cajero: '<rect x="3" y="12" width="18" height="8.5" rx="1.5"/><path d="M5.5 12l1.2-5h10.6l1.2 5"/><rect x="8" y="3" width="8" height="4" rx="1"/><path d="M3 16.5h18M10.5 18.5h3"/>',
  // cesta de la compra
  "cajero principal": '<path d="M3 10h18"/><path d="M5 10l1.6 9a1.5 1.5 0 0 0 1.5 1.2h7.8a1.5 1.5 0 0 0 1.5-1.2L19 10"/><path d="M8.5 10L11 4M15.5 10L13 4"/><path d="M9.5 13.5v3.5M14.5 13.5v3.5M12 13.5v3.5"/>',
  // portapapeles
  supervisor: '<rect x="5" y="4" width="14" height="17" rx="2"/><rect x="9" y="2.5" width="6" height="3.5" rx="1"/><path d="M8.5 13.5l2.5 2.5 4.5-5"/>',
  // maletin
  gerente: '<rect x="3" y="7" width="18" height="13" rx="2"/><path d="M9 7V5a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2v2"/><path d="M3 12.5h18"/><rect x="10.5" y="11" width="3" height="3" rx=".6" fill="currentColor"/>',
};
const RANK_STARS = { reponedor: 1, cajero: 2, "cajero principal": 3, supervisor: 4, gerente: 5, "jefe tribal": 5 };
const RANK_STAR_SVG = '<svg viewBox="0 0 10 10" aria-hidden="true"><polygon points="5,0.4 6.35,3.4 9.6,3.7 7.15,5.85 7.85,9.1 5,7.45 2.15,9.1 2.85,5.85 0.4,3.7 3.65,3.4" fill="currentColor"/></svg>';
function rankAvatar(rank, fallbackText = "?", extraCls = "") {
  const key = normalizeKeySimple(rank || "");
  const n = RANK_STARS[key] || 0;
  const div = document.createElement("div");
  div.className = `rk-av ${empRankCls(rank)}${extraCls ? " " + extraCls : ""}`;
  if (key === "jefe tribal") {
    const img = document.createElement("img");
    img.src = "badulaque_central_logo.png";
    img.alt = "";
    img.onerror = () => img.replaceWith(document.createTextNode(fallbackText));
    div.appendChild(img);
  } else if (RANK_ICON_SVG[key]) {
    div.insertAdjacentHTML("beforeend", `<svg class="rk-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${RANK_ICON_SVG[key]}</svg>`);
  } else {
    div.classList.add("rk-txt");
    div.textContent = fallbackText;
  }
  if (n) {
    const st = document.createElement("span");
    st.className = "rk-stars";
    st.innerHTML = RANK_STAR_SVG.repeat(n);
    div.appendChild(st);
  }
  if (rank) div.title = `${rank}${n ? ` · nivel ${n}` : ""}`;
  return div;
}

// Escalera para Subir / Bajar desde la ficha (el Jefe Tribal no entra: es solo del dueño).
const EMP_LADDER = ["Reponedor", "Cajero", "Cajero Principal", "Supervisor", "Gerente"];

// Posicion del rango (mayor = mas arriba). Sin rango o desconocido: abajo del todo.
function rankOrder(rank) {
  const key = normalizeKeySimple(rank || "");
  return RANKS.findIndex((r) => normalizeKeySimple(r.label) === key);
}

// Orden de la plantilla: Jefe Tribal arriba ... Reponedor abajo; dentro del rango, por apellido.
function byRankThenName(a, b) {
  return (
    rankOrder(b.rank) - rankOrder(a.rank) ||
    `${a.surname || ""} ${a.name || ""}`.localeCompare(`${b.surname || ""} ${b.name || ""}`, "es", { sensitivity: "base" })
  );
}

// Semana que se esta revisando en Pagos (domingo del cuadro de fechas).
function payWeekKey() {
  return (cloudOn() && byId("dlog-from")?.value) || "";
}

// Discord, IBAN y "No cobra" de cada empleado: se guardan por nombre completo,
// en el navegador, porque el programa de escritorio solo guarda nombre,
// apellido y rango.
function loadMap(key) {
  try {
    const parsed = JSON.parse(localStorage.getItem(key) || "{}");
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function saveMap(key, map) {
  try {
    localStorage.setItem(key, JSON.stringify(map || {}));
  } catch {
    // sin almacenamiento
  }
}

function setInMap(key, fullNameStr, value) {
  const map = loadMap(key);
  const k = normalizeKeySimple(fullNameStr);
  if (value) map[k] = value;
  else delete map[k];
  saveMap(key, map);
}

const EMPLOYEE_DISCORD_STORAGE_KEY = "badu_employee_discord_v1";
const EMPLOYEE_IBAN_STORAGE_KEY = "badu_employee_iban_v1";
const EMPLOYEE_NOPAY_STORAGE_KEY = "badu_employee_nopay_v1";
const IBAN_PENDING_TEXT = "**IBAN pendiente**"; // en negrita en Discord
const NO_PAY_TEXT = "No cobra";

// Acepta el numero solo o pegado como <@123...>. "" = borrar; null = no valido.
function parseDiscordId(raw) {
  const s = String(raw ?? "").trim();
  if (!s) return "";
  const m = s.match(/^<?@?!?(\d{17,20})>?$/);
  return m ? m[1] : null;
}

// Una letra y 6 numeros (J739745). "" = borrar; null = no valido.
function parseIban(raw) {
  const s = String(raw ?? "").replace(/\s+/g, "").toUpperCase();
  if (!s) return "";
  return /^[A-Z]\d{6}$/.test(s) ? s : null;
}

// Con la nube activa salen de la tabla "employees"; si no, del navegador.
const getEmployeeDiscord = (n) => (empCloudOn() ? empCloudFind(n)?.discord || "" : loadMap(EMPLOYEE_DISCORD_STORAGE_KEY)[normalizeKeySimple(n)] || "");
const getEmployeeIban = (n) => (empCloudOn() ? empCloudFind(n)?.iban || "" : loadMap(EMPLOYEE_IBAN_STORAGE_KEY)[normalizeKeySimple(n)] || "");
const isEmployeeNoPay = (n) => (empCloudOn() ? !!empCloudFind(n)?.noPay : !!loadMap(EMPLOYEE_NOPAY_STORAGE_KEY)[normalizeKeySimple(n)]);
function setEmployeeDiscord(n, v, onDone) {
  if (empCloudOn()) return empCloudSet(n, { discord: v || "" }, onDone);
  setInMap(EMPLOYEE_DISCORD_STORAGE_KEY, n, v);
}
function setEmployeeIban(n, v, onDone) {
  if (empCloudOn()) return empCloudSet(n, { iban: v || "" }, onDone);
  setInMap(EMPLOYEE_IBAN_STORAGE_KEY, n, v);
}
function setEmployeeNoPay(n, v, onDone) {
  if (empCloudOn()) return empCloudSet(n, { noPay: !!v }, onDone);
  setInMap(EMPLOYEE_NOPAY_STORAGE_KEY, n, v ? 1 : 0);
}

// ============================================================================
// Nube (Supabase): inicio de sesion con Discord, empleados en linea y
// permisos por rango. Igual que en Aguila Motors.
// ----------------------------------------------------------------------------
// Quien es Jefe lo decide la BASE DE DATOS (funcion es_jefe: rango Gerente o
// Jefe Tribal con su ID de Discord en la plantilla), no la pagina: aunque
// alguien toque el codigo, sin ser Jefe no recibe datos.
// Mientras no haya URL y clave, o en el programa de escritorio, la pagina
// funciona como antes (con contrasenas y datos en el navegador).
// La clave "publishable" es publica: sola no deja leer ni escribir nada.
// ============================================================================
const BADU_CLOUD_URL = window.BADU_CLOUD_URL || "https://aewhpzwksxaqsuwsekcd.supabase.co";
const BADU_CLOUD_KEY = window.BADU_CLOUD_KEY || "sb_publishable_sWiHTAwMYnw1hmTaCbLl5Q_4jMPZ0AB";
const CLOUD_SESSION_KEY = "badu_cloud_session_v1";
const HIGH_RANKS = ["Gerente", "Jefe Tribal"];

function cloudOn() {
  return !!(BADU_CLOUD_URL && BADU_CLOUD_KEY) && /^https?:$/.test(location.protocol);
}

const cloud = {
  session: (() => {
    try {
      return JSON.parse(localStorage.getItem(CLOUD_SESSION_KEY) || "null");
    } catch {
      return null;
    }
  })(),

  setSession(j) {
    this.session = {
      access_token: j.access_token,
      refresh_token: j.refresh_token,
      expires_at: Date.now() + (Number(j.expires_in) || 3600) * 1000,
    };
    try {
      localStorage.setItem(CLOUD_SESSION_KEY, JSON.stringify(this.session));
    } catch {
      // sin almacenamiento: la sesion dura hasta cerrar la pagina
    }
  },

  clearSession() {
    this.session = null;
    try {
      localStorage.removeItem(CLOUD_SESSION_KEY);
    } catch {
      // nada
    }
  },

  async req(path, { method = "GET", body, headers = {}, auth = true } = {}) {
    const h = { apikey: BADU_CLOUD_KEY, ...headers };
    if (auth) {
      const tok = await this.token();
      if (!tok) throw Object.assign(new Error("Tu sesión caducó: vuelve a iniciar sesión."), { status: 401 });
      h.Authorization = `Bearer ${tok}`;
    }
    let payload = body;
    if (body !== undefined) {
      h["Content-Type"] = "application/json";
      payload = JSON.stringify(body);
    }
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), 20000);
    let r;
    try {
      r = await fetch(BADU_CLOUD_URL + path, { method, headers: h, body: payload, signal: ctl.signal });
    } catch {
      throw new Error("No hay conexión con la base de datos en línea.");
    } finally {
      clearTimeout(timer);
    }
    const text = await r.text();
    let data = null;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      data = text;
    }
    if (!r.ok) {
      const e = new Error((data && (data.message || data.error_description || data.msg || data.error)) || `Error ${r.status}`);
      e.status = r.status;
      e.code = data?.code || data?.error_code || "";
      throw e;
    }
    return data;
  },

  async token() {
    if (!this.session) return null;
    if (Date.now() > this.session.expires_at - 60000) {
      try {
        const j = await this.req("/auth/v1/token?grant_type=refresh_token", {
          method: "POST",
          body: { refresh_token: this.session.refresh_token },
          auth: false,
        });
        this.setSession(j);
      } catch {
        this.clearSession();
        return null;
      }
    }
    return this.session.access_token;
  },

  loginWithDiscord() {
    const back = location.origin + location.pathname;
    location.href = `${BADU_CLOUD_URL}/auth/v1/authorize?provider=discord&redirect_to=${encodeURIComponent(back)}`;
  },

  async logout() {
    try {
      if (this.session) await this.req("/auth/v1/logout", { method: "POST" });
    } catch {
      // aunque falle, se cierra en este navegador
    }
    this.clearSession();
  },

  rpc(name) {
    return this.req(`/rest/v1/rpc/${name}`, { method: "POST", body: {} });
  },
};

// ---------------------------------------------------------------------------
// Sesion y permisos
// ---------------------------------------------------------------------------
const AUTH = { role: "none", tribal: false, name: "", avatar: "", discordId: "", profile: null, error: "" };
let resolveAuthReady;
const AUTH_READY = new Promise((res) => (resolveAuthReady = res));

function isJefe() {
  return AUTH.role === "jefe";
}

async function authInit() {
  // Vuelta desde Discord: la sesion llega en la direccion (#access_token=...).
  const h = new URLSearchParams(location.hash.replace(/^#/, ""));
  const q = new URLSearchParams(location.search);
  const err = h.get("error_description") || q.get("error_description");
  if (h.get("access_token")) {
    cloud.setSession({ access_token: h.get("access_token"), refresh_token: h.get("refresh_token"), expires_in: h.get("expires_in") });
  }
  if (h.get("access_token") || err) {
    try {
      history.replaceState(null, "", location.pathname);
    } catch {
      // nada
    }
  }
  if (err) AUTH.error = err.replace(/\+/g, " ");
  await authRefresh();
}

async function authRefresh() {
  Object.assign(AUTH, { role: "none", tribal: false, name: "", avatar: "", discordId: "", profile: null });
  if (!cloud.session) return;
  try {
    const u = await cloud.req("/auth/v1/user");
    const md = u?.user_metadata || {};
    AUTH.name = md.custom_claims?.global_name || md.full_name || md.name || "";
    AUTH.avatar = md.avatar_url || md.picture || "";
    const ident = (u?.identities || []).find((i) => i.provider === "discord");
    AUTH.discordId = String(md.provider_id || ident?.identity_data?.sub || "");
  } catch (e) {
    if (e.status) {
      cloud.clearSession();
      return;
    }
    // Sin conexion: con sesion guardada se deja usar la Caja.
    AUTH.role = "offline";
    AUTH.error = e.message;
    return;
  }
  try {
    if ((await cloud.rpc("es_jefe")) === true) {
      AUTH.role = "jefe";
      AUTH.tribal = (await cloud.rpc("es_jefe_tribal")) === true;
    } else {
      AUTH.role = (await cloud.rpc("es_empleado")) === true ? "empleado" : "invitado";
    }
    if (AUTH.role !== "invitado") {
      const rows = await cloud.rpc("mi_perfil");
      const r = Array.isArray(rows) ? rows[0] : rows;
      if (r?.name) AUTH.profile = { name: String(r.name), surname: String(r.surname || ""), rank: canonRank(r.rank) };
    }
  } catch (e) {
    AUTH.role = "invitado";
    AUTH.error =
      e.status === 404 || e.code === "PGRST202"
        ? "La base de datos aún no está preparada (falta pegar el SQL en Supabase)."
        : e.message;
  }
}

// ---------------------------------------------------------------------------
// Empleados en linea (tabla "employees"). Solo los Jefes los reciben.
// ---------------------------------------------------------------------------
const EMP_CLOUD = { ok: false, list: [] };

function empCloudOn() {
  return cloudOn() && EMP_CLOUD.ok;
}

const empFromRow = (r) => ({
  id: String(r.id),
  name: String(r.name || "").trim(),
  surname: String(r.surname || "").trim(),
  rank: canonRank(r.rank),
  discord: String(r.discord || ""),
  iban: String(r.iban || ""),
  noPay: r.no_pay === true,
  firedAt: r.despedido_at || "",
  firedBy: String(r.despedido_por || ""),
  firedReason: String(r.despedido_motivo || ""),
  altaAt: localDay(r.alta_at),
  contratadoAt: localDay(r.contratado_at),
});

// Apunta en el historial lo que cambia entre dos versiones del mismo empleado.
function empLogDiff(before, next) {
  if (!next?.id) return;
  const id = next.id;
  if (!before) {
    empLog(id, "alta", `➕ Entró al Badulaque${next.rank ? ` como ${next.rank}` : ""}`);
    return;
  }
  if (!before.firedAt && next.firedAt) {
    empLog(id, "despido", `🚪 Despedido${next.firedReason ? `: ${next.firedReason}` : ""}`);
    return;
  }
  if (before.firedAt && !next.firedAt) empLog(id, "alta", `↩️ Readmitido${next.rank ? ` como ${next.rank}` : ""}`);
  if ((before.rank || "") !== (next.rank || "")) {
    const up = rankOrder(next.rank) > rankOrder(before.rank);
    empLog(id, "rango", `${up ? "⬆️ Ascendido" : "⬇️ Bajado"} de ${before.rank || "sin rango"} a ${next.rank || "sin rango"}`);
  }
  if (fullName(before) !== fullName(next)) empLog(id, "datos", `✏️ Cambio de nombre: ${fullName(before)} → ${fullName(next)}`);
  if (!!before.noPay !== !!next.noPay) empLog(id, "datos", next.noPay ? "💸 Marcado como «No cobra»" : "💸 Vuelve a cobrar la nómina");
  if ((before.discord || "") !== (next.discord || "")) empLog(id, "datos", next.discord ? "🔗 Discord cambiado" : "🔗 Discord quitado");
  if ((before.iban || "") !== (next.iban || "")) empLog(id, "datos", `🏦 IBAN: ${next.iban || "quitado"}`);
  if ((before.altaAt || "") !== (next.altaAt || "")) empLog(id, "datos", `📅 Fecha de ingreso al Badulaque: ${empDate(next.altaAt) || "sin fecha"}`);
  if ((before.contratadoAt || "") !== (next.contratadoAt || "")) empLog(id, "datos", `📝 Fecha de contratación: ${empDate(next.contratadoAt) || "sin fecha"}`);
}

async function empCloudLoad() {
  const rows = await cloud.req("/rest/v1/employees?select=*&order=surname.asc,name.asc&limit=1000");
  EMP_CLOUD.list = (rows || []).map(empFromRow).filter((e) => e.name && e.surname);
  // Con el SQL 9 la tabla tiene la fecha de contratacion: se guardan las dos fechas.
  EMP_CLOUD.hasDates = (rows || []).some((r) => "contratado_at" in r);
  EMP_CLOUD.ok = true;
  return EMP_CLOUD.list;
}

// Primero entre los que siguen en plantilla; si no, entre los despedidos.
function empCloudFind(fullNameStr) {
  const k = normalizeKeySimple(fullNameStr);
  const same = (e) => normalizeKeySimple(fullName(e)) === k;
  return EMP_CLOUD.list.find((e) => !e.firedAt && same(e)) || EMP_CLOUD.list.find(same);
}

function empCloudRequireJefe() {
  if (!isJefe()) throw new Error("Solo los Gerentes y el Jefe Tribal pueden cambiar la plantilla (inicia sesión con Discord).");
}

async function empCloudInsert(row) {
  empCloudRequireJefe();
  const out = await cloud.req("/rest/v1/employees", {
    method: "POST",
    body: [row],
    headers: { Prefer: "return=representation" },
  });
  const e = empFromRow(out[0]);
  EMP_CLOUD.list.push(e);
  empLogDiff(null, e);
  return e;
}

async function empCloudPatch(id, patch, beforeSnap = null) {
  empCloudRequireJefe();
  const out = await cloud.req(`/rest/v1/employees?id=eq.${encodeURIComponent(id)}`, {
    method: "PATCH",
    body: patch,
    headers: { Prefer: "return=representation" },
  });
  if (!out?.length) throw new Error("No se pudo guardar: no tienes permiso para cambiar a este empleado.");
  const fresh = empFromRow(out[0]);
  const idx = EMP_CLOUD.list.findIndex((e) => e.id === fresh.id);
  const before = beforeSnap || (idx >= 0 ? EMP_CLOUD.list[idx] : null);
  if (idx >= 0) EMP_CLOUD.list[idx] = fresh;
  if (before) empLogDiff(before, fresh);
  return fresh;
}

async function empCloudDelete(id) {
  empCloudRequireJefe();
  const out = await cloud.req(`/rest/v1/employees?id=eq.${encodeURIComponent(id)}`, {
    method: "DELETE",
    headers: { Prefer: "return=representation" },
  });
  if (!out?.length) throw new Error("No se pudo eliminar: no tienes permiso para quitar a este empleado.");
  EMP_CLOUD.list = EMP_CLOUD.list.filter((e) => e.id !== String(id));
}

// Discord / IBAN / No cobra desde la tabla (se llaman sin esperar): guarda y avisa si falla.
function empCloudSet(fullNameStr, patch, onDone) {
  const e = empCloudFind(fullNameStr);
  if (!e) return;
  const prev = { ...e };
  const row = {};
  if ("discord" in patch) row.discord = patch.discord;
  if ("iban" in patch) row.iban = patch.iban;
  if ("noPay" in patch) row.no_pay = !!patch.noPay;
  Object.assign(e, patch);
  empCloudPatch(e.id, row, prev)
    .then(() => onDone?.(true))
    .catch((err) => {
      Object.assign(e, prev);
      alert(`No se pudo guardar en línea: ${err.message || err}`);
      onDone?.(false);
    });
}

// Pasa a la nube los empleados guardados en este navegador (una sola vez).
async function empCloudUploadLocal() {
  empCloudRequireJefe();
  await empCloudLoad();
  const local = loadEmployeesLocal();
  const dMap = loadMap(EMPLOYEE_DISCORD_STORAGE_KEY);
  const iMap = loadMap(EMPLOYEE_IBAN_STORAGE_KEY);
  const nMap = loadMap(EMPLOYEE_NOPAY_STORAGE_KEY);
  let added = 0;
  const errors = [];
  for (const e of local) {
    const key = normalizeKeySimple(fullName(e));
    if (empCloudFind(fullName(e))) continue;
    try {
      await empCloudInsert({
        name: e.name,
        surname: e.surname,
        rank: e.rank || "",
        discord: dMap[key] || "",
        iban: iMap[key] || "",
        no_pay: !!nMap[key],
      });
      added++;
    } catch (err) {
      errors.push(`${fullName(e)}: ${err.message || err}`);
    }
  }
  return { added, total: local.length, errors };
}

// ---------------------------------------------------------------------------
// Pantalla de inicio de sesion, tarjeta de sesion y permisos en la pagina
// ---------------------------------------------------------------------------
function renderAuthGate() {
  const gate = byId("auth-gate");
  if (!gate) return;
  const show = cloudOn() && (AUTH.role === "none" || AUTH.role === "invitado");
  gate.hidden = !show;
  document.documentElement.classList.remove("auth-pending");
  // Sin sesion valida no se carga nada de la pagina debajo.
  document.documentElement.classList.toggle("auth-locked", show);
  if (!show) return;
  const msg = byId("auth-gate-msg");
  const login = byId("auth-gate-login");
  const out = byId("auth-gate-logout");
  if (AUTH.role === "invitado") {
    msg.textContent =
      AUTH.error ||
      `${AUTH.name ? AUTH.name + ", tu" : "Tu"} Discord no está en la plantilla del Badulaque. Pide a un Gerente que te añada con tu ID de Discord${AUTH.discordId ? ` (${AUTH.discordId})` : ""}.`;
    login.hidden = true;
    out.hidden = false;
  } else {
    msg.textContent = AUTH.error || "Inicia sesión con tu cuenta de Discord para entrar.";
    login.hidden = false;
    out.hidden = true;
  }
}

function renderAuthCard() {
  const box = byId("auth-user");
  if (!box) return;
  const show = cloudOn() && (AUTH.role === "jefe" || AUTH.role === "empleado" || AUTH.role === "offline");
  box.hidden = !show;
  if (!show) return;
  const p = AUTH.profile;
  const name = p ? `${p.name} ${p.surname}`.trim() : AUTH.name || "Sesión iniciada";
  const rank = AUTH.role === "offline" ? "Sin conexión" : p?.rank || (isJefe() ? "Gerente" : "Empleado");
  const img = byId("auth-avatar");
  if (AUTH.avatar) {
    img.src = AUTH.avatar;
    img.hidden = false;
  } else {
    img.hidden = true;
  }
  byId("auth-name").textContent = name;
  const rk = byId("auth-rank");
  rk.textContent = rank;
  rk.className = "auth-rank " + (RANK_BADGE_CLASS[normalizeKeySimple(rank)] || "w-nopay");
}

const RANK_BADGE_CLASS = {
  reponedor: "r-pruebas",
  cajero: "r-cajero",
  "cajero principal": "r-exp",
  supervisor: "r-encargado",
  gerente: "r-jefe",
  "jefe tribal": "r-tribal",
};

function applyRoleUi() {
  const root = document.body;
  const on = cloudOn();
  root.classList.toggle("cloud-mode", on);
  root.classList.toggle("role-jefe", on && isJefe());
  root.classList.toggle("role-tribal", on && AUTH.tribal);
  // Sin ser Jefe solo se ve la Caja.
  if (on && !isJefe()) {
    const active = document.querySelector(".tab.is-active");
    if (active && active.dataset.tabTarget !== "tab-caja") document.querySelector('.tab[data-tab-target="tab-caja"]')?.click();
  }
  renderAuthGate();
  renderAuthCard();
}

async function cloudStart() {
  if (!cloudOn()) {
    resolveAuthReady();
    return;
  }
  document.documentElement.classList.add("auth-pending");
  byId("auth-gate-login")?.addEventListener("click", () => cloud.loginWithDiscord());
  const doLogout = async () => {
    await cloud.logout();
    location.reload();
  };
  byId("auth-gate-logout")?.addEventListener("click", doLogout);
  byId("auth-logout")?.addEventListener("click", doLogout);
  try {
    await authInit();
    if (isJefe()) {
      try {
        await empCloudLoad();
      } catch {
        EMP_CLOUD.ok = false;
      }
    }
  } finally {
    applyRoleUi();
    resolveAuthReady();
    document.dispatchEvent(new Event("badu-auth"));
  }
}


function normalizeKeySimple(s) {
  return s
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .trim()
    .replace(/\s+/g, " ");
}

function parseMoney(raw) {
  return Number(String(raw).replace(/[.,]/g, "")) || 0;
}

// Importe con punto de miles siempre: "$ 1.000", "$ 25.000".
function fmtMoney(n) {
  const v = Math.trunc(Number(n) || 0);
  return `$ ${String(v).replace(/\B(?=(\d{3})+(?!\d))/g, ".")}`;
}

// Igual que fmtMoney pero sin "$ " (para el texto de Discord): "5.000".
function fmtMoneyPlain(n) {
  return fmtMoney(n).slice(2);
}


function slugFilename(name) {
  return `${normalizeKeySimple(name).replaceAll(" ", "_")}.png`;
}

async function copyText(text) {
  const safe = String(text ?? "");

  try {
    const ta = document.createElement("textarea");
    ta.value = safe;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.left = "0";
    ta.style.top = "0";
    ta.style.width = "1px";
    ta.style.height = "1px";
    ta.style.opacity = "0";

    const openDlg = document.querySelector("dialog[open]");
    (openDlg || document.body).appendChild(ta);

    try { ta.focus({ preventScroll: true }); } catch { ta.focus(); }
    ta.select();
    try { ta.setSelectionRange(0, ta.value.length); } catch { /* ignore */ }

    const ok = typeof document.execCommand === "function" && document.execCommand("copy");
    ta.remove();
    if (ok) return true;
  } catch {
  }

  if (navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(safe);
      return true;
    } catch {
    }
  }

  return false;
}

function openCopyFallback(text) {
  const textStr = String(text ?? "");

  const modal = byId("copy-fallback-modal");
  const ta = byId("copy-fallback-text");

  function openOverlay() {
    const overlay = document.createElement("div");
    overlay.style.position = "fixed";
    overlay.style.inset = "0";
    overlay.style.background = "rgba(0,0,0,.55)";
    overlay.style.zIndex = "99999";
    overlay.style.display = "grid";
    overlay.style.placeItems = "center";
    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) overlay.remove();
    });

    const box = document.createElement("div");
    box.style.width = "min(720px, 92vw)";
    box.style.background = "#0f1115";
    box.style.border = "1px solid rgba(255,255,255,.12)";
    box.style.borderRadius = "14px";
    box.style.padding = "14px";
    box.style.boxShadow = "0 20px 60px rgba(0,0,0,.6)";

    const p = document.createElement("p");
    p.textContent = "Tu navegador ha bloqueado la copia automática (HTTP). El texto está seleccionado: pulsa Ctrl+C (o ⌘C).";
    p.style.margin = "0 0 10px 0";
    p.style.opacity = "0.9";

    const t = document.createElement("textarea");
    t.value = textStr;
    t.readOnly = true;
    t.style.width = "100%";
    t.style.minHeight = "180px";
    t.style.borderRadius = "12px";
    t.style.padding = "12px";
    t.style.background = "#0b0d10";
    t.style.color = "#e8eefc";
    t.style.border = "1px solid rgba(255,255,255,.12)";
    t.style.resize = "vertical";

    const row = document.createElement("div");
    row.style.display = "flex";
    row.style.gap = "10px";
    row.style.marginTop = "10px";
    row.style.justifyContent = "flex-end";

    const btn = (label) => {
      const b = document.createElement("button");
      b.type = "button";
      b.textContent = label;
      b.style.padding = "10px 12px";
      b.style.borderRadius = "12px";
      b.style.border = "1px solid rgba(255,255,255,.14)";
      b.style.background = "#121622";
      b.style.color = "#e8eefc";
      b.style.cursor = "pointer";
      return b;
    };

    const bSelect = btn("Seleccionar todo");
    bSelect.addEventListener("click", () => {
      try { t.focus({ preventScroll: true }); } catch { t.focus(); }
      t.select();
    });

    const bClose = btn("Cerrar");
    bClose.addEventListener("click", () => overlay.remove());

    row.appendChild(bSelect);
    row.appendChild(bClose);

    box.appendChild(p);
    box.appendChild(t);
    box.appendChild(row);
    overlay.appendChild(box);
    document.body.appendChild(overlay);

    setTimeout(() => {
      try { t.focus({ preventScroll: true }); } catch { t.focus(); }
      t.select();
    }, 30);
  }

  if (!modal || !ta) {
    openOverlay();
    return;
  }

  ta.value = textStr;

  if (typeof modal.showModal === "function") {
    try { modal.showModal(); } catch { /* ignore */ }
    setTimeout(() => {
      try { ta.focus({ preventScroll: true }); } catch { ta.focus(); }
      ta.select();
      try { ta.setSelectionRange(0, ta.value.length); } catch { /* ignore */ }
    }, 50);
  } else {
    openOverlay();
  }
}

function setupCopyFallbackModal() {
  const btnSelect = byId("copy-fallback-select");
  const btnCopy = byId("copy-fallback-copy");
  const btnDl = byId("copy-fallback-download");
  const ta = byId("copy-fallback-text");
  const note = byId("copy-fallback-note");

  if (!ta) return;

  function selectAll() {
    try { ta.focus({ preventScroll: true }); } catch { ta.focus(); }
    ta.select();
  }

  if (btnSelect) btnSelect.addEventListener("click", selectAll);

  if (btnCopy) {
    btnCopy.addEventListener("click", async () => {
      const ok = await copyText(ta.value);
      if (note) {
        note.textContent = ok
          ? "✅ Copiado al portapapeles."
          : "⚠️ El navegador no permite copiar en HTTP. Pulsa Ctrl+C (o ⌘C) con el texto seleccionado.";
      }
      if (!ok) selectAll();
    });
  }

  if (btnDl) {
    btnDl.addEventListener("click", () => {
      try {
        const blob = new Blob([String(ta.value ?? "")], { type: "text/plain;charset=utf-8" });
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = "badu_copia.txt";
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(a.href), 5000);
        if (note) note.textContent = "✅ Descargado: badu_copia.txt";
      } catch {
        if (note) note.textContent = "⚠️ No se pudo descargar. Pulsa Ctrl+C (o ⌘C) para copiar.";
        selectAll();
      }
    });
  }
}


function escapeCsvCell(v) {
  const s = String(v ?? "");
  if (s.includes(",") || s.includes('"') || s.includes("\n")) {
    return `"${s.replaceAll('"', '""')}"`;
  }
  return s;
}

function downloadCsv(filename, headers, rows) {
  const lines = [headers.map(escapeCsvCell).join(",")];
  for (const row of rows) {
    lines.push(row.map(escapeCsvCell).join(","));
  }
  const blob = new Blob([lines.join("\n")], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function sortByValueDescThenName(a, b) {
  if (b[1] !== a[1]) return b[1] - a[1];
  return a[0].localeCompare(b[0], "es", { sensitivity: "base" });
}

// Pide la contraseña de una zona. Devuelve true solo si es correcta.
// Escape, "Cerrar" o "Cancelar" siempre devuelven false.
function showAccessModal({ sectionLabel, zone }) {
  const dlg = byId("access-modal");
  const titleEl = byId("access-title");
  const input = byId("access-pass");
  const errEl = byId("access-error");
  const btnOk = byId("access-ok");
  const btnCancel1 = byId("access-cancel");
  const btnCancel2 = byId("access-cancel-2");
  const btnToggle = byId("access-toggle");

  if (!dlg || !titleEl || !input || !errEl || !btnOk || !btnCancel1 || !btnCancel2 || !btnToggle) {
    const pass = window.prompt("Introduce la contraseña:");
    return verifyPassword(zone, pass);
  }

  titleEl.textContent = sectionLabel ? `Acceso: ${sectionLabel}` : "Acceso restringido";
  errEl.textContent = "";
  input.value = "";
  input.type = "password";
  btnToggle.textContent = "Mostrar";

  return new Promise((resolve) => {
    let granted = false;
    let checking = false;

    const onOk = async () => {
      if (checking) return;
      checking = true;
      try {
        const ok = await verifyPassword(zone, input.value);
        if (!ok) {
          errEl.textContent = "Contraseña incorrecta.";
          input.focus();
          input.select();
          return;
        }
        granted = true;
        dlg.close();
      } finally {
        checking = false;
      }
    };

    const onCancel = () => dlg.close();

    const onToggle = () => {
      if (input.type === "password") {
        input.type = "text";
        btnToggle.textContent = "Ocultar";
      } else {
        input.type = "password";
        btnToggle.textContent = "Mostrar";
      }
      input.focus();
    };

    const onKey = (ev) => {
      if (ev.key === "Enter") {
        ev.preventDefault();
        onOk();
      }
    };

    const onClose = () => {
      cleanup();
      input.value = "";
      resolve(granted);
    };

    const cleanup = () => {
      btnOk.removeEventListener("click", onOk);
      btnCancel1.removeEventListener("click", onCancel);
      btnCancel2.removeEventListener("click", onCancel);
      btnToggle.removeEventListener("click", onToggle);
      input.removeEventListener("keydown", onKey);
      dlg.removeEventListener("close", onClose);
    };

    btnOk.addEventListener("click", onOk);
    btnCancel1.addEventListener("click", onCancel);
    btnCancel2.addEventListener("click", onCancel);
    btnToggle.addEventListener("click", onToggle);
    input.addEventListener("keydown", onKey);
    dlg.addEventListener("close", onClose);

    dlg.showModal();
    setTimeout(() => input.focus(), 50);
  });
}

// ============================================================================
// Panel del Jefe Tribal (como el Panel del Jefe de Aguila Motors v124). Solo
// el Jefe Tribal y con la nube. Se llena solo: facturas del Discord del
// Badulaque (discord_log), semanas cerradas de Pagos (pagos_semanas),
// plantilla e historial.
// ============================================================================
const JP = { sun: "", weeks: new Map(), logs: new Map(), busy: false, all: false, allAlerts: false };

const jpIsoAdd = (iso, n) => {
  const [y, m, d] = iso.split("-").map(Number);
  return new Date(Date.UTC(y, m - 1, d + n)).toISOString().slice(0, 10);
};
const jpDM = (iso) => `${iso.slice(8, 10)}/${iso.slice(5, 7)}`;
// Semana de pago (domingo a sabado, hora de Espana), igual que en Pagos:
// si en Espana ya es domingo, la que acaba de cerrar; si no, la que esta en curso.
function jpDefaultSun() {
  const md = dlogMadridParts(Date.now());
  const today = Date.UTC(md.y, md.m - 1, md.d);
  return new Date(today - (md.wd === 0 ? 7 : md.wd) * 86400000).toISOString().slice(0, 10);
}
const jpOpenSun = () => {
  const md = dlogMadridParts(Date.now());
  return new Date(Date.UTC(md.y, md.m - 1, md.d) - md.wd * 86400000).toISOString().slice(0, 10);
};

async function jpLogsOf(sun) {
  if (JP.logs.has(sun)) return JP.logs.get(sun);
  const a = new Date(dlogMadridMidnight(sun)).toISOString();
  const b = new Date(dlogMadridMidnight(sun, 7)).toISOString();
  const rows = [];
  for (let off = 0; ; off += 1000) {
    const part = await cloud.req(`/rest/v1/discord_log?select=id,ts,content,embeds&ts=gte.${encodeURIComponent(a)}&ts=lt.${encodeURIComponent(b)}&order=ts.asc,id.asc&limit=1000&offset=${off}`);
    if (!Array.isArray(part)) break;
    rows.push(...part);
    if (part.length < 1000) break;
  }
  if (sun !== jpOpenSun()) JP.logs.set(sun, rows);
  return rows;
}

// Cifras de una semana. Cerrada en Pagos: lo guardado (facturas + rascas).
// Sin cerrar: estimacion con las facturas del Discord (sin rascas, que estan
// en el Discord de la ciudad).
async function jpWeek(sun) {
  if (JP.weeks.has(sun)) return JP.weeks.get(sun);
  const rows = await jpLogsOf(sun);
  let res;
  try {
    res = processText(dlogToText(rows));
  } catch {
    res = { invoices: {}, invSummary: { paid_total: 0, paid_count: 0 }, invByIssuerPaid: {} };
  }
  const closed = STRIKE_HIST.find((w) => String(w.semana) === sun && w.datos?.rows);
  const emps = EMP_CLOUD.list.filter((e) => !e.firedAt);
  let people;
  if (closed) {
    people = closed.datos.rows.map((r) => ({ id: r.id, name: r.name, rank: canonRank(r.rank), gross: Number(r.gross) || 0, payout: Number(r.payout) || 0, bonus: Number(r.bonus) || 0, noPay: !!r.noPay }));
  } else {
    const byKey = new Map(emps.map((e) => [normalizeKeySimple(fullName(e)), e]));
    const map = new Map(emps.map((e) => [normalizeKeySimple(fullName(e)), { id: e.id, name: fullName(e), rank: e.rank, gross: 0 }]));
    for (const [who, tot] of Object.entries(res.invByIssuerPaid || {})) {
      const k = normalizeKeySimple(who);
      const e = byKey.get(k);
      const p = map.get(k) || { id: null, name: who, rank: "", gross: 0, extern: !e };
      p.gross += Number(tot) || 0;
      map.set(k, p);
    }
    people = [...map.values()].map((p) => {
      const noPay = !p.extern && isEmployeeNoPay(p.name);
      return { ...p, noPay, bonus: 0, payout: noPay || p.extern ? 0 : Math.round(p.gross * pctForRank(p.rank)) };
    });
    // Bono del empleado de la semana (el Jefe Tribal no compite).
    const competes = (p) => !p.extern && !p.noPay && !isOwnerRank(p.rank);
    const max = Math.max(0, ...people.filter(competes).map((p) => p.payout));
    if (max > 0) for (const p of people) if (competes(p) && p.payout === max) { p.bonus = WEEK_BONUS; p.payout += WEEK_BONUS; }
  }
  const clients = new Map();
  for (const inv of Object.values(res.invoices || {})) {
    const who = String(inv.recipient || "").trim();
    if (!who || !(inv.amount > 0)) continue;
    const k = normalizeKeySimple(who);
    const c = clients.get(k) || { name: who, total: 0, n: 0, last: "" };
    c.total += inv.amount;
    c.n++;
    const when = String(inv.paid_at || inv.sent_at || "");
    if (when > c.last) c.last = when;
    clients.set(k, c);
  }
  const w = {
    sun,
    closed: !!closed,
    vendido: closed ? Number(closed.datos.total) || 0 : Number(res.invSummary?.paid_total) || 0,
    facturas: closed ? Number(closed.datos.facturas) || 0 : Number(res.invSummary?.paid_count) || 0,
    rascas: closed ? Number(closed.datos.rascas) || 0 : null,
    nominas: people.reduce((a, p) => a + (p.payout || 0), 0),
    people,
    clients: [...clients.values()].sort((x, y) => y.total - x.total),
  };
  w.queda = w.vendido - w.nominas;
  // La semana en curso no se guarda (cambia a cada factura).
  if (sun !== jpOpenSun()) JP.weeks.set(sun, w);
  return w;
}

async function jpPlantilla(sun) {
  const s = dlogMadridMidnight(sun), e = dlogMadridMidnight(sun, 7);
  const sat = jpIsoAdd(sun, 6);
  let up = 0, down = 0;
  try {
    const rows = await cloud.req(`/rest/v1/emp_historial?select=texto&tipo=eq.rango&at=gte.${encodeURIComponent(new Date(s).toISOString())}&at=lt.${encodeURIComponent(new Date(e).toISOString())}`);
    for (const r of rows || []) {
      const p = parseRankLog(r.texto);
      if (p) p.up ? up++ : down++;
    }
  } catch {
    // sin historial
  }
  const all = EMP_CLOUD.list;
  const inWeek = (day) => !!day && day >= sun && day <= sat;
  return {
    n: all.filter((x) => !x.firedAt).length,
    up,
    down,
    bajas: all.filter((f) => f.firedAt && +new Date(f.firedAt) >= s && +new Date(f.firedAt) < e).length,
    altas: all.filter((x) => inWeek(x.altaAt)).length,
  };
}

// ---------------------------------------------------------------------------
// Pantalla
// ---------------------------------------------------------------------------
function setupPanelJefe() {
  const root = byId("tab-jefe");
  if (!root) return;
  const $ = (id) => byId(id);
  const mk = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  };
  const money = (v) => fmtMoney(Math.round(v || 0));
  const kShort = (v) => (Math.abs(v) >= 1000 ? `${Math.round(v / 1000)}k` : String(Math.round(v)));
  const delta = (cur, prev, goodUp = true) => {
    // La semana en curso aun no esta completa: compararla con una entera confunde.
    if (JP.sun === jpOpenSun()) return mk("div", "jp-d muted", "Semana en curso · se compara al cerrarla");
    if (!prev) return mk("div", "jp-d muted", "— sin semana anterior");
    const p = Math.round(((cur - prev) / Math.abs(prev)) * 100);
    const up = p >= 0;
    const cls = p === 0 ? "muted" : up === goodUp ? "up" : "down";
    return mk("div", `jp-d ${cls}`, `${up ? "▲" : "▼"} ${Math.abs(p)} % vs semana anterior`);
  };
  const status = (t) => ($("jp-status").textContent = t);
  const allowed = () => cloudOn() && isJefe() && AUTH.tribal;

  async function load(force = false) {
    if (!allowed() || JP.busy) return;
    JP.busy = true;
    if (!JP.sun) JP.sun = jpDefaultSun();
    const max = jpOpenSun();
    if (JP.sun > max) JP.sun = max;
    $("jp-week").textContent = `Semana del ${jpDM(JP.sun)} al ${jpDM(jpIsoAdd(JP.sun, 6))}`;
    $("jp-next").disabled = JP.sun >= max;
    status("Cargando…");
    root.classList.add("is-loading");
    try {
      if (force) {
        JP.weeks.clear();
        JP.logs.clear();
      }
      await loadStrikeHist();
      await empCloudLoad();
      const suns = Array.from({ length: 8 }, (_, i) => jpIsoAdd(JP.sun, -7 * (7 - i)));
      const [weeks, plant] = await Promise.all([Promise.all(suns.map(jpWeek)), jpPlantilla(JP.sun), inactLoad(force)]);
      render(weeks, plant);
      const open = JP.sun === jpOpenSun();
      status(`${open ? "Semana en curso (estimada con las facturas del Discord, sin rascas)" : weeks[7].closed ? "Semana cerrada en Pagos" : "Semana sin cerrar en Pagos (estimada, sin rascas)"} · actualizado a las ${new Date().toLocaleTimeString("es-ES", { hour: "2-digit", minute: "2-digit" })}`);
    } catch (err) {
      status(`No se pudo cargar: ${err.message || err}`);
    } finally {
      JP.busy = false;
      root.classList.remove("is-loading");
    }
  }

  function kpi(box, icon, label, value, d, sub) {
    box.textContent = "";
    box.append(mk("div", "jp-l", `${icon} ${label}`), mk("div", "jp-v", value), d, mk("div", "jp-s", sub));
  }

  function render(weeks, plant) {
    const w = weeks[7], p = weeks[6];
    // ---- Cifras de la semana
    const avg = w.facturas ? Math.round((w.vendido - 0) / w.facturas) : 0;
    const sub1 = [`${w.facturas} ${w.facturas === 1 ? "factura" : "facturas"}`];
    if (w.rascas != null) sub1.push(`${w.rascas} ${w.rascas === 1 ? "rasca" : "rascas"}`);
    else sub1.push("sin rascas hasta cerrar la semana");
    if (avg && w.rascas == null) sub1.push(`ticket medio ${money(avg)}`);
    kpi($("jp-k1"), "💰", `Vendido${w.closed ? "" : " (estimado)"}`, money(w.vendido), delta(w.vendido, p.vendido), sub1.join(" · "));
    const cobran = w.people.filter((x) => x.payout > 0).length;
    kpi($("jp-k2"), "👥", `Nóminas${w.closed ? "" : " (estimadas)"}`, money(w.nominas), delta(w.nominas, p.nominas, false), `${cobran} ${cobran === 1 ? "empleado cobra" : "empleados cobran"} · incluye el bono de ${money(WEEK_BONUS)}`);
    const pct = w.vendido > 0 ? Math.round((w.queda / w.vendido) * 100) : 0;
    kpi($("jp-k3"), "🍎", "Queda para el Badulaque", money(w.queda), delta(w.queda, p.queda), `${pct} % de lo vendido`);
    const stars = w.people.filter((x) => x.bonus > 0);
    const prevStar = p.people.filter((x) => x.bonus > 0).map((x) => x.name);
    const dStar = mk("div", "jp-d muted", stars.length && prevStar.length ? `La semana anterior: ${prevStar.join(", ")}` : "—");
    kpi($("jp-k4"), "⭐", "Empleado de la semana", stars.length ? stars.map((x) => x.name).join(", ") : "—", dStar, stars.length ? `Vendió ${money(stars[0].gross)} · bono de ${money(WEEK_BONUS)}` : "Nadie ha vendido todavía");
    $("jp-k4").querySelector(".jp-v").classList.add("jp-v-name");

    renderChart(weeks);
    renderAlerts(w);
    renderRanking(w, p);

    // ---- Clientes y plantilla
    const cl = $("jp-clients");
    cl.textContent = "";
    if (!w.clients.length) cl.appendChild(mk("p", "muted jp-empty", "Sin facturas con cliente esta semana."));
    for (const c of w.clients.slice(0, 5)) {
      const tr = mk("div", "jp-row");
      const l = mk("div", "jp-row-l");
      const when = (c.last.match(/(\d{1,2})\/(\d{1,2})/) || []).slice(1).map((x) => x.padStart(2, "0")).join("/");
      l.append(mk("b", "", c.name), mk("small", "muted", `${c.n} ${c.n === 1 ? "compra" : "compras"}${when ? ` · última el ${when}` : ""}`));
      tr.append(l, mk("b", "jp-num", money(c.total)));
      cl.appendChild(tr);
    }
    const pl = $("jp-plant");
    pl.textContent = "";
    for (const [k, v] of [["En plantilla", plant.n], ["⬆️ Ascensos · ⬇️ Descensos", `${plant.up} · ${plant.down}`], ["➕ Altas · 🚪 Bajas", `${plant.altas} · ${plant.bajas}`]]) {
      const r = mk("div", "jp-mv");
      r.append(mk("span", "", k), mk("b", "", String(v)));
      pl.appendChild(r);
    }
  }

  function renderChart(weeks) {
    const box = $("jp-chart");
    const W = Math.max(320, Math.round(box.clientWidth || 720)), H = 230, top = 22, base = 186, left = 44;
    const max = Math.max(1, ...weeks.map((w) => Math.max(w.vendido, w.nominas)));
    const step = 10 ** Math.floor(Math.log10(max));
    const nice = Math.ceil(max / step / 2) * step * 2 || 1;
    const y = (v) => base - (Math.max(0, v) / nice) * (base - top);
    const col = (W - left - 10) / weeks.length;
    const bw = Math.max(8, Math.min(30, col / 2 - 6));
    let g = "";
    for (let i = 0; i <= 3; i++) {
      const v = (nice / 3) * i;
      g += `<line x1="${left}" y1="${y(v)}" x2="${W - 8}" y2="${y(v)}" stroke="rgba(255,255,255,.07)"/><text x="${left - 6}" y="${y(v) + 3}" fill="#8a96a3" font-size="10" text-anchor="end">${kShort(v)}</text>`;
    }
    let line = "";
    weeks.forEach((w, i) => {
      const x = left + i * col + col / 2;
      const sel = i === weeks.length - 1;
      const est = !w.closed;
      g += `<rect x="${x - bw - 2}" y="${y(w.vendido)}" width="${bw}" height="${base - y(w.vendido)}" rx="4" fill="${sel ? "#3aa0ff" : "#1f5f99"}" ${est ? 'fill-opacity=".55" stroke="#3aa0ff" stroke-dasharray="3 2"' : ""}><title>Vendido ${money(w.vendido)}${est ? " (estimado, sin rascas)" : ""}</title></rect>`;
      g += `<rect x="${x + 2}" y="${y(w.nominas)}" width="${bw}" height="${base - y(w.nominas)}" rx="4" fill="#4b5563" ${est ? 'fill-opacity=".55"' : ""}><title>Nóminas ${money(w.nominas)}</title></rect>`;
      line += `${i ? "L" : "M"}${x},${y(w.queda)} `;
      g += `<text x="${x}" y="${base + 16}" fill="${sel ? "#8fcaff" : "#8a96a3"}" font-size="10.5" text-anchor="middle" font-weight="${sel ? 700 : 400}">${jpDM(w.sun)}${est ? "*" : ""}</text>`;
      if (sel) g += `<text x="${x - bw / 2 - 2}" y="${y(w.vendido) - 6}" fill="#8fcaff" font-size="10.5" text-anchor="middle" font-weight="700">${kShort(w.vendido)}</text>`;
    });
    g += `<path d="${line}" fill="none" stroke="#7cffc4" stroke-width="2"/>`;
    weeks.forEach((w, i) => {
      const x = left + i * col + col / 2;
      g += `<circle cx="${x}" cy="${y(w.queda)}" r="3.5" fill="#7cffc4"><title>Para el Badulaque ${money(w.queda)}</title></circle>`;
    });
    box.innerHTML = `<svg viewBox="0 0 ${W} ${H}" width="100%" height="${H}" role="img" aria-label="Vendido y nóminas de las últimas 8 semanas">${g}</svg>`;
    $("jp-chart-note").hidden = weeks.every((w) => w.closed);
  }

  function renderAlerts(w) {
    const box = $("jp-alerts");
    box.textContent = "";
    const out = [];
    const open = JP.sun === jpOpenSun();
    const gross = new Map(w.people.map((p) => [normalizeKeySimple(p.name), p.gross]));
    const staff = EMP_CLOUD.list.filter((e) => !e.firedAt);
    for (const e of staff) {
      const name = fullName(e);
      if (isOwnerRank(e.rank)) continue;
      const noPay = isEmployeeNoPay(name);
      const n = noPay ? 0 : strikesBefore(e.id, name);
      const g = gross.get(normalizeKeySimple(name)) || 0;
      if (n >= STRIKE_MAX) out.push({ o: 0, i: "🚫", t: `${name} · ${Math.min(n, STRIKE_MAX)}/${STRIKE_MAX} strikes`, s: "Para despido · no llegó al mínimo semanas seguidas" });
      else if (n === STRIKE_MAX - 1 && open && g < WEEK_MIN) out.push({ o: 2, i: "⚠️", t: `${name} · ${n}/${STRIKE_MAX} strikes`, s: `Le faltan ${money(WEEK_MIN - g)} para el mínimo esta semana (sin contar rascas; si no llega, tercer strike)` });
      const ix = inactOf(e);
      if (ix && ix.level >= 2) out.push({ o: ix.level === 3 ? 1 : 3, i: "💤", t: `${name} · ${ix.more ? `+${INACT_VENTANA}` : ix.days} días sin facturar`, s: ix.level === 3 ? "Grave · candidato a baja por inactividad" : "Alerta · lleva varios días sin facturar" });
    }
    const sinIban = staff.filter((e) => !isEmployeeNoPay(fullName(e)) && !getEmployeeIban(fullName(e))).map(fullName);
    if (sinIban.length) out.push({ o: 4, i: "🏦", t: `${sinIban.length} ${sinIban.length === 1 ? "empleado" : "empleados"} sin IBAN`, s: `No se les puede pagar: ${sinIban.join(", ")}` });
    const sinDisc = staff.filter((e) => !getEmployeeDiscord(fullName(e))).map(fullName);
    if (sinDisc.length) out.push({ o: 5, i: "🔗", t: `${sinDisc.length} ${sinDisc.length === 1 ? "empleado" : "empleados"} sin Discord`, s: `No pueden iniciar sesión ni se les etiqueta: ${sinDisc.join(", ")}` });
    out.sort((a, b) => a.o - b.o);
    if (!out.length) box.appendChild(mk("p", "muted jp-empty", "✅ Todo en orden: nada que revisar."));
    const shown = JP.allAlerts ? out : out.slice(0, 6);
    for (const a of shown) {
      const r = mk("div", "jp-alert");
      const t = mk("div", "");
      t.append(mk("b", "", a.t), mk("small", "", a.s));
      r.append(mk("span", "jp-ai", a.i), t);
      box.appendChild(r);
    }
    if (out.length > 6) {
      const more = mk("button", "ghost jp-more", JP.allAlerts ? "Ver menos" : `Ver los ${out.length} avisos`);
      more.type = "button";
      more.addEventListener("click", () => {
        JP.allAlerts = !JP.allAlerts;
        renderAlerts(w);
      });
      box.appendChild(more);
    }
  }

  function renderRanking(w, p) {
    const box = $("jp-rank");
    box.textContent = "";
    const prev = new Map(p.people.map((x) => [normalizeKeySimple(x.name), x.gross]));
    const list = w.people.filter((x) => !x.extern && !isOwnerRank(x.rank)).sort((a, b) => b.gross - a.gross || a.name.localeCompare(b.name, "es"));
    const max = Math.max(1, ...list.map((x) => x.gross));
    const shown = JP.all ? list : list.slice(0, 5);
    if (!list.length) box.appendChild(mk("p", "muted jp-empty", "Sin datos de esta semana."));
    const emp = new Map(EMP_CLOUD.list.filter((e) => !e.firedAt).map((e) => [normalizeKeySimple(fullName(e)), e]));
    shown.forEach((x) => {
      const r = mk("div", "jp-row");
      const l = mk("div", "jp-row-l");
      const head = mk("div", "jp-rk-head");
      head.append(mk("span", "jp-pos", `${list.indexOf(x) + 1}.`), mk("b", "", x.name), mk("span", `pg-badge ${empRankCls(x.rank)}`, x.rank || "sin rango"));
      if (x.bonus) head.appendChild(mk("span", "jp-star", "⭐"));
      const e = emp.get(normalizeKeySimple(x.name));
      const ix = e ? inactOf(e) : null;
      if (ix && ix.level) head.appendChild(mk("span", `emp-inact l${ix.level}`, `💤 ${ix.more ? `+${INACT_VENTANA}` : ix.days} d`));
      const bar = mk("div", "jp-bar");
      const fill = mk("span");
      fill.style.width = `${Math.round((x.gross / max) * 100)}%`;
      if (x.gross < WEEK_MIN) fill.classList.add("lo");
      bar.appendChild(fill);
      l.append(head, bar);
      const rgt = mk("div", "jp-num");
      rgt.appendChild(mk("b", "", money(x.gross)));
      const pv = JP.sun === jpOpenSun() ? 0 : prev.get(normalizeKeySimple(x.name));
      if (pv) {
        const d = Math.round(((x.gross - pv) / pv) * 100);
        rgt.appendChild(mk("small", d >= 0 ? "up" : "down", `${d >= 0 ? "▲" : "▼"} ${Math.abs(d)} %`));
      } else if (x.gross && JP.sun !== jpOpenSun()) rgt.appendChild(mk("small", "muted", "nuevo"));
      r.append(l, rgt);
      box.appendChild(r);
    });
    if (list.length > 5) {
      const more = mk("button", "ghost jp-more", JP.all ? "Ver solo los 5 primeros" : `Ver los ${list.length}`);
      more.type = "button";
      more.addEventListener("click", () => {
        JP.all = !JP.all;
        renderRanking(w, p);
      });
      box.appendChild(more);
    }
  }

  $("jp-prev").addEventListener("click", () => {
    JP.sun = jpIsoAdd(JP.sun || jpDefaultSun(), -7);
    load();
  });
  $("jp-next").addEventListener("click", () => {
    JP.sun = jpIsoAdd(JP.sun || jpDefaultSun(), 7);
    load();
  });
  $("jp-refresh").addEventListener("click", async () => {
    const b = $("jp-refresh");
    b.disabled = true;
    status("Pidiendo al bot lo último del canal…");
    try {
      const tok = await cloud.token();
      const ctl = new AbortController();
      const timer = setTimeout(() => ctl.abort(), 60000);
      await fetch(`${BADU_CLOUD_URL}/functions/v1/leer-logs`, {
        method: "POST",
        headers: { apikey: BADU_CLOUD_KEY, Authorization: `Bearer ${tok || BADU_CLOUD_KEY}`, "Content-Type": "application/json" },
        body: "{}",
        signal: ctl.signal,
      }).finally(() => clearTimeout(timer));
    } catch {
      // si el bot no responde se usa lo ya guardado
    }
    b.disabled = false;
    load(true);
  });

  let first = true;
  const onOpen = () => {
    if (!allowed()) return;
    if (first) {
      first = false;
      JP.sun = jpDefaultSun();
    }
    load();
  };
  // Solo al entrar en la pestana (no con cada cambio de clase, como "is-loading").
  let wasActive = root.classList.contains("is-active");
  new MutationObserver(() => {
    const on = root.classList.contains("is-active");
    if (on && !wasActive) onOpen();
    wasActive = on;
  }).observe(root, { attributes: true, attributeFilter: ["class"] });
  if (wasActive) onOpen();
}


function setupTabs() {
  const tabs = document.querySelectorAll(".tab");
  const panels = document.querySelectorAll(".tab-panel");
  const unlocked = new Set();

  const openTab = (tab) => {
    tabs.forEach((t) => t.classList.remove("is-active"));
    panels.forEach((p) => p.classList.remove("is-active"));
    tab.classList.add("is-active");
    byId(tab.dataset.tabTarget).classList.add("is-active");
  };

  tabs.forEach((tab) => {
    tab.addEventListener("click", async () => {
      const target = tab.dataset.tabTarget;
      const zone = TAB_PASSWORD_ZONES[target];
      // El Panel es solo del Jefe Tribal (y solo con la nube).
      if (target === "tab-jefe" && !(cloudOn() && isJefe() && AUTH.tribal)) return;
      if (zone && cloudOn()) {
        // Con la nube manda la sesion: solo los Jefes entran, sin contrasena.
        if (!isJefe()) return;
      } else if (zone && !unlocked.has(target)) {
        const ok = await showAccessModal({
          sectionLabel: tab.textContent?.trim() || "Acceso restringido",
          zone,
        });
        if (!ok) return;
        unlocked.add(target);
      }
      openTab(tab);
    });
  });
}

// ============================================================================
// Productos gestionados desde la app ("Gestion de Productos")
// ============================================================================

// true solo mientras la ventana de Gestion de Productos esta abierta tras
// meter la contraseña correcta.
let productAdminUnlocked = false;
const CUSTOM_PRODUCTS_STORAGE_KEY = "badu_custom_products_v1";
const PRODUCT_OVERRIDES_STORAGE_KEY = "badu_product_overrides_v1";

function loadCustomProductsLocal() {
  try {
    const parsed = JSON.parse(localStorage.getItem(CUSTOM_PRODUCTS_STORAGE_KEY) || "[]");
    if (!Array.isArray(parsed)) return [];
    return parsed
      .map((p) => ({
        id: String(p?.id || safeRandomId()),
        name: String(p?.name || "").trim(),
        price: Math.max(0, Math.floor(Number(p?.price) || 0)),
        supplies: Math.max(0, Math.floor(Number(p?.supplies) || 0)),
        image: String(p?.image || ""),
      }))
      .filter((p) => p.name);
  } catch {
    return [];
  }
}

function saveCustomProductsLocal(list) {
  localStorage.setItem(CUSTOM_PRODUCTS_STORAGE_KEY, JSON.stringify(list || []));
}

function loadProductOverridesLocal() {
  try {
    const parsed = JSON.parse(localStorage.getItem(PRODUCT_OVERRIDES_STORAGE_KEY) || "{}");
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function saveProductOverridesLocal(map) {
  localStorage.setItem(PRODUCT_OVERRIDES_STORAGE_KEY, JSON.stringify(map || {}));
}

function checkProductPassword() {
  if (!productAdminUnlocked) throw new Error("Contraseña incorrecta");
}

function addCustomProduct(payload) {
  checkProductPassword();
  const list = loadCustomProductsLocal();
  list.push({
    id: safeRandomId(),
    name: String(payload.name).trim(),
    price: Math.max(0, Math.floor(Number(payload.price) || 0)),
    supplies: Math.max(0, Math.floor(Number(payload.supplies) || 0)),
    image: String(payload.image || ""),
  });
  saveCustomProductsLocal(list);
}

function updateCustomProduct(id, payload) {
  checkProductPassword();
  const list = loadCustomProductsLocal();
  const idx = list.findIndex((p) => String(p.id) === String(id));
  if (idx === -1) throw new Error("Producto no encontrado");
  const cur = list[idx];
  list[idx] = {
    ...cur,
    name: String(payload.name ?? cur.name).trim(),
    price: Math.max(0, Math.floor(Number(payload.price ?? cur.price) || 0)),
    supplies: Math.max(0, Math.floor(Number(payload.supplies ?? cur.supplies) || 0)),
    image: payload.image ? String(payload.image) : cur.image,
  };
  saveCustomProductsLocal(list);
}

function deleteCustomProduct(id) {
  checkProductPassword();
  saveCustomProductsLocal(loadCustomProductsLocal().filter((p) => String(p.id) !== String(id)));
}

function setFixedProductOverride(name, payload) {
  checkProductPassword();
  const map = loadProductOverridesLocal();
  const key = normalizeKeySimple(name);
  const cur = map[key] || {};
  map[key] = {
    ...cur,
    price: Math.max(0, Math.floor(Number(payload.price ?? cur.price) || 0)),
    supplies: Math.max(0, Math.floor(Number(payload.supplies ?? cur.supplies) || 0)),
    image: payload.image ? String(payload.image) : cur.image,
  };
  saveProductOverridesLocal(map);
}

function setFixedProductHidden(name, hidden) {
  checkProductPassword();
  const map = loadProductOverridesLocal();
  const key = normalizeKeySimple(name);
  map[key] = { ...(map[key] || {}), hidden: !!hidden };
  saveProductOverridesLocal(map);
}

function fixedProductView(p, overrides) {
  const key = normalizeKeySimple(p.name);
  const ov = overrides[key] || {};
  const baseSupplies = CRAFTEO_SUPPLIES[key] || 0;
  return {
    name: p.name,
    price: ov.price ?? p.price,
    supplies: ov.supplies ?? baseSupplies,
    image: ov.image || p.image || "",
    hidden: !!ov.hidden,
    fixed: true,
  };
}

// Productos visibles en la Caja (fijos no ocultos + agregados), con ajustes aplicados.
function getAllProducts() {
  const overrides = loadProductOverridesLocal();
  const out = [];
  for (const p of PRODUCTS) {
    const v = fixedProductView(p, overrides);
    if (!v.hidden) out.push(v);
  }
  for (const c of loadCustomProductsLocal()) out.push({ ...c, hidden: false, fixed: false });
  return out;
}

// Todos (incluidos ocultos) para la tabla de administracion.
function listProductsForAdmin() {
  const overrides = loadProductOverridesLocal();
  const rows = PRODUCTS.map((p) => fixedProductView(p, overrides));
  for (const c of loadCustomProductsLocal()) rows.push({ ...c, hidden: false, fixed: false });
  return rows;
}

// Suministros por unidad de un producto (usa ajustes y productos agregados).
function getSuppliesCostForKey(key) {
  const ov = loadProductOverridesLocal()[key];
  if (ov && ov.supplies != null) return Number(ov.supplies) || 0;
  const custom = loadCustomProductsLocal().find((c) => normalizeKeySimple(c.name) === key);
  if (custom) return custom.supplies || 0;
  return CRAFTEO_SUPPLIES[key] || 0;
}

const _placeholderIconCache = new Map();

function generatePlaceholderIcon(name) {
  const label = String(name || "?").replace(/[^\p{L}\p{N}\s]/gu, " ").trim();
  const words = label.split(/\s+/).filter(Boolean);
  const initials = ((words[0]?.[0] || "?") + (words.length > 1 ? words[1][0] : "")).toUpperCase();
  let hash = 0;
  for (const ch of label) hash = (hash * 31 + ch.codePointAt(0)) >>> 0;
  const palette = ["#1f9dff", "#2f7fd1", "#3b6fb5", "#ff6f3c", "#c4562d", "#2a9d8f", "#7a5cc7"];
  const color = palette[hash % palette.length];

  const c = document.createElement("canvas");
  c.width = 128;
  c.height = 128;
  const ctx = c.getContext("2d");
  ctx.fillStyle = color;
  ctx.beginPath();
  if (ctx.roundRect) ctx.roundRect(4, 4, 120, 120, 24);
  else ctx.rect(4, 4, 120, 120);
  ctx.fill();
  ctx.fillStyle = "#08121c";
  ctx.font = "bold 56px 'Segoe UI', sans-serif";
  ctx.textAlign = "center";
  ctx.textBaseline = "middle";
  ctx.fillText(initials, 64, 68);
  return c.toDataURL("image/png");
}

function getProductIcon(product) {
  if (product.image) return product.image;
  const key = normalizeKeySimple(product.name);
  if (!_placeholderIconCache.has(key)) _placeholderIconCache.set(key, generatePlaceholderIcon(product.name));
  return _placeholderIconCache.get(key);
}

function fileToResizedDataUrl(file, maxSide = 256) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error("No se pudo leer la imagen"));
    reader.onload = () => {
      const img = new Image();
      img.onerror = () => reject(new Error("La imagen no es valida"));
      img.onload = () => {
        const scale = Math.min(1, maxSide / Math.max(img.width, img.height));
        const w = Math.max(1, Math.round(img.width * scale));
        const h = Math.max(1, Math.round(img.height * scale));
        const c = document.createElement("canvas");
        c.width = w;
        c.height = h;
        c.getContext("2d").drawImage(img, 0, 0, w, h);
        resolve(c.toDataURL("image/png"));
      };
      img.src = reader.result;
    };
    reader.readAsDataURL(file);
  });
}

function setupProductsAdminModal(onProductsChanged) {
  const openBtn = byId("btn-add-product");
  const modal = byId("add-product-modal");
  if (!openBtn || !modal) return;

  const nameEl = byId("prod-new-name");
  const priceEl = byId("prod-new-price");
  const suppliesEl = byId("prod-new-supplies");
  const imageEl = byId("prod-new-image");
  const hintEl = byId("prod-new-image-hint");
  const previewBox = byId("prod-new-preview");
  const previewImg = byId("prod-new-preview-img");
  const errorEl = byId("prod-new-error");
  const saveBtn = byId("prod-new-save");
  const cancelEditBtn = byId("prod-new-cancel-edit");
  const searchEl = byId("prod-search");
  const bodyEl = byId("prod-admin-body");

  let editing = null; // { fixed: bool, name?: string, id?: string }
  let pendingImage = "";

  const defaultHint = hintEl.textContent;

  function showSubtab(id) {
    modal.querySelectorAll(".subtab").forEach((b) => b.classList.toggle("is-active", b.dataset.subtabTarget === id));
    modal.querySelectorAll(".subtab-panel").forEach((p) => p.classList.toggle("is-active", p.id === id));
  }

  function resetForm() {
    editing = null;
    pendingImage = "";
    nameEl.value = "";
    nameEl.disabled = false;
    priceEl.value = "";
    suppliesEl.value = "";
    imageEl.value = "";
    previewBox.style.display = "none";
    previewImg.removeAttribute("src");
    errorEl.textContent = "";
    hintEl.textContent = defaultHint;
    saveBtn.textContent = "Guardar producto";
    cancelEditBtn.style.display = "none";
  }

  function isDuplicateName(name, exceptKey) {
    const key = normalizeKeySimple(name);
    if (key === exceptKey) return false;
    return listProductsForAdmin().some((p) => normalizeKeySimple(p.name) === key);
  }

  function enterEditMode(row) {
    resetForm();
    editing = row.fixed ? { fixed: true, name: row.name } : { fixed: false, id: row.id, name: row.name };
    nameEl.value = row.name;
    nameEl.disabled = row.fixed; // el nombre de un producto fijo no se cambia
    priceEl.value = row.price;
    suppliesEl.value = row.supplies || 0;
    previewImg.src = getProductIcon(row);
    previewBox.style.display = "block";
    hintEl.textContent = "Si no eliges una imagen nueva, se mantiene la actual.";
    saveBtn.textContent = "Guardar cambios";
    cancelEditBtn.style.display = "";
    showSubtab("prod-tab-add");
  }

  function renderAdminTable() {
    const q = normalizeKeySimple(searchEl.value || "");
    const rows = listProductsForAdmin().filter((r) => !q || normalizeKeySimple(r.name).includes(q));
    bodyEl.innerHTML = "";
    for (const row of rows) {
      const tr = document.createElement("tr");
      const origin = row.fixed
        ? (row.hidden ? '<span class="tag-pill tag-oculto">Oculto</span>' : '<span class="tag-pill tag-fijo">Fijo</span>')
        : '<span class="tag-pill tag-agregado">Agregado</span>';
      const removeLabel = row.fixed ? (row.hidden ? "Restaurar" : "Quitar") : "Eliminar";
      tr.innerHTML = `
        <td><img class="prod-thumb" alt="" src="${escapeHtml(getProductIcon(row))}" /></td>
        <td>${escapeHtml(row.name)}</td>
        <td class="num">${fmtMoney(row.price)}</td>
        <td class="num">${row.supplies || 0}</td>
        <td>${origin}</td>
        <td class="num">
          <button type="button" class="ghost small" data-act="edit">Editar</button>
          <button type="button" class="${row.fixed && row.hidden ? "ghost" : "danger"} small" data-act="remove">${removeLabel}</button>
        </td>`;
      tr.querySelector('[data-act="edit"]').addEventListener("click", () => enterEditMode(row));
      tr.querySelector('[data-act="remove"]').addEventListener("click", async () => {
        try {
          if (row.fixed) {
            setFixedProductHidden(row.name, !row.hidden);
          } else {
            if (!confirm(`Eliminar "${row.name}" definitivamente?`)) return;
            deleteCustomProduct(row.id);
          }
          renderAdminTable();
          onProductsChanged?.();
        } catch (err) {
          alert(String(err?.message || err));
        }
      });
      bodyEl.appendChild(tr);
    }
    if (!rows.length) {
      bodyEl.innerHTML = '<tr><td colspan="6" class="muted">Sin resultados</td></tr>';
    }
  }

  modal.querySelectorAll(".subtab").forEach((b) => {
    b.addEventListener("click", () => {
      showSubtab(b.dataset.subtabTarget);
      if (b.dataset.subtabTarget === "prod-tab-edit") renderAdminTable();
    });
  });

  imageEl.addEventListener("change", async () => {
    const file = imageEl.files?.[0];
    if (!file) {
      pendingImage = "";
      return;
    }
    try {
      pendingImage = await fileToResizedDataUrl(file, 256);
      previewImg.src = pendingImage;
      previewBox.style.display = "block";
    } catch (err) {
      pendingImage = "";
      errorEl.textContent = String(err?.message || err);
    }
  });

  searchEl.addEventListener("input", renderAdminTable);
  cancelEditBtn.addEventListener("click", resetForm);

  saveBtn.addEventListener("click", () => {
    errorEl.textContent = "";
    const name = String(nameEl.value || "").trim();
    const priceRaw = String(priceEl.value || "").trim();
    const suppliesRaw = String(suppliesEl.value || "").trim();
    const price = Number(priceRaw);
    const supplies = suppliesRaw === "" ? 0 : Number(suppliesRaw);

    if (!name) { errorEl.textContent = "Pon el nombre del producto."; return; }
    if (priceRaw === "" || !Number.isFinite(price) || price < 0) { errorEl.textContent = "Pon un precio valido."; return; }
    if (!Number.isFinite(supplies) || supplies < 0) { errorEl.textContent = "Suministros no valido."; return; }

    try {
      if (!editing) {
        if (isDuplicateName(name)) { errorEl.textContent = "Ya existe un producto con ese nombre."; return; }
        addCustomProduct({ name, price, supplies, image: pendingImage });
      } else if (editing.fixed) {
        setFixedProductOverride(editing.name, { price, supplies, image: pendingImage });
      } else {
        if (isDuplicateName(name, normalizeKeySimple(editing.name))) { errorEl.textContent = "Ya existe un producto con ese nombre."; return; }
        updateCustomProduct(editing.id, { name, price, supplies, image: pendingImage });
      }
    } catch (err) {
      errorEl.textContent = String(err?.message || err);
      return;
    }
    const wasEditing = !!editing;
    resetForm();
    renderAdminTable();
    onProductsChanged?.();
    if (wasEditing) showSubtab("prod-tab-edit");
  });

  openBtn.addEventListener("click", async () => {
    const ok = cloudOn() ? isJefe() : await showAccessModal({ sectionLabel: "Gestión de Productos", zone: "productos" });
    if (!ok) return;
    productAdminUnlocked = true;
    resetForm();
    showSubtab("prod-tab-add");
    searchEl.value = "";
    renderAdminTable();
    modal.showModal();
  });

  modal.addEventListener("close", () => {
    productAdminUnlocked = false;
    resetForm();
  });
}

function setupCaja() {
  const state = {
    cart: {},
    history: [],
    selected: null,
    last: null, // ultimo producto tocado, para el visor: { name, delta, price }
  };

  const productGrid = byId("product-grid");
  const searchInput = byId("product-search");
  const productCount = byId("product-count");
  const ticketBody = byId("ticket-body");
  const ticketTotal = byId("ticket-total");

  // Aviso breve abajo (como en Aguila Motors): showToast("✔ Añadido", nombre, " · $ 800").
  let toastTimer = null;
  function showToast(lead, bold = "", tail = "", kind = "") {
    let el = byId("add-toast");
    if (!el) {
      el = document.createElement("div");
      el.id = "add-toast";
      el.className = "add-toast";
      el.setAttribute("role", "status");
    }
    // Con una ventana abierta (cobros por partes) el aviso va dentro, para que se vea encima.
    const host = document.querySelector("dialog[open]") || document.body;
    if (el.parentNode !== host) host.appendChild(el);
    el.textContent = "";
    el.append(`${lead} `);
    if (bold) {
      const b = document.createElement("b");
      b.textContent = bold.length > 60 ? `${bold.slice(0, 57)}…` : bold;
      el.append(b);
    }
    if (tail) el.append(tail);
    el.dataset.kind = kind;
    el.classList.add("is-visible");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.remove("is-visible"), 1600);
  }

  function addItemDelta(name, price, delta, quiet = false) {
    if (!quiet) {
      if (delta > 0) showToast("✔ Añadido", name, ` · ${fmtMoney(price)}`, "add");
      else if (state.cart[name]) showToast("➖ Quitado", name, ` · ${fmtMoney(price)}`, "remove");
    }
    const row = state.cart[name];
    if (!row) {
      if (delta > 0) state.cart[name] = { price, qty: delta };
      else return;
    } else {
      const next = row.qty + delta;
      if (next <= 0) delete state.cart[name];
      else row.qty = next;
    }
    state.history.push([name, delta]);
    state.last = { name, delta, price };
    renderTicket();
  }

  function renderTicket() {
    ticketBody.innerHTML = "";
    let total = 0;
    for (const [name, row] of Object.entries(state.cart)) {
      const tr = document.createElement("tr");
      if (state.selected === name) tr.classList.add("is-selected");
      else if (state.last?.name === name) tr.classList.add("is-last");
      tr.addEventListener("click", (ev) => {
        if (ev.target?.closest?.("input, button")) return;
        state.selected = name;
        renderTicket();
      });

      const qtyInput = document.createElement("input");
      qtyInput.className = "qty-input";
      qtyInput.type = "number";
      qtyInput.min = "0";
      qtyInput.step = "1";
      qtyInput.inputMode = "numeric";
      qtyInput.value = row.qty;
      qtyInput.addEventListener("click", (ev) => ev.stopPropagation());
      qtyInput.addEventListener("mousedown", (ev) => ev.stopPropagation());
      qtyInput.addEventListener(
        "wheel",
        (ev) => {
          ev.preventDefault();
        },
        { passive: false }
      );
      qtyInput.addEventListener("change", () => {
        const n = Math.floor(Number(qtyInput.value));
        if (!Number.isFinite(n) || n <= 0) {
          delete state.cart[name];
          showToast("🗑 Borrado del ticket", name, "", "remove");
        } else {
          state.cart[name].qty = n;
          showToast("✎ Cantidad", name, ` · ×${n}`);
        }
        renderTicket();
      });

      const trashBtn = document.createElement("button");
      trashBtn.type = "button";
      trashBtn.className = "trash-btn";
      trashBtn.setAttribute("aria-label", `Borrar ${name}`);
      trashBtn.innerHTML = "&#128465;";
      trashBtn.addEventListener("click", (ev) => {
        ev.stopPropagation();
        delete state.cart[name];
        showToast("🗑 Borrado del ticket", name, "", "remove");
        if (state.selected === name) state.selected = null;
        renderTicket();
      });

      const sub = row.price * row.qty;
      total += sub;
      tr.innerHTML = `
        <td>${escapeHtml(name)}</td>
        <td class="num"></td>
        <td class="num">${fmtMoney(row.price)}</td>
        <td class="num">${fmtMoney(sub)}</td>
        <td class="num"></td>
      `;
      tr.children[1].appendChild(qtyInput);
      tr.children[4].appendChild(trashBtn);
      ticketBody.appendChild(tr);
    }
    ticketTotal.textContent = fmtMoney(total);
    renderQtyBadges();
    const units = Object.values(state.cart).reduce((a, r) => a + (r.qty || 0), 0);
    renderLcd(units, total);
    renderConceptInfo();
    document.dispatchEvent(new CustomEvent("badu-ticket", { detail: { units, total } }));
  }

  // --- Concepto para el datafono (40 caracteres) --------------------------
  // Lineas del ticket en el orden de la Caja (los que ya no existen, al final).
  function ticketItems() {
    const items = [];
    const seen = new Set();
    const add = (name, row) => {
      const [short, group] = PRODUCT_SHORT[normalizeKeySimple(name)] || [name, ""];
      items.push({ name, qty: row.qty, price: row.price, short, group });
      seen.add(name);
    };
    for (const p of getAllProducts()) {
      const row = state.cart[p.name];
      if (row?.qty > 0) add(p.name, row);
    }
    for (const [name, row] of Object.entries(state.cart)) {
      if (!seen.has(name) && row?.qty > 0) add(name, row);
    }
    return items;
  }

  const fullConcept = (items) => items.map((it) => `x${it.qty} ${it.name}`).join(" ");

  // "2xAlitas+3xCerv, Bacon+Lomo Boc": cada grupo se escribe una sola vez.
  function shortConcept(items) {
    const groups = new Map();
    for (const it of items) {
      const part = it.qty > 1 ? `${it.qty}x${it.short}` : it.short;
      if (!groups.has(it.group)) groups.set(it.group, []);
      groups.get(it.group).push(part);
    }
    return [...groups.entries()].map(([g, parts]) => parts.join("+") + (g ? ` ${g}` : "")).join(", ");
  }

  function mergeQty(list) {
    const out = [];
    for (const it of list) {
      const prev = out.find((x) => x.name === it.name);
      if (prev) prev.qty += it.qty;
      else out.push({ ...it });
    }
    return out;
  }

  // Si ni abreviado cabe, se reparte en varios cobros que si caben.
  function splitIntoCharges(items) {
    const charges = [];
    let current = [];
    for (const it of items) {
      for (let n = 0; n < it.qty; n++) {
        const unit = { ...it, qty: 1 };
        if (current.length && shortConcept(mergeQty([...current, unit])).length > CONCEPT_MAX) {
          charges.push(mergeQty(current));
          current = [unit];
        } else {
          current.push(unit);
        }
      }
    }
    if (current.length) charges.push(mergeQty(current));
    return charges.map((list) => ({
      concept: shortConcept(list),
      total: list.reduce((a, it) => a + it.price * it.qty, 0),
    }));
  }

  function conceptPlan() {
    const items = ticketItems();
    if (!items.length) return { kind: "empty" };
    const full = fullConcept(items);
    if (full.length <= CONCEPT_MAX) return { kind: "full", text: full };
    const short = shortConcept(items);
    if (short.length <= CONCEPT_MAX) return { kind: "short", text: short };
    return { kind: "split", charges: splitIntoCharges(items) };
  }

  function renderConceptInfo() {
    const el = byId("ticket-concept-info");
    if (!el) return;
    const plan = conceptPlan();
    el.className = "concept-info";
    el.title = "";
    if (plan.kind === "empty") {
      el.textContent = "";
    } else if (plan.kind === "full") {
      el.textContent = `Concepto: ${plan.text.length}/${CONCEPT_MAX} · completo`;
      el.title = plan.text;
    } else if (plan.kind === "short") {
      el.textContent = `Concepto: ${plan.text.length}/${CONCEPT_MAX} · abreviado (el completo no cabe en el datáfono)`;
      el.title = plan.text;
    } else {
      el.classList.add("is-over");
      el.textContent = `No cabe en un cobro: se divide en ${plan.charges.length} cobros al copiar el concepto`;
    }
  }

  function openChargesDialog(charges) {
    const dlg = byId("charges-modal");
    const body = byId("charges-body");
    if (!dlg || !body) return;
    body.innerHTML = "";
    charges.forEach((c, i) => {
      const tr = document.createElement("tr");
      const tdN = document.createElement("td");
      tdN.textContent = `${i + 1} de ${charges.length}`;
      const tdC = document.createElement("td");
      tdC.className = "charge-concept";
      tdC.textContent = c.concept;
      tdC.title = `${c.concept.length}/${CONCEPT_MAX} caracteres`;
      const tdT = document.createElement("td");
      tdT.className = "num";
      tdT.textContent = fmtMoney(c.total);
      const tdA = document.createElement("td");
      tdA.className = "num charge-actions";
      const mk = (label, text, cls) => {
        const b = document.createElement("button");
        b.type = "button";
        b.className = `small ${cls}`;
        b.textContent = label;
        b.addEventListener("click", async () => {
          const ok = await copyText(text);
          if (!ok) openCopyFallback(text);
          else showToast(`📋 Cobro ${i + 1} de ${charges.length} ·`, label === "Copiar total" ? `total ${fmtMoney(c.total)}` : "concepto copiado", "", "copy");
          tr.classList.add("is-selected");
        });
        return b;
      };
      tdA.append(mk("Copiar total", String(c.total), "primary"), mk("Copiar concepto", c.concept, ""));
      tr.append(tdN, tdC, tdT, tdA);
      body.appendChild(tr);
    });
    dlg.showModal();
  }

  // Visor: ultimo producto tocado y total (en PC dentro del ticket, en el movil arriba).
  function renderLcd(units, total) {
    const last = state.last;
    const lastText = !units ? "LISTO" : last ? `${last.delta > 0 ? "+" : "−"}${Math.abs(last.delta)} ${last.name.toUpperCase()}` : "TICKET";
    const lastPrice = units && last ? fmtMoney(last.price * Math.abs(last.delta)) : "";
    document.querySelectorAll(".lcd-last").forEach((el) => (el.textContent = lastText));
    document.querySelectorAll(".lcd-last-price").forEach((el) => (el.textContent = lastPrice));
    document.querySelectorAll(".lcd-units").forEach((el) => (el.textContent = `${units} ${units === 1 ? "ARTÍCULO" : "ARTÍCULOS"}`));
    document.querySelectorAll(".m-lcd .lcd-total").forEach((el) => (el.textContent = fmtMoney(total)));
    // Importes largos ($ 16.000, $ 150.000) con letra mas pequena para que quepan en el visor.
    const len = fmtMoney(total).length;
    const size = len <= 7 ? "l" : len <= 8 ? "m" : len <= 9 ? "s" : "xs";
    document.querySelectorAll(".lcd .lcd-total").forEach((el) => (el.dataset.size = size));
  }

  // Buscador: oculta las teclas que no coinciden con lo escrito.
  function applySearch() {
    const q = normalizeKeySimple(searchInput?.value || "");
    let shown = 0;
    productGrid.querySelectorAll(".product-btn").forEach((btn) => {
      const ok = !q || normalizeKeySimple(btn.dataset.name || "").includes(q);
      btn.hidden = !ok;
      if (ok) shown++;
    });
    let empty = productGrid.querySelector(".no-results");
    if (!shown) {
      if (!empty) {
        empty = document.createElement("p");
        empty.className = "no-results";
        productGrid.appendChild(empty);
      }
      empty.textContent = `Ningún producto coincide con "${searchInput.value.trim()}".`;
    } else if (empty) {
      empty.remove();
    }
    const all = productGrid.querySelectorAll(".product-btn").length;
    if (productCount) productCount.textContent = q ? `${shown} de ${all}` : `${all} productos`;
  }

  // Cuantas unidades de cada producto hay en el ticket (se ve en el movil).
  function renderQtyBadges() {
    productGrid.querySelectorAll(".product-btn").forEach((btn) => {
      const qty = state.cart[btn.dataset.name]?.qty || 0;
      const badge = btn.querySelector(".qty-badge");
      if (!badge) return;
      badge.textContent = qty ? `×${qty}` : "";
      btn.classList.toggle("in-ticket", qty > 0);
    });
  }

  function renderProductGrid() {
    productGrid.innerHTML = "";
    for (const product of getAllProducts()) {
      const button = document.createElement("button");
      button.className = "product-btn";
      button.type = "button";
      button.dataset.name = product.name;
      button.innerHTML = `
        <img src="${escapeHtml(getProductIcon(product))}" alt="${escapeHtml(product.name)}" />
        <strong>${escapeHtml(product.name)}</strong>
        <small>${fmtMoney(product.price)}</small>
        <span class="qty-badge"></span>
      `;
      button.addEventListener("click", () => addItemDelta(product.name, product.price, +1));
      button.addEventListener("contextmenu", (ev) => {
        ev.preventDefault();
        addItemDelta(product.name, product.price, -1);
      });
      productGrid.appendChild(button);
    }
    renderQtyBadges();
    applySearch();
  }

  searchInput?.addEventListener("input", applySearch);
  searchInput?.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape") {
      searchInput.value = "";
      applySearch();
    }
  });

  renderProductGrid();

  byId("btn-undo").addEventListener("click", () => {
    const op = state.history.pop();
    if (!op) {
      showToast("↩ Nada que deshacer");
      return;
    }
    const [name, delta] = op;
    showToast(delta > 0 ? "↩ Deshecho: quitado" : "↩ Deshecho: vuelto a añadir", name);
    const item = state.cart[name];
    const price = getAllProducts().find((p) => p.name === name)?.price || state.cart[name]?.price || 0;
    if (!item) {
      if (-delta > 0) state.cart[name] = { price, qty: -delta };
    } else {
      const next = item.qty - delta;
      if (next <= 0) delete state.cart[name];
      else item.qty = next;
    }
    renderTicket();
  });

  byId("btn-remove").addEventListener("click", () => {
    if (!state.selected) {
      showToast("☝ Selecciona una línea del ticket para quitarla");
      return;
    }
    const price = getAllProducts().find((p) => p.name === state.selected)?.price || state.cart[state.selected]?.price || 0;
    addItemDelta(state.selected, price, -1);
  });

  byId("btn-clear").addEventListener("click", () => {
    showToast(Object.keys(state.cart).length ? "🧹 Ticket limpio" : "🧹 El ticket ya estaba vacío", "", "", "remove");
    state.cart = {};
    state.history = [];
    state.selected = null;
    state.last = null;
    renderTicket();
  });

  byId("btn-copy-total").addEventListener("click", async () => {
    const total = Object.values(state.cart).reduce((acc, r) => acc + r.price * r.qty, 0);
    if (!total) {
      showToast("📋 El ticket está vacío: no hay total que copiar");
      return;
    }
    const ok = await copyText(String(total));
    if (!ok) openCopyFallback(String(total));
    else showToast("📋 Total copiado", fmtMoney(total), "", "copy");
  });

  // Lo que copia "Concepto": completo si cabe; si no, abreviado; si no, en cobros.
  byId("btn-copy-concept").addEventListener("click", async () => {
    const plan = conceptPlan();
    if (plan.kind === "empty") {
      showToast("📋 El ticket está vacío: no hay concepto que copiar");
      return;
    }
    if (plan.kind === "split") {
      openChargesDialog(plan.charges);
      return;
    }
    const ok = await copyText(plan.text);
    if (!ok) openCopyFallback(plan.text);
    else showToast("📋 Concepto copiado", plan.text, "", "copy");
  });

  renderTicket();
  setupProductsAdminModal(renderProductGrid);
}

function processText(rawText) {
  // Limpia lo que a veces llega en crudo desde Discord con el formato nuevo
  // del datafono: colores ANSI ("[36mComercio:[0m"), la linea "ansi" del
  // bloque de codigo, titulos "# 150000€" y asteriscos de negrita/cursiva.
  const raw = String(rawText || "")
    .replace(/\u001b?\[[\d;]*m/g, "")
    .replace(/```[a-z]*/gi, "")
    .split(/\r?\n/)
    .filter((l) => !/^\s*ansi\s*$/i.test(l))
    .map((l) => l.replace(/^[ \t]*(?:-#|#{1,3})[ \t]+/, "").replace(/\*/g, ""));
  // Etiqueta sola en su linea ("Vendedor:" y el nombre debajo, como sale al
  // copiar recuadros de Discord con el copiador): se juntan en una sola linea.
  const RE_LABEL_ONLY = /^\s*(Vendedor|Comprador|Cantidad|Total|Comercio|Cobrador|Cliente|Concepto|Emitida por|Para)\s*:?\s*$/i;
  const lines = [];
  for (let i = 0; i < raw.length; i++) {
    const m = raw[i].match(RE_LABEL_ONLY);
    const next = raw[i + 1];
    if (m && next != null && next.trim() && !RE_LABEL_ONLY.test(next) && !/:\s*$/.test(next)) {
      lines.push(`${m[1]}: ${next.trim()}`);
      i++;
    } else {
      lines.push(raw[i]);
    }
  }
  const invoices = {};
  let currentKind = null; // "sent" | "paid" | "datafono"
  let current = {};
  const sales = [];
  let saleActive = false;
  let sale = {};
  let dtfSeq = 0;
  let ignoredOtherBusiness = 0;

  const flushInvoice = () => {
    if (!currentKind) return;

    if (currentKind === "datafono") {
      if (current.amount != null) {
        // Si el recibo trae "Comercio:" y no es Badulaque, se ignora.
        if (current.comercio && !normalizeKeySimple(current.comercio).includes("badulaque")) {
          ignoredOtherBusiness++;
        } else {
          const key = current.aut ? `AUT-${current.aut}` : `DTF-${++dtfSeq}`;
          invoices[key] = {
            invoice_id: current.aut || key,
            issuer: current.issuer || null,
            recipient: current.recipient || null,
            concept: current.concept || null,
            amount: current.amount,
            sent_at: current.timestampText || null,
            // El datafono cobra al instante: queda pagada siempre.
            paid_at: current.timestampText || "OK",
            method: "datafono",
          };
        }
      }
      currentKind = null;
      current = {};
      return;
    }

    if (current.invoice_id == null) {
      currentKind = null;
      current = {};
      return;
    }
    const invId = Number(current.invoice_id);
    if (!invoices[invId]) {
      invoices[invId] = {
        invoice_id: invId,
        issuer: null,
        recipient: null,
        concept: null,
        amount: null,
        sent_at: null,
        paid_at: null,
        method: "facturas",
      };
    }
    const row = invoices[invId];
    if (currentKind === "sent") {
      if (current.issuer) row.issuer = current.issuer;
      if (current.recipient) row.recipient = current.recipient;
      if (current.concept) row.concept = current.concept;
      if (current.amount != null) row.amount = current.amount;
      if (current.timestamp) row.sent_at = current.timestamp;
    } else {
      if (current.concept) row.concept = current.concept;
      if (current.amount != null) row.amount = current.amount;
      if (current.timestamp) row.paid_at = current.timestamp;
    }
    currentKind = null;
    current = {};
  };

  const flushSale = () => {
    if (!saleActive) return;
    if (sale.total == null) {
      saleActive = false;
      sale = {};
      return;
    }
    sales.push({
      buyer: sale.buyer || null,
      seller: sale.seller || null,
      qty: sale.qty || null,
      total: sale.total,
    });
    saleActive = false;
    sale = {};
  };

  for (let line of lines) {
    line = line.trim();
    if (!line || RE_IGNORE.test(line)) continue;

    if (RE_DTF_AMOUNT.test(line)) {
      flushSale();
      flushInvoice();
      const m = RE_DTF_AMOUNT.exec(line);
      currentKind = "datafono";
      current = { amount: parseMoney(m[1]) };
      continue;
    }
    if (RE_NEW.test(line)) {
      flushSale();
      flushInvoice();
      currentKind = "sent";
      current = {};
      continue;
    }
    if (RE_PAID.test(line)) {
      flushSale();
      flushInvoice();
      currentKind = "paid";
      current = {};
      continue;
    }
    if (RE_RASCA.test(line)) {
      flushInvoice();
      flushSale();
      saleActive = true;
      sale = {};
      continue;
    }

    if (currentKind === "datafono") {
      let m = RE_CONCEPT.exec(line);
      if (m) { current.concept = stripWrap(m[1]); continue; }
      m = RE_DTF_COMERCIO.exec(line);
      if (m) { current.comercio = stripWrap(m[1]); continue; }
      m = RE_DTF_COBRADOR.exec(line);
      if (m) { current.issuer = stripWrap(m[1]); continue; }
      m = RE_DTF_CLIENTE.exec(line);
      if (m) { current.recipient = stripWrap(m[1]); continue; }
      m = RE_DTF_AUT.exec(line);
      if (m) {
        current.aut = stripWrap(m[1]);
        current.card = stripWrap(m[2]);
        current.timestampText = stripWrap(m[3]);
      }
      continue;
    }

    if (currentKind) {
      let m = RE_ID.exec(line);
      if (m) { current.invoice_id = Number(m[1]); continue; }
      m = RE_ISSUER.exec(line);
      if (m) { current.issuer = stripWrap(m[1]); continue; }
      m = RE_TO.exec(line);
      if (m) { current.recipient = stripWrap(m[1]); continue; }
      m = RE_AMOUNT.exec(line);
      if (m) { current.amount = parseMoney(m[1]); continue; }
      m = RE_CONCEPT.exec(line);
      if (m) { current.concept = stripWrap(m[1]); continue; }
      m = RE_TS.exec(line);
      if (m) { current.timestamp = m[1]; }
      continue;
    }
    if (saleActive) {
      let m = RE_BUYER.exec(line);
      if (m) { sale.buyer = stripWrap(m[1]).split("(")[0].trim(); continue; }
      m = RE_SELLER.exec(line);
      if (m) { sale.seller = stripWrap(m[1]).split("(")[0].trim(); continue; }
      m = RE_QTY.exec(line);
      if (m) { sale.qty = Number(m[1]); continue; }
      m = RE_TOTAL.exec(line);
      if (m) { sale.total = parseMoney(m[1]); }
    }
  }
  flushInvoice();
  flushSale();

  const invValues = Object.values(invoices);
  const invSummary = {
    count: invValues.length,
    total: invValues.reduce((a, v) => a + (v.amount || 0), 0),
    paid_count: invValues.filter((v) => v.paid_at).length,
    paid_total: invValues.filter((v) => v.paid_at).reduce((a, v) => a + (v.amount || 0), 0),
    pending_count: invValues.filter((v) => !v.paid_at).length,
    pending_total: invValues.filter((v) => !v.paid_at).reduce((a, v) => a + (v.amount || 0), 0),
  };

  const invByIssuer = {};
  const invByIssuerPaid = {};
  const invByIssuerPending = {};
  for (const inv of invValues) {
    if (!inv.issuer || inv.amount == null) continue;
    invByIssuer[inv.issuer] = (invByIssuer[inv.issuer] || 0) + inv.amount;
    if (inv.paid_at) invByIssuerPaid[inv.issuer] = (invByIssuerPaid[inv.issuer] || 0) + inv.amount;
    else invByIssuerPending[inv.issuer] = (invByIssuerPending[inv.issuer] || 0) + inv.amount;
  }

  const salesSummary = {
    count: sales.length,
    total: sales.reduce((a, s) => a + (s.total || 0), 0),
  };
  const salesBySeller = {};
  const salesBySellerQty = {};
  for (const s of sales) {
    if (!s.seller) continue;
    salesBySeller[s.seller] = (salesBySeller[s.seller] || 0) + (s.total || 0);
    salesBySellerQty[s.seller] = (salesBySellerQty[s.seller] || 0) + (s.qty || 0);
  }

  return {
    invoices,
    invSummary,
    invByIssuer,
    invByIssuerPaid,
    invByIssuerPending,
    sales,
    salesSummary,
    salesBySeller,
    salesBySellerQty,
    ignoredOtherBusiness,
  };
}

function setupContabilidad() {
  const state = {
    invoices: {},
    sales: [],
    invByIssuer: {},
    invByIssuerPaid: {},
    invByIssuerPending: {},
    salesBySeller: {},
    salesBySellerQty: {},
    ignoredOtherBusiness: 0,
  };

  const refs = {
    input: byId("conta-input"),
    invLine1: byId("inv-line1"),
    invLine2: byId("inv-line2"),
    invLine3: byId("inv-line3"),
    salesLine1: byId("sales-line1"),
    salesLine2: byId("sales-line2"),
    loaded: byId("conta-loaded"),
    invTable: byId("inv-table"),
    salesTable: byId("sales-table"),
    totalGeneral: byId("conta-total-general"),
    totalAPagar: byId("conta-total-a-pagar"),
    footer: byId("conta-footer"),
  };

  const RANK_BADGE = {
    reponedor: "r-pruebas",
    cajero: "r-cajero",
    "cajero principal": "r-exp",
    supervisor: "r-encargado",
    gerente: "r-jefe",
    "jefe tribal": "r-tribal",
  };

  // Una fila por persona: facturas pagadas + rascas, su rango y lo que se le paga.
  function buildRanking(employees) {
    const byKey = new Map();
    const row = (name) => {
      const key = normalizeKeySimple(name);
      if (!byKey.has(key)) byKey.set(key, { name, fact: 0, ras: 0, rasQty: 0 });
      return byKey.get(key);
    };
    for (const [name, total] of Object.entries(state.invByIssuerPaid)) row(name).fact += Number(total || 0);
    for (const [name, total] of Object.entries(state.salesBySeller)) {
      const r = row(name);
      r.ras += Number(total || 0);
      r.rasQty += Number(state.salesBySellerQty[name] || 0);
    }
    const empByKey = new Map(employees.map((e) => [normalizeKeySimple(fullName(e)), e]));
    const rows = [...byKey.entries()].map(([key, r]) => {
      const e = empByKey.get(key);
      const fired = e ? null : findFired(r.name);
      const name = e ? fullName(e) : fired ? fullName(fired) : r.name;
      const total = r.fact + r.ras;
      const pct = e ? pctForRank(e.rank) : 0;
      return { ...r, name, emp: e, fired, rank: e?.rank || "", pct, total, payout: Math.round(total * pct), noPay: e ? isEmployeeNoPay(name) : false, iban: e ? getEmployeeIban(name) : "" };
    });
    rows.sort((a, b) => b.total - a.total || a.name.localeCompare(b.name, "es"));
    // Empleado de la semana: quien mas cobra (si hay empate, todos) se lleva el bono.
    const competes = (r) => r.emp && !r.noPay && !isOwnerRank(r.rank);
    const maxPayout = Math.max(0, ...rows.map((r) => (competes(r) ? r.payout : 0)));
    for (const r of rows) {
      r.bonus = maxPayout > 0 && competes(r) && r.payout === maxPayout ? WEEK_BONUS : 0;
      r.toPay = r.payout + r.bonus;
    }
    return rows;
  }

  function renderRanking(rows, invSummary, salesSummary, totalAPagar, employees = []) {
    const list = byId("pg-ranking");
    const maxTotal = Math.max(1, ...rows.map((r) => r.total));
    const top = rows.find((r) => r.bonus);
    const paying = rows.filter((r) => r.emp && !r.noPay && r.payout > 0).length;

    byId("pg-kpi-fact").textContent = fmtMoney(invSummary.paid_total + salesSummary.total);
    byId("pg-kpi-fact-sub").textContent = rows.length
      ? `${invSummary.paid_count} facturas · ${rows.length} ${rows.length === 1 ? "persona" : "personas"}`
      : "Sin datos";
    byId("pg-kpi-pay").textContent = fmtMoney(totalAPagar);
    // Importes largos ($ 100.000 o mas): letra mas pequena para que quepan.
    const payLen = fmtMoney(totalAPagar).length;
    byId("pg-kpi-pay").dataset.size = payLen > 10 ? "s" : payLen > 7 ? "m" : "";
    byId("pg-kpi-rascas").textContent = String(salesSummary.qty);
    byId("pg-kpi-rascas-sub").textContent = salesSummary.count ? `${salesSummary.count} ventas · ${fmtMoney(salesSummary.total)}` : "-";
    byId("pg-kpi-top").textContent = top ? top.name : "-";
    byId("pg-kpi-top").title = top ? top.name : "";
    byId("pg-kpi-top-sub").textContent = top ? `${fmtMoney(top.total)} cobrados · bono ${fmtMoney(WEEK_BONUS)}` : "-";
    byId("pg-total-label").textContent = paying ? `TOTAL A PAGAR · ${paying} ${paying === 1 ? "EMPLEADO" : "EMPLEADOS"}` : "TOTAL A PAGAR";

    list.textContent = "";
    lastSnapshot = null;
    if (!rows.length) {
      const p = document.createElement("p");
      p.className = "muted pg-empty";
      p.textContent = "Pega el texto de Discord y pulsa Procesar para ver el ranking.";
      list.appendChild(p);
      renderClose();
      return;
    }
    const el = (tag, cls, text) => {
      const n = document.createElement(tag);
      if (cls) n.className = cls;
      if (text != null) n.textContent = text;
      return n;
    };
    rows.forEach((r, i) => {
      const card = el("div", "pg-row" + (r.bonus ? " first" : ""));
      const initials = r.name.split(/\s+/).filter(Boolean).map((w) => w[0]).slice(0, 2).join("").toUpperCase();
      const avCls = "pg-av" + (r.noPay || !r.emp ? " np" : "");
      const av = r.emp && r.rank ? rankAvatar(r.rank, initials, avCls) : el("div", avCls, initials);
      if (r.bonus) {
        av.appendChild(el("span", "crown", "★"));
        av.title = "Empleado de la semana";
      }
      const pos = el("span", "pg-pos", String(i + 1));

      const mid = el("div", "pg-mid");
      const nameRow = el("div", "pg-name");
      nameRow.appendChild(el("span", "", r.name));
      if (!r.emp && r.fired) nameRow.appendChild(el("span", "pg-badge w-fired", "Despedido"));
      else if (!r.emp) nameRow.appendChild(el("span", "pg-badge w-nopay", "Sin registrar"));
      else if (r.rank) nameRow.appendChild(el("span", "pg-badge " + (RANK_BADGE[normalizeKeySimple(r.rank)] || "w-nopay"), `${r.rank} · ${pctText(r.pct)}`));
      else nameRow.appendChild(el("span", "pg-badge w-iban", "Sin rango"));
      if (r.emp && r.noPay) nameRow.appendChild(el("span", "pg-badge w-nopay", "No cobra"));
      else if (r.emp && !r.iban) nameRow.appendChild(el("span", "pg-badge w-iban", "Sin IBAN"));
      const bar = el("div", "pg-bar");
      const fill = el("i");
      fill.style.width = `${Math.max(2, Math.round((r.total / maxTotal) * 100))}%`;
      bar.appendChild(fill);
      const meta = [`Facturas ${fmtMoney(r.fact)}`];
      if (r.rasQty || r.ras) meta.push(`${r.rasQty} ${r.rasQty === 1 ? "rasca" : "rascas"} ${fmtMoney(r.ras)}`);
      if (r.iban) meta.push(`IBAN ${r.iban}`);
      mid.append(nameRow, bar, el("div", "pg-meta", meta.join(" · ")));

      const amt = el("div", "pg-amt");
      if (!r.emp) amt.append(el("small", "", r.fired ? "Despedido" : "Sin registrar"), el("b", "pg-dash", "$ 0"));
      else if (r.noPay) amt.append(el("small", "", `Le tocarían ${fmtMoney(r.payout)}`), el("b", "pg-dash", "No cobra"));
      else if (!r.pct) amt.append(el("small", "", "Sin rango"), el("b", "pg-dash", "$ 0"));
      else if (r.bonus) amt.append(el("small", "", `incl. bono ${fmtMoney(r.bonus)} ★`), el("b", "pay", fmtMoney(r.toPay)));
      else amt.append(el("small", "", `de ${fmtMoney(r.total)}`), el("b", "pay", fmtMoney(r.payout)));
      card.append(pos, av, mid, amt);
      list.appendChild(card);
    });

    // Strikes: quien cobra y no llega al minimo (o no vendio nada), salvo que
    // el Jefe Tribal lo quite o lo ponga a mano (ajustes en app_settings).
    const wk = payWeekKey();
    const grossOf = (e) => rows.find((x) => x.emp === e)?.total || 0;
    const wsOf = new Map(employees.map((e) => [e, weekStrike(wk, e.id, fullName(e), grossOf(e), isEmployeeNoPay(fullName(e)), e.rank)]));
    const idle = employees.filter((e) => wsOf.get(e).on).sort(byRankThenName);
    const forgiven = employees.filter((e) => wsOf.get(e).forgiven && wsOf.get(e).auto).sort(byRankThenName);
    lastSnapshot = {
      rows: employees.map((e) => {
        const name = fullName(e);
        const r = rows.find((x) => x.emp === e);
        const noPay = isEmployeeNoPay(name);
        const ws = wsOf.get(e);
        return {
          id: e.id ?? null,
          name,
          rank: e.rank || "",
          gross: r ? r.total : 0,
          payout: r && !noPay ? r.toPay : 0,
          bonus: r && !noPay ? r.bonus : 0,
          noPay,
          strike: ws.on,
          ...(ws.manual || ws.forgiven ? { strikeMotivo: ws.reason } : {}),
        };
      }),
      total: invSummary.paid_total + salesSummary.total,
      facturas: invSummary.paid_count,
      rascas: salesSummary.qty,
    };
    const boss = cloudOn() && AUTH.tribal && wk;
    const act = async (btn, fn) => {
      btn.disabled = true;
      try {
        await fn();
        refresh();
      } catch (err) {
        btn.disabled = false;
        alert(`No se pudo guardar: ${err.message || err}`);
      }
    };
    if (idle.length || forgiven.length || boss) {
      const box = el("div", "pg-warn-box");
      box.appendChild(el("div", "pg-warn-head", `⚠️ Strikes de esta semana · no llegaron a ${fmtMoney(WEEK_MIN)} (${idle.length})`));
      const chips = el("div", "pg-warn-list");
      if (!idle.length) chips.appendChild(el("span", "muted pg-strike-why", "Nadie tiene strike esta semana."));
      for (const e of idle) {
        const ws = wsOf.get(e);
        const n = strikesBefore(e.id, fullName(e), wk) + 1;
        const max = cloudOn() && n >= STRIKE_MAX;
        const chip = el("span", "pg-warn-chip" + (max ? " max" : "") + (ws.manual ? " manual" : ""));
        chip.appendChild(el("b", "", fullName(e)));
        if (e.rank) chip.appendChild(el("span", "pg-badge " + (RANK_BADGE[normalizeKeySimple(e.rank)] || "w-nopay"), e.rank));
        const g = grossOf(e);
        chip.appendChild(el("span", "pg-strike-why", ws.manual ? `✍️ ${ws.reason}` : g > 0 ? `${fmtMoney(g)} de ${fmtMoney(WEEK_MIN)}` : "Sin ventas"));
        chip.appendChild(el("span", "pg-strike" + (max ? " max" : ""), max ? `🚫 ${strikeLabel(n)}` : strikeLabel(n)));
        if (boss) {
          const x = el("button", "pg-chip-btn", "✕");
          x.type = "button";
          x.title = ws.manual ? "Quitar este strike puesto a mano" : "Quitar el strike (ausencia justificada, etc.)";
          x.addEventListener("click", () => {
            if (ws.manual && !ws.auto) return act(x, () => saveStrikeAdj(wk, e.id, fullName(e), null));
            const m = prompt(`Quitar el strike de ${fullName(e)} esta semana.\n\nMotivo (opcional, p. ej. «ausencia justificada»):`, "");
            if (m === null) return;
            act(x, () => saveStrikeAdj(wk, e.id, fullName(e), { s: false, m: m.trim() || "quitado por el Jefe Tribal" }));
          });
          chip.appendChild(x);
        }
        chips.appendChild(chip);
      }
      box.appendChild(chips);
      if (forgiven.length) {
        const fl = el("div", "pg-warn-list pg-forgiven");
        fl.appendChild(el("span", "pg-strike-why", "Quitados por el Jefe Tribal:"));
        for (const e of forgiven) {
          const ws = wsOf.get(e);
          const chip = el("span", "pg-warn-chip off");
          chip.appendChild(el("b", "", fullName(e)));
          if (ws.reason) chip.appendChild(el("span", "pg-strike-why", ws.reason));
          if (boss) {
            const u = el("button", "pg-chip-btn", "↺");
            u.type = "button";
            u.title = "Volver a poner el strike";
            u.addEventListener("click", () => act(u, () => saveStrikeAdj(wk, e.id, fullName(e), null)));
            chip.appendChild(u);
          }
          fl.appendChild(chip);
        }
        box.appendChild(fl);
      }
      if (boss) {
        // Poner un strike a mano esta semana (mal comportamiento, etc.).
        const add = el("div", "pg-strike-add");
        const sel = document.createElement("select");
        sel.className = "text-input";
        sel.appendChild(new Option("Poner strike a…", ""));
        for (const e of employees) {
          const ws = wsOf.get(e);
          if (ws.on || isEmployeeNoPay(fullName(e)) || isOwnerRank(e.rank)) continue;
          sel.appendChild(new Option(`${fullName(e)}${e.rank ? ` (${e.rank})` : ""}`, String(e.id)));
        }
        const why = document.createElement("input");
        why.className = "text-input";
        why.placeholder = "Motivo (p. ej. mal comportamiento)";
        why.maxLength = 120;
        const go = el("button", "", "➕ Poner strike");
        go.type = "button";
        go.addEventListener("click", () => {
          const e = employees.find((x) => String(x.id) === sel.value);
          if (!e) return alert("Elige a quién ponerle el strike.");
          const m = why.value.trim();
          if (!m) return alert("Escribe el motivo del strike.");
          act(go, () => saveStrikeAdj(wk, e.id, fullName(e), { s: true, m }));
        });
        add.append(sel, why, go);
        box.appendChild(add);
        box.appendChild(el("p", "muted pg-strike-why pg-strike-note", "Los strikes de semanas anteriores se gestionan en 👥 Gestión de empleados → Strikes."));
      }
      list.appendChild(box);
    }
    renderClose();
  }

  // ---------- Cierre de semana (guarda la semana para contar strikes) ----------
  let lastSnapshot = null;
  const fmtDay = (iso) => (iso ? `${iso.slice(8, 10)}/${iso.slice(5, 7)}` : "");
  function renderClose() {
    const box = byId("pg-close");
    if (!box) return;
    box.hidden = !(cloudOn() && isJefe());
    if (box.hidden) return;
    const wk = payWeekKey();
    const to = byId("dlog-to")?.value || "";
    const done = STRIKE_HIST.find((w) => String(w.semana) === wk);
    const hasData = !!(lastSnapshot && lastSnapshot.rows.length && lastSnapshot.total > 0);
    byId("pg-close-week").textContent = wk ? `dom ${fmtDay(wk)} – sáb ${fmtDay(to)}` : "";
    const btn = byId("pg-close-btn");
    const reopen = byId("pg-reopen-btn");
    const info = byId("pg-close-info");
    reopen.hidden = !done;
    btn.disabled = !hasData || !wk;
    btn.querySelector(".btn-txt").textContent = done ? "Volver a guardar" : "Cerrar semana";
    if (done) {
      const n = (done.datos?.rows || []).filter((r) => r.strike).length;
      const when = done.created_at ? new Date(done.created_at).toLocaleString("es-GT", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" }) : "";
      info.textContent = `✅ Cerrada${when ? ` el ${when}` : ""}${done.cerrada_por ? ` por ${done.cerrada_por}` : ""} · ${n} ${n === 1 ? "strike guardado" : "strikes guardados"}.`;
    } else if (!hasData) {
      info.textContent = "Carga las facturas y los rascas de la semana para poder cerrarla.";
    } else {
      info.textContent = "Cuando hayas pagado, ciérrala: así se guardan los strikes para las próximas semanas.";
    }
  }

  byId("pg-close-btn")?.addEventListener("click", async () => {
    const wk = payWeekKey();
    const to = byId("dlog-to")?.value || "";
    if (!wk || !lastSnapshot) return;
    const strikes = lastSnapshot.rows.filter((r) => r.strike).map((r) => `${r.name} (${strikeLabel(strikesBefore(r.id, r.name, wk) + 1)})`);
    const msg = `¿Cerrar la semana del domingo ${fmtDay(wk)} al sábado ${fmtDay(to)}?\n\n` +
      (strikes.length ? `Strikes que se guardan:\n• ${strikes.join("\n• ")}` : "Nadie recibe strike esta semana.");
    if (!confirm(msg)) return;
    const btn = byId("pg-close-btn");
    btn.disabled = true;
    try {
      await cloud.req("/rest/v1/pagos_semanas?on_conflict=semana", {
        method: "POST",
        headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
        body: { semana: wk, desde: wk, hasta: to || wk, datos: lastSnapshot, cerrada_por: authWho(), created_at: new Date().toISOString() },
      });
      await loadStrikeHist();
      await refresh();
    } catch (e) {
      alert(`No se pudo cerrar la semana: ${e.message}\n\n¿Ejecutaste el SQL 5_semanas_strikes.sql en Supabase?`);
    } finally {
      renderClose();
    }
  });

  byId("pg-reopen-btn")?.addEventListener("click", async () => {
    const wk = payWeekKey();
    if (!wk || !confirm(`¿Reabrir la semana del ${fmtDay(wk)}? Se borran sus strikes guardados.`)) return;
    try {
      await cloud.req(`/rest/v1/pagos_semanas?semana=eq.${wk}`, { method: "DELETE" });
      await loadStrikeHist();
      await refresh();
    } catch (e) {
      alert(`No se pudo reabrir: ${e.message}`);
    } finally {
      renderClose();
    }
  });
  for (const id of ["dlog-from", "dlog-to"]) byId(id)?.addEventListener("change", () => refresh());
  document.addEventListener("badu-auth", async () => {
    await loadStrikeHist();
    refresh();
  });

  async function refresh() {
    const inv = Object.values(state.invoices);
    const invSummary = {
      count: inv.length,
      total: inv.reduce((a, v) => a + (v.amount || 0), 0),
      paid_count: inv.filter((v) => v.paid_at).length,
      paid_total: inv.filter((v) => v.paid_at).reduce((a, v) => a + (v.amount || 0), 0),
      pending_count: inv.filter((v) => !v.paid_at).length,
      pending_total: inv.filter((v) => !v.paid_at).reduce((a, v) => a + (v.amount || 0), 0),
    };
    const salesSummary = {
      count: state.sales.length,
      qty: state.sales.reduce((a, s) => a + (s.qty || 0), 0),
      total: state.sales.reduce((a, s) => a + (s.total || 0), 0),
    };

    refs.invLine1.textContent = `Total: ${invSummary.count} | ${fmtMoney(invSummary.total)}`;
    refs.invLine2.textContent = `Pagadas: ${invSummary.paid_count} | ${fmtMoney(invSummary.paid_total)}`;
    refs.invLine3.textContent = `Pendientes: ${invSummary.pending_count} | ${fmtMoney(invSummary.pending_total)}`;
    refs.salesLine1.textContent = `Ventas: ${salesSummary.count}`;
    refs.salesLine2.textContent = `Total: ${fmtMoney(salesSummary.total)}`;

    refs.invTable.innerHTML = "";
    for (const [name, total] of Object.entries(state.invByIssuer).sort(sortByValueDescThenName)) {
      refs.invTable.insertAdjacentHTML(
        "beforeend",
        `<tr>
          <td>${escapeHtml(name)}</td>
          <td class="num">${fmtMoney(total)}</td>
          <td class="num">${fmtMoney(state.invByIssuerPaid[name] || 0)}</td>
          <td class="num">${fmtMoney(state.invByIssuerPending[name] || 0)}</td>
        </tr>`
      );
    }
    refs.salesTable.innerHTML = "";
    for (const [name, total] of Object.entries(state.salesBySeller).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0], "es"))) {
      refs.salesTable.insertAdjacentHTML(
        "beforeend",
        `<tr>
          <td>${escapeHtml(name)}</td>
          <td class="num">${state.salesBySellerQty[name] || 0}</td>
          <td class="num">${fmtMoney(total)}</td>
        </tr>`
      );
    }

    let employees = [];
    try {
      employees = await listEmployees();
    } catch {
      employees = [];
    }
    const rows = buildRanking(employees);
    PAGOS_WEEK_GROSS = rows.length ? new Map(rows.map((r) => [normalizeKeySimple(r.name), r.total])) : null;
    const totalAPagar = rows.reduce((a, r) => a + (r.emp && !r.noPay ? r.toPay : 0), 0);

    const totalGeneral = invSummary.total + salesSummary.total;
    refs.totalGeneral.textContent = fmtMoney(totalGeneral);
    refs.totalAPagar.textContent = fmtMoney(totalAPagar);
    let footerText = `Facturas: ${invSummary.count} | Rascas: ${salesSummary.count} | Total: ${fmtMoney(totalGeneral)}`;
    if (state.ignoredOtherBusiness > 0) footerText += ` | Ignorados (otro comercio): ${state.ignoredOtherBusiness}`;
    refs.footer.textContent = footerText;
    refs.loaded.textContent = invSummary.count || salesSummary.count ? "Datos cargados" : "Sin datos";
    renderRanking(rows, invSummary, salesSummary, totalAPagar, employees);
  }

  function clearState() {
    state.invoices = {};
    state.sales = [];
    state.invByIssuer = {};
    state.invByIssuerPaid = {};
    state.invByIssuerPending = {};
    state.salesBySeller = {};
    state.salesBySellerQty = {};
    state.ignoredOtherBusiness = 0;
    refresh();
  }

  async function processCurrent() {
    const text = refs.input.value.trim();
    if (!text) {
      alert("Pega el texto antes de procesar.");
      return;
    }
    const out = processText(text);
    state.invoices = out.invoices;
    state.sales = out.sales;
    state.invByIssuer = out.invByIssuer;
    state.invByIssuerPaid = out.invByIssuerPaid;
    state.invByIssuerPending = out.invByIssuerPending;
    state.salesBySeller = out.salesBySeller;
    state.salesBySellerQty = out.salesBySellerQty;
    state.ignoredOtherBusiness = out.ignoredOtherBusiness || 0;
    await refresh();
    // En el movil el resumen queda debajo del texto: se baja hasta el.
    if (window.matchMedia("(max-width: 1100px)").matches) {
      document.querySelector("#tab-conta .pg-kpis")?.scrollIntoView({ block: "start", behavior: "smooth" });
    }
  }

  byId("conta-process").addEventListener("click", processCurrent);
  byId("conta-clear").addEventListener("click", () => {
    refs.input.value = "";
    delete refs.input.dataset.discord;
    clearState();
  });
  byId("conta-paste").addEventListener("click", async () => {
    try {
      const clip = await navigator.clipboard.readText();
      // Si ya se trajeron las facturas del Discord, lo pegado (las rascas) se
      // añade debajo en vez de reemplazarlas.
      const keep = refs.input.dataset.discord === "1" ? refs.input.value.trim() : "";
      refs.input.value = keep ? `${keep}\n\n${clip}` : clip;
    } catch {
      alert("No se pudo leer el portapapeles. Pega el texto a mano y pulsa Procesar.");
      return;
    }
    await processCurrent();
  });
  byId("conta-export").addEventListener("click", () => {
    if (!Object.keys(state.invoices).length && !state.sales.length) {
      alert("No hay datos para exportar.");
      return;
    }
    const sortInvoices = (a, b) => {
      const an = Number(a.invoice_id);
      const bn = Number(b.invoice_id);
      if (!Number.isNaN(an) && !Number.isNaN(bn)) return an - bn;
      return String(a.invoice_id).localeCompare(String(b.invoice_id), "es");
    };
    const invoicesRows = Object.values(state.invoices)
      .sort(sortInvoices)
      .map((v) => [v.invoice_id, v.issuer || "", v.recipient || "", v.concept || "", v.amount ?? "", v.sent_at || "", v.paid_at || "", v.paid_at ? "PAGADA" : "PENDIENTE", v.method || "facturas"]);
    const salesRows = state.sales.map((s) => [s.seller || "", s.buyer || "", s.qty ?? "", s.total ?? ""]);
    downloadCsv("facturas_resultado.csv", ["invoice_id", "issuer", "recipient", "concept", "amount", "sent_at", "paid_at", "status", "metodo"], invoicesRows);
    downloadCsv("ventas_rasca_y_gana.csv", ["seller", "buyer", "qty", "total"], salesRows);
  });

  setupEmployeesModal(state, refresh);
  setupDiscordLog(refs, processCurrent, () => Object.keys(state.invoices || {}).length);
  setupRascasCopier();
  clearState();
}

// ===================== Copiador de Rasca y Gana (marcador) =====================
// El log de Rasca y Gana esta en el Discord de la ciudad, donde no podemos
// meter un bot. Este marcador se ejecuta en discord.com y solo lee los mensajes
// que ya ves en pantalla (no usa tu cuenta ni la API, no se desplaza solo).
// Recoge los de la semana (hora de España) mientras subes con la rueda y los
// copia. Igual que el copiador de kits de Aguila Motors.
// Enlace directo al canal del log de Rasca y Gana en el Discord de la ciudad
// (clic derecho en el canal → Copiar enlace). Vacio = no se muestra el boton.
const RASCAS_CHANNEL_URL = "https://discord.com/channels/943830234128597003/1424138655114592470";

function baduRascasCopier() {
  if (window.__baduRascas) { window.__baduRascas.show(); return; }
  if (!/discord\.com$/.test(location.hostname)) { alert("Abre el canal de Rasca y Gana en discord.com (en el navegador, no en la aplicación) y pulsa otra vez el marcador."); return; }
  const EPOCH = 1420070400000n;
  const seen = new Map();
  const tsOf = (id) => { try { return Number((BigInt(id) >> 22n) + EPOCH); } catch { return 0; } };
  const madrid = (ms) => {
    const p = {};
    for (const x of new Intl.DateTimeFormat("en-US", { timeZone: "Europe/Madrid", year: "numeric", month: "numeric", day: "numeric", hour: "numeric", minute: "numeric", second: "numeric", weekday: "short", hourCycle: "h23" }).formatToParts(new Date(ms))) p[x.type] = x.value;
    return { y: +p.year, m: +p.month, d: +p.day, h: +p.hour % 24, mi: +p.minute, s: +p.second, wd: ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"].indexOf(p.weekday) };
  };
  const midnight = (iso, add = 0) => {
    const [y, m, d] = iso.split("-").map(Number);
    const t = Date.UTC(y, m - 1, d + add);
    let g = t;
    for (let i = 0; i < 3; i++) { const p = madrid(g); g += t - Date.UTC(p.y, p.m - 1, p.d, p.h, p.mi, p.s); }
    return g;
  };
  const md = madrid(Date.now());
  const today = Date.UTC(md.y, md.m - 1, md.d);
  const startDay = new Date(today - (md.wd === 0 ? 7 : md.wd) * 86400000);
  const iso = (d) => d.toISOString().slice(0, 10);
  const fmt = (ms) => new Date(ms).toLocaleString("es-ES", { weekday: "short", day: "numeric", month: "short", hour: "2-digit", minute: "2-digit", hour12: false }).replace(/,/g, "");

  let chan = "";
  const grab = () => {
    const cur = (location.pathname.match(/\/channels\/[^/]+\/(\d+)/) || [])[1] || "";
    if (cur !== chan) { chan = cur; seen.clear(); }
    for (const li of document.querySelectorAll('li[id^="chat-messages-"]')) {
      const parts = li.id.split("-");
      const id = parts.pop();
      if (!/^\d+$/.test(id) || (chan && parts.pop() !== chan)) continue;
      const txt = (li.innerText || "").trim();
      if (txt) seen.set(id, txt);
    }
    update();
  };

  const box = document.createElement("div");
  box.style.cssText = "position:fixed;top:70px;right:20px;z-index:99999;width:320px;background:#14171b;color:#e6e9ee;border:1px solid #3aa0ff;border-radius:12px;padding:12px 14px;font:13px/1.4 system-ui,sans-serif;box-shadow:0 8px 30px rgba(0,0,0,.5)";
  box.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px"><b style="font-size:14px">🍎 Copiador de Rasca y Gana</b><button data-x style="background:none;border:0;color:#aaa;font-size:18px;cursor:pointer">×</button></div>
    <div style="display:flex;gap:8px;margin-bottom:6px">
      <label style="flex:1;font-size:11px;opacity:.8">Desde (domingo)<input data-f type="date" style="width:100%;margin-top:2px;background:#0f1216;color:#fff;border:1px solid #2f353d;border-radius:6px;padding:4px;color-scheme:dark"></label>
      <label style="flex:1;font-size:11px;opacity:.8">Hasta (sábado)<input data-t type="date" style="width:100%;margin-top:2px;background:#0f1216;color:#fff;border:1px solid #2f353d;border-radius:6px;padding:4px;color-scheme:dark"></label>
    </div>
    <div data-s style="margin:8px 0;min-height:54px"></div>
    <button data-c style="width:100%;padding:9px;border:0;border-radius:8px;background:#3aa0ff;color:#04121f;font-weight:700;cursor:pointer">Copiar rascas de la semana</button>
    <div style="font-size:11px;opacity:.6;margin-top:6px">Solo lee lo que ya ves en pantalla. Ve subiendo con la rueda del ratón.</div>`;
  document.body.appendChild(box);
  const $ = (s) => box.querySelector(s);
  $("[data-f]").value = iso(startDay);
  $("[data-t]").value = iso(new Date(startDay.getTime() + 6 * 86400000));

  const inRange = () => {
    const a = midnight($("[data-f]").value), b = midnight($("[data-t]").value, 1);
    const list = [...seen.entries()].map(([id, t]) => ({ id, t, ts: tsOf(id) })).sort((x, y) => x.ts - y.ts);
    return { a, b, list, sel: list.filter((m) => m.ts >= a && m.ts < b) };
  };
  function update() {
    if (!$("[data-f]").value || !$("[data-t]").value) return;
    const { a, b, list, sel } = inRange();
    const oldest = list[0]?.ts, newest = list[list.length - 1]?.ts;
    const n = sel.filter((m) => /rasca\s+y\s+gana/i.test(m.t)).length;
    let s = `<b>${n}</b> ventas de Rasca y Gana recogidas de esa semana.<br>`;
    if (!list.length) s += "⏳ No veo mensajes: abre el canal de Rasca y Gana.";
    else if (oldest >= a) s += `<span style="color:#f2bf7a">⬆ Sigue subiendo hasta pasar el <b>${fmt(a)}</b> (tu hora). Ahora llegas al ${fmt(oldest)}.</span>`;
    else if (newest < b && b < Date.now() - 60000) s += `<span style="color:#f2bf7a">⬇ Baja hasta pasar el <b>${fmt(b)}</b> (tu hora).</span>`;
    else s += `<span style="color:#7cffc4">✅ Semana completa. Pulsa Copiar.</span>`;
    if ($("[data-s]").innerHTML !== s) $("[data-s]").innerHTML = s;
  }

  $("[data-f]").addEventListener("change", update);
  $("[data-t]").addEventListener("change", update);
  $("[data-x]").addEventListener("click", () => { box.style.display = "none"; });
  $("[data-c]").addEventListener("click", async () => {
    grab();
    const { sel } = inRange();
    const text = sel.map((m) => m.t).join("\n\n");
    if (!text) { $("[data-s]").innerHTML += "<br>No hay mensajes de esa semana todavía."; return; }
    let ok = false;
    try { await navigator.clipboard.writeText(text); ok = true; } catch {}
    if (!ok) {
      const ta = document.createElement("textarea");
      ta.value = text; document.body.appendChild(ta); ta.select();
      try { ok = document.execCommand("copy"); } catch {}
      ta.remove();
    }
    $("[data-c]").textContent = ok ? `✅ Copiados ${sel.length} mensajes` : "No se pudo copiar";
    setTimeout(() => { $("[data-c]").textContent = "Copiar rascas de la semana"; }, 3000);
  });

  const obs = new MutationObserver((muts) => {
    if (muts.every((m) => box.contains(m.target))) return;
    clearTimeout(window.__baduRascasT);
    window.__baduRascasT = setTimeout(grab, 150);
  });
  obs.observe(document.body, { childList: true, subtree: true });
  window.__baduRascas = { show: () => { box.style.display = ""; grab(); } };
  grab();
}

function rascasBookmarkletHref() {
  return "javascript:" + encodeURIComponent(`(${baduRascasCopier.toString()})();`);
}

function setupRascasCopier() {
  const dlg = byId("rascas-dlg");
  const open = byId("rascas-install");
  if (!dlg || !open) return;
  const link = byId("rascas-bm");
  link.href = rascasBookmarkletHref();
  link.addEventListener("click", (e) => {
    e.preventDefault();
    alert("No lo pulses aquí: arrástralo a tu barra de favoritos y úsalo dentro de Discord.");
  });
  open.addEventListener("click", () => dlg.showModal());
  byId("rascas-copy-code")?.addEventListener("click", async () => {
    const ok = await copyText(link.href);
    byId("rascas-copy-code").textContent = ok ? "✅ Código copiado" : "No se pudo copiar";
  });
  const chan = byId("rascas-channel");
  if (chan) {
    chan.hidden = !RASCAS_CHANNEL_URL;
    if (RASCAS_CHANNEL_URL) chan.href = RASCAS_CHANNEL_URL;
  }
}

// ===================== Facturas desde el Discord del Badulaque =====================
// Un bot (funcion "leer-logs" en Supabase) copia el canal de facturas a la
// tabla discord_log. Aqui se traen por fechas y se convierten al mismo texto
// que sale al copiar a mano desde Discord, para usar el lector de siempre.
// Igual que en Aguila Motors.

function dlogClean(t) {
  return String(t || "")
    .replace(/\u001b?\[[\d;]*m/g, "") // colores ANSI del bloque ```ansi
    .replace(/```[a-z]*[ \t]*\n?/gi, "") // aperturas/cierres de bloque de codigo
    .replace(/\*|__|~~|`/g, "")
    .replace(/^[ \t]*(?:-#|#{1,3})[ \t]+/gm, "") // titulos "# 150000€" y subtexto "-#"
    .replace(/^\s*>\s?/gm, "");
}

function dlogDate(iso) {
  const d = new Date(iso);
  if (isNaN(d)) return "";
  const p = (n) => String(n).padStart(2, "0");
  return `${p(d.getDate())}/${p(d.getMonth() + 1)}/${d.getFullYear()} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

function dlogMessageText(m) {
  const out = [];
  const push = (t) => {
    const c = dlogClean(t).trim();
    if (c) out.push(c);
  };
  push(m.content);
  for (const e of Array.isArray(m.embeds) ? m.embeds : []) {
    push(e.author?.name);
    push(e.title);
    push(e.description);
    for (const f of e.fields || []) {
      const name = dlogClean(f.name).trim().replace(/:\s*$/, "");
      const value = dlogClean(f.value).trim();
      if (!name || name === "\u200b") push(value);
      else if (!value || value === "\u200b") push(name);
      else if (/^[\d.,]+\s*€$/.test(value) || value.includes("\n")) {
        push(name);
        push(value);
      } else push(`${name}: ${value}`);
    }
    const foot = dlogClean(e.footer?.text).trim();
    const when = dlogDate(e.timestamp || m.ts);
    if (foot) out.push(foot.includes("•") && when && !/\d{1,2}[/:]\d{2}/.test(foot.split("•").pop()) ? `${foot} • ${when}` : foot);
  }
  return out.join("\n");
}

// Partes de una fecha vista en hora de España (Europe/Madrid).
function dlogMadridParts(ms) {
  const parts = {};
  for (const p of new Intl.DateTimeFormat("en-US", {
    timeZone: "Europe/Madrid", year: "numeric", month: "numeric", day: "numeric",
    hour: "numeric", minute: "numeric", second: "numeric", weekday: "short", hourCycle: "h23",
  }).formatToParts(new Date(ms))) parts[p.type] = p.value;
  return {
    y: +parts.year, m: +parts.month, d: +parts.day, h: +parts.hour % 24, mi: +parts.minute, s: +parts.second,
    wd: ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"].indexOf(parts.weekday),
  };
}

// Instante (ms) de las 00:00 en España del dia "AAAA-MM-DD" (+ addDays).
function dlogMadridMidnight(isoDay, addDays = 0) {
  const [y, m, d] = isoDay.split("-").map(Number);
  const target = Date.UTC(y, m - 1, d + addDays);
  let guess = target;
  for (let i = 0; i < 3; i++) {
    const p = dlogMadridParts(guess);
    const seen = Date.UTC(p.y, p.m - 1, p.d, p.h, p.mi, p.s);
    guess += target - seen;
  }
  return guess;
}

function dlogToText(rows) {
  return rows.map(dlogMessageText).filter(Boolean).join("\n\n");
}

function setupDiscordLog(refs, processCurrent, invoiceCount) {
  const box = byId("dlog-box");
  if (!box) return;
  const from = byId("dlog-from");
  const to = byId("dlog-to");
  const btn = byId("dlog-load");
  const status = byId("dlog-status");
  // Solo con la nube y para Jefes (la tabla tampoco deja leer a nadie mas).
  const sync = () => (box.hidden = !(cloudOn() && isJefe()));
  document.addEventListener("badu-auth", sync);
  sync();

  // Semana de pago: domingo 00:00 a sabado 24:00 en hora de ESPAÑA. En
  // Guatemala el cierre cae el sabado a las 16:00 (verano europeo) o a las
  // 17:00 (invierno europeo); el calculo lo hace solo. Por defecto: si en
  // España ya es domingo, la semana que acaba de cerrar; si no, la en curso.
  const md = dlogMadridParts(Date.now());
  const todayUtc = Date.UTC(md.y, md.m - 1, md.d);
  const startDay = md.wd === 0 ? new Date(todayUtc - 7 * 86400000) : new Date(todayUtc - md.wd * 86400000);
  const isoU = (d) => d.toISOString().slice(0, 10);
  from.value = isoU(startDay);
  to.value = isoU(new Date(startDay.getTime() + 6 * 86400000));
  const rangeBox = byId("dlog-range");
  // Banderas en SVG: Windows no dibuja los emojis de banderas (salen "ES"/"GT").
  const FLAG_ES = '<svg class="flag" viewBox="0 0 30 20" aria-label="España"><rect width="30" height="20" fill="#c60b1e"/><rect y="5" width="30" height="10" fill="#ffc400"/></svg>';
  const FLAG_GT = '<svg class="flag" viewBox="0 0 30 20" aria-label="Guatemala"><rect width="30" height="20" fill="#4997d0"/><rect x="10" width="10" height="20" fill="#fff"/><circle cx="15" cy="10" r="2.6" fill="none" stroke="#6a9a3a" stroke-width="1.1"/></svg>';
  const fmtIn = (ms, tz) =>
    new Date(ms).toLocaleString("es-ES", { timeZone: tz, weekday: "long", day: "numeric", month: "short", hour: "2-digit", minute: "2-digit", hour12: false }).replace(/,/g, "").replace(/ (\d{2}:\d{2})$/, " a las $1");
  const showRange = () => {
    if (!from.value || !to.value || !rangeBox) return;
    const s = dlogMadridMidnight(from.value);
    const e = dlogMadridMidnight(to.value, 1);
    const esFrom = fmtIn(s, "Europe/Madrid");
    const esTo = fmtIn(e - 60000, "Europe/Madrid").replace(/23:59$/, "24:00");
    rangeBox.innerHTML =
      `<div class="dlog-tz">${FLAG_ES}<span><b>España:</b> del ${esFrom} al ${esTo}</span></div>` +
      `<div class="dlog-tz">${FLAG_GT}<span><b>Guatemala:</b> del ${fmtIn(s, "America/Guatemala")} al ${fmtIn(e, "America/Guatemala")}</span></div>`;
  };
  from.addEventListener("change", showRange);
  to.addEventListener("change", showRange);
  showRange();
  const say = (msg, kind = "") => {
    status.className = `dlog-status ${kind}`;
    status.innerHTML = msg;
  };

  btn.addEventListener("click", async () => {
    if (!from.value || !to.value) return say("Elige las dos fechas.", "err");
    const start = new Date(dlogMadridMidnight(from.value));
    const end = new Date(dlogMadridMidnight(to.value, 1));
    if (end <= start) return say("La fecha <b>Hasta</b> debe ser igual o posterior a <b>Desde</b>.", "err");
    btn.disabled = true;
    try {
      // 1) Pide al bot que copie lo ultimo del canal (si falla, se usa lo ya guardado).
      say("Actualizando desde Discord…");
      let botNote = "";
      let botNew = null;
      try {
        const tok = await cloud.token();
        const ctl = new AbortController();
        const timer = setTimeout(() => ctl.abort(), 60000);
        const r = await fetch(`${BADU_CLOUD_URL}/functions/v1/leer-logs`, {
          method: "POST",
          headers: { apikey: BADU_CLOUD_KEY, Authorization: `Bearer ${tok || BADU_CLOUD_KEY}`, "Content-Type": "application/json" },
          body: "{}",
          signal: ctl.signal,
        }).finally(() => clearTimeout(timer));
        const j = await r.json().catch(() => ({}));
        if (r.ok && j.ok !== false && typeof j.nuevos === "number") botNew = j.nuevos;
        if (r.ok && j.ok !== true && j.ok !== false) {
          // Responde, pero no es el bot (p. ej. la plantilla "Hello" de Supabase).
          botNote = " ⚠ La función <b>leer-logs</b> no tiene el código del bot: en Supabase, borra el contenido de su <b>index.ts</b>, pega el de <b>3_bot_funcion_leer-logs.ts</b> y pulsa Deploy.";
        } else if (!r.ok || j.ok === false) botNote = ` ⚠ El bot no respondió bien${j.error ? ` (${escapeHtml(String(j.error).slice(0, 160))})` : ""}; se usó lo ya guardado.`;
      } catch {
        botNote = " ⚠ No se pudo avisar al bot; se usó lo ya guardado.";
      }
      // 2) Lee los mensajes del rango, por paginas de 1000.
      say("Leyendo facturas…");
      const rows = [];
      for (let off = 0; ; off += 1000) {
        const q = `/rest/v1/discord_log?select=id,ts,author,content,embeds&ts=gte.${encodeURIComponent(start.toISOString())}&ts=lt.${encodeURIComponent(end.toISOString())}&order=ts.asc,id.asc&limit=1000&offset=${off}`;
        const part = await cloud.req(q);
        if (!Array.isArray(part)) break;
        rows.push(...part);
        if (part.length < 1000) break;
      }
      if (!rows.length) {
        // Diagnostico: que tiene guardado la tabla, para saber si falla el bot
        // (no copia nada) o si simplemente no hubo facturas esas fechas.
        let info = "";
        try {
          const first = await cloud.req("/rest/v1/discord_log?select=ts&order=ts.asc&limit=1");
          const last = await cloud.req("/rest/v1/discord_log?select=ts&order=ts.desc&limit=1");
          const fmtD = (iso) => new Date(iso).toLocaleString("es-ES", { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
          info = first?.length
            ? `<br>Hay mensajes guardados del <b>${fmtD(first[0].ts)}</b> al <b>${fmtD(last[0].ts)}</b>: prueba con esas fechas.`
            : "<br>La tabla está <b>vacía</b>: el bot todavía no ha copiado nada. Revisa que <b>LOG_CHANNEL_ID</b> sea el canal de facturas, que el bot pueda ver ese canal y que tenga activado <b>Message Content Intent</b>.";
        } catch {
          // sin diagnostico
        }
        const copied = botNew === null ? "" : `<br>El bot copió <b>${botNew}</b> mensajes nuevos en esta llamada.`;
        say(`No hay mensajes guardados entre esas fechas.${copied}${info}${botNote}`, "err");
        return;
      }
      refs.input.value = dlogToText(rows);
      refs.input.dataset.discord = "1";
      await processCurrent();
      const n = invoiceCount();
      say(`✅ ${rows.length} mensajes · <b>${n}</b> facturas cargadas. Ahora copia el log de <b>Rasca y Gana</b> y pulsa <strong>Pegar + Procesar</strong> (se añade debajo).${botNote}`, "ok");
    } catch (e) {
      say(`No se pudieron traer: ${escapeHtml(String(e.message || e))}`, "err");
    } finally {
      btn.disabled = false;
    }
  });
}



function setupEmployeesModal(state, refreshPagos) {
  const totalsModal = byId("employees-modal");
  const totalsBody = byId("employees-body");
  const adminModal = byId("employees-admin-modal");

  let selectedId = null;
  let totalsRows = [];

  function sumByNormalizedName(map, name) {
    const target = normalizeKeySimple(name);
    let sum = 0;
    for (const [k, v] of Object.entries(map || {})) {
      if (normalizeKeySimple(k) === target) sum += Number(v || 0);
    }
    return sum;
  }

  async function buildTotalsRows() {
    const employees = await listEmployees();
    totalsRows = employees.map((e) => {
      const name = fullName(e);
      const paid = sumByNormalizedName(state.invByIssuerPaid, name);
      const ras = sumByNormalizedName(state.salesBySeller, name);
      const gross = paid + ras;
      const pct = pctForRank(e.rank);
      return {
        id: e.id, name, rank: e.rank || "", pct, paid, ras, gross,
        payout: Math.round(gross * pct),
        discord: getEmployeeDiscord(name), iban: getEmployeeIban(name), noPay: isEmployeeNoPay(name),
      };
    });
    // Primero quien cobra (de mas a menos); los que no cobran, al final.
    totalsRows.sort((a, b) => a.noPay - b.noPay || b.payout - a.payout || a.name.localeCompare(b.name, "es"));
    // Bono del empleado de la semana y strikes (no llegar al minimo).
    const competes = (r) => !r.noPay && !isOwnerRank(r.rank);
    const maxPayout = Math.max(0, ...totalsRows.map((r) => (competes(r) ? r.payout : 0)));
    const wk = payWeekKey();
    for (const r of totalsRows) {
      r.bonus = maxPayout > 0 && competes(r) && r.payout === maxPayout ? WEEK_BONUS : 0;
      r.toPay = r.payout + r.bonus;
      const ws = weekStrike(wk, r.id, r.name, r.gross, r.noPay, r.rank);
      r.strike = ws.on;
      r.strikeWhy = ws.reason;
      r.strikeN = r.strike ? strikesBefore(r.id, r.name, wk) + 1 : 0;
    }
  }

  function renderTotalsRows() {
    totalsBody.innerHTML = "";
    for (const row of totalsRows) {
      const tr = document.createElement("tr");
      if (row.id === selectedId) tr.classList.add("is-selected");
      tr.innerHTML = `
        <td>${escapeHtml(row.name)}${row.strike ? `<br><small class="warn">${row.strikeN >= STRIKE_MAX && cloudOn() ? "🚫" : "⚠️"} ${escapeHtml(strikeLabel(row.strikeN))} (${escapeHtml(row.strikeWhy || strikeReason(row.gross))})</small>` : ""}</td>
        <td>${escapeHtml(row.rank || "-")}</td>
        <td class="num">${row.pct ? pctText(row.pct) : "-"}</td>
        <td class="num">${fmtMoney(row.paid)}</td>
        <td class="num">${fmtMoney(row.ras)}</td>
        <td class="num">${row.noPay ? `<span class="muted" title="Le corresponderían ${fmtMoney(row.payout)}">${NO_PAY_TEXT}</span>` : fmtMoney(row.toPay)}${row.bonus ? `<br><small class="muted">incl. bono ${fmtMoney(row.bonus)} ★</small>` : ""}</td>
      `;
      tr.addEventListener("click", () => {
        selectedId = row.id;
        renderTotalsRows();
      });
      tr.addEventListener("dblclick", async () => {
        const text = row.noPay ? NO_PAY_TEXT : String(row.toPay);
        const ok = await copyText(text);
        if (!ok) openCopyFallback(text);
      });
      totalsBody.appendChild(tr);
    }
    const bankTotal = totalsRows.reduce((acc, r) => acc + (r.noPay ? 0 : r.toPay), 0);
    byId("employees-bank-total").textContent = `Total a pagar: ${fmtMoney(bankTotal)}`;
  }

  async function openTotalsModal() {
    const employees = await listEmployees();
    if (!employees.length) {
      alert("No hay empleados en la lista. Entra en 'Gestión de empleados' para añadirlos.");
      return;
    }
    await buildTotalsRows();
    selectedId = null;
    renderTotalsRows();
    totalsModal.showModal();
  }

  byId("conta-employees").addEventListener("click", () => {
    openTotalsModal().catch(() => alert("No se pudieron cargar los empleados."));
  });

  // Quien mas cobra (y si cobra) es el empleado de la semana; si hay empate, todos.
  function isEmployeeOfWeek(row) {
    return !!row.bonus;
  }

  const payForCopy = (row) => (row.bonus ? `${fmtMoneyPlain(row.toPay)} (incl. bono ${fmtMoneyPlain(row.bonus)})` : fmtMoneyPlain(row.toPay));

  // "Nombre (Rango) <@ID>": si tiene Discord, se le etiqueta.
  function labelForCopy(row) {
    let label = row.rank ? `${row.name} (${row.rank})` : row.name;
    if (row.discord) label += ` <@${row.discord}>`;
    return label;
  }

  const ibanForCopy = (row) => (row.iban ? `IBAN ${row.iban}` : IBAN_PENDING_TEXT);

  byId("employees-copy-sel").addEventListener("click", async () => {
    const row = totalsRows.find((r) => r.id === selectedId);
    if (!row) return;
    const pct = row.pct ? pctText(row.pct) : "-";
    let text = row.noPay
      ? `${labelForCopy(row)} | ${pct} | Cobrado: ${fmtMoney(row.gross)} | ${NO_PAY_TEXT}`
      : `${labelForCopy(row)} | ${pct} | Cobrado: ${fmtMoney(row.gross)} | A pagar: ${fmtMoney(row.toPay)}${row.bonus ? ` (incl. bono ${fmtMoney(row.bonus)})` : ""} | ${ibanForCopy(row)}`;
    if (isEmployeeOfWeek(row)) text += ` | ${EMPLOYEE_OF_WEEK_TAG}`;
    if (row.strike) text += ` | ${strikeText(row.strikeN, row.gross, row.strikeWhy)}`;
    const ok = await copyText(text);
    if (!ok) openCopyFallback(text);
  });

  byId("employees-remove")?.addEventListener("click", () => {
    if (!totalsRows.some((r) => r.id === selectedId)) return;
    totalsRows = totalsRows.filter((r) => r.id !== selectedId);
    selectedId = null;
    renderTotalsRows();
  });

  // Texto para el canal de pagas (el mismo de "Copiar todo").
  function discordPayText() {
    return totalsRows
      .map((r) => {
        let line = r.noPay
          ? `* ${labelForCopy(r)}: ${NO_PAY_TEXT}`
          : `* ${labelForCopy(r)}: ${payForCopy(r)} · ${ibanForCopy(r)}`;
        if (isEmployeeOfWeek(r)) line += ` ${EMPLOYEE_OF_WEEK_TAG}`;
        if (r.strike) line += ` ${strikeText(r.strikeN, r.gross, r.strikeWhy)}`;
        return line;
      })
      .join("\n");
  }

  byId("employees-copy-all").addEventListener("click", async () => {
    if (!totalsRows.length) return;
    const text = discordPayText();
    const ok = await copyText(text);
    if (!ok) openCopyFallback(text);
  });

  // Boton del panel de Pagos: arma los totales sin abrir la ventana y copia.
  byId("pg-copy-discord")?.addEventListener("click", async () => {
    const status = byId("pg-copy-status");
    try {
      await buildTotalsRows();
    } catch {
      alert("No se pudieron cargar los empleados.");
      return;
    }
    if (!totalsRows.length) {
      alert("No hay empleados en la lista. Entra en 'Gestión de empleados' para añadirlos.");
      return;
    }
    const text = discordPayText();
    const ok = await copyText(text);
    if (!ok) openCopyFallback(text);
    if (status) {
      status.textContent = ok ? `✔ Copiado: ${totalsRows.length} empleados. Pégalo en el canal de pagas.` : "";
      setTimeout(() => (status.textContent = ""), 4000);
    }
  });

  function openAdminModal() {
    adminModal.showModal();
    adminModal.dispatchEvent(new Event("badu-open"));
  }

  byId("conta-manage-employees").addEventListener("click", openAdminModal);
  byId("employees-manage").addEventListener("click", () => {
    totalsModal.close();
    openAdminModal();
  });

  setupEmployeesAdminModal({
    onChanged: async () => {
      // Rango, IBAN o "No cobra" cambian lo que muestra Pagos.
      await refreshPagos?.();
      if (totalsModal.open) {
        await buildTotalsRows();
        renderTotalsRows();
      }
    },
  });
}

// Editor de strikes de una persona (solo Jefe Tribal): semanas cerradas,
// ＋1 / −1 / quitar todos y clic en una semana para poner o quitar.
function buildStrikeEditor(emp, onDone) {
  const name = fullName(emp);
  const id = emp.id;
  const mk = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  };
  const dm = (iso) => (iso ? `${iso.slice(8, 10)}/${iso.slice(5, 7)}` : "");
  const box = mk("div", "strike-editor");
  const hist = strikeHistoryOf(id, name);
  const run = async (btn, changes) => {
    btn.disabled = true;
    try {
      await saveStrikeAdjMany(changes, id, name);
      onDone?.();
    } catch (err) {
      btn.disabled = false;
      alert(`No se pudo guardar: ${err.message || err}`);
    }
  };
  const acts = mk("div", "strike-ed-acts");
  const plus = mk("button", "small", "＋1 strike");
  plus.type = "button";
  // ＋1: la semana mas reciente sin strike (o con el strike quitado).
  const breaker = hist.find((h) => !h.on);
  plus.disabled = !breaker;
  plus.title = breaker ? `Se marca la semana del ${dm(breaker.wk)}` : "No hay semanas cerradas donde ponerlo";
  plus.addEventListener("click", () => {
    const m = prompt(`Poner un strike a ${name} (semana del ${dm(breaker.wk)}).\n\nMotivo:`, "");
    if (m === null) return;
    if (!m.trim()) return alert("Escribe el motivo del strike.");
    run(plus, [{ wk: breaker.wk, value: strikeValueFor(breaker, true, m.trim()) }]);
  });
  const minus = mk("button", "ghost small", "−1 strike");
  minus.type = "button";
  const lastOn = hist.find((h) => h.counted);
  minus.disabled = !lastOn;
  minus.addEventListener("click", () => {
    const m = prompt(`Quitar a ${name} el strike de la semana del ${dm(lastOn.wk)}.\n\nMotivo (opcional):`, "");
    if (m === null) return;
    run(minus, [{ wk: lastOn.wk, value: strikeValueFor(lastOn, false, m.trim() || "quitado por el Jefe Tribal") }]);
  });
  const all = mk("button", "ghost small", "Quitar todos");
  all.type = "button";
  const counted = hist.filter((h) => h.counted);
  all.disabled = !counted.length;
  all.addEventListener("click", () => {
    const m = prompt(`Quitar los ${counted.length} strikes seguidos de ${name}.\n\nMotivo (opcional):`, "");
    if (m === null) return;
    run(all, counted.map((h) => ({ wk: h.wk, value: strikeValueFor(h, false, m.trim() || "quitado por el Jefe Tribal") })));
  });
  acts.append(plus, minus, all);
  box.appendChild(acts);
  const weeks = mk("div", "strike-ed-weeks");
  if (!hist.length) weeks.appendChild(mk("span", "muted emp-small", "Todavía no tiene semanas cerradas."));
  for (const h of hist.slice(0, 10)) {
    const b = mk("button", "strike-week" + (h.on ? " on" : "") + (h.forgiven ? " off" : "") + (h.counted ? " counted" : ""));
    b.type = "button";
    b.appendChild(mk("b", "", `${dm(h.wk)}–${dm(h.hasta)}`));
    b.appendChild(mk("span", "", h.on ? `⚠️ ${h.manual ? "✍️ " : ""}${h.motivo || "strike"}` : h.forgiven ? `Quitado${h.motivo ? `: ${h.motivo}` : ""}` : `✅ ${fmtMoney(h.gross)}`));
    b.title = h.on ? "Clic para quitar este strike" : "Clic para poner un strike esta semana";
    b.addEventListener("click", () => {
      if (h.on) {
        const m = prompt(`Quitar el strike de ${name} de la semana del ${dm(h.wk)}.\n\nMotivo (opcional):`, "");
        if (m === null) return;
        run(b, [{ wk: h.wk, value: strikeValueFor(h, false, m.trim() || "quitado por el Jefe Tribal") }]);
      } else {
        const m = prompt(`Poner un strike a ${name} en la semana del ${dm(h.wk)}.\n\nMotivo:`, "");
        if (m === null) return;
        if (!m.trim() && !(h.forgiven && h.auto)) return alert("Escribe el motivo del strike.");
        run(b, [{ wk: h.wk, value: strikeValueFor(h, true, m.trim()) }]);
      }
    });
    weeks.appendChild(b);
  }
  box.appendChild(weeks);
  return box;
}

// ===================== Gestión de empleados (por pestañas) =====================
// Listado · Nuevo empleado · Strikes · Rangos · Despedidos. El listado solo
// informa; al tocar a alguien se abre su ficha. Con la nube: editar, subir /
// bajar, despedir y los strikes son del Jefe Tribal; los Jefes lo ven todo,
// dan de alta (rangos bajos) y readmiten rangos bajos. Sin la nube (programa
// de escritorio): con la contraseña de empleados.
function setupEmployeesAdminModal({ onChanged }) {
  const modal = byId("employees-admin-modal");
  const status = byId("emp-admin-status");
  const passInput = byId("emp-admin-pass");
  const nameInput = byId("emp-new-name");
  const surInput = byId("emp-new-surname");
  const rankInput = byId("emp-new-rank");
  const discordInput = byId("emp-new-discord");
  const ibanInput = byId("emp-new-iban");
  const searchInput = byId("emp-search");

  let unlocked = false;
  let adminPass = "";
  let employees = [];
  let tab = "list";
  let filter = "all";
  let sortBy = "rank";
  let fichaId = null;
  let editing = false;

  const mk = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  };
  const btn = (text, cls = "ghost", title = "") => {
    const b = mk("button", cls, text);
    b.type = "button";
    if (title) b.title = title;
    return b;
  };
  const dm = (iso) => (iso ? `${String(iso).slice(8, 10)}/${String(iso).slice(5, 7)}` : "");
  const isHigh = (rank) => HIGH_RANKS.includes(rank);
  const hasAccess = () => (cloudOn() ? isJefe() : true);
  // Editar, subir/bajar y despedir: Jefe Tribal con la nube; sin ella, con la contraseña.
  const canEdit = () => (cloudOn() ? isJefe() && AUTH.tribal : unlocked);
  // Dar de alta y readmitir: cualquier Jefe con la nube; sin ella, con la contraseña.
  const canAdd = () => (cloudOn() ? isJefe() : unlocked);
  // Strikes: solo el Jefe Tribal y con la nube (necesitan las semanas cerradas).
  const boss = () => cloudOn() && isJefe() && AUTH.tribal;
  const isSelf = (e) => !!(cloudOn() && AUTH.discordId && getEmployeeDiscord(fullName(e)) === AUTH.discordId);
  const strikesOf = (e) => (cloudOn() ? strikesBefore(e.id, fullName(e)) : 0);
  const pctOf = (e) => (e.rank ? `${Math.round(pctForRank(e.rank) * 100)}\u00a0%` : "-");
  const cloudRow = (e) => (cloudOn() ? EMP_CLOUD.list.find((x) => String(x.id) === String(e.id)) : null);

  function setStatus(text, ok = false) {
    status.textContent = text;
    status.style.color = ok ? "var(--ok)" : "var(--muted)";
  }

  // Desplegable de rangos con su %. Con la nube, Gerente y Jefe Tribal solo para el Jefe Tribal.
  function fillRankSelect(select, current) {
    select.textContent = "";
    select.disabled = false;
    select.appendChild(new Option("Sin rango", ""));
    for (const r of RANKS.slice().reverse()) {
      const opt = new Option(`${r.label} (${pctText(r.pct)})`, r.label);
      if (cloudOn() && !AUTH.tribal && isHigh(r.label) && r.label !== current) {
        opt.disabled = true;
        opt.textContent += " · solo Jefe Tribal";
      }
      select.appendChild(opt);
    }
    if (current && !pctForRank(current)) select.appendChild(new Option(`${current} (sin %)`, current));
    select.value = current || "";
  }
  fillRankSelect(rankInput, "");

  function avatar(e, big = false) {
    return rankAvatar(e.rank, empInitials(e), `emp-av${big ? " big" : ""}`);
  }
  function badge(rank) {
    return mk("span", `pg-badge ${empRankCls(rank)}`, rank || "Sin rango");
  }
  function strikeChip(n) {
    return mk("span", "pg-strike emp-st" + (n >= STRIKE_MAX ? " max" : "") + (n ? "" : " zero"), `${n >= STRIKE_MAX ? "🚫 " : n ? "⚠️ " : ""}${n}/${STRIKE_MAX}`);
  }

  // ---------- Pestañas y modo ----------
  function setTab(t) {
    tab = t;
    modal.querySelectorAll(".emp-tab").forEach((b) => b.classList.toggle("is-on", b.dataset.empTab === t));
    modal.querySelectorAll(".emp-pane").forEach((p) => (p.hidden = p.dataset.empPane !== t));
    renderAll();
  }
  modal.querySelectorAll(".emp-tab").forEach((b) => b.addEventListener("click", () => setTab(b.dataset.empTab)));
  byId("emp-sort")?.addEventListener("click", (ev) => {
    const b = ev.target.closest("[data-sort]");
    if (!b) return;
    sortBy = b.dataset.sort;
    byId("emp-sort").querySelectorAll("[data-sort]").forEach((x) => x.classList.toggle("is-on", x === b));
    renderList();
  });

  const uploadBtn = byId("emp-cloud-upload");
  function applyMode() {
    const on = cloudOn();
    const lock = byId("emp-lock");
    if (lock) lock.hidden = on || unlocked;
    const note = byId("emp-cloud-note");
    if (note) {
      if (on) {
        const who = AUTH.name || (AUTH.profile ? fullName(AUTH.profile) : "");
        note.textContent = isJefe()
          ? `☁️ En línea · ${employees.length} ${employees.length === 1 ? "empleado" : "empleados"} · ${AUTH.tribal ? "Jefe Tribal" : "Gerente"}: ${who} ${AUTH.tribal ? "(los cambios se guardan al momento)" : "(solo lectura: das de alta y readmites rangos bajos; lo demás, el Jefe Tribal)"}`
          : "Solo los Gerentes y el Jefe Tribal ven la plantilla.";
      } else {
        note.textContent = unlocked ? "🔓 Desbloqueado en este equipo" : "🔒 Programa de escritorio: desbloquea con la contraseña para cambiar algo.";
      }
    }
    // "Subir empleados de este navegador" solo si queda alguno que no esta en la nube.
    if (uploadBtn) {
      const inCloud = new Set(EMP_CLOUD.list.map((x) => normalizeKeySimple(fullName(x))));
      uploadBtn.hidden = !(on && isJefe() && loadEmployeesLocal().some((x) => !inCloud.has(normalizeKeySimple(fullName(x)))));
    }
    byId("emp-tab-new").hidden = !canAdd() && cloudOn();
    byId("emp-tab-fired").hidden = !hasAccess();
  }

  // ---------- Listado ----------
  const FILTERS = [
    { k: "all", label: "En plantilla", test: () => true },
    { k: "strikes", label: "Con strikes", test: (e) => strikesOf(e) > 0, cls: "w", cloud: true },
    { k: "fire", label: `Para despido (${STRIKE_MAX}/${STRIKE_MAX})`, test: (e) => strikesOf(e) >= STRIKE_MAX, cls: "r", cloud: true },
    { k: "iban", label: "Sin IBAN", test: (e) => !getEmployeeIban(fullName(e)) && !isEmployeeNoPay(fullName(e)), cls: "w" },
    { k: "discord", label: "Sin Discord", test: (e) => !getEmployeeDiscord(fullName(e)), cls: "w" },
    { k: "nodates", label: "Sin fecha de ingreso", test: (e) => !empDatesOf(e).altaAt, cls: "w", dates: true },
    { k: "inact", label: "Sin facturar", test: (e) => (inactOf(e)?.level || 0) >= 1, cls: "w", cloud: true },
  ];

  // Filtro por fechas (ingreso o contratacion) entre "desde" y "hasta".
  const dateFilter = () => {
    const box = byId("emp-datefilter");
    if (!box || box.hidden) return null;
    const from = byId("emp-df-from").value;
    const to = byId("emp-df-to").value;
    if (!from && !to) return null;
    return { field: byId("emp-df-field").value, from, to };
  };

  function shownList() {
    const q = normalizeKeySimple(searchInput.value || "");
    const f = FILTERS.find((x) => x.k === filter) || FILTERS[0];
    let out = employees.filter((e) => f.test(e) && (!q || normalizeKeySimple(`${e.name} ${e.surname} ${e.rank || ""}`).includes(q)));
    const df = dateFilter();
    if (df) out = out.filter((e) => {
      const v = empDatesOf(e)[df.field] || "";
      return !!v && (!df.from || v >= df.from) && (!df.to || v <= df.to);
    });
    if (sortBy === "seniority") out = out.slice().sort((x, y) => (empDatesOf(x).altaAt || "9999").localeCompare(empDatesOf(y).altaAt || "9999") || byRankThenName(x, y));
    else if (sortBy === "az") out = out.slice().sort((x, y) => fullName(x).localeCompare(fullName(y), "es", { sensitivity: "base" }));
    else if (sortBy === "strikes") out = out.slice().sort((x, y) => strikesOf(y) - strikesOf(x) || byRankThenName(x, y));
    if (filter === "inact") out = out.slice().sort((x, y) => (inactOf(y)?.days || 0) - (inactOf(x)?.days || 0));
    return out;
  }
  byId("emp-date-toggle")?.addEventListener("click", () => {
    const box = byId("emp-datefilter");
    box.hidden = !box.hidden;
    byId("emp-date-toggle").classList.toggle("is-on", !box.hidden);
    renderList();
  });
  for (const id of ["emp-df-field", "emp-df-from", "emp-df-to"]) byId(id)?.addEventListener("change", () => renderList());
  byId("emp-df-clear")?.addEventListener("click", () => {
    byId("emp-df-from").value = "";
    byId("emp-df-to").value = "";
    renderList();
  });

  function renderKpis() {
    const box = byId("emp-kpis");
    box.textContent = "";
    for (const f of FILTERS) {
      if (f.cloud && !cloudOn()) continue;
      if (f.dates && !empHasDates()) continue;
      const n = employees.filter(f.test).length;
      const k = mk("button", `emp-kpi${f.cls && n ? " " + f.cls : ""}${filter === f.k ? " is-on" : ""}`);
      k.type = "button";
      k.append(mk("b", "", String(n)), mk("span", "", f.label));
      k.addEventListener("click", () => {
        filter = filter === f.k ? "all" : f.k;
        renderList();
      });
      box.appendChild(k);
    }
  }

  function renderCounts() {
    byId("emp-tab-n-list").textContent = String(employees.length);
    const sN = cloudOn() ? employees.filter((e) => strikesOf(e) > 0).length : 0;
    byId("emp-tab-n-strikes").textContent = sN ? String(sN) : "";
  }

  function renderList() {
    renderCounts();
    const listView = byId("emp-list-view");
    const fichaView = byId("emp-ficha-view");
    const inFicha = fichaId && employees.some((e) => String(e.id) === fichaId);
    listView.hidden = !!inFicha;
    fichaView.hidden = !inFicha;
    modal.classList.toggle("emp-in-ficha", !!inFicha);
    if (inFicha) return renderFicha();
    fichaId = null;
    renderKpis();
    const list = byId("emp-list");
    list.textContent = "";
    const shown = shownList();
    if (!shown.length) list.appendChild(mk("p", "muted emp-empty", employees.length ? "Nadie con ese filtro." : "Todavía no hay empleados. Añádelos en «Nuevo empleado»."));
    for (const e of shown) {
      const full = fullName(e);
      const row = mk("button", "emp-row");
      row.type = "button";
      const nm = mk("div", "emp-row-name");
      nm.append(mk("b", "", full), mk("small", "", `${e.rank || "Sin rango"} · ${pctOf(e)}`));
      const ed = empDatesOf(e);
      if (empHasDates() || ed.altaAt) {
        const parts = [];
        if (ed.altaAt) parts.push(`Ingreso ${empDate(ed.altaAt)}`);
        if (ed.contratadoAt && ed.contratadoAt !== ed.altaAt) parts.push(`Contratado ${empDate(ed.contratadoAt)}`);
        nm.appendChild(mk("small", "emp-dates" + (parts.length ? "" : " none"), parts.length ? `📅 ${parts.join(" · ")}` : "📅 Sin fechas"));
      }
      const flags = mk("div", "emp-row-flags");
      const disc = getEmployeeDiscord(full);
      const iban = getEmployeeIban(full);
      flags.append(
        mk("span", disc ? "emp-ok" : "emp-no", disc ? "✔ Discord" : "⚠ Sin Discord"),
        isEmployeeNoPay(full) ? mk("span", "emp-mut", "No cobra") : mk("span", iban ? "emp-ok" : "emp-no", iban ? "✔ IBAN" : "⚠ Sin IBAN")
      );
      row.append(avatar(e), nm, badge(e.rank));
      if (cloudOn() && !isOwnerRank(e.rank)) row.append(strikeChip(strikesOf(e)));
      else row.append(mk("span", ""));
      const ic = cloudOn() && isJefe() ? inactChip(e) : null;
      if (ic) flags.prepend(ic);
      row.append(flags, mk("span", "emp-go", "›"));
      row.addEventListener("click", () => openFicha(e.id));
      list.appendChild(row);
    }
  }

  // Al abrir una ficha (o pasar a otra) se empieza arriba del todo.
  const toTop = () => {
    const card = modal.querySelector(".emp-card");
    if (card) card.scrollTop = 0;
    const f = modal.querySelector(".emp-ficha");
    if (f) f.scrollTop = 0;
  };
  function openFicha(id) {
    fichaId = String(id);
    editing = false;
    if (tab !== "list") setTab("list");
    else renderList();
    toTop();
  }

  // ---------- Ficha ----------
  function box(title, cls = "") {
    const b = mk("div", "emp-box " + cls);
    b.appendChild(mk("h6", "", title));
    return b;
  }
  function kv(k, v, cls = "") {
    const r = mk("div", "emp-kv");
    r.append(mk("span", "", k), mk("b", cls, v));
    return r;
  }

  function renderFicha() {
    const view = byId("emp-ficha-view");
    const e = employees.find((x) => String(x.id) === fichaId);
    if (!e) return;
    const full = fullName(e);
    const n = strikesOf(e);
    view.textContent = "";

    // Barra: volver y anterior / siguiente (dentro del filtro actual)
    const nav = mk("div", "emp-nav");
    const back = btn("← Listado", "emp-back");
    back.addEventListener("click", () => {
      fichaId = null;
      editing = false;
      renderList();
      toTop();
    });
    nav.appendChild(back);
    const seq = shownList();
    const i = seq.findIndex((x) => String(x.id) === fichaId);
    const go = (d) => {
      const t = seq[i + d];
      if (!t) return;
      fichaId = String(t.id);
      editing = false;
      renderList();
      toTop();
    };
    const pn = mk("div", "emp-prevnext");
    const prev = btn(seq[i - 1] ? `‹ ${fullName(seq[i - 1])}` : "‹", "emp-back");
    prev.disabled = !seq[i - 1];
    prev.addEventListener("click", () => go(-1));
    const next = btn(seq[i + 1] ? `${fullName(seq[i + 1])} ›` : "›", "emp-back");
    next.disabled = !seq[i + 1];
    next.addEventListener("click", () => go(1));
    pn.append(prev, next);
    nav.appendChild(pn);
    view.appendChild(nav);

    const card = mk("div", "emp-ficha");
    // Cabecera
    const head = mk("div", "emp-fh");
    head.appendChild(avatar(e, true));
    const who = mk("div", "emp-fh-who");
    who.appendChild(mk("b", "", full));
    const line = mk("div", "emp-fh-line");
    line.appendChild(badge(e.rank));
    if (cloudOn() && n) line.appendChild(strikeChip(n));
    const icF = cloudOn() && isJefe() ? inactChip(e) : null;
    if (icF) line.appendChild(icF);
    const fd = empDatesOf(e);
    const since = fd.altaAt || (STRIKE_HIST.slice().reverse().find((w) => strikeRowIn(w, e.id, full))?.semana ?? "");
    if (since) line.appendChild(mk("span", "muted", `· en el Badulaque desde ${empDate(since)}${fd.altaAt ? ` (${empSeniority(since)})` : " (primera semana cerrada)"}`));
    who.appendChild(line);
    head.appendChild(who);
    if (canEdit()) {
      const acts = mk("div", "emp-fh-acts");
      const edit = btn(editing ? "Cancelar" : "✏️ Editar datos");
      edit.addEventListener("click", () => {
        editing = !editing;
        renderFicha();
      });
      acts.appendChild(edit);
      if (!isOwnerRank(e.rank) && !isSelf(e)) {
        const fire = btn("Despedir", "danger");
        fire.addEventListener("click", () => fireEmp(e));
        acts.appendChild(fire);
      }
      head.appendChild(acts);
    }
    card.appendChild(head);

    // Datos
    const datos = box("Datos", "emp-datos");
    const disc = getEmployeeDiscord(full);
    const iban = getEmployeeIban(full);
    const noPay = isEmployeeNoPay(full);
    if (editing) datos.appendChild(editForm(e));
    else {
      datos.append(
        kv("Discord", disc || "⚠ Falta", disc ? "" : "emp-no"),
        kv("IBAN", noPay ? "No cobra" : iban || "⚠ Falta", iban || noPay ? "" : "emp-no"),
        kv("Comisión", pctOf(e)),
        kv("Cobra nómina", noPay ? "No" : "Sí")
      );
      const fdd = empDatesOf(e);
      if (empHasDates() || fdd.altaAt) {
        datos.append(
          kv("Ingreso al Badulaque", fdd.altaAt ? `${empDate(fdd.altaAt)} · ${empSeniority(fdd.altaAt)}` : "⚠ Sin fecha", fdd.altaAt ? "" : "emp-no"),
          kv("Contratación", fdd.contratadoAt ? empDate(fdd.contratadoAt) : empHasDates() ? "⚠ Sin fecha" : "—", fdd.contratadoAt || !empHasDates() ? "" : "emp-no")
        );
      }
      const ix = cloudOn() && isJefe() ? inactOf(e) : null;
      if (ix) datos.append(kv("Última factura", ix.last ? `${dlogDate(new Date(ix.last).toISOString())} · hace ${ix.days} ${ix.days === 1 ? "día" : "días"}` : inactText(ix), ix.level >= 2 ? "emp-no" : ""));
    }
    card.appendChild(datos);

    // Rango
    const rango = box("Rango", "emp-rango");
    const li = EMP_LADDER.findIndex((x) => normalizeKeySimple(x) === normalizeKeySimple(e.rank || ""));
    if (isOwnerRank(e.rank)) rango.appendChild(mk("p", "muted emp-small", "Jefe Tribal: el rango del dueño (100 %). No entra en la escalera ni lleva strikes."));
    else if (li < 0) rango.appendChild(mk("p", "muted emp-small", e.rank ? `${e.rank}: rango fuera de la escalera (lo cambias en «Editar datos»).` : "Sin rango: ponle uno en «Editar datos»."));
    else {
      const ladder = mk("div", "emp-ladder");
      EMP_LADDER.forEach((r, k) => {
        if (k) ladder.appendChild(mk("span", "emp-ladder-sep", "›"));
        ladder.appendChild(mk("span", `pg-badge ${empRankCls(r)}${k === li ? " cur" : ""}`, r));
      });
      rango.appendChild(ladder);
    }
    const gross = PAGOS_WEEK_GROSS ? PAGOS_WEEK_GROSS.get(normalizeKeySimple(full)) || 0 : null;
    if (!isOwnerRank(e.rank)) {
      if (gross != null) rango.appendChild(kv("Esta semana", `${fmtMoney(gross)} facturados · mínimo ${fmtMoney(WEEK_MIN)} ${gross >= WEEK_MIN ? "✔" : "✖"}`, gross >= WEEK_MIN ? "emp-ok" : "emp-no"));
      else rango.appendChild(mk("p", "muted emp-small", "Procesa la semana en Pagos para ver lo que lleva facturado."));
    }
    if (canEdit() && li >= 0 && !isSelf(e)) {
      const ra = mk("div", "emp-acts");
      if (EMP_LADDER[li + 1]) {
        const up = btn(`⬆️ Subir a ${EMP_LADDER[li + 1]}`);
        up.addEventListener("click", () => moveRank(e, EMP_LADDER[li + 1], up));
        ra.appendChild(up);
      }
      if (li > 0) {
        const down = btn(`⬇️ Bajar a ${EMP_LADDER[li - 1]}`);
        down.addEventListener("click", () => moveRank(e, EMP_LADDER[li - 1], down));
        ra.appendChild(down);
      }
      rango.appendChild(ra);
    }
    card.appendChild(rango);

    // Facturacion de las ultimas semanas cerradas (+ la actual si Pagos la tiene)
    const fac = box("Facturación · últimas semanas", "emp-fac");
    const pts = [];
    for (const w of STRIKE_HIST) {
      const r = strikeRowIn(w, e.id, full);
      if (r) pts.push({ label: dm(w.semana), v: Number(r.gross || 0) });
      if (pts.length >= 6) break;
    }
    pts.reverse();
    if (gross != null) pts.push({ label: "Esta", v: gross, now: true });
    if (!pts.length) fac.appendChild(mk("p", "muted emp-small", cloudOn() ? "Todavía no hay semanas cerradas con esta persona." : "La gráfica necesita las semanas cerradas de la nube (en la web)."));
    else {
      const max = Math.max(WEEK_MIN * 1.25, ...pts.map((p) => p.v));
      const chart = mk("div", "emp-chart");
      const minLine = mk("div", "emp-chart-min");
      minLine.style.bottom = `${(WEEK_MIN / max) * 100}%`;
      minLine.title = `Mínimo ${fmtMoney(WEEK_MIN)}`;
      chart.appendChild(minLine);
      const labels = mk("div", "emp-chart-x");
      for (const p of pts) {
        const c = mk("div", "emp-col" + (p.v < WEEK_MIN ? " lo" : "") + (p.now ? " now" : ""));
        c.style.height = `${Math.max(2, (p.v / max) * 100)}%`;
        c.title = `${p.label}: ${fmtMoney(p.v)}`;
        c.appendChild(mk("em", "", p.v >= 1000 ? `${Math.round(p.v / 1000)}k` : String(p.v)));
        chart.appendChild(c);
        labels.appendChild(mk("span", "", p.label));
      }
      fac.append(chart, labels);
      const closed = pts.filter((p) => !p.now);
      if (closed.length) {
        const avg = Math.round(closed.reduce((a, p) => a + p.v, 0) / closed.length);
        const best = Math.max(...closed.map((p) => p.v));
        fac.appendChild(mk("p", "muted emp-small", `Media: ${fmtMoney(avg)} · Mejor semana: ${fmtMoney(best)} · Línea = mínimo ${fmtMoney(WEEK_MIN)}`));
      }
    }
    card.appendChild(fac);

    // Strikes
    if (!isOwnerRank(e.rank)) {
      const st = box(cloudOn() ? `Strikes · ${n >= STRIKE_MAX ? "🚫" : "⚠️"} ${n}/${STRIKE_MAX}` : "Strikes", "emp-strk");
      if (!cloudOn()) st.appendChild(mk("p", "muted emp-small", "Los strikes semana a semana necesitan la nube (en la web)."));
      else if (boss()) st.appendChild(buildStrikeEditor(e, () => renderAll()));
      else {
        const hist = strikeHistoryOf(e.id, full);
        const weeks = mk("div", "strike-ed-weeks");
        if (!hist.length) weeks.appendChild(mk("span", "muted emp-small", "Sin semanas cerradas."));
        for (const h of hist.slice(0, 6)) {
          const w = mk("span", "strike-week ro" + (h.on ? " on" : "") + (h.forgiven ? " off" : "") + (h.counted ? " counted" : ""));
          w.append(mk("b", "", dm(h.wk)), mk("span", "", h.on ? `⚠️ ${h.motivo || "strike"}` : h.forgiven ? "Quitado" : `✅ ${fmtMoney(h.gross)}`));
          weeks.appendChild(w);
        }
        st.appendChild(weeks);
      }
      card.appendChild(st);
    }

    // Historial
    const hb = box("Historial", "emp-hist");
    const tl = mk("div", "emp-tl");
    tl.appendChild(mk("p", "muted emp-small", "Cargando…"));
    hb.appendChild(tl);
    card.appendChild(hb);
    view.appendChild(card);
    loadHistory(e, tl);
  }

  async function loadHistory(e, tl) {
    const id = String(e.id);
    let rows = [];
    let err = "";
    if (!cloudOn()) err = "El historial necesita la nube (se ve en la web con la sesión de Discord).";
    else {
      try {
        rows = (await empHistory(id)) || [];
      } catch (x) {
        err = x.code === "PGRST205" || x.code === "42P01" || x.status === 404
          ? "Falta pegar en Supabase el SQL 7_historial_empleados.sql para guardar el historial."
          : `No se pudo cargar: ${x.message || x}`;
      }
    }
    if (fichaId !== id) return; // se cambio de ficha mientras cargaba
    tl.textContent = "";
    if (err) return tl.appendChild(mk("p", "muted emp-small", err));
    if (!rows.length) return tl.appendChild(mk("p", "muted emp-small", "Sin movimientos todavía. Desde ahora se apuntan aquí los ascensos, descensos, strikes, cambios de datos, despidos y readmisiones."));
    for (const r of rows) {
      const it = mk("div", "emp-tl-row");
      const d = r.at ? new Date(r.at) : null;
      it.append(mk("em", "", d ? d.toLocaleDateString("es-ES", { day: "2-digit", month: "2-digit", year: "2-digit" }) : ""), mk("span", "", r.texto || ""));
      if (r.por) it.appendChild(mk("small", "muted", `· ${r.por}`));
      tl.appendChild(it);
    }
  }

  function editForm(e) {
    const full = fullName(e);
    const f = mk("div", "emp-edit");
    const field = (label, input) => {
      const l = mk("label", "");
      l.append(mk("span", "", label), input);
      return l;
    };
    const inp = (v, ph, extra = {}) => {
      const x = mk("input", "text-input");
      x.type = "text";
      x.value = v || "";
      x.placeholder = ph;
      Object.assign(x, extra);
      return x;
    };
    const nIn = inp(e.name, "Nombre");
    const sIn = inp(e.surname, "Apellido");
    const rSel = mk("select", "text-input");
    fillRankSelect(rSel, e.rank || "");
    const dIn = inp(getEmployeeDiscord(full), "ID de Discord", { inputMode: "numeric" });
    const iIn = inp(getEmployeeIban(full), "J000000", { maxLength: 9 });
    const np = mk("input");
    np.type = "checkbox";
    np.checked = isEmployeeNoPay(full);
    const npL = mk("label", "emp-check");
    npL.append(np, mk("span", "", "No cobra la nómina"));
    const grid = mk("div", "emp-edit-grid");
    grid.append(field("Nombre", nIn), field("Apellido", sIn), field("Rango", rSel), field("IBAN", iIn), field("ID de Discord", dIn));
    const dNow = empDatesOf(e);
    const aIn = inp(dNow.altaAt, "");
    aIn.type = "date";
    aIn.max = empToday();
    aIn.classList.add("emp-date");
    const cIn = inp(dNow.contratadoAt, "");
    cIn.type = "date";
    cIn.max = empToday();
    cIn.classList.add("emp-date");
    const dates = mk("div", "emp-edit-grid emp-edit-dates");
    if (empHasDates()) dates.append(field("📅 Ingreso al Badulaque", aIn), field("📝 Contratación", cIn));
    else dates.appendChild(mk("p", "muted emp-small", "Para guardar las fechas de ingreso y contratación, pega en Supabase el SQL 9_fechas_empleados.sql."));
    const save = btn("Guardar", "primary");
    const cancel = btn("Cancelar");
    cancel.addEventListener("click", () => {
      editing = false;
      renderFicha();
    });
    save.addEventListener("click", async () => {
      const name = nIn.value.trim().replace(/\s+/g, " ");
      const surname = sIn.value.trim().replace(/\s+/g, " ");
      if (!name || !surname) return alert("Pon Nombre y Apellido.");
      const discord = parseDiscordId(dIn.value);
      if (discord === null) return alert("Eso no parece un ID de Discord. Es un número de 17 a 20 cifras (clic derecho sobre la persona → Copiar ID de usuario).");
      const ib = parseIban(iIn.value);
      if (ib === null) return alert("El IBAN no es válido. Es una letra y 6 números, como J739745.");
      if (empHasDates() && aIn.value && cIn.value && cIn.value < aIn.value) return alert("La fecha de contratación no puede ser anterior a la de ingreso al Badulaque.");
      const newFull = `${name} ${surname}`;
      if (newFull !== full) {
        const clash = [...employees, ...listFired()].find((x) => String(x.id) !== String(e.id) && normalizeKeySimple(fullName(x)) === normalizeKeySimple(newFull));
        if (clash) return alert(`Ya hay alguien llamado ${fullName(clash)}${clash.firedAt ? " (en Despedidos)" : ""}.`);
        if (!confirm(`¿Cambiar el nombre de ${full} a ${newFull}?\n\nConserva su rango, Discord, IBAN y strikes. Las ventas nuevas deben salir en Discord con el nombre nuevo.`)) return;
      }
      if (isSelf(e) && rSel.value !== (e.rank || "") && !confirm("Vas a cambiar tu propio rango. Si dejas de ser Jefe Tribal perderás estos permisos. ¿Seguir?")) return;
      save.disabled = true;
      try {
        if (cloudOn()) {
          const patch = { name, surname, rank: rSel.value, discord, iban: ib, no_pay: np.checked };
          // Las fechas solo se mandan con el SQL 9 (sin el, la columna no existe).
          if (EMP_CLOUD.hasDates) {
            patch.alta_at = aIn.value || null;
            patch.contratado_at = cIn.value || null;
          }
          await empCloudPatch(e.id, patch);
        } else {
          await updateEmployee(e.id, { name, surname, rank: rSel.value }, adminPass);
          if (newFull !== full) {
            setEmployeeDiscord(full, "");
            setEmployeeIban(full, "");
            setEmployeeNoPay(full, false);
          }
          setEmployeeDiscord(newFull, discord);
          setEmployeeIban(newFull, ib);
          setEmployeeNoPay(newFull, np.checked);
          if (newFull !== full) setEmployeeDatesLocal(full, null);
          setEmployeeDatesLocal(newFull, { a: aIn.value, c: cIn.value });
        }
        editing = false;
        setStatus(`✔ Datos de ${newFull} guardados.`, true);
        await refresh();
        // Sin la nube el programa puede cambiar el id al guardar: se busca por nombre.
        if (!employees.some((x) => String(x.id) === fichaId)) {
          const again = employees.find((x) => normalizeKeySimple(fullName(x)) === normalizeKeySimple(newFull));
          if (again) {
            fichaId = String(again.id);
            renderList();
          }
        }
        await (onChanged?.());
      } catch (err) {
        save.disabled = false;
        alert(`No se pudo guardar: ${err.message || err}`);
      }
    });
    const acts = mk("div", "emp-acts");
    acts.append(save, cancel);
    f.append(grid, dates, npL, acts);
    return f;
  }

  async function moveRank(e, to, b) {
    const up = rankOrder(to) > rankOrder(e.rank);
    if (!confirm(`¿${up ? "Subir" : "Bajar"} a ${fullName(e)} de ${e.rank} a ${to}?`)) return;
    b.disabled = true;
    try {
      await updateEmployee(e.id, { rank: to }, adminPass);
      setStatus(`✔ ${fullName(e)} ahora es ${to}.`, true);
      dc.key = "";
      const name = fullName(e);
      await refresh();
      if (!employees.some((x) => String(x.id) === fichaId)) {
        const again = employees.find((x) => normalizeKeySimple(fullName(x)) === normalizeKeySimple(name));
        if (again) {
          fichaId = String(again.id);
          renderList();
        }
      }
      await (onChanged?.());
      if (cloudOn() && isJefe()) status.append(" ", dcGoBtn());
    } catch (err) {
      b.disabled = false;
      alert(`No se pudo cambiar el rango: ${err.message || err}`);
    }
  }

  async function fireEmp(e) {
    const label = fullName(e);
    if (!canEdit()) return alert(cloudOn() ? "Solo el Jefe Tribal puede despedir." : "Primero desbloquea con la contraseña.");
    if (isOwnerRank(e.rank) || isSelf(e)) return alert("No puedes despedirte a ti mismo ni al Jefe Tribal: perderías el acceso a la página.");
    const n = strikesOf(e);
    const suggest = n >= STRIKE_MAX ? "strikes" : (cloudOn() && (inactOf(e)?.level || 0) >= 3) ? "inactividad" : "";
    const extra = n ? `${n >= STRIKE_MAX ? "🚫" : "⚠️"} Lleva ${n}/${STRIKE_MAX} strikes seguidos.` : "";
    const reason = await askBaja(`${label}${e.rank ? ` (${e.rank})` : ""}`, suggest, extra);
    if (reason === null) return;
    try {
      await fireEmployee(e, reason.trim(), adminPass);
      fichaId = null;
      setStatus(`🚪 ${label} pasa a Despedidos.`, true);
      dc.key = "";
      await refresh();
      await (onChanged?.());
      if (cloudOn() && isJefe()) status.append(" ", dcGoBtn());
    } catch (err) {
      alert(`No se pudo despedir: ${err.message || err}`);
    }
  }

  // ---------- Pestaña Strikes ----------
  function renderStrikesTab() {
    const root = byId("emp-strikes");
    root.textContent = "";
    if (!cloudOn()) return root.appendChild(mk("p", "muted emp-empty", "Los strikes de semanas cerradas necesitan la nube: se ven en la web con la sesión de Discord. Los de la semana en curso salen en Pagos."));
    if (!isJefe()) return root.appendChild(mk("p", "muted emp-empty", "Solo los Gerentes y el Jefe Tribal ven los strikes."));
    const rows = employees.map((e) => ({ e, n: strikesOf(e), hist: strikeHistoryOf(e.id, fullName(e)) })).filter((x) => x.n > 0);
    const run = async (b, fn) => {
      b.disabled = true;
      try {
        await fn();
        renderAll();
      } catch (err) {
        b.disabled = false;
        alert(`No se pudo guardar: ${err.message || err}`);
      }
    };
    const plus = (e, b, motivo) => {
      const w = strikePlusWeek(e);
      if (!w) return alert("No hay semanas cerradas donde ponerle el strike.");
      const m = motivo ?? prompt(`Poner un strike a ${fullName(e)} (semana del ${dm(w.wk)}).\n\nMotivo:`, "");
      if (m === null) return;
      if (!String(m).trim()) return alert("Escribe el motivo del strike.");
      run(b, () => saveStrikeAdjMany([{ wk: w.wk, value: strikeValueFor(w, true, String(m).trim()) }], e.id, fullName(e)));
    };
    const minus = (e, b) => {
      const w = strikeMinusWeek(e);
      if (!w) return;
      const m = prompt(`Quitar a ${fullName(e)} el strike de la semana del ${dm(w.wk)}.\n\nMotivo (opcional):`, "");
      if (m === null) return;
      run(b, () => saveStrikeAdjMany([{ wk: w.wk, value: strikeValueFor(w, false, m.trim() || "quitado por el Jefe Tribal") }], e.id, fullName(e)));
    };
    const group = (title, items) => {
      root.appendChild(mk("div", "emp-grp", title));
      for (const { e, n, hist } of items) {
        const r = mk("div", "emp-srow");
        const nm = mk("button", "emp-srow-name");
        nm.type = "button";
        nm.title = "Abrir ficha";
        nm.append(mk("b", "", fullName(e)), mk("small", "", e.rank || "Sin rango"));
        nm.addEventListener("click", () => openFicha(e.id));
        const dots = mk("div", "emp-dots");
        for (const h of hist.slice(0, 4)) dots.appendChild(mk("i", h.counted || h.on ? "s" : h.forgiven ? "f" : "", ""));
        dots.title = "Últimas semanas cerradas (rojo = strike, punteado = quitado)";
        const why = mk("span", "muted emp-small emp-why", hist.filter((h) => h.counted).map((h) => `${dm(h.wk)} ${h.motivo || "strike"}`).join(" · "));
        r.append(avatar(e), nm, strikeChip(n), dots, why);
        const acts = mk("div", "emp-acts");
        if (boss()) {
          if (n < STRIKE_MAX) {
            const p = btn("＋1", "ghost", "Poner un strike");
            p.addEventListener("click", () => plus(e, p));
            acts.appendChild(p);
          }
          const m = btn("−1", "ghost", "Quitar el último strike");
          m.addEventListener("click", () => minus(e, m));
          acts.appendChild(m);
          if (n >= STRIKE_MAX && !isOwnerRank(e.rank) && !isSelf(e)) {
            const f = btn("Despedir", "danger");
            f.addEventListener("click", () => fireEmp(e));
            acts.appendChild(f);
          }
        }
        r.appendChild(acts);
        root.appendChild(r);
      }
    };
    const fire = rows.filter((x) => x.n >= STRIKE_MAX).sort((a, b) => byRankThenName(a.e, b.e));
    const rest = rows.filter((x) => x.n < STRIKE_MAX).sort((a, b) => b.n - a.n || byRankThenName(a.e, b.e));
    if (!rows.length) root.appendChild(mk("p", "muted emp-empty", "👏 Nadie tiene strikes ahora mismo."));
    if (fire.length) group("🚫 Para despido", fire);
    if (rest.length) group("⚠️ Con strikes", rest);
    if (boss()) {
      root.appendChild(mk("div", "emp-grp", "➕ Poner strike"));
      const add = mk("div", "emp-sadd");
      const sel = mk("select", "text-input");
      sel.appendChild(new Option("Elige empleado…", ""));
      for (const e of employees) if (!isEmployeeNoPay(fullName(e)) && !isOwnerRank(e.rank) && strikesOf(e) < STRIKE_MAX) sel.appendChild(new Option(`${fullName(e)}${e.rank ? ` (${e.rank})` : ""}`, String(e.id)));
      const why = mk("input", "text-input");
      why.placeholder = "Motivo (p. ej. mal comportamiento)";
      why.maxLength = 120;
      const go = btn("➕ Poner strike", "");
      go.addEventListener("click", () => {
        const e = employees.find((x) => String(x.id) === sel.value);
        if (!e) return alert("Elige a quién ponerle el strike.");
        plus(e, go, why.value);
      });
      add.append(sel, why, go);
      root.appendChild(add);
    }
    root.appendChild(mk("p", "muted emp-note", "Aquí salen los strikes de las semanas ya cerradas. Los de la semana en curso se ven en Pagos, porque dependen de lo que se venda hasta el sábado. Un strike quitado no suma ni corta la racha."));
  }

  // ---------- Pestaña Rangos ----------
  // ---------- 📣 Para Discord: movimientos de personal de una semana ----------
  // Separados en pantalla, pero en UN solo mensaje (un copiar, un pegar).
  const dc = { sun: null, key: "", items: [], desc: [], bajas: [], off: new Set(), frase: ascFraseAzar(), cierre: pickOne(DESC_CIERRES), cierreB: pickOne(BAJAS_CIERRES), err: "", star: [], starKey: "", starFrase: "", starAuto: false };
  // ⭐ Empleado de la semana: el del bono en Pagos (semana cerrada) o el que elijas.
  const dcIso = (d) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
  const dcStarPool = () => EMP_CLOUD.list.filter((e) => !e.firedAt && !isOwnerRank(e.rank)).sort(byRankThenName);
  function dcStarInit() {
    const wk = STRIKE_HIST.find((w) => String(w.semana) === dcIso(dc.sun));
    const winners = (wk?.datos?.rows || []).filter((r) => Number(r.bonus) > 0);
    const pool = dcStarPool();
    dc.star = winners.map((r) => pool.find((e) => (r.id != null && String(e.id) === String(r.id)) || normalizeKeySimple(fullName(e)) === normalizeKeySimple(r.name))).filter(Boolean).map((e) => String(e.id));
    dc.starAuto = !!dc.star.length;
    dc.starClosed = !!wk;
    dc.starFrase = pickOne(dc.star.length > 1 ? STAR_FRASES_VARIOS : STAR_FRASES);
  }
  const dcStar = () => {
    const pool = dcStarPool();
    const people = dc.star.map((id) => pool.find((e) => String(e.id) === id)).filter(Boolean).map((e) => ({ name: fullName(e), discord: e.discord }));
    if (!people.length) return null;
    const many = people.length > 1;
    const okFrase = (many ? STAR_FRASES_VARIOS : STAR_FRASES).includes(dc.starFrase);
    if (!okFrase) dc.starFrase = pickOne(many ? STAR_FRASES_VARIOS : STAR_FRASES);
    return { people, frase: dc.starFrase };
  };
  function dcGoBtn() {
    const go = btn("📣 Mensaje para Discord", "ghost emp-dc-go", "Abrir el mensaje de la semana");
    go.addEventListener("click", () => {
      dc.sun = ascDefaultWeek();
      dc.key = "";
      fichaId = null;
      setTab("discord");
    });
    return go;
  }
  const dcOn = (it, pre) => !dc.off.has(`${pre}:${it.id}`);
  const dcText = () => {
    const up = dc.items.filter((it) => dcOn(it, "u"));
    const desc = dc.desc.filter((it) => dcOn(it, "d"));
    const bajas = dc.bajas.filter((it) => dcOn(it, "b"));
    return movDiscordText(up, desc, bajas, dc.sun, up.length ? dc.frase : desc.length ? dc.cierre : dc.cierreB, dcStar());
  };
  function renderDiscordPreview() {
    const t = dcText();
    byId("emp-dc-prev").textContent = t || "No hay nada marcado para esa semana.";
    byId("emp-dc-copy").disabled = !t;
  }
  const dcFrases = (keepUp = false) => {
    if (!keepUp) {
      const mot = ascMotivosAzar(dc.items.length);
      dc.items.forEach((it, i) => (it.motivo = mot[i]));
    }
    for (const it of dc.desc) it.frase = pickOne((DESC_MOTIVOS.find((m) => m.k === it.motivo) || DESC_MOTIVOS[0]).f, it.frase);
    const used = new Set();
    for (const it of dc.bajas) {
      const pool = BAJA_FRASES[it.tipo] || BAJA_FRASES.otro;
      const free = pool.filter((f) => !used.has(f) && f !== it.frase);
      it.frase = pickOne(free.length ? free : pool);
      used.add(it.frase);
    }
  };
  function dcCheck(pre, it) {
    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.checked = dcOn(it, pre);
    cb.addEventListener("change", () => {
      if (cb.checked) dc.off.delete(`${pre}:${it.id}`);
      else dc.off.add(`${pre}:${it.id}`);
      renderDiscordPreview();
    });
    return cb;
  }
  const dcBadge = (r) => mk("span", `pg-badge ${empRankCls(r)}`, r || "sin rango");
  function dcPath(from, to) {
    const path = mk("span", "emp-dc-path");
    path.append(dcBadge(from), mk("span", "emp-dc-arrow", "➜"), dcBadge(to));
    return path;
  }
  function dcSelect(opts, val, onChange) {
    const sel = document.createElement("select");
    sel.className = "text-input emp-dc-sel";
    for (const [v, t] of opts) sel.append(new Option(t, v));
    sel.value = val;
    sel.addEventListener("change", () => onChange(sel.value));
    return sel;
  }
  const noDiscord = () => mk("span", "muted emp-small", "· sin Discord: saldrá solo el nombre");
  async function renderDiscordTab(force = false) {
    const list = byId("emp-dc-list");
    if (!list) return;
    if (!dc.sun) dc.sun = ascDefaultWeek();
    const max = ascDefaultWeek();
    if (dc.sun > max) dc.sun = max;
    byId("emp-dc-week").textContent = `Semana del ${ascDM(dc.sun)} al ${ascDM(ascDay(dc.sun, 6))}`;
    byId("emp-dc-next").disabled = +dc.sun >= +max;
    const info = byId("emp-dc-info");
    const key = String(+dc.sun);
    if (dc.key !== key || force) {
      dc.key = key;
      dc.err = "";
      list.textContent = "";
      list.appendChild(mk("p", "muted emp-empty", "Buscando en el historial…"));
      try {
        const people = EMP_CLOUD.list;
        const [items, r] = await Promise.all([ascensosSemana(dc.sun, people), descensosSemana(dc.sun, people)]);
        if (dc.key !== key) return;
        dc.items = items;
        dc.desc = r.desc;
        dc.bajas = r.bajas;
        dcFrases();
        await loadStrikeHist().catch(() => {});
        if (dc.key !== key) return;
        dcStarInit();
      } catch (err) {
        dc.items = [];
        dc.desc = [];
        dc.bajas = [];
        dc.err = err.code === "PGRST205" || err.code === "42P01" || err.status === 404 ? "falta pegar en Supabase el SQL 7_historial_empleados.sql." : err.message || String(err);
      }
      dc.off.clear();
    }
    list.textContent = "";
    if (dc.err) {
      info.textContent = "";
      list.appendChild(mk("p", "muted emp-empty", `No se pudo leer el historial: ${dc.err}`));
      return renderDiscordPreview();
    }
    const nu = dc.items.length, nd = dc.desc.length, nb = dc.bajas.length;
    const pl = (n, a, b) => `${n} ${n === 1 ? a : b}`;
    info.textContent = `${pl(nu, "ascenso", "ascensos")}, ${pl(nd, "descenso", "descensos")} y ${pl(nb, "baja", "bajas")} · entre el ${ascDM(ascDay(dc.sun, 6))} y el ${ascDM(ascDay(dc.sun, 13))}`;
    if (!nu && !nd && !nb) list.appendChild(mk("p", "muted emp-empty", "No hay ascensos, descensos ni bajas para esta semana (se apuntan solos al subir o bajar a alguien desde su ficha y al despedir). Puedes mandar solo el reconocimiento al empleado de la semana."));
    if (nu) list.appendChild(mk("div", "emp-dc-group", "📈 Ascensos"));
    for (const it of dc.items) {
      const row = mk("label", "emp-dc-row");
      row.append(dcCheck("u", it), mk("span", "emp-dc-who", it.name), dcPath(it.from, it.to), mk("span", "muted emp-small emp-dc-mot", it.motivo));
      if (!it.discord) row.appendChild(noDiscord());
      list.appendChild(row);
    }
    if (nd) list.appendChild(mk("div", "emp-dc-group", "📉 Descensos"));
    for (const it of dc.desc) {
      const row = mk("div", "emp-dc-row");
      const sel = dcSelect(DESC_MOTIVOS.map((m) => [m.k, m.label]), it.motivo, (v) => {
        it.motivo = v;
        it.frase = pickOne(DESC_MOTIVOS.find((m) => m.k === v).f);
        renderDiscordTab();
      });
      row.append(dcCheck("d", it), mk("span", "emp-dc-who", it.name), dcPath(it.from, it.to), sel, mk("span", "muted emp-small emp-dc-mot", it.frase));
      if (!it.discord) row.appendChild(noDiscord());
      list.appendChild(row);
    }
    if (nb) list.appendChild(mk("div", "emp-dc-group", "🚪 Bajas del Badulaque"));
    for (const it of dc.bajas) {
      const row = mk("div", "emp-dc-row");
      const sel = dcSelect(BAJA_TIPOS.map((t) => [t.k, `${t.e} ${t.label}`]), it.tipo, (v) => {
        it.tipo = v;
        it.frase = pickOne(BAJA_FRASES[v] || BAJA_FRASES.otro);
        renderDiscordTab();
      });
      row.append(dcCheck("b", it), mk("span", "emp-dc-who", it.name), dcBadge(it.rank), sel);
      if (it.discord) {
        const ml = mk("label", "emp-dc-ment");
        const m = document.createElement("input");
        m.type = "checkbox";
        m.checked = it.mention !== false;
        m.title = "Si ya no está en el servidor de Discord, quítalo y saldrá su nombre";
        m.addEventListener("change", () => {
          it.mention = m.checked;
          renderDiscordPreview();
        });
        ml.append(m, " Mencionar");
        row.append(ml);
      } else row.appendChild(noDiscord());
      row.append(mk("span", "muted emp-small emp-dc-mot", it.frase + (it.nota ? `  · Nota interna: ${it.nota}` : "")));
      list.appendChild(row);
    }
    // ⭐ Empleado de la semana
    list.appendChild(mk("div", "emp-dc-group", "⭐ Empleado de la semana"));
    const pool = dcStarPool();
    const srow = mk("div", "emp-dc-row");
    const sel = dcSelect([["", "— Nadie (no se felicita) —"], ...pool.map((e) => [String(e.id), fullName(e)])], dc.star[0] || "", (v) => {
      dc.star = v ? [v] : [];
      dc.starAuto = false;
      renderDiscordTab();
    });
    srow.append(mk("span", "emp-dc-star", "⭐"), sel);
    if (dc.star.length > 1) srow.append(mk("span", "muted emp-small", `+ ${dc.star.slice(1).map((id) => fullName(pool.find((e) => String(e.id) === id) || {})).join(", ")} (empate en Pagos)`));
    const st = dcStar();
    const who = st?.people.find((x) => !x.discord);
    srow.append(mk("span", "muted emp-small emp-dc-mot", dc.starAuto && dc.star.length ? "El del bono de esta semana en Pagos" : dc.starClosed ? "Elegido a mano" : "Semana sin cerrar en Pagos: elígelo a mano"));
    if (who) srow.appendChild(noDiscord());
    if (st) srow.append(mk("span", "muted emp-small emp-dc-mot", st.frase));
    list.appendChild(srow);
    renderDiscordPreview();
  }
  const dcMove = (n) => {
    dc.sun = ascDay(dc.sun || ascDefaultWeek(), 7 * n);
    renderDiscordTab();
  };
  byId("emp-dc-prev-w")?.addEventListener("click", () => dcMove(-1));
  byId("emp-dc-next")?.addEventListener("click", () => dcMove(1));
  byId("emp-dc-frase")?.addEventListener("click", () => {
    dc.frase = ascFraseAzar(dc.frase);
    dc.cierre = pickOne(DESC_CIERRES, dc.cierre);
    dc.cierreB = pickOne(BAJAS_CIERRES, dc.cierreB);
    dc.starFrase = pickOne(dc.star.length > 1 ? STAR_FRASES_VARIOS : STAR_FRASES, dc.starFrase);
    dcFrases();
    renderDiscordTab();
  });
  byId("emp-dc-copy")?.addEventListener("click", async () => {
    const t = dcText();
    if (!t) return;
    const ok = await copyText(t);
    if (!ok) openCopyFallback(t);
    else setStatus("✔ Mensaje copiado. Pégalo en el canal de Discord.", true);
  });

  function renderRanksTab() {
    const t = byId("emp-rank-table");
    t.textContent = "";
    t.appendChild(mk("h4", "emp-rk-title", "Rangos y plantilla"));
    for (const r of RANKS.slice().reverse()) {
      const people = employees.filter((e) => normalizeKeySimple(e.rank || "") === normalizeKeySimple(r.label));
      const row = mk("div", "emp-rk");
      const lab = mk("div", "emp-rk-lab");
      lab.append(rankAvatar(r.label, "?", "emp-av sm"), mk("span", `pg-badge ${empRankCls(r.label)}`, r.label));
      row.append(lab, mk("span", "emp-rk-pct", `${Math.round(r.pct * 100)} %`), mk("span", "emp-rk-n", people.length ? people.map(fullName).join(", ") : "—"));
      t.appendChild(row);
    }
    t.appendChild(mk("p", "muted emp-note", `Mínimo semanal para no llevar strike: ${fmtMoney(WEEK_MIN)} (facturas pagadas + rascas). Bono del empleado de la semana: ${fmtMoney(WEEK_BONUS)}. ${STRIKE_MAX} strikes seguidos = despido. El Jefe Tribal no lleva strikes ni compite por el bono. Los ascensos no son automáticos: se dan desde la ficha.`));
    if (!(cloudOn() && isJefe())) return;
    // 💤 Aviso de inactividad: dias sin facturar para cada color.
    const ib = mk("div", "emp-inact-cfg");
    ib.appendChild(mk("h4", "", "💤 Aviso de inactividad"));
    ib.appendChild(mk("p", "muted emp-small", `Días sin facturar (según las facturas del Discord del Badulaque, últimos ${INACT_VENTANA} días) para que salga el aviso en el listado y en la ficha.`));
    const D = INACT.dias;
    const grid = mk("div", "emp-inact-grid");
    const inputs = {};
    for (const [k, lbl, cls] of [["aviso", "Aviso", "l1"], ["alerta", "Alerta", "l2"], ["grave", "Grave", "l3"]]) {
      const l = mk("label", "emp-inact-f");
      l.appendChild(mk("span", `emp-inact ${cls}`, `💤 ${lbl}`));
      const i = mk("input", "text-input");
      i.type = "number";
      i.min = "1";
      i.max = String(INACT_VENTANA);
      i.value = String(D[k]);
      i.disabled = !AUTH.tribal;
      inputs[k] = i;
      l.append(i, mk("span", "muted emp-small", "días"));
      grid.appendChild(l);
    }
    ib.appendChild(grid);
    if (AUTH.tribal) {
      const save = btn("Guardar días", "");
      save.addEventListener("click", async () => {
        save.disabled = true;
        try {
          await inactSaveDias({ aviso: +inputs.aviso.value, alerta: +inputs.alerta.value, grave: +inputs.grave.value });
          setStatus("✔ Días del aviso de inactividad guardados.", true);
          renderAll();
        } catch (err) {
          alert(err.message || err);
        } finally {
          save.disabled = false;
        }
      });
      ib.appendChild(save);
    } else ib.appendChild(mk("p", "muted emp-small", "Solo el Jefe Tribal puede cambiar los días."));
    t.appendChild(ib);
  }

  // ---------- Pestaña Despedidos ----------
  function renderFired() {
    const list = byId("emp-fired-list");
    const fired = listFired();
    byId("emp-fired-n").textContent = fired.length ? String(fired.length) : "";
    if (tab !== "fired") return;
    list.textContent = "";
    if (!fired.length) list.appendChild(mk("p", "muted emp-empty", "No hay nadie en el registro de despedidos."));
    for (const f of fired) {
      const row = mk("div", "emp-fired-row");
      const when = f.firedAt ? new Date(f.firedAt).toLocaleString("es-ES", { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" }) : "";
      const info = mk("div", "emp-fired-info");
      const head = mk("div", "");
      head.append(mk("b", "", fullName(f)));
      if (f.rank) head.append(` · ${f.rank}`);
      info.append(head, mk("div", "muted", `🚪 ${when}${f.firedBy ? ` · por ${f.firedBy}` : ""}`));
      if (f.firedReason) info.append(mk("div", "emp-fired-why", `Motivo: ${f.firedReason}`));
      const acts = mk("div", "emp-acts");
      const back = btn("Readmitir");
      if (cloudOn() && isHigh(f.rank) && !AUTH.tribal) {
        back.disabled = true;
        back.title = "Solo el Jefe Tribal puede readmitir a un Gerente";
      }
      back.addEventListener("click", () => readmit(f));
      acts.append(back);
      if (cloudOn() ? AUTH.tribal : unlocked) {
        const del = btn("Borrar registro", "danger", "Borra a esta persona por completo (solo para errores o duplicados)");
        del.addEventListener("click", async () => {
          if (!confirm(`¿Borrar por completo a ${fullName(f)} del registro? No se puede deshacer.`)) return;
          try {
            if (cloudOn()) await empCloudDelete(f.id);
            else saveFiredLocal(loadFiredLocal().filter((x) => x.id !== f.id));
            await refresh();
          } catch (err) {
            alert(String(err?.message || err || "Error"));
          }
        });
        acts.append(del);
      }
      row.append(rankAvatar(f.rank, empInitials(f), "emp-av"), info, acts);
      list.appendChild(row);
    }
  }

  async function readmit(f) {
    if (!canAdd()) return alert(cloudOn() ? "Solo los Gerentes y el Jefe Tribal pueden readmitir." : "Primero desbloquea con la contraseña.");
    const full = fullName(f);
    if (employees.some((e) => normalizeKeySimple(fullName(e)) === normalizeKeySimple(full))) return alert(`${full} ya está en la plantilla.`);
    if (cloudOn() && isHigh(f.rank) && !AUTH.tribal) return alert("Solo el Jefe Tribal puede readmitir a un Gerente.");
    if (!confirm(`¿Readmitir a ${full}${f.rank ? ` como ${f.rank}` : ""}? Sale de Despedidos y vuelve a la plantilla con su Discord e IBAN.`)) return;
    try {
      await readmitEmployee(f, adminPass);
      setStatus(`↩️ ${full} vuelve a la plantilla.`, true);
      await refresh();
      await (onChanged?.());
    } catch (err) {
      alert(String(err?.message || err || "Error"));
    }
  }

  function renderAll() {
    applyMode();
    const nd = byId("emp-new-dates");
    if (nd) {
      nd.hidden = !empHasDates();
      for (const id of ["emp-new-alta", "emp-new-contrato"]) {
        const x = byId(id);
        if (x && !x.value) x.value = empToday();
        if (x) x.max = empToday();
      }
    }
    const dt = byId("emp-date-toggle");
    if (dt) dt.hidden = !empHasDates();
    const ds = modal.querySelector('[data-sort="seniority"]');
    if (ds) ds.hidden = !empHasDates();
    if (tab === "new" && byId("emp-tab-new").hidden) tab = "list";
    if (tab === "list") renderList();
    else renderCounts();
    if (tab === "strikes") renderStrikesTab();
    if (tab === "ranks") renderRanksTab();
    const dcTab = byId("emp-tab-discord");
    if (dcTab) dcTab.hidden = !(cloudOn() && isJefe());
    if (tab === "discord" && dcTab?.hidden) return setTab("list");
    if (tab === "discord") renderDiscordTab();
    renderFired();
  }

  async function refresh() {
    try {
      if (cloudOn() && isJefe()) await loadStrikeHist();
      employees = await listEmployees();
      employees.sort(byRankThenName);
      renderAll();
    } catch {
      alert("No se pudieron cargar los empleados.");
      return;
    }
    // Inactividad: se lee en segundo plano y se repinta al llegar.
    if (cloudOn() && isJefe()) inactLoad().then((ok) => ok && modal.open && renderAll());
  }

  // ---------- Desbloquear (programa de escritorio) ----------
  async function tryUnlock() {
    const p = String(passInput.value || "");
    if (!p) return setStatus("Escribe la contraseña.");
    if (!(await verifyPassword("empleados", p))) {
      unlocked = false;
      adminPass = "";
      return setStatus("Contraseña incorrecta.");
    }
    unlocked = true;
    adminPass = p;
    passInput.value = "";
    setStatus("🔓 Desbloqueado", true);
    renderAll();
  }
  byId("emp-admin-unlock").addEventListener("click", tryUnlock);
  passInput.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") {
      ev.preventDefault();
      tryUnlock();
    }
  });

  // ---------- Nuevo empleado ----------
  const addBtn = byId("emp-new-add");
  addBtn.addEventListener("click", async () => {
    if (addBtn.disabled) return;
    const name = String(nameInput.value || "").trim().replace(/\s+/g, " ");
    const surname = String(surInput.value || "").trim().replace(/\s+/g, " ");
    const rank = String(rankInput.value || "").trim();
    const discord = parseDiscordId(discordInput.value);
    const iban = parseIban(ibanInput.value);
    if (!name || !surname) return alert("Pon Nombre y Apellido.");
    if (discord === null) return alert("El ID de Discord no es válido. Es un número de 17 a 20 cifras (o déjalo vacío).");
    if (iban === null) return alert("El IBAN no es válido. Es una letra y 6 números, como J739745 (o déjalo vacío).");
    if (!canAdd()) return alert(cloudOn() ? "Solo los Gerentes y el Jefe Tribal pueden dar de alta." : "Primero desbloquea con la contraseña.");
    if (cloudOn() && isHigh(rank) && !AUTH.tribal) return alert(`Solo el Jefe Tribal puede dar el rango ${rank}.`);
    if (employees.some((e) => normalizeKeySimple(fullName(e)) === normalizeKeySimple(`${name} ${surname}`))) return alert(`${name} ${surname} ya está en la plantilla.`);
    const prevFired = findFired(`${name} ${surname}`);
    if (prevFired) {
      if (confirm(`${fullName(prevFired)} está en Despedidos${prevFired.firedReason ? ` (${prevFired.firedReason})` : ""}.\n\n¿Readmitirlo en vez de añadirlo de nuevo? Así conserva su historial.`)) await readmit(prevFired);
      return;
    }
    const altaIn = byId("emp-new-alta");
    const contIn = byId("emp-new-contrato");
    const altaAt = (empHasDates() && altaIn?.value) || empToday();
    const contratadoAt = (empHasDates() && contIn?.value) || altaAt;
    if (contratadoAt < altaAt) return alert("La fecha de contratación no puede ser anterior a la de ingreso al Badulaque.");
    addBtn.disabled = true; // evita guardar dos veces mientras se guarda
    try {
      const full = `${name} ${surname}`;
      if (cloudOn()) {
        // Todo en un solo guardado (Discord, IBAN y fechas).
        await addEmployee({ name, surname, rank, discord, iban, altaAt, contratadoAt }, adminPass);
      } else {
        await addEmployee({ name, surname, rank }, adminPass);
        if (discord) setEmployeeDiscord(full, discord);
        if (iban) setEmployeeIban(full, iban);
        setEmployeeDatesLocal(full, { a: altaAt, c: contratadoAt });
      }
      nameInput.value = "";
      surInput.value = "";
      rankInput.value = "";
      discordInput.value = "";
      ibanInput.value = "";
      if (altaIn) altaIn.value = empToday();
      if (contIn) contIn.value = empToday();
      setStatus(`✔ ${full} añadido${discord ? " con su Discord" : ""}${iban ? `${discord ? " e" : " con su"} IBAN` : ""}.`, true);
      await refresh();
      await (onChanged?.());
    } catch (err) {
      alert(String(err?.message || err || "Error"));
    } finally {
      addBtn.disabled = false;
    }
  });

  byId("emp-refresh").addEventListener("click", refresh);
  searchInput.addEventListener("input", renderList);

  uploadBtn?.addEventListener("click", async () => {
    if (!confirm("¿Subir a la nube los empleados guardados en este navegador? Los que ya estén en línea (mismo nombre) no se duplican.")) return;
    uploadBtn.disabled = true;
    try {
      const r = await empCloudUploadLocal();
      alert(`Subidos ${r.added} de ${r.total} empleados.${r.errors.length ? "\n\nNo se pudieron subir:\n" + r.errors.join("\n") : ""}`);
      await refresh();
      await (onChanged?.());
    } catch (err) {
      alert(String(err?.message || err));
    } finally {
      uploadBtn.disabled = false;
    }
  });

  document.addEventListener("badu-auth", () => {
    // El desplegable de "Nuevo empleado" se lleno antes de saber quien entra.
    fillRankSelect(rankInput, rankInput.value);
    refresh();
  });

  // Al cerrar la ventana se vuelve a bloquear (programa de escritorio) y a la lista.
  modal.addEventListener("close", () => {
    unlocked = false;
    adminPass = "";
    passInput.value = "";
    fichaId = null;
    editing = false;
    setStatus("");
  });

  modal.addEventListener("badu-open", () => {
    // Siempre se abre en el Listado.
    tab = "list";
    modal.querySelectorAll(".emp-tab").forEach((b) => b.classList.toggle("is-on", b.dataset.empTab === "list"));
    modal.querySelectorAll(".emp-pane").forEach((p) => (p.hidden = p.dataset.empPane !== "list"));
    fillRankSelect(rankInput, rankInput.value);
    refresh();
  });

  refresh();
}

function processCrafteos(rawText) {
  const lines = rawText.split(/\r?\n/);
  const events = [];
  const byEmployee = {};
  const byItem = {};
  const unknownItems = new Set();

  for (let line of lines) {
    line = line.trim();
    if (!line || RE_IGNORE.test(line)) continue;
    const m = RE_CRAFTEO.exec(line);
    if (!m) continue;
    const who = m.groups.who.trim();
    const qty = Number(m.groups.qty);
    const itemRaw = m.groups.item.trim();
    const key = normalizeKeySimple(itemRaw);
    const cost = getSuppliesCostForKey(key);
    if (!cost) unknownItems.add(itemRaw);
    const suministros = qty * cost;
    events.push({ who, item: itemRaw, qty, cost, suministros });

    if (!byEmployee[who]) byEmployee[who] = { items: 0, suministros: 0 };
    byEmployee[who].items += qty;
    byEmployee[who].suministros += suministros;

    if (!byItem[itemRaw]) byItem[itemRaw] = { qty: 0, suministros: 0 };
    byItem[itemRaw].qty += qty;
    byItem[itemRaw].suministros += suministros;
  }

  const summary = {
    events: events.length,
    total_items: events.reduce((a, e) => a + e.qty, 0),
    total_suministros: events.reduce((a, e) => a + e.suministros, 0),
  };
  return { events, summary, byEmployee, byItem, unknownItems };
}

function setupCrafteos() {
  const state = {
    events: [],
    summary: {},
    byEmployee: {},
    byItem: {},
    unknownItems: new Set(),
  };
  const refs = {
    input: byId("craft-input"),
    totalItems: byId("craft-total-items"),
    totalSup: byId("craft-total-sup"),
    unknown: byId("craft-unknown"),
    empTable: byId("craft-emp-table"),
    itemTable: byId("craft-item-table"),
  };

  function refresh() {
    refs.totalItems.textContent = `Items crafteados: ${state.summary.total_items ?? "-"}`;
    refs.totalSup.textContent = `Suministros gastados: ${state.summary.total_suministros ?? "-"}`;
    if (state.unknownItems.size) {
      const shown = [...state.unknownItems].sort().slice(0, 6);
      const extra = state.unknownItems.size > 6 ? ` (+${state.unknownItems.size - 6} mas)` : "";
      refs.unknown.textContent = `Sin coste asignado: ${shown.join(", ")}${extra}`;
    } else refs.unknown.textContent = "";

    refs.empTable.innerHTML = "";
    Object.entries(state.byEmployee)
      .sort((a, b) => b[1].suministros - a[1].suministros || a[0].localeCompare(b[0], "es"))
      .forEach(([name, d]) => {
        refs.empTable.insertAdjacentHTML("beforeend", `<tr><td>${name}</td><td class="num">${d.items}</td><td class="num">${d.suministros}</td></tr>`);
      });

    refs.itemTable.innerHTML = "";
    Object.entries(state.byItem)
      .sort((a, b) => b[1].suministros - a[1].suministros || a[0].localeCompare(b[0], "es"))
      .forEach(([item, d]) => {
        refs.itemTable.insertAdjacentHTML("beforeend", `<tr><td>${item}</td><td class="num">${d.qty}</td><td class="num">${d.suministros}</td></tr>`);
      });
  }

  async function processCurrent() {
    const text = refs.input.value.trim();
    if (!text) {
      alert("Pega el log de crafteo antes de procesar.");
      return;
    }
    const out = processCrafteos(text);
    state.events = out.events;
    state.summary = out.summary;
    state.byEmployee = out.byEmployee;
    state.byItem = out.byItem;
    state.unknownItems = out.unknownItems;
    refresh();
  }

  byId("craft-process").addEventListener("click", processCurrent);
  byId("craft-clear").addEventListener("click", () => {
    refs.input.value = "";
    state.events = [];
    state.summary = {};
    state.byEmployee = {};
    state.byItem = {};
    state.unknownItems = new Set();
    refresh();
  });
  byId("craft-paste").addEventListener("click", async () => {
    try {
      refs.input.value = await navigator.clipboard.readText();
      await processCurrent();
    } catch {
      alert("No se pudo leer el portapapeles.");
    }
  });
  byId("craft-export").addEventListener("click", () => {
    if (!state.events.length) {
      alert("No hay datos para exportar.");
      return;
    }
    const rows = state.events.map((e) => [e.who, e.item, e.qty, e.cost, e.suministros]);
    downloadCsv("crafteos_suministros.csv", ["who", "item", "qty", "suministros_por_unidad", "suministros_total"], rows);
  });

  refresh();
}

// ============================================================================
// Estructura: en PC barra lateral; en el movil la misma barra va abajo, con el
// visor arriba y los botones "Copiar total" / "Ver ticket" fijos en la Caja.
// ============================================================================
function setupLayout() {
  const cajaPanel = byId("tab-caja");
  const isCaja = () => cajaPanel.classList.contains("is-active");

  // El buscador y los botones fijos solo se ven en la Caja.
  const syncSection = () => document.body.classList.toggle("is-caja", isCaja());
  new MutationObserver(syncSection).observe(cajaPanel, { attributes: true, attributeFilter: ["class"] });
  syncSection();

  // Boton "Productos" de la barra lateral = Gestion de Productos.
  byId("rail-products")?.addEventListener("click", () => {
    if (!isCaja()) document.querySelector('.tab[data-tab-target="tab-caja"]')?.click();
    byId("btn-add-product")?.click();
  });

  byId("m-copy-concept")?.addEventListener("click", () => byId("btn-copy-concept")?.click());
  byId("m-view-ticket")?.addEventListener("click", () => {
    document.querySelector("#tab-caja .ticket-card")?.scrollIntoView({ block: "start", behavior: "smooth" });
  });
  document.addEventListener("badu-ticket", (ev) => {
    const { units } = ev.detail || {};
    const el = byId("m-ticket-count");
    if (el) el.textContent = `(${units || 0})`;
  });
}

// ============================================================================
// Sorteo (igual que en Aguila Motors)
// ----------------------------------------------------------------------------
// Se pegan las facturas del datafono. Una factura vale para el sorteo si:
//   1) tiene nombre del comprador (Cliente / Para), 2) el concepto lleva
//   "sorteo" y 3) no es venta a si mismo (comprador distinto del que cobra).
// Los boletos salen del monto (1 cada X $) o 1 por factura. Al sortear el primer
// premio se "sella" la lista (huella SHA-256) y cada premio sale al azar segun
// los boletos de cada persona. Todo queda guardado en el navegador.
// ============================================================================
const SORTEO_STORAGE_KEY = "badu_sorteo_v1";
const SORTEO_ICONS = ["🎁", "💰", "🎒", "📱", "🍎", "🥪", "🍕", "🌮", "🍩", "🍺", "☕", "💨", "🧺", "🎟️", "⭐", "💎", "🏆"];
const SORTEO_DEFAULT_PRIZES = [
  { icon: "🎒", name: "Mochila de Outfits" },
  { icon: "💰", name: "Vale de $ 10.000 en el Badu" },
  { icon: "🧺", name: "Cesta Badulaque" },
];

function fmtStamp(d = new Date()) {
  const p = (n) => String(n).padStart(2, "0");
  return `${p(d.getDate())}/${p(d.getMonth() + 1)}/${d.getFullYear()} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

function sorteoEmptyState() {
  return {
    text: "",
    mode: "amount",
    price: 1000,
    from: "",
    to: "",
    noStaff: false,
    oneEach: true,
    prizes: SORTEO_DEFAULT_PRIZES.map((p) => ({ ...p, winner: null })),
    seal: null, // { hash, tickets, people, at }
  };
}

function sorteoLoad() {
  try {
    const raw = JSON.parse(localStorage.getItem(SORTEO_STORAGE_KEY) || "null");
    if (raw && Array.isArray(raw.prizes)) return { ...sorteoEmptyState(), ...raw };
  } catch {
    // sin almacenamiento
  }
  return sorteoEmptyState();
}

function sorteoSave(st) {
  try {
    localStorage.setItem(SORTEO_STORAGE_KEY, JSON.stringify(st));
  } catch {
    // sin almacenamiento
  }
}

// "13/10/2026 19:02" o "2026-10-13 01:17:30" -> "2026-10-13" (o "" si no hay fecha)
function sorteoIsoDay(text) {
  const t = String(text || "");
  let m = t.match(/(\d{1,2})\/(\d{1,2})\/(\d{4})/);
  if (m) return `${m[3]}-${m[2].padStart(2, "0")}-${m[1].padStart(2, "0")}`;
  m = t.match(/(\d{4})-(\d{2})-(\d{2})/);
  return m ? `${m[1]}-${m[2]}-${m[3]}` : "";
}

// Numero al azar seguro en [0, n)
function sorteoRandomInt(n) {
  try {
    const buf = new Uint32Array(1);
    const limit = Math.floor(0x100000000 / n) * n;
    do crypto.getRandomValues(buf); while (buf[0] >= limit);
    return buf[0] % n;
  } catch {
    return Math.floor(Math.random() * n);
  }
}

function setupSorteo() {
  const root = byId("tab-sorteo");
  if (!root) return;
  let st = sorteoLoad();
  let staffKeys = new Set();
  let result = { valid: [], bad: [], people: [] };
  let lastWinnerIdx = -1;

  const $ = (id) => byId(id);
  const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  };
  const initials = (name) => String(name).split(/\s+/).filter(Boolean).map((w) => w[0]).slice(0, 2).join("").toUpperCase();
  const pct = (a, b) => (b ? ((a / b) * 100).toFixed(1).replace(".", ",") : "0") + " %";
  const shortHash = (h) => (h ? `${h.slice(0, 4)}…${h.slice(-4)}` : "");
  const boletos = (n) => `${n} ${n === 1 ? "boleto" : "boletos"}`;

  // ---------- subpestanas ----------
  function showPane(id) {
    root.querySelectorAll(".sx-subtab").forEach((b) => b.classList.toggle("is-active", b.dataset.sx === id));
    root.querySelectorAll(".sx-pane").forEach((p) => p.classList.toggle("is-active", p.id === id));
  }
  root.querySelectorAll(".sx-subtab").forEach((b) => b.addEventListener("click", () => showPane(b.dataset.sx)));

  // ---------- ajustes ----------
  $("sx-input").value = st.text || "";
  $("sx-mode").value = st.mode;
  $("sx-price").value = st.price;
  $("sx-from").value = st.from;
  $("sx-to").value = st.to;
  $("sx-no-staff").checked = !!st.noStaff;
  $("sx-one-each").checked = st.oneEach !== false;
  for (const ic of SORTEO_ICONS) $("sx-new-icon").appendChild(new Option(ic, ic));

  function readSettings() {
    st.mode = $("sx-mode").value;
    st.price = Math.max(1, Math.floor(Number($("sx-price").value) || 1000));
    st.from = $("sx-from").value;
    st.to = $("sx-to").value;
    st.noStaff = $("sx-no-staff").checked;
    st.oneEach = $("sx-one-each").checked;
    $("sx-price-wrap").hidden = st.mode !== "amount";
  }

  // ---------- reglas ----------
  function evaluate() {
    readSettings();
    const valid = [];
    const bad = [];
    if (st.text.trim()) {
      const out = processText(st.text);
      for (const inv of Object.values(out.invoices)) {
        if (inv.amount == null) continue;
        if (inv.method !== "datafono" && !inv.paid_at) continue; // factura sin pagar
        const buyer = String(inv.recipient || "").trim();
        const seller = String(inv.issuer || "").trim();
        const concept = String(inv.concept || "");
        const day = sorteoIsoDay(inv.paid_at || inv.sent_at);
        const base = { amount: inv.amount, buyer, seller, concept, when: inv.paid_at && inv.paid_at !== "OK" ? inv.paid_at : inv.sent_at || "" };
        let reason = "";
        if (!buyer) reason = "Sin comprador";
        else if (!normalizeKeySimple(concept).includes("sorteo")) reason = "Sin «sorteo»";
        else if (seller && normalizeKeySimple(buyer) === normalizeKeySimple(seller)) reason = "Venta a sí mismo";
        else if (st.noStaff && staffKeys.has(normalizeKeySimple(buyer))) reason = "Empleado del Badu";
        else if ((st.from && day && day < st.from) || (st.to && day && day > st.to)) reason = "Fuera de fecha";
        const tickets = st.mode === "amount" ? Math.floor(inv.amount / st.price) : 1;
        if (!reason && tickets < 1) reason = "Menos de 1 boleto";
        if (reason) bad.push({ ...base, reason });
        else valid.push({ ...base, tickets });
      }
    }
    const map = new Map();
    for (const v of valid) {
      const key = normalizeKeySimple(v.buyer);
      if (!map.has(key)) map.set(key, { key, name: v.buyer, tickets: 0, invoices: 0, amount: 0 });
      const p = map.get(key);
      p.tickets += v.tickets;
      p.invoices += 1;
      p.amount += v.amount;
    }
    const people = [...map.values()].sort((a, b) => b.tickets - a.tickets || a.name.localeCompare(b.name, "es"));
    result = { valid, bad, people };
  }

  // ---------- paso 1 ----------
  function renderParticipants() {
    const { valid, bad, people } = result;
    const total = people.reduce((a, p) => a + p.tickets, 0);
    $("sx-k-valid").textContent = String(valid.length);
    $("sx-k-tickets").textContent = String(total);
    $("sx-k-people").textContent = String(people.length);
    $("sx-k-bad").textContent = String(bad.length);
    $("sx-rule-note").textContent = st.mode === "amount" ? `1 boleto cada ${fmtMoney(st.price)}` : "1 boleto por factura";

    const list = $("sx-people");
    list.textContent = "";
    if (!people.length) {
      list.appendChild(el("p", "muted pg-empty", st.text.trim() ? "Ninguna factura cumple las reglas." : "Pega las facturas del sorteo y pulsa Procesar."));
    }
    const max = Math.max(1, ...people.map((p) => p.tickets));
    for (const p of people) {
      const row = el("div", "sx-row");
      const mid = el("div", "sx-mid");
      mid.appendChild(el("b", "", p.name));
      const bar = el("div", "pg-bar");
      const fill = el("i");
      fill.style.width = `${Math.max(3, Math.round((p.tickets / max) * 100))}%`;
      bar.appendChild(fill);
      mid.append(bar, el("div", "pg-meta", `${p.invoices} ${p.invoices === 1 ? "factura" : "facturas"} · ${fmtMoney(p.amount)}`));
      const tk = el("div", "sx-tk", String(p.tickets));
      tk.appendChild(el("small", "", p.tickets === 1 ? "boleto" : "boletos"));
      row.append(el("div", "pg-av", initials(p.name)), mid, tk, el("div", "sx-pc", pct(p.tickets, total)));
      list.appendChild(row);
    }

    const badEl = $("sx-bad");
    badEl.textContent = "";
    if (!bad.length) badEl.appendChild(el("p", "muted", "Ninguna."));
    const chip = { "Venta a sí mismo": "w-self", "Sin «sorteo»": "w-iban", "Sin comprador": "w-nopay" };
    for (const b of bad) {
      const row = el("div", "sx-bad");
      const txt = el("span");
      txt.append(`${fmtMoney(b.amount)} · Cobra `, el("b", "", b.seller || "—"), " → Compra ", el("b", "", b.buyer || "—"));
      if (b.concept) txt.append(` · «${b.concept}»`);
      row.append(txt, el("span", "pg-badge " + (chip[b.reason] || "w-nopay"), b.reason), el("span", "muted", b.when || ""));
      badEl.appendChild(row);
    }
  }

  // ---------- bombo ----------
  function winnersKeys() {
    return new Set(st.prizes.filter((p) => p.winner).map((p) => normalizeKeySimple(p.winner.name)));
  }

  function currentPool() {
    const won = st.oneEach ? winnersKeys() : new Set();
    return result.people.filter((p) => !won.has(p.key));
  }

  function sealText() {
    const lines = result.people.map((p) => `${p.key}:${p.tickets}`).sort().join("|");
    return `${lines}#${st.mode}:${st.price}`;
  }

  // ---------- paso 2 ----------
  function nextPrizeIndex() {
    return st.prizes.findIndex((p) => !p.winner);
  }

  function renderPrizes() {
    const box = $("sx-prizes");
    box.textContent = "";
    const done = st.prizes.filter((p) => p.winner).length;
    const next = nextPrizeIndex();
    st.prizes.forEach((p, i) => {
      const row = el("div", "sx-pz" + (p.winner ? " done" : "") + (i === lastWinnerIdx ? " now" : "") + (i === next && lastWinnerIdx < 0 ? " next" : ""));
      row.appendChild(el("div", "ico", p.icon || "🎁"));
      const mid = el("div", "sx-mid");
      mid.appendChild(el("b", "", p.name));
      mid.appendChild(el("small", "", p.winner ? `${boletos(p.winner.tickets)} · ${p.winner.odds}` : i === next ? "Siguiente" : "Pendiente"));
      row.appendChild(mid);
      const who = el("div", "who");
      if (p.winner) {
        who.appendChild(el("b", "", (i === lastWinnerIdx ? "🏆 " : "") + p.winner.name));
      } else if (!st.seal) {
        const tools = el("div", "sx-tools");
        const mk = (label, title, fn) => {
          const b = el("button", "ghost small", label);
          b.type = "button";
          b.title = title;
          b.setAttribute("aria-label", `${title} ${p.name}`);
          b.addEventListener("click", fn);
          return b;
        };
        if (i > 0) tools.appendChild(mk("↑", "Subir", () => { [st.prizes[i - 1], st.prizes[i]] = [st.prizes[i], st.prizes[i - 1]]; sorteoSave(st); renderLive(); }));
        if (i < st.prizes.length - 1) tools.appendChild(mk("↓", "Bajar", () => { [st.prizes[i + 1], st.prizes[i]] = [st.prizes[i], st.prizes[i + 1]]; sorteoSave(st); renderLive(); }));
        tools.appendChild(mk("✕", "Quitar", () => { st.prizes.splice(i, 1); sorteoSave(st); renderLive(); }));
        who.appendChild(tools);
      } else {
        who.appendChild(el("span", "muted", "Pendiente"));
      }
      row.appendChild(who);
      box.appendChild(row);
    });
    if (!st.prizes.length) box.appendChild(el("p", "muted pg-empty", "Añade los premios en el orden en que se sortean."));
    $("sx-prog-text").textContent = `${done} de ${st.prizes.length} premios sorteados`;
    $("sx-prog-bar").style.width = st.prizes.length ? `${Math.round((done / st.prizes.length) * 100)}%` : "0%";
    const pool = currentPool();
    $("sx-pool-text").textContent = `${pool.reduce((a, p) => a + p.tickets, 0)} boletos en el bombo`;
    root.querySelector(".sx-add").hidden = !!st.seal;
  }

  function drawButtonText(next, pool) {
    if (next < 0) return st.prizes.length ? "✔ Sorteo terminado" : "🎰 Sortear";
    if (!pool.length) return "No hay participantes en el bombo";
    return `🎰 Sortear: ${st.prizes[next].icon || "🎁"} ${st.prizes[next].name}`;
  }

  function renderStage() {
    const next = nextPrizeIndex();
    const total = st.prizes.length;
    const last = lastWinnerIdx >= 0 ? st.prizes[lastWinnerIdx] : null;
    const shown = last || (next >= 0 ? st.prizes[next] : null);
    $("sx-stage-tag").textContent = shown ? `PREMIO ${st.prizes.indexOf(shown) + 1} DE ${total}` : total ? "SORTEO TERMINADO" : "SORTEO";
    $("sx-stage-title").textContent = shown ? `${shown.icon || "🎁"} ${shown.name}` : total ? "¡Todos los premios sorteados!" : "Añade los premios";
    const btn = $("sx-draw");
    const pool = currentPool();
    btn.disabled = next < 0 || !pool.length;
    btn.textContent = drawButtonText(next, pool);
    if (!last) {
      $("sx-odds").textContent = pool.length ? `${pool.length} participantes · ${boletos(pool.reduce((a, p) => a + p.tickets, 0))} en el bombo` : "Procesa las facturas en «1 · Participantes».";
      if (!$("sx-reel").children.length) fillReelIdle();
    }
    $("sx-seal").textContent = st.seal
      ? `🔒 Lista sellada · huella ${shortHash(st.seal.hash)} · ${boletos(st.seal.tickets)} · ${st.seal.people} participantes · ${st.seal.at}`
      : "La lista se sella al sortear el primer premio.";
  }

  function fillReelIdle() {
    const ul = $("sx-reel");
    ul.style.transition = "none";
    ul.style.transform = "translateY(0)";
    ul.textContent = "";
    const names = result.people.map((p) => p.name);
    const show = names.length ? names : ["—", "—", "—"];
    for (let i = 0; i < 3; i++) ul.appendChild(el("li", "", show[i % show.length]));
  }

  function discordText() {
    const done = st.prizes.filter((p) => p.winner);
    const lines = [
      "# 🎉 BADULAQUE CENTRAL · ¡GANADORES DEL SORTEO! 🎉",
      "> 🦅 *Tu súper de confianza* 🍎",
      "",
      "## 🏆 PREMIOS",
    ];
    for (const p of st.prizes) {
      lines.push(p.winner ? `${p.icon || "🎁"} **${p.name}** → **${p.winner.name}**` : `${p.icon || "🎁"} ${p.name} → *por sortear…*`);
    }
    lines.push("");
    if (st.seal) lines.push(`-# 🎟️ ${boletos(st.seal.tickets)} · ${st.seal.people} participantes · 🔒 Huella de la lista: ${shortHash(st.seal.hash)}`);
    if (done.length) lines.push("Pasad por el Badulaque (📍 Parcela 8140) para recoger vuestro premio 🍎");
    return lines.join("\n");
  }

  function renderDiscord() {
    $("sx-discord").textContent = discordText();
  }

  function renderLive() {
    renderPrizes();
    renderStage();
    renderDiscord();
  }

  function renderAll() {
    evaluate();
    renderParticipants();
    renderLive();
  }

  // ---------- confeti ----------
  function confetti() {
    const box = $("sx-confetti");
    box.textContent = "";
    const cols = ["#3aa0ff", "#8fcaff", "#7cffc4", "#ffffff", "#f2bf7a", "#d64545"];
    for (let i = 0; i < 70; i++) {
      const c = el("i");
      c.style.left = `${Math.random() * 100}%`;
      c.style.background = cols[i % cols.length];
      c.style.animationDelay = `${Math.random() * 0.6}s`;
      c.style.animationDuration = `${1.8 + Math.random() * 1.4}s`;
      c.style.transform = `rotate(${Math.random() * 360}deg)`;
      box.appendChild(c);
    }
    setTimeout(() => (box.textContent = ""), 3800);
  }

  // ---------- sortear ----------
  let spinning = false;
  async function draw() {
    if (spinning) return;
    const next = nextPrizeIndex();
    const pool = currentPool();
    if (next < 0 || !pool.length) return;
    spinning = true;
    $("sx-draw").disabled = true;
    if (!st.seal) {
      st.seal = {
        hash: await sha256Hex(sealText()),
        tickets: result.people.reduce((a, p) => a + p.tickets, 0),
        people: result.people.length,
        at: fmtStamp(),
      };
    }
    const total = pool.reduce((a, p) => a + p.tickets, 0);
    let r = sorteoRandomInt(total);
    let winner = pool[pool.length - 1];
    for (const p of pool) {
      if (r < p.tickets) {
        winner = p;
        break;
      }
      r -= p.tickets;
    }
    const odds = pct(winner.tickets, total);
    st.prizes[next].winner = { name: winner.name, tickets: winner.tickets, odds, at: fmtStamp() };
    sorteoSave(st);

    // animacion: la lista gira y se para en el ganador
    lastWinnerIdx = -1;
    const prize = st.prizes[next];
    $("sx-stage-tag").textContent = `PREMIO ${next + 1} DE ${st.prizes.length}`;
    $("sx-stage-title").textContent = `${prize.icon || "🎁"} ${prize.name}`;
    $("sx-odds").textContent = "Girando…";
    const ul = $("sx-reel");
    ul.style.transition = "none";
    ul.style.transform = "translateY(0)";
    ul.textContent = "";
    const names = pool.map((p) => p.name);
    // Nombres de relleno; junto al ganador no se repite su nombre para que no confunda.
    const others = names.filter((n) => n !== winner.name);
    const filler = (avoidWinner) => {
      const src = avoidWinner && others.length ? others : names;
      return src[sorteoRandomInt(src.length)];
    };
    const N = 34;
    for (let i = 0; i < N; i++) ul.appendChild(el("li", "", filler(i >= N - 2)));
    ul.appendChild(el("li", "win", `🏆 ${winner.name}`));
    ul.appendChild(el("li", "", filler(true)));
    ul.appendChild(el("li", "", filler(true)));
    const item = 56;
    void ul.offsetHeight;
    ul.style.transition = "transform 4.2s cubic-bezier(0.12, 0.7, 0.12, 1)";
    ul.style.transform = `translateY(${-(N * item) + item}px)`;
    await new Promise((res) => setTimeout(res, 4300));
    spinning = false;
    lastWinnerIdx = next;
    confetti();
    renderPrizes();
    renderDiscord();
    renderStage();
    $("sx-odds").textContent = "";
    $("sx-odds").append(`${winner.name} tenía `, el("b", "", `${boletos(winner.tickets)} de ${total}`), ` (${odds})`);
  }

  // ---------- eventos ----------
  function process() {
    st.text = $("sx-input").value;
    if (st.seal && !window.confirm("El sorteo ya empezó y la lista está sellada. Si cambias las facturas, la lista ya no coincidirá con la huella. ¿Continuar?")) return;
    sorteoSave(st);
    renderAll();
  }
  $("sx-process").addEventListener("click", process);
  $("sx-paste").addEventListener("click", async () => {
    try {
      $("sx-input").value = await navigator.clipboard.readText();
    } catch {
      alert("No se pudo leer el portapapeles. Pega con Ctrl+V y pulsa Procesar.");
      return;
    }
    process();
  });
  $("sx-clear").addEventListener("click", () => {
    $("sx-input").value = "";
  });
  ["sx-mode", "sx-price", "sx-from", "sx-to", "sx-no-staff"].forEach((id) =>
    $(id).addEventListener("change", () => {
      readSettings();
      sorteoSave(st);
      renderAll();
    })
  );
  $("sx-one-each").addEventListener("change", () => {
    st.oneEach = $("sx-one-each").checked;
    sorteoSave(st);
    renderLive();
  });
  $("sx-go-live").addEventListener("click", () => showPane("sx-live"));
  $("sx-copy-seal").addEventListener("click", async () => {
    if (!result.people.length) {
      alert("Primero procesa las facturas del sorteo.");
      return;
    }
    const hash = st.seal ? st.seal.hash : await sha256Hex(sealText());
    const total = result.people.reduce((a, p) => a + p.tickets, 0);
    const text = [
      "# 🎟️ BADULAQUE CENTRAL · LISTA DEL SORTEO 🎟️",
      `> **${result.people.length}** participantes · **${total}** boletos`,
      "",
      ...result.people.map((p) => `• ${p.name}: ${boletos(p.tickets)}`),
      "",
      `🔒 Huella de la lista: \`${hash}\``,
      "-# La lista queda sellada: después del sorteo se puede comprobar que no se cambió.",
    ].join("\n");
    const ok = await copyText(text);
    if (!ok) openCopyFallback(text);
  });
  $("sx-add-prize").addEventListener("click", () => {
    const name = $("sx-new-name").value.trim();
    if (!name) return;
    st.prizes.push({ icon: $("sx-new-icon").value, name, winner: null });
    $("sx-new-name").value = "";
    sorteoSave(st);
    renderLive();
  });
  $("sx-new-name").addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") $("sx-add-prize").click();
  });
  $("sx-draw").addEventListener("click", draw);
  $("sx-reset").addEventListener("click", () => {
    if (!window.confirm("¿Empezar un sorteo nuevo? Se borran los ganadores y el sello (los premios y las facturas se mantienen).")) return;
    st.prizes = st.prizes.map((p) => ({ ...p, winner: null }));
    st.seal = null;
    lastWinnerIdx = -1;
    sorteoSave(st);
    fillReelIdle();
    renderAll();
  });
  $("sx-copy-all").addEventListener("click", async () => {
    const text = discordText();
    const ok = await copyText(text);
    if (!ok) openCopyFallback(text);
    $("sx-copy-status").textContent = ok ? "✔ Anuncio copiado." : "";
  });
  $("sx-copy-last").addEventListener("click", async () => {
    const p = lastWinnerIdx >= 0 ? st.prizes[lastWinnerIdx] : [...st.prizes].reverse().find((x) => x.winner);
    if (!p?.winner) {
      alert("Todavía no ha salido ningún ganador.");
      return;
    }
    const text = `🏆 **${p.name}** → **${p.winner.name}** 🎉\n-# ${boletos(p.winner.tickets)} · ${p.winner.odds} · Sorteo Badulaque Central`;
    const ok = await copyText(text);
    if (!ok) openCopyFallback(text);
    $("sx-copy-status").textContent = ok ? `✔ Copiado: ${p.name} → ${p.winner.name}` : "";
  });
  $("sx-export").addEventListener("click", () => {
    const rows = [
      ...st.prizes.map((p, i) => ["Premio", i + 1, `${p.icon} ${p.name}`, p.winner?.name || "", p.winner?.tickets ?? "", p.winner?.odds || "", p.winner?.at || ""]),
      ...result.people.map((p) => ["Participante", "", "", p.name, p.tickets, "", ""]),
      ...result.bad.map((b) => ["Descartada", "", b.reason, b.buyer, "", fmtMoney(b.amount), b.when]),
    ];
    if (st.seal) rows.push(["Huella", "", st.seal.hash, "", st.seal.tickets, "", st.seal.at]);
    downloadCsv("sorteo_badulaque_central.csv", ["Tipo", "N", "Premio / Motivo", "Persona", "Boletos", "Probabilidad / Monto", "Fecha"], rows);
  });

  // empleados del Badulaque (para la opcion de excluirlos)
  listEmployees()
    .then((list) => {
      staffKeys = new Set(list.map((e) => normalizeKeySimple(fullName(e))));
      renderAll();
    })
    .catch(() => renderAll());
  renderAll();
}

// Al abrir desde la pantalla de Inicio, el logo se queda un momento y se desvanece.
(function hideAppSplash() {
  const splash = byId("app-splash");
  if (!splash || !document.documentElement.classList.contains("is-app")) return;
  const hide = () => setTimeout(() => splash.classList.add("is-hidden"), 700);
  if (document.readyState === "complete") hide();
  else window.addEventListener("load", hide, { once: true });
})();

cloudStart();
setupCopyFallbackModal();
setupTabs();
setupLayout();
setupCaja();
setupContabilidad();
setupCrafteos();
setupSorteo();
setupPanelJefe();
