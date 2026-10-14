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
// Si dos zonas tienen la misma huella, comparten contraseña: Facturas y
// Crafteos usan la de gerencia; Productos y Empleados, la de jefe.
// ============================================================================
const PASSWORD_SALT = "badulaque-central:";
const PASSWORD_HASHES = {
  // Pestaña "Facturas / Rascas" (incluye Ver 50% y Totales empleados)
  facturas: "cb71ca1470c6a2d157fe7afb1c5ea0001baba5410f714a00ff762078071ee3a9",
  // Pestaña "Crafteos / Suministros"
  crafteos: "cb71ca1470c6a2d157fe7afb1c5ea0001baba5410f714a00ff762078071ee3a9",
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
const RE_RASCA = /^\s*Venta\s+de\s+Rasca\s+y\s+Gana\s*$/i;
const RE_BUYER = /^\s*Comprador:\s*(.+?)\s*$/i;
const RE_SELLER = /^\s*Vendedor:\s*(.+?)\s*$/i;
const RE_QTY = /^\s*Cantidad:\s*`?(\d+)`?\s*$/i;
const RE_TOTAL = /^\s*Total:\s*\$?\s*`?([\d.,]+)`?\s*$/i;
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
  const api = await waitPyApi();
  if (api && typeof api.emp_list === "function") {
    try {
      const data = await api.emp_list();
      const arr = Array.isArray(data) ? data : (Array.isArray(data?.employees) ? data.employees : []);
      return arr;
    } catch {
    }
  }
  return loadEmployeesLocal();
}

// El programa de escritorio (.exe) recibe su propia clave al guardar empleados.
// Se mantiene la antigua para que siga funcionando; la nueva se valida aqui.
const BACKEND_LEGACY_PASSWORD = "0000";

async function addEmployee(payload, password) {
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

// Cambiar el rango de un empleado. El programa de escritorio no tiene una
// funcion para editar, asi que alli se borra y se vuelve a anadir con el
// rango nuevo (el resto de datos se guarda por nombre, asi que no se pierde).
async function updateEmployee(id, payload, password) {
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
  { label: "En Pruebas", pct: 0.35 },
  { label: "Cajero", pct: 0.40 },
  { label: "Cajero Experimentado", pct: 0.45 },
  { label: "Encargado", pct: 0.50 },
  { label: "Jefe", pct: 0.50 },
  { label: "Jefe Tribal", pct: 0.50 },
];

function pctForRank(rank) {
  const key = normalizeKeySimple(String(rank || ""));
  const found = RANKS.find((r) => normalizeKeySimple(r.label) === key);
  return found ? found.pct : 0;
}

const pctText = (pct) => `${Math.round(pct * 100)}%`;

function fullName(e) {
  return `${String(e?.name || "").trim()} ${String(e?.surname || "").trim()}`.replace(/\s+/g, " ").trim();
}

// Rol de Discord del empleado de la semana (quien mas cobra).
const EMPLOYEE_OF_WEEK_TAG = "<@&1364707155130712195>";

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

const getEmployeeDiscord = (n) => loadMap(EMPLOYEE_DISCORD_STORAGE_KEY)[normalizeKeySimple(n)] || "";
const setEmployeeDiscord = (n, v) => setInMap(EMPLOYEE_DISCORD_STORAGE_KEY, n, v);
const getEmployeeIban = (n) => loadMap(EMPLOYEE_IBAN_STORAGE_KEY)[normalizeKeySimple(n)] || "";
const setEmployeeIban = (n, v) => setInMap(EMPLOYEE_IBAN_STORAGE_KEY, n, v);
const isEmployeeNoPay = (n) => !!loadMap(EMPLOYEE_NOPAY_STORAGE_KEY)[normalizeKeySimple(n)];
const setEmployeeNoPay = (n, v) => setInMap(EMPLOYEE_NOPAY_STORAGE_KEY, n, v ? 1 : 0);

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
      if (zone && !unlocked.has(target)) {
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
    const ok = await showAccessModal({ sectionLabel: "Gestión de Productos", zone: "productos" });
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

  function addItemDelta(name, price, delta) {
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
        if (!Number.isFinite(n) || n <= 0) delete state.cart[name];
        else state.cart[name].qty = n;
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
    if (!op) return;
    const [name, delta] = op;
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
    if (!state.selected) return;
    const price = getAllProducts().find((p) => p.name === state.selected)?.price || state.cart[state.selected]?.price || 0;
    addItemDelta(state.selected, price, -1);
  });

  byId("btn-clear").addEventListener("click", () => {
    state.cart = {};
    state.history = [];
    state.selected = null;
    state.last = null;
    renderTicket();
  });

  byId("btn-copy-total").addEventListener("click", async () => {
    const total = Object.values(state.cart).reduce((acc, r) => acc + r.price * r.qty, 0);
    const ok = await copyText(String(total));
    if (!ok) openCopyFallback(String(total));
  });

  // Lo que copia "Concepto": completo si cabe; si no, abreviado; si no, en cobros.
  byId("btn-copy-concept").addEventListener("click", async () => {
    const plan = conceptPlan();
    if (plan.kind === "empty") {
      alert("El ticket esta vacio.");
      return;
    }
    if (plan.kind === "split") {
      openChargesDialog(plan.charges);
      return;
    }
    const ok = await copyText(plan.text);
    if (!ok) openCopyFallback(plan.text);
  });

  renderTicket();
  setupProductsAdminModal(renderProductGrid);
}

function processText(rawText) {
  const lines = rawText.split(/\r?\n/);
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
    "en pruebas": "r-pruebas",
    cajero: "r-cajero",
    "cajero experimentado": "r-exp",
    encargado: "r-encargado",
    jefe: "r-jefe",
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
      const name = e ? fullName(e) : r.name;
      const total = r.fact + r.ras;
      const pct = e ? pctForRank(e.rank) : 0;
      return { ...r, name, emp: e, rank: e?.rank || "", pct, total, payout: Math.round(total * pct), noPay: isEmployeeNoPay(name), iban: getEmployeeIban(name) };
    });
    rows.sort((a, b) => b.total - a.total || a.name.localeCompare(b.name, "es"));
    return rows;
  }

  function renderRanking(rows, invSummary, salesSummary, totalAPagar) {
    const list = byId("pg-ranking");
    const maxTotal = Math.max(1, ...rows.map((r) => r.total));
    const maxPayout = Math.max(0, ...rows.map((r) => (r.noPay ? 0 : r.payout)));
    const top = rows.find((r) => maxPayout > 0 && !r.noPay && r.payout === maxPayout);
    const paying = rows.filter((r) => r.emp && !r.noPay && r.payout > 0).length;

    byId("pg-kpi-fact").textContent = fmtMoney(invSummary.paid_total + salesSummary.total);
    byId("pg-kpi-fact-sub").textContent = rows.length
      ? `${invSummary.paid_count} facturas · ${rows.length} ${rows.length === 1 ? "persona" : "personas"}`
      : "Sin datos";
    byId("pg-kpi-pay").textContent = fmtMoney(totalAPagar);
    byId("pg-kpi-rascas").textContent = String(salesSummary.qty);
    byId("pg-kpi-rascas-sub").textContent = salesSummary.count ? `${salesSummary.count} ventas · ${fmtMoney(salesSummary.total)}` : "-";
    byId("pg-kpi-top").textContent = top ? top.name : "-";
    byId("pg-kpi-top").title = top ? top.name : "";
    byId("pg-kpi-top-sub").textContent = top ? `${fmtMoney(top.total)} cobrados` : "-";
    byId("pg-total-label").textContent = paying ? `TOTAL A PAGAR · ${paying} ${paying === 1 ? "EMPLEADO" : "EMPLEADOS"}` : "TOTAL A PAGAR";

    list.textContent = "";
    if (!rows.length) {
      const p = document.createElement("p");
      p.className = "muted pg-empty";
      p.textContent = "Pega el texto de Discord y pulsa Procesar para ver el ranking.";
      list.appendChild(p);
      return;
    }
    const el = (tag, cls, text) => {
      const n = document.createElement(tag);
      if (cls) n.className = cls;
      if (text != null) n.textContent = text;
      return n;
    };
    rows.forEach((r, i) => {
      const card = el("div", "pg-row" + (r === top ? " first" : ""));
      const initials = r.name.split(/\s+/).filter(Boolean).map((w) => w[0]).slice(0, 2).join("").toUpperCase();
      const av = el("div", "pg-av" + (r.noPay || !r.emp ? " np" : ""), initials);
      if (r === top) {
        av.appendChild(el("span", "crown", "★"));
        av.title = "Empleado de la semana";
      }
      const pos = el("span", "pg-pos", String(i + 1));

      const mid = el("div", "pg-mid");
      const nameRow = el("div", "pg-name");
      nameRow.appendChild(el("span", "", r.name));
      if (!r.emp) nameRow.appendChild(el("span", "pg-badge w-nopay", "Sin registrar"));
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
      if (!r.emp) amt.append(el("small", "", "Sin registrar"), el("b", "pg-dash", "$ 0"));
      else if (r.noPay) amt.append(el("small", "", `Le tocarían ${fmtMoney(r.payout)}`), el("b", "pg-dash", "No cobra"));
      else if (!r.pct) amt.append(el("small", "", "Sin rango"), el("b", "pg-dash", "$ 0"));
      else amt.append(el("small", "", `de ${fmtMoney(r.total)}`), el("b", "pay", fmtMoney(r.payout)));
      card.append(pos, av, mid, amt);
      list.appendChild(card);
    });
  }

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
    const totalAPagar = rows.reduce((a, r) => a + (r.emp && !r.noPay ? r.payout : 0), 0);

    const totalGeneral = invSummary.total + salesSummary.total;
    refs.totalGeneral.textContent = fmtMoney(totalGeneral);
    refs.totalAPagar.textContent = fmtMoney(totalAPagar);
    let footerText = `Facturas: ${invSummary.count} | Rascas: ${salesSummary.count} | Total: ${fmtMoney(totalGeneral)}`;
    if (state.ignoredOtherBusiness > 0) footerText += ` | Ignorados (otro comercio): ${state.ignoredOtherBusiness}`;
    refs.footer.textContent = footerText;
    refs.loaded.textContent = invSummary.count || salesSummary.count ? "Datos cargados" : "Sin datos";
    renderRanking(rows, invSummary, salesSummary, totalAPagar);
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
    clearState();
  });
  byId("conta-paste").addEventListener("click", async () => {
    try {
      refs.input.value = await navigator.clipboard.readText();
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
  clearState();
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
  }

  function renderTotalsRows() {
    totalsBody.innerHTML = "";
    for (const row of totalsRows) {
      const tr = document.createElement("tr");
      if (row.id === selectedId) tr.classList.add("is-selected");
      tr.innerHTML = `
        <td>${escapeHtml(row.name)}</td>
        <td>${escapeHtml(row.rank || "-")}</td>
        <td class="num">${row.pct ? pctText(row.pct) : "-"}</td>
        <td class="num">${fmtMoney(row.paid)}</td>
        <td class="num">${fmtMoney(row.ras)}</td>
        <td class="num">${row.noPay ? `<span class="muted" title="Le corresponderían ${fmtMoney(row.payout)}">${NO_PAY_TEXT}</span>` : fmtMoney(row.payout)}</td>
      `;
      tr.addEventListener("click", () => {
        selectedId = row.id;
        renderTotalsRows();
      });
      tr.addEventListener("dblclick", async () => {
        const text = row.noPay ? NO_PAY_TEXT : String(row.payout);
        const ok = await copyText(text);
        if (!ok) openCopyFallback(text);
      });
      totalsBody.appendChild(tr);
    }
    const bankTotal = totalsRows.reduce((acc, r) => acc + (r.noPay ? 0 : r.payout), 0);
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
    const maxPayout = Math.max(0, ...totalsRows.map((r) => (r.noPay ? 0 : r.payout)));
    return maxPayout > 0 && !row.noPay && row.payout === maxPayout;
  }

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
      : `${labelForCopy(row)} | ${pct} | Cobrado: ${fmtMoney(row.gross)} | A pagar: ${fmtMoney(row.payout)} | ${ibanForCopy(row)}`;
    if (isEmployeeOfWeek(row)) text += ` | ${EMPLOYEE_OF_WEEK_TAG}`;
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
          : `* ${labelForCopy(r)}: ${fmtMoneyPlain(r.payout)} · ${ibanForCopy(r)}`;
        if (isEmployeeOfWeek(r)) line += ` ${EMPLOYEE_OF_WEEK_TAG}`;
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
  const body = byId("emp-admin-body");

  // Desplegable de rangos con su %; un rango antiguo que no este en la lista se conserva.
  function fillRankSelect(select, current) {
    select.textContent = "";
    const blank = document.createElement("option");
    blank.value = "";
    blank.textContent = "Sin rango";
    select.appendChild(blank);
    for (const r of RANKS) {
      const opt = document.createElement("option");
      opt.value = r.label;
      opt.textContent = `${r.label} (${pctText(r.pct)})`;
      select.appendChild(opt);
    }
    if (current && !pctForRank(current)) {
      const opt = document.createElement("option");
      opt.value = current;
      opt.textContent = `${current} (sin %)`;
      select.appendChild(opt);
    }
    select.value = current || "";
  }
  fillRankSelect(rankInput, "");

  let unlocked = false;
  let adminPass = "";
  let employees = [];

  function setStatus(text, ok = false) {
    status.textContent = text;
    status.style.color = ok ? "var(--ok)" : "var(--muted)";
  }

  const needUnlock = () => {
    if (unlocked) return false;
    alert("Primero desbloquea con la contraseña.");
    return true;
  };

  function renderList() {
    const q = normalizeKeySimple(searchInput.value || "");
    const shown = !q
      ? employees
      : employees.filter((e) => normalizeKeySimple(`${e.name} ${e.surname} ${e.rank || ""}`).includes(q));

    body.innerHTML = "";
    if (!shown.length) {
      body.innerHTML = `<tr><td colspan="7" class="muted">${employees.length ? "Sin resultados" : "Aún no hay empleados. Añádelos arriba."}</td></tr>`;
      return;
    }
    for (const e of shown) {
      const full = fullName(e);
      const pct = pctForRank(e.rank);
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${escapeHtml(full)}</td>
        <td><select class="text-input emp-rank-select" aria-label="Rango de ${escapeHtml(full)}"></select></td>
        <td class="num emp-pct">${e.rank ? pctText(pct) : "-"}</td>
        <td><input class="text-input emp-discord-input" type="text" inputmode="numeric" placeholder="ID de Discord" aria-label="Discord de ${escapeHtml(full)}" title="ID de Discord: clic derecho sobre la persona → Copiar ID de usuario" /></td>
        <td><input class="text-input emp-iban-input" type="text" placeholder="J000000" maxlength="9" aria-label="IBAN de ${escapeHtml(full)}" title="IBAN del banco del servidor (una letra y 6 números)" /></td>
        <td class="center"><input class="emp-nopay-input" type="checkbox" aria-label="${escapeHtml(full)} no cobra" title="No cobra la nómina: no se le pide IBAN y no suma al Total a Pagar" /></td>
        <td class="num"><button type="button" class="danger small" data-del="1">Eliminar</button></td>
      `;
      body.appendChild(tr);

      const select = tr.querySelector(".emp-rank-select");
      fillRankSelect(select, e.rank || "");
      select.addEventListener("change", async () => {
        if (needUnlock()) {
          select.value = e.rank || "";
          return;
        }
        try {
          await updateEmployee(e.id, { rank: select.value }, adminPass);
          await refresh();
          await (onChanged?.());
        } catch (err) {
          alert(String(err?.message || err || "Error"));
          select.value = e.rank || "";
        }
      });

      const dInput = tr.querySelector(".emp-discord-input");
      dInput.value = getEmployeeDiscord(full);
      dInput.addEventListener("change", async () => {
        if (needUnlock()) {
          dInput.value = getEmployeeDiscord(full);
          return;
        }
        const id = parseDiscordId(dInput.value);
        if (id === null) {
          alert("Eso no parece un ID de Discord. Es un número de 17 a 20 cifras (clic derecho sobre la persona → Copiar ID de usuario).");
          dInput.value = getEmployeeDiscord(full);
          return;
        }
        setEmployeeDiscord(full, id);
        dInput.value = id;
        await (onChanged?.());
      });

      const iInput = tr.querySelector(".emp-iban-input");
      iInput.value = getEmployeeIban(full);
      iInput.addEventListener("change", async () => {
        if (needUnlock()) {
          iInput.value = getEmployeeIban(full);
          return;
        }
        const iban = parseIban(iInput.value);
        if (iban === null) {
          alert("El IBAN no es válido. Es una letra y 6 números, como J739745 (sale en el banco, en Informaciones).");
          iInput.value = getEmployeeIban(full);
          return;
        }
        setEmployeeIban(full, iban);
        iInput.value = iban;
        await (onChanged?.());
      });

      const npInput = tr.querySelector(".emp-nopay-input");
      npInput.checked = isEmployeeNoPay(full);
      npInput.addEventListener("change", async () => {
        if (needUnlock()) {
          npInput.checked = isEmployeeNoPay(full);
          return;
        }
        setEmployeeNoPay(full, npInput.checked);
        await (onChanged?.());
      });

      tr.querySelector("button[data-del]").addEventListener("click", async () => {
        if (needUnlock()) return;
        if (!confirm(`Eliminar a ${full}?`)) return;
        try {
          await deleteEmployee(e.id, adminPass);
          setEmployeeDiscord(full, "");
          setEmployeeIban(full, "");
          setEmployeeNoPay(full, false);
          await refresh();
          await (onChanged?.());
        } catch (err) {
          alert(String(err?.message || err || "Error"));
        }
      });
    }
  }

  async function refresh() {
    try {
      employees = await listEmployees();
      employees.sort((a, b) =>
        `${a.surname} ${a.name}`.localeCompare(`${b.surname} ${b.name}`, "es", { sensitivity: "base" })
      );
      renderList();
    } catch {
      alert("No se pudieron cargar los empleados.");
    }
  }

  async function tryUnlock() {
    const p = String(passInput.value || "");
    if (!p) {
      setStatus("Escribe la contraseña.");
      return;
    }
    if (!(await verifyPassword("empleados", p))) {
      unlocked = false;
      adminPass = "";
      setStatus("Contraseña incorrecta.");
      return;
    }
    unlocked = true;
    adminPass = p;
    passInput.value = "";
    setStatus("Desbloqueado", true);
  }

  byId("emp-admin-unlock").addEventListener("click", tryUnlock);
  passInput.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") {
      ev.preventDefault();
      tryUnlock();
    }
  });

  const addBtn = byId("emp-new-add");
  addBtn.addEventListener("click", async () => {
    if (addBtn.disabled) return;
    const name = String(nameInput.value || "").trim();
    const surname = String(surInput.value || "").trim();
    const rank = String(rankInput.value || "").trim();
    const discord = parseDiscordId(discordInput.value);
    const iban = parseIban(ibanInput.value);

    if (!name || !surname) {
      alert("Pon Nombre y Apellido.");
      return;
    }
    if (discord === null) {
      alert("El ID de Discord no es válido. Es un número de 17 a 20 cifras (o déjalo vacío).");
      return;
    }
    if (iban === null) {
      alert("El IBAN no es válido. Es una letra y 6 números, como J739745 (o déjalo vacío).");
      return;
    }
    if (needUnlock()) return;
    addBtn.disabled = true; // evita guardar dos veces mientras se guarda
    try {
      await addEmployee({ name, surname, rank }, adminPass);
      const full = `${name} ${surname}`;
      if (discord) setEmployeeDiscord(full, discord);
      if (iban) setEmployeeIban(full, iban);
      nameInput.value = "";
      surInput.value = "";
      rankInput.value = "";
      discordInput.value = "";
      ibanInput.value = "";
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

  // Al cerrar la ventana se vuelve a bloquear.
  modal.addEventListener("close", () => {
    unlocked = false;
    adminPass = "";
    passInput.value = "";
    setStatus("Bloqueado");
  });

  modal.addEventListener("badu-open", refresh);

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

  byId("m-copy-total")?.addEventListener("click", () => byId("btn-copy-total")?.click());
  byId("m-view-ticket")?.addEventListener("click", () => {
    document.querySelector("#tab-caja .ticket-card")?.scrollIntoView({ block: "start", behavior: "smooth" });
  });
  document.addEventListener("badu-ticket", (ev) => {
    const { units } = ev.detail || {};
    const el = byId("m-ticket-count");
    if (el) el.textContent = `(${units || 0})`;
  });
}

// Al abrir desde la pantalla de Inicio, el logo se queda un momento y se desvanece.
(function hideAppSplash() {
  const splash = byId("app-splash");
  if (!splash || !document.documentElement.classList.contains("is-app")) return;
  const hide = () => setTimeout(() => splash.classList.add("is-hidden"), 700);
  if (document.readyState === "complete") hide();
  else window.addEventListener("load", hide, { once: true });
})();

setupCopyFallbackModal();
setupTabs();
setupLayout();
setupCaja();
setupContabilidad();
setupCrafteos();
