# Badulaque Central · Caja registradora

Herramienta web para el rol del servidor (FiveM): los empleados del **Badulaque Central** cobran en la caja y la gerencia lleva la contabilidad de **facturas, Datáfono TPV, Rasca y Gana y crafteos** a partir de los registros que salen en Discord.

Funciona en el navegador (GitHub Pages) y también como programa de escritorio (`.exe` con pywebview, en `Empleados_Badulaque/Pagina_badu`).

## Qué hace

1. **Caja** · Cuadrícula con los productos del Badulaque. Clic izquierdo suma una unidad y clic derecho la resta. El ticket permite cambiar la cantidad a mano, borrar líneas, **Deshacer**, **Quitar** la línea seleccionada y **Limpiar**. Con **Copiar total** y **Copiar concepto** (por ejemplo `x2 Cerveza x1 Pan`) se rellena la factura del juego sin escribir nada. No pide contraseña.
2. **Gestión de Productos** · Desde la Caja: añadir productos nuevos (nombre, precio, suministros por unidad e icono), editar el precio y los suministros de los productos fijos, y ocultarlos o restaurarlos. Si no subes imagen, se genera un icono con las iniciales.
3. **Facturas / Rascas** · Pegas el texto copiado de Discord y pulsa **Procesar** (o **Pegar + Procesar**). Reconoce:
   - **Facturas**: `Nueva Factura` y `Factura Pagada`, unidas por su ID. Se separan en pagadas y pendientes.
   - **Datáfono TPV**: recibos con importe, cobrador, cliente, concepto y AUT. Cuentan siempre como pagados, y los de **otros comercios se ignoran** (se indica cuántos al pie).
   - **Rasca y Gana**: ventas con vendedor, comprador, cantidad y total.

   Muestra el resumen general y las tablas por empleado. **Ver 50%** cambia todas las cifras a la mitad (la parte del empleado). **Exportar CSV** descarga `facturas_resultado.csv` y `ventas_rasca_y_gana.csv`.
4. **Totales empleados** · Suma, por cada empleado registrado, sus facturas pagadas y sus rascas (respetando Ver 50%) y el **total banco**. **Copiar todo** genera la lista para Discord y menciona el rol configurado en quien más ha facturado; doble clic en una fila copia su total.
5. **Gestión de empleados** · Alta y baja de empleados (nombre, apellido y rango). El nombre debe coincidir con el que sale en Discord (*Emitida por*, *Cobrador* o *Vendedor*).
6. **Crafteos / Suministros** · Pegas el log de crafteo (`Nombre crafteó 5x Cerveza`) y calcula los **suministros gastados** por empleado y por producto. Avisa de los productos sin coste asignado. **Exportar CSV** descarga `crafteos_suministros.csv`.

## Productos

| Producto | Precio | Suministros por unidad |
|---|---|---|
| Alitas | $ 1.000 | 3 |
| Venda | $ 600 | 10 |
| Cerveza | $ 200 | 2 |
| Bocadillo de Bacon | $ 250 | 3 |
| Bocadillo Ibérico | $ 250 | 3 |
| Bocadillo de Lomo | $ 250 | 3 |
| Bocadillo de Tortilla | $ 250 | 3 |
| Bocadillo Vegetal | $ 250 | 3 |
| Pan | $ 200 | 1 |
| Cortadito | $ 2.500 | 5 |
| Cerveza Mixta | $ 350 | 3 |
| Cimarrona | $ 1.000 | 3 |
| Donas | $ 150 | 1 |
| Energy | $ 100 | 1 |
| Granizado | $ 350 | 1 |
| Menú Badulaque | $ 300 | 3 |
| Michelada | $ 350 | 3 |
| Teléfono | $ 900 | 5 |
| Pizza | $ 100 | 1 |
| Refresco de Cola | $ 100 | 1 |
| Refresco de Limón | $ 100 | 1 |
| Spray | $ 1.000 | 3 |
| Spray Remove | $ 150 | 3 |
| Tacos de Birria | $ 350 | 3 |
| Vaper | $ 1.500 | 3 |
| Agua | $ 100 | 1 |
| Bayeta | $ 500 | — |
| Recarga de Cachimba | $ 1.000 | — |
| Mochila de Outfits | $ 5.000 | 20 |

Precios fijos en `app.js` → `PRODUCTS`; suministros en `app.js` → `CRAFTEO_SUPPLIES`. Los cambios hechos desde **Gestión de Productos** se guardan en el navegador de cada equipo (no en el repositorio), así que en otro ordenador no aparecen.

## Contraseñas

Cada zona tiene su propia contraseña:

| Zona | Quién la usa |
|---|---|
| Caja | Sin contraseña |
| Facturas / Rascas (incluye Ver 50% y Totales empleados) | Gerencia |
| Crafteos / Suministros | Gerencia |
| Gestión de Productos | Jefe |
| Gestión de empleados | Jefe |

Las contraseñas no están escritas en el código: solo se guarda su huella SHA-256 en `app.js` → `PASSWORD_HASHES`. Gestión de Productos y Gestión de empleados se vuelven a bloquear al cerrar la ventana.

**Cambiar una contraseña:** calcula la huella de la nueva y sustitúyela en la zona que quieras de `PASSWORD_HASHES`. Si dos zonas tienen la misma huella, comparten contraseña.

- En la web: pulsa F12 → Consola y escribe `await baduHash("NuevaContraseña")`.
- En una terminal: `echo -n "badulaque-central:NuevaContraseña" | sha256sum`

> Es una web estática: la contraseña evita miradas casuales, pero no es seguridad real. Usa contraseñas largas; una de 4 cifras se adivina en segundos.

## Estructura

```
├── index.html     Página principal (pestañas y ventanas)
├── styles.css     Estilos (tema azul)
├── app.js         Caja, procesado de Discord, crafteos, empleados y contraseñas
├── favicon.ico
├── manifest.webmanifest  Datos de la app web (nombre, colores e iconos)
├── iconos/        Icono del Inicio y pantallas de arranque del iPhone
└── *.png          Logo del Badulaque e iconos de los productos
```

No necesita servidor ni dependencias: es HTML, CSS y JavaScript puros.

**Versión de escritorio:** el `.exe` carga la misma web. Ahí los empleados se guardan en el programa de Python; en la web, en el navegador.

## Vista para móvil

En pantallas pequeñas (móvil o app de la pantalla de Inicio) la página cambia sola; en PC se ve igual que siempre:

- Cabecera compacta con un botón **☰** que abre un menú lateral con las secciones (Caja, Facturas / Rascas y Crafteos / Suministros). Las secciones con contraseña la siguen pidiendo.
- Los productos se ven en **lista**: icono pequeño, nombre y precio en una fila, y un contador (×2) en los que ya están en el ticket.
- Una barra abajo muestra cuántos productos y el total del ticket; al tocarla baja hasta el ticket.
- En el ticket del móvil no sale la columna Precio (el subtotal ya lo incluye) ni el logo grande.

## App en el iPhone

En Safari: **Compartir → Añadir a pantalla de inicio**. Se instala como app con el icono del Badulaque y, al abrirla, muestra el logo mientras carga.

Si ya la tenías anclada de antes, bórrala del Inicio y vuelve a añadirla: el iPhone guarda el icono antiguo.

Para regenerar los iconos tras cambiar el logo, sustituye los PNG de `iconos/` manteniendo el nombre y el tamaño de cada uno.

## Publicar en GitHub Pages

En el repositorio: **Settings → Pages → Build and deployment → Source: Deploy from a branch**, rama `main`, carpeta `/ (root)`. Cada cambio subido a `main` se publica en un par de minutos.

## Personalizar

- **Productos y precios fijos**: `app.js` → `PRODUCTS`. El icono es un PNG con el nombre indicado en `image`.
- **Suministros por crafteo**: `app.js` → `CRAFTEO_SUPPLIES` (nombre en minúsculas y sin tildes).
- **Rol mencionado en "Copiar todo"**: `app.js`, busca `<@&` y cambia el ID del rol de Discord.
- **Formatos de Discord**: expresiones `RE_…` al principio de `app.js` (facturas, Datáfono TPV, Rasca y Gana y crafteos).

## Bitácora

Cada cambio queda también detallado en el historial de commits.

### 2026-10-11 · Vista para móvil
- Menú oculto (☰) con las secciones, productos en lista con iconos pequeños y contador de unidades, y barra del ticket abajo con el total.
- Misma mejora que la versión 16 de Aguila Motors, con los colores del Badulaque.
- En PC la página se ve igual que antes.

### 2026-10-09 · Icono y pantalla de arranque en el iPhone
- Icono del Badulaque al anclar la web al Inicio (`apple-touch-icon` y manifiesto de app web).
- Pantalla de arranque con el logo para cada tamaño de iPhone, del SE al 16 Pro Max.
- Se abre a pantalla completa, sin la barra de Safari.

### 2026-10-09 · README y bitácora
- Descripción completa del proyecto, tabla de productos y guía de contraseñas.
- Las contraseñas ya no aparecen en los comentarios de `app.js`.

### 2026-10-08 · Contraseñas separadas por sección
- **Arreglado:** tras meter una contraseña una vez, el resto de bloqueos se abrían pulsando Escape o Enter con el campo vacío (diálogo de acceso duplicado y código antiguo sin usar).
- Contraseña propia para Facturas, Crafteos, Gestión de Productos y Gestión de empleados, guardada como huella SHA-256.
- Gestión de Productos y Gestión de empleados se vuelven a bloquear al cerrar la ventana.

### 2026-10-07 · Versión inicial
- Caja con los productos del Badulaque, incluida la Mochila de Outfits ($ 5.000, 20 suministros).
- Procesado de facturas, Datáfono TPV y Rasca y Gana desde Discord, con Ver 50% y totales por empleado.
- Gestión de Productos, Gestión de empleados y cálculo de suministros por crafteo.

---

Proyecto de rol. Badulaque Central es un negocio del servidor; no representa a ninguna empresa real.
