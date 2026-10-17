# Badulaque Central · Caja registradora

Herramienta web para el rol del servidor (FiveM): los empleados del **Badulaque Central** cobran en la caja y la gerencia lleva la contabilidad de **facturas, Datáfono TPV, Rasca y Gana y crafteos** a partir de los registros que salen en Discord.

Funciona en el navegador (GitHub Pages) y también como programa de escritorio (`.exe` con pywebview, en `Empleados_Badulaque/Pagina_badu`).

## Qué hace

1. **Caja** · Teclas con los productos del Badulaque y un **buscador** arriba para encontrarlos al escribir. Clic izquierdo suma una unidad y clic derecho la resta. El **visor** verde del ticket muestra el último producto tocado y el total. El ticket permite cambiar la cantidad a mano, borrar líneas, **Deshacer**, **Quitar** la línea seleccionada y **Limpiar**. Con **Copiar total** y **Concepto** se rellena el cobro del datáfono sin escribir nada; el concepto se ajusta solo a los 40 caracteres del datáfono (ver *Concepto para el datáfono*). No pide contraseña.
2. **Gestión de Productos** · Botón **⚙ Productos** de la barra lateral (en el móvil, el botón de la Caja): añadir productos nuevos (nombre, precio, suministros por unidad e icono), editar el precio y los suministros de los productos fijos, y ocultarlos o restaurarlos. Si no subes imagen, se genera un icono con las iniciales.
3. **Pagos** · Pegas el texto copiado de Discord y pulsa **Procesar** (o **Pegar + Procesar**). Reconoce:
   - **Facturas**: `Nueva Factura` y `Factura Pagada`, unidas por su ID. Se separan en pagadas y pendientes.
   - **Datáfono TPV**: recibos con importe, cobrador, cliente, concepto y AUT. Cuentan siempre como pagados, y los de **otros comercios se ignoran** (se indica cuántos al pie).
   - **Rasca y Gana**: ventas con vendedor, comprador, cantidad y total.

   Muestra tarjetas con lo **cobrado**, el **total a pagar**, las **rascas** y el **empleado de la semana**, y un **ranking** con una fila por persona: rango y %, barra de lo cobrado, IBAN, lo que hay que pagarle y avisos (*Sin IBAN*, *No cobra*, *Sin registrar*, *Sin rango*). **Copiar para Discord** copia la lista de pagos lista para pegar. Las tablas de siempre están en **Ver detalle**. **Exportar CSV** descarga `facturas_resultado.csv` y `ventas_rasca_y_gana.csv`.
4. **Totales empleados** · Por cada empleado registrado: rango, %, facturas pagadas, rascas y **lo que hay que pagarle**, más el **total a pagar**. **Copiar todo** (igual que *Copiar para Discord*) genera una línea por persona: `* Ana Lopez (Encargado) <@ID>: 5.000 · IBAN J739745`, con `**IBAN pendiente**` si falta y el rol de empleado de la semana en quien más cobra. Quien no cobra va al final como *No cobra*. Doble clic en una fila copia lo que se le paga.
5. **Gestión de empleados** · Igual que en Aguila Motors: tabla con **Empleado, Rango, % de Comisión según Rango, Discord, IBAN y No cobra**. El rango se elige en un desplegable (cambia el % al momento), el ID de Discord sirve para etiquetarle al copiar los pagos, el IBAN (una letra y 6 números, como `J739745`) sale en la nómina, y *No cobra* le saca del total a pagar. El nombre debe coincidir con el que sale en Discord (*Emitida por*, *Cobrador* o *Vendedor*). Discord, IBAN y No cobra se guardan en el navegador de cada equipo.
6. **Crafteos / Suministros** · Pegas el log de crafteo (`Nombre crafteó 5x Cerveza`) y calcula los **suministros gastados** por empleado y por producto. Avisa de los productos sin coste asignado. **Exportar CSV** descarga `crafteos_suministros.csv`.

## Rangos y comisión

Lo que se paga a cada empleado es un **% de lo que ha cobrado** en la semana (facturas pagadas, datáfono incluido, más sus rascas), según su rango:

| Rango | Comisión |
|---|---|
| En Pruebas | 35 % |
| Cajero | 40 % |
| Cajero Experimentado | 45 % |
| Encargado | 50 % |
| Jefe | 50 % |
| Jefe Tribal | 50 % |

Las facturas pendientes de pago no cuentan. Los rangos y porcentajes se cambian en `app.js` → `RANKS`.

## Concepto para el datáfono

El datáfono solo acepta **40 caracteres** de concepto. Debajo del visor del ticket se ve cuántos ocupa, y el botón **Concepto** elige solo:

1. **Completo**, si cabe: `x2 Alitas x3 Cerveza`.
2. **Abreviado**, si el completo no cabe. Los bocadillos se agrupan y se escribe «Boc» una sola vez al final: `2xAlitas+3xCerv, Bacon+2xLomo Boc`.
3. **En varios cobros**, si ni abreviado cabe: se abre una ventana con cada cobro (total y concepto) para pasarlos por el datáfono uno tras otro. La suma de los cobros es el total del ticket.

| Abreviatura | Producto |
|---|---|
| Bacon, Iber, Lomo, Tort, Veg + `Boc` | Bocadillo de Bacon, Ibérico, de Lomo, de Tortilla y Vegetal |
| Cerv, CervMix, Cort, Cimarr, Graniz, Mich | Cerveza, Cerveza Mixta, Cortadito, Cimarrona, Granizado, Michelada |
| Cola, Limon, Menu, Tlf, Tacos, SprayRem | Refresco de Cola, Refresco de Limón, Menú Badulaque, Teléfono, Tacos de Birria, Spray Remove |
| Cachimba, Mochila | Recarga de Cachimba, Mochila de Outfits |
| Alitas, Venda, Pan, Donas, Energy, Pizza, Spray, Vaper, Agua, Bayeta | Igual que el nombre |
| `2x` delante | Cantidad (si es más de 1) |

Los productos agregados desde Gestión de Productos usan su nombre completo. Las abreviaturas se cambian en `app.js` → `PRODUCT_SHORT`.

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
| Pagos (incluye Totales empleados) | Gerencia |
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

## Diseño "Terminal TPV"

La página imita una caja registradora: fondo grafito, botones con relieve tipo tecla, cifras en letra monoespaciada y un visor verde con el total.

**En PC:**
- Barra lateral con las secciones (Caja, Pagos y Crafteos; el candado indica que piden contraseña) y el botón **⚙ Productos** para la Gestión de Productos.
- Productos en teclas compactas con icono, nombre, precio y contador (×2) de las unidades que ya están en el ticket.
- Ticket con el visor arriba (último producto tocado y total), la lista y las teclas Deshacer, Quitar, Limpiar, **Copiar concepto** y Total.

**En el móvil (pantallas de hasta 700px):**
- Visor fijo arriba con el último producto, los artículos y el total.
- Teclas de producto en dos columnas.
- Botones fijos **Copiar concepto** y **Ver ticket (n)** sobre la barra de secciones, que pasa abajo como en una app.

Los importes se muestran con punto de miles (`$ 1.000`). Lo que se copia para el juego (Copiar total) sigue siendo el número sin puntos.

## App en el iPhone

En Safari: **Compartir → Añadir a pantalla de inicio**. Se instala como app con el icono del Badulaque y, al abrirla, muestra el logo mientras carga y se desvanece al terminar.

Si ya la tenías anclada de antes, bórrala del Inicio y vuelve a añadirla: el iPhone guarda el icono antiguo.

Para regenerar los iconos tras cambiar el logo, sustituye los PNG de `iconos/` manteniendo el nombre y el tamaño de cada uno.

## Publicar en GitHub Pages

En el repositorio: **Settings → Pages → Build and deployment → Source: Deploy from a branch**, rama `main`, carpeta `/ (root)`. Cada cambio subido a `main` se publica en un par de minutos.

Al publicar un cambio, sube el número de versión en `index.html`: el pie de página y el `?v=` de `styles.css` y `app.js`. Así los navegadores y la app del iPhone cargan la versión nueva sin Ctrl+F5.

## Personalizar

- **Productos y precios fijos**: `app.js` → `PRODUCTS`. El icono es un PNG con el nombre indicado en `image`.
- **Suministros por crafteo**: `app.js` → `CRAFTEO_SUPPLIES` (nombre en minúsculas y sin tildes).
- **Rol mencionado en "Copiar todo"**: `app.js`, busca `<@&` y cambia el ID del rol de Discord.
- **Formatos de Discord**: expresiones `RE_…` al principio de `app.js` (facturas, Datáfono TPV, Rasca y Gana y crafteos).

## Bitácora

Cada cambio queda también detallado en el historial de commits. El pie de la página muestra la versión publicada.

### Versión 12 · 16 de octubre de 2026 · Copiar concepto destacado
- En el ticket, el botón grande azul es ahora **Copiar concepto** y el pequeño, **Total**, porque el concepto es lo que más se usa.
- En el móvil, el botón fijo de abajo también copia el concepto (el total sigue en el ticket).

### Versión 11 · 13 de octubre de 2026 · Pagos por rangos
- La pestaña Facturas pasa a ser **Pagos**, con el estilo del módulo de pagos de Aguila Motors adaptado al Terminal TPV: tarjetas (cobrado, total a pagar, rascas y empleado de la semana), ranking por persona con rango, barra, IBAN, avisos y lo que hay que pagarle, total a pagar en el visor y botón **Copiar para Discord**. Las tablas de antes quedan en *Ver detalle*.
- **Comisión por rango** (En Pruebas 35 %, Cajero 40 %, Cajero Experimentado 45 %, Encargado 50 %, Jefe 50 %, Jefe Tribal 50 %) sobre facturas pagadas + rascas. Sustituye al botón *Ver 50%*.
- **Gestión de empleados** como en Aguila Motors: rango en desplegable con su %, ID de Discord, IBAN y casilla *No cobra*.
- Totales empleados y *Copiar todo* con %, lo que hay que pagar, etiqueta de Discord, IBAN (o **IBAN pendiente**) y quien no cobra al final.
- Importes con punto de miles también en el texto para Discord.
- El programa de escritorio sigue recibiendo su clave antigua al guardar empleados; la nueva se comprueba en la página.

### Versión 10 · 13 de octubre de 2026 · Contraseñas nuevas
- Contraseñas nuevas y más largas: una para gerencia (Facturas y Crafteos) y otra para jefe (Gestión de Productos y Gestión de empleados). Las antiguas dejan de funcionar.
- En el código solo está su huella SHA-256; las contraseñas no aparecen ni en el código ni en el historial.

### Versión 9 · 13 de octubre de 2026 · Concepto de 40 caracteres
- **Concepto para el datáfono** (máximo 40 caracteres), igual que en Aguila Motors: se copia completo si cabe; si no, abreviado (`2xAlitas+3xCerv, Bacon+2xLomo Boc`); y si ni así cabe, se reparte en varios cobros con su total y su concepto.
- Debajo del visor del ticket se ve cuántos caracteres ocupa el concepto.
- El total del visor reduce la letra en importes largos (de $ 10.000 en adelante) para que siempre quepa.

### Versión 8 · 13 de octubre de 2026 · Terminal TPV
- Nuevo diseño tipo caja registradora (la propuesta C): fondo grafito, teclas con relieve, cifras en monoespaciada y visor verde con el último producto y el total.
- PC: barra lateral con las secciones y el botón ⚙ Productos; productos en teclas compactas.
- Móvil: visor fijo arriba, teclas en dos columnas, botones Copiar total y Ver ticket, y barra de secciones abajo (sustituye al menú ☰).
- Buscador de productos en la Caja.
- Importes con punto de miles (`$ 1.000`); el total copiado para el juego no cambia.
- Facturas, Crafteos y las ventanas con el mismo estilo; el total general se ve como visor.

### Versión 7 · 11 de octubre de 2026 · Logo en la cabecera
- Logo pequeño del Badulaque junto al nombre, en PC y en el móvil, como en Aguila Motors.
- Pie de página con la versión y el último cambio (por ejemplo, «Versión 7 · Logo en la cabecera»).
- Bitácora numerada por versiones.

### Versión 6 · 11 de octubre de 2026 · Logo al abrir la app del Inicio
- Al abrir la app desde la pantalla de Inicio, el logo se queda un momento en pantalla y se desvanece, como en Aguila Motors.
- Es igual que la imagen de arranque del iPhone, así que el paso de una a otra no se nota. En Safari normal y en PC no aparece.

### Versión 5 · 11 de octubre de 2026 · Vista para móvil
- Menú oculto (☰) con las secciones, productos en lista con iconos pequeños y contador de unidades, y barra del ticket abajo con el total.
- Misma mejora que la versión 16 de Aguila Motors, con los colores del Badulaque.
- En PC la página se ve igual que antes.

### Versión 4 · 9 de octubre de 2026 · Icono y pantalla de arranque en el iPhone
- Icono del Badulaque al anclar la web al Inicio (`apple-touch-icon` y manifiesto de app web).
- Pantalla de arranque con el logo para cada tamaño de iPhone, del SE al 16 Pro Max.
- Se abre a pantalla completa, sin la barra de Safari.

### Versión 3 · 9 de octubre de 2026 · README y bitácora
- Descripción completa del proyecto, tabla de productos y guía de contraseñas.
- Las contraseñas ya no aparecen en los comentarios de `app.js`.

### Versión 2 · 8 de octubre de 2026 · Contraseñas separadas por sección
- **Arreglado:** tras meter una contraseña una vez, el resto de bloqueos se abrían pulsando Escape o Enter con el campo vacío (diálogo de acceso duplicado y código antiguo sin usar).
- Contraseña propia para Facturas, Crafteos, Gestión de Productos y Gestión de empleados, guardada como huella SHA-256.
- Gestión de Productos y Gestión de empleados se vuelven a bloquear al cerrar la ventana.

### Versión 1 · 7 de octubre de 2026 · Versión inicial
- Caja con los productos del Badulaque, incluida la Mochila de Outfits ($ 5.000, 20 suministros).
- Procesado de facturas, Datáfono TPV y Rasca y Gana desde Discord, con Ver 50% y totales por empleado.
- Gestión de Productos, Gestión de empleados y cálculo de suministros por crafteo.

---

Proyecto de rol. Badulaque Central es un negocio del servidor; no representa a ninguna empresa real.
