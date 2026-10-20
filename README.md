# SIGMETAS en Render y Neon

La aplicación guarda el conjunto compartido en PostgreSQL de Neon. Render sirve la página y la API; el Excel solo reemplaza los datos si se proporciona la clave de responsable. Los visitantes pueden consultar la última versión sin iniciar sesión.

## Configuración inicial

1. Crea una base de datos PostgreSQL en Neon y copia su cadena de conexión (`DATABASE_URL`), conservando el parámetro TLS `sslmode=require` que entrega Neon. La aplicación crea la tabla necesaria y carga los datos iniciales del tablero solo si la tabla aún está vacía.
2. Genera una clave privada de al menos 32 caracteres, por ejemplo con `node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"`. No la guardes en el repositorio.
3. En Render, crea o actualiza un servicio **Web Service** conectado a este repositorio y selecciona el Blueprint `render.yaml`. Si ya existe un Static Site para este tablero, crea el Web Service y luego usa su URL nueva o mueve el dominio personalizado a ese servicio.
4. En la configuración del servicio en Render, establece `DATABASE_URL` con la cadena de Neon y `ADMIN_WRITE_KEY` con la clave generada. Son secretos: no los publiques ni los pongas en archivos del repositorio.
5. Render instala las dependencias y despliega cada cambio de la rama conectada. El endpoint `/api/health` comprueba la conexión con la base.

## Actualizar datos

Abre la URL del Web Service, elige **Cargar otro Excel** e introduce la clave de responsable. Al confirmar, el archivo se guarda en Neon; el tablero muestra la última versión y todos los visitantes la reciben al abrir o recargar la página. Si falla el guardado, los datos compartidos no se reemplazan y se muestra el error.

La clave se solicita en cada carga y no se guarda en el navegador. Para cambiarla, actualiza `ADMIN_WRITE_KEY` en Render y vuelve a desplegar. No compartas esa clave con los visitantes.

## Validación local

Requiere Node.js 20 o posterior. Ejecuta `npm install` y `npm test`. Para iniciar el servicio localmente también se requieren `DATABASE_URL` y `ADMIN_WRITE_KEY`.
