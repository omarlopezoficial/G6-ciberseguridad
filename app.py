# ============================================================
# app.py — Med-Core App
# Punto de entrada principal de la aplicación Flask.
# Gestiona la autenticación de usuarios consultando la tabla
# 'usuarios' mediante SQL puro (sin ORM).
#
# ADVERTENCIA EDUCATIVA: Las contraseñas en este entorno de
# prueba se almacenan en texto plano para demostrar
# vulnerabilidades comunes. NUNCA usar en producción.
# ============================================================

from flask import (
    Flask,
    render_template,
    request,
    session,
    redirect,
    url_for,
    flash,
    jsonify,
)

import atexit
import logging
import re

from logging.handlers import RotatingFileHandler
from config import Config
from database import init_pool, init_db, get_db_connection, close_pool

# ------------------------------------------------------------------
# Creación e inicialización de la aplicación Flask
# ------------------------------------------------------------------

app = Flask(__name__)

# Cargar la configuración desde la clase Config (lee el archivo .env)
app.secret_key = Config.SECRET_KEY
app.debug = Config.DEBUG

# BLINDAJE A10: Forzar debug=False independientemente del .env.
# Previene que un FLASK_DEBUG=true accidental active el debugger de
# Werkzeug y exponga stack traces al cliente.
app.debug = False
app.config["DEBUG"] = False

# ------------------------------------------------------------------
# Configuración de logging seguro (A10:2025 — CWE-209)
# Los stack traces completos se escriben únicamente en el archivo
# 'backend_errors.log' y en consola del servidor. NUNCA se exponen
# al cliente (frontend) a través de respuestas HTTP.
# ------------------------------------------------------------------
logger = logging.getLogger("medcore_errors")
logger.setLevel(logging.ERROR)

# Handler: archivo backend_errors.log con rotación (previene DoS por Log Flooding)
_file_handler = RotatingFileHandler(
    "backend_errors.log",
    maxBytes=5 * 1024 * 1024,  # 5 MB por archivo
    backupCount=3,              # Mantener 3 backups (total: ~20 MB máx)
    encoding="utf-8",
)
_file_handler.setFormatter(
    logging.Formatter("[%(asctime)s] %(levelname)s in %(module)s: %(message)s")
)
logger.addHandler(_file_handler)

# Handler: consola del servidor (stderr)
_console_handler = logging.StreamHandler()
_console_handler.setFormatter(
    logging.Formatter("[%(asctime)s] %(levelname)s in %(module)s: %(message)s")
)
logger.addHandler(_console_handler)


# ------------------------------------------------------------------
# Helper de sanitización para logging (A10:2025 — CWE-117)
# Previene Log Forging / CRLF Injection: un atacante podría inyectar
# secuencias \r\n en parámetros de URL para fabricar entradas falsas
# en el log. Esta función elimina todos los caracteres de control.
# ------------------------------------------------------------------

def _sanitize_log_param(value):
    """Elimina caracteres de control (\r, \n, \t, etc.) de un valor antes de loguearlo."""
    if not isinstance(value, str):
        value = str(value)
    return re.sub(r'[\x00-\x1f\x7f]', '_', value)


# ------------------------------------------------------------------
# Ciclo de vida del pool de conexiones
# ------------------------------------------------------------------
# IMPORTANTE: El pool se inicializa a nivel de módulo, FUERA de
# cualquier app_context. Usar 'with app.app_context()' aquí sería
# un error: al salir del bloque 'with', Flask dispara teardown_appcontext
# y cerraría el pool antes de atender cualquier petición real.
# ------------------------------------------------------------------

# Inicializar el pool al arrancar el proceso (no necesita app context)
init_pool()

# Registrar el cierre del pool al apagar el proceso con atexit,
# que se ejecuta una sola vez cuando el servidor Flask termina.
atexit.register(close_pool)

# Bandera para ejecutar init_db() una única vez antes de la primera petición
_db_inicializada = False


@app.before_request
def bootstrap_db():
    """
    Ejecuta init_db() una sola vez antes de la primera petición HTTP.
    Usa una bandera de módulo para no repetir la inicialización en
    cada petición subsiguiente.
    """
    global _db_inicializada
    if not _db_inicializada:
        init_db()
        _db_inicializada = True


# ------------------------------------------------------------------
# Rutas de autenticación
# ------------------------------------------------------------------

@app.route("/")
def index():
    """
    GET /
    Landing page del proyecto. No requiere sesión activa.
    Muestra el contexto del laboratorio y los enlaces a las vistas vulnerables.
    """
    return render_template("index.html")


@app.route("/login", methods=["GET"])
def login_get():
    """
    GET /login
    Muestra la página de inicio de sesión.
    Si ya existe una sesión activa, redirige directamente al dashboard.
    """
    # Si el usuario ya inició sesión, no tiene sentido mostrar el login
    if "usuario_id" in session:
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login_post():
    """
    POST /login
    Procesa el formulario de inicio de sesión.

    Recibe 'username' y 'password' del formulario HTML, consulta la
    tabla 'usuarios' con SQL puro y, si las credenciales coinciden,
    almacena el id, username y rol del usuario en la sesión de Flask.

    NOTA: La consulta usa parámetros posicionales (%s) para evitar
    inyección SQL básica, aunque las contraseñas estén en texto plano.
    """
    # Obtener los datos enviados por el formulario
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    # Validación básica: los campos no deben estar vacíos
    if not username or not password:
        flash("Por favor, ingresa tu usuario y contraseña.", "warning")
        return redirect(url_for("login_get"))

    # Consulta SQL para verificar las credenciales en la tabla 'usuarios'.
    # Se usan parámetros posicionales (%s) para prevenir inyección SQL.
    # Las columnas 'username', 'password' y 'rol' deben existir en la tabla.
    sql_autenticacion = """
        SELECT id, username, rol
        FROM usuarios
        WHERE username = %s
          AND password = %s
        LIMIT 1;
    """

    usuario_encontrado = None

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                # Ejecutar la consulta pasando los valores como parámetros
                cur.execute(sql_autenticacion, (username, password))
                # fetchone() retorna una tupla o None si no hay coincidencia
                usuario_encontrado = cur.fetchone()

    except Exception as error:
        # Registrar el error en consola y mostrar un mensaje genérico al usuario
        logger.error("Error al consultar la base de datos en /login: %s", error)
        flash("Ocurrió un error interno. Intenta nuevamente.", "danger")
        return redirect(url_for("login_get"))

    if usuario_encontrado is None:
        # Las credenciales no coinciden con ningún registro
        flash("Usuario o contraseña incorrectos.", "danger")
        return redirect(url_for("login_get"))

    # Desempaquetar los datos del usuario retornados por la consulta
    usuario_id, usuario_nombre, usuario_rol = usuario_encontrado

    # Limpiar cualquier sesión previa antes de crear una nueva
    session.clear()

    # Guardar los datos del usuario autenticado en la sesión de Flask.
    # Flask firma la sesión con SECRET_KEY, por lo que no puede ser
    # manipulada desde el cliente sin invalidarla.
    session["usuario_id"]     = usuario_id
    session["usuario_nombre"] = usuario_nombre
    session["usuario_rol"]    = usuario_rol

    # Redirigir al dashboard tras el inicio de sesión exitoso
    return redirect(url_for("dashboard"))


# ------------------------------------------------------------------
# Ruta de búsqueda de pacientes (vista)
# ------------------------------------------------------------------

@app.route("/search")
def search_page():
    """
    GET /search
    Muestra la página de búsqueda de pacientes.
    Requiere sesión activa.
    """
    if "usuario_id" not in session:
        flash("Debes iniciar sesión para acceder a la búsqueda.", "warning")
        return redirect(url_for("login_get"))

    return render_template("search.html")


# ------------------------------------------------------------------
# API de búsqueda de pacientes (INTENCIONALMENTE VULNERABLE)
#
# ADVERTENCIA EDUCATIVA: Este endpoint concatena el input del usuario
# directamente en la consulta SQL para demostrar SQL Injection (A05).
# NUNCA hacer esto en producción — usar consultas parametrizadas.
# ------------------------------------------------------------------

@app.route("/patients/search")
def patients_search():
    """
    GET /patients/search?q=<término>
    Busca pacientes cuyo nombre coincida parcialmente con el término.
    Devuelve JSON.

    VULNERABLE a SQL Injection: el parámetro 'q' se concatena
    directamente en la consulta SQL (sin parámetros ni sanitización).

    Consulta original:
        SELECT id, full_name, document_id, email, phone, birth_date
        FROM patients
        WHERE full_name LIKE '%<q>%';
    """
    if "usuario_id" not in session:
        return {"error": "No autorizado"}, 401

    q = request.args.get("q", "").strip()

    if not q:
        return {"error": "Parámetro 'q' requerido"}, 400

    # VULNERABILIDAD INTENCIONAL: concatenación directa del input
    # Permite inyección SQL: ', OR, UNION, ORDER BY, etc.
    sql = (
        "SELECT id, full_name, document_id, email, phone, birth_date "
        f"FROM patients WHERE full_name LIKE '%{q}%'"
    )

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql)
                filas = cur.fetchall()
    except Exception as error:
        print(f"[app] Error en /patients/search: {error}")
        return {"error": "Error interno del servidor"}, 500

    if not filas:
        return []

    columnas = ["id", "full_name", "document_id", "email", "phone", "birth_date"]
    resultados = [dict(zip(columnas, fila)) for fila in filas]

    return resultados


# ------------------------------------------------------------------
# Ruta de perfil de paciente (INTENCIONALMENTE VULNERABLE)
#
# ADVERTENCIA EDUCATIVA: Este endpoint NO valida el tipo ni rango
# del parámetro <id>, NO usa bloques try-except y accede a una
# estructura de datos mediante indexación directa. Cualquier entrada
# inesperada (string, índice fuera de rango, caracteres especiales)
# provoca una excepción no capturada que, combinada con debug=True,
# expone el stack trace completo al navegador (CWE-209, OWASP A10).
# NUNCA hacer esto en producción.
# ------------------------------------------------------------------

# Estructura de datos simulada con información de pacientes.
# Se usa una lista (no un diccionario) para que el acceso por índice
# genere errores de tipo (TypeError) o de rango (IndexError) cuando
# el Red Team envíe payloads malformados.
PATIENTS_DATA = [
    {
        "id": 1,
        "full_name": "Carlos Mendoza",
        "document_id": "V-12345678",
        "email": "cmendoza@email.com",
        "phone": "0414-1234567",
        "birth_date": "1985-04-12",
        "diagnosis": "Hipertensión arterial",
        "blood_type": "O+",
        "allergies": "Penicilina",
    },
    {
        "id": 2,
        "full_name": "María Fernández",
        "document_id": "V-87654321",
        "email": "mfernandez@email.com",
        "phone": "0412-9876543",
        "birth_date": "1990-11-25",
        "diagnosis": "Diabetes tipo 2",
        "blood_type": "A+",
        "allergies": "Ninguna",
    },
    {
        "id": 3,
        "full_name": "José Pérez",
        "document_id": "V-11223344",
        "email": "jperez@email.com",
        "phone": "0416-1122334",
        "birth_date": "1978-02-05",
        "diagnosis": "Asma bronquial",
        "blood_type": "B-",
        "allergies": "Aspirina, Ibuprofeno",
    },
    {
        "id": 4,
        "full_name": "Ana Gómez",
        "document_id": "V-44332211",
        "email": "agomez@email.com",
        "phone": "0424-4433221",
        "birth_date": "2001-08-19",
        "diagnosis": "Gastritis crónica",
        "blood_type": "AB+",
        "allergies": "Mariscos",
    },
    {
        "id": 5,
        "full_name": "Luis Rodríguez",
        "document_id": "V-55667788",
        "email": "lrodriguez@email.com",
        "phone": "0414-5566778",
        "birth_date": "1995-12-30",
        "diagnosis": "Migraña crónica",
        "blood_type": "O-",
        "allergies": "Sulfonamidas",
    },
]


@app.route("/patients/<id>")
def patient_profile(id):
    """
    GET /patients/<id>
    Devuelve el perfil completo de un paciente según su ID.

    REMEDIADO (A10:2025 — CWE-209):
    - Valida que 'id' sea numérico antes de convertirlo.
    - Envuelve toda la lógica en try-except para capturar
      cualquier excepción inesperada.
    - Devuelve respuestas JSON sanitizadas sin revelar
      stack traces, rutas del sistema ni nombres de excepciones.
    - Los errores reales se registran en backend_errors.log.
    """
    try:
        # Validación de tipo: 'id' debe ser numérico
        if not id.isdigit():
            return jsonify({"error": "Paciente no encontrado o solicitud inválida.", "status": 400}), 400

        patient_index = int(id)

        # Validación de rango
        if patient_index < 0 or patient_index >= len(PATIENTS_DATA):
            return jsonify({"error": "Paciente no encontrado o solicitud inválida.", "status": 404}), 404

        patient = PATIENTS_DATA[patient_index]

        return render_template("profile.html", patient=patient)

    except (ValueError, TypeError, IndexError) as error:
        # Error de tipo o de índice: registrar internamente, responder genérico
        safe_id = _sanitize_log_param(id)
        logger.error("Excepción controlada en /patients/%s: %s", safe_id, error)
        return jsonify({"error": "Paciente no encontrado o solicitud inválida.", "status": 400}), 400

    except Exception as error:
        # Cualquier otro error imprevisto: registrar con traceback completo, responder genérico
        safe_id = _sanitize_log_param(id)
        logger.exception("Excepción inesperada en /patients/%s", safe_id)
        return jsonify({"error": "Error interno del servidor.", "status": 500}), 500


# ------------------------------------------------------------------
# Ruta de cierre de sesión
# ------------------------------------------------------------------

@app.route("/logout")
def logout():
    """
    GET /logout
    Elimina todos los datos de la sesión actual y redirige al login.
    """
    session.clear()
    flash("Sesión cerrada correctamente.", "info")
    return redirect(url_for("login_get"))


# ------------------------------------------------------------------
# Rutas protegidas (requieren sesión activa)
# ------------------------------------------------------------------

@app.route("/dashboard")
def dashboard():
    """
    GET /dashboard
    Vista principal protegida de la aplicación.

    Verifica que exista una sesión activa. Si no hay sesión, redirige
    al login. Si existe, renderiza el template del dashboard pasando
    el nombre y rol del usuario para personalizar la vista.
    """
    # Verificar si existe una sesión activa comprobando la clave de usuario
    if "usuario_id" not in session:
        flash("Debes iniciar sesión para acceder al dashboard.", "warning")
        return redirect(url_for("login_get"))

    # Recuperar los datos del usuario desde la sesión
    nombre_usuario = session.get("usuario_nombre")
    rol_usuario    = session.get("usuario_rol")

    # Renderizar el template pasando los datos de sesión al contexto
    # Los roles posibles son: 'medico', 'administrador', 'paciente'
    return render_template(
        "dashboard.html",
        username=nombre_usuario,
        rol=rol_usuario,
    )


# ------------------------------------------------------------------
# Hardening de cabeceras HTTP (A10:2025 — CWE-200, CWE-693)
# Se ejecuta DESPUÉS de cada respuesta para agregar cabeceras
# de seguridad que previenen fingerprinting del framework y
# hardening del navegador contra MIME sniffing.
# ------------------------------------------------------------------

@app.after_request
def agregar_cabeceras_seguridad(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Server"] = "MedCore-Server"  # Enmascara Werkzeug/Python
    return response


# ------------------------------------------------------------------
# Manejadores globales de excepciones (A10:2025 — CWE-209)
# Capturan cualquier error imprevisto en el backend y devuelven
# respuestas sanitizadas al cliente. Los stack traces reales se
# escriben únicamente en backend_errors.log y consola del servidor.
# ------------------------------------------------------------------

@app.errorhandler(404)
def pagina_no_encontrada(error):
    logger.error("404 Not Found: %s", request.url)
    return jsonify({"error": "Recurso no encontrado.", "status": 404}), 404


@app.errorhandler(500)
def error_interno_servidor(error):
    logger.exception("500 Internal Server Error: %s", request.url)
    return jsonify({"error": "Error interno del servidor.", "status": 500}), 500


@app.errorhandler(Exception)
def manejar_excepcion_global(error):
    logger.exception("Excepción no capturada: %s", request.url)
    return jsonify({"error": "Error interno del servidor.", "status": 500}), 500


# ------------------------------------------------------------------
# Punto de entrada cuando se ejecuta directamente
# ------------------------------------------------------------------

if __name__ == "__main__":
    # Ejecutar el servidor de desarrollo integrado de Flask.
    # En producción se debe usar un servidor WSGI como Gunicorn o uWSGI.
    app.run(
        host="0.0.0.0",   # Escuchar en todas las interfaces de red
        port=5000,         # Puerto por defecto de Flask
        debug=False,       # REMEDIADO: stack traces NO se exponen al cliente (A10)
    )
