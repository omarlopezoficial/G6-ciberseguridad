# Med-Core App - Manual Tecnico de Despliegue

Simulacion de Ataque Informatico y Remediacion (UCAB - Prof. Gustavo Lara Jr.)
Sub-equipo 2: Defensa y Remediacion Backend - OWASP A10:2025

---

## Stack Tecnologico

| Capa | Tecnologia | Version |
|------|-----------|---------|
| Runtime | Python | 3.11+ |
| Framework | Flask | 3.x |
| Base de datos | PostgreSQL | 14+ |
| Adaptador DB | psycopg2-binary | 2.9+ |
| Variables de entorno | python-dotenv | 1.0+ |
| Servidor WSGI (produccion) | Gunicorn | 21.x |

---

## Estructura del Proyecto

```
G6-ciberseguridad/
  app.py              # Punto de entrada principal (Flask)
  config.py           # Configuracion centralizada desde .env
  database.py         # Pool de conexiones PostgreSQL
  requirements.txt    # Dependencias de Python
  .env.example        # Plantilla de variables de entorno
  .gitignore          # Archivos excluidos del repositorio
  templates/
    login.html        # Pagina de inicio de sesion
    dashboard.html    # Panel principal (vista protegida)
    search.html       # Busqueda de pacientes
    profile.html      # Perfil de paciente
    index.html        # Pagina de inicio
```

---

## Prerequisitos

- Python 3.11 o superior
- PostgreSQL 14 o superior
- pip (gestor de paquetes de Python)
- Git

---

## Paso 1: Clonar el Repositorio

```bash
git clone https://github.com/omarlopezoficial/G6-ciberseguridad.git
cd G6-ciberseguridad
git checkout version-sanitizada
```

---

## Paso 2: Crear el Entorno Virtual

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/macOS
source venv/bin/activate
```

---

## Paso 3: Instalar Dependencias

```bash
pip install -r requirements.txt
```

---

## Paso 4: Configurar Variables de Entorno

```bash
# Copiar la plantilla
copy .env.example .env   # Windows
cp .env.example .env     # Linux/macOS
```

Editar el archivo `.env` con los valores reales:

```ini
# Flask
SECRET_KEY=tu-clave-secreta-aqui-muy-larga-y-aleatoria
FLASK_DEBUG=false

# PostgreSQL
DB_HOST=localhost
DB_NAME=med_core_db
DB_USER=postgres
DB_PASSWORD=tu-password-aqui
DB_PORT=5432
```

> **IMPORTANTE:** Nunca commitear el archivo `.env` al repositorio. Ya esta excluido en `.gitignore`.

---

## Paso 5: Configurar la Base de Datos

Conectar a PostgreSQL y crear la base de datos y tablas:

```sql
-- Crear la base de datos
CREATE DATABASE med_core_db;

-- Conectar a la base de datos
\c med_core_db

-- Tabla de usuarios (Sub-equipo 1 - autenticacion)
CREATE TABLE usuarios (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    rol VARCHAR(20) NOT NULL
);

-- Tabla de pacientes (Sub-equipo 1 - SQL Injection)
CREATE TABLE patients (
    id SERIAL PRIMARY KEY,
    full_name VARCHAR(100) NOT NULL,
    document_id VARCHAR(20),
    email VARCHAR(100),
    phone VARCHAR(20),
    birth_date DATE
);

-- Insertar usuario de prueba
INSERT INTO usuarios (username, password, rol)
VALUES ('admin', 'admin123', 'administrador');

-- Insertar pacientes de prueba
INSERT INTO patients (full_name, document_id, email, phone, birth_date)
VALUES
    ('Carlos Mendoza', 'V-12345678', 'cmendoza@email.com', '0414-1234567', '1985-04-12'),
    ('Maria Fernandez', 'V-87654321', 'mfernandez@email.com', '0412-9876543', '1990-11-25'),
    ('Jose Perez', 'V-11223344', 'jperez@email.com', '0416-1122334', '1978-02-05');
```

---

## Paso 6: Ejecutar la Aplicacion

```bash
python app.py
```

El servidor estara disponible en:

```
http://localhost:5000
```

---

## Endpoints Disponibles

| Ruta | Metodo | Descripcion | Autenticacion |
|------|--------|-------------|---------------|
| `/login` | GET | Formulario de login | No |
| `/login` | POST | Procesar login | No |
| `/dashboard` | GET | Panel principal | Si |
| `/search` | GET | Pagina de busqueda | Si |
| `/patients/search?q=` | GET | API busqueda (remediada) | Si |
| `/patients/<id>` | GET | Perfil de paciente | No |
| `/logout` | GET | Cerrar sesion | Si |

---

## Remediaciones de Seguridad Implementadas (OWASP A10:2025)

### Desactivacion de Debug

- `app.debug = False` forzado por codigo (3 puntos de anclaje)
- `app.config["DEBUG"] = False` sobreescribe cualquier `.env`
- `app.run(debug=False)` en el punto de entrada
- Previene la exposicion de stack traces y el Interactive Debugger de Werkzeug

### Manejo de Excepciones en `/patients/<id>`

- Validacion de tipo: `id.isdigit()` antes de `int()`
- Validacion de rango: verificacion de limites de la lista
- Bloque `try-except` de dos niveles:
  - `ValueError, TypeError, IndexError` para errores esperados
  - `Exception` para errores imprevistos
- Respuestas JSON sanitizadas en todos los casos

### Global Error Handlers

```python
@app.errorhandler(404)    # Rutas inexistentes
@app.errorhandler(500)    # Errores internos
@app.errorhandler(Exception)  # Cualquier excepcion no capturada
```

Todos devuelven JSON generico: `{"error": "...", "status": 4xx/5xx}`

### Logging Seguro

- `RotatingFileHandler` con maxBytes=5MB y backupCount=3
- Archivo de log: `backend_errors.log` (no trackeado por git)
- Stack traces completos se escriben SOLO en el log, nunca al cliente
- Formato: `[timestamp] LEVEL in module: message`

### Prevencion de Log Forging

- Funcion `_sanitize_log_param()` elimina caracteres de control (`\r`, `\n`, `\t`)
- Parametro `id` se sanitiza antes de pasarlo al logger
- Previene inyeccion CRLF en archivos de log

### Hardening de Cabeceras HTTP

```python
@app.after_request
def agregar_cabeceras_seguridad(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Server"] = "MedCore-Server"
    return response
```

- `X-Content-Type-Options: nosniff` previene MIME sniffing
- `Server: MedCore-Server` enmascara Werkzeug/Python (anti-fingerprinting)

---

### Remediación A05:2025 — SQL Injection

Se corrigió la vulnerabilidad de inyección SQL en `/patients/search` reemplazando la concatenación directa de strings por consultas parametrizadas con psycopg2:

```python
# ANTES (vulnerable)
sql = f"SELECT ... FROM patients WHERE full_name LIKE '%{q}%'"
cur.execute(sql)

# DESPUÉS (remediado)
like_pattern = f"%{q}%"
sql = "SELECT ... FROM patients WHERE full_name ILIKE %s"
cur.execute(sql, (like_pattern,))

Esto convierte cualquier payload malicioso (' OR '1'='1, UNION SELECT, etc.) en texto de búsqueda literal, imposibilitando la inyección SQL.

---

## Produccion (Gunicorn)

```bash
pip install gunicorn

# Ejecutar con 4 workers
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

> En produccion, no usar el servidor de desarrollo de Flask (`app.py`). Usar Gunicorn o uWSGI.

---

## Equipo

David Crespo — C.I: 30.497.143

Andres Martinez — C.I: 29.686.554

Edwin Li — C.I: 29.845.709

Omar Lopez — C.I: 20.896.095

Diego Flores — C.I: 31.290.731

Jose Bozzelli — C.I: 30.142.780
