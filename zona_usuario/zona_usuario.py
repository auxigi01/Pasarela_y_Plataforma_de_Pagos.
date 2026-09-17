from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_mysqldb import MySQL
from flask_mail import Mail, Message
from datetime import datetime, timedelta
from functools import wraps
from flask import make_response
from dotenv import load_dotenv
from PIL import Image, ImageDraw, ImageFont
from datetime import timedelta
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from urllib.parse import urlencode
from email.header import Header
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from email.message import EmailMessage
from flask import Flask, request, send_file, jsonify
from decimal import Decimal, InvalidOperation
import random, string, os
import logging
import uuid 
import requests
import secrets
import pdfkit
import MySQLdb.cursors  # Importa DictCursor
import base64
import hashlib
import pytz
import hmac
import tempfile
import socket
import locale
import re
import json
import logging
import time
import os
from datetime import datetime
import threading
from random import randint
import psycopg2
from psycopg2.extras import RealDictCursor
from flask_wtf.csrf import CSRFProtect
from flask_wtf.csrf import CSRFError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask import jsonify
from flask_talisman import Talisman
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash


load_dotenv()

app = Flask(__name__, template_folder='templates')



limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[]
)
csrf = CSRFProtect(app)

APP_ENV = os.getenv("APP_ENV", "QA")

if APP_ENV == "PROD":

    csp = {

        "default-src": [
            "'self'"
        ],

        "script-src": [
            "'self'",
            "'unsafe-inline'",
            "https://code.jquery.com",
            "https://cdn.jsdelivr.net",
            "https://cdnjs.cloudflare.com",
            "https://stackpath.bootstrapcdn.com"
        ],

        "style-src": [
            "'self'",
            "'unsafe-inline'",
            "https://fonts.googleapis.com",
            "https://stackpath.bootstrapcdn.com",
            "https://cdn.jsdelivr.net",
            "https://cdnjs.cloudflare.com"
        ],

        "font-src": [
            "'self'",
            "data:",
            "https://fonts.gstatic.com",
            "https://cdnjs.cloudflare.com",
            "https://cdn.jsdelivr.net"
        ],

        "img-src": [
            "'self'",
            "data:",
            "blob:"
        ],

        "connect-src": [
            "'self'"
        ],

        "object-src": [
            "'none'"
        ],

        "frame-src": [
            "'self'"
        ],

        "media-src": [
            "'self'",
            "blob:"
        ],

        "worker-src": [
            "'self'",
            "blob:"
        ],

        "manifest-src": [
            "'self'"
        ],

        "base-uri": [
            "'self'"
        ],

        "form-action": [
            "'self'"
        ],

        "frame-ancestors": [
            "'self'"
        ]
    }

    Talisman(
        app,
        force_https=APP_ENV == "PROD",
        content_security_policy=csp,
        strict_transport_security=APP_ENV == "PROD",
        session_cookie_secure=APP_ENV == "PROD",
        session_cookie_http_only=True
    )

app.secret_key = os.getenv("SECRET_KEY")

app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)

app.config["SESSION_COOKIE_HTTPONLY"] = True

app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

app.config["SESSION_REFRESH_EACH_REQUEST"] = True

if APP_ENV == "PROD":
    app.config["SESSION_COOKIE_SECURE"] = True
else:
    app.config["SESSION_COOKIE_SECURE"] = False



# 1. Configuración para: Zona Usuario (ZU)
app.config['ZU_PG_HOST'] = os.getenv('ZU_PG_HOST')
app.config['ZU_PG_PORT'] = int(os.getenv('ZU_PG_PORT', 5440))
app.config['ZU_PG_USER'] = os.getenv('ZU_PG_USER')
app.config['ZU_PG_PASSWORD'] = os.getenv('ZU_PG_PASSWORD')
app.config['ZU_PG_DB'] = os.getenv('ZU_PG_DB')

# 2. Configuración para: Web Rescarven (WR)
app.config['WR_PG_HOST'] = os.getenv('WR_PG_HOST')
app.config['WR_PG_PORT'] = int(os.getenv('WR_PG_PORT', 5440))
app.config['WR_PG_USER'] = os.getenv('WR_PG_USER')
app.config['WR_PG_PASSWORD'] = os.getenv('WR_PG_PASSWORD')
app.config['WR_PG_DB'] = os.getenv('WR_PG_DB')

# ==============================================================================
# FUNCIONES PARA OBTENER LAS CONEXIONES
# ==============================================================================

# Conexión exclusiva para Zona Usuario
def get_zu_db_connection():
    conn = psycopg2.connect(
        host=app.config['ZU_PG_HOST'],
        port=app.config['ZU_PG_PORT'],
        user=app.config['ZU_PG_USER'],
        password=app.config['ZU_PG_PASSWORD'],
        dbname=app.config['ZU_PG_DB']
    )
    return conn

# Conexión exclusiva para Web Rescarven
def get_wr_db_connection():
    conn = psycopg2.connect(
        host=app.config['WR_PG_HOST'],
        port=app.config['WR_PG_PORT'],
        user=app.config['WR_PG_USER'],
        password=app.config['WR_PG_PASSWORD'],
        dbname=app.config['WR_PG_DB']
    )
    return conn

# Configuraciones de Flask-Mail
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')
mail = Mail(app)

# Obtener el nombre del remitente desde las variables de entorno
sender_name = os.getenv('SENDER_NAME')

@app.errorhandler(CSRFError)
def handle_csrf_error(e):

    logging.warning(f"CSRF detectado: {e.description}")

    flash(
        "Su sesion expiró. Cargue la página nuevamente e intente otra vez.",
        "login_error"
    )

    return redirect(url_for("inicio"))

@app.errorhandler(429)
def ratelimit_handler(e):

    logging.warning(
        f"Demasiados intentos desde {request.remote_addr}"
    )

    flash(
        "Has excedido el número de intentos. Intenta nuevamente más tarde.",
        "login_error"
    )

    return redirect(url_for("inicio"))

def no_cache(view):
    @wraps(view)
    def no_cache_wrapper(*args, **kwargs):
        response = make_response(view(*args, **kwargs))
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '-1'
        return response
    return no_cache_wrapper

# Nombre base del archivo de log
log_folder = "log"

# Crear la carpeta si no existe
if not os.path.exists(log_folder):
    os.makedirs(log_folder)
    log_message = f"Carpeta '{log_folder}' creada en {os.path.abspath(log_folder)}"
    print(log_message)
    logging.basicConfig(level=logging.INFO)
    logging.info(log_message)

# Nombre base del archivo de log dentro de la carpeta
log_file = os.path.join(log_folder, "accesos.log")

# Configurar logging
logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    encoding="utf-8",
)

logger = logging.getLogger("my_logger")

# Función para crear un nuevo archivo de log cada 24 horas
def rotate_log_periodically():
    while True:
        time.sleep(86400)  # Esperar 24 horas (86400 segundos)

        # Renombrar el archivo de log con la fecha actual
        timestamp = datetime.now().strftime("%Y-%m-%d")
        new_log_file = os.path.join(log_folder, f"accesos_{timestamp}.log")

        if os.path.exists(log_file):
            os.rename(log_file, new_log_file)

        # Crear un nuevo log vacío
        open(log_file, "w").close()

        logger.info(f"Nuevo archivo de log creado: {new_log_file}")

# Iniciar el proceso en segundo plano
thread = threading.Thread(target=rotate_log_periodically, daemon=True)
thread.start()

# Mantener logs esenciales de Flask, pero silenciar peticiones innecesarias
log = logging.getLogger("werkzeug")
log.setLevel(logging.WARNING)

api_consultas = os.getenv("API_CONSULTAS")

if api_consultas:
    logging.info(f"API_CONSULTAS está definida y tiene el valor: {api_consultas}")
else:
    logging.warning("API_CONSULTAS no está definida o no tiene valor.")

@app.route('/')
def inicio():
    logging.info(f"Se accedio a la pagina")

    return render_template('inicio.html')
  
def desencriptar_datos(datos_cifrados, token):
    try:
        fernet = Fernet(token)
        datos_bytes = datos_cifrados.encode()
        datos_desencriptados = fernet.decrypt(datos_bytes)
        return json.loads(datos_desencriptados.decode())
    except Exception as e:
        return []

def generar_captcha():
    texto = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    session['captcha'] = texto  

    # Crear imagen CAPTCHA con fondo transparente (RGBA)
    ancho, alto = 150, 20  
    imagen = Image.new('RGBA', (ancho, alto), (255, 255, 255, 0))  
    draw = ImageDraw.Draw(imagen)

    # Cargar fuente y ajustar tamaño del texto
    try:
        font = ImageFont.truetype('arial.ttf', 14)  
    except IOError:
        font = ImageFont.load_default()  

    # Calcular las coordenadas para centrar el texto
    bbox = draw.textbbox((0, 0), texto, font=font)  
    texto_ancho = bbox[2] - bbox[0]  
    texto_alto = bbox[3] - bbox[1]  

    # Calcular las coordenadas para centrar el texto
    x = (ancho - texto_ancho) // 2
    y = (alto - texto_alto) // 2

    draw.text((x, y), texto, font=font, fill=(0, 0, 0))

    # Guardar imagen en carpeta estática
    base_dir = os.path.abspath(os.path.dirname(__file__))
    img_dir = os.path.join(base_dir, 'static', 'img')
    if not os.path.exists(img_dir):
        os.makedirs(img_dir)

    path_captcha = os.path.join(img_dir, 'captcha.png')
    imagen.save(path_captcha, format='PNG') 
    return path_captcha

@app.route('/registro')
def registro():
    generar_captcha()  
    version = randint(1, 999999)
    return render_template('registrarse.html', captcha_path='img/captcha.png', version=version)

X_ENVIOREMENT = os.getenv('X_ENVIOREMENT')
ID_COMERCIO_API = os.getenv('ID_COMERCIO_API')

headers_api_rescarven = {
    "Content-Type": "application/json",
    "id-comercio": ID_COMERCIO_API,
    "X-Environment": X_ENVIOREMENT
}
token_api_rescarven = os.getenv('token_api_rescarven')


@app.route('/registro', methods=['POST'])
def registro_post():
    email = request.form.get("email", "").strip().lower()
    ci = request.form.get("ci_login", "").strip()
    tipo_documento = request.form.get('tipo_documento')  
    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")
    captcha = request.form.get("captcha", "").strip()
    ci_pagador = f"{tipo_documento}{ci}".upper().strip()

    logging.info(f"Intento de registro - Email: {email}, CI: {ci_pagador}")
    
    if len(email) > 40:
        flash("Correo inválido", "register_error")
        return redirect(url_for("registro"))
    
    if len(ci) > 15:
        flash("Documento inválido", "register_error")
        return redirect(url_for("registro"))

    # Verificar CAPTCHA
    if captcha.upper() != session.get('captcha', ''):
        session.pop("captcha", None)
        logging.info(f"Registro fallido - CAPTCHA incorrecto para {email}")
        flash("El CAPTCHA es incorrecto", "register_error")
        return redirect(url_for('registro'))
    
    if len(password) < 12 or len(password) > 64:
        flash(
            "La contraseña debe tener entre 12 y 64 caracteres.",
            "register_error"
        )
        return redirect(url_for("registro"))
    
    if not re.search(r"[A-Z]", password):
        flash(
            "La contraseña debe contener al menos una letra mayúscula.",
            "register_error"
        )
        return redirect(url_for("registro"))
    
    if not re.search(r"[a-z]", password):
        flash(
            "La contraseña debe contener una letra minúscula.",
            "register_error"
        )
        return redirect(url_for("registro"))
    
    if not re.search(r"\d", password):
        flash(
            "La contraseña debe contener un número.",
            "register_error"
        )
        return redirect(url_for("registro"))
    
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", password):
        flash(
            "La contraseña debe contener un carácter especial.",
            "register_error"
        )
        return redirect(url_for("registro"))

    # Verificar si las contraseñas coinciden
    if password != confirm_password:
        logging.info(f"Registro fallido - Contrasenas no coinciden para {email}")
        flash("Las contraseñas no coinciden", "register_error")
        return redirect(url_for('registro'))

    # Consultar API externa
    API_CONSULTAS = os.getenv('API_CONSULTAS')
    api_url_usuarios = f"{API_CONSULTAS}/apiusuarios"

    try:
        response = requests.post(api_url_usuarios, json={'ci_pagador': ci_pagador}, headers=headers_api_rescarven)
        if APP_ENV == "QA":
            print(response.status_code)
            print(response.text)

        if response.status_code == 200:
            api_response = response.json()
            datos_desencriptados = desencriptar_datos(api_response.get('datos_usuarios', ''), token_api_rescarven)
            if APP_ENV == "QA":
                print(datos_desencriptados)

            if 'mensaje' in datos_desencriptados and datos_desencriptados['mensaje'] == 'OK':
                logging.info(f"Registro - CI {ci_pagador} validada en API externa")
            else:
                logging.info(f"Registro fallido - CI {ci_pagador} no encontrada en API externa")
                return redirect(url_for('registro'))
            
        elif response.status_code == 404:
            logging.info(f"Registro fallido - CI {ci_pagador} no encontrada en API externa (404)")
            flash("Cédula no encontrada en ningún sistema externo", "register_error")
            return redirect(url_for('registro'))

        else:
            logging.info(f"Registro fallido - Error en API para CI {ci_pagador} (Código: {response.status_code})")
            flash("Error al consultar las APIs a través de la API intermediaria", "register_error")
            return redirect(url_for('registro'))

    except requests.exceptions.RequestException as e:
        logging.info(f"Registro fallido - Fallo de conexión con API: {str(e)}")
        flash("Error al conectar con la API intermediaria", "register_error")
        return redirect(url_for('registro'))


    # ==============================================================================
    # NUEVA LÓGICA DE GUARDADO (ESQUEMA: data_general) - CONEXIÓN WR
    # ==============================================================================
    conn = get_wr_db_connection() # Usamos la conexión centralizada de Web Rescarven
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        # 1. Verificar si ya existe el correo, cédula o usuario en data_general.usuarios
        cur.execute("SELECT id_usuario FROM data_general.usuarios WHERE correo = %s", (email,))
        email_existente = cur.fetchone()

        cur.execute("SELECT id_usuario FROM data_general.usuarios WHERE cedula = %s", (ci_pagador,))
        ci_existente = cur.fetchone()

        if email_existente:
            logging.info(f"Registro fallido - Email ya registrado: {email}")
            flash("Este correo ya está registrado", "register_error")
            return redirect(url_for('registro'))

        if ci_existente:
            logging.info(f"Registro fallido - CI ya registrada: {ci_pagador}")
            flash("Esta CI ya está registrada", "register_error")
            return redirect(url_for('registro'))

        # 2. Cifrar la contraseña
        hashed_password = generate_password_hash(password)
        
        # 3. PASO 1: Insertar en la tabla principal de usuarios y retornar el ID generado
        cur.execute(
            """
            INSERT INTO data_general.usuarios ( cedula, correo, contrasena) 
            VALUES (%s,%s, %s) 
            RETURNING id_usuario;
            """, 
            (ci_pagador, email, hashed_password)
        )
        # Obtenemos el ID que Postgres le acaba de asignar a este usuario
        id_usuario_nuevo = cur.fetchone()['id_usuario']

        # 4. PASO 2: Insertar en la tabla de permisos relacionándolo con Zona Usuario (ID = 1)
        id_sistema_zona_usuario = 1
        cur.execute(
            """
            INSERT INTO data_general.permisos_usuarios (id_usuario, id_sistema) 
            VALUES (%s, %s);
            """, 
            (id_usuario_nuevo, id_sistema_zona_usuario)
        )
        
        # Registrar al usuario en la base de datos de Zona Usuario
        conn_r4 = get_zu_db_connection()
        cur_r4 = conn_r4.cursor()

        cur_r4.execute(
            """
            INSERT INTO aplication_web.usuarios
            (id_usuario, rol)
            VALUES (%s,%s)
            """,
            (
                id_usuario_nuevo,
                "usuario"
            )
        )

        conn_r4.commit()
        cur_r4.close()
        conn_r4.close()
        
        # Confirmamos la transacción completa de ambas tablas de forma segura
        conn.commit() 
        logging.info(f"Registro exitoso - Usuario creado: {email}, Conectado al Sistema: {id_sistema_zona_usuario}")
        flash("Registro exitoso", "login_success")
        
    except Exception as err:
        conn.rollback() # Si algo falla, revierte los cambios para no dejar datos corruptos
        logging.error(f"Error en la base de datos durante el registro: {str(err)}")
        print(f"Error en la base de datos durante el registro: {str(err)}")
        flash("Ocurrió un error interno al procesar el registro", "register_error")
        return redirect(url_for('registro'))
        
    finally:
        cur.close()
        conn.close()

    return redirect(url_for('inicio'))

@app.route('/iniciarsesion', methods=['POST'])
@limiter.limit("5 per 15 minutes")
def iniciarsesion():
    email = request.form.get("email", "").strip().lower()

    password = request.form.get("password", "")
    
    if len(email) > 40:
        flash("Correo o contraseña incorrectos", "login_error")
        return redirect(url_for("inicio"))

    if len(password) < 12 or len(password) > 64:
        flash("Correo o contraseña incorrectos", "login_error")
        return redirect(url_for("inicio"))
    
    logging.info(f"Intento de inicio de sesión - Email: {email}")

    # ==============================================================================
    # NUEVA CONEXIÓN CENTRALIZADA (ESQUEMA: data_general)
    # ==============================================================================
    conn = get_wr_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    # Buscamos al usuario en la nueva tabla general
    cur.execute(
        """
        SELECT id_usuario, usuario, cedula, correo, contrasena 
        FROM data_general.usuarios 
        WHERE correo = %s
        """, 
        (email,)
    )
    user = cur.fetchone()
    
    cur.close()
    conn.close()

    if user:

        password_guardada = user["contrasena"]
        login_correcto = False

        # Usuarios nuevos (Werkzeug)
        if password_guardada.startswith("pbkdf2:") or password_guardada.startswith("scrypt:"):
            login_correcto = check_password_hash(password_guardada, password)

        # Usuarios antiguos (SHA256)
        else:
            sha = hashlib.sha256(password.encode()).hexdigest()

            if sha == password_guardada:
                login_correcto = True

                # Migrar automáticamente al nuevo algoritmo
                nueva_password = generate_password_hash(password)

                conn_update = get_wr_db_connection()
                cur_update = conn_update.cursor()

                cur_update.execute(
                    """
                    UPDATE data_general.usuarios
                    SET contrasena = %s
                    WHERE id_usuario = %s
                    """,
                    (nueva_password, user["id_usuario"])
                )

                conn_update.commit()
                cur_update.close()
                conn_update.close()

        if login_correcto:

            session.clear()
            
            # ==============================================================================
            # VERIFICACIÓN DE PERMISOS PARA ESTE SISTEMA (ZONA USUARIO = ID 1)
            # ==============================================================================
            conn_permiso = get_wr_db_connection()
            cur_permiso = conn_permiso.cursor(cursor_factory=RealDictCursor)
            
            id_sistema_zona_usuario = 1
            cur_permiso.execute(
                """
                SELECT id_permiso 
                FROM data_general.permisos_usuarios 
                WHERE id_usuario = %s AND id_sistema = %s
                """, 
                (user['id_usuario'], id_sistema_zona_usuario)
            )
            tiene_permiso = cur_permiso.fetchone()
            
            cur_permiso.close()
            conn_permiso.close()
            
            if not tiene_permiso:
                logging.info(f"Inicio de sesión fallido - Usuario {email} no tiene permisos para Zona Usuario")
                flash("No tienes acceso autorizado para este sistema.", "login_error")
                return redirect(url_for('inicio'))
            
            # Consultar el rol específico de Zona Usuario
            conn_r4 = get_zu_db_connection()
            cur_r4 = conn_r4.cursor(cursor_factory=RealDictCursor)

            cur_r4.execute(
                """
                SELECT rol
                FROM aplication_web.usuarios
                WHERE id_usuario = %s
                """,
                (user["id_usuario"],)
            )

            rol_usuario = cur_r4.fetchone()

            cur_r4.close()
            conn_r4.close()
            
            
            
            # ==============================================================================
            # ASIGNACIÓN DE VARIABLES DE SESIÓN (Nombres de columnas actualizados)
            # ==============================================================================
            session['user_id'] = user['id_usuario'] 
            session['email'] = user['correo']       
            session['ci_pagador'] = user['cedula']  
            if rol_usuario:
                session["user_role"] = rol_usuario["rol"].lower()
            else:
                session["user_role"] = "usuario"
            session.permanent = True

            logging.info(f"Inicio de sesión exitoso - Email: {email}")
            
            if session["user_role"] == "admin1":
                logging.info(f"Usuario admin1 redirigido a PagoMovil - Email: {email}")
                return redirect(url_for("pagomovil"))

            elif session["user_role"] == "admin2":
                logging.info(f"Usuario admin2 redirigido a MiBanco - Email: {email}")
                return redirect(url_for("mibanco"))


            # Proceder con la lógica de las APIs usando la cédula de la base de datos
            ci_pagador = user['cedula'] 

            if not token_api_rescarven:
                logging.info(f"Inicio de sesión fallido - No se pudo obtener el token de cifrado para {email}")
                flash("No se pudo obtener el token de cifrado", "login_error")
                return redirect(url_for('inicio'))

            # Llamar a la API intermediaria para obtener los datos cifrados
            API_CONSULTAS = f"{os.getenv('API_CONSULTAS')}/apiusuarios"

            try:
                response = requests.post(API_CONSULTAS, json={"ci_pagador": ci_pagador}, headers=headers_api_rescarven)
                if APP_ENV == "QA":

                    print(response.status_code)

                    print(response.text)
                
                if response.status_code == 200:
                    data_cifrada = response.json().get('datos_usuarios', None)

                    if data_cifrada:
                        try:
                            datos_desencriptados = desencriptar_datos(data_cifrada, token_api_rescarven)
                            nombre = datos_desencriptados.get('pagador', {}).get('nombre', '')
                            apellido = datos_desencriptados.get('pagador', {}).get('apellido', '')

                            session['nombre'] = nombre
                            session['apellido'] = apellido

                            logging.info(f"Datos desencriptados con éxito - Nombre: {nombre}, Apellido: {apellido}, Email: {email}")
                            print(f"CI del pagador: {ci_pagador}")

                            return redirect(url_for('paginaprincipal'))
                        except Exception as e:
                            logging.error(f"Error al desencriptar: {e}")
                            flash(
                                "Ocurrió un error interno. Intente nuevamente.",
                                "login_error"
                            )
                            return redirect(url_for('inicio'))
                    else:
                        logging.info(f"No se recibieron datos válidos desde la API intermediaria para {email}")
                        flash("No se recibieron datos válidos desde la API intermediaria", "login_error")
                else:
                    logging.info(f"Error de conexión con la API intermediaria para {email}: Código {response.status_code}")
                    flash(f"Error al conectar con la API intermediaria: {response.status_code}", "login_error")

            except requests.exceptions.ConnectionError as e:
                logging.info(f"Error de conexión con la API intermediaria para {email}: {e}")
                flash("Error al conectar con la API intermediaria.", "login_error")

        else:
            logging.info(f"Inicio de sesión fallido - Contraseña incorrecta para {email}")
            flash("Correo o contraseña incorrectos", "login_error")
    else:
        logging.info(f"Inicio de sesión fallido - Correo no registrado: {email}")
        flash("Correo o contraseña incorrectos", "login_error")

    return redirect(url_for('inicio'))

@app.route('/extend_session')
def extend_session():
    if 'user_id' in session:  
        session.permanent = True  
        logging.info(f"Sesion extendida - Usuario ID: {session['user_id']}, Email: {session.get('email', 'Desconocido')}")
        return jsonify({'status': 'Session extended'})
    else:
        logging.info("Intento de extender sesion sin usuario activo")
        return jsonify({'status': 'No active session'}), 401

@app.route('/logout')
def logout():
    if 'user_id' in session:
        logging.info(f"Email: {session.get('email', 'Desconocido')} cerro sesion")
    else:
        logging.info("Cierre de sesion sin usuario autenticado")

    session.clear()
    return redirect(url_for('inicio'))

@app.route('/recuperar-contraseña') 
def recuperar_contraseña():
    return render_template('recuperar_contrasena.html')

# URL de la API para enviar correos
API_CORREO = os.getenv('API_CORREO')

# Función para generar token
def generate_token(email):
    return f"TOKEN-{email}-{datetime.now().timestamp()}"

@app.route('/recuperar-contraseña', methods=['POST'])
def recuperar_contraseña_post():
    try:
        email = request.form.get("email_recuperar", "").strip().lower()

        if not email:
            flash('El campo de correo es obligatorio.', 'error')
            return redirect(url_for('recuperar_contraseña'))

        # 1. Verificar si el usuario existe en la tabla general
        conn = get_wr_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        cur.execute("SELECT id_usuario, correo FROM data_general.usuarios WHERE correo = %s", (email,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if user:
            token = generate_token()
            expiration_time = datetime.now() + timedelta(hours=1)

            # 2. Guardar el token en la NUEVA tabla independiente
            conn = get_wr_db_connection()
            cur = conn.cursor(cursor_factory=RealDictCursor)
            
            print(token)
            print(len(token))
            
            # Insertamos la solicitud de recuperación apuntando al id_usuario
            cur.execute(
                """
                INSERT INTO data_general.tokens_recuperacion
                    (id_usuario, token, fecha_expiracion, utilizado)
                VALUES (%s, %s, %s, FALSE)
                """,
                (
                    user['id_usuario'],
                    token,
                    expiration_time
                )
            )
            conn.commit()
            cur.close()
            conn.close()

            # Construir el enlace de recuperación
            reset_link = url_for('reset_password', token=token, _external=True)
            print(reset_link)
            # Preparar datos para enviar a la API
            data = {
                        "destinatarios": [email],
                        "asunto": "Rescarven - Recuperar Contraseña",
                        "mensaje": {
                            "tipo": "html",
                            "contenido":f"""
                            <!DOCTYPE html>
                            <html lang="es">
                            <head>
                            <meta charset="UTF-8">
                            <meta name="viewport" content="width=device-width, initial-scale=1.0">
                            <style>
                                body {{
                                margin: 0;
                                padding: 0;
                                font-family: Arial, sans-serif;
                                }}

                                .contenedor {{
                                max-width: 95%;
                                width: 500px;
                                margin: auto;
                                padding: 20px;
                                border-radius: 15px;
                                border: 1px solid #0091ff;
                                background-color: white;
                                text-align: center;
                                box-sizing: border-box;
                                }}

                                .logo img {{
                                width: 70%;
                                max-width: 400px;
                                height: auto;
                                border-radius: 10px;
                                }}

                                .logo-secundario {{
                                margin-top: 15px;
                                }}

                                .logo-secundario img {{
                                width: 100%;
                                max-width: 200px;
                                height: auto;
                                }}

                                .texto {{
                                color: black;
                                font-size: 0.9rem;
                                text-align: left;
                                margin-top: 10px;
                                }}

                                .pie {{
                                font-size: 0.8rem;
                                color: #0091ff;
                                text-align: center;
                                margin-top: 20px;
                                }}

                                .nota {{
                                text-align: center;
                                font-size: 0.85rem;
                                color: rgb(116, 116, 116);
                                margin-top: 10px;
                                }}

                                @media (max-width: 480px) {{
                                .contenedor {{
                                    padding: 15px;
                                }}

                                .texto {{
                                    font-size: 1rem;
                                }}

                                .logo img {{
                                    max-width: 100vw;
                                }}

                                .logo-secundario img {{
                                    max-width: 50vw;
                                }}

                                .pie {{
                                    font-size: 0.75rem;
                                }}

                                .nota {{
                                    font-size: 0.8rem;
                                }}
                                }}
                            </style>
                            </head>
                            <body>
                            <div class="contenedor">
                                <div class="logo">
                                <img src="https://api.rescarven.com/imagenes/logorescarven.png" alt="Logo Rescarven">
                                </div>

                                <div class="logo-secundario">
                                <img src="https://api.rescarven.com/imagenes/imagencorreo.jpg alt="Decorativo">
                                </div>

                                <div class="texto">
                                <p>Un cordial saludo de Rescarven,</p><br>
                                <p>Recibimos una solicitud para <b>restablecer tu contraseña</b>. Para continuar, haz clic en el siguiente botón:</p>
                                <div style="text-align: center; margin: 20px 0;">
                                    <a href="{reset_link}" style="
                                    background-color: #007BFF; 
                                    color: white; 
                                    padding: 10px 18px; 
                                    text-decoration: none; 
                                    border-radius: 5px;
                                    font-size: 1rem;">
                                    Restablecer contraseña
                                    </a>
                                </div>
                                <p>Si tiene alguna duda o necesita más información, no dude en contactarnos.</p>
                                <p>¡Gracias por confiar en nosotros!</p><br>
                                <p>- El equipo de Rescarven</p>
                                </div>
                            </div>

                            <div class="pie">
                                <p style="margin: 0;">Rescarven - Atención al cliente (0212) 628.25.00.</p>
                                <p style="margin: 0;">© 2025 Rescarven</p>
                            </div>

                            <p class="nota">Por favor, no responder a este correo</p>
                            </body>
                            </html>
                            """ }
                                    }

            # Convertir el diccionario a JSON
            json_data = json.dumps(data, ensure_ascii=False)

            # Enviar la solicitud POST con JSON
            response = requests.post(API_CORREO, data={"datos": json.dumps(data)})

            if response.status_code == 200:
                logging.info(f"Solicitud de recuperacion de contrasena para {email}")
                flash('Se ha enviado un correo con instrucciones para restablecer tu contraseña', 'info')
            else:
                logging.warning(f"Error al enviar correo de recuperación a: {email}")
                flash(f'Error al enviar el correo: {response.text}', 'error')

            return redirect(url_for('recuperar_contraseña'))

        else:
            flash('No se encontró ninguna cuenta asociada con este correo electrónico', 'error')
            return redirect(url_for('recuperar_contraseña'))

    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('recuperar_contraseña'))


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if request.method == 'POST':
        new_password = request.form['new_password']
        
        if len(new_password) < 12 or len(new_password) > 64:
            flash(
                "La contraseña debe tener entre 12 y 64 caracteres.",
                "danger"
            )
            return redirect(url_for("reset_password", token=token))
        
        if not re.search(r"[A-Z]", new_password):
            flash(
                "La contraseña debe contener al menos una letra mayúscula.",
                "register_error"
            )
            return redirect(url_for("reset_password", token=token))
        
        if not re.search(r"[a-z]", new_password):
            flash(
                "La contraseña debe contener una letra minúscula.",
                "register_error"
            )
            return redirect(url_for("reset_password", token=token))
    
        if not re.search(r"\d", new_password):
            flash(
                "La contraseña debe contener un número.",
                "register_error"
            )
            return redirect(url_for("reset_password", token=token))
    
        if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", new_password):
            flash(
                "La contraseña debe contener un carácter especial.",
                "register_error"
            )
            return redirect(url_for("reset_password", token=token))

        conn = get_wr_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        
        # 3. Validar el token consultando la tabla de tokens unida (JOIN) a la de usuarios
        cur.execute(
            """
            SELECT t.id_token, u.id_usuario, u.correo 
            FROM data_general.tokens_recuperacion t
            JOIN data_general.usuarios u ON t.id_usuario = u.id_usuario
            WHERE t.token = %s AND t.fecha_expiracion > %s AND t.utilizado = FALSE
            """, 
            (token, datetime.now())
        )
        token_data = cur.fetchone()
        

        if token_data:
            hashed_password = generate_password_hash(new_password)
            
            try:
                # Actualizamos la contraseña en la tabla general de usuarios
                cur.execute(
                    "UPDATE data_general.usuarios SET contrasena = %s WHERE id_usuario = %s", 
                    (hashed_password, token_data['id_usuario'])
                )
                
                # Eliminar todos los tokens de recuperación del usuario
                cur.execute(
                    """
                    DELETE FROM data_general.tokens_recuperacion
                    WHERE id_usuario = %s
                    """,
                    (token_data['id_usuario'],)
                )
                
                conn.commit()
                logging.info(f"Contrasena restablecida exitosamente para {token_data['correo']}")
                flash('Tu contraseña ha sido restablecida con éxito', 'login_success')
                return redirect(url_for('inicio'))
                
            except Exception as e:
                conn.rollback()
                logging.error(f"Error al procesar el cambio de clave en la BD: {e}")
                flash("Error interno al restablecer la contraseña", "error")
                return redirect(url_for('recuperar_contraseña'))
            finally:
                cur.close()
                conn.close()
        else:
            cur.close()
            conn.close()
            logging.warning(f"Intento de restablecimiento fallido con token inválido, usado o caducado: {token}")
            flash('El enlace de restablecimiento de contraseña es inválido o ha caducado', 'error')
            return redirect(url_for('recuperar_contraseña'))

    return render_template('restablecer_contrasena.html', token=token)

def generate_token():
    return secrets.token_urlsafe(64)

@app.route('/paginaprincipal')
@no_cache
def paginaprincipal():
    if 'user_id' not in session:
        logging.warning(f"Intento de acceso no autorizado a la página principal, redirigiendo a 'inicio'. Usuario no autenticado.")
        return redirect(url_for('inicio'))

    nombre = session.get('nombre', '')
    apellido = session.get('apellido', '')

    # Registro en el log de acceso a la página principal
    logging.info(f"El usuario {nombre} {apellido} accedio a la pagina principal.")

    return render_template('paginaprincipal.html', nombre=nombre, apellido=apellido)

@app.route('/cambiar_contraseña', methods=['GET', 'POST'])
@no_cache
def cambiar_contraseña():
    if request.method == 'POST':
        user_id = session.get('user_id')
        if not user_id:
            flash("Debe iniciar sesión para cambiar la contraseña", "login_error")
            logging.warning("Intento de cambiar la contrasena sin estar autenticado.")
            return redirect(url_for('inicio'))

        old_password = request.form.get("old_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")
        
        if len(new_password) < 12 or len(new_password) > 64:
            flash(
                "La contraseña debe tener entre 12 y 64 caracteres.",
                "danger"
            )
            return redirect(url_for("cambiar_contraseña"))
        
        if not re.search(r"[A-Z]", new_password):
            flash(
                "La contraseña debe contener al menos una letra mayúscula.",
                "register_error"
            )
            return redirect(url_for("cambiar_contraseña"))
        
        if not re.search(r"[a-z]", new_password):
            flash(
                "La contraseña debe contener una letra minúscula.",
                "register_error"
            )
            return redirect(url_for("cambiar_contraseña"))
    
        if not re.search(r"\d", new_password):
            flash(
                "La contraseña debe contener un número.",
                "register_error"
            )
            return redirect(url_for("cambiar_contraseña"))
    
        if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", new_password):
            flash(
                "La contraseña debe contener un carácter especial.",
                "register_error"
            )
            return redirect(url_for("cambiar_contraseña"))

        if new_password != confirm_password:
            flash('Las contraseñas no coinciden', 'danger')
            logging.warning(f"El usuario {user_id} intento cambiar la contrasena, pero las contrasenas no coinciden.")
            return redirect(url_for('cambiar_contraseña'))

        # ==============================================================================
        # CONSULTA EN EL NUEVO ESQUEMA: data_general.usuarios
        # ==============================================================================
        conn = get_wr_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # Buscamos la contraseña actual usando el nuevo nombre de columna y esquema
        cur.execute("SELECT contrasena FROM data_general.usuarios WHERE id_usuario = %s", (user_id,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        # Ojo con el cambio: comparamos contra user['contrasena']
        if user is None or not check_password_hash(user['contrasena'], old_password):
            flash('Contraseña actual incorrecta', 'danger')
            logging.warning(f"El usuario {user_id} intento cambiar la contrasena pero proporciono la contrasena actual incorrecta.")
            return redirect(url_for('cambiar_contraseña'))
        
        if check_password_hash(user["contrasena"], new_password):
            flash(
                "La nueva contraseña debe ser diferente de la actual.",
                "danger"
            )
            return redirect(url_for("cambiar_contraseña"))

        # ==============================================================================
        # ACTUALIZACIÓN EN LA TABLA GENERAL DE USUARIOS
        # ==============================================================================
        hashed_password = generate_password_hash(new_password)
        
        conn = get_wr_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # Actualizamos la columna contrasena usando id_usuario en el esquema general
        cur.execute(
            "UPDATE data_general.usuarios SET contrasena = %s WHERE id_usuario = %s", 
            (hashed_password, user_id)
        )
        
        cur.execute(
            """
            DELETE FROM data_general.tokens_recuperacion
            WHERE id_usuario = %s
            """,
            (user_id,)
        )
        
        conn.commit()
        cur.close()
        conn.close()
        

        flash('Su contraseña ha sido cambiada exitosamente', 'success')
        logging.info(f"El usuario {user_id} cambio su contrasena exitosamente.")
        return redirect(url_for('cambiar_contraseña'))
    


    if 'user_id' not in session:
        logging.warning("Intento de acceder a la pagina de cambio de contrasena sin estar autenticado.")
        return redirect(url_for('inicio'))

    nombre = session.get('nombre', '')
    apellido = session.get('apellido', '')
    
    return render_template('cambiar_contrasena.html', nombre=nombre, apellido=apellido)

@app.route('/info_planes')
@no_cache
def info_planes():

    if 'user_id' not in session:
        logging.warning("Intento de acceder a la página de informacion de polizas sin estar autenticado.")
        return redirect(url_for('inicio'))

    nombre = session.get('nombre', '')
    apellido = session.get('apellido', '')
    ci_pagador = session.get('ci_pagador')
    mensaje = request.args.get('mensaje', None)
    moneda = session.get('moneda_pago', '')

    # API Contratos_RMP - Usando la API intermediaria
    API_CONSULTAS = os.getenv('API_CONSULTAS')
    api_url_contratos = f"{API_CONSULTAS}/apicontratos"  # Ruta de la API intermediaria

    contratos_rmp = []
    contratos_amb = []

    try:
        logging.info(f"Solicitud de contratos para el CI {ci_pagador}")
        response_contratos = requests.post(api_url_contratos, json={'ci_pagador': ci_pagador},headers=headers_api_rescarven)

        if response_contratos.status_code == 200:
            api_response = response_contratos.json()
            contratos_rmp = desencriptar_datos(api_response.get('contratos_rmp', ''), token_api_rescarven)
            contratos_amb = desencriptar_datos(api_response.get('contratos_amb', ''), token_api_rescarven)
            print(f"Contratos RMP: {contratos_rmp}")
            print(f"Contratos AMB: {contratos_amb}")
            logging.info(f"Se obtuvieron {len(contratos_rmp)} contratos RMP y {len(contratos_amb)} contratos AMB para el CI {ci_pagador}.")
        else:
            flash("Error al obtener los contratos desde la API intermediaria", "error")
            logging.error(f"Error al obtener contratos: {response_contratos.status_code}")
    except requests.exceptions.RequestException as e:
        flash(f"Error al conectar con la API intermediaria: {e}", "error")
        logging.error(f"Error de conexión con la API: {e}")


    mensaje_batpay = request.args.get('mensaje')
    success = request.args.get('success', 'False') == 'True'

    if mensaje_batpay == 'Pago aprobado' and success:
        print(">>> Procesando pago aprobado de BatPay <<<")

        referencia = request.args.get('reference_batpay')
        monto_pagado = request.args.get('amount')
        fecha_hora = request.args.get('fecha', '').replace('%2F', '/').replace('%3A', ':').replace('+', ' ')
        order_id = request.args.get('order_id')
        moneda = session.get('moneda_pago', '')
        banco_emisor = 200  

        fecha_hora = fecha_hora.strip()  # elimina espacios al inicio y al final
  # Limpiar completamente cualquier carácter raro
        fecha_hora = re.sub(r'[^\w/: ]', '', fecha_hora)

        partes = fecha_hora.split()

        fecha_pago = "No disponible"
        hora_pago = "No disponible"
        fecha_pago_formateada = "No disponible"

        # Extraer partes
        if len(partes) >= 2:
            fecha_pago = partes[0].strip()
            hora_pago = partes[1].strip()
        elif len(partes) == 1:
            fecha_pago = partes[0].strip()
        
        # Probar varios formatos conocidos
        formatos_aceptados = ["%d/%m/%Y", "%d-%m-%Y", "%Y/%m/%d", "%Y-%m-%d", "%m/%d/%Y"]
        
        for formato in formatos_aceptados:
            try:
                fecha_obj = datetime.strptime(fecha_pago, formato)
                fecha_pago_formateada = fecha_obj.strftime("%Y-%m-%d")
                break  # Si funciona, sal del bucle
            except ValueError:
                continue
        
        
        confirmar_pagos(
            numero_cobros=session.get('idcuotas', []),
            forma_pago=session.get('compania', 'Desconocido'),
            moneda_pago=moneda,
            referencia=referencia,
            tasa=session.get('lista_tasas'),
            montos=monto_pagado
        )
        
        datos_recibo = {
            "nombre_pagador": f"{session.get('nombre', 'Desconocido')} {session.get('apellido', 'Desconocido')}",
            "correo": session.get('email', 'No registrado'),
            "compania": session.get('compania', 'No disponible'),
            "nro_contrato": session.get('contrato', 'No disponible'),
            "cuotas_pagadas": ', '.join(map(str, session.get('cuotas', []))),
            "total_pagado": monto_pagado,
            "referencia_pago": str(referencia),
            "telefono_utilizado": session.get('telefono', 'No disponible'),
            "fecha_pago": fecha_pago_formateada,
            "hora_pago": hora_pago,
            "banco_emisor": str(banco_emisor),
            "id_comercio": order_id,
            "monto_pagado": monto_pagado,
            "moneda": moneda
        }

        guardar_en_base_de_datos(datos_recibo)
        archivo_pdf = f"recibo_de_pago.pdf"
        generar_pdf(datos_recibo, archivo_pdf)
        enviar_correo(session.get('email', 'No registrado'), archivo_pdf)
        
            # --- Mostrar mensaje si lo hay ---
    if mensaje is not None:
        mensaje_fijo = "¡Su pago ha sido aprobado!. Se ha enviado un recibo de pago a su correo registrado."
        flash(mensaje_fijo, 'payment_success')
        logging.info(f"Mensaje fijo mostrado en la página de pólizas: {mensaje_fijo}")

        flash("Favor, pasar por nuestras oficinas a retirar su factura. Gracias.", "payment_success")
    else:
        mensaje_fijo = None

    return render_template('info_planes.html', contratos_rmp=contratos_rmp, contratos_amb=contratos_amb, nombre=nombre, apellido=apellido, mensaje=mensaje_fijo)

def limpiar_y_formatear(valor, decimales=2):
    """
    Función auxiliar para transformar Nones o Strings de la API
    al formato de moneda venezolano (1.234,56).
    """
    # Si es None, "null", "None" o vacío, devolvemos el cero formateado
    if valor is None or str(valor).lower() in ['none', 'null', '']:
        return "0,00" if decimales == 2 else "0,0000"
    
    try:
        # Convertimos a float por si viene como string
        num = float(valor)
        if decimales == 2:
            return f"{num:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
        else:
            return f"{num:,.4f}".replace(",", "X").replace(".", ",").replace("X", ".")
    except (ValueError, TypeError):
        # Si no es un número válido, devolvemos cero para no romper la tabla
        return "0,00" if decimales == 2 else "0,0000"

def formatear_montos_venezolanos(cuotas):
    """Recorre la lista de cuotas y limpia cada campo monetario."""
    if not cuotas:
        return []
        
    for cuota in cuotas:
        
        cuota['MontoBs'] = limpiar_y_formatear(cuota.get('MontoBs'))
        cuota['MontoUs'] = limpiar_y_formatear(cuota.get('MontoUs'))
        cuota['Tasa'] = limpiar_y_formatear(cuota.get('Tasa'), decimales=4)
    return cuotas

@app.route('/datos_polizas', methods=['POST'])
def datos_polizas_post():
    contrato = request.form.get('contrato') 
    compania = request.form.get('compania')
    moneda = request.form.get('moneda')

    session['contrato'] = contrato
    session['compania'] = compania
    session['moneda'] = moneda

    return redirect(url_for('datos_polizas')) 

@app.route('/datos_polizas', methods=['GET'])
def datos_polizas(): 
    # Verificación de sesión de usuario
    if 'user_id' not in session:
        return redirect(url_for('inicio'))

    contrato = session.get('contrato', '').strip()
    compania = session.get('compania')
    moneda = session.get('moneda')
    no_encontrado = False
    datos_polizas_lista = []

    if not contrato:
        flash("Número de contrato no proporcionado", "error")
        no_encontrado = True
    else:
        API_CONSULTAS = os.getenv('API_CONSULTAS')
        api_url_datos_polizas = f"{API_CONSULTAS}/apidatospolizas"

        try:
            # Petición a la API externa
            response = requests.post(
                api_url_datos_polizas, 
                json={'contrato': contrato}, 
                headers=headers_api_rescarven,
                timeout=10
            )

            if response.status_code == 200:
                resultado_json = response.json()
                datos_cifrados = resultado_json.get('datos_polizas')

                if datos_cifrados:
                    # Desencriptación
                    datos_desencriptados = desencriptar_datos(datos_cifrados, token_api_rescarven)
                    
                    if datos_desencriptados and len(datos_desencriptados) > 0:
                        # Aplicamos el formateo blindado contra Nulos
                        datos_polizas_lista = formatear_montos_venezolanos(datos_desencriptados)
                    else:
                        no_encontrado = True
                else:
                    no_encontrado = True
            else:
                logging.error(f"API Error {response.status_code}: {response.text}")
                no_encontrado = True

        except Exception as e:
            logging.error(f"Error crítico en datos_polizas: {str(e)}")
            no_encontrado = True

    # Datos adicionales para el template
    nombre = session.get('nombre', '')
    apellido = session.get('apellido', '')
    session['ip_cliente'] = request.remote_addr
    
    return render_template(
        'datos_polizas.html', 
        datos=datos_polizas_lista, 
        nombre=nombre, 
        apellido=apellido,
        no_encontrado=no_encontrado, 
        compania=compania, 
        moneda=moneda
    )

@app.route('/guardar_datos_pago', methods=['POST'])
def guardar_datos_pago():
    try:
        data = request.get_json()

        session['montobs'] = data.get('montobs', '0.00')
        session['montous'] = data.get('montous', '0.00') 
        session['cuotas'] = data.get('cuotas', [])
        session['fechasvct'] = data.get('fechasvct', [])
        session['idcuotas'] = data.get('idcuotas', [])
        session['lista_montosbs'] = data.get('lista_montosbs', [])  
        session['lista_montosus'] = data.get('lista_montosus', []) 
        session['moneda_pago'] = data.get('moneda_pago', []) 
        session['lista_tasas'] = data.get('lista_tasas', []) 

        logging.info(
            f"Datos de pago guardados: montobs={session['montobs']}, montous={session['montous']}, "
            f"cuotas={session['cuotas']}, fechasvct={session['fechasvct']}, idcuotas={session['idcuotas']}, "
            f"lista_montosbs={session['lista_montosbs']}, lista_montosus={session['lista_montosus']}"
        )

        return jsonify({"success": True})
    except Exception as e:
        logging.error(f"Error al guardar los datos de pago: {str(e)}")
        return jsonify({"success": False, "error": str(e)})

@app.route('/metodos_de_pago_bs')
def metodos_de_pago_bs():
    if 'user_id' not in session:
        logging.warning("Intento de acceso sin sesion activa. Redirigiendo a la pagina de inicio.")
        return redirect(url_for('inicio'))
    
    # Obtener valores desde la sesión
    nombre = session.get('nombre', '')
    apellido = session.get('apellido', '')
    montobs = session.get('montobs', '0.00')
    cuotas = session.get('cuotas', [])
    fechasvct = session.get('fechasvct', [])
    montos = session.get('mnt_cta', [])
    idcuotas = session.get('idcuotas', [])

    # Registrar los valores recuperados de la sesión
    logging.info(f"Datos de sesion recuperados para el usuario: {nombre} {apellido}")
    logging.info(f"Monto: {montobs}, Cuotas: {cuotas}, Fechas de vencimiento: {fechasvct}, Montos de cuenta: {montos}, ID cuotas: {idcuotas}")

    return render_template(
        'metodos_de_pago_bs.html',
        nombre=nombre,
        apellido=apellido,
        montobs=montobs,
        cuotas=cuotas,
        fechasvct=fechasvct,
        montos=montos,
        idcuotas=idcuotas
    )

@app.route('/metodos_de_pago_bs_amb')
def metodos_de_pago_bs_amb():
    if 'user_id' not in session:
        logging.warning("Intento de acceso sin sesion activa. Redirigiendo a la pagina de inicio.")
        return redirect(url_for('inicio'))
    
    # Obtener valores desde la sesión
    nombre = session.get('nombre', '')
    apellido = session.get('apellido', '')
    montobs = session.get('montobs', '0.00')
    cuotas = session.get('cuotas', [])
    fechasvct = session.get('fechasvct', [])
    montos = session.get('mnt_cta', [])
    idcuotas = session.get('idcuotas', [])

    # Registrar los valores recuperados de la sesión
    logging.info(f"Datos de sesion recuperados para el usuario: {nombre} {apellido}")
    logging.info(f"Monto: {montobs}, Cuotas: {cuotas}, Fechas de vencimiento: {fechasvct}, Montos de cuenta: {montos}, ID cuotas: {idcuotas}")

    return render_template(
        'metodos_de_pago_bs_amb.html',
        nombre=nombre,
        apellido=apellido,
        montobs=montobs,
        cuotas=cuotas,
        fechasvct=fechasvct,
        montos=montos,
        idcuotas=idcuotas
    )

@app.route('/metodos_de_pago_usd')
def metodos_de_pago_usd():
    if 'user_id' not in session:
        logging.warning("Intento de acceso sin sesion activa. Redirigiendo a la pagina de inicio.")
        return redirect(url_for('inicio'))
    
    # Obtener valores desde la sesión
    nombre = session.get('nombre', '') 
    apellido = session.get('apellido', '')
    montobs = session.get('montobs', '0.00')
    montous = session.get('montous', '0.00')
    cuotas = session.get('cuotas', [])
    fechasvct = session.get('fechasvct', [])
    montos = session.get('mnt_cta', [])
    idcuotas = session.get('idcuotas', [])

    # Registrar los valores recuperados de la sesión
    logging.info(f"Datos de sesion recuperados para el usuario: {nombre} {apellido}")
    logging.info(f"Monto: {montous}, Cuotas: {cuotas}, Fechas de vencimiento: {fechasvct}, Montos de cuenta: {montos}, ID cuotas: {idcuotas}")

    return render_template(
        'metodos_de_pago_usd.html',
        nombre=nombre,
        apellido=apellido,
        montobs=montobs,
        montous=montous,
        cuotas=cuotas,
        fechasvct=fechasvct,
        montos=montos,
        idcuotas=idcuotas
    )
    
# Usamos strip() y rstrip('/') para que no importen los espacios o barras extra en el .env
CREDICARD_CLIENT_ID = os.getenv("CREDICARD_CLIENT_ID", "").strip()
CREDICARD_CLIENT_SECRET = os.getenv("CREDICARD_CLIENT_SECRET", "").strip()
CREDICARD_BASE_URL = os.getenv("CREDICARD_BASE_URL").strip().rstrip('/')


@app.route("/api/credicard/crear-pago", methods=["POST"])
def crear_pago_credicard():
    # Usamos la URL base con el puerto que ya confirmamos que funciona
    base_url = os.getenv("CREDICARD_BASE_URL", "https://gatewayqa.credicard.com.ve:8443").strip().rstrip('/')
    endpoint = f"{base_url}/v1/api/commerce/paymentOrder/clientCredentials"

    try:
        monto_raw = session.get('montobs', '0,00')
        ci_raw = str(session.get('ci_pagador', '')).strip()
        
        # Lógica de monto (Ya la tienes perfecta)
        monto_limpio = monto_raw.replace('.', '').replace(',', '.') if "," in str(monto_raw) else str(monto_raw)
        amount = round(float(monto_limpio), 2)

        # Identificación con guion (Ya validado por el banco)
        solo_numeros = re.sub(r'\D', '', ci_raw)
        match_letra = re.search(r'[a-zA-Z]', ci_raw)
        tipo_doc = match_letra.group(0).upper() if match_letra else "V"
        identificacion_string = f"{tipo_doc}-{solo_numeros}"

        # Payload sin 'currency' porque vimos que en QA da problemas
        payload = {
            "amount": amount,
            "subAmount": amount,
            "email": "comercioqa51@yopmail.com",
            "concept": "Prueba de Pago",
            "identification": "V-18913353",
            "redirectSuccess": url_for("credicard_success", _external=True),
            "redirectFailure": url_for("credicard_failure", _external=True)
        }

        response = requests.post(
            endpoint,
            json=payload,
            headers={
                "client-id": os.getenv("CREDICARD_CLIENT_ID"),
                "client-secret": os.getenv("CREDICARD_CLIENT_SECRET"),
                "Content-Type": "application/json"
            },
            timeout=20
        )
        if response.status_code in [200, 201]:
                    data_json = response.json()
                    order_id = data_json.get('data', {}).get('id')
                    payment_url = data_json.get('data', {}).get('paymentUrl')
                    
                    if order_id:
                        session['last_credicard_order_id'] = order_id
                        
                    return jsonify({"success": True, "url": payment_url}), 200


        print(f"DEBUG - ERROR DEL BANCO: {response.status_code} - {response.text}")
        return jsonify({
            "success": False, 
            "message": f"Error del banco: {response.status_code}",
            "detalle": response.text
        }), response.status_code

    except Exception as e:
        print(f"EXCEPCIÓN: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500

# ==========================================
# 3. ENDPOINTS DE RETORNO (OBLIGATORIOS)
# ==========================================
@app.route("/credicard/success")
def credicard_success():
    order_id = session.get('last_credicard_order_id')
    
    if not order_id:
        print("DEBUG - ERROR: No se encontró order_id. Intento de acceso directo detectado.")
        return redirect(url_for("metodos_de_pago_bs"))

    # Intentamos la consulta (para logs), pero no bloqueamos el flujo si da 401
    base_url = os.getenv("CREDICARD_BASE_URL", "https://gatewayqa.credicard.com.ve:8443").strip().rstrip('/')
    check_endpoint = f"{base_url}/v1/api/commerce/paymentOrder/{order_id}"
    
    try:
        headers = {
            "client-id": os.getenv("CREDICARD_CLIENT_ID"),
            "client-secret": os.getenv("CREDICARD_CLIENT_SECRET"),
            "Content-Type": "application/json"
        }
        
        response = requests.get(check_endpoint, headers=headers, timeout=10)
        print(f"DEBUG - STATUS CONSULTA: {response.status_code}")

        # SI DA 200, validamos el status del JSON
        if response.status_code == 200:
            status_pago = response.json().get('data', {}).get('status')
            if status_pago != 'approved':
                return redirect(url_for("metodos_de_pago_bs"))
        
        print(f"¡PROCESANDO PAGO EXITOSO PARA LA ORDEN {order_id}!")
        
        # update_contrato_pagado(session.get('contrato'))
        
        session.pop('last_credicard_order_id', None) # Limpiamos para que no puedan refrescar y duplicar
        return redirect(url_for("info_planes"))

    except Exception as e:
        print(f"DEBUG - EXCEPCIÓN: {str(e)}")
        return redirect(url_for("metodos_de_pago_bs"))

@app.route("/credicard/failure")
def credicard_failure():
    """
    Ruta a la que Credicard envía al usuario cuando el pago falla o se cancela.
    """
    # 1. Limpiamos el ID de la orden de la sesión para que pueda intentar uno nuevo
    session.pop('last_credicard_order_id', None)
    
    # 2. Log para monitoreo interno
    print("INFO - El usuario regresó desde Credicard por una transacción fallida o cancelada.")
    
    
    # 4. Lo mandamos de vuelta a los métodos de pago
    return redirect(url_for("metodos_de_pago_bs"))


    
@app.route('/pagomovil')
@no_cache
def pagomovil():
    try:
        # Verificar si el usuario está autenticado
        if 'email' not in session:
            logging.warning("Acceso denegado: usuario no autenticado.")
            return "Usuario no autenticado", 401  # Bloquea si no hay sesión
        
        logging.info("Usuario autenticado, recuperando informacion de pagos.")
        
        connection = get_zu_db_connection()
        cursor = connection.cursor(cursor_factory=RealDictCursor)

        # Obtener parámetros de la URL
        periodo = request.args.get('periodo')
        fecha_inicio = request.args.get('fecha_inicio')
        fecha_fin = request.args.get('fecha_fin')

        logging.info(f"Parametros recibidos: periodo={periodo}, fecha_inicio={fecha_inicio}, fecha_fin={fecha_fin}")

        # 1. Definimos la base de la consulta
        query = """
            SELECT
                nombre_pagador,
                telefono_utilizado,
                nro_contrato,
                compania,
                fecha_pago,
                monto_pagado,
                referencia_pago,
                correo,
                cuotas_pagadas,
                total_pagado,
                hora_pago,
                banco_emisor
            FROM aplication_web.recibos
        """
        params = []
        filtros = [] # Usaremos esta lista para guardar las condiciones (WHERE)
        hoy = datetime.today().date()

        # 2. Lógica de periodos (Solo definimos fechas, no escribimos SQL todavía)
        if periodo == "hoy":
            filtros.append("fecha_pago = %s")
            params.append(hoy)

        elif periodo == "ultima_semana":
            filtros.append("fecha_pago BETWEEN %s AND %s")
            params.extend([hoy - timedelta(days=6), hoy])

        elif periodo == "mes":
            filtros.append("fecha_pago BETWEEN %s AND %s")
            params.extend([hoy.replace(day=1), hoy])

        elif periodo == "tres_meses":
            filtros.append("fecha_pago BETWEEN %s AND %s")
            params.extend([hoy - timedelta(days=89), hoy])

        # 3. Caso especial: si no hay periodo pero sí fechas manuales
        elif not periodo and fecha_inicio and fecha_fin:
            filtros.append("fecha_pago BETWEEN %s AND %s")
            params.extend([fecha_inicio, fecha_fin])


        if filtros:
            query += " WHERE " + " AND ".join(filtros)

        cursor.execute(query, params)
        recibos = cursor.fetchall()
        

        logging.info(f"Recibos obtenidos: {len(recibos)} registros encontrados.")

        return render_template('pagos.html', recibos=recibos, periodo=periodo, fecha_inicio=fecha_inicio, fecha_fin=fecha_fin)
    
    except Exception as e:
        logging.error(f"Error al obtener los recibos: {e}")
        return render_template('pagos.html', recibos=[])
    
@app.route('/mibanco') 
@no_cache
def mibanco():
    try:
        # Verificar si el usuario está autenticado
        if 'email' not in session:
            logging.warning("Acceso denegado: usuario no autenticado.")
            return "Usuario no autenticado", 401
        
        logging.info("Usuario autenticado, recuperando información de registros de MiBanco.")

        connection = get_zu_db_connection()
        cursor = connection.cursor(cursor_factory=RealDictCursor)

        # Obtener parámetros de la URL
        periodo = request.args.get('periodo')
        fecha_inicio_str = request.args.get('fecha_inicio')
        fecha_fin_str = request.args.get('fecha_fin')

        logging.info(f"Parámetros recibidos: periodo={periodo}, fecha_inicio={fecha_inicio_str}, fecha_fin={fecha_fin_str}")

        # 1. Consulta base 
        query = "SELECT idcomercio, telefonoemisor, bancoemisor, monto, fecha, referencia FROM r4.registros_mibanco"
        params = []
        hoy = datetime.today().date()

        fecha_inicio = None
        fecha_fin = None

        if periodo:
            if periodo == "hoy":
                fecha_inicio = hoy
                fecha_fin = hoy
            elif periodo == "ultima_semana":
                fecha_inicio = hoy - timedelta(days=6)
                fecha_fin = hoy
            elif periodo == "mes":
                fecha_inicio = hoy.replace(day=1)
                fecha_fin = hoy
            elif periodo == "tres_meses":
                fecha_inicio = hoy - timedelta(days=90)
                fecha_fin = hoy

        # 3. Rango personalizado 
        if fecha_inicio_str and fecha_fin_str:
            try:
                fecha_inicio = datetime.strptime(fecha_inicio_str, '%Y-%m-%d').date()
                fecha_fin = datetime.strptime(fecha_fin_str, '%Y-%m-%d').date()
            except ValueError:
                flash("Formato de fecha no válido", "error")
                return redirect(url_for('mibanco'))

        # 4. Aplicar filtro 
        if fecha_inicio and fecha_fin:
            
            query += " WHERE fecha::date BETWEEN %s AND %s"
            params.extend([fecha_inicio, fecha_fin])
            logging.info(f"Filtro aplicado: Fecha entre {fecha_inicio} y {fecha_fin}")

        # 5. Ejecución 
        cursor.execute(query, params)
        registros_mibanco = cursor.fetchall()

        logging.info(f"Registros obtenidos: {len(registros_mibanco)}")

        return render_template('mibanco.html', registros_mibanco=registros_mibanco,
        periodo=periodo, fecha_inicio=fecha_inicio, fecha_fin=fecha_fin)

    except Exception as e:
        logging.error(f"Error al obtener los registros: {e}")
        return render_template('mibanco.html', registros_mibanco=[])

@app.route('/metodos_de_pago_usd_amb')
def metodos_de_pago_usd_amb():
    if 'user_id' not in session:
        logging.info("Usuario no autenticado, redirigiendo al inicio.")
        return redirect(url_for('inicio'))
    
    # Obtener valores desde la sesión
    nombre = session.get('nombre', '')
    apellido = session.get('apellido', '')
    montobs = session.get('montobs', '0.00')
    montous = session.get('montous', '0.00')
    cuotas = session.get('cuotas', [])
    fechasvct = session.get('fechasvct', [])
    montos = session.get('mnt_cta', [])
    idcuotas = session.get('idcuotas', [])

    logging.info(f"Datos cargados para el usuario: {nombre} {apellido}, Monto: {montous}, Cuotas: {len(cuotas)}")
    
    return render_template(
        'metodos_de_pago_usd_amb.html',
        nombre=nombre,
        apellido=apellido,
        montobs=montobs,
        montous=montous,
        cuotas=cuotas,
        fechasvct=fechasvct,
        montos=montos,
        idcuotas=idcuotas
    )

# Variables de entorno
PUBLIC_KEY_BP = os.getenv('PUBLIC_KEY_BP')
PRIVATE_KEY_BP = os.getenv('PRIVATE_KEY_BP')
URL_GET_TOKEN_BP = os.getenv('URL_GET_TOKEN_BP')

@app.route('/process_payment', methods=['POST'])
def process_payment():
    # Obtener los datos desde el formulario
    item_batpay = request.form.get('item_batpay')
    amount_batpay_str = request.form.get('amount_batpay')
    amount_batpay = amount_batpay_str.replace(',', '.').replace(' ', '')  
    email_batpay = request.form.get('email_batpay')
    client_id_batpay = request.form.get('client_id_batpay')

    # Validar y formatear el monto
    try:
        amount_batpay = "{:.2f}".format(float(amount_batpay))
    except ValueError:
        return "Monto inválido. Asegúrate de ingresar un número válido.", 400

    # Generar order_id único
    order_id = str(uuid.uuid4())[:8]

    logging.info(f"Procesando pago: order_id={order_id}, item={item_batpay}, amount={amount_batpay}, email={email_batpay}")

    # Obtener token desde BatPay
    result = get_token_from_batpay(order_id, item_batpay, amount_batpay, email_batpay, client_id_batpay)

    if 'error' in result:
        logging.error(f"Error comunicándose con BatPay: {result['error']}")
        return result['error'], 500

    # Redirigir al usuario si hay URL
    redirect_url = result.get('url')
    if redirect_url:
        logging.info(f"Redirigiendo al usuario a BatPay: {redirect_url}")
        return redirect(redirect_url)
    else:
        message = result.get("message", "Respuesta inválida de BatPay.")
        logging.error(f"Error al obtener token: {message}")
        return f"Error al obtener el token de BatPay. Mensaje: {message}", 500

def get_token_from_batpay(order_id, item, amount, email, client_id):
    url_fail = url_for('paginaprincipal', _external=True)
    url_success = url_for('info_planes', _external=True)
    url_notificacion = url_for('batpay_notification', _external=True)

    logging.info(f"Solicitando token BatPay para order_id={order_id}")

    data = {
        "order_id": order_id,
        "item": item,
        "amount": amount,
        "email": email,
        "client_id": client_id,
        "public_key": PUBLIC_KEY_BP,
        "private_key": PRIVATE_KEY_BP,
        "url_fail": url_fail,
        "url_success": url_success,
        "url_notificacion": url_notificacion
    }

    headers = {"Content-Type": "application/json"}

    try:
        response = requests.post(URL_GET_TOKEN_BP, json=data, headers=headers)
        response.raise_for_status()
        resp_json = response.json()
        logging.info(f"Respuesta de BatPay: {resp_json}")

        if 'url' not in resp_json:
            return {"error": "Respuesta de BatPay no contiene una URL de redirección."}

        return resp_json

    except requests.exceptions.HTTPError as http_err:
        return {"error": f"HTTP error occurred: {http_err}. Response: {response.text}"}
    except requests.exceptions.RequestException as err:
        return {"error": f"Error de conexión con BatPay: {err}"}

@app.route('/batpay_notification', methods=['POST'])
def batpay_notification():
    data = request.json
    logging.info(f"Notificación recibida de BatPay: {data}")
    
    return '', 200
    
    

#configuracion c2pm
PORT_C2PM_RMP = int(os.getenv('PORT_C2PM_RMP', 5000))
HOST_C2PM_RMP = os.getenv('HOST_C2PM_RMP', '127.0.0.1')
MERCHANT_ID_C2PM_RMP = os.getenv('MERCHANT_ID_C2PM_RMP')
CLIENT_ID_C2PM_RMP = os.getenv('CLIENT_ID_C2PM_RMP')
SECRET_KEY_C2PM_RMP = os.getenv('SECRET_KEY_C2PM_RMP')
INTEGRATOR_ID_C2PM_RMP = int(os.getenv('INTEGRATOR_ID_C2PM_RMP'))
TERMINAL_ID_C2PM_RMP = int(os.getenv('TERMINAL_ID_C2PM_RMP'))
PHONE_NUMBER_C2PM_RMP = os.getenv('PHONE_NUMBER_C2PM_RMP')
URL_C2PM_RMP = os.getenv('URL_C2PM_RMP')

def encrypt_message_c2pm(message, secret_key):
    
    logging.info(f"Iniciando encriptacion con una clave de {len(secret_key)} caracteres.")
     
    try:
        # Generar el hash de la clave secreta para obtener la clave de encriptación
        hash_obj = hashlib.sha256(secret_key.encode())
        key = hash_obj.digest()[:16]  
        cipher = AES.new(key, AES.MODE_ECB)  
        
       
        padded_message = pad(message.encode(), AES.block_size)
        
        # Encriptar el mensaje
        encrypted_message = cipher.encrypt(padded_message)
        
        
        encrypted_message_b64 = base64.b64encode(encrypted_message).decode()
        
        logging.info("Mensaje encriptado exitosamente. Longitud del mensaje encriptado: %d caracteres.", len(encrypted_message_b64))
        
        return encrypted_message_b64
    
    except Exception as e:
        logging.error(f"Error durante la encriptacion del mensaje: {e}")
        raise

@app.route('/pago_c2p_m', methods=['POST'])
def pago_c2pm():
    compania = session.get('compania', 'No disponible')
    id_comercio = None  
    moneda = session.get('moneda_pago', '')
    ip_cliente = session.get('ip_cliente', 'IP no encontrada')
    codigo_banco = request.form.get('Banco') 
    try:
        # Recibir datos del formulario
        trx_type = request.form.get('trxType')
        amount_str = request.form.get('amount')
        amount = amount_str.replace('.', '').replace(',', '.') if amount_str else '0.00'
        customer_id = f"{request.form.get('customerIdPrefix')}{request.form.get('customerId')}"
        customer_phone_number = f"58{request.form.get('customerPhonePrefix')}{request.form.get('customerPhoneNumber')}"
        twofactor = request.form.get('twofactor', '')
        invoice_number = request.form.get('invoiceNumber')
        montobs = request.args.get('montobs', amount)
        

        # Log de entrada de datos
        logging.info(f"Datos recibidos: trx_type={trx_type}, amount={amount}, customer_id={customer_id}, "
                     f"customer_phone_number={customer_phone_number}, twofactor={twofactor}, invoice_number={invoice_number}")

        # Enviar la solicitud a la API externa
        body = {
            "merchant_identify": {
                "integratorId": INTEGRATOR_ID_C2PM_RMP,
                "merchantId": MERCHANT_ID_C2PM_RMP,
                "terminalId": TERMINAL_ID_C2PM_RMP
            },
            "client_identify": {
                "ipaddress": ip_cliente,
                "mobile": {
                }
            },
            "transaction_c2p": {
                "amount": amount,
                "currency": 'ves',
                "destination_bank_id": codigo_banco, 
                "destination_id": encrypt_message_c2pm(customer_id, SECRET_KEY_C2PM_RMP),
                "destination_mobile_number": encrypt_message_c2pm(customer_phone_number, SECRET_KEY_C2PM_RMP),
                "origin_mobile_number": encrypt_message_c2pm(PHONE_NUMBER_C2PM_RMP, SECRET_KEY_C2PM_RMP),
                "payment_reference": invoice_number if trx_type == "anulacion" else "",
                "trx_type": trx_type,
                "payment_method": "p2p" if trx_type == 'vuelto' else "c2p",
                "invoice_number": str(random.randint(100000, 999999)),
                "twofactor_auth": encrypt_message_c2pm(twofactor, SECRET_KEY_C2PM_RMP) if trx_type == 'compra' else ''
            }
        }

        # Log de la solicitud que se va a enviar
        logging.info(f"Enviando solicitud a C2PM con datos: {body}")

        # Enviar la solicitud
        response = requests.post(URL_C2PM_RMP, headers={
            'Content-Type': 'application/json',
            'X-IBM-Client-ID': CLIENT_ID_C2PM_RMP
        }, json=body)

        # Procesar la respuesta
        response_data = response.json()
        print(f"response c2pm {response_data}")

        # Log de la respuesta
        logging.info(f"Respuesta de la API C2PM: {response_data}")

        if 'transaction_c2p_response' in response_data:
            trx_response = response_data['transaction_c2p_response']
            monto_pagado = trx_response.get('amount', 0)
            referencia_pago = trx_response.get('payment_reference', 'No disponible')
            destination_bank_id = codigo_banco
            
            confirmar_pagos(
                numero_cobros= session.get('idcuotas', []),
                forma_pago= session.get('compania', 'Desconocido'),
                moneda_pago= session.get('moneda_pago', 'VES'),
                referencia= referencia_pago,
                tasa= session.get('lista_tasas'),
                montos= monto_pagado
                )
            
            # Log de los datos de pago procesados
            logging.info(f"Transaccion procesada: monto_pagado={monto_pagado}, referencia_pago={referencia_pago}")
            

            # Lógica para determinar el id_comercio según la compañia
            if compania == 'RMP':
                id_comercio = 000000
            elif compania == 'AMB':
                id_comercio = 000000
            else:
                id_comercio = None  # O cualquier otro valor que desees manejar

            # Datos del recibo
            datos_recibo = {
                'nombre_pagador': f"{session.get('nombre', 'Desconocido')} {session.get('apellido', 'Desconocido')}",
                'correo': session.get('email', 'No registrado'),
                'compania': compania,
                'nro_contrato': session.get('contrato', 'No disponible'),
                'cuotas_pagadas': ', '.join(map(str, session.get('cuotas', []))),
                'total_pagado': montobs,
                'referencia_pago': referencia_pago,
                'telefono_utilizado': customer_phone_number,  
                'fecha_pago': trx_response.get('processing_date').split()[0], 
                'hora_pago': trx_response.get('processing_date').split()[1],  
                'banco_emisor': str(destination_bank_id).lstrip("0"), 
                'id_comercio': id_comercio,
                'monto_pagado': monto_pagado,
                'moneda': moneda
            }

            # Guardar en la base de datos
            guardar_en_base_de_datos(datos_recibo)

            # Generar y enviar recibo en PDF
            archivo_pdf = f"recibo_de_pago.pdf"
            generar_pdf(datos_recibo, archivo_pdf)
            enviar_correo(session.get('email', 'No registrado'), archivo_pdf)

            # Log de confirmación de pago
            logging.info(f"Pago aprobado. Recibo generado y enviado al correo de {session.get('email', 'No registrado')}.")

            flash("¡Su pago ha sido aprobado!. Se ha enviado un recibo de pago a su correo registrado.", "payment_success")
            flash("Favor, pasar por nuestras oficinas a retirar su factura. Gracias.", "payment_success")
        else:
            flash("Error en el pago movil. Verifique sus datos e intete nuevamente.", "payment_error")
            logging.warning(f"Pago movil no encontrado para la transaccion: {body}")
            return redirect(url_for('metodos_de_pago_bs'))
        
        return redirect(url_for('info_planes'))

    except Exception as e:
        logging.error(f"Error inesperado intente de nuevo mas tarde: {str(e)}")
        flash(f"Error inesperado: {str(e)}", "payment_error")
        return redirect(url_for('metodos_de_pago_bs'))

# Configuración SEARCHC2PM 
PORT_SEARCHC2PM_RMP = int(os.getenv('PORT_SEARCHC2PM_RMP')) 
HOST_SEARCHC2PM_RMP = os.getenv('HOST_SEARCHC2PM_RMP')
MERCHANTID_SEARCHC2PM_RMP = os.getenv('MERCHANTID_SEARCHC2PM_RMP')
CLIENTID_SEARCHC2PM_RMP = os.getenv('CLIENTID_SEARCHC2PM_RMP')
SECRETKEY_SEARCHC2PM_RMP = os.getenv('SECRETKEY_SEARCHC2PM_RMP')
INTEGRATORID_SEARCHC2PM_RMP = int(os.getenv('INTEGRATORID_SEARCHC2PM_RMP'))
TERMINALID_SEARCHC2PM_RMP =  int(os.getenv('TERMINALID_SEARCHC2PM_RMP'))
PHONE_NUMBER_SEARCHC2PM_RMP = os.getenv('PHONE_NUMBER_SEARCHC2PM_RMP')
URL_SEARCHC2PM_RMP = os.getenv('URL_SEARCHC2PM_RMP')

# Función para cifrar los campos con AES
def encrypt_message_searchc2pm(message, secret_key):
    try:
        # Log de entrada con los datos
        logging.info(f"Iniciando cifrado del mensaje: {message} con la clave secreta: {secret_key}")

        # Cifrado del mensaje
        hash_obj = hashlib.sha256(secret_key.encode())
        key = hash_obj.digest()[:16]  
        cipher = AES.new(key, AES.MODE_ECB)  
        padded_message = pad(message.encode(), AES.block_size)  
        encrypted_message = cipher.encrypt(padded_message) 

        # Codificar el mensaje cifrado en base64
        encrypted_message_base64 = base64.b64encode(encrypted_message).decode()

        # Log de éxito con el resultado cifrado
        logging.info(f"Mensaje cifrado exitosamente: {encrypted_message_base64[:30]}...")

        return encrypted_message_base64

    except Exception as e:
        
        logging.error(f"Error al cifrar el mensaje: {str(e)}")
        raise

@app.route('/searchC2p', methods=['POST'])
def search_c2p():
    try: 
        # Obtención de datos del formulario
        amount = request.form.get('amount')
        logging.info(f"Monto recibido: {amount}")

        if amount:
            amount = amount.replace(',', '.')  
            try:
                amount = float(amount)  
            except ValueError:
                flash("El monto ingresado no es válido.", "payment_error")
                logging.error("Monto ingresado no valido.")
                return redirect(url_for('metodos_de_pago_bs'))
        
        customer_phone_prefix = request.form.get('customerPhoneNumberPrefix')
        customer_phone_number = f"58{customer_phone_prefix}{request.form.get('customerPhoneNumber')}"
        ref_number = request.form.get('paymentReference')
        transaction_date = request.form.get('transactionDate')

        logging.info(f"Datos recibidos - Prefix Telefono: {customer_phone_prefix}, Telefono: {customer_phone_number}, Referencia: {ref_number}, Fecha de transaccion: {transaction_date}")

        body = {
            "merchant_identify": {
                "integratorId": INTEGRATORID_SEARCHC2PM_RMP,
                "merchantId": MERCHANTID_SEARCHC2PM_RMP,
                "terminalId": TERMINALID_SEARCHC2PM_RMP
            },
            "client_identify": {
                "ipaddress": '127.0.0.1',
                "browser_agent": 'Chrome 18.1.3',
                "mobile": {
                    "manufacturer": 'Samsung',
                    "model": 'S9',
                    "os_version": 'Oreo 9.1',
                    "location": {
                        "lat": 0,
                        "lng": 0
                    }
                }
            },
            "search_by": {
                "amount": amount,
                "currency": 'ves',
                "origin_mobile_number": encrypt_message_searchc2pm(PHONE_NUMBER_SEARCHC2PM_RMP, SECRETKEY_SEARCHC2PM_RMP),
                "destination_mobile_number": encrypt_message_searchc2pm(customer_phone_number, SECRETKEY_SEARCHC2PM_RMP),
                "payment_reference": ref_number,
                "trx_date": transaction_date
            }
        }

        # Log de la solicitud a la API
        logging.info(f"Solicitando a la API con los siguientes datos: {body}")

        # Encabezados de la solicitud
        headers = {
            'Content-Type': 'application/json',
            'X-IBM-Client-ID': CLIENTID_SEARCHC2PM_RMP,
            'Accept': 'application/json'
        }

        # Realizar la solicitud POST a la API
        response = requests.post(URL_SEARCHC2PM_RMP, headers=headers, json=body)
        response_data = response.json()

        # Imprimir solicitud y respuesta para depuración
        logging.debug(f"Respuesta de la API: {response_data}")

        if 'transaction_list' in response_data:
            transaction = response_data['transaction_list'][0]
            if transaction['authorization_code']:
                # Caso de éxito
                mensaje = "¡Su pago ha sido aprobado!"
                logging.info(f"Pago aprobado con autorizacion: {transaction['authorization_code']}")
                return redirect(url_for('info_planes', mensaje=mensaje))
        elif 'error_list' in response_data:
            # Error en la consulta de pago
            error_message = response_data['error_list'][0]['description']
            flash(error_message, "payment_error")
            logging.error(f"Error en la consulta de pago: {error_message}")
            return redirect(url_for('metodos_de_pago_bs'))
        else:
            # Caso de error inesperado
            flash("Error inesperado en la consulta de pago", "payment_error")
            logging.error("Error inesperado en la respuesta de la API")
            return redirect(url_for('metodos_de_pago_bs'))

    except Exception as e:
        # Log de error en caso de excepción
        logging.error(f"Error inesperado en la funcion search_c2p: {str(e)}")
        flash(f"Error inesperado: {str(e)}", "payment_error")
        return redirect(url_for('metodos_de_pago_bs'))

# Configuración de la API AUTORIZACIÓN
PORT_AUTH_RMP = int(os.getenv('PORT_AUTH_RMP'))
HOST_AUTH_RMP = os.getenv('HOST_AUTH_RMP')
MERCHANT_ID_AUTH_RMP = os.getenv('MERCHANT_ID_AUTH_RMP')
INTEGRATOR_ID_AUTH_RMP = int(os.getenv('INTEGRATOR_ID_AUTH_RMP'))
TERMINAL_ID_AUTH_RMP = int(os.getenv('TERMINAL_ID_AUTH_RMP'))
CLIENT_ID_AUTH_RMP = os.getenv('CLIENT_ID_AUTH_RMP')
SECRET_KEY_AUTH_RMP = os.getenv('SECRET_KEY_AUTH_RMP')
URL_AUTH_RMP = os.getenv('URL_AUTH_RMP')

# Configuración de la API para Pago TDD
PORT_TDD_RMP = int(os.getenv('PORT_TDD_RMP')) 
HOST_TDD_RMP = os.getenv('HOST_TDD_RMP')
MERCHANTID_TDD_RMP = os.getenv('MERCHANTID_TDD_RMP')
CLIENTID_TDD_RMP = os.getenv('CLIENTID_TDD_RMP')
SECRETKEY_TDD_RMP = os.getenv('SECRETKEY_TDD_RMP')
INTEGRATORID_TDD_RMP = int(os.getenv('INTEGRATORID_TDD_RMP'))
TERMINALID_TDD_RMP = int(os.getenv('TERMINALID_TDD_RMP'))
URL_TDD_M_RMP = os.getenv('URL_TDD_M_RMP')

def encrypt(message, key):
    logging.info("Iniciando cifrado AES")
    
    hash_key = hashlib.sha256(key.encode('utf-8')).digest()
    key_bytes = hash_key[:16]
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    message_bytes = message.encode('utf-8')
    padded_message = pad(message_bytes, AES.block_size)
    encrypted_bytes = cipher.encrypt(padded_message)
    encrypted_base64 = base64.b64encode(encrypted_bytes).decode('utf-8')

    logging.info("Cifrado AES exitoso")
    
    return encrypted_base64

@app.route('/getauth', methods=['POST'])
def get_auth_and_pay():
    logging.info("Solicitud recibida en /getauth")

    # Datos de sesión comunes
    ip_cliente = session.get('ip_cliente', 'IP no encontrada')
    print(f"IP del cliente: {ip_cliente}")
    compania = session.get('compania', 'No disponible')
    moneda = session.get('moneda_pago', '')

    try:
        # Obtener datos del formulario
        customer_id_prefix = request.form.get('customerid_prefix', '').strip()
        customer_id = request.form.get('customerid', '').strip()
        card_number = request.form.get('card_number', '').strip()
        account_type = request.form.get('account-type', '').strip()
        expiration_date = request.form.get('expiration-date', '').strip()
        cvv = request.form.get('cvv', '').strip()
        amount_str = request.form.get('amounttdd', '').strip()
        amount = amount_str.replace('.', '').replace(',', '.') if amount_str else '0.00'
        
        two_factor_auth = request.form.get('twofactortdd', '').strip()

        # Validación básica
        if not all([customer_id_prefix, customer_id, card_number, account_type, expiration_date, cvv, amount, two_factor_auth]):
            flash("Todos los campos son obligatorios.", "payment_error")
            return redirect(url_for('metodos_de_pago_bs'))

        full_customer_id = f"{customer_id_prefix}{customer_id}"

        # ---- AUTENTICACIÓN ----
        auth_body = {
            "merchant_identify": {
                "integratorId": INTEGRATOR_ID_AUTH_RMP,
                "merchantId": MERCHANT_ID_AUTH_RMP,
                "terminalId": TERMINAL_ID_AUTH_RMP
            },
            "client_identify": {
                "ipaddress": ip_cliente,
                "mobile": {}
            },
            "transaction_authInfo": {
                "trx_type": "solaut",
                "payment_method": "tdd",
                "customer_id": full_customer_id,
                "card_number": card_number
            }
        }

        auth_headers = {
            'Content-Type': 'application/json',
            'X-IBM-Client-ID': CLIENT_ID_AUTH_RMP
        }
        print(f"Request api auth tdd {auth_body}")
        auth_response = requests.post(URL_AUTH_RMP, headers=auth_headers, json=auth_body)
        auth_json = auth_response.json()
        print(f"Respuesta de autenticación: {auth_json}")

        if auth_response.status_code != 200 or auth_json.get('authentication_info', {}).get('trx_status') != "approved":
            flash("Error en la autenticación. Verifique sus datos e intente nuevamente.", "payment_error")
            return redirect(url_for('metodos_de_pago_bs'))

        # ---- PAGO ----
        encrypted_two_factor_auth = encrypt(two_factor_auth, SECRETKEY_TDD_RMP)
        encrypted_cvv = encrypt(cvv, SECRETKEY_TDD_RMP)
        invoice_number = str(random.randint(100000, 999999))

        payment_body = {
            'merchant_identify': {
                'integratorId': INTEGRATORID_TDD_RMP,
                'merchantId': MERCHANTID_TDD_RMP,
                'terminalId': TERMINALID_TDD_RMP
            },
            'client_identify': {
                'ipaddress': ip_cliente,
                'mobile': {}
            },
            'transaction': {
                'trx_type': 'compra',
                'payment_method': 'tdd',
                'card_number': card_number,
                'customer_id': full_customer_id,
                'account_type': account_type,
                'invoice_number': invoice_number,
                'twofactor_auth': encrypted_two_factor_auth,
                'expiration_date': expiration_date,
                'cvv': encrypted_cvv,
                'currency': 'ves',
                'amount': amount
            }
        }

        payment_headers = {
            'Content-Type': 'application/json',
            'X-IBM-Client-ID': CLIENTID_TDD_RMP
        }
        print(f"Request api pago tdd {payment_body}")
        payment_response = requests.post(URL_TDD_M_RMP, json=payment_body, headers=payment_headers)
        payment_json = payment_response.json()
        print(f"Respuesta de pago: {payment_json}")

        if 'error_list' in payment_json:
            error_description = payment_json['error_list'][0]['description']
            flash(f"Error en el pago: {error_description}", "payment_error")
            return redirect(url_for('metodos_de_pago_bs'))

        trx_response = payment_json.get('transaction_response', {})
        if trx_response.get('trx_status') != 'approved':
            flash("El pago no fue aprobado.Verifique los datos e intente nuevamente", "payment_error")
            return redirect(url_for('metodos_de_pago_bs'))

        # Pago exitoso
        referencia_pago = trx_response.get('payment_reference', invoice_number)
        monto_pagado = trx_response.get('amount', amount)
        banco_emisor = 105

        confirmar_pagos(
            numero_cobros=session.get('idcuotas', []),
            forma_pago=compania,
            moneda_pago=moneda,
            referencia=referencia_pago,
            tasa=session.get('lista_tasas'),
            montos=monto_pagado
        )

        # Procesar fecha
        fecha_pago = hora_pago = ''
        try:
            dt = datetime.strptime(trx_response.get('processing_date', '').replace('VET', '').strip(), "%Y-%m-%d %H:%M:%S")
            fecha_pago = dt.strftime("%Y-%m-%d")
            hora_pago = dt.strftime("%H:%M:%S")
        except:
            logging.warning("No se pudo procesar la fecha de pago.")

        id_comercio = 2880716 if compania == 'RMP' else 303458025 if compania == 'AMB' else None

        datos_recibo = {
            'nombre_pagador': f"{session.get('nombre', 'Desconocido')} {session.get('apellido', 'Desconocido')}",
            'correo': session.get('email', 'No registrado'),
            'compania': compania,
            'nro_contrato': session.get('contrato', 'No disponible'),
            'cuotas_pagadas': ', '.join(map(str, session.get('cuotas', []))),
            'total_pagado': amount,
            'referencia_pago': referencia_pago,
            'telefono_utilizado': session.get('telefono', 'No disponible'),
            'fecha_pago': fecha_pago,
            'hora_pago': hora_pago,
            'banco_emisor': str(banco_emisor),
            'id_comercio': id_comercio,
            'monto_pagado': monto_pagado,
            'moneda': moneda
        }

        guardar_en_base_de_datos(datos_recibo)
        generar_pdf(datos_recibo, "recibo_de_pago.pdf")
        enviar_correo(datos_recibo['correo'], "recibo_de_pago.pdf")

        flash("¡Su pago ha sido aprobado! Se ha enviado un recibo de pago a su correo registrado.", "payment_success")
        flash("Favor, pasar por nuestras oficinas a retirar su factura. Gracias.", "payment_success")
        return redirect(url_for('info_planes'))

    except Exception as e:
        logging.exception("Error inesperado durante autenticación y pago.")
        flash(f"Error inesperado: {str(e)}", "payment_error")
        return redirect(url_for('metodos_de_pago_bs'))
    
    #----------------------------------------
    



COMMERCE_HEADER = 'D-PYM-001' 

# Configuración para la primera API (Consulta Pago Móvil)
def generate_hmac_consulta(referencia, telefono):
    """Genera el HMAC-SHA256 para la autorización de consulta pago móvil."""
    logging.info("Generando HMAC-SHA256 para consulta de pago movil.")
    message = f"{referencia}{telefono}"
    return hmac.new(
        key=COMMERCE_HEADER.encode(),
        msg=message.encode(),
        digestmod=hashlib.sha256
    ).hexdigest()

@app.route('/bpm_mibanco', methods=['POST'])
def bpm_mibanco():
    try:
        referencia = request.form.get('referencia')
        
        if len(referencia) < 5:
            flash("La referencia debe contener al menos 5 dígitos.", "payment_error")
            return redirect(url_for('metodos_de_pago_bs'))
        
        phone_prefix = request.form.get('customerPhonePrefix')
        phone_number = request.form.get('customerPhoneNumber')
        telefono_origen = f"{phone_prefix}{phone_number}"
        cuotas = session.get('cuotas')
        montobs = float(session.get('montobs', 0))
        moneda = session.get('moneda_pago', 'VES')

        print(f"Moneda bpm: {moneda}")

        logging.info(f"Montobs recibido: {montobs} {cuotas}")  # Registrar valor recibido

        if not referencia or not phone_prefix or not phone_number:
            flash("Todos los campos son obligatorios.", "payment_error")
            return redirect(url_for('metodos_de_pago_bs'))

        connection = get_zu_db_connection()
        cursor = connection.cursor(cursor_factory=RealDictCursor)

        query = """
            SELECT
                idcomercio,
                telefonoemisor,
                bancoemisor,
                referencia,
                fecha,
                hora,
                monto,
                status
            FROM r4.registros_mibanco
            WHERE telefonoemisor = %s
            ORDER BY fecha DESC, hora DESC
        """

        cursor.execute(query, (telefono_origen,))
        registros = cursor.fetchall()
        
        registro = None

        for r in registros:

            referencia_bd = str(r["referencia"]).strip().lstrip("0")

            if (
                referencia_bd.endswith(referencia) or
                referencia.endswith(referencia_bd)
            ):
                registro = r
                break

        if registro:
            if registro["status"] == "Aprobado":
                flash("Esta referencia ya fue aprobada anteriormente.", "payment_success")
                return redirect(url_for('info_planes'))

            monto_pagado = float(registro["monto"])  # Convertir el monto de la BD a número
            logging.info(f"Monto pagado desde la BD: {monto_pagado}, Monto a comparar: {montobs}")  # Registrar valores

            if monto_pagado >= montobs:
                

                now = datetime.now()
                fecha_actual = now.strftime("%Y-%m-%d") 
                hora_actual = now.strftime("%H:%M:%S")  
                
                # 2. Se mantiene la llamada a confirmar_pagos
                confirmar_pagos(
                    numero_cobros= session.get('idcuotas', []),
                    forma_pago= session.get('compania', 'Desconocido'),
                    moneda_pago= session.get('moneda_pago', 'VES'),
                    referencia= referencia,
                    tasa= session.get('lista_tasas'),
                    montos= monto_pagado
                )
                
                # 3. Se usan las variables de fecha y hora actuales en 'datos_recibo'
                datos_recibo = {
                    "nombre_pagador": f"{session.get('nombre', 'Desconocido')} {session.get('apellido', 'Desconocido')}",
                    "correo": session.get('email', 'No registrado'),
                    "compania": session.get('compania', 'No disponible'),
                    "nro_contrato": session.get('contrato', 'No disponible'),
                    "cuotas_pagadas": ', '.join(map(str, session.get('cuotas', []))),
                    "total_pagado": montobs,
                    "referencia_pago": str(registro["referencia"]),
                    "telefono_utilizado": str(registro["telefonoemisor"]),
                    "fecha_pago": fecha_actual, 
                    "hora_pago": hora_actual,   
                    "banco_emisor": str(registro["bancoemisor"]),
                    "id_comercio": str(registro["idcomercio"]),
                    "monto_pagado": str(monto_pagado),
                    "moneda": moneda
                }
                # --- FIN DE CORRECCIÓN ---
                
                guardar_en_base_de_datos(datos_recibo)
                archivo_pdf = f"recibo_de_pago.pdf"
                generar_pdf(datos_recibo, archivo_pdf)
                enviar_correo(session.get('email', 'No registrado'), archivo_pdf)
                flash("¡Su pago ha sido aprobado!. Se ha enviado un recibo de pago a su correo registrado.", "payment_success")
                flash("Favor, pasar por nuestras oficinas a retirar su factura. Gracias.", "payment_success")
                
                # Marcar la referencia como aprobada
                cursor.execute(
                    """
                    UPDATE r4.registros_mibanco
                    SET status = %s
                    WHERE idcomercio = %s
                    """,
                    ("Aprobado", registro["idcomercio"])
                )
                connection.commit()
                
                
                logging.info("Pago aprobado y recibo enviado.")
                return redirect(url_for('info_planes'))
            
                # ⬅️ PAGO INSUFICIENTE → ERROR
            else:
                flash("⚠️ Pago encontrado, pero el monto es insuficiente. Se ha enviado un mensaje a su correo electrónico", "payment_error")

                enviar_correo_pago_insuficiente(
                    destinatario=session.get('email', 'No registrado'),
                    nombre=session.get('nombre', ''),
                    apellido=session.get('apellido', ''),
                    monto_pagado=monto_pagado,
                    monto_requerido=montobs
                )

                return redirect(url_for('metodos_de_pago_bs'))

        else:
            # ⬅️ PAGO NO ENCONTRADO → ERROR
            flash("Pago Móvil no encontrado.", "payment_error")
            logging.error("Pago Movil no encontrado en la base de datos.")

            return redirect(url_for('metodos_de_pago_bs'))

    except Exception as e:
        flash(f"Error inesperado: {str(e)}", "payment_error")
        logging.error(f"Error inesperado: {str(e)}")
        return redirect(url_for('metodos_de_pago_bs'))

    finally:
        if 'cursor' in locals():
            cursor.close()


def guardar_en_base_de_datos(datos_recibo):
    """Guarda los datos en la tabla recibos si el monto es suficiente."""
    try:
        connection = get_zu_db_connection()
        cursor = connection.cursor(cursor_factory=RealDictCursor)

        consulta_recibos = """
        INSERT INTO aplication_web.recibos (nombre_pagador, correo, compania, nro_contrato, cuotas_pagadas, 
                             total_pagado, referencia_pago, telefono_utilizado, fecha_pago, 
                             hora_pago, banco_emisor, id_comercio, monto_pagado, moneda)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        valores_recibos = (
            datos_recibo['nombre_pagador'],
            datos_recibo['correo'],
            datos_recibo['compania'],
            datos_recibo['nro_contrato'],
            datos_recibo['cuotas_pagadas'],
            datos_recibo['total_pagado'],
            datos_recibo['referencia_pago'],
            datos_recibo['telefono_utilizado'],
            datos_recibo['fecha_pago'],
            datos_recibo['hora_pago'],
            datos_recibo['banco_emisor'],
            datos_recibo['id_comercio'],
            datos_recibo['monto_pagado'],
            datos_recibo['moneda']
        )
        cursor.execute(consulta_recibos, valores_recibos)
        connection.commit()
        logging.info("Datos guardados correctamente en la tabla recibos.")

    except Exception as error:
        logging.error(f"Error al insertar datos en Postgre: {error}")
        print(f"Error Postgre: {error}")
        connection.rollback()

    finally:
        cursor.close()

with open("zona_usuario/static/img/logo_blanco.png", "rb") as img_file:
    encoded_image = base64.b64encode(img_file.read()).decode('utf-8')

# Configura las opciones para permitir acceso a archivos locales
options = {
    'enable-local-file-access': '',  
    'no-images': '',                 
}

image_path = f"data:image/png;base64,{encoded_image}"

# Diccionario de códigos y nombres de bancos
bancos = {
    "171": "BANCO ACTIVO(0171)",
    "166": "BANCO AGRICOLA DE VENEZUELA(0166)",
    "128": "BANCO CARONI(0128)",
    "175": "BANCO BICENTENARIO BANCO UNIVERSAL(0175)",
    "114": "BANCO DEL CARIBE(0114)",
    "163": "BANCO DEL TESORO (0163)",
    "177": "BANCO DE LA FUERZA ARMADA NACIONAL BOLIVARIANA (0177)",
    "102": "BANCO DE VENEZUELA(0102)",
    "115": "BANCO EXTERIOR(0115)",
    "191": "BANCO NACIONAL DE CREDITO(0191)",
    "116": "BANCO OCCIDENTAL DE DESCUENTO(0116)",
    "138": "BANCO PLAZA (0138)",
    "108": "BANCO PROVINCIAL(0108)",
    "137": "BANCO SOFITASA (0137)",
    "156": "100% BANCO(0156)",
    "168": "BANCRECER(0168)",
    "172": "BANCAMIGA BANCO UNIVERSAL (0172)",
    "134": "BANESCO(0134)",
    "174": "BANPLUS BANCO UNIVERSAL(0174)",
    "200": "BATPAY",
    "157": "DEL SUR BANCO UNIVERSAL (0157)",
    "151": "FONDO COMUN(0151)",
    "105": "MERCANTIL(0105)",
    "169": "MIBANCO BANCO DE DESARROLLO (0169)",
    "104": "VENEZOLANO DE CREDITO(0104)"
}

def obtener_nombre_banco(codigo_banco):
    """Función para obtener el nombre del banco a partir de su código."""
    return bancos.get(codigo_banco, "Banco no encontrado")

def generar_pdf(datos_recibo, archivo_salida):
    """Genera un PDF con la información del recibo, formateando fecha, hora y montos correctamente."""
    
    fecha_original = datos_recibo.get('fecha_pago', '')
    hora_pago = datos_recibo.get('hora_pago', '')

    # Función robusta para formatear fechas
    def formatear_fecha(fecha_str):
        for fmt in ("%Y-%m-%d", "%m/%d/%Y", "%d-%m-%Y"):
            try:
                fecha = datetime.strptime(fecha_str, fmt)
                return fecha.strftime("%d/%m/%Y") 
            except ValueError:
                continue
        return fecha_str 

    # Aplicar el formateo
    if isinstance(fecha_original, str) and fecha_original.strip():
        fecha_formateada = formatear_fecha(fecha_original)
    else:
        fecha_formateada = fecha_original  

    print(f"Fecha formateada: {fecha_formateada}")


    # Convertir la lista de cuotas pagadas a un string separado por comas
    cuotas_pagadas = datos_recibo.get('cuotas_pagadas', [])
    if isinstance(cuotas_pagadas, list):
        cuotas_pagadas = ", ".join(cuotas_pagadas)

    # Función para formatear montos con separador de miles y coma decimal
    def formatear_monto(valor):
        try:
            return "{:,.2f}".format(float(valor)).replace(",", "X").replace(".", ",").replace("X", ".")
        except ValueError:
            return "0,00"

    # Función para verificar si el monto ya está formateado correctamente
    def esta_formateado(monto):
        return bool(re.match(r"^\d{1,3}(\.\d{3})*,\d{2}$", str(monto)))  


    antes_del_formateo_total = str(datos_recibo.get('total_pagado', '0'))
    antes_del_formateo_monto = str(datos_recibo.get('monto_pagado', '0'))

    print("Antes del formateo:", antes_del_formateo_total, antes_del_formateo_monto)

    # Aplicar el formateo solo si el monto no está ya en formato correcto
    total_pagado = antes_del_formateo_total if esta_formateado(antes_del_formateo_total) else formatear_monto(antes_del_formateo_total)
    monto_pagado = antes_del_formateo_monto if esta_formateado(antes_del_formateo_monto) else formatear_monto(antes_del_formateo_monto)

    print("Después del formateo:", total_pagado, monto_pagado)
    
    
    # Obtener el código del banco y su nombre correspondiente
    codigo_banco = datos_recibo.get('banco_emisor', '')
    nombre_banco = obtener_nombre_banco(codigo_banco)
    moneda = session.get('moneda_pago', '')
    
    compania_original = datos_recibo.get('compania', '').strip().lower()
    compania_mapeada = 'Desconocida'

    if compania_original == 'rmp':
        compania_mapeada = 'Rescarven Medicina Prepagada'
    elif compania_original == 'amb':
        compania_mapeada = 'Rescarven Ambulancias'
    else:
        compania_mapeada = datos_recibo.get('compania', '') 

    html_content = f"""
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Recibo de Pago</title>
        <style>
        body {{
            font-family: Arial, Helvetica, sans-serif;
            font-style: italic;
            background-color: #e1f5fe;
            padding: 20px;
        }}
        .recibo-container {{
            padding-top: 120px;
            margin-top: 120px;
            background: #e1f5fe;
        }}
        .header {{
            text-align:right;
            background: #03519E;
            color: white; 
            padding: 20px;
            border-radius: 12px 12px 0 0;
            border-bottom: 4px solid #023A70;
        }}
        .header h1 {{
            margin-right: 110px; /* ajusta este valor a gusto */
        }}
        .datos-persona, .datos-recibo, .extra-info {{
            margin-top: 30px;
            padding: 20px;
            border-radius: 8px;
            background: #f3f3f3;
            box-shadow: 0px 8px 25px rgba(0, 0, 0, 0.6);
        }}
        .datos-recibo table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            font-size: 13px;
        }}
        .datos-recibo th, .datos-recibo td {{
            padding: 10px;
            font-size: 14px;
            text-align: center;
            border: 1px solid #D9251D;
            word-wrap: break-word;
        }}
        .datos-recibo th {{
            background-color: #D9251D;
            color: white;
            font-size: 14px;
        }}
        .datos-recibo th:first-child,
        .datos-recibo td:first-child {{
            width: 10%; /* Reducimos "Cuotas Pagadas" */
        }}
        .datos-recibo th:nth-child(5),
        .datos-recibo td:nth-child(5) {{
            width: 15%; /* Damos más espacio a la hora */
        }}
        .datos-recibo th:nth-child(3),
        .datos-recibo td:nth-child(3) {{
            font-size: 14px;
            font-weight: normal; /* Quitamos la negrita */
        }}
        .extra-info .monto-pagado {{
            color: #D9251D;
            font-size: 30px;
            text-align: center;
            display: inline-block;
            margin-top: 10px;
        }}
        .extra-info .monto-label {{
            color: #03519E; /* Azul del código */
            font-size: 30px;
            display: inline-block;
            margin-right: 5px;
        }}
        img {{
            padding-top: 100px;
            margin-top: 130px;
            width: 400px; 
            height: auto;
            position: absolute;
            left: 10px;
        }}
    </style>
    </head>
    <body>

        <img src="{image_path}" alt="Logo Rescarven" />

        <div class="recibo-container">
            <div class="header">
                <h1>Recibo de Pago</h1>
            </div>

            <div class="datos-persona">
                <p><strong>Nombre:</strong> {datos_recibo.get('nombre_pagador', '')}</p>
                <p><strong>Compañía:</strong>{compania_mapeada}</p>
                <p><strong>Número de Contrato:</strong> {datos_recibo.get('nro_contrato', '')}</p>
                <p><strong>Teléfono Utilizado:</strong> {datos_recibo.get('telefono_utilizado', '')}</p>
            </div>

            <div class="datos-recibo">
                <table>
                    <tr>
                        <th>Cuotas Pagadas</th>
                        <th>Monto Cuotas</th>
                        <th><strong>Referencia de Pago</strong></th>
                        <th>Fecha de Pago</th>
                        <th>Hora</th>
                        <th>Banco Emisor</th>
                    </tr>
                    <tr>
                        <td>{cuotas_pagadas}</td>
                        <td>{total_pagado} {moneda}.</td>
                        <td>{datos_recibo.get('referencia_pago', '')}</td>
                        <td>{fecha_formateada}</td>
                        <td>{hora_pago}</td>
                        <td>{nombre_banco}</td>
                    </tr>
                </table>
            </div>

            <div class="extra-info">
            <center>
                <span class="monto-label">Monto Pagado:</span><span class="monto-pagado">{total_pagado} {moneda}.</span>
            </center>
            </div>
        </div>
    </body>
    </html>
    """

    pdfkit.from_string(html_content, archivo_salida)
    print(f"PDF generado correctamente en {archivo_salida}")

@app.route('/recibo_de_pago')
@no_cache
def recibo_de_pago():
    try:
        if 'email' not in session:
            logging.warning("Intento de acceso sin sesión autenticada.")
            return "Usuario no autenticado", 401

        email_usuario = session['email']
        logging.info(f"Usuario {email_usuario} está accediendo a su recibo de pago.")

        connection = get_zu_db_connection()
        cursor = connection.cursor(cursor_factory=RealDictCursor)

        # Parámetros de la URL
        periodo = request.args.get('periodo')
        fecha_inicio = request.args.get('fecha_inicio')
        fecha_fin = request.args.get('fecha_fin')

        # Consulta base con filtro por correo
        query = """
            SELECT nombre_pagador, telefono_utilizado, nro_contrato, compania, fecha_pago,
            monto_pagado, referencia_pago, cuotas_pagadas, total_pagado, hora_pago, banco_emisor
            FROM aplication_web.recibos
            WHERE correo = %s
        """
        params = [email_usuario]
        filtros = []

        hoy = datetime.today().date()

        # Lógica de filtros según periodo
        if periodo == "hoy":
            filtros.append("fecha_pago = %s")
            params.append(hoy)

        elif periodo == "ultima_semana":
            fecha_inicio = hoy - timedelta(days=6)
            fecha_fin = hoy
            filtros.append("fecha_pago BETWEEN %s AND %s")
            params.extend([fecha_inicio, fecha_fin])

        elif periodo == "mes":
            fecha_inicio = hoy.replace(day=1)
            fecha_fin = hoy
            filtros.append("fecha_pago BETWEEN %s AND %s")
            params.extend([fecha_inicio, fecha_fin])

        elif periodo == "tres_meses":
            fecha_inicio = hoy - timedelta(days=89)
            fecha_fin = hoy
            filtros.append("fecha_pago BETWEEN %s AND %s")
            params.extend([fecha_inicio, fecha_fin])

        elif not periodo and fecha_inicio and fecha_fin:
            filtros.append("fecha_pago BETWEEN %s AND %s")
            params.extend([fecha_inicio, fecha_fin])

        # Agregar los filtros adicionales a la consulta
        if filtros:
            query += " AND " + " AND ".join(filtros)

        logging.info(f"Consulta SQL: {query}")
        logging.info(f"Parámetros: {params}")

        # Ejecutar consulta
        cursor.execute(query, params)
        recibos = cursor.fetchall()

        logging.info(f"Recibos encontrados: {len(recibos)}")

        return render_template('recibo_de_pago.html', recibos=recibos,
        periodo=periodo, fecha_inicio=fecha_inicio, fecha_fin=fecha_fin)

    except Exception as e:
        logging.error(f"Error al obtener los recibos para {email_usuario}: {e}")
        return render_template('recibo_de_pago.html', recibos=[])

COMMERCE_TOKEN = os.getenv('COMMERCE_TOKEN')
OTP_MIBANCO_URL = os.getenv('OTP_MIBANCO_URL')

def generar_token(data):
    mensaje = f"{data['Banco']}{data['Monto']}{data['Telefono']}{data['Cedula']}"
    return hmac.new(COMMERCE_TOKEN.encode(), mensaje.encode(), hashlib.sha256).hexdigest()

@app.route('/otp_mibanco', methods=['POST'])
def otp_mibanco():
    session.pop('consulta_id', None)
    if request.method == 'POST':
        # Obtener valores individuales del formulario
        phone_prefix = request.form['customerPhonePrefix']
        phone_number = request.form['customerPhoneNumber']
        id_prefix = request.form['customerIdPrefix']
        id_number = request.form['customerId']
        banco = request.form['Banco']
        monto_str = request.form['Monto']
        monto = monto_str.replace('.', '').replace(',', '.') if monto_str else '0.00'

        # Guardar en session con sufijo _dimb
        session['customerPhonePrefix_dimb'] = phone_prefix
        session['customerPhoneNumber_dimb'] = phone_number
        session['customerIdPrefix_dimb'] = id_prefix
        session['customerId_dimb'] = id_number
        session['Banco_dimb'] = banco
        session['Monto_dimb'] = monto

        # Concatenar para enviar a la API
        telefono = phone_prefix + phone_number
        cedula = id_prefix + id_number

        data = {
            "Banco": banco,
            "Monto": monto,
            "Telefono": telefono,
            "Cedula": cedula
        }

        headers = {
            "Content-Type": "application/json",
            "Authorization": generar_token(data),
            "Commerce": COMMERCE_TOKEN
        }
        print("Request_OTP_mibanco",headers, data)  
        try:
            response = requests.post(OTP_MIBANCO_URL, json=data, headers=headers)
            data_respuesta = response.json()
            print("Respuesta de otp mi banco:", data_respuesta, response.status_code)  # Imprimir la respuesta de la API para depuración

            if data_respuesta.get("code") == "202":
                return jsonify({"success": True})
            else:
                return jsonify({"success": False, "message":data_respuesta.get("message", "Error desconocido")}), 400

        except Exception as e:
            return jsonify({"success": False, "message": f"Error en la solicitud: {str(e)}"}), 500

API_DI_MIBANCO = os.getenv('API_DI_MIBANCO')
API_CO_MIBANCO = os.getenv('API_CO_MIBANCO')

def token_di_mibanco(data):
    mensaje = f"{data['Banco']}{data['Cedula']}{data['Telefono']}{data['Monto']}{data['OTP']}"
    return hmac.new(COMMERCE_TOKEN.encode(), mensaje.encode(), hashlib.sha256).hexdigest()

def token_consulta_operaciones(consulta_id):
    return hmac.new(COMMERCE_TOKEN.encode(), consulta_id.encode(), hashlib.sha256).hexdigest()

@app.route('/di_mibanco', methods=['POST'])
def di_mibanco():
    try:
        banco = session.get('Banco_dimb')
        monto = session.get('Monto_dimb')
        telefono = session.get('customerPhonePrefix_dimb') + session.get('customerPhoneNumber_dimb')
        cedula = session.get('customerIdPrefix_dimb') + session.get('customerId_dimb')
        nombre = "Rescarven AMB"
        concepto = "Pago en línea"
        otp = request.json.get('OTP')
        moneda = session.get('moneda_pago', '')
        
        print(f"moonto mi banco: {monto}")

        
        banco_codigo = str(banco).lstrip("0")

        payload = {
            "Banco": banco,
            "Monto": monto,
            "Telefono": telefono,
            "Cedula": cedula,
            "Nombre": nombre,
            "OTP": otp,
            "Concepto": concepto
        }

        headers = {
            "Content-Type": "application/json",
            "Authorization": token_di_mibanco(payload),
            "Commerce": COMMERCE_TOKEN
        }
        print(f"{payload}")
        print("Request Di_mibanco:", headers, payload)
        response = requests.post(API_DI_MIBANCO, json=payload, headers=headers)
        

        
        data = response.json()
        print("Respuesta Di_mibanco:", data, response.status_code)
        print("monto:", monto)

        code = data.get("code")
        mensaje = data.get("message", "Respuesta desconocida del servidor")

        # Si el pago fue aprobado directamente
        if code == "ACCP":
            flash("Su pago ha sido aprobado", "success")
            mensaje = "¡Su pago ha sido aprobado!"
            return redirect(url_for('info_planes', mensaje=mensaje))

        # Si no fue aprobado directamente, intentar consulta
        consulta_id = str(data.get("id", "")).strip()
        if consulta_id:
            session['consulta_id'] = consulta_id
            consulta_headers = {
                "Content-Type": "application/json",
                "Authorization": token_consulta_operaciones(consulta_id),
                "Commerce": COMMERCE_TOKEN
            }
            consulta_payload = {"Id": consulta_id}
            print("Request Consulta_mibanco:", consulta_headers, consulta_payload)
            time.sleep(15)
            consulta_response = requests.post(API_CO_MIBANCO, json=consulta_payload, headers=consulta_headers)
            consulta_data = consulta_response.json()
            referencia = consulta_data.get("reference", "")

            confirmar_pagos(
                numero_cobros= session.get('idcuotas', []),
                forma_pago= session.get('compania', 'Desconocido'),
                moneda_pago= session.get('moneda_pago', 'VES'),
                referencia= referencia,
                tasa= session.get('lista_tasas'),
                montos= monto
                )
            
            print("Respuesta Consulta_mibanco", consulta_data, consulta_response.status_code)
            code2 = consulta_data.get("code")
            mensaje2 = consulta_data.get("message", "Respuesta desconocida en consulta")

            if code2 == "ACCP":
                compania = session.get('compania', 'Desconocido')

                # Determinar el id_comercio según la compañía
                if compania == 'RMP':
                    id_comercio = 000000000
                elif compania == 'AMB':
                    id_comercio = 000000000
                else:
                    id_comercio = None  # O cualquier otro valor que desees manejar
                
                datos_recibo = {
                    "nombre_pagador": f"{session.get('nombre', 'Desconocido')} {session.get('apellido', 'Desconocido')}",
                    "correo": session.get('email', 'No registrado'),
                    "compania": compania,
                    "nro_contrato": session.get('contrato', 'No disponible'),
                    "cuotas_pagadas": ', '.join(map(str, session.get('cuotas', []))),
                    "total_pagado": monto,
                    "referencia_pago": referencia,
                    "telefono_utilizado": telefono,
                    "fecha_pago": datetime.now().strftime("%Y-%m-%d"),
                    "hora_pago": datetime.now().strftime("%H:%M:%S"),
                    "banco_emisor": banco_codigo,
                    "id_comercio": id_comercio,
                    "monto_pagado": str(monto),
                    "moneda": moneda
                }

                guardar_en_base_de_datos(datos_recibo)
                archivo_pdf = "recibo_de_pago.pdf"
                generar_pdf(datos_recibo, archivo_pdf)
                enviar_correo(session.get('email', 'No registrado'), archivo_pdf)

                logging.info("Pago aprobado y recibo enviado.")
                
                return redirect(url_for('info_planes', mensaje="¡Su pago ha sido aprobado!"))
            else:
                return jsonify({"success": False, "message": mensaje2}), 400
        else:
            return jsonify({"success": False, "message": "No se recibió ID para consulta"}), 400

    except Exception as e:
        return jsonify({"success": False, "message": f"Error en la solicitud: {str(e)}"}), 500

@app.route('/verificar_operacion', methods=['POST','GET'])
def verificar_operacion():
    mensaje = None
    exito = False
    consulta_id = session.get('consulta_id')

    if consulta_id:
        try:
            consulta_headers = {
                "Content-Type": "application/json",
                "Authorization": token_consulta_operaciones(consulta_id),
                "Commerce": COMMERCE_TOKEN
            }
            consulta_payload = {
                "Id": consulta_id
            }
            print("Request Consulta_mibanco:",consulta_headers ,consulta_payload)  
            consulta_response = requests.post(API_CO_MIBANCO, json=consulta_payload, headers=consulta_headers)
            consulta_data = consulta_response.json()
            print("Respuesta Consulta_mibanco", consulta_data, consulta_response.status_code)

            if consulta_data.get("code") == "ACCP":
                mensaje = f"Su pago ha sido aprobado"
                exito = True
            else:
                mensaje = f"{consulta_data.get('message', 'Sin mensaje del servidor')}"
                exito = False
        except Exception as e:
            mensaje = f"Error al consultar operación: {str(e)}"
            exito = False
    else:
        mensaje = "No hay ID de operación para verificar."
        exito = False

    return render_template(
        'di_mibanco.html',
        mensaje=mensaje,
        exito=exito,
        monto_dimb=session.get('Monto_dimb')
    )
    
def enviar_correo_pago_insuficiente(destinatario, nombre, apellido, monto_pagado, monto_requerido):
    print(f"Enviando correo de PAGO INSUFICIENTE a {destinatario}")

    try:
        mensaje_html = f"""
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body {{
      margin: 0;
      padding: 0;
      font-family: Arial, sans-serif;
    }}
    .contenedor {{
      max-width: 95%;
      width: 500px;
      margin: auto;
      padding: 20px;
      border-radius: 15px;
      border: 1px solid #d9534f;
      background-color: white;
      text-align: center;
    }}
    .logo img {{
      width: 70%;
      max-width: 400px;
      border-radius: 10px;
    }}
    .texto {{
      color:black;
      font-size: 0.9rem;
      text-align: left;
      margin-top: 10px;
      line-height: 1.5;
    }}
    .pie {{
      font-size: 0.8rem;
      color: #d9534f;
      text-align: center;
      margin-top: 20px;
    }}
  </style>
</head>
<body>

  <div class="contenedor">

    <div class="logo">
      <img src="https://i.postimg.cc/RZYLV7hV/logo-rescarven.png" alt="Logo Rescarven">
    </div>

    <div class="texto">
      <p><b>Buen día {nombre} {apellido},</b></p>

      <p>
      Hemos recibido su pago recientemente. Sin embargo, el monto acreditado 
      (<b>{monto_pagado} Bs</b>) es <b>insuficiente</b> y no cubre la totalidad de la cuota 
      correspondiente, cuyo monto requerido es de <b>{monto_requerido} Bs</b>.
      </p>

      <p>
      Para evitar inconvenientes o la suspensión del servicio, 
      le invitamos cordialmente a comunicarse con nuestro 
      <b>equipo de Atención al Cliente</b> al siguiente número:
      </p>

      <p style="text-align:center; font-size:1.1rem; font-weight:bold; color:#d9534f;">
      (0212) 628.25.00
      </p>

      <p>
      Estaremos encantados de ayudarle a regularizar su situación y brindarle la información necesaria.
      </p>

      <p>Gracias por elegir Rescarven.</p>
      <p>- Equipo de Rescarven</p>
    </div>

  </div>

  <div class="pie">
    <p style="margin: 0;">Rescarven - Atención al cliente (0212) 628.25.00.</p>
    <p style="margin: 0;">© 2025 Rescarven</p>
  </div>

</body>
</html>
        """

        data = {
            "destinatarios": [destinatario],
            "asunto": "Rescarven - Pago insuficiente",
            "mensaje": {
                "tipo": "html",
                "contenido": mensaje_html
            }
        }

        json_str = json.dumps(data, indent=4, ensure_ascii=False)
        response = requests.post(API_CORREO, data={"datos": json_str})
        response.raise_for_status()

    except Exception as e:
        print(f"Error al enviar correo de pago insuficiente: {e}")

def enviar_correo(destinatario, pdf_filename):
    print(f"Enviando correo a {destinatario} con el archivo {pdf_filename}")

    try:
        # 1. Leer y codificar el PDF en Base64
        with open(pdf_filename, "rb") as pdf_file:
            pdf_content = pdf_file.read()
            pdf_base64 = base64.b64encode(pdf_content).decode('utf-8')

        # 2. Construir el objeto de datos (JSON)
        data = {
            "destinatarios": [destinatario],
            "asunto": "Rescarven - Recibo de pago",
            "mensaje": {
                "tipo": "html",
                "contenido": f"""
                <!DOCTYPE html>
                <html lang="es">
                <head>
                  <meta charset="UTF-8">
                  <meta name="viewport" content="width=device-width, initial-scale=1.0">
                  <style>
                    body {{ margin: 0; padding: 0; font-family: Arial, sans-serif; }}
                    .contenedor {{ max-width: 95%; width: 500px; margin: auto; padding: 20px; border-radius: 15px; border: 1px solid #0091ff; background-color: white; text-align: center; box-sizing: border-box; }}
                    .logo img {{ width: 70%; max-width: 400px; height: auto; border-radius: 10px; }}
                    .logo-secundario {{ margin-top: 15px; }}
                    .logo-secundario img {{ width: 100%; max-width: 200px; height: auto; }}
                    .texto {{ color:black; font-size: 0.9rem; text-align: left; margin-top: 10px; }}
                    .pie {{ font-size: 0.8rem; color: #0091ff; text-align: center; margin-top: 20px; }}
                    .nota {{ text-align: center; font-size: 0.85rem; color: rgb(116, 116, 116); margin-top: 10px; }}
                    @media (max-width: 480px) {{
                      .contenedor {{ padding: 15px; }}
                      .texto {{ font-size: 1rem; }}
                      .logo img {{ max-width: 90vw; }}
                      .logo-secundario img {{ max-width: 50vw; }}
                    }}
                  </style>
                </head>
                <body>
                  <div class="contenedor">
                    <div class="logo">
                      <img src="https://api.rescarven.com/imagenes/logorescarven.png" alt="Logo Rescarven">
                    </div>
                    <div class="logo-secundario">
                      <img src="https://api.rescarven.com/imagenes/imagencorreo.jpg" alt="Decorativo">
                    </div>
                    <div class="texto">
                      <p>Un cordial saludo de Rescarven,</p><br>
                      <p>Adjunto a este correo encontrará su <b>recibo de pago</b> correspondiente en formato PDF.</p>
                      <p>Si tiene alguna duda o necesita más información, no dude en contactarnos.</p>
                      <p>¡Gracias por confiar en nosotros!</p><br>
                      <p>- El equipo de Rescarven</p>
                    </div>
                  </div>
                  <div class="pie">
                    <p style="margin: 0;">Rescarven - Atención al cliente (0212) 628.25.00.</p>
                    <p style="margin: 0;">© 2025 Rescarven</p>
                  </div>
                  <p class="nota">Por favor, no responder a este correo</p>
                </body>
                </html>
                """
            },
            "adjuntos": [
                {
                    "nombre": pdf_filename,
                    "tipo": "application/pdf",
                    "contenido": pdf_base64
                }
            ]
        }

        # 3. Preparar el envío
        # Serializamos el JSON
        json_str = json.dumps(data, ensure_ascii=False)
        
        # Usamos un context manager para el archivo en 'files' para asegurar que se cierre
        with open(pdf_filename, 'rb') as f:
            files = {
                'archivos': (pdf_filename, f, 'application/pdf')
            }
            data_form = {'datos': json_str}
            
            # 4. Petición POST a la API
            response = requests.post(API_CORREO, data=data_form, files=files)

        # 5. Logs y verificación de respuesta
        print("==== Respuesta de la API ====")
        print(f"Status Code: {response.status_code}")
        print(f"Response JSON: {response.text}")

        response.raise_for_status()

        if response.status_code == 200:
            logging.info(f"Correo enviado satisfactoriamente a {destinatario}")
            print(f" [✓] Correo enviado a {destinatario}")
        else:
            print(f" [!] Error en la respuesta de la API: {response.text}")

    except requests.exceptions.RequestException as e:
        logging.error(f"Error de red al enviar el correo: {e}")
        print(f" [X] Error de red: {e}")
    except Exception as e:
        logging.error(f"Error inesperado en enviar_correo: {e}")
        print(f" [X] Error inesperado: {e}")
        
        
def confirmar_pagos(numero_cobros, forma_pago, moneda_pago, referencia, tasa, montos):
    API_CONSULTAS = os.getenv('API_CONSULTAS')
    api_url_pagos = f"{API_CONSULTAS}/apipagos"


    for i in range(len(numero_cobros)):
        try:
            monto_float = float(str(montos).replace(",", "."))
            tasa_float = float(str(tasa[i]).replace(",", "."))
        except (ValueError, IndexError) as e:
            print(f"[✗] Error al convertir monto o tasa: monto={montos}, tasa={tasa[i]}")
            continue

        payload = {
            "Numero_cobro": str(numero_cobros[i]).strip(),
            "Forma_pago": str(forma_pago).strip(),
            "Moneda_pago": str(moneda_pago).strip(),
            "Referencia": str(referencia).strip(),
            "Tasa": f"{tasa_float:.4f}",
            "Monto": f"{monto_float:.2f}"
        }

        print("[DEBUG] Payload enviado a API:", payload)
        
        try:
            response = requests.post(api_url_pagos, json=payload, headers=headers_api_rescarven)
            data = response.json()

            if response.status_code == 200:
                # Verificamos si la respuesta viene cifrada
                print("[DEBUG] Respuesta cruda de la API:", data)
                respuesta_cifrada = data.get('datos')  # o 'mensaje', depende de la API

                if respuesta_cifrada:
                    datos_desencriptados = desencriptar_datos(respuesta_cifrada, token_api_rescarven)
                    mensaje = datos_desencriptados.get('mensaje', 'Cobro confirmado correctamente')
                else:
                    mensaje = data.get('mensaje', 'Cobro confirmado correctamente')

                mensaje = str(mensaje)

                print("DEBUG mensaje:", mensaje, "tipo:", type(mensaje))
                print(f"[✓] Cuota {numero_cobros[i]} actualizada correctamente: {mensaje}")

            else:
                error = data.get('error', 'Error al procesar el cobro')
                flash(f"{numero_cobros[i]}: {error}", "danger")
                print(f"[✗] Error al actualizar cuota {numero_cobros[i]}: {error}")

        except requests.exceptions.RequestException as e:
            flash(f"{numero_cobros[i]}: Error al conectar con la API: {str(e)}", "danger")
            print(f"[✗] Error de conexión al actualizar cuota {numero_cobros[i]}: {str(e)}")


@app.route("/enviar_recibo", methods=["POST"])
def enviar_recibo():
    try:
        data = request.get_json()
        logging.info(f"Datos recibidos en Flask: {data}")  
        print("Datos recibidos en Flask:", data)  

        if not data:
            logging.warning("No se recibieron datos")  
            return jsonify({"error": "No se recibieron datos"}), 400

        # 🔹 Enviar mensaje de "Enviando recibo..."
        response = {"message": "El recibo se está enviando...", "status": "info"}

        # Generar PDF
        pdf_filename = "recibo_de_pago.pdf"  
        generar_pdf(data, pdf_filename)
        logging.info(f"PDF generado con nombre: {pdf_filename}")  

        print("Llamando a enviar_correo...")  
        enviar_correo(data["correo_pagador"], pdf_filename)  
        logging.info(f"Correo enviado a: {data['correo_pagador']}")  

        # ✅ Si todo sale bien, enviamos el mensaje de éxito
        response["message"] = "Recibo enviado correctamente."
        response["status"] = "success"
        return jsonify(response), 200

    except Exception as e:
        logging.error(f"Error en el servidor: {str(e)}")  
        print("Error en el servidor:", str(e))  
        return jsonify({"message": "Error al enviar el recibo.", "status": "error"}), 500

# Establecer la configuración regional a español
locale.setlocale(locale.LC_ALL, 'es_ES.UTF-8')

with open("zona_usuario/static/img/logo_blanco.png", "rb") as img_file:
    encoded_image = base64.b64encode(img_file.read()).decode('utf-8')

def formatear_fecha(fecha_str):
    # Convertir la cadena de fecha a un objeto datetime
    fecha = datetime.strptime(fecha_str, "%Y-%m-%d") 
    return fecha.strftime("%d-%m-%Y") 

def formatear_monto(monto_str):
    try:
        # Convertir la cadena a un número flotante
        monto = float(monto_str)
        
        return "{:,.2f}".format(monto).replace(',', 'X').replace('.', ',').replace('X', '.')
    except ValueError:
        logging.error(f"Error al convertir el monto: {monto_str}") 
        print(f"Error al convertir el monto: {monto_str}")
        return monto_str  

def generar_pdf_guardado(data):
    logging.info("Generando PDF...")  
    print("Generando PDF...") 

    # Diccionario de bancos
    bancos = {
        "171": "BANCO ACTIVO(0171)",
        "166": "BANCO AGRICOLA DE VENEZUELA(0166)",
        "128": "BANCO CARONI(0128)",
        "175": "BANCO BICENTENARIO BANCO UNIVERSAL(0175)",
        "114": "BANCO DEL CARIBE(0114)",
        "163": "BANCO DEL TESORO (0163)",
        "177": "BANCO DE LA FUERZA ARMADA NACIONAL BOLIVARIANA (0177)",
        "102": "BANCO DE VENEZUELA(0102)",
        "115": "BANCO EXTERIOR(0115)",
        "191": "BANCO NACIONAL DE CREDITO(0191)",
        "116": "BANCO OCCIDENTAL DE DESCUENTO(0116)",
        "138": "BANCO PLAZA (0138)",
        "108": "BANCO PROVINCIAL(0108)",
        "137": "BANCO SOFITASA (0137)",
        "156": "100% BANCO(0156)",
        "168": "BANCRECER(0168)",
        "172": "BANCAMIGA BANCO UNIVERSAL (0172)",
        "134": "BANESCO(0134)",
        "174": "BANPLUS BANCO UNIVERSAL(0174)",
        "200": "BATPAY",
        "157": "DEL SUR BANCO UNIVERSAL (0157)",
        "151": "FONDO COMUN(0151)",
        "105": "MERCANTIL(0105)",
        "169": "MIBANCO BANCO DE DESARROLLO (0169)",
        "104": "VENEZOLANO DE CREDITO(0104)"
    }

    fecha_formateada = formatear_fecha(data['fecha_pago'])
    total_pagado_formateado = formatear_monto(data['total_pagado'])  
    monto_pagado_formateado = formatear_monto(data['monto_pagado'])  

    # Obtener el nombre del banco
    moneda = session.get('moneda_pago', '')
    banco_num = data['banco_emisor']
    banco_nombre = bancos.get(banco_num, 'Banco Desconocido')  
    logging.info(f"Banco emisor: {banco_nombre}")  
    compania_original = data.get('compania', '').strip().lower()
    compania_mapeada = 'Desconocida'

    if compania_original == 'rmp':
        compania_mapeada = 'Rescarven Medicina Prepagada'
    elif compania_original == 'amb':
        compania_mapeada = 'Rescarven Ambulancias'
    else:
        compania_mapeada = data.get('compania', '')

    html_content = f"""
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Detalles de Pago</title>
        <style>
        body {{
            font-family: Arial, Helvetica, sans-serif;
            font-style: italic;
            background-color: #e1f5fe;
            padding: 20px;
        }}
        .recibo-container {{
            padding-top: 120px;
            margin-top: 120px;
            background: #e1f5fe;
        }}
        .header {{
            text-align:right;
            background: #03519E;
            color: white; 
            padding: 20px;
            border-radius: 12px 12px 0 0;
            border-bottom: 4px solid #023A70;
        }}
        .header h1 {{
            margin-right: 110px; 
        }}
        .datos-persona, .datos-recibo, .extra-info {{
            margin-top: 30px;
            padding: 20px;
            border-radius: 8px;
            background: #f3f3f3;
            box-shadow: 0px 8px 25px rgba(0, 0, 0, 0.6);
        }}
        .datos-recibo table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            font-size: 13px;
        }}
        .datos-recibo th, .datos-recibo td {{
            padding: 10px;
            font-size: 14px;
            text-align: center;
            border: 1px solid #D9251D;
            word-wrap: break-word;
        }}
        .datos-recibo th {{
            background-color: #D9251D;
            color: white;
            font-size: 14px;
        }}
        .datos-recibo th:first-child,
        .datos-recibo td:first-child {{
            width: 10%; 
        }}
        .datos-recibo th:nth-child(5),
        .datos-recibo td:nth-child(5) {{
            width: 15%; 
        }}
        .datos-recibo th:nth-child(3),
        .datos-recibo td:nth-child(3) {{
            font-size: 14px;
            font-weight: normal;
        }}
        .extra-info .monto-pagado {{
            color: #D9251D;
            font-size: 30px;
            text-align: center;
            display: inline-block;
            margin-top: 10px;
        }}
        .extra-info .monto-label {{
            color: #03519E; /* Azul del código */
            font-size: 30px;
            display: inline-block;
            margin-right: 5px;
        }}
        img {{
            padding-top: 100px;
            margin-top: 130px;
            width: 400px; 
            height: auto;
            position: absolute;
            left: 10px;
        }}
    </style>
    </head>
    <body>
        <img src="{image_path}" alt="Logo Rescarven" />
        <div class="recibo-container">
            <div class="header">
                <h1>Recibo de Pago</h1>
            </div>
            <div class="datos-persona">
                <div class="detalle"><strong>Nombre del pagador:</strong> {data['nombre_pagador']}</div>
                <div class="detalle"><strong>Compañía:</strong> {compania_mapeada}</div>
                <div class="detalle"><strong>Número de contrato:</strong> {data['nro_contrato']}</div>
                <div class="detalle"><strong>Teléfono utilizado:</strong> {data['telefono_utilizado']}</div>
            </div>
            <div class="datos-recibo">
                <table>
                    <tr>
                        <th>Cuotas pagadas</th>
                        <th>Total pagado</th>
                        <th>Referencia de pago</th>
                        <th>Fecha de pago</th>
                        <th>Banco emisor</th>
                    </tr>
                    <tr>   
                        <td>{data['cuotas_pagadas']}</td>
                        <td>{total_pagado_formateado} {moneda}.</td>
                        <td>{data['referencia_pago']}</td>
                        <td>{fecha_formateada}</td>
                        <td>{banco_num} - {banco_nombre}</td>  <!-- Muestra número y nombre del banco -->
                    </tr>
                </table>
            </div>
            <div class="extra-info">
                <p><strong>Monto pagado:</strong> <span class="monto-pagado">{total_pagado_formateado} {moneda}.</span></p>
            </div>
        </div>
    </body>
    </html>
    """
    
    # Crear un archivo temporal para guardar el PDF
    with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp_file:
        pdfkit.from_string(html_content, tmp_file.name)
        
        print(f"PDF generado correctamente en {tmp_file.name}")
        return tmp_file.name  

@csrf.exempt
@app.route("/descargar_recibo", methods=["POST"])
def descargar_recibo():
    try:
        data = request.get_json()
        logging.info(f"Datos recibidos en Flask: {data}") 

        if not data:
            logging.warning("No se recibieron datos")  
            return jsonify({"error": "No se recibieron datos"}), 400

        # Generar PDF y obtener la ruta del archivo
        pdf_path = generar_pdf_guardado(data)
        logging.info(f"PDF generado y guardado en la ruta: {pdf_path}")  

        # Enviar el archivo como respuesta para su descarga
        logging.info(f"Enviando archivo {pdf_path} como adjunto para descarga")  
        return send_file(
            pdf_path, 
            as_attachment=True, 
            download_name='recibo_de_pago.pdf',
            mimetype='application/pdf'
        )

    except Exception as e:
        logging.error(f"Error en el servidor: {str(e)}")  
        return jsonify({"error": "Error interno del servidor"}), 500

if __name__ == '__main__':
    host = "0.0.0.0"  
    port = 0000  # Cambia esto al puerto que desees usar       

    # Obtener la IP local para mostrarla en la terminal
    local_ip = socket.gethostbyname(socket.gethostname())


    app.run(host=host, port=port, debug=True)