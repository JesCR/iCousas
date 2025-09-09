import os
import sys
import logging
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import pyodbc
from dotenv import load_dotenv
from dateutil import parser as date_parser

# Cargar variables de entorno (manejar problemas de BOM)
def load_env_file():
    """Carga variables de entorno desde archivo .env, manejando problemas de BOM."""
    env_file = os.path.join(os.getcwd(), '.env')
    if os.path.exists(env_file):
        with open(env_file, 'rb') as f:
            content = f.read()

        # Remover BOM si está presente
        if content.startswith(b'\xef\xbb\xbf'):  # BOM UTF-8
            content = content[3:]
            encoding = 'utf-8'
        elif content.startswith(b'\xff\xfe'):  # BOM UTF-16 LE
            content = content[2:]
            encoding = 'utf-16-le'
        elif content.startswith(b'\xfe\xff'):  # BOM UTF-16 BE
            content = content[2:]
            encoding = 'utf-16-be'
        else:
            encoding = 'utf-8'

        # Decodificar contenido
        try:
            decoded_content = content.decode(encoding)
        except UnicodeDecodeError:
            # Fallback a latin-1 si falla la decodificación
            decoded_content = content.decode('latin-1')

        # Parsear y establecer variables de entorno
        lines = decoded_content.split('\n')
        loaded_count = 0

        for line in lines:
            line = line.strip()
            # Saltar líneas vacías y líneas con caracteres nulos
            if (line and '\x00' not in line):
                # Manejar comentarios: tratar '#' como comentario solo si no está dentro de comillas o después de '='
                if line.startswith('#'):
                    continue  # Saltar líneas de comentario

                # Encontrar el primer '=' que no esté dentro de un valor
                if '=' in line:
                    # Dividir en el primer '=' para separar clave de valor
                    parts = line.split('=', 1)
                    if len(parts) == 2:
                        key = parts[0].strip()
                        value = parts[1].strip()

                        # Remover comentarios en línea (todo después de '#' si está precedido por espacio)
                        if '#' in value:
                            hash_pos = value.find('#')
                            # Tratar como comentario solo si está precedido por espacio (no parte del valor)
                            if hash_pos > 0 and value[hash_pos - 1] == ' ':
                                # Remover todo desde '#' en adelante (incluyendo el espacio antes del #)
                                value = value[:hash_pos].rstrip()

                        if key and value:  # Asegurar que tanto clave como valor no estén vacíos
                            os.environ[key] = value
                            loaded_count += 1
                            # Salida de debug para contraseñas (mostrar longitud para verificación, ocultar valor)
                            if 'PASSWORD' in key.upper():
                                print(f"Variable de contraseña cargada: {key} (longitud: {len(value)} caracteres)")
                            else:
                                print(f"Cargado: {key}={value}")
                else:
                    # Saltar líneas sin '='
                    continue

        print(f"Variables de entorno cargadas exitosamente ({loaded_count} variables)")

        # Establecer verificación SSL por defecto si no está configurada
        if 'HTTP_VERIFY_SSL' not in os.environ:
            os.environ['HTTP_VERIFY_SSL'] = 'false'  # Por defecto falso para pruebas
            print("Verificación SSL deshabilitada por defecto (establecer HTTP_VERIFY_SSL=true para producción)")
    else:
        print("Archivo .env no encontrado")

load_env_file()

# Configurar logging después de cargar variables de entorno
def setup_logging():
    """Configurar logging con manejadores de archivo y consola."""
    # Crear directorio de logs si no existe
    logs_dir = os.path.join(os.getcwd(), 'logs')
    os.makedirs(logs_dir, exist_ok=True)

    # Generar nombre de archivo de log con formato YYYY-MM-DD-HH.txt
    now = datetime.now()
    log_filename = now.strftime('%Y-%m-%d-%H') + '.txt'
    log_filepath = os.path.join(logs_dir, log_filename)

    # Crear logger
    logger = logging.getLogger(__name__)
    logger.setLevel(getattr(logging, os.getenv('LOG_LEVEL', 'INFO').upper()))

    # Crear formateadores
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )

    # Crear manejador de archivo
    file_handler = logging.FileHandler(log_filepath, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)  # Registrar todo en archivo
    file_handler.setFormatter(file_formatter)

    # Crear manejador de consola
    console_handler = logging.StreamHandler()
    console_handler.setLevel(getattr(logging, os.getenv('LOG_LEVEL', 'INFO').upper()))
    console_handler.setFormatter(console_formatter)

    # Agregar manejadores al logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger

logger = setup_logging()

class Config:
    """Gestión de configuración para variables de entorno."""

    # Variables de entorno requeridas
    REQUIRED_VARS = [
        'KEYCLOAK_URL', 'KEYCLOAK_CLIENT_ID', 'KEYCLOAK_USERNAME',
        'KEYCLOAK_PASSWORD', 'KEYCLOAK_GRANT_TYPE', 'HTTP_TIMEOUT',
        'HTTP_MAX_RETRIES', 'HTTP_RETRY_BACKOFF_BASE', 'SENSORS_BASE_URL',
        'SENSORS_ATTRIBUTES', 'SENSORS_TIME_WINDOW_MINUTES', 'SENSORS_LAST_N',
        'SENSORS_LIMIT', 'SENSORS_ORGANIZATION', 'DB_SERVER', 'DB_USERNAME',
        'DB_PASSWORD', 'DB_NAME', 'DB_CONNECTION_TIMEOUT'
    ]

    @classmethod
    def validate(cls) -> None:
        """Validar que todas las variables de entorno requeridas estén configuradas."""
        missing = []
        for var in cls.REQUIRED_VARS:
            if not os.getenv(var):
                missing.append(var)

        if missing:
            raise ValueError(f"Variables de entorno requeridas faltantes: {', '.join(missing)}")

    @classmethod
    def get_keycloak_config(cls) -> Dict[str, str]:
        """Obtener configuración de autenticación de Keycloak."""
        return {
            'url': os.getenv('KEYCLOAK_URL'),
            'client_id': os.getenv('KEYCLOAK_CLIENT_ID'),
            'username': os.getenv('KEYCLOAK_USERNAME'),
            'password': os.getenv('KEYCLOAK_PASSWORD'),
            'grant_type': os.getenv('KEYCLOAK_GRANT_TYPE')
        }

    @classmethod
    def get_http_config(cls) -> Dict[str, Any]:
        """Obtener configuración HTTP."""
        return {
            'timeout': int(os.getenv('HTTP_TIMEOUT', 15)),
            'max_retries': int(os.getenv('HTTP_MAX_RETRIES', 3)),
            'retry_backoff_base': int(os.getenv('HTTP_RETRY_BACKOFF_BASE', 1)),
            'verify_ssl': os.getenv('HTTP_VERIFY_SSL', 'true').lower() == 'true'
        }

    @classmethod
    def get_sensors_config(cls) -> Dict[str, Any]:
        """Obtener configuración de la API de sensores."""
        return {
            'base_url': os.getenv('SENSORS_BASE_URL'),
            'attributes': os.getenv('SENSORS_ATTRIBUTES'),
            'time_window_minutes': int(os.getenv('SENSORS_TIME_WINDOW_MINUTES', 20)),
            'last_n': int(os.getenv('SENSORS_LAST_N', 100)),
            'limit': int(os.getenv('SENSORS_LIMIT', 100)),
            'organization': os.getenv('SENSORS_ORGANIZATION')
        }

    @classmethod
    def get_db_config(cls) -> Dict[str, Any]:
        """Obtener configuración de base de datos."""
        return {
            'server': os.getenv('DB_SERVER'),
            'username': os.getenv('DB_USERNAME'),
            'password': os.getenv('DB_PASSWORD'),
            'database': os.getenv('DB_NAME'),
            'connection_timeout': int(os.getenv('DB_CONNECTION_TIMEOUT', 30))
        }

class AuthenticationError(Exception):
    """Excepción personalizada para fallos de autenticación."""
    pass

class AuthManager:
    """Maneja la autenticación de Keycloak usando flujo Resource Owner Password."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.http_config = Config.get_http_config()
        self._access_token: Optional[str] = None
        self._token_expires_at: Optional[datetime] = None

    def _create_session(self) -> requests.Session:
        """Crear sesión HTTP con configuración de reintentos."""
        session = requests.Session()

        retry_strategy = Retry(
            total=self.http_config['max_retries'],
            status_forcelist=[429, 500, 502, 503, 504],
            backoff_factor=self.http_config['retry_backoff_base'],
            allowed_methods=['HEAD', 'GET', 'OPTIONS', 'POST']
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount('http://', adapter)
        session.mount('https://', adapter)

        # Configurar verificación SSL
        if not self.http_config.get('verify_ssl', True):
            session.verify = False
            # Suprimir advertencias SSL
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        return session

    def get_access_token(self) -> str:
        """Obtener token de acceso válido, refrescando si es necesario."""
        now = datetime.now(timezone.utc)

        # Verificar si tenemos un token válido
        if self._access_token and self._token_expires_at and now < self._token_expires_at:
            return self._access_token

        # Token expirado o faltante, obtener uno nuevo
        return self._authenticate()

    def _authenticate(self) -> str:
        """Realizar autenticación y retornar token de acceso."""
        logger.info('Autenticando con Keycloak...')

        session = self._create_session()

        # Usar formato diccionario para codificación URL correcta (especialmente importante para contraseñas con caracteres especiales)
        data = {
            'client_id': self.config['client_id'],
            'username': self.config['username'],
            'password': self.config['password'],
            'grant_type': self.config['grant_type']
        }
        
        try:
            # Registrar información detallada de la petición HTTP
            logger.info("=== DETALLES DE PETICIÓN HTTP ===")
            logger.info(f"Método: POST")
            logger.info(f"URL: {self.config['url']}")
            logger.info(f"Headers: Content-Type: application/x-www-form-urlencoded")
            logger.info(f"Datos: client_id={self.config['client_id']}&username={self.config['username']}&password=[OCULTO]&grant_type={self.config['grant_type']}")
            logger.debug(f"Longitud de contraseña: {len(self.config['password'])} caracteres")
            logger.debug("El diccionario de datos contiene información sensible - no registrado")
            logger.info("Timeout: {} segundos".format(self.http_config['timeout']))

            # Generar equivalente curl (sin contraseña por seguridad)
            curl_cmd = (
                f"curl --location --request POST \"{self.config['url']}\" "
                f"--header \"Content-Type: application/x-www-form-urlencoded\" "
                f"--data-urlencode \"client_id={self.config['client_id']}\" "
                f"--data-urlencode \"username={self.config['username']}\" "
                f"--data-urlencode \"password=[HIDDEN]\" "
                f"--data-urlencode \"grant_type={self.config['grant_type']}\" "
                f"--max-time {self.http_config['timeout']}"
            )
            if not self.http_config.get('verify_ssl', True):
                curl_cmd += " --insecure"
            logger.info(f"equivalente curl: {curl_cmd}")

            response = session.post(
                self.config['url'],
                data=data,
                timeout=self.http_config['timeout']
            )

            # Registrar detalles de respuesta
            logger.info("=== DETALLES DE RESPUESTA HTTP ===")
            logger.info(f"Código de estado: {response.status_code}")
            logger.info(f"Headers de respuesta: {dict(response.headers)}")
            if response.status_code == 200:
                logger.debug(f"Cuerpo de respuesta: {response.text}")
            else:
                logger.info(f"Cuerpo de respuesta: {response.text}")
            logger.info("=== FIN DETALLES HTTP ===")

            if response.status_code == 200:
                token_data = response.json()
                self._access_token = token_data['access_token']

                # Calcular tiempo de expiración (con buffer de 5 minutos)
                expires_in = token_data.get('expires_in', 300)  # Por defecto 5 minutos
                self._token_expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in - 300)

                logger.info('Autenticación exitosa')
                return self._access_token
            else:
                raise AuthenticationError(f'Autenticación fallida: {response.status_code} - {response.text}')

        except requests.RequestException as e:
            raise AuthenticationError(f'Petición de autenticación fallida: {str(e)}')

class DataFetchError(Exception):
    """Excepción personalizada para fallos de obtención de datos."""
    pass

class SensorDataFetcher:
    """Maneja la obtención de datos de sensores desde la API."""

    def __init__(self, auth_manager: AuthManager, config: Dict[str, Any]):
        self.auth_manager = auth_manager
        self.config = config
        self.http_config = Config.get_http_config()

    def _create_session(self) -> requests.Session:
        """Crear sesión HTTP con configuración de reintentos."""
        session = requests.Session()

        retry_strategy = Retry(
            total=self.http_config['max_retries'],
            status_forcelist=[429, 500, 502, 503, 504],
            backoff_factor=self.http_config['retry_backoff_base'],
            allowed_methods=['HEAD', 'GET', 'OPTIONS']
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount('http://', adapter)
        session.mount('https://', adapter)

        # Configurar verificación SSL
        if not self.http_config.get('verify_ssl', True):
            session.verify = False
            # Suprimir advertencias SSL
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        return session

    def _calculate_time_window(self) -> tuple[str, str]:
        """Calcular la ventana temporal para obtención de datos."""
        now = datetime.now(timezone.utc)
        from_time = now - timedelta(minutes=self.config['time_window_minutes'])

        # Formatear como ISO 8601 con offset UTC
        from_iso = from_time.strftime('%Y-%m-%dT%H:%M:%S+00:00')
        to_iso = now.strftime('%Y-%m-%dT%H:%M:%S+00:00')

        return from_iso, to_iso
    
    def fetch_data(self) -> List[Dict[str, Any]]:
        """Obtener datos de sensores desde la API."""
        logger.info('Iniciando operación de obtención de datos')

        from_date, to_date = self._calculate_time_window()
        logger.info(f'Obteniendo datos desde {from_date} hasta {to_date}')

        session = self._create_session()
        all_devices = []

        # Preparar parámetros iniciales de petición
        params = {
            'attrs': self.config['attributes'],
            'fromDate': from_date,
            'toDate': to_date,
            'lastN': self.config['last_n'],
            'limit': self.config['limit'],
            'organization': self.config['organization']
        }

        url = self.config['base_url']

        while True:
            try:
                # Obtener token fresco para cada petición
                token = self.auth_manager.get_access_token()
                headers = {
                    'Accept': 'application/json',
                    'Authorization': f'Bearer {token}'
                }

                # Registrar información detallada de petición HTTP para API de sensores
                logger.info("=== DETALLES DE PETICIÓN API SENSORES ===")
                logger.info(f"Método: GET")
                full_url = f"{url}?{requests.compat.urlencode(params)}"
                logger.info(f"URL completa: {full_url}")
                # Ocultar headers sensibles
                safe_headers = headers.copy()
                if 'Authorization' in safe_headers:
                    safe_headers['Authorization'] = 'Bearer ***'
                logger.info(f"Headers: {safe_headers}")
                logger.info("Timeout: {} segundos".format(self.http_config['timeout']))

                # Generar equivalente curl
                curl_cmd = f"curl -X GET '{full_url}'"
                for header_name, header_value in headers.items():
                    if header_name.lower() == 'authorization':
                        curl_cmd += f" -H '{header_name}: ***'"
                    else:
                        curl_cmd += f" -H '{header_name}: {header_value}'"
                curl_cmd += f" --max-time {self.http_config['timeout']}"
                if not self.http_config.get('verify_ssl', True):
                    curl_cmd += " --insecure"
                logger.info(f"equivalente curl: {curl_cmd}")

                response = session.get(
                    url,
                    headers=headers,
                    params=params,
                    timeout=self.http_config['timeout']
                )

                # Registrar detalles de respuesta
                logger.info("=== DETALLES DE RESPUESTA API SENSORES ===")
                logger.info(f"Código de estado: {response.status_code}")
                logger.info(f"Headers de respuesta: {dict(response.headers)}")
                if response.status_code == 200:
                    logger.debug(f"Longitud del cuerpo de respuesta: {len(response.text)} caracteres")
                    # Parsear y registrar información básica sobre dispositivos
                    try:
                        response_data = response.json()
                        if 'devices' in response_data:
                            logger.info(f"Encontrados {len(response_data['devices'])} dispositivos en respuesta")
                        else:
                            logger.info("No se encontró clave 'devices' en respuesta")
                    except:
                        logger.info("La respuesta no es JSON válido")
                else:
                    logger.info(f"Cuerpo de respuesta: {response.text}")
                logger.info("=== FIN DETALLES API SENSORES ===")

                # Manejar 401 refrescando token una vez
                if response.status_code == 401:
                    logger.warning('Token expirado (401), refrescando y reintentando...')
                    logger.info("=== DETALLES DE PETICIÓN REFRESCO TOKEN ===")

                    # Refrescar token
                    self.auth_manager._authenticate()  # Forzar refresco de token
                    token = self.auth_manager.get_access_token()

                    # Actualizar headers con nuevo token
                    headers['Authorization'] = f'Bearer {token}'

                    # Reintentar petición con nuevo token
                    logger.info("Reintentando petición a API de sensores con token refrescado...")
                    logger.info(f"Header Authorization actualizado: Bearer ***")

                    response = session.get(
                        url,
                        headers=headers,
                        params=params,
                        timeout=self.http_config['timeout']
                    )

                    # Registrar respuesta del reintento
                    logger.info("=== DETALLES DE RESPUESTA REINTENTO ===")
                    logger.info(f"Código de estado del reintento: {response.status_code}")
                    if response.status_code == 200:
                        logger.debug(f"Longitud del cuerpo de respuesta del reintento: {len(response.text)} caracteres")
                        try:
                            response_data = response.json()
                            if 'devices' in response_data:
                                logger.info(f"Reintento encontró {len(response_data['devices'])} dispositivos en respuesta")
                        except:
                            logger.info("Respuesta del reintento no es JSON válido")
                    else:
                        logger.info(f"Cuerpo de respuesta del reintento: {response.text}")
                    logger.info("=== FIN DETALLES REINTENTO ===")

                if response.status_code == 200:
                    data = response.json()
                    devices = data.get('devices', [])

                    if not devices:
                        logger.info('No se encontraron dispositivos en respuesta')
                        break

                    all_devices.extend(devices)
                    logger.debug(f'Recuperados {len(devices)} dispositivos (total: {len(all_devices)})')

                    # Verificar paginación (asumiendo que API usa paginación estándar)
                    # Esto necesitaría ajustarse basado en formato de respuesta real de API
                    if len(devices) < self.config['limit']:
                        break

                    # Si API soporta paginación, actualizar params para siguiente página
                    # Esto es un placeholder - ajustar basado en API real
                    if 'next' in data:
                        url = data['next']
                        params = {}  # Limpiar params para siguiente página
                    else:
                        break

                else:
                    raise DataFetchError(f'Petición API fallida: {response.status_code} - {response.text}')

            except requests.RequestException as e:
                raise DataFetchError(f'Petición de obtención de datos fallida: {str(e)}')

        logger.info(f'Se obtuvieron exitosamente {len(all_devices)} dispositivos totales')
        return all_devices

class DataProcessor:
    """Procesa y normaliza datos de sensores."""

    # Atributos esperados desde la API
    EXPECTED_ATTRIBUTES = [
        'airTemperature', 'atmosphericPressure', 'batteryVoltage',
        'lightningAverageDistance', 'lightningStrikeCount', 'maximumWindSpeed',
        'precipitation', 'relativeHumidity', 'solarRadiation',
        'vaporPressure', 'windDirection', 'windSpeed'
    ]

    @staticmethod
    def parse_datetime(iso_string: str) -> str:
        """Parsea datetime ISO 8601 y convierte a formato SQL Server DATETIME2."""
        try:
            dt = date_parser.parse(iso_string)
            # Asegurar zona horaria UTC
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                dt = dt.astimezone(timezone.utc)

            # Formatear para SQL Server DATETIME2 (YYYY-MM-DD HH:MM:SS.ffffff)
            return dt.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]  # Remover últimos 3 dígitos para milisegundos
        except Exception as e:
            logger.error(f'Error al parsear datetime {iso_string}: {str(e)}')
            raise ValueError(f'Formato de datetime inválido: {iso_string}')

    @staticmethod
    def safe_float_convert(value: Any) -> Optional[float]:
        """Convierte valor a float de forma segura, manejando strings y valores None."""
        if value is None:
            return None

        try:
            if isinstance(value, str):
                # Manejar strings vacías
                if value.strip() == '':
                    return None
                return float(value)
            return float(value)
        except (ValueError, TypeError):
            logger.warning(f'No se pudo convertir {value} a float, estableciendo NULL')
            return None

    @classmethod
    def normalize_record(cls, device: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Normaliza un registro de dispositivo individual."""
        try:
            entity_id = device.get('entityId')
            index_raw = device.get('index')

            if not entity_id or not index_raw:
                logger.warning(f'Saltando registro de dispositivo con entityId o index faltante: {device}')
                return None

            # Parsear datetime
            index = cls.parse_datetime(index_raw)

            # Extraer y normalizar atributos
            attributes = device.get('attributes', {})
            normalized = {
                'entityId': str(entity_id),
                'index': index
            }

            for attr in cls.EXPECTED_ATTRIBUTES:
                raw_value = attributes.get(attr)
                normalized[attr] = cls.safe_float_convert(raw_value)

            return normalized

        except Exception as e:
            logger.error(f'Error al normalizar registro {device}: {str(e)}')
            return None

    @classmethod
    def process_devices(cls, devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Procesa todos los registros de dispositivos y retorna datos normalizados."""
        logger.info(f'Procesando {len(devices)} registros de dispositivos')

        normalized_records = []
        for device in devices:
            normalized = cls.normalize_record(device)
            if normalized:
                normalized_records.append(normalized)

        logger.info(f'Se normalizaron exitosamente {len(normalized_records)} registros')
        return normalized_records

class DatabaseError(Exception):
    """Excepción personalizada para operaciones de base de datos."""
    pass

class DatabaseManager:
    """Maneja operaciones de SQL Server usando pyodbc."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.connection_string = (
            f'DRIVER={{ODBC Driver 17 for SQL Server}};'
            f'SERVER={config["server"]};'
            f'DATABASE={config["database"]};'
            f'UID={config["username"]};'
            f'PWD={config["password"]};'
            f'CONNECTION TIMEOUT={config["connection_timeout"]};'
        )
        self._connection: Optional[pyodbc.Connection] = None

    def _get_connection(self) -> pyodbc.Connection:
        """Obtiene conexión a base de datos, creándola si es necesario."""
        if self._connection is None:
            try:
                self._connection = pyodbc.connect(self.connection_string)
                self._connection.autocommit = False  # Administraremos las transacciones
                logger.info('Conexión a base de datos establecida')
            except pyodbc.Error as e:
                raise DatabaseError(f'Error al conectar a base de datos: {str(e)}')

        return self._connection

    def _close_connection(self) -> None:
        """Cierra conexión a base de datos."""
        if self._connection:
            try:
                self._connection.close()
                self._connection = None
                logger.info('Conexión a base de datos cerrada')
            except pyodbc.Error as e:
                logger.warning(f'Error al cerrar conexión a base de datos: {str(e)}')

    def upsert_records(self, records: List[Dict[str, Any]]) -> tuple[int, int]:
        """Inserta/actualiza registros usando tabla temporal y declaración MERGE."""
        if not records:
            logger.info('No hay registros para insertar/actualizar')
            return 0, 0

        connection = self._get_connection()
        cursor = connection.cursor()

        try:
            # Iniciar transacción
            connection.autocommit = False

            logger.info(f'Iniciando upsert de {len(records)} registros')

            # Crear tabla temporal
            temp_table_name = '#staging'
            create_temp_sql = f'''
                CREATE TABLE {temp_table_name} (
                    entityId NVARCHAR(200) NOT NULL,
                    [index] DATETIME2 NOT NULL,
                    airTemperature FLOAT NULL,
                    atmosphericPressure FLOAT NULL,
                    batteryVoltage FLOAT NULL,
                    lightningAverageDistance FLOAT NULL,
                    lightningStrikeCount FLOAT NULL,
                    maximumWindSpeed FLOAT NULL,
                    precipitation FLOAT NULL,
                    relativeHumidity FLOAT NULL,
                    solarRadiation FLOAT NULL,
                    vaporPressure FLOAT NULL,
                    windDirection FLOAT NULL,
                    windSpeed FLOAT NULL
                );
            '''

            cursor.execute(create_temp_sql)
            logger.debug('Tabla temporal creada')

            # Insertar registros en masa en tabla temporal
            insert_sql = f'''
                INSERT INTO {temp_table_name} (
                    entityId, [index], airTemperature, atmosphericPressure, batteryVoltage,
                    lightningAverageDistance, lightningStrikeCount, maximumWindSpeed,
                    precipitation, relativeHumidity, solarRadiation, vaporPressure,
                    windDirection, windSpeed
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            '''

            # Preparar datos para inserción en masa
            data_to_insert = []
            for record in records:
                row = (
                    record['entityId'],
                    record['index'],
                    record['airTemperature'],
                    record['atmosphericPressure'],
                    record['batteryVoltage'],
                    record['lightningAverageDistance'],
                    record['lightningStrikeCount'],
                    record['maximumWindSpeed'],
                    record['precipitation'],
                    record['relativeHumidity'],
                    record['solarRadiation'],
                    record['vaporPressure'],
                    record['windDirection'],
                    record['windSpeed']
                )
                data_to_insert.append(row)
            
            # Ejecutar inserción en masa
            cursor.executemany(insert_sql, data_to_insert)
            logger.debug(f'Se insertaron en masa {len(data_to_insert)} registros en tabla temporal')

            # Ejecutar operación MERGE
            merge_sql = f'''
                MERGE dbo.TemporalDatosBrutos_iCousas AS target
                USING {temp_table_name} AS src
                   ON target.entityId = src.entityId AND target.[index] = src.[index]
                WHEN MATCHED THEN
                   UPDATE SET
                     airTemperature = src.airTemperature,
                     atmosphericPressure = src.atmosphericPressure,
                     batteryVoltage = src.batteryVoltage,
                     lightningAverageDistance = src.lightningAverageDistance,
                     lightningStrikeCount = src.lightningStrikeCount,
                     maximumWindSpeed = src.maximumWindSpeed,
                     precipitation = src.precipitation,
                     relativeHumidity = src.relativeHumidity,
                     solarRadiation = src.solarRadiation,
                     vaporPressure = src.vaporPressure,
                     windDirection = src.windDirection,
                     windSpeed = src.windSpeed
                WHEN NOT MATCHED BY TARGET THEN
                   INSERT (
                     entityId, [index],
                     airTemperature, atmosphericPressure, batteryVoltage,
                     lightningAverageDistance, lightningStrikeCount, maximumWindSpeed,
                     precipitation, relativeHumidity, solarRadiation,
                     vaporPressure, windDirection, windSpeed
                   )
                   VALUES (
                     src.entityId, src.[index],
                     src.airTemperature, src.atmosphericPressure, src.batteryVoltage,
                     src.lightningAverageDistance, src.lightningStrikeCount, src.maximumWindSpeed,
                     src.precipitation, src.relativeHumidity, src.solarRadiation,
                     src.vaporPressure, src.windDirection, src.windSpeed
                   );
            '''
            
            cursor.execute(merge_sql)

            # Obtener conteo de filas afectadas
            cursor.execute('SELECT @@ROWCOUNT')
            affected_rows = cursor.fetchone()[0]

            # Limpiar tabla temporal
            cursor.execute(f'DROP TABLE {temp_table_name}')

            # Confirmar transacción
            connection.commit()

            # Calcular actualizados vs insertados (aproximado)
            # Esta es una simplificación - en un escenario real podría necesitar rastrearse diferente
            updated_count = max(0, affected_rows - len(records))
            inserted_count = len(records) - updated_count

            logger.info(f'Upsert completado: {inserted_count} insertados, {updated_count} actualizados')
            return inserted_count, updated_count

        except pyodbc.Error as e:
            # Rollback en caso de error
            try:
                connection.rollback()
            except:
                pass
            raise DatabaseError(f'Operación de base de datos fallida: {str(e)}')
        
        finally:
            try:
                cursor.close()
            except:
                pass
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self._close_connection()

def main() -> int:
    """Función principal para ejecutar el proceso de recopilación y almacenamiento de datos."""
    start_time = datetime.now(timezone.utc)
    logger.info('Iniciando trabajo de recopilación de datos de sensores iCousas')
    logger.info(f'Los archivos de log se guardarán en: {os.path.join(os.getcwd(), "logs")}')

    try:
        # Validar variables de entorno
        Config.validate()
        logger.info('Configuración de entorno validada')

        # Inicializar componentes
        keycloak_config = Config.get_keycloak_config()
        sensors_config = Config.get_sensors_config()
        db_config = Config.get_db_config()

        auth_manager = AuthManager(keycloak_config)
        data_fetcher = SensorDataFetcher(auth_manager, sensors_config)

        # Obtener datos
        logger.info('Iniciando obtención de datos...')
        devices = data_fetcher.fetch_data()

        if not devices:
            logger.info('No se recibieron datos de dispositivos, saliendo correctamente')
            return 0

        # Procesar datos
        logger.info('Procesando datos obtenidos...')
        normalized_records = DataProcessor.process_devices(devices)

        if not normalized_records:
            logger.warning('No se pudieron normalizar registros, saliendo')
            return 1

        # Almacenar datos
        logger.info('Almacenando datos en base de datos...')
        with DatabaseManager(db_config) as db_manager:
            inserted, updated = db_manager.upsert_records(normalized_records)

        end_time = datetime.now(timezone.utc)
        duration = end_time - start_time

        logger.info(
            f'Trabajo completado exitosamente en {duration.total_seconds():.2f} segundos. '
            f'Procesados {len(normalized_records)} registros: {inserted} insertados, {updated} actualizados'
        )

        return 0
    
    except AuthenticationError as e:
        logger.error(f'Autenticación fallida: {str(e)}')
        return 1
    except DataFetchError as e:
        logger.error(f'Obtención de datos fallida: {str(e)}')
        return 1
    except DatabaseError as e:
        logger.error(f'Operación de base de datos fallida: {str(e)}')
        return 1
    except ValueError as e:
        logger.error(f'Error de configuración: {str(e)}')
        return 1
    except Exception as e:
        logger.error(f'Error inesperado: {str(e)}')
        return 1

if __name__ == '__main__':
    """Punto de entrada para el script."""
    exit_code = main()
    sys.exit(exit_code)