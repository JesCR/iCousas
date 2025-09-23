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

# Funciones utilitarias
def show_progress(current: int, total: int, bar_width: int = 40, description: str = "Procesando") -> None:
    """Muestra una barra de progreso simple usando caracteres."""
    if total == 0:
        return

    percentage = int((current / total) * 100)
    filled_width = int((current / total) * bar_width)
    bar = '█' * filled_width + '░' * (bar_width - filled_width)

    # Solo mostrar en consola, no en archivo de log
    print(f'\r{description}: [{bar}] {percentage}% ({current}/{total})', end='', flush=True)

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

    @classmethod
    def get_proxy_config(cls) -> Optional[Dict[str, Any]]:
        """Obtener configuración de proxy desde variables de entorno."""
        http_proxy = os.getenv('HTTP_PROXY')
        https_proxy = os.getenv('HTTPS_PROXY')
        no_proxy = os.getenv('NO_PROXY')

        # Solo configurar proxy si las variables principales tienen valores
        if http_proxy or https_proxy:
            proxy_config = {}

            # Configurar proxies HTTP y HTTPS
            if http_proxy:
                proxy_config['http'] = http_proxy
            if https_proxy:
                proxy_config['https'] = https_proxy

            # Configurar excepciones (no_proxy)
            if no_proxy:
                proxy_config['no_proxy'] = no_proxy

            return proxy_config

        return None

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

        # Configurar proxy si está disponible
        proxy_config = Config.get_proxy_config()
        if proxy_config:
            session.proxies.update(proxy_config)
            logger.debug(f'Configuración de proxy aplicada para autenticación: {proxy_config}')

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
            logger.debug("=== DETALLES DE PETICIÓN HTTP ===")
            logger.debug(f"Método: POST")
            logger.debug(f"URL: {self.config['url']}")
            logger.debug(f"Headers: Content-Type: application/x-www-form-urlencoded")
            logger.debug(f"Datos: client_id={self.config['client_id']}&username={self.config['username']}&password=[OCULTO]&grant_type={self.config['grant_type']}")
            logger.debug(f"Longitud de contraseña: {len(self.config['password'])} caracteres")
            logger.debug("El diccionario de datos contiene información sensible - no registrado")
            logger.debug("Timeout: {} segundos".format(self.http_config['timeout']))

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
            logger.debug(f"equivalente curl: {curl_cmd}")

            response = session.post(
                self.config['url'],
                data=data,
                timeout=self.http_config['timeout']
            )

            # Registrar detalles de respuesta
            logger.debug("=== DETALLES DE RESPUESTA HTTP ===")
            logger.debug(f"Código de estado: {response.status_code}")
            logger.debug(f"Headers de respuesta: {dict(response.headers)}")
            if response.status_code == 200:
                logger.debug(f"Cuerpo de respuesta: {response.text}")
            else:
                logger.debug(f"Cuerpo de respuesta: {response.text}")
            logger.debug("=== FIN DETALLES HTTP ===")

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

        # Configurar proxy si está disponible
        proxy_config = Config.get_proxy_config()
        if proxy_config:
            session.proxies.update(proxy_config)
            logger.debug(f'Configuración de proxy aplicada para obtención de datos: {proxy_config}')

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
        logger.debug('Iniciando operación de obtención de datos')

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
                logger.debug("=== DETALLES DE PETICIÓN API SENSORES ===")
                logger.debug(f"Método: GET")
                full_url = f"{url}?{requests.compat.urlencode(params)}"
                logger.debug(f"URL completa: {full_url}")
                # Ocultar headers sensibles
                safe_headers = headers.copy()
                if 'Authorization' in safe_headers:
                    safe_headers['Authorization'] = 'Bearer ***'
                logger.debug(f"Headers: {safe_headers}")
                logger.debug("Timeout: {} segundos".format(self.http_config['timeout']))

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
                logger.debug(f"equivalente curl: {curl_cmd}")

                response = session.get(
                    url,
                    headers=headers,
                    params=params,
                    timeout=self.http_config['timeout']
                )

                # Registrar detalles de respuesta
                logger.debug("=== DETALLES DE RESPUESTA API SENSORES ===")
                logger.debug(f"Código de estado: {response.status_code}")
                logger.debug(f"Headers de respuesta: {dict(response.headers)}")
                if response.status_code == 200:
                    logger.debug(f"Longitud del cuerpo de respuesta: {len(response.text)} caracteres")
                    # Parsear y registrar información básica sobre dispositivos
                    try:
                        response_data = response.json()
                        if 'devices' in response_data:
                            logger.debug(f"Api devuelve {len(response_data['devices'])} registros")
                        else:
                            logger.debug("No se encontró clave 'devices' en respuesta")
                    except:
                        logger.debug("La respuesta no es JSON válido")
                else:
                    logger.debug(f"Cuerpo de respuesta: {response.text}")
                logger.debug("=== FIN DETALLES API SENSORES ===")

                # Manejar 401 refrescando token una vez
                if response.status_code == 401:
                    logger.warning('Token expirado (401), refrescando y reintentando...')
                    logger.debug("=== DETALLES DE PETICIÓN REFRESCO TOKEN ===")

                    # Refrescar token
                    self.auth_manager._authenticate()  # Forzar refresco de token
                    token = self.auth_manager.get_access_token()

                    # Actualizar headers con nuevo token
                    headers['Authorization'] = f'Bearer {token}'

                    # Reintentar petición con nuevo token
                    logger.debug("Reintentando petición a API de sensores con token refrescado...")
                    logger.debug(f"Header Authorization actualizado: Bearer ***")

                    response = session.get(
                        url,
                        headers=headers,
                        params=params,
                        timeout=self.http_config['timeout']
                    )

                    # Registrar respuesta del reintento
                    logger.debug("=== DETALLES DE RESPUESTA REINTENTO ===")
                    logger.debug(f"Código de estado del reintento: {response.status_code}")
                    if response.status_code == 200:
                        logger.debug(f"Longitud del cuerpo de respuesta del reintento: {len(response.text)} caracteres")
                        try:
                            response_data = response.json()
                            if 'devices' in response_data:
                                logger.debug(f"Reintento encontró {len(response_data['devices'])} registros en la llamada a la api")
                        except:
                            logger.debug("Respuesta del reintento no es JSON válido")
                    else:
                        logger.debug(f"Cuerpo de respuesta del reintento: {response.text}")
                    logger.debug("=== FIN DETALLES REINTENTO ===")

                if response.status_code == 200:
                    data = response.json()
                    devices = data.get('devices', [])

                    if not devices:
                        logger.info('No se encontraron registros en la llamada a la api')
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

        logger.info(f'Se obtuvieron {len(all_devices)} registros')
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
    def _parse_iso_to_utc(iso_string: str) -> datetime:
        """Devuelve un datetime consciente en UTC a partir de un ISO 8601."""
        s = iso_string.replace('Z', '+00:00')  # Soporta sufijo Z
        try:
            dt = datetime.fromisoformat(s)
        except ValueError:
            dt = date_parser.parse(iso_string)

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt

    @staticmethod
    def _round_to_allowed_10min(dt: datetime) -> datetime:
        """
        Redondea al múltiplo de 10 minutos más cercano (0,10,20,30,40,50).
        Estrategia: +5 minutos y luego 'floor' a décimas → evita minute=60 y hour=24.
        """
        dt = dt + timedelta(minutes=5)  # redondeo al más cercano por minutos
        floored_minute = (dt.minute // 10) * 10
        return dt.replace(minute=floored_minute, second=0, microsecond=0)

    @staticmethod
    def parse_datetime(iso_string: str) -> str:
        """ISO 8601 → SMALLDATETIME (UTC), redondeo a 0/10/20/30/40/50."""
        try:
            dt = DataProcessor._parse_iso_to_utc(iso_string)
            dt = DataProcessor._round_to_allowed_10min(dt)
            return dt.strftime('%Y-%m-%d %H:%M:%S')
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
        total_devices = len(devices)
        logger.info(f'Procesando {total_devices} registros')

        normalized_records = []
        for i, device in enumerate(devices, 1):
            normalized = cls.normalize_record(device)
            if normalized:
                normalized_records.append(normalized)

            # Mostrar progreso cada 10 registros o al final
            if i % 10 == 0 or i == total_devices:
                show_progress(i, total_devices, description="Procesando dispositivos")

        # Nueva línea después de la barra de progreso
        print()

        logger.info(f'Se normalizaron exitosamente {len(normalized_records)} registros')
        return normalized_records

class DatabaseError(Exception):
    """Excepción personalizada para operaciones de base de datos."""
    pass

class IngestionError(Exception):
    """Excepción personalizada para operaciones de ingestión."""
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
        """Inserta/actualiza registros usando tabla temporal y declaración MERGE, filtrando por fecha de último dato."""
        if not records:
            logger.info('No hay registros para insertar/actualizar')
            return 0, 0

        connection = self._get_connection()
        cursor = connection.cursor()

        try:
            # Iniciar transacción
            connection.autocommit = False

            logger.debug(f'Iniciando upsert de {len(records)} registros')

            # Ordenar registros por fecha ascendente para procesamiento correcto
            records_sorted = sorted(records, key=lambda x: x['index'])
            logger.debug(f'Registros ordenados por fecha: {len(records_sorted)} registros')

            # Filtrar registros basándose en fecha de último dato
            filtered_records = []
            for record in records_sorted:
                entity_id = record['entityId']
                record_date = record['index']

                # Buscar lnEstacion para este entityId
                estacion_cursor = connection.cursor()
                try:
                    estacion_sql = 'SELECT lnEstacion FROM dbo.AuxEstacionesCodigos WHERE codigo = ?'
                    estacion_cursor.execute(estacion_sql, entity_id)
                    estacion_row = estacion_cursor.fetchone()

                    if estacion_row:
                        ln_estacion = estacion_row[0]

                        # Verificar fecha de último dato con lnTipoFechaUltimoDato = 2
                        fecha_cursor = connection.cursor()
                        try:
                            #No queremos fechas anteriores ala ultima fecha procesada por el mcheck
                            fecha_sql = '''
                                SELECT Fecha FROM dbo.CruceEstacionesListaEstacionesFechasUltimosDatos
                                WHERE lnEstacion = ? AND lnTipoFechaUltimoDato = 2
                            '''
                            fecha_cursor.execute(fecha_sql, ln_estacion)
                            fecha_row = fecha_cursor.fetchone()

                            if fecha_row:
                                ultima_fecha = fecha_row[0]

                                # Convertir fechas para comparación
                                if hasattr(record_date, 'strftime'):
                                    record_dt = record_date
                                else:
                                    record_dt = datetime.strptime(str(record_date), '%Y-%m-%d %H:%M:%S')

                                if hasattr(ultima_fecha, 'strftime'):
                                    ultima_dt = ultima_fecha
                                else:
                                    ultima_dt = datetime.strptime(str(ultima_fecha), '%Y-%m-%d %H:%M:%S')

                                # Si la fecha del registro es anterior o igual a la última fecha procesada, saltarlo
                                if record_dt <= ultima_dt:
                                    logger.debug(f'Registro ya procesado anteriormente: entityId={entity_id}, fecha={record_date}, última_fecha_procesada={ultima_fecha}')
                                    continue

                        finally:
                            fecha_cursor.close()

                finally:
                    estacion_cursor.close()

                # Si llega aquí, el registro debe procesarse
                filtered_records.append(record)

            logger.debug(f'Registros después del filtro: {len(filtered_records)} de {len(records_sorted)}')

            if not filtered_records:
                logger.info('Todos los registros fueron filtrados (ya procesados anteriormente)')
                return 0, 0

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

            # Insertar registros filtrados en masa en tabla temporal
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
            for record in filtered_records:
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

            updated_count = max(0, affected_rows - len(filtered_records))
            inserted_count = len(filtered_records) - updated_count

            logger.debug(f'Upsert completado: {inserted_count} insertados, {updated_count} actualizados')
            logger.info(f'Procesados {len(filtered_records)} registros nuevos (filtrados {len(records_sorted) - len(filtered_records)} ya procesados)')
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

class DataIngestionManager:
    """Maneja el proceso de ingestión de datos desde TemporalDatosBrutos_iCousas hacia TemporalDatosBrutos."""

    def __init__(self, db_config: Dict[str, Any]):
        self.db_config = db_config
        self.logger = self._setup_ingestion_logger()
        self.db_manager = DatabaseManager(db_config)

    def _setup_ingestion_logger(self) -> logging.Logger:
        """Configura logging específico para ingestión con sufijo '_ingest'."""
        # Crear directorio de logs si no existe
        logs_dir = os.path.join(os.getcwd(), 'logs')
        os.makedirs(logs_dir, exist_ok=True)

        # Generar nombre de archivo de log con formato YYYY-MM-DD_ingest.txt
        now = datetime.now()
        log_filename = now.strftime('%Y-%m-%d') + '_ingest.txt'
        log_filepath = os.path.join(logs_dir, log_filename)

        # Crear logger específico para ingestión
        ingestion_logger = logging.getLogger('ingestion')
        ingestion_logger.setLevel(getattr(logging, os.getenv('LOG_LEVEL', 'INFO').upper()))

        # Evitar duplicación de handlers si ya existe
        if ingestion_logger.handlers:
            return ingestion_logger

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
        ingestion_logger.addHandler(file_handler)
        ingestion_logger.addHandler(console_handler)

        return ingestion_logger

    def read_records_from_icousas(self) -> List[Dict[str, Any]]:
        """Lee todos los registros de TemporalDatosBrutos_iCousas."""
        self.logger.info('Leyendo registros de TemporalDatosBrutos_iCousas...')

        connection = self.db_manager._get_connection()
        cursor = connection.cursor()

        try:
            select_sql = '''
                SELECT entityId, [index], airTemperature, atmosphericPressure, batteryVoltage,
                       lightningAverageDistance, lightningStrikeCount, maximumWindSpeed,
                       precipitation, relativeHumidity, solarRadiation, vaporPressure,
                       windDirection, windSpeed
                FROM dbo.TemporalDatosBrutos_iCousas
                ORDER BY entityId, [index]
            '''
            #print(f"DEBUG SQL - SELECT: {select_sql}")

            cursor.execute(select_sql)
            columns = [column[0] for column in cursor.description]
            records = []

            for row in cursor.fetchall():
                record = dict(zip(columns, row))
                records.append(record)

            self.logger.info(f'Se leyeron {len(records)} registros de TemporalDatosBrutos_iCousas')
            return records

        except pyodbc.Error as e:
            raise IngestionError(f'Error al leer registros de TemporalDatosBrutos_iCousas: {str(e)}')
        finally:
            cursor.close()

    def lookup_ln_estacion(self, entity_id: str) -> Optional[int]:
        """Busca el lnEstacion correspondiente al entityId en AuxEstacionesCodigos."""
        connection = self.db_manager._get_connection()
        cursor = connection.cursor()

        try:
            select_sql = '''
                SELECT lnEstacion
                FROM dbo.AuxEstacionesCodigos
                WHERE codigo = ?
            '''

            cursor.execute(select_sql, entity_id)
            row = cursor.fetchone()

            if row:
                return row[0]
            else:
                self.logger.warning(f'No se encontró lnEstacion para entityId: {entity_id}')
                self.logger.info(f'Query ejecutada: SELECT lnEstacion FROM dbo.AuxEstacionesCodigos WHERE codigo = \'{entity_id}\'')
                return None

        except pyodbc.Error as e:
            raise IngestionError(f'Error al buscar lnEstacion para entityId {entity_id}: {str(e)}')
        finally:
            cursor.close()

    def get_channels_for_station(self, ln_estacion: int) -> List[Dict[str, Any]]:
        """Obtiene la lista de canales y medidas para una estación específica."""
        connection = self.db_manager._get_connection()
        cursor = connection.cursor()

        try:
            select_sql = '''
                SELECT medida, idmedida, canal
                FROM dbo.VIDX_AMC_ConNulls
                WHERE idEstacion = ? AND Derivada = 0 AND idTipoIntervalo = 1 AND activa = 1
                ORDER BY canal
            '''

            cursor.execute(select_sql, ln_estacion)
            columns = [column[0] for column in cursor.description]
            channels = []

            for row in cursor.fetchall():
                channel = dict(zip(columns, row))
                channels.append(channel)

            self.logger.debug(f'Se encontraron {len(channels)} canales para la estación {ln_estacion}')
            return channels

        except pyodbc.Error as e:
            raise IngestionError(f'Error al obtener canales para estación {ln_estacion}: {str(e)}')
        finally:
            cursor.close()

    def _parse_iso_to_utc(self, iso_string: str) -> datetime:
        """Devuelve un datetime consciente en UTC a partir de un ISO 8601."""
        s = iso_string.replace('Z', '+00:00')  # Soporta sufijo Z
        try:
            dt = datetime.fromisoformat(s)
        except ValueError:
            dt = date_parser.parse(iso_string)

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt

    def _round_to_allowed_10min(self, dt: datetime) -> datetime:
        """
        Redondea al múltiplo de 10 minutos más cercano (0,10,20,30,40,50).
        Estrategia: +5 minutos y luego 'floor' a décimas → evita minute=60 y hour=24.
        """
        dt = dt + timedelta(minutes=5)  # redondeo al más cercano por minutos
        floored_minute = (dt.minute // 10) * 10
        return dt.replace(minute=floored_minute, second=0, microsecond=0)

    def _normalize_datetime_for_sql(self, fecha_hora: str) -> str:
        """Normaliza y redondea a múltiplos de 10 min para SMALLDATETIME (UTC)."""
        try:
            dt = self._parse_iso_to_utc(fecha_hora)
            dt = self._round_to_allowed_10min(dt)
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            # Si ya viniera formateada correctamente, la devolvemos tal cual
            return fecha_hora

    def insert_into_temporal_datos_brutos(self, ln_estacion: int, fecha_hora: str,
                                        canal: int, valor: Optional[float]) -> str:
        """
        Inserta o actualiza un registro en TemporalDatosBrutos usando consultas separadas.
        Primero verifica existencia, luego decide INSERT o UPDATE.
        """
        # Normalizar la fecha para asegurar compatibilidad con SMALLDATETIME
        fecha_hora_original = fecha_hora
        fecha_hora = self._normalize_datetime_for_sql(fecha_hora)
        if fecha_hora != fecha_hora_original:
            print(f"DEBUG - Fecha redondeada: '{fecha_hora}' (original: {fecha_hora_original})")

        connection = self.db_manager._get_connection()
        cursor = connection.cursor()

        try:
            # PASO 1: Verificar si el registro ya existe
            check_sql = f'''
                SELECT Valor FROM dbo.TemporalDatosBrutos
                WHERE lnEstacion = {ln_estacion} AND FechaHora = CONVERT(smalldatetime, '{fecha_hora}', 120) AND Canal = {canal}
            '''
            #self.logger.debug(f"DEBUG SQL - CHECK: {check_sql}")

            cursor.execute(check_sql)
            existing_row = cursor.fetchone()

            if existing_row is not None:
                # El registro existe
                existing_value = existing_row[0]

                # Redondear ambos valores a 5 decimales para evitar problemas de precisión
                existing_value_rounded = round(existing_value, 4) if existing_value is not None else None
                valor_rounded = round(valor, 4) if valor is not None else None

                if existing_value_rounded == valor_rounded:
                    # Valor igual - no hacer nada
                    self.logger.debug(f'Registro ya existe con mismo valor: estación={ln_estacion}, canal={canal}, fecha={fecha_hora}, valor={valor}')
                    return 'unchanged'
                else:
                    # Valor diferente - actualizar
                    self.logger.debug(f'Valor_bd: {existing_value} (redondeado: {existing_value_rounded}), valor_nuevo: {valor} (redondeado: {valor_rounded})')
                    update_sql = f'''
                        UPDATE dbo.TemporalDatosBrutos
                        SET Valor = {valor}, FechaEntrada = GETDATE()
                        WHERE lnEstacion = {ln_estacion} AND FechaHora = CONVERT(smalldatetime, '{fecha_hora}', 120) AND Canal = {canal}
                    '''
                    #self.logger.debug(f"DEBUG SQL - UPDATE: {update_sql}")
                    cursor.execute(update_sql)
                    connection.commit()
                    self.logger.debug(f'Registro actualizado: estación={ln_estacion}, canal={canal}, fecha={fecha_hora}, valor_antiguo={existing_value_rounded}, valor_nuevo={valor_rounded}')
                    return 'updated'
            else:
                # El registro no existe - insertar
                if valor is None:
                    valor_str = 'NULL'
                else:
                    valor_str = str(valor)

                insert_sql = f'''
                    INSERT INTO dbo.TemporalDatosBrutos (lnEstacion, FechaHora, Canal, Valor, FechaEntrada)
                    VALUES ({ln_estacion}, CONVERT(smalldatetime, '{fecha_hora}', 120), {canal}, {valor_str}, GETDATE())
                '''
                #self.logger.debug(f"DEBUG SQL - INSERT: {insert_sql}")
                cursor.execute(insert_sql)
                connection.commit()
                self.logger.debug(f'Registro insertado: estación={ln_estacion}, canal={canal}, fecha={fecha_hora}, valor={valor}')
                return 'inserted'

        except pyodbc.Error as e:
            connection.rollback()
            # Log detallado del error para debugging
            self.logger.error(f'Error SQL detallado - lnEstacion: {ln_estacion}, fecha_hora: {fecha_hora}, canal: {canal}, valor: {valor}')
            raise IngestionError(f'Error al procesar registro en TemporalDatosBrutos: {str(e)}')
        finally:
            cursor.close()

    def update_fecha_ultimo_dato(self, ln_estacion: int, fecha_hora: str) -> None:
        """Actualiza la tabla CruceEstacionesListaEstacionesFechasUltimosDatos con restricciones.
        Requiere que la estación ya esté registrada en la tabla de metadatos."""
        from datetime import datetime

        connection = self.db_manager._get_connection()
        cursor = connection.cursor()

        try:
            # Asegurar que fecha_hora sea un string en formato correcto
            if hasattr(fecha_hora, 'strftime'):
                # Es un objeto datetime, convertir a string
                fecha_hora_str = fecha_hora.strftime('%Y-%m-%d %H:%M:%S')
                nueva_fecha = fecha_hora
            elif isinstance(fecha_hora, str):
                fecha_hora_str = fecha_hora
                nueva_fecha = datetime.strptime(fecha_hora, '%Y-%m-%d %H:%M:%S')
            else:
                # Otro tipo, convertir
                fecha_hora_str = str(fecha_hora)
                nueva_fecha = datetime.strptime(fecha_hora_str, '%Y-%m-%d %H:%M:%S')

            fecha_actual = datetime.now()

            # La nueva fecha no puede ser posterior al instante actual
            if nueva_fecha > fecha_actual:
                self.logger.debug(f'Fecha futura ignorada para actualización: estación={ln_estacion}, fecha={fecha_hora}')
                return

            # Verificar si existe registro actual
            check_sql = '''
                SELECT Fecha FROM dbo.CruceEstacionesListaEstacionesFechasUltimosDatos
                WHERE lnEstacion = ? AND lnTipoFechaUltimoDato = 1
            '''

            cursor.execute(check_sql, ln_estacion)
            existing_row = cursor.fetchone()

            if existing_row is not None:
                # Existe registro, verificar si la nueva fecha es más reciente
                fecha_actual_registro = existing_row[0]

                # Convertir a datetime si es necesario (puede venir como datetime, string, etc.)
                if hasattr(fecha_actual_registro, 'strftime'):
                    # Es un objeto datetime
                    fecha_actual_dt = fecha_actual_registro
                elif isinstance(fecha_actual_registro, str):
                    # Es un string, convertir
                    fecha_actual_dt = datetime.strptime(fecha_actual_registro, '%Y-%m-%d %H:%M:%S')
                else:
                    # Otro tipo, convertir a string primero
                    fecha_actual_dt = datetime.strptime(str(fecha_actual_registro), '%Y-%m-%d %H:%M:%S')

                if nueva_fecha > fecha_actual_dt:
                    # Actualizar con la nueva fecha
                    update_sql = f'''
                        UPDATE dbo.CruceEstacionesListaEstacionesFechasUltimosDatos
                        SET Fecha = CONVERT(smalldatetime, '{fecha_hora_str}', 120)
                        WHERE lnEstacion = {ln_estacion} AND lnTipoFechaUltimoDato = 1
                    '''
                    cursor.execute(update_sql)
                    connection.commit()
                    self.logger.debug(f'Fecha último dato actualizada: estación={ln_estacion}, fecha_antigua={fecha_actual_dt}, fecha_nueva={nueva_fecha}')
                else:
                    self.logger.debug(f'Fecha no actualizada (no es más reciente): estación={ln_estacion}, fecha_actual={fecha_actual_dt}, fecha_nueva={nueva_fecha}')
            else:
                # ERROR: No existe registro de metadatos para esta estación
                error_msg = f'Estación {ln_estacion} no encontrada en tabla CruceEstacionesListaEstacionesFechasUltimosDatos. ' \
                           f'La estación debe estar registrada antes de procesar datos.'
                self.logger.error(error_msg)
                raise IngestionError(error_msg)

        except pyodbc.Error as e:
            connection.rollback()
            raise IngestionError(f'Error al actualizar fecha último dato para estación {ln_estacion}: {str(e)}')
        except ValueError as e:
            # Error al parsear fecha
            self.logger.error(f'Error al parsear fecha {fecha_hora} para estación {ln_estacion}: {str(e)}')
        finally:
            cursor.close()

    def delete_from_icousas(self, entity_id: str, fecha_hora: str) -> None:
        """Elimina un registro específico de TemporalDatosBrutos_iCousas."""
        connection = self.db_manager._get_connection()
        cursor = connection.cursor()

        try:
            delete_sql = '''
                DELETE FROM dbo.TemporalDatosBrutos_iCousas
                WHERE entityId = ? AND [index] = ?
            '''

            cursor.execute(delete_sql, entity_id, fecha_hora)
            connection.commit()

            self.logger.debug(f'Registro eliminado: entityId={entity_id}, fecha_hora={fecha_hora}')

        except pyodbc.Error as e:
            connection.rollback()
            raise IngestionError(f'Error al eliminar registro de TemporalDatosBrutos_iCousas: {str(e)}')
        finally:
            cursor.close()

    def _show_progress(self, current: int, total: int, bar_width: int = 40) -> None:
        """Muestra una barra de progreso simple usando caracteres."""
        show_progress(current, total, bar_width, description="Procesando registros")

        # Mostrar información detallada cada 20 registros o al final
        if current % 20 == 0 or current == total:
            percentage = int((current / total) * 100)
            self.logger.info(f'Progreso: {current}/{total} registros procesados ({percentage}%)')

    def process_ingestion(self) -> tuple[int, int]:
        """
        Procesa la ingestión completa de datos desde TemporalDatosBrutos_iCousas hacia TemporalDatosBrutos.

        Returns:
            tuple[int, int]: (registros_procesados, registros_eliminados)
        """
        self.logger.info('Iniciando proceso de ingestión de datos...')

        try:
            # Leer todos los registros de TemporalDatosBrutos_iCousas
            records = self.read_records_from_icousas()

            if not records:
                self.logger.info('No hay registros para procesar en TemporalDatosBrutos_iCousas')
                return 0, 0

            processed_count = 0
            deleted_count = 0
            total_records = len(records)

            self.logger.info(f'Iniciando procesamiento de {total_records} registros...')

            # Procesar cada registro
            for record in records:
                entity_id = record['entityId']
                fecha_hora = record['index']

                try:
                    # Buscar lnEstacion
                    ln_estacion = self.lookup_ln_estacion(entity_id)

                    if ln_estacion is None:
                        self.logger.warning(f'Saltando registro con entityId desconocido: {entity_id}')
                        processed_count += 1
                        self._show_progress(processed_count, total_records)
                        continue

                    # Obtener canales para la estación
                    channels = self.get_channels_for_station(ln_estacion)

                    if not channels:
                        self.logger.warning(f'No se encontraron canales para la estación {ln_estacion}')
                        processed_count += 1
                        self._show_progress(processed_count, total_records)
                        continue

                    # Mapear campos por orden (1-based indexing)
                    field_mapping = [
                        ('entityId', 1),  # Canal 1
                        ('index', 2),     # Canal 2
                        ('airTemperature', 3),  # Canal 3
                        ('atmosphericPressure', 4),  # Canal 4
                        ('batteryVoltage', 5),  # Canal 5
                        ('lightningAverageDistance', 6),  # Canal 6
                        ('lightningStrikeCount', 7),  # Canal 7
                        ('maximumWindSpeed', 8),  # Canal 8
                        ('precipitation', 9),  # Canal 9
                        ('relativeHumidity', 10),  # Canal 10
                        ('solarRadiation', 11),  # Canal 11
                        ('vaporPressure', 12),  # Canal 12
                        ('windDirection', 13),  # Canal 13
                        ('windSpeed', 14)  # Canal 14
                    ]

                    # Insertar datos para cada canal
                    operations_completed = 0
                    processed_count_local = 0
                    unchanged_count_local = 0

                    for field_name, expected_canal in field_mapping:
                        # Buscar si este canal existe en la configuración de la estación
                        channel_info = next((ch for ch in channels if ch['canal'] == expected_canal), None)

                        if channel_info:
                            valor = record.get(field_name)
                            # Convertir index a datetime si es necesario
                            if field_name == 'index':
                                valor = fecha_hora

                            try:
                                operation_result = self.insert_into_temporal_datos_brutos(
                                    ln_estacion, fecha_hora, expected_canal, valor
                                )
                                operations_completed += 1

                                # Contabilizar el tipo de operación
                                if operation_result in ['inserted', 'updated', 'processed']:
                                    processed_count_local += 1
                                elif operation_result == 'unchanged':
                                    unchanged_count_local += 1

                            except IngestionError as e:
                                self.logger.error(f'Error al procesar canal {expected_canal}: {str(e)}')
                                raise  # Re-lanzar para detener procesamiento de este registro

                    # Si todas las operaciones fueron exitosas, actualizar tabla de fechas y eliminar el registro original
                    if operations_completed > 0:
                        # Actualizar tabla CruceEstacionesListaEstacionesFechasUltimosDatos
                        self.update_fecha_ultimo_dato(ln_estacion, fecha_hora)

                        # Eliminar el registro original
                        self.delete_from_icousas(entity_id, fecha_hora)
                        deleted_count += 1
                        self.logger.debug(f'Procesado exitosamente registro: entityId={entity_id}, fecha_hora={fecha_hora} '
                                        f'(procesados: {processed_count_local}, sin_cambio: {unchanged_count_local})')

                    processed_count += 1
                    self._show_progress(processed_count, total_records)

                except IngestionError as e:
                    self.logger.error(f'Error procesando registro {entity_id} {fecha_hora}: {str(e)}')
                    processed_count += 1
                    self._show_progress(processed_count, total_records)
                    # Continuar con el siguiente registro
                    continue

            # Nueva línea después de la barra de progreso
            print()

            self.logger.info(f'Proceso de ingestión completado: {processed_count} registros procesados, {deleted_count} registros eliminados')
            return processed_count, deleted_count

        except Exception as e:
            self.logger.error(f'Error inesperado en proceso de ingestión: {str(e)}')
            raise IngestionError(f'Proceso de ingestión fallido: {str(e)}')

def main() -> int:
    """Función principal para ejecutar el proceso de recopilación y almacenamiento de datos."""
    start_time = datetime.now(timezone.utc)
    logger.info('Empezamos.')
    logger.debug(f'Los archivos de log se guardarán en: {os.path.join(os.getcwd(), "logs")}')

    try:
        # Validar variables de entorno
        Config.validate()
        logger.info('Configuración de entorno validada')

        # Registrar configuración de proxy activa
        proxy_config = Config.get_proxy_config()
        if proxy_config:
            logger.info('Configuración de proxy detectada y activada:')
            for key, value in proxy_config.items():
                if key == 'no_proxy':
                    logger.debug(f'  NO_PROXY: {value} (hosts excluidos del proxy)')
                else:
                    logger.debug(f'  {key.upper()}_PROXY: {value}')
        else:
            logger.info('No se detectó configuración de proxy - las conexiones serán directas')

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

        # Procesar ingestión después de la inserción exitosa
        logger.info('Iniciando proceso de ingestión de datos...')
        try:
            ingestion_manager = DataIngestionManager(db_config)
            processed_ingestion, deleted_ingestion = ingestion_manager.process_ingestion()

            logger.info(
                f'Proceso de ingestión completado: {processed_ingestion} registros procesados, '
                f'{deleted_ingestion} registros eliminados de tabla temporal'
            )
        except IngestionError as e:
            logger.error(f'Proceso de ingestión fallido: {str(e)}')
            return 1

        end_time = datetime.now(timezone.utc)
        duration = end_time - start_time

        logger.info(
            f'Trabajo completado exitosamente en {duration.total_seconds():.2f} segundos. '
            f'Procesados {len(normalized_records)} registros: {inserted + updated} insertados/actualizados, '
            f'{processed_ingestion} ingestados, {deleted_ingestion} eliminados'
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
    except IngestionError as e:
        logger.error(f'Operación de ingestión fallida: {str(e)}')
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