# 🛰️ iCousas - Recopilador de Datos de Sensores Meteorológicos

Un script robusto y de producción en Python para recopilar, procesar y almacenar datos meteorológicos de sensores iCousas utilizando autenticación Keycloak y base de datos SQL Server.

## 📋 Tabla de Contenidos

- [Características](#características)
- [Arquitectura](#arquitectura)
- [Requisitos Previos](#requisitos-previos)
- [Instalación](#instalación)
- [Configuración](#configuración)
- [Uso](#uso)
- [Estructura del Proyecto](#estructura-del-proyecto)
- [Logging y Monitoreo](#logging-y-monitoreo)
- [Solución de Problemas](#solución-de-problemas)
- [Desarrollo](#desarrollo)
- [Licencia](#licencia)

## ✨ Características

### 🔐 Autenticación Segura
- **Autenticación Keycloak**: Resource Owner Password Flow
- **Gestión automática de tokens**: Refresh automático cuando expira
- **Reintentos con backoff exponencial**: Manejo robusto de fallos temporales
- **Seguridad**: Credenciales nunca expuestas en logs

### 📊 Procesamiento de Datos
- **API RESTful**: Consulta datos históricos de sensores
- **Ventana temporal configurable**: Últimos N minutos de datos
- **Paginación automática**: Manejo de grandes volúmenes de datos
- **Normalización**: Conversión automática de tipos de datos
- **Conversión de unidades**: atmosphericPressure kPa → hPa (canal 4)
- **Validación**: Verificación de integridad de datos
- **Redondeo robusto de minutos**: Algoritmo avanzado que evita hour=24 y minute=60
- **Ordenamiento inteligente**: Registros ordenados por fecha para procesamiento correcto
- **Filtrado inteligente**: Evita reprocesar datos ya procesados basándose en metadatos
- **Barra de progreso visual**: Seguimiento en tiempo real del procesamiento
- **Procesamiento en dos fases**: API → TemporalDatosBrutos_iCousas → TemporalDatosBrutos

### 🗄️ Almacenamiento en Base de Datos
- **SQL Server**: Compatibilidad completa
- **Operación MERGE**: Insert/Update automático (Upsert)
- **Transacciones ACID**: Garantía de integridad de datos
- **Tablas temporales**: Optimización de rendimiento
- **Manejo inteligente de duplicados**: Verificación previa con redondeo de floats
- **Actualización automática de metadatos**: Tabla CruceEstacionesListaEstacionesFechasUltimosDatos (estaciones pre-registradas)
- **Manejo de errores**: Rollback automático en fallos

### 📝 Logging Avanzado
- **Archivo + Consola**: Logging dual simultáneo
- **Rotación automática**: Archivo por hora (formato YYYY-MM-DD-HH.txt)
- **Niveles configurables**: DEBUG, INFO, WARNING, ERROR
- **Información detallada**: Curl equivalents, headers, respuestas
- **Consultas SQL visibles**: Para debugging de base de datos
- **Barra de progreso integrada**: Seguimiento visual en logs
- **Seguridad**: Contraseñas ocultas en logs

### 🛠️ Características Técnicas
- **Python 3.11+**: Última versión LTS
- **Tipado estático**: Type hints completos
- **Manejo de excepciones**: Tratamiento robusto de errores
- **Configuración externa**: Variables de entorno
- **Documentación completa**: Docstrings en español

## 🏗️ Arquitectura

```
iCousas Data Collector
├── 🔐 AuthManager (Keycloak)
├── 📡 SensorDataFetcher (API REST)
├── 🔄 DataProcessor (ETL)
├── 💾 DatabaseManager (SQL Server)
├── 🔄 DataIngestionManager (Procesamiento Final)
├── 📊 ProgressMonitor (Barras de Progreso)
└── 📝 Logger (Archivo + Consola)
```

### Componentes Principales

1. **AuthManager**: Gestiona autenticación OAuth2 con Keycloak
2. **SensorDataFetcher**: Consulta API de sensores con paginación
3. **DataProcessor**: Normaliza y valida datos meteorológicos
4. **DatabaseManager**: Ejecuta operaciones MERGE en SQL Server
5. **DataIngestionManager**: Procesa datos finales de TemporalDatosBrutos_iCousas → TemporalDatosBrutos
6. **ProgressMonitor**: Muestra barras de progreso visual en tiempo real
7. **Sistema de Logging**: Registra todas las operaciones detalladamente

## 📋 Requisitos Previos

### 🔧 Requisitos del Sistema
- **SO**: Windows 10/11, Linux, macOS
- **Python**: 3.11 o superior
- **RAM**: Mínimo 512MB (recomendado 1GB)
- **Espacio en disco**: 100MB para logs y datos temporales

### 🗄️ Base de Datos
- **SQL Server**: 2016 o superior
- **Controlador ODBC**: SQL Server Native Client 11.0+
- **Tablas requeridas**:
  - `TemporalDatosBrutos_iCousas` (temporal - fase 1)
  - `TemporalDatosBrutos` (final - fase 2)
  - `AuxEstacionesCodigos` (mapeo estaciones)
  - `VIDX_AMC_ConNulls` (configuración canales)
  - `CruceEstacionesListaEstacionesFechasUltimosDatos` (metadatos)

#### 📝 Esquemas de Tablas

**Tabla Temporal (Fase 1):**
```sql
CREATE TABLE dbo.TemporalDatosBrutos_iCousas (
    entityId                  NVARCHAR(200)   NOT NULL,
    [index]                   DATETIME2       NOT NULL,
    airTemperature            FLOAT           NULL,
    atmosphericPressure       FLOAT           NULL,
    batteryVoltage            FLOAT           NULL,
    lightningAverageDistance  FLOAT           NULL,
    lightningStrikeCount      FLOAT           NULL,
    maximumWindSpeed          FLOAT           NULL,
    precipitation             FLOAT           NULL,
    relativeHumidity          FLOAT           NULL,
    solarRadiation            FLOAT           NULL,
    vaporPressure             FLOAT           NULL,
    windDirection             FLOAT           NULL,
    windSpeed                 FLOAT           NULL,
    CONSTRAINT PK_TemporalDatosBrutos_iCousas PRIMARY KEY (entityId, [index])
);
```

**Tabla Final (Fase 2):**
```sql
CREATE TABLE dbo.TemporalDatosBrutos (
    lnEstacion                INT             NOT NULL,
    FechaHora                 SMALLDATETIME   NOT NULL,
    Canal                     SMALLINT        NOT NULL,
    Valor                     REAL            NOT NULL,
    FechaEntrada              SMALLDATETIME   NULL,
    CONSTRAINT PK_new_TemporalDatosBrutos PRIMARY KEY CLUSTERED (lnEstacion, FechaHora, Canal)
);
```

**Tabla de Metadatos:**
```sql
CREATE TABLE dbo.CruceEstacionesListaEstacionesFechasUltimosDatos (
    lnEstacion                      INT           NOT NULL,
    lnTipoFechaUltimoDato           INT           NOT NULL,
    Fecha                          SMALLDATETIME NOT NULL,
    CONSTRAINT PK_new_CruceListaEstacionesFechasUltimosDatos PRIMARY KEY CLUSTERED (lnEstacion, lnTipoFechaUltimoDato)
);
```

### 🌐 Conectividad
- **API iCousas**: `https://sensors.icousas.gal`
- **Keycloak**: `https://iam.icousas.gal`
- **SQL Server**: Acceso a servidor de base de datos

## 🚀 Instalación

### Paso 1: Clonar/Descargar el Proyecto
```bash
# Crear directorio del proyecto
mkdir icousas-data-collector
cd icousas-data-collector

# Copiar archivos del proyecto
# main.py, requirements.txt, .env.example
```

### Paso 2: Instalar Python
Verificar instalación de Python 3.11+:
```bash
python --version
# Debe mostrar Python 3.11.x o superior
```

### Paso 3: Instalar Dependencias
```bash
# Instalar dependencias Python
pip install -r requirements.txt
```

#### Dependencias Incluidas:
- `requests>=2.31.0` - Cliente HTTP
- `pyodbc>=5.2.0` - Conector SQL Server
- `python-dotenv>=1.1.1` - Gestión de variables de entorno
- `python-dateutil>=2.9.0` - Manejo de fechas

### Paso 4: Verificar Instalación
```bash
python -c "import requests, pyodbc, dotenv, dateutil; print('✅ Todas las dependencias instaladas correctamente')"
```

## ⚙️ Configuración

### Paso 1: Configurar Variables de Entorno
```bash
# Copiar archivo de ejemplo
copy .env.example .env

# Editar .env con tus valores reales
notepad .env
```

### Paso 2: Archivo de Configuración (.env)

```bash
# ===========================================
# CONFIGURACIÓN DE AUTENTICACIÓN KEYCLOAK
# ===========================================
KEYCLOAK_URL=https://iam.icousas.gal/auth/realms/icousas/protocol/openid-connect/token
KEYCLOAK_CLIENT_ID=icousas-backend
KEYCLOAK_USERNAME=tu_usuario
KEYCLOAK_PASSWORD=tu_contraseña
KEYCLOAK_GRANT_TYPE=password

# ===========================================
# CONFIGURACIÓN HTTP
# ===========================================
HTTP_TIMEOUT=15
HTTP_MAX_RETRIES=3
HTTP_RETRY_BACKOFF_BASE=1
HTTP_VERIFY_SSL=false

# ===========================================
# CONFIGURACIÓN API SENSORES
# ===========================================
SENSORS_BASE_URL=https://sensors.icousas.gal/v1/data/historic/devices
SENSORS_ATTRIBUTES=airTemperature,atmosphericPressure,batteryVoltage,lightningAverageDistance,lightningStrikeCount,maximumWindSpeed,precipitation,relativeHumidity,solarRadiation,vaporPressure,windDirection,windSpeed
SENSORS_TIME_WINDOW_MINUTES=20
SENSORS_LAST_N=100
SENSORS_LIMIT=100
SENSORS_ORGANIZATION=MedioAmbiente

# ===========================================
# CONFIGURACIÓN BASE DE DATOS SQL SERVER
# ===========================================
DB_SERVER=tu_servidor_sql_server
DB_USERNAME=tu_usuario_db
DB_PASSWORD=tu_contraseña_db
DB_NAME=tu_base_datos
DB_CONNECTION_TIMEOUT=30

# ===========================================
# CONFIGURACIÓN DE LOGGING
# ===========================================
LOG_LEVEL=INFO
```

### Paso 3: Verificar Configuración
```bash
python main.py
# Debe mostrar "Variables de entorno cargadas exitosamente"
```

## 🎯 Uso

### Flujo de Procesamiento

El script ejecuta un **procesamiento en dos fases**:

1. **Fase 1**: API → `TemporalDatosBrutos_iCousas`
   - Obtiene datos de la API iCousas
   - Los almacena en tabla temporal
   - Barra de progreso visual

2. **Fase 2**: `TemporalDatosBrutos_iCousas` → `TemporalDatosBrutos`
   - Procesa datos de tabla temporal
   - Los mapea a formato final usando configuración de canales
   - Actualiza metadatos de fechas
   - Elimina registros procesados
   - Barra de progreso visual

### Ejecución Básica
```bash
python main.py
```

### Ejecución con Logging Detallado
```bash
# Editar .env y cambiar:
LOG_LEVEL=DEBUG

# Ejecutar
python main.py
```

### Ejecución con Consultas SQL Visibles
```bash
# Editar .env y cambiar:
LOG_LEVEL=DEBUG

# Ejecutar - mostrará todas las consultas SQL ejecutadas
python main.py
```

### Ejecución Programada (Windows Task Scheduler)
```batch
# Crear tarea programada para ejecutar cada hora
schtasks /create /tn "iCousasDataCollector" /tr "python D:\test\iCousas\main.py" /sc hourly /mo 1
```

### Ejecución Programada (Linux Cron)
```bash
# Editar crontab
crontab -e

# Agregar línea para ejecutar cada hora
0 * * * * /usr/bin/python3 /ruta/a/main.py
```

## 📁 Estructura del Proyecto

```
icousas-data-collector/
├── 📄 main.py                 # Script principal
├── 📄 requirements.txt        # Dependencias Python
├── 📄 .env.example           # Plantilla de configuración
├── 📄 .env                   # Configuración personal (no versionar)
├── 📁 logs/                  # Directorio de logs
│   ├── 2025-09-09-12.txt    # Log principal de las 12:00
│   ├── 2025-09-09-12_ingest.txt  # Log de ingestión de las 12:00
│   └── ...
├── 📄 README.md             # Esta documentación
└── 📁 __pycache__/          # Archivos compilados Python
```

### Componentes del Script
- **AuthManager**: Autenticación Keycloak
- **SensorDataFetcher**: Consulta API de sensores
- **DataProcessor**: Procesamiento inicial con barra de progreso
- **DatabaseManager**: Operaciones SQL Server
- **DataIngestionManager**: Procesamiento final con barra de progreso
- **Sistema de Logging**: Logs separados para cada fase

## 📊 Logging y Monitoreo

### Sistema de Logs
- **Ubicación**: `logs/YYYY-MM-DD-HH.txt`
- **Rotación**: Automática por hora
- **Contenido**: Información detallada de todas las operaciones

### Ejemplo de Log Exitoso

**Log Principal (main.py):**
```
2025-09-09 12:00:01 - __main__ - INFO - Empezamos
2025-09-09 12:00:01 - __main__ - INFO - Variables de entorno cargadas exitosamente (20 variables)
2025-09-09 12:00:01 - __main__ - INFO - Configuración de entorno validada
2025-09-09 12:00:01 - __main__ - INFO - Autenticando con Keycloak...
2025-09-09 12:00:02 - __main__ - INFO - Autenticación exitosa
2025-09-09 12:00:02 - __main__ - INFO - Iniciando obtención de datos...
2025-09-09 12:00:03 - __main__ - INFO - Se obtuvieron exitosamente 150 dispositivos totales
Procesando dispositivos: [██████████████████████████████] 100% (150/150)
2025-09-09 12:00:04 - __main__ - INFO - Se normalizaron exitosamente 150 registros
2025-09-09 12:00:04 - __main__ - INFO - Almacenando datos en base de datos...
2025-09-09 12:00:05 - __main__ - INFO - Iniciando proceso de ingestión de datos...
Procesando registros: [██████████████████████████████] 100% (150/150)
2025-09-09 12:00:06 - __main__ - INFO - Progreso: 150/150 registros procesados (100%)
2025-09-09 12:00:06 - __main__ - INFO - Proceso de ingestión completado: 150 registros procesados, 150 registros eliminados
2025-09-09 12:00:06 - __main__ - INFO - Trabajo completado exitosamente en 5.42 segundos. Procesados 150 registros: 150 insertados/actualizados, 150 ingestados, 150 eliminados
```

**Log de Ingestión (ingest):**
```
2025-09-09 12:00:05 - ingestion - INFO - Iniciando proceso de ingestión de datos...
2025-09-09 12:00:05 - ingestion - INFO - Leyendo registros de TemporalDatosBrutos_iCousas...
2025-09-09 12:00:05 - ingestion - INFO - Se leyeron 150 registros de TemporalDatosBrutos_iCousas
2025-09-09 12:00:05 - ingestion - INFO - Iniciando procesamiento de 150 registros...
2025-09-09 12:00:06 - ingestion - INFO - Progreso: 150/150 registros procesados (100%)
2025-09-09 12:00:06 - ingestion - INFO - Proceso de ingestión completado: 150 registros procesados, 150 registros eliminados
```

### Monitoreo de Logs
```bash
# Ver logs más recientes
Get-ChildItem logs\*.txt | Sort-Object LastWriteTime -Descending | Select-Object -First 5

# Buscar errores en logs
Select-String -Path logs\*.txt -Pattern "ERROR" -CaseSensitive:$false

# Contar líneas de log por hora
Get-ChildItem logs\*.txt | ForEach-Object { "$($_.Name): $((Get-Content $_.FullName).Count) líneas" }
```

## 🔧 Solución de Problemas

### Problema: Error de Autenticación (401)
```
❌ Authentication failed: 401 - {"error":"invalid_grant","error_description":"Invalid user credentials"}
```

**Soluciones:**
1. Verificar credenciales en `.env`
2. Asegurar que la contraseña termine con `#`
3. Confirmar que el usuario tenga permisos en Keycloak

### Problema: Error de Conexión SSL
```
❌ HTTPSConnectionPool: Max retries exceeded (Caused by SSLCertVerificationError)
```

**Soluciones:**
1. Configurar `HTTP_VERIFY_SSL=false` en `.env`
2. Verificar conectividad a la red corporativa
3. Revisar configuración de proxy si aplica

### Problema: Variables de Entorno Faltantes
```
❌ Missing required environment variables: KEYCLOAK_URL, KEYCLOAK_PASSWORD
```

**Soluciones:**
1. Verificar que `.env` exista y esté completo
2. Revisar sintaxis (especialmente contraseñas con `#`)
3. Asegurar que no haya BOM UTF-8/UTF-16

### Problema: Error de Base de Datos
```
❌ Database operation failed: Login timeout expired
```

**Soluciones:**
1. Verificar credenciales de SQL Server
2. Confirmar conectividad al servidor
3. Revisar configuración de firewall
4. Verificar que la tabla exista

### Problema: Memoria Insuficiente
```
❌ MemoryError: Unable to allocate array
```

**Soluciones:**
1. Reducir `SENSORS_LIMIT` en configuración
2. Procesar datos en lotes más pequeños
3. Aumentar RAM del sistema

### Debugging Avanzado
```bash
# Ejecutar con logging máximo
# Editar .env: LOG_LEVEL=DEBUG
python main.py

# Ver logs detallados
Get-Content logs\*.txt -Tail 50
```

## 🛠️ Desarrollo

### Configuración del Entorno de Desarrollo
```bash
# Instalar dependencias de desarrollo
pip install black flake8 mypy pytest

# Ejecutar linter
flake8 main.py

# Formatear código
black main.py

# Verificar tipos
mypy main.py
```

### Estructura del Código
```python
class AuthManager:
    """Maneja la autenticación Keycloak."""
    # Métodos: get_access_token, _authenticate, _create_session

class SensorDataFetcher:
    """Maneja la obtención de datos desde la API."""
    # Métodos: fetch_data, _calculate_time_window

class DataProcessor:
    """Procesa y normaliza datos de sensores."""
    # Métodos: process_devices, normalize_record, parse_datetime

class DatabaseManager:
    """Maneja operaciones de base de datos SQL Server."""
    # Métodos: upsert_records, _get_connection

def main():
    """Función principal del programa."""
    # Lógica principal de ejecución
```

### Testing
```python
# Ejecutar tests (si se implementan)
pytest tests/

# Ejecutar con coverage
pytest --cov=main --cov-report=html
```

## 📈 Métricas y Rendimiento

### Rendimiento Típico
- **Tiempo de ejecución**: 3-15 segundos
- **Registros procesados**: 100-1000 por ejecución
- **Memoria utilizada**: 50-200MB
- **CPU**: 5-15% durante ejecución

### Optimizaciones
- **Tablas temporales**: Reduce I/O en base de datos
- **Bulk inserts**: Optimización de inserciones masivas
- **Paginación**: Manejo eficiente de grandes datasets
- **Pooling de conexiones**: Reutilización de conexiones HTTP

## 🤝 Contribución

1. **Fork** el proyecto
2. Crear rama para feature: `git checkout -b feature/nueva-funcionalidad`
3. **Commit** cambios: `git commit -am 'Agrega nueva funcionalidad'`
4. **Push** a rama: `git push origin feature/nueva-funcionalidad`
5. Crear **Pull Request**

### Estándares de Código
- **PEP 8**: Estilo de código Python
- **Type hints**: Anotaciones de tipo completas
- **Docstrings**: Documentación en español
- **Logging**: Mensajes informativos en español
- **Comentarios**: Explicativos y útiles

## 📄 Licencia

Este proyecto está bajo la Licencia MIT. Ver archivo `LICENSE` para más detalles.

## 📞 Soporte

Para soporte técnico o reportar problemas:

1. **Revisar logs**: `logs/YYYY-MM-DD-HH.txt`
2. **Verificar configuración**: Archivo `.env`
3. **Documentar el error**: Incluir logs completos
4. **Crear issue**: Con descripción detallada del problema

## 🏆 Características Destacadas

- ✅ **Redondeo Inteligente de Minutos**: Fechas normalizadas para sistema de almacenamiento
- ✅ **Procesamiento en Dos Fases**: API → Temporal → Final con barras de progreso
- ✅ **Manejo Inteligente de Duplicados**: Verificación con redondeo de floats
- ✅ **Actualización Automática de Metadatos**: Tabla de fechas de último dato
- ✅ **Consultas SQL Visibles**: Para debugging completo de base de datos
- ✅ **Logging Dual**: Logs separados para cada fase del procesamiento
- ✅ **Barra de Progreso Visual**: Seguimiento en tiempo real sin dependencias externas
- ✅ **Producción Ready**: Código robusto y probado
- ✅ **Documentación Completa**: En español con ejemplos actualizados
- ✅ **Manejo de Errores**: Tratamiento completo de excepciones
- ✅ **Configuración Flexible**: Variables de entorno
- ✅ **Seguridad**: Credenciales protegidas
- ✅ **Rendimiento**: Optimizado para grandes volúmenes
- ✅ **Mantenibilidad**: Código modular y bien estructurado

---

**Desarrollado con ❤️ para el proyecto iCousas**

*Última actualización: Septiembre 2025*

---

## 📋 Historial de Cambios (v2.0.0)

### ✨ Nuevas Funcionalidades
- **DataIngestionManager**: Procesamiento independiente de datos finales
- **Redondeo inteligente de minutos**: Fechas normalizadas a minutos permitidos (0,10,20,30,40,50)
- **Ordenamiento inteligente**: Registros ordenados por fecha para procesamiento correcto
- **Filtrado inteligente**: Evita reprocesar datos ya procesados
- **Barras de progreso visual**: Seguimiento en tiempo real sin dependencias externas
- **Actualización automática de metadatos**: Gestión de fechas de último dato (estaciones pre-registradas)
- **Consultas SQL visibles**: Debugging completo de operaciones de BD

### 🔧 Mejoras Técnicas
- **Manejo robusto de duplicados**: Verificación previa con redondeo de floats
- **Conversión de unidades meteorológicas**: atmosphericPressure ×10 (kPa→hPa)
- **Corrección de conversión SMALLDATETIME**: Formatos de fecha compatibles
- **Parsing avanzado de fechas ISO 8601**: datetime.fromisoformat + fallback dateutil + redondeo robusto
- **Validación de integridad**: Estaciones deben estar pre-registradas en metadatos
- **Logging dual**: Logs separados para cada fase de procesamiento
- **Transacciones atómicas**: Mejor integridad de datos
- **Manejo de errores mejorado**: Mensajes detallados y recuperación automática
