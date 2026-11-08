
# 🛡️ PhishGuard 3.1.0

Detector heurístico de posibles intentos de phishing desarrollado en Python.

PhishGuard analiza correos electrónicos para identificar señales que podrían indicar intentos de fraude, suplantación de identidad o enlaces sospechosos.

## Funcionalidades

- Análisis del asunto y cuerpo del correo.
- Detección de expresiones de urgencia y solicitudes de información sensible.
- Identificación de enlaces HTTP sin cifrado.
- Detección de enlaces que utilizan direcciones IP.
- Identificación de posibles dominios fraudulentos y suplantación de marcas.
- Detección de dominios Punycode.
- Análisis de enlaces acortados.
- Detección de diferencias entre el texto visible y el destino real de enlaces HTML.
- Inspección de URLs incluidas en parámetros de redirección.
- Análisis de remitentes sospechosos.
- Importación y análisis de archivos .eml.
- Interpretación de encabezados SPF, DKIM y DMARC cuando están disponibles.
- Clasificación del riesgo como BAJO, MEDIO o ALTO.
- API local mediante FastAPI.
- Interfaz gráfica desarrollada con Streamlit.

## Tecnologías

- Python
- Streamlit
- FastAPI
- Uvicorn
- Pydantic
- tldextract

## Instalación

Requisitos:
- Python 3.11 o superior.
- Windows, Linux o macOS.
- Conexión a Internet para instalar las dependencias.

### 1. Crear entorno virtual

```powershell
python -m venv .venv
```

### 2. Activar entorno virtual en Windows

```powershell
.\.venv\Scripts\Activate.ps1
```

### 3. Instalar dependencias

```powershell
python -m pip install -r requirements.txt
```

## Ejecutar la interfaz gráfica

```powershell
python -m streamlit run app.py
```

Abrir en el navegador:

http://localhost:8501

## Ejecutar la API local

En otra terminal:

```powershell
python -m uvicorn api:app --host 127.0.0.1 --port 8000
```

Documentación interactiva:

http://127.0.0.1:8000/docs

### Endpoints

GET /estado

Comprueba que el servicio esté funcionando.

POST /analizar

Recibe un correo con los siguientes campos:

```json
{
  "asunto": "Ejemplo de correo",
  "cuerpo": "Contenido del mensaje",
  "html": "",
  "remitente": "ejemplo@dominio.com"
}
```

Devuelve una puntuación, clasificación de riesgo y lista de señales detectadas.

## Extensión para navegadores

El proyecto incluye una extensión experimental Manifest V3 diseñada para analizar correos abiertos en Gmail mediante la API local.

Estado: pendiente de revisión de seguridad debido a un bloqueo reportado por Opera.

No se recomienda distribuir ni reinstalar la extensión bloqueada hasta aclarar esa advertencia.

## Limitaciones

PhishGuard utiliza reglas heurísticas y no garantiza identificar todos los correos fraudulentos.

Un resultado BAJO no significa necesariamente que un mensaje sea seguro.

El análisis de URLs de redirección es estático: no visita los destinos ni verifica cadenas de redirección reales.

Los resultados SPF, DKIM y DMARC obtenidos desde archivos EML corresponden a información declarada en sus encabezados. PhishGuard no realiza una verificación criptográfica independiente.

La API está pensada para ejecutarse localmente. La comprobación de Origin no constituye autenticación y no protege frente a todos los programas locales.

## Estado del proyecto

Versión 3.1.0

- Detector heurístico: funcional.
- Análisis EML: funcional.
- API local: funcional.
- Interfaz Streamlit: funcional.
- Extensión del navegador: pendiente de revisión.
```
