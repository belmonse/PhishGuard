
from pathlib import Path

from detector import analizar_correo
from eml_analyzer import analizar_eml


# ==========================================
# PHISHGUARD 3.0
# EVALUACIÓN DEL DETECTOR
# ==========================================

# Correos de evaluación anteriores (PhishGuard 2.2)

correos = [
    {
        "nombre": "Reunión de trabajo",
        "tipo_real": "LEGITIMO",
        "asunto": "Reunión del equipo",
        "cuerpo": (
            "Hola, nos reuniremos el martes "
            "a las 10:00 para revisar el proyecto."
        )
    },
    {
        "nombre": "Consejo de seguridad",
        "tipo_real": "LEGITIMO",
        "asunto": "Consejos para proteger tu cuenta",
        "cuerpo": (
            "Nunca compartas tu contraseña "
            "con otras personas."
        )
    },
    {
        "nombre": "Notificación informativa",
        "tipo_real": "LEGITIMO",
        "asunto": "Información de seguridad",
        "cuerpo": (
            "Por seguridad, recuerda que nunca "
            "debes entregar tus credenciales."
        )
    },
    {
        "nombre": "Suplantación de banco",
        "tipo_real": "PHISHING",
        "asunto": "URGENTE: Cuenta suspendida",
        "cuerpo": (
            "Ingresa tu contraseña inmediatamente "
            "en https://bancoestado-seguridad.example/login"
        )
    },
    {
        "nombre": "Enlace bancario engañoso",
        "tipo_real": "PHISHING",
        "asunto": "Verificación de cuenta",
        "cuerpo": (
            "Verifique sus datos bancarios en "
            "https://bancoestado.cl.seguridad.example/login"
        )
    },
    {
        "nombre": "Premio fraudulento",
        "tipo_real": "PHISHING",
        "asunto": "Ganaste un premio",
        "cuerpo": (
            "Reclama tu premio inmediatamente "
            "en http://192.0.2.10/premio"
        )
    },
    {
        "nombre": "Phishing sin palabras sospechosas",
        "tipo_real": "PHISHING",
        "asunto": "Documento compartido",
        "cuerpo": (
            "Hola, te comparto el documento "
            "que solicitaste. Puedes revisarlo aquí: "
            "https://documento-compartido.example/archivo"
        )
    }
]


# ==========================================
# ARCHIVOS EML DE EVALUACIÓN (PHISHGUARD 3.0)
# ==========================================

carpeta_eml = Path("correos_prueba") / "evaluacion"

archivos_eml = {
    "01_reunion.eml": "LEGITIMO",
    "02_compra.eml": "LEGITIMO",
    "03_banco_falso.eml": "PHISHING",
    "04_premio_falso.eml": "PHISHING",
    "05_phishing_sutil.eml": "PHISHING"
}


# ==========================================
# MOSTRAR RESULTADO
# ==========================================

def mostrar_resultado(nombre, tipo_real, resultado):

    print(f"\nCorreo: {nombre}")
    print(f"Tipo esperado: {tipo_real}")
    print(f"Riesgo detectado: {resultado['nivel']}")
    print(f"Puntuación: {resultado['puntuacion']}/100")
    print("-" * 45)


# ==========================================
# EVALUAR CORREOS DE TEXTO
# ==========================================

def evaluar_textos():

    print("\n===== CORREOS DE TEXTO =====")

    for correo in correos:

        resultado = analizar_correo(
            asunto=correo["asunto"],
            cuerpo=correo["cuerpo"]
        )

        mostrar_resultado(
            correo["nombre"],
            correo["tipo_real"],
            resultado
        )


# ==========================================
# EVALUAR ARCHIVOS EML
# ==========================================

def evaluar_archivos_eml():

    print("\n===== CORREOS EML =====")

    for nombre_archivo, tipo_real in archivos_eml.items():

        ruta = carpeta_eml / nombre_archivo

        if not ruta.is_file():
            print(f"\nNo se encontró: {ruta}")
            continue

        # Leer el archivo EML
        contenido = ruta.read_bytes()
        datos = analizar_eml(contenido)

        # Analizar con el mismo detector de Streamlit
        resultado = analizar_correo(
            asunto=datos["asunto"],
            cuerpo=datos["cuerpo"],
            html=datos["html"],
            remitente=datos["remitente"]
        )

        mostrar_resultado(
            nombre_archivo,
            tipo_real,
            resultado
        )


# ==========================================
# EJECUTAR EVALUACIÓN COMPLETA
# ==========================================

if __name__ == "__main__":

    print("\n===== EVALUACIÓN PHISHGUARD 3.0 =====")

    evaluar_textos()
    evaluar_archivos_eml()

    print("\n===== FIN DE EVALUACIÓN =====")
