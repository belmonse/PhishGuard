# ==========================================
# PHISHGUARD 3.0
# LECTOR DE CORREOS .EML
# ==========================================

from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from auth_analyzer import (
    leer_autenticacion_eml,
    evaluar_confianza_autenticacion
)




def analizar_eml(contenido):

    # 1. INTERPRETAR EL CORREO
    mensaje = BytesParser(
        policy=policy.default
    ).parsebytes(contenido)

    # 2. EXTRAER ENCABEZADOS
    remitente = str(mensaje.get("From", ""))
    destinatario = str(mensaje.get("To", ""))
    asunto = str(mensaje.get("Subject", ""))
    fecha = str(mensaje.get("Date", ""))

    # 3. SEPARAR DATOS DEL REMITENTE
    nombre_remitente, correo_remitente = parseaddr(
        remitente
    )

    # 4. EXTRAER TEXTO Y HTML
    cuerpo = ""
    html = ""

    for parte in mensaje.walk():

        if parte.get_content_disposition() == "attachment":
            continue

        tipo = parte.get_content_type()

        if tipo == "text/plain" and not cuerpo:
            try:
                cuerpo = parte.get_content()
            except (UnicodeError, LookupError, ValueError):
                continue

        elif tipo == "text/html" and not html:
            try:
                html = parte.get_content()
            except (UnicodeError, LookupError, ValueError):
                continue

    # 5. LEER RESULTADOS DE AUTENTICACIÓN
    autenticacion = leer_autenticacion_eml(contenido)

    # 6. EVALUAR CONFIANZA DE LOS RESULTADOS
    confianza_autenticacion = evaluar_confianza_autenticacion(
        autenticacion
)
    # 7. DEVOLVER INFORMACIÓN
    return {
        "remitente": remitente,
        "nombre_remitente": nombre_remitente,
        "correo_remitente": correo_remitente,
        "destinatario": destinatario,
        "asunto": asunto,
        "fecha": fecha,
        "cuerpo": cuerpo,
        "html": html,
        "autenticacion": autenticacion,
        "confianza_autenticacion": confianza_autenticacion
    }
