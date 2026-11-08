import re
import unicodedata
from config_riesgo import obtener_puntuacion, clasificar_riesgo
from url_analyzer import analizar_url, obtener_urls
from html_analyzer import (
    analizar_enlaces_html,
    extraer_destinos_html
)
from sender_analyzer import analizar_remitente



# ==========================================
# REGLAS DE DETECCIÓN DE TEXTO
# ==========================================

REGLAS = [
    {
        "nombre": "Amenaza de suspensión",
        "patron": (
            r"\b(suspendid[ao]s?|suspension|"
            r"suspender|suspendemos|"
            r"bloquead[ao]s?|bloqueo|"
            r"cuenta sera cancelada)\b"
        ),
        "puntos": obtener_puntuacion(
            "amenaza_suspension"
        ),
        "descripcion": (
            "El mensaje menciona el bloqueo o "
            "la suspensión de una cuenta."
        )
    },
    {
        "nombre": "Lenguaje de urgencia",
        "patron": (
            r"\b(urgente|inmediatamente|actua ahora|"
            r"24 horas|ultimo aviso)\b"
        ),
        "puntos": obtener_puntuacion("urgencia"),
        "descripcion": (
            "El mensaje utiliza expresiones de urgencia."
        )
    },
    {
        "nombre": "Solicitud de credenciales",
        "patron": (
            r"\b(verifica|verifique|verificar|ingresa|"
            r"ingrese|introduce|confirma|confirme|"
            r"envia|envie|proporciona|proporcione|"
            r"actualiza|actualice)\b"
            r"(?:\s+\w+){0,6}"
            r"\s+(?:contrasena|clave de acceso|"
            r"credenciales|codigo de verificacion|"
            r"datos bancarios)\b"
        ),
        "puntos": obtener_puntuacion(
            "solicitud_credenciales"
        ),
        "descripcion": (
            "El mensaje solicita ingresar, confirmar "
            "o proporcionar información sensible."
        )
    },
    {
        "nombre": "Premios sospechosos",
        "patron": (
            r"\b(ganaste un premio|reclama tu premio|"
            r"recompensa exclusiva)\b"
        ),
        "puntos": obtener_puntuacion("premio"),
        "descripcion": (
            "El mensaje promete premios o recompensas."
        )
    },
    
    {
        "nombre": "Solicitud de pago",
        "patron": (
            r"\b(?:pago pendiente|transfiere dinero|"
            r"paga ahora|realizar un pago|"
            r"realice un pago|realiza un pago|"
            r"debes pagar|debe pagar|"
            r"pago de verificación|"
            r"pago de verificacion)\b"
        ),
        "puntos": obtener_puntuacion(
            "solicitud_pago"
        ),
        "descripcion": (
            "El mensaje solicita realizar un pago "
            "o una transferencia de dinero."
        )
    }

]

# ==========================================
# ELIMINAR HALLAZGOS DUPLICADOS
# ==========================================

def eliminar_duplicados(hallazgos):
    """
    Evita contabilizar varias veces un mismo
    tipo de alerta para la misma coincidencia.
    """

    hallazgos_unicos = []
    coincidencias_vistas = set()

    for hallazgo in hallazgos:

        identificador = (
            hallazgo["tipo"],
            hallazgo["coincidencia"]
        )

        if identificador not in coincidencias_vistas:

            coincidencias_vistas.add(identificador)

            hallazgos_unicos.append(hallazgo)

    return hallazgos_unicos


# ==========================================
# NORMALIZAR TEXTO
# ==========================================

def normalizar(texto):
    texto = unicodedata.normalize(
        "NFKD",
        texto.lower()
    )

    return "".join(
        caracter for caracter in texto
        if not unicodedata.combining(caracter)
    )

# ==========================================
# ANÁLISIS PRINCIPAL DEL CORREO
# PHISHGUARD 3.0
# ==========================================


def analizar_correo(asunto, cuerpo, html="", remitente=""):
    """
    Analiza asunto, cuerpo, HTML y remitente.

    También devuelve los destinos encontrados
    en los enlaces HTML del correo.
    """

    contenido_original = f"{asunto}\n{cuerpo}"
    texto = normalizar(contenido_original)

    hallazgos = []

    # 1. ANALIZAR PATRONES DE TEXTO
    for regla in REGLAS:
        coincidencia = re.search(
            regla["patron"],
            texto
        )

        if coincidencia:
            hallazgos.append({
                "tipo": regla["nombre"],
                "detalle": regla["descripcion"],
                "coincidencia": coincidencia.group(),
                "puntos": regla["puntos"]
            })

    # 2. EXTRAER Y ANALIZAR URLS DE TEXTO
    enlaces = obtener_urls(contenido_original)
    enlaces = list(dict.fromkeys(enlaces))

    for enlace in enlaces:
        hallazgos.extend(analizar_url(enlace))

    # 3. ANALIZAR HTML Y EXTRAER DESTINOS
    enlaces_html = []

    if html.strip():
        hallazgos.extend(
            analizar_enlaces_html(html)
        )

        enlaces_html = extraer_destinos_html(html)

        # Analizar los destinos reales de botones
        # y enlaces HTML, incluso si no aparecen
        # escritos en el texto del correo.
        urls_analizadas = set(enlaces)

        for enlace_html in enlaces_html:
            destino = enlace_html["destino"]

            if destino in urls_analizadas:
                continue

            urls_analizadas.add(destino)

            hallazgos.extend(
                analizar_url(destino)
            )


    # 4. ANALIZAR REMITENTE
    if remitente.strip():
        hallazgos.extend(
            analizar_remitente(remitente)
        )

    # 5. ELIMINAR HALLAZGOS DUPLICADOS
    hallazgos = eliminar_duplicados(hallazgos)

   
    # ==========================================
    # 6. CALCULAR PUNTUACIÓN SIN REPETIR TIPOS
    # ==========================================

    puntos_por_tipo = {}

    for hallazgo in hallazgos:
        tipo = hallazgo["tipo"]
        puntos = hallazgo["puntos"]

        # Cada categoría aporta su puntuación
        # máxima una sola vez por correo.
        puntos_por_tipo[tipo] = max(
            puntos_por_tipo.get(tipo, 0),
            puntos
        )

    puntuacion = min(
        sum(puntos_por_tipo.values()),
        100
    )

    # 7. CLASIFICAR RIESGO
    nivel = clasificar_riesgo(puntuacion)

    # 8. DEVOLVER RESULTADOS
    return {
        "puntuacion": puntuacion,
        "nivel": nivel,
        "hallazgos": hallazgos,
        "enlaces": enlaces,
        "enlaces_html": enlaces_html
    }
