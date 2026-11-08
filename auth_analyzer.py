# ==========================================
# PHISHGUARD 3.0
# ANALIZADOR DE AUTENTICACIÓN
# ==========================================

import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
import tldextract


METODOS = {"spf", "dkim", "dmarc"}

RESULTADOS_VALIDOS = {
    "pass",
    "fail",
    "softfail",
    "neutral",
    "none",
    "temperror",
    "permerror"
}


def leer_autenticacion_eml(contenido):
    """
    Extrae resultados declarados en
    los encabezados Authentication-Results.

    No verifica si estos encabezados
    proceden de un servidor confiable.
    """

    mensaje = BytesParser(
        policy=policy.default
    ).parsebytes(contenido)

    encabezados = mensaje.get_all(
        "Authentication-Results", []
    )

    resultados = []

    for encabezado in encabezados:

        texto = str(encabezado)

        # Dividir el encabezado en secciones.
        partes = texto.split(";")

        servidor = partes[0].strip()

        registro = {
            "servidor": servidor,
            "spf": "no informado",
            "dkim": "no informado",
            "dmarc": "no informado",
            "dominio_spf": "",
            "dominio_dkim": "",
            "dominio_from": ""
        }

        # Analizar cada sección por separado.
        for parte in partes[1:]:

            coincidencia = re.match(
                r"^\s*(spf|dkim|dmarc)\s*=\s*"
                r"([a-zA-Z]+)\b",
                parte,
                flags=re.IGNORECASE
            )

            if not coincidencia:
                continue

            metodo = coincidencia.group(1).lower()
            estado = coincidencia.group(2).lower()

            
            # Extraer dominios declarados en el encabezado.
            # Estos valores no están verificados.

            propiedades = {
                "dominio_spf": "smtp.mailfrom",
                "dominio_dkim": "header.d",
                "dominio_from": "header.from"
            }

            campo = {
                "spf": "dominio_spf",
                "dkim": "dominio_dkim",
                "dmarc": "dominio_from"
            }[metodo]

            propiedad = propiedades[campo]

            dominio_encontrado = re.search(
                rf"(?<![\w.]){re.escape(propiedad)}"
                r'\s*=\s*(?:"([^"]+)"|([^\s;()]+))',
                parte,
                flags=re.IGNORECASE
            )

            if dominio_encontrado and not registro[campo]:
                registro[campo] = (
                    dominio_encontrado.group(1)
                    or dominio_encontrado.group(2)
                )

            if (
                metodo in METODOS
                and estado in RESULTADOS_VALIDOS
                and registro[metodo] == "no informado"
            ):
                registro[metodo] = estado

        resultados.append(registro)

    return resultados


# ==========================================
# IDENTIFICAR SERVIDORES DE AUTENTICACIÓN
# ==========================================

def obtener_servidores_autenticacion(contenido):
    """
    Obtiene los identificadores de los servidores
    declarados en Authentication-Results.

    No determina si los servidores son confiables.
    """

    registros = leer_autenticacion_eml(contenido)

    servidores = []

    for registro in registros:
        servidor = registro["servidor"]

        if servidor and servidor not in servidores:
            servidores.append(servidor)

    return servidores


# ==========================================
# COMPARAR DOMINIOS DECLARADOS
# ==========================================

def comparar_dominios_autenticacion(remitente, registro):
    """
    Compara el dominio del remitente visible
    con los dominios declarados para SPF y DKIM.

    La comparación es informativa.
    No verifica SPF, DKIM ni DMARC.
    """

    _, correo = parseaddr(remitente)

    dominio_remitente = (
        correo.rsplit("@", 1)[-1].lower()
        if "@" in correo
        else ""
    )

    def dominio_organizacional(dominio):
        dominio = dominio.strip().lower().strip(".")

        if not dominio:
            return ""

        extraido = tldextract.extract(dominio)

        if extraido.domain and extraido.suffix:
            return f"{extraido.domain}.{extraido.suffix}"

        # Para dominios ficticios usados en pruebas.
        return dominio

    dominio_visible = dominio_organizacional(
        dominio_remitente
    )

    dominio_spf = dominio_organizacional(
        registro.get("dominio_spf", "")
    )

    dominio_dkim = dominio_organizacional(
        registro.get("dominio_dkim", "")
    )

    return {
        "dominio_remitente": dominio_remitente,
        "alineacion_spf": (
            dominio_visible == dominio_spf
            if dominio_visible and dominio_spf
            else None
        ),
        "alineacion_dkim": (
            dominio_visible == dominio_dkim
            if dominio_visible and dominio_dkim
            else None
        )
    }


# ==========================================
# PHISHGUARD 3.0
# EVALUAR CONFIANZA EN LOS ENCABEZADOS
# ==========================================

def evaluar_confianza_autenticacion(registros):

    if not registros:
        return {
            "estado": "sin_datos",
            "confiable": False,
            "mensaje": (
                "El correo no contiene resultados "
                "de autenticación disponibles."
            )
        }

    return {
        "estado": "no_verificado",
        "confiable": False,
        "mensaje": (
            "El correo contiene resultados SPF, "
            "DKIM o DMARC declarados, pero "
            "PhishGuard no puede confirmar "
            "que provengan de un servidor confiable."
        )
    }
