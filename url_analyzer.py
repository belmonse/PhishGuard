import ipaddress
import re
import tldextract
from urllib.parse import urlsplit, parse_qsl
from marcas import MARCAS
from config_riesgo import obtener_puntuacion

# Utiliza la lista de sufijos incluida en la biblioteca.
# No consulta Internet durante el análisis.
EXTRACTOR = tldextract.TLDExtract(
    suffix_list_urls=()
)

def obtener_dominio_registrable(host):
    """
    Obtiene el dominio registrable de un host.

    Incluye soporte para dominios ficticios .example
    utilizados en las pruebas de PhishGuard.
    """

    host = host.lower().rstrip(".")

    # Dominios ficticios utilizados en pruebas
    if host.endswith(".example"):
        partes = host.split(".")

        if len(partes) >= 2:
            return ".".join(partes[-2:])

    # Dominios reales
    resultado = EXTRACTOR(host)

    return resultado.top_domain_under_public_suffix


# ==========================================
# DOMINIOS CONFIGURADOS
# ==========================================


ACORTADORES = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly"
}

# Sustituciones simples usadas en algunos
# intentos de imitación de marcas.
SUSTITUCIONES = str.maketrans({
    "0": "o",
    "1": "l",
    "3": "e",
    "5": "s",
    "7": "t"
})


# ==========================================
# FUNCIONES AUXILIARES
# ==========================================

def es_dominio_oficial(host, dominio):
    return (
        host == dominio
        or host.endswith("." + dominio)
    )


def obtener_urls(texto):
    """Extrae URLs sin visitarlas."""

    urls = re.findall(
        r"https?://[^\s<>\"']+",
        texto,
        flags=re.IGNORECASE
    )

    return [
        url.rstrip(".,;!?)")
        for url in urls
    ]


def crear_hallazgo(tipo, detalle, url, puntos):
    return {
        "tipo": tipo,
        "detalle": detalle,
        "coincidencia": url,
        "puntos": puntos
    }


# ==========================================
# ANALIZADOR PRINCIPAL DE URLS
# ==========================================


def analizar_url(url, profundidad=0, visitadas=None):
    hallazgos = []

    # Evitar ciclos y análisis repetidos.
    if visitadas is None:
        visitadas = set()

    if url in visitadas or profundidad > 3:
        return []

    visitadas.add(url)

    try:
        partes = urlsplit(url.strip())

        if partes.scheme.lower() not in ("http", "https"):
            return hallazgos

        host = (partes.hostname or "").lower().rstrip(".")

        if not host:
            return hallazgos

        # 1. NORMALIZAR EL HOST
        try:
            host_ascii = host.encode("idna").decode("ascii")
        except UnicodeError:
            hallazgos.append(crear_hallazgo(
                "Dominio inválido",
                "No fue posible normalizar el dominio.",
                url,
                20
            ))
            return hallazgos

        # 2. OBTENER EL DOMINIO REGISTRABLE
        dominio_registrable = obtener_dominio_registrable(
            host_ascii
        )

        # 3. DETECTAR DIRECCIONES IP
        try:
            ipaddress.ip_address(host_ascii)

            hallazgos.append(crear_hallazgo(
                "Enlace con dirección IP",
                f"El enlace utiliza la IP {host_ascii}.",
                url,
                obtener_puntuacion("direccion_ip")
            ))

        except ValueError:
            pass

        # 4. DETECTAR HTTP SIN CIFRADO
        if partes.scheme.lower() == "http":
            hallazgos.append(crear_hallazgo(
                "Enlace sin HTTPS",
                "El enlace utiliza HTTP sin cifrado.",
                url,
                obtener_puntuacion("http")
            ))

        # 5. DETECTAR ACORTADORES
        if any(
            es_dominio_oficial(host_ascii, acortador)
            for acortador in ACORTADORES
        ):
            hallazgos.append(crear_hallazgo(
                "URL acortada",
                "El enlace utiliza un acortador. "
                "Su destino final no ha sido verificado.",
                url,
                obtener_puntuacion("url_acortada")
            ))

        # 6. DETECTAR PUNYCODE
        etiquetas = host_ascii.split(".")

        if any(
            etiqueta.startswith("xn--")
            for etiqueta in etiquetas
        ):
            hallazgos.append(crear_hallazgo(
                "Dominio internacionalizado (Punycode)",
                f"El host {host_ascii} contiene "
                "una etiqueta Punycode que requiere revisión.",
                url,
                obtener_puntuacion("punycode")
            ))

        # 7. DETECTAR POSIBLE SUPLANTACIÓN
        host_normalizado = host_ascii.translate(
            SUSTITUCIONES
        )

        for marca, datos in MARCAS.items():

            oficial = any(
                es_dominio_oficial(host_ascii, dominio)
                for dominio in datos["dominios"]
            )

            if oficial:
                continue

            marca_directa = any(
                palabra in host_ascii
                for palabra in datos["palabras"]
            )

            marca_alterada = any(
                palabra in host_normalizado
                for palabra in datos["palabras"]
            )

            if marca_directa:
                hallazgos.append(crear_hallazgo(
                    f"Posible suplantación de {marca}",
                    f"Host completo: {host_ascii}. "
                    f"Dominio registrable: {dominio_registrable}. "
                    f"El enlace menciona {marca}, pero no "
                    "coincide con sus dominios configurados.",
                    url,
                    obtener_puntuacion("suplantacion_marca")
                ))

            elif marca_alterada:
                hallazgos.append(crear_hallazgo(
                    f"Posible imitación de {marca}",
                    f"Host completo: {host_ascii}. "
                    f"Dominio registrable: {dominio_registrable}. "
                    "Se identificaron posibles sustituciones "
                    "de letras por números.",
                    url,
                    obtener_puntuacion("imitacion_marca")
                ))

    except ValueError:
        pass


    
    # ==========================================
    # ANALIZAR DESTINOS DE REDIRECCIÓN
    # ==========================================

    for destino in extraer_redirecciones(url):

        hallazgos.extend(
            analizar_url(
                destino,
                profundidad=profundidad + 1,
                visitadas=visitadas
            )
        )


    return hallazgos


# ==========================================
# PHISHGUARD 3.1
# EXTRACCIÓN DE REDIRECCIONES
# ==========================================

PARAMETROS_REDIRECCION = {
    "url",
    "redirect",
    "redirect_url",
    "redirect_uri",
    "return",
    "return_url",
    "next",
    "target",
    "destination"
}


def extraer_redirecciones(url):
    """
    Detecta URLs absolutas incluidas en
    parámetros habituales de redirección.

    No abre enlaces ni realiza conexiones.
    """

    destinos = []

    try:
        partes = urlsplit(url)

        parametros = parse_qsl(
            partes.query,
            keep_blank_values=False
        )

        for nombre, valor in parametros:

            if nombre.lower() not in PARAMETROS_REDIRECCION:
                continue

            destino = valor.strip()

            if not destino:
                continue

            partes_destino = urlsplit(destino)

            if (
                partes_destino.scheme.lower() in ("http", "https")
                and partes_destino.hostname
                and destino not in destinos
            ):
                destinos.append(destino)

    except ValueError:
        pass

    return destinos

