from html.parser import HTMLParser
from urllib.parse import urlsplit
from config_riesgo import obtener_puntuacion
from url_analyzer import obtener_dominio_registrable


class ExtractorEnlaces(HTMLParser):
    """Extrae enlaces y sus textos visibles desde HTML."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.enlaces = []
        self.href_actual = None
        self.texto_actual = []

    def handle_starttag(self, tag, attrs):
        atributos = dict(attrs)

        if tag.lower() == "a":
            self.href_actual = atributos.get("href")
            self.texto_actual = []

        elif tag.lower() == "img" and self.href_actual is not None:
            texto_alternativo = (
                atributos.get("alt") or ""
            ).strip()

            if texto_alternativo:
                self.texto_actual.append(texto_alternativo)

    def handle_data(self, data):
        if self.href_actual is not None:
            self.texto_actual.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self.href_actual is not None:
            self.enlaces.append({
                "texto": "".join(self.texto_actual).strip(),
                "destino": self.href_actual
            })

            self.href_actual = None
            self.texto_actual = []



def analizar_enlaces_html(html):
    """
    Detecta enlaces HTML cuyo dominio visible
    no coincide con el dominio de destino.
    """

    parser = ExtractorEnlaces()
    parser.feed(html)

    hallazgos = []

    for enlace in parser.enlaces:
        texto = enlace["texto"]
        destino = enlace["destino"]

        # Comparar solo textos que aparentan ser URLs.
        if not texto.lower().startswith(
            ("http://", "https://")
        ):
            continue

        try:
            host_visible = urlsplit(texto).hostname
            host_destino = urlsplit(destino).hostname

            if not host_visible or not host_destino:
                continue

            dominio_visible = obtener_dominio_registrable(
                host_visible
            )

            dominio_destino = obtener_dominio_registrable(
                host_destino
            )

            if (
                dominio_visible
                and dominio_destino
                and dominio_visible != dominio_destino
            ):
                hallazgos.append({
                    "tipo": "Enlace HTML engañoso",
                    "detalle": (
                        f"El enlace muestra {dominio_visible}, "
                        f"pero realmente dirige a {dominio_destino}."
                    ),
                    "coincidencia": destino,
                    "puntos": obtener_puntuacion(
                        "enlace_html_enganoso"
                    )
                })

        except ValueError:
            continue

    return hallazgos

# ==========================================
# PHISHGUARD 3.1
# EXTRAER DESTINOS DE ENLACES HTML
# ==========================================

def extraer_destinos_html(html):
    """
    Extrae los destinos de enlaces HTML,
    incluidos los que funcionan como botones.

    No abre enlaces ni realiza conexiones.
    """

    parser = ExtractorEnlaces()
    parser.feed(html or "")

    enlaces = []
    vistos = set()

    for enlace in parser.enlaces:
        destino = (enlace["destino"] or "").strip()

        if not destino:
            continue

        # Solo conservar enlaces web absolutos.
        partes = urlsplit(destino)

        if partes.scheme.lower() not in ("http", "https"):
            continue

        if not partes.hostname:
            continue

        if destino in vistos:
            continue

        vistos.add(destino)

        enlaces.append({
            "texto": enlace["texto"] or "Enlace sin texto",
            "destino": destino
        })

    return enlaces


