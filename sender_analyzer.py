# ==========================================
# PHISHGUARD 3.0
# ANÁLISIS DEL REMITENTE
# ==========================================

from email.utils import parseaddr

from marcas import MARCAS
from url_analyzer import es_dominio_oficial


def analizar_remitente(remitente):
    """
    Comprueba si el nombre visible del remitente
    menciona una marca cuyo dominio no coincide
    con la dirección indicada en From.
    """
    hallazgos = []

    # 1. Separar nombre y dirección
    nombre, direccion = parseaddr(remitente)

    if not nombre or not direccion:
        return hallazgos

    # 2. Obtener el dominio del correo
    if "@" not in direccion:
        return hallazgos

    dominio = direccion.rsplit("@", 1)[1].lower().rstrip(".")
    nombre_normalizado = nombre.lower()

    # 3. Comparar con el catálogo de marcas
    for marca, datos in MARCAS.items():

        menciona_marca = (
            marca.lower() in nombre_normalizado
            or any(
                palabra in nombre_normalizado
                for palabra in datos["palabras"]
            )
        )

        if not menciona_marca:
            continue

        dominio_coincide = any(
            es_dominio_oficial(dominio, oficial)
            for oficial in datos["dominios"]
        )

        if not dominio_coincide:
            hallazgos.append({
                "tipo": f"Posible suplantación de remitente: {marca}",
                "detalle": (
                    f"El nombre visible menciona {marca}, "
                    f"pero la dirección {direccion} utiliza "
                    f"el dominio {dominio}, que no coincide "
                    "con los dominios configurados."
                ),
                "coincidencia": direccion,
                "puntos": 35
            })

    return hallazgos
