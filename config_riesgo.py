# ==========================================
# PHISHGUARD 2.2
# CONFIGURACIÓN DE PUNTUACIONES
# ==========================================

PUNTUACIONES = {

    # INDICADORES DÉBILES
    "http": 5,
    "url_acortada": 10,
    "punycode": 5,

    # INDICADORES MEDIOS
    "direccion_ip": 20,
    "urgencia": 20,
    "amenaza_suspension": 25,
    "premio": 15,
    "solicitud_pago": 15,

    # INDICADORES FUERTES
    "solicitud_credenciales": 30,
    "suplantacion_marca": 35,
    "imitacion_marca": 35,
    "enlace_html_enganoso": 40
}


# ==========================================
# CLASIFICACIÓN DEL RIESGO
# ==========================================

UMBRALES = {
    "medio": 25,
    "alto": 60
}


def obtener_puntuacion(indicador):
    """
    Devuelve la puntuación configurada
    para un indicador de phishing.
    """

    return PUNTUACIONES.get(indicador, 0)


def clasificar_riesgo(puntuacion):
    """
    Clasifica el nivel de riesgo
    según los umbrales establecidos.
    """

    if puntuacion >= UMBRALES["alto"]:
        return "ALTO"

    elif puntuacion >= UMBRALES["medio"]:
        return "MEDIO"

    return "BAJO"
