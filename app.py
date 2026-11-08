import streamlit as st
from pathlib import Path
from eml_analyzer import analizar_eml
from detector import analizar_correo
from auth_analyzer import comparar_dominios_autenticacion


# ==========================================
# CONFIGURACIÓN DE STREAMLIT
# ==========================================

st.set_page_config(
    page_title="PhishGuard",
    layout="centered"
)

# ==========================================
# ENCABEZADO DE PHISHGUARD
# ==========================================

from pathlib import Path

logo_path = Path("assets/logo.png")

col_logo, col_titulo = st.columns(
    [1, 4],
    vertical_alignment="center"
)

with col_logo:
    if logo_path.exists():
        st.image(str(logo_path), width=190)

with col_titulo:
    st.title("PhishGuard")

st.write("Detector de posibles intentos de phishing")
st.caption("Versión 3.1.0 — Análisis de texto, URLs, HTML, correos EML y detección de redirecciones sospechosas")

st.divider()


# ==========================================
# PHISHGUARD 3.0
# CARGA DE ARCHIVOS EML
# ==========================================

st.subheader("📂 Importar correo electrónico")

st.write(
    "Selecciona un archivo .eml para visualizar "
    "la información del correo."
)

archivo_eml = st.file_uploader(
    "Seleccionar archivo EML",
    type=["eml"],
    key="archivo_eml"
)

if archivo_eml is not None:

    contenido = archivo_eml.getvalue()

    # Límite inicial de 5 MB.
    if len(contenido) > 5 * 1024 * 1024:
        st.error(
            "El archivo supera el límite de 5 MB."
        )

    else:
        try:
            datos = analizar_eml(contenido)

            st.success(
                "✅ Correo procesado correctamente."
            )

            st.subheader("📋 Información del correo")

            st.write(
                "**Remitente:**",
                datos["remitente"]
            )

            st.write(
                "**Dirección del remitente:**",
                datos["correo_remitente"]
            )

            st.write(
                "**Destinatario:**",
                datos["destinatario"]
            )

            st.write(
                "**Asunto:**",
                datos["asunto"]
            )

            st.write(
                "**Fecha:**",
                datos["fecha"]
            )

            # Mostrar el cuerpo del correo
            with st.expander("📄 Contenido del mensaje"):
                st.text(datos["cuerpo"])

            # Mostrar el código HTML como texto,
            # sin ejecutarlo ni renderizarlo.
            if datos["html"]:
                with st.expander("🌐 Código HTML"):
                    st.code(
                        datos["html"],
                        language="html"
                    )

            
            # ==========================================
            # RESULTADOS DE AUTENTICACIÓN
            # PHISHGUARD 3.0
            # ==========================================

            st.subheader("🔐 Autenticación del correo")

            autenticaciones = datos["autenticacion"]

            if autenticaciones:
        
                for numero, registro in enumerate(
                    autenticaciones,
                    start=1
                ):

                    with st.expander(
                        f"📋 Registro de autenticación {numero}"
                    ):

                        st.write(
                            "**Servidor declarado:**",
                            registro["servidor"]
                        )

                        columna1, columna2, columna3 = (
                            st.columns(3)
                        )
                        
                        with columna1:
                            st.write("**SPF**")
                            st.code(registro["spf"])

                            st.caption("Dominio SPF:")
                            st.write(
                                registro["dominio_spf"]
                                or "No informado"
                            )

                        with columna2:
                            st.write("**DKIM**")
                            st.code(registro["dkim"])

                            st.caption("Dominio DKIM:")
                            st.write(
                                registro["dominio_dkim"]
                                or "No informado"
                            )

                        with columna3:
                            st.write("**DMARC**")
                            st.code(registro["dmarc"])

                            st.caption("Dominio From declarado:")
                            st.write(
                                registro["dominio_from"]
                                or "No informado"
                            )

                        
                        # ==================================
                        # COMPARACIÓN DE DOMINIOS
                        # ==================================

                        comparacion = comparar_dominios_autenticacion(
                            datos["remitente"],
                            registro
                        )

                        st.markdown("**🔎 Comparación de dominios**")

                        st.write(
                            "**Dominio del remitente:**",
                            comparacion["dominio_remitente"]
                            or "No disponible"
                        )

                        def mostrar_coincidencia(valor):
                            if valor is True:
                                return "🔗 Coinciden los dominios"

                            if valor is False:
                                return "⚠️ Dominios diferentes"

                            return "⚪ Sin información suficiente"


                        st.write(
                            "**Dominio SPF:**",
                            mostrar_coincidencia(
                                comparacion["alineacion_spf"]
                            )
                        )

                        st.write(
                            "**Dominio DKIM:**",
                            mostrar_coincidencia(
                                comparacion["alineacion_dkim"]
                            )
                        )

                        
                        st.caption(
                            "Se comparan los dominios declarados "
                            "en el correo. Una coincidencia no "
                            "significa que SPF, DKIM o DMARC hayan "
                            "sido verificados correctamente. "
                            "Esta comparación no modifica "
                            "la puntuación de riesgo."
                        )

            
            # ==========================================
            # ESTADO DE CONFIANZA DE AUTENTICACIÓN
            # ==========================================

            confianza = datos["confianza_autenticacion"]

            if confianza["estado"] == "sin_datos":
                st.info(
                    "ℹ️ No hay resultados de autenticación "
                    "disponibles en los encabezados."
                )

            elif confianza["estado"] == "no_verificado":
                st.warning(
                    "⚠️ Autenticación no verificada: "
                    "los resultados SPF, DKIM y DMARC "
                    "están declarados en el archivo EML, "
                    "pero PhishGuard no ha confirmado "
                    "su procedencia."
                )


            else:
                st.info(
                    "No se encontraron encabezados "
                    "Authentication-Results en este correo."
                )
                    
            # ==========================================
            # ANALIZAR CORREO EML IMPORTADO
            # ==========================================

            st.divider()

            if st.button(
                "🛡️ Analizar correo importado",
                key="analizar_eml",
                type="primary",
                use_container_width=True
            ):

                resultado_eml = analizar_correo(
                    asunto=datos["asunto"],
                    cuerpo=datos["cuerpo"],
                    html=datos["html"],
                    remitente=datos["remitente"]
                )

                puntuacion = resultado_eml["puntuacion"]
                nivel = resultado_eml["nivel"]
                hallazgos = resultado_eml["hallazgos"]

                st.subheader("🔎 Resultado del correo importado")

                col1, col2 = st.columns(2)

                with col1:
                    st.metric(
                        "Puntuación de riesgo",
                        f"{puntuacion}/100"
                    )

                with col2:
                    st.metric(
                        "Señales detectadas",
                        len(hallazgos)
                    )

                st.progress(puntuacion / 100)

                if nivel == "ALTO":
                    st.error("🔴 Riesgo ALTO")

                elif nivel == "MEDIO":
                    st.warning("🟡 Riesgo MEDIO")

                else:
                    st.info(
                        "🔵 **Riesgo BAJO**\n\n"
                        "No se detectaron indicadores sospechosos "
                        "con las reglas actuales. Esto no significa "
                        "que el correo haya sido verificado como seguro."
)

                st.subheader("⚠️ Hallazgos")

                if hallazgos:
                    for hallazgo in hallazgos:
                        with st.expander(
                            f"{hallazgo['tipo']} "
                            f"(+{hallazgo['puntos']} puntos)"
                        ):
                            st.write(hallazgo["detalle"])
                            st.code(
                                hallazgo["coincidencia"],
                                language=None
                            )
                else:
                    st.info(
                        "No se encontraron señales "
                        "con las reglas disponibles."
                    )

                st.caption(
                    "La puntuación es heurística. "
                    "Un riesgo bajo no garantiza "
                    "que el correo sea seguro."
                )

        except (ValueError, TypeError, UnicodeError) as error:
            st.error(
                "No fue posible procesar el archivo EML."
            )

st.divider()

# ==========================================
# FORMULARIO DEL CORREO
# ==========================================

st.subheader("📨 Analizar correo")

asunto = st.text_input(
    "Asunto del correo",
    placeholder="Escribe el asunto..."
)

cuerpo = st.text_area(
    "Contenido del correo",
    height=180,
    placeholder="Pega aquí el mensaje..."
)

# NUEVA FUNCIONALIDAD: ANÁLISIS HTML
with st.expander("🌐 Contenido HTML del correo (opcional)"):

    st.info(
        "Si tienes el código HTML del correo, "
        "puedes pegarlo aquí para identificar "
        "enlaces engañosos."
    )

    html = st.text_area(
        "Código HTML",
        height=180,
        placeholder='<a href="https://ejemplo.com">Enlace</a>'
    )


# ==========================================
# BOTÓN DE ANÁLISIS
# ==========================================

if st.button(
    "🔍 Analizar correo",
    type="primary",
    use_container_width=True
):

    if not asunto.strip() and not cuerpo.strip() and not html.strip():
        st.warning("Ingresa algún contenido para analizar.")

    else:

        resultado = analizar_correo(
            asunto=asunto,
            cuerpo=cuerpo,
            html=html
        )
        puntuacion = resultado["puntuacion"]
        nivel = resultado["nivel"]
        hallazgos = resultado["hallazgos"]

        st.divider()
        st.subheader("📊 Resultado del análisis")

        columna1, columna2 = st.columns(2)

        with columna1:
            st.metric(
                "Puntuación de riesgo",
                f"{puntuacion}/100"
            )

        with columna2:
            st.metric(
                "Señales detectadas",
                len(hallazgos)
            )

        st.progress(puntuacion / 100)

        # ==================================
        # CLASIFICACIÓN DEL RIESGO
        # ==================================


        if nivel == "ALTO":
            st.error(
                "🔴 **Riesgo ALTO**\n\n"
                "Se detectaron indicadores importantes de phishing. "
                "Evita abrir enlaces o entregar información "
                "hasta verificar el correo por un canal oficial."
            )

        elif nivel == "MEDIO":
            st.warning(
                "🟡 **Riesgo MEDIO**\n\n"
                "Se encontraron señales sospechosas. "
                "Revisa cuidadosamente el remitente "
                "y los enlaces antes de interactuar."
            )

        else:
            st.info(
                "🔵 **Riesgo BAJO**\n\n"
                "No se detectaron suficientes indicadores "
                "con las reglas actuales. Esto no significa "
                "que el correo haya sido verificado como seguro."
            )

        # ==================================
        # MOSTRAR HALLAZGOS
        # ==================================

        st.subheader("🔎 Patrones encontrados")

        if hallazgos:

            for hallazgo in hallazgos:

                with st.expander(
                    f"⚠️ {hallazgo['tipo']} "
                    f"(+{hallazgo['puntos']} puntos)"
                ):

                    st.write(hallazgo["detalle"])

                    st.write("**Coincidencia detectada:**")

                    st.code(
                        hallazgo["coincidencia"],
                        language=None
                    )

        else:
            st.info(
                "No se encontraron patrones sospechosos "
                "con las reglas configuradas."
            )

        # ==================================
        # ENLACES EXTRAÍDOS DEL TEXTO
        # ==================================

        if resultado["enlaces"]:

            st.subheader("🔗 Enlaces encontrados")

            for enlace in resultado["enlaces"]:
                st.code(enlace, language=None)

        st.divider()

        st.caption(
            "PhishGuard utiliza reglas heurísticas. "
            "La puntuación no representa una "
            "probabilidad estadística de phishing. "
            "Un resultado bajo no garantiza "
            "que el correo sea seguro."
        )
