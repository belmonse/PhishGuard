
# ==========================================
# PHISHGUARD 3.1
# API LOCAL PARA ANALIZAR CORREOS
# ==========================================

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from detector import analizar_correo


# ==========================================
# CONFIGURACION DE LA API
# ==========================================

app = FastAPI(
    title="PhishGuard API",
    version="3.1.0",
    description="API local para el analisis heuristico de correos."
)


# ==========================================
# RESTRICCION DE ORIGENES WEB
# ==========================================

ORIGENES_PERMITIDOS = {
    "http://127.0.0.1:8000",
    "http://localhost:8000"
}


# ==========================================
# DATOS DEL CORREO
# ==========================================

class CorreoEntrada(BaseModel):
    asunto: str = Field(default="", max_length=1000)
    cuerpo: str = Field(default="", max_length=200000)
    html: str = Field(default="", max_length=200000)
    remitente: str = Field(default="", max_length=1000)


# ==========================================
# ESTADO DE LA API
# ==========================================

@app.get("/estado")
def consultar_estado():
    return {
        "aplicacion": "PhishGuard",
        "version": "3.1.0",
        "estado": "activo"
    }


# ==========================================
# ANALIZAR CORREO
# ==========================================

@app.post("/analizar")
def analizar_correo_api(
    correo: CorreoEntrada,
    request: Request
):
    origen = request.headers.get("origin")

    # Bloquea solicitudes de paginas web
    # que declaran un origen no autorizado.
    if origen is not None and origen not in ORIGENES_PERMITIDOS:
        raise HTTPException(
            status_code=403,
            detail="Origen web no autorizado"
        )

    return analizar_correo(
        asunto=correo.asunto,
        cuerpo=correo.cuerpo,
        html=correo.html,
        remitente=correo.remitente
    )
