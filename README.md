<div align="center">
██████╗ ██╗  ██╗██████╗ ██████╗ ███████╗██████╗ ████████╗
██╔══██╗██║  ██║██╔══██╗██╔══██╗██╔════╝██╔══██╗╚══██╔══╝
██████╔╝███████║██████╔╝██████╔╝█████╗  ██████╔╝   ██║   
██╔═══╝ ██╔══██║██╔═══╝ ██╔══██╗██╔══╝  ██╔══██╗   ██║   
██║     ██║  ██║██║     ██████╔╝███████╗██║  ██║   ██║   
╚═╝     ╚═╝  ╚═╝╚═╝     ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝

Detección de vulnerabilidades en código PHP con IA

Trabajo de Fin de Grado · CFGS ASIR

Mostrar imagen
Mostrar imagen
Mostrar imagen
Mostrar imagen

F1 0.915  ·  92% precisión  ·  Demo en vivo ↗

</div>

▸ Qué es

PHPBERT es un sistema híbrido que detecta vulnerabilidades en código PHP
combinando dos enfoques:


Análisis estático — reglas y patrones que buscan construcciones peligrosas
conocidas (inyección SQL, XSS, inclusión de ficheros, etc.).
Análisis con IA — un modelo CodeBERT afinado que aprende a reconocer
patrones de código vulnerable a partir de miles de ejemplos etiquetados.


Un motor de decisión combina ambos resultados para dar un veredicto final más
fiable que cualquiera de los dos por separado.


▸ Resultados del modelo

┌────────────────────────────────────────────┐
│   MÉTRICA            VALOR                   │
├────────────────────────────────────────────┤
│   F1-Score          0.915                    │
│   Precisión         92%                      │
│   Modelo base       microsoft/codebert-base  │
│   Tarea             clasificación binaria    │
│                     (vulnerable / seguro)    │
└────────────────────────────────────────────┘

Modelo publicado en HuggingFace: R0bl3s/php-vuln-detector


▸ Arquitectura

   ┌──────────────┐     ┌──────────────────┐     ┌─────────────────┐
   │  Código PHP  │ ──▸ │   Preprocesado   │ ──▸ │  Análisis dual  │
   │  (entrada)   │     │  + tokenización  │     │                 │
   └──────────────┘     └──────────────────┘     └────────┬────────┘
                                                          │
                        ┌─────────────────────────────────┴───┐
                        ▼                                      ▼
              ┌──────────────────┐                  ┌──────────────────┐
              │ Análisis estático│                  │ CodeBERT (IA)    │
              │  reglas/patrones │                  │  modelo afinado  │
              └────────┬─────────┘                  └────────┬─────────┘
                       │                                     │
                       └──────────────┬──────────────────────┘
                                      ▼
                          ┌────────────────────────┐
                          │   Motor de decisión    │
                          │  veredicto + registro  │
                          └───────────┬────────────┘
                                      ▼
                          ┌────────────────────────┐
                          │  Resultado + feedback  │
                          │  (mejora incremental)  │
                          └────────────────────────┘


▸ Stack técnico

BACKEND     Python · FastAPI · CodeBERT (transformers) · PyTorch
FRONTEND    HTML · CSS · JavaScript
DATOS       SQLite (local) · Supabase (producción)
DESPLIEGUE  Docker · HuggingFace Spaces
ML          fine-tuning de CodeBERT · aprendizaje incremental por feedback


▸ Estructura del proyecto

php-ai-security-tfg/
├── backend/
│   ├── app/
│   │   ├── routes/         # endpoints API (analyze, auth, feedback)
│   │   ├── services/       # análisis estático, ML, motor de decisión
│   │   ├── models/         # entrenamiento e inferencia del modelo
│   │   ├── db/             # base de datos y autenticación
│   │   └── middleware/     # rate limiting
│   └── requirements.txt
├── frontend/               # interfaz web
├── Dockerfile
└── README.md


▸ Características


Detección de vulnerabilidades PHP con enfoque híbrido (estático + IA)
API REST construida con FastAPI
Interfaz web para analizar código
Sistema de autenticación de usuarios
Rate limiting para proteger la API
Aprendizaje incremental: el modelo mejora con el feedback de los usuarios
Desplegado y funcionando en HuggingFace Spaces



▸ Cómo ejecutarlo

bash# Clonar el repositorio
git clone https://github.com/miguelrobles2002/php-ai-security-tfg
cd php-ai-security-tfg/backend

# Instalar dependencias
pip install -r requirements.txt

# Configurar variables de entorno (.env)
# HF_MODEL_ID=R0bl3s/php-vuln-detector
# HF_TOKEN=tu_token_de_huggingface

# Arrancar el servidor
uvicorn app.main:app --reload


El modelo se descarga automáticamente desde HuggingFace al arrancar.




<div align="center">
// Miguel Robles · Técnico Superior ASIR · Huelva · 2026

Portfolio ↗ · LinkedIn ↗

</div>
