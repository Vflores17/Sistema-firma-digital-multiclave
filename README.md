Sistema de Firma Digital Multiclave
Plataforma criptográfica para la firma digital secuencial de contratos laborales y comerciales remotos mediante múltiples algoritmos de clave pública (ECC, RSA y EdDSA), con verificación de integridad basada en SHA-256.

Descripción
Este sistema permite la validación y certificación de documentos digitales mediante un esquema de firma multiclave. Cada firmante utiliza un algoritmo distinto y debe validar la integridad del documento antes de avanzar al siguiente nivel, garantizando así las propiedades fundamentales de seguridad de la información:

Integridad — el documento no ha sido alterado
Autenticidad — cada firma proviene de quien dice ser
No repudio — ningún firmante puede negar su participación
Trazabilidad — se registra cada etapa del proceso

El flujo de firma es secuencial entre tres roles:

Empleado / Proveedor → firma con ECC
Empresa → firma con RSA
Auditor / Notario → firma con EdDSA


Objetivo
Desarrollar un sistema de firma digital multiclave que permita la gestión segura de contratos remotos mediante la aplicación de algoritmos criptográficos de clave pública y funciones hash.

Flujo del Proceso de Firma
Carga del PDF
     ↓
Generación del hash SHA-256
     ↓
Firma del empleado/proveedor (ECC)
     ↓
Verificación de integridad
     ↓
Firma de la empresa (RSA)
     ↓
Verificación de integridad
     ↓
Firma del auditor/notario (EdDSA)
     ↓
Validación final del contrato

Tecnologías Utilizadas
TecnologíaUsoPythonLenguaje principalStreamlitInterfaz webcryptographyAlgoritmos RSA y ECCPyNaClAlgoritmo EdDSA (Ed25519)pypdf / reportlabManejo y generación de PDFsPillow / numpy / scikit-imageProcesamiento de imágenesface-recognitionVerificación biométrica facialqrcodeGeneración de códigos QR para validaciónSQLiteAlmacenamiento de metadatos y registros

Estructura del Proyecto
Sistema-firma-digital-multiclave/
├── src/                  # Código fuente principal
├── keys/                 # Claves generadas automáticamente (no se suben al repo)
├── setup.py              # Verificación e instalación de dependencias
├── .gitignore
└── README.md

La carpeta keys/ y la base de datos se generan automáticamente al ejecutar el sistema por primera vez. No se incluyen en el repositorio.


Instalación y Uso
Requisitos previos

Python 3.10 o superior
pip

Pasos

Clonar el repositorio:

bash   git clone https://github.com/Vflores17/Sistema-firma-digital-multiclave.git
   cd Sistema-firma-digital-multiclave

Instalar las dependencias:

bash   python setup.py

Ejecutar la aplicación:

bash   streamlit run src/main.py

Abrir el navegador en http://localhost:8501


Alcance del Proyecto
Este sistema tiene fines académicos y demostrativos. No incluye:

Integración con una PKI (Infraestructura de Clave Pública) oficial
Certificados digitales emitidos por autoridades certificadoras reconocidas
Dispositivos criptográficos físicos (HSM)


Equipo de Desarrollo
Proyecto académico — Curso de Criptografía
NombreGitHubVflores17@Vflores17Heillyn Madriz Madrigal—@heillynmadriz

📄 Licencia
Este proyecto fue desarrollado con fines académicos. No se otorga licencia de uso comercial.
## 👥 Equipo de Desarrollo

Proyecto académico — Curso de Criptografía
