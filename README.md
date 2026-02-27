# Sistema de Firma Digital Multillave

Plataforma criptográfica para la firma digital secuencial de contratos laborales y comerciales remotos mediante múltiples algoritmos de clave pública (ECC, RSA y EdDSA), con verificación de integridad basada en SHA-256.

---

## 📌 Descripción del Proyecto

Este sistema permite la validación y certificación de documentos digitales mediante un esquema de firma multillave, garantizando las propiedades fundamentales de seguridad de la información:

- Integridad
- Autenticidad
- No repudio
- Trazabilidad del proceso de firma

El flujo de firma se realiza de manera secuencial entre distintos roles:

1. Empleado / Proveedor (ECC)
2. Empresa (RSA)
3. Auditor / Notario (EdDSA)

Cada etapa valida la integridad del documento antes de permitir el avance al siguiente nivel.

---

## 🎯 Objetivo

Desarrollar un sistema de firma digital multillave que permita la gestión segura de contratos remotos mediante la aplicación de algoritmos criptográficos de clave pública y funciones hash.

---

## 🏗️ Arquitectura General

El sistema está compuesto por los siguientes módulos principales:

- Generación y verificación de hash (SHA-256)
- Firma digital con ECC
- Firma digital con RSA
- Firma digital con EdDSA
- Gestión de metadatos en formato JSON
- Flujo de estados del contrato
- Interfaz web de usuario

---

## 🔐 Flujo del Proceso de Firma

1. Carga del documento PDF
2. Generación del hash SHA-256
3. Firma del empleado/proveedor (ECC)
4. Verificación de integridad
5. Firma de la empresa (RSA)
6. Verificación de integridad
7. Firma del auditor/notario (EdDSA)
8. Validación final del contrato

---

## 🧪 Tecnologías Utilizadas

- Python
- Librerías criptográficas (cryptography / PyNaCl)
- JSON para metadatos
- Interfaz web (por definir)
- Sistemas Windows y Linux

---

## 📂 Estructura del Proyecto

- src/ → Código fuente principal
- docs/ → Documentación técnica
- tests/ → Pruebas del sistema

- 
---

## ⚠️ Alcance del Proyecto

Este sistema tiene fines académicos y demostrativos. No incluye:

- Integración con PKI oficial
- Certificados digitales de autoridades certificadoras
- Autenticación biométrica
- Dispositivos criptográficos físicos (HSM)

---

## 👥 Equipo de Desarrollo

Proyecto académico — Curso de Criptografía
