# Inventario Académico – Versión Segura

## Descripción
Sistema de gestión de inventario desarrollado en Python para consola, enfocado en buenas prácticas de seguridad. Incluye:
- Control de acceso basado en roles (RBAC) para perfiles de `admin` y `user`.
- Autenticación segura mediante hash Argon2id (`seguridad.py`).
- Persistencia de datos en formato JSON (`inventario.json`).
- Sistema de auditoría detallado de eventos (`auditoria.jsonl`).
- Manejo robusto de errores críticos y validación de entradas.

---

## Dependencias
* **Python** (versión 3.8 o superior recomendada).
* Librería externa para hashing de contraseñas: `argon2-cffi`.

---

## Instrucciones de Ejecución
1. Clona o descarga este repositorio en tu computadora.
2. Abre tu terminal en la carpeta del proyecto e instala la dependencia de seguridad ejecutando:
   ```bash
   pip install argon2-cffi