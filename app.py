#Natalie Soto 
#Y00672748

import json
from datetime import datetime
from pathlib import Path
from seguridad import verificar_clave

RAIZ = Path(__file__).resolve().parent
DATOS = RAIZ / "inventario.json"
USUARIOS = RAIZ / "usuarios.json"
LOG = RAIZ / "auditoria.jsonl"


def cargar_inventario():
    """Carga el inventario controlando errores de archivo ausente o JSON inválido sin sobrescribir."""
    if not DATOS.exists():
        print("Error crítico: El archivo de inventario (inventario.json) no existe.")
        return None
    try:
        contenido = DATOS.read_text(encoding="utf-8")
        return json.loads(contenido)
    except json.JSONDecodeError:
        print("Error crítico: El archivo inventario.json contiene un formato JSON inválido.")
        return None


def guardar_inventario(productos):
    """Guarda la lista de productos en inventario.json."""
    DATOS.write_text(json.dumps(productos, indent=2, ensure_ascii=False), encoding="utf-8")


def registrar_evento(usuario, accion, resultado, **detalles):
    """Registra eventos en auditoria.jsonl en formato JSONL sin incluir datos sensibles."""
    evento = {
        "timestamp": datetime.now().isoformat(),
        "usuario": usuario if usuario else "sin_sesion",
        "accion": accion,
        "resultado": resultado
    }
    evento.update(detalles)
    with LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(evento, ensure_ascii=False) + "\n")


def autenticar(nombre, clave):
    """Autentica al usuario verificando hashes Argon2id y registra intentos exitosos/fallidos."""
    if not USUARIOS.exists():
        print("Error: Archivo de usuarios no encontrado.")
        return None
    
    try:
        usuarios = json.loads(USUARIOS.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        usuarios = []

    for usuario in usuarios:
        if usuario["usuario"] == nombre:
            # Se usa verificar_clave de seguridad.py (evita contraseñas legibles y usa salt)
            if verificar_clave(usuario.get("hash_clave", ""), clave):
                registrar_evento(nombre, "login", "exitoso")
                return {"usuario": nombre, "rol": usuario["rol"]}
            else:
                registrar_evento(nombre, "login", "fallido")
                print("Credenciales incorrectas.")
                return None

    registrar_evento(nombre, "login", "fallido")
    print("Credenciales incorrectas.")
    return None


def consultar_inventario(sesion):
    """Consulta el inventario validando que exista una sesión activa."""
    if not sesion:
        print("Acceso denegado: Debe iniciar sesión para consultar el inventario.")
        registrar_evento("sin_sesion", "consultar", "rechazado_sin_sesion")
        return

    productos = cargar_inventario()
    if productos is None:
        return
    
    print("\n--- INVENTARIO ACTUAL ---")
    for producto in productos:
        print(f"ID: {producto['id']} | Nombre: {producto['nombre']} | Cantidad: {producto['cantidad']}")
    print("-" * 27)
    registrar_evento(sesion["usuario"], "consultar", "exitoso")


def modificar_cantidad(sesion, identificador, entrada):
    """Modifica la cantidad de un producto validando sesión, rol de admin y límites (0 a 1000)."""
    if not sesion:
        print("Acceso denegado: Sesión ausente.")
        registrar_evento("sin_sesion", "modificar", "rechazado_sin_sesion", producto=identificador)
        return False

    if sesion.get("rol") != "admin":
        print("Acceso denegado: Se requiere rol de administrador.")
        registrar_evento(sesion["usuario"], "modificar", "rechazado_por_permisos", producto=identificador)
        return False
    
    try:
        if entrada.strip() == "":
            raise ValueError("Entrada vacía")
        if "." in entrada or "," in entrada:
            raise ValueError("No se permiten valores decimales")
        cantidad = int(entrada)
    except ValueError:
        print("Error: La cantidad debe ser un número entero válido.")
        registrar_evento(sesion["usuario"], "modificar", "rechazado_entrada_invalida", producto=identificador, entrada_recibida=entrada)
        return False

    if not (0 <= cantidad <= 1000):
        print("Error: La cantidad debe estar entre 0 y 1000 inclusive.")
        registrar_evento(sesion["usuario"], "modificar", "rechazado_fuera_de_rango", producto=identificador, cantidad_intentada=cantidad)
        return False

    productos = cargar_inventario()
    if productos is None:
        return False

    for producto in productos:
        if producto["id"] == identificador:
            anterior = producto["cantidad"]
            producto["cantidad"] = cantidad
            guardar_inventario(productos)
            registrar_evento(
                sesion["usuario"], "modificar", "exitoso",
                producto=identificador, anterior=anterior, nueva=cantidad
            )
            print("Cantidad actualizada exitosamente.")
            return True

    print(f"Error: El producto con ID '{identificador}' no existe.")
    registrar_evento(sesion["usuario"], "modificar", "rechazado_producto_no_encontrado", producto=identificador)
    return False


def main():
    print("Inventario académico — VERSIÓN SEGURA CORREGIDA")
    estudiante = input("Escriba su nombre: ")
    print(f"Bienvenido/a, {estudiante}.\n")
    
    sesion = None
    while True:
        if sesion is None:
            nombre = input("Usuario (o 'salir'): ").strip()
            if nombre.lower() == "salir":
                break
            clave = input("Contraseña: ")
            sesion = autenticar(nombre, clave)
            continue
        
        print(f"\n[Sesión activa: {sesion['usuario']} ({sesion['rol']})]")
        print("1. Consultar inventario")
        print("2. Modificar cantidad (Solo Admin)")
        print("3. Cerrar sesión")
        print("0. Salir")
        
        opcion = input("Opción: ").strip()
        if opcion == "1":
            consultar_inventario(sesion)
        elif opcion == "2":
            identificador = input("ID del producto: ").strip()
            entrada = input("Nueva cantidad (0-1000): ").strip()
            modificar_cantidad(sesion, identificador, entrada)
        elif opcion == "3":
            print("Sesión cerrada.")
            sesion = None
        elif opcion == "0":
            print("Saliendo del programa...")
            break
        else:
            print("Opción inválida. Seleccione una opción correcta.")


if __name__ == "__main__":
    main()