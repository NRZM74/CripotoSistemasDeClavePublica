# 🔐 Guía Paso a Paso: Firma Digital con RSA en Python

# 🎯 Objetivo de este script:
# Comprender cómo se crea y verifica una firma digital usando el algoritmo RSA,
# y cómo las funciones hash garantizan la integridad del mensaje.

# 🔧 Paso 1: Preparar el entorno (Asegúrate de haber instalado la biblioteca)
# Abre la terminal en Visual Studio Code (Ctrl + Shift + Ñ o F1 y busca 'Terminal: Create New Terminal')
# Ejecuta el siguiente comando para instalar la biblioteca 'cryptography':
# pip install cryptography

# 📥 Paso 2: Importar las bibliotecas necesarias
# 'rsa' para la generación de claves RSA y el proceso de firma/verificación.
# 'padding' para los esquemas de relleno criptográfico (PSS en este caso).
# 'hashes' para las funciones hash como SHA256.
# 'serialization' para convertir claves a formatos que puedan ser almacenados (no usado directamente en este script pero útil).
# 'default_backend' para usar el backend criptográfico predeterminado de 'cryptography'.
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

print("🚀 Iniciando el proceso de firma digital con RSA...")

# 🔐 Paso 3: Generar un par de claves (pública y privada)
# La clave privada es el secreto; se usa para firmar.
# 'public_exponent=65537' es un valor comúnmente usado para el exponente público en RSA.
# 'key_size=2048' define el tamaño de la clave en bits. 2048 bits es un tamaño seguro recomendado hoy en día.
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
# La clave pública se deriva de la privada y se usa para verificar la firma.
public_key = private_key.public_key()

print("✅ Par de claves RSA (privada y pública) generado con éxito.")

# 🧾 Paso 4: Crear un mensaje original
# El mensaje debe estar en formato de bytes (por eso la 'b' antes de la cadena).
message = b"Este es el mensaje que quiero firmar digitalmente."
print(f"\n📝 Mensaje original: '{message.decode()}'")

# ✍️ Paso 5: Firmar el mensaje con la clave privada
# Solo el poseedor de la clave privada puede crear una firma válida para este mensaje.
# 'padding.PSS': PSS (Probabilistic Signature Scheme) es un esquema de relleno recomendado para firmas RSA,
#                 que añade un elemento aleatorio, aumentando la seguridad.
# 'mgf=padding.MGF1(hashes.SHA256())': MGF1 (Mask Generation Function 1) usa SHA256.
# 'salt_length=padding.PSS.MAX_LENGTH': Usa la longitud máxima de 'salt' para PSS.
# 'hashes.SHA256()': La función hash utilizada para crear la "huella digital" del mensaje antes de firmar.
signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

print(f"✍️ Firma digital creada (primeros 30 bytes para referencia): {signature[:30]}...")

# ✅ Paso 6: Verificar la firma con la clave pública
# Cualquiera que tenga la clave pública puede verificar que la firma es auténtica
# y que corresponde al mensaje original.
# Si la verificación falla, se lanzará una excepción.
try:
    public_key.verify(
        signature,        # La firma que queremos verificar
        message,          # El mensaje ORIGINAL contra el que se verifica la firma
        padding.PSS(      # El mismo esquema de relleno usado para firmar
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()   # La misma función hash usada para firmar
    )
    print("\n✅ Firma verificada con éxito. El mensaje es auténtico y no ha sido alterado.")
except Exception as e:
    print(f"\n❌ ERROR: La firma no es válida. Esto podría indicar que el mensaje fue alterado o que la firma es falsa. Detalles: {e}")

# 🔄 Paso 7 (opcional): Probar manipulación del mensaje
# Este paso demuestra la capacidad de las firmas digitales para detectar cualquier cambio.
message_alterado = b"Este es un mensaje modificado."
print(f"\n--- Intentando verificar la firma con un mensaje ALTERADO: '{message_alterado.decode()}' ---")

try:
    public_key.verify(
        signature,          # Usamos la misma firma (que fue creada para el mensaje original)
        message_alterado,   # Pero ahora intentamos verificarla con el mensaje ALTERADO
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    # Si esta línea se imprime, algo está mal, ya que la verificación debería fallar.
    print("⚠️ ¡Advertencia! La firma ES VÁLIDA para el mensaje alterado. Esto NO debería ocurrir.")
except Exception as e:
    # Esto es el resultado esperado: la verificación falla porque el mensaje ha cambiado.
    print(f"🛑 Alerta: La firma es INVÁLIDA para el mensaje alterado. Esto es lo esperado y demuestra que la firma digital detectó la manipulación.")
    print(f"Error específico: {e}")

print("\n🎉 Proceso de firma y verificación digital con RSA completado.")