
# Vigenère (clave por defecto: `LD`)

Script  para **cifrar y descifrar** mensajes con el **cifrado de Vigenère**.

## Requisitos

- Python 3.9+ (no requiere dependencias externas).

## Instalación

Descarga `vigenere_ld.py` y marca como ejecutable (opcional en Linux/Mac):

```bash
chmod +x vigenere_ld.py
```

## Detalles de implementación

- Alfabeto: **A–Z** (26 letras).
- Se conservan **mayúsculas/minúsculas**, espacios y signos.
- Soporte de acentos y `ñ`: se **normalizan** a su base ASCII para operar
  (á→a, ñ→n), sin alterar los demás caracteres.

## Uso

**Cifrar** (clave `LD`):

```bash
python vigenere_ld.py -m encrypt -k LD "INFORMACION"
# → TQQRCPLFTRY
```

**Descifrar**:

```bash
python vigenere_ld.py -m decrypt -k LD "TQQRCPLFTRY"
# → INFORMACION
```

**Ejemplo con la clave `DATOS` y mensaje `DIPLOMADO`:**

```bash
python vigenere_ld.py -m encrypt -k DATOS "DIPLOMADO"
# → GIIZGPAWC
```

  ---

# Cifrado/Descifrado Asimétrico de Archivos (RSA-OAEP + AES-256-GCM)

Este proyecto implementa un esquema **híbrido** de cifrado de archivos:

- **RSA-OAEP (SHA-256):** usado para envolver una clave de sesión AES-256.  
- **AES-256-GCM:** usado para cifrar el contenido del archivo en *streaming* (bloques), proporcionando **confidencialidad e integridad autenticada**.
- **RSA (Rivest-Shamir-Adleman)** - **OAEP (Optimal Asymmetric Encryption Padding)** **SHA-256**
- **AES (Advanced Encryption Standard)**-**GCM(Galois/Counter Mode)**
### Formato del Archivo `.enc` (v2)

El archivo `.enc` versión 2 sigue una estructura precisa, permitiendo la validación y el descifrado seguro de su contenido. Cada campo está definido por una longitud y un propósito específico.

---

#### Estructura de los Datos

| Nombre              | Tamaño (Bytes) | Descripción                                                                |
|---------------------|----------------|----------------------------------------------------------------------------|
| **MAGIC** | 8              | Firma de archivo `'HACv1\x00\x00'` para validación.                       |
| **LEN_WRAPPED_KEY** | 4 (BE)         | Longitud de la clave AES-256 envuelta.                                     |
| **WRAPPED_KEY** | Variable       | Clave AES-256 envuelta con RSA-OAEP.                                       |
| **NONCE** | 12             | Vector de inicialización único para GCM.                                   |
| **SUFFIX_LEN** | 2 (BE)         | Longitud de la extensión original del archivo.                             |
| **SUFFIX** | Variable       | Extensión del archivo original (ej. `.pdf`, `.tar.gz`), en UTF-8.          |
| **TAG** | 16             | Etiqueta de autenticación e integridad generada por GCM.                   |
| **CIPHERTEXT** | Variable       | Datos del archivo original cifrados por bloques.                           |


Soporta **cualquier tipo de archivo** (texto, binario, PDF, imágenes, etc.) y tamaños grandes gracias al procesamiento por bloques.

## Requisitos

- Python 3.9 o superior  
- Librería [cryptography](https://cryptography.io/en/latest/)  

## Instalación  

Instalar la librería cryptography

```bash
pip install cryptography
```

Descarga `hybrid_asym_crypto.py` y marca como ejecutable (opcional en Linux/Mac):

```bash
chmod +x hybrid_asym_crypto.py
```

## Detalles de implementación

- **Esquema híbrido moderno:** RSA-OAEP + AES-256-GCM.  
- **Streaming:** procesa bloques de 64 KiB.  
- **Escritura atómica:** genera primero `*.part` y lo reemplaza solo si finaliza correctamente.  
- **Integridad garantizada:** si el TAG de GCM no coincide, el descifrado falla.  
- **Borrado siempre activo:**
  - Al **cifrar**, se borra automáticamente el archivo original.  
  - Al **descifrar**, se borra automáticamente el archivo `.enc`.  

## Uso

### 1. Generar llaves
Genera un par de llaves RSA (privada y pública).  
```bash
python hybrid_asym_crypto.py gen-keys --out-dir keys/ --bits 4096
# crea keys/private.pem y keys/public.pem
```

### 2. Cifrar un archivo
Cifra el archivo con la llave pública:  
```bash
python hybrid_asym_crypto.py encrypt --in ejemplo.pdf --pub keys/public.pem
```

Resultado:
- `ejemplo.pdf` → `ejemplo.enc`  
- El archivo **ejemplo.pdf se elimina automáticamente**  

### 3. Descifrar un archivo
Descifra el `.enc` usando la llave privada:  
```bash
python hybrid_asym_crypto.py decrypt --in ejemplo.enc --priv keys/private.pem
```

Resultado:
- `ejemplo.enc` → `ejemplo.pdf` (extensión restaurada del header)  
- El archivo **ejemplo.enc se elimina automáticamente**  
