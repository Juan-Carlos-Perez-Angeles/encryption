
# Vigenère (clave por defecto: `LD`)

Script educativo para **cifrar y descifrar** mensajes con el **cifrado de Vigenère**.
Incluye **comentarios en todo el código**, documentación y uso por CLI.

## Requisitos
- Python 3.9+ (no requiere dependencias externas).

## Instalación
Descarga `vigenere_ld.py` y marca como ejecutable (opcional en Linux/Mac):

```bash
chmod +x vigenere_ld.py
```

## Uso rápido

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

**Ejemplo con la clave `DATOS` del material:**
```bash
python vigenere_ld.py -m encrypt -k DATOS "DIPLOMADO"
# → GIIZGPAWC
```

## Detalles de implementación
- Alfabeto: **A–Z** (26 letras).
- Se conservan **mayúsculas/minúsculas**, espacios y signos.
- Soporte de acentos y `ñ`: se **normalizan** a su base ASCII para operar
  (á→a, ñ→n), sin alterar los demás caracteres.
- API disponible para importar:
  ```python
  from vigenere_ld import vigenere_encrypt, vigenere_decrypt
  ```

## Pruebas rápidas en Python

```python
>>> from vigenere_ld import vigenere_encrypt, vigenere_decrypt
>>> vigenere_encrypt("INFORMACION", key="LD")
'TQQRCPLFTRY'
>>> vigenere_decrypt("TQQRCPLFTRY", key="LD")
'INFORMACION'
>>> vigenere_encrypt("Diplomado", key="DATOS")
'GIIZGPAWC'
>>> vigenere_decrypt("GIIZGPAWC", key="DATOS")
'DIPLOMADO'
```
