# Proyecto de criptografía RSA · MM2015

Aplicación en Python con interfaz gráfica para encriptar y desencriptar mensajes de texto mediante RSA. 

## Autores

- Carlos Altán 25772
- Sergio Tepaz 25787

## Versión y dependencias

- Versión de Python recomendada: **3.10 o superior** (con Tkinter, que viene incluido en la instalación estándar).
- Desarrollado y probado con **Python 3.14.0** y **Tk 8.6**.
- Usa únicamente módulos de la biblioteca estándar: `dataclasses`, `sys`, `tkinter` y `unittest`.

## Ejecución

Desde la carpeta del proyecto:

```powershell
py app.py
```

En sistemas donde el lanzador `py` no esté disponible:

```powershell
python app.py
```

## Uso

### Encriptar

1. Abra la pestaña **Encriptar**.
2. Ingrese los primos distintos `p` y `q`, el exponente público `e` y el mensaje `M`.
3. Pulse **Encriptar**.
4. La interfaz muestra `n`, `φ`, la llave pública `(e, n)`, la longitud original `L`, la presencia de relleno, los códigos ASCII, los bloques `m` y el cifrado `C`.
5. Seleccione un bloque para consultar cada paso de la exponenciación modular.

`C` y `L` se muestran por separado y pueden copiarse individualmente. **Pasar a desencriptar** lleva el último resultado válido a la segunda pestaña.

### Desencriptar

1. Abra la pestaña **Desencriptar**.
2. Ingrese `p`, `q`, `e`, el cifrado `C` y su longitud original `L`.
3. `C` debe contener bloques de exactamente seis dígitos separados por un único espacio.
4. Pulse **Desencriptar**.
5. La interfaz muestra `n`, `φ`, el exponente privado `d`, la llave privada `(d, n)`, el mensaje recuperado, los códigos ASCII y los bloques antes y después de la operación.

El mensaje aparece también mediante `repr(...)` en el resumen para que sean visibles los espacios iniciales y finales.

## Ejemplo completo

Los botones **Cargar ejemplo** preparan el caso de referencia del enunciado:

| Dato | Valor esperado |
| --- | --- |
| Mensaje original `M` | `RSA` |
| `p`, `q`, `e` | `367`, `373`, `17` |
| `n`, `φ(n)` | `136891`, `136152` |
| `MCD(e, φ)` | `1` |
| Longitud original `L` | `3` |
| Mensaje con relleno | `RSA ` |
| Bloques del mensaje | `082083 065032` |
| Cifrado `C` | `026054 123875` |
| Exponente privado `d` | `8009` |
| Mensaje recuperado | `RSA` |

## Representación y relleno

- Se aceptan únicamente caracteres ASCII imprimibles con códigos entre 32 y 126.
- Cada carácter se representa con tres dígitos y cada bloque contiene dos caracteres. Por ejemplo, `AB` produce `065066`.
- `L` registra la cantidad de caracteres del mensaje original, incluidos todos sus espacios.
- Si `L` es impar, se agrega exactamente un espacio al final antes de encriptar.
- Al desencriptar se comprueba que ese último carácter sea un espacio y se retira únicamente ese carácter mediante una operación posicional. No se usa `strip()` ni `rstrip()`, por lo que los espacios reales se conservan.

## Implementación matemática

- `rsa_math.py`
  - `is_prime`: comprobación propia de primalidad.
  - `gcd`: algoritmo de Euclides para el máximo común divisor.
  - `extended_gcd` y `modular_inverse`: inverso modular para obtener `d`.
  - `modular_power`: algoritmo recursivo `mpower2` visto en clase (si el exponente es par, `[mpower2(b, n/2, m)]² mod m`; si es impar, `b·[mpower2(b, (n−1)/2, m)]² mod m`), con reducción módulo `n` en cada paso y complejidad O(log n).
  - `modular_power_trace`: registra las llamadas recursivas mostradas en la interfaz.
  - `validate_parameters`: valida `p`, `q`, `e`, `n` y `φ`.
- `rsa_encrypt.py`
  - `encrypt`: valida `M`, agrega relleno cuando corresponde, forma parejas ASCII y obtiene `C`.
- `rsa_decrypt.py`
  - `parse_ciphertext`: valida el formato y rango de cada bloque de `C`.
  - `validate_length`: comprueba la coherencia de `L` con la cantidad de bloques.
  - `decrypt`: calcula `d`, recupera los bloques ASCII y reconstruye exactamente `M`.
- `app.py`: interfaz Tkinter para ambas operaciones y sus paneles de detalle.

## Validaciones

- `p`, `q`, `e` y `L` deben ser enteros.
- `p` y `q` deben ser primos distintos.
- `126126 < n = p × q < 1000000`.
- `e > 1` y `MCD(e, φ) = 1`.
- Cada carácter de `M` debe estar entre ASCII 32 y 126.
- `M` y `C` no pueden estar vacíos (el enunciado define `L` solo para `k > 0` bloques).
- Cada bloque de `C` debe tener exactamente seis dígitos ASCII y cumplir `0 ≤ c < n`.
- Con `k > 0` bloques, `L` debe ser `2k` o `2k - 1`.
- Cada bloque recuperado debe producir dos códigos ASCII válidos.
- Si `L` es impar, el último carácter recuperado debe ser el espacio de relleno.

Los errores se presentan mediante mensajes comprensibles y se limpia cualquier resultado anterior para evitar que parezca válido.
