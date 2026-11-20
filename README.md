# Proyecto de criptografía RSA · MM2015

Aplicación de escritorio en Python con interfaz gráfica para encriptar y desencriptar mensajes de texto mediante RSA. Implementa la aritmética solicitada sin usar `math.gcd`, `pow` con módulo ni bibliotecas criptográficas.

## Autor

- Carlos Altán (`carlosaltan18`)

Si la entrega se presenta en pareja, agregue aquí el nombre y carné del segundo integrante antes de enviarla.

## Versión y dependencias

- Desarrollado y probado con **Python 3.14.0** y **Tk 8.6**.
- El código es compatible con Python 3.10 o posterior.
- Usa únicamente módulos de la biblioteca estándar: `dataclasses`, `tkinter` y `unittest`.

No se incluye `requirements.txt` porque no hay paquetes externos que instalar. Esta decisión sigue la indicación del enunciado para proyectos que usan solo la biblioteca estándar.

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
  - `modular_power`: exponenciación por cuadrados sucesivos con reducción módulo `n` durante el cálculo.
  - `modular_power_trace`: registra los pasos mostrados en la interfaz.
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
- Cada bloque de `C` debe tener exactamente seis dígitos ASCII y cumplir `0 ≤ c < n`.
- Con `k > 0` bloques, `L` debe ser `2k` o `2k - 1`.
- Cada bloque recuperado debe producir dos códigos ASCII válidos.
- Si `L` es impar, el último carácter recuperado debe ser el espacio de relleno.

Los errores se presentan mediante mensajes comprensibles y se limpia cualquier resultado anterior para evitar que parezca válido.

## Pruebas

Ejecute:

```powershell
py -m unittest discover -v
```

Las pruebas cubren el ejemplo oficial, mensajes pares e impares, texto vacío, mayúsculas y minúsculas, números, símbolos, espacios consecutivos, iniciales y finales, ceros iniciales en `C`, parámetros inválidos, bloques mal formados, valores fuera de rango, longitudes incoherentes, ASCII inválido y relleno incorrecto.

## Entregables

- Código fuente completo e interfaz: incluidos en este repositorio.
- Dependencias: no se requieren paquetes externos.
- Documento de lectura rápida: este README.
- Video demostrativo: pendiente de agregar por el equipo antes de la entrega.

> Los parámetros pequeños exigidos por el curso hacen que esta aplicación sea educativa; no debe usarse para proteger información real.
