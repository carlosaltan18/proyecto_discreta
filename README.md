# Proyecto de criptografía RSA · MM2015

Aplicación de escritorio en Python con interfaz Tkinter para encriptar y desencriptar mensajes mediante RSA. El proyecto corresponde al Parcial 3 de Matemática Discreta 1 y conserva exactamente mayúsculas, minúsculas, signos y espacios del mensaje original.

## Autores y entorno

- Carlos Altán: aritmética RSA, validación de llaves, encriptación e interfaz inicial.
- Sergio: desencriptación, validación de `C` y `L`, integración final y pruebas de ida y vuelta.
- Versión usada para la verificación final: Python 3.14.3.
- Versión mínima: Python 3.10 o posterior con Tkinter.

El programa utiliza únicamente la biblioteca estándar de Python. No requiere `requirements.txt` ni dependencias externas.

## Instalación y ejecución

Clone o descargue el repositorio y, desde su carpeta, ejecute:

```powershell
py app.py
```

Si el lanzador `py` no está disponible:

```powershell
python app.py
```

Para ejecutar todas las pruebas automatizadas:

```powershell
py -m unittest discover -v
```

## Uso de la aplicación

### Encriptar

1. Abra la pestaña **Encriptar**.
2. Ingrese los primos distintos `p` y `q`, y el exponente público `e`.
3. Escriba el mensaje `M`. Se admiten caracteres ASCII imprimibles del 32 al 126.
4. Pulse **Encriptar**.
5. Copie `C` y `L` con sus botones independientes o pulse **Pasar a parte 2**.

La interfaz muestra `n`, `φ`, la llave pública `(e, n)`, la longitud original `L`, el relleno, los códigos ASCII y cada transformación `m → c`. Al seleccionar un bloque se muestran los pasos de la exponenciación modular.

### Desencriptar

1. Abra la pestaña **Desencriptar** o use **Pasar a parte 2** tras encriptar.
2. Ingrese los mismos valores `p`, `q` y `e`.
3. Ingrese `C` como bloques de exactamente seis dígitos separados por un único espacio.
4. Ingrese `L` por separado; no forma parte de `C`.
5. Pulse **Desencriptar**.

La pestaña muestra `n`, `φ`, el exponente privado `d`, la llave privada `(d, n)`, `L`, si retiró relleno y el mensaje recuperado. También incluye una fila por bloque con `c`, `m`, los códigos ASCII y la pareja de caracteres, además del cálculo modular `c^d mod n`. La representación `repr(...)` permite comprobar visualmente los espacios iniciales y finales.

## Relleno y conservación de espacios

Cada bloque representa dos caracteres. Si `L` es impar, al encriptar se agrega exactamente un espacio al final para completar la última pareja. Al desencriptar se comprueba que ese último carácter sea un espacio y se retira únicamente ese carácter.

No se usa `strip()` ni `rstrip()`: los espacios originales al inicio, al final y entre palabras se conservan. Por eso `L` debe guardarse y entregarse junto con `C`.

## Ejemplo completo

En **Encriptar**, pulse **Cargar ejemplo** y luego **Encriptar**. Después pulse **Pasar a parte 2** y **Desencriptar**.

| Dato | Valor esperado |
| --- | --- |
| Mensaje `M` | `RSA` |
| `p`, `q`, `e` | `367`, `373`, `17` |
| `n`, `φ` | `136891`, `136152` |
| MCD(`e`, `φ`) | `1` |
| Longitud original `L` | `3` |
| Mensaje con relleno | `"RSA "` |
| Bloques `m` | `082083 065032` |
| Cifrado `C` | `026054 123875` |
| Exponente privado `d` | `8009` |
| Llave privada | `(8009, 136891)` |
| Mensaje recuperado | `RSA` |

El primer bloque cifrado, `026054`, demuestra que los ceros iniciales se conservan.

## Implementación

- `rsa_math.py` contiene `is_prime`, `gcd`, `extended_gcd`, `modular_inverse`, `modular_power`, `modular_power_trace` y `validate_parameters`.
- `rsa_encrypt.py` valida el mensaje, forma parejas ASCII, agrega el relleno cuando corresponde y calcula `c = m^e mod n`.
- `rsa_decrypt.py` valida estrictamente `C` y `L`, obtiene `d`, calcula `m = c^d mod n`, valida los códigos ASCII y retira solo el relleno indicado por `L`.
- `app.py` contiene la interfaz Tkinter, las tablas de bloques, los resúmenes y las trazas de cuadrados sucesivos.
- `tests/` contiene las pruebas unitarias de aritmética, encriptación, desencriptación y validaciones.

El MCD, el inverso modular y la exponenciación modular están implementados manualmente. No se usan `math.gcd`, `pow` con módulo, `pow` para inversos ni bibliotecas criptográficas.

## Comprobaciones realizadas

Las pruebas automatizadas cubren:

- el ejemplo oficial y el valor `d = 8009`;
- mensajes de longitud par e impar;
- mayúsculas, minúsculas, números, símbolos y límites ASCII 032/126;
- espacios iniciales, finales y consecutivos;
- mensaje vacío y bloques cifrados con ceros iniciales;
- parámetros RSA inválidos, primos iguales o no válidos y `n` fuera de rango;
- `e` no coprimo con `φ`;
- bloques `C` mal formados, separadores inválidos y `c ≥ n`;
- `L` inválida o incompatible;
- códigos ASCII recuperados fuera de rango y relleno impar incorrecto.

Los errores se muestran en un diálogo comprensible, no cierran la ventana y limpian el resultado inválido de la operación correspondiente.
