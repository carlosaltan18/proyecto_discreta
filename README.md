# Proyecto de criptografía RSA · MM2015

Aplicación de escritorio en Python para encriptar y, tras integrar la segunda parte del equipo, desencriptar mensajes con RSA. La implementación sigue el enunciado de **Matemática Discreta 1, Parcial 3**.

**Estado de esta rama:** parte 1 de `carlosaltan18` terminada. Incluye algoritmos matemáticos, validación de `p`, `q`, `e`, codificación ASCII por parejas, encriptación e interfaz de encriptación. La pestaña de desencriptación contiene las entradas y está pendiente de la parte 2.

## Ejecutar

Se necesita Python 3.10 o posterior con Tkinter. No hay bibliotecas externas.

```powershell
py app.py
```

Si `py` no está disponible, use `python app.py`. Para correr las pruebas:

```powershell
py -m unittest discover -v
```

## Probar la parte 1

En la pestaña **Encriptar**, pulse **Cargar ejemplo** y luego **Encriptar**. El resultado esperado es:

| Dato | Valor |
| --- | --- |
| Mensaje `M` | `RSA` |
| `p`, `q`, `e` | `367`, `373`, `17` |
| `n`, `φ(n)` | `136891`, `136152` |
| Longitud original `L` | `3` |
| Bloques antes de cifrar | `082083 065032` |
| Cifrado `C` | `026054 123875` |

Como `L` es impar, el programa agrega exactamente un espacio final antes de agrupar los caracteres. `C` y `L` aparecen por separado y tienen botones para copiarlos al portapapeles. El botón **Pasar a parte 2** lleva el último cifrado, su longitud y sus parámetros a la pestaña que completará el otro integrante.

En **Bloques y códigos ASCII** se ven las parejas de caracteres, los códigos y los bloques antes y después de cifrar. Al seleccionar una fila, **Cálculo modular** muestra cada paso de los cuadrados sucesivos que produjo ese bloque cifrado.

## Archivos y contrato entre las partes

- `rsa_math.py`: `validate_parameters(p, q, e)` devuelve `RSAParameters` con `p`, `q`, `e`, `n` y `phi`. También implementa `is_prime`, `gcd`, `modular_inverse`, `modular_power` y `modular_power_trace` para explicar el cálculo. Los errores de entrada lanzan `ValidationError`.
- `rsa_encrypt.py`: `encrypt(message, p, q, e)` devuelve `EncryptionResult` con `ciphertext`, `original_length`, `filler_added`, `padded_message`, `blocks` y `parameters`.
- `app.py`: interfaz Tkinter. La segunda parte conectará la pestaña de desencriptación a su módulo de lógica.
- `tests/`: pruebas de los algoritmos y de la encriptación.

La documentación local de distribución del trabajo está en `docs/`. Esa carpeta figura en `.gitignore` por solicitud del equipo y **no forma parte del repositorio ni de la PR**; hay que compartir sus archivos directamente con el segundo integrante.

> Este RSA se implementa con los parámetros pequeños exigidos por el curso y sirve para aprendizaje, no para proteger información real.
