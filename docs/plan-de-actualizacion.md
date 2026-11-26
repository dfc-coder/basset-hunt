# Plan de actualización de Basset Hunt

**Meta de v0.2.** En un pull request de un repositorio propio, el equipo puede ubicar un secreto de prueba en el archivo y la línea correctos, distinguir una coincidencia de una exposición confirmada y saber cuándo el análisis quedó incompleto. La misma versión permite auditar el historial fuera del pipeline del PR.

## Punto de partida

Basset Hunt es un CLI Rust que analiza archivos, stdin, registros JSONL, el índice de Git y el historial local. Usa `secrets_scanner` 0.2.3 y exige al menos 800 detectores compilados. La salida JSONL ya informa ubicación, línea, detector, estado e inventario; no incluye el texto detectado. La verificación usa huellas HMAC contra un inventario controlado por el propietario y con fecha de observación. El adaptador IAM actualiza estados de claves previamente vinculadas durante su aprovisionamiento.

**M1 está implementado y verificado:** `Cargo.lock` está versionado; `Cargo.toml` declara Rust 1.85 como mínimo; CI compila con `--locked`; Docker copia el lockfile y usa `rust:1.100.0-trixie`. Pasan `cargo build --release --locked`, `cargo test --locked`, `tests/test_iam.py` y `tests/e2e.py`. También se comprobó build y tests con Rust 1.85. La imagen se construyó con Podman y se ejecutó sin red, como usuario sin privilegios y con filesystem de solo lectura. El workflow `Build and audit` terminó correctamente para el commit `7150ce3` en [GitHub Actions](https://github.com/dfc-coder/basset-hunt/actions/runs/45732612852).

El CI actual ejecuta `basset git .` sobre el historial completo en cada push y PR. No existe un modo de escaneo limitado al rango del PR ni salida SARIF. El modo `staged` escanea el índice local, que no representa los cambios del PR en un runner. El campo `location.source` puede ser una ruta absoluta del runner. El informe no lleva versión de esquema ni procedencia explícita de evidencia. Los registros del inventario rechazan campos desconocidos (`deny_unknown_fields`), por lo que añadir metadatos exige definir su compatibilidad.

## Hitos y criterios de aceptación

| Orden | Prioridad | Trabajo | Depende de | Listo cuando |
|---|---|---|---|---|
| 1 · M1 | P0 · cierre | Cerrar la estabilización reproducible ya implementada. | Paquete actual | El workflow de GitHub Actions en `develop` termina correctamente con `cargo build --release --locked`, `cargo test --locked` y ambas suites Python. Verificado para `7150ce3` en [la ejecución de GitHub Actions](https://github.com/dfc-coder/basset-hunt/actions/runs/45732612852); las pruebas locales, Rust 1.85 y la imagen también están verificadas. |
| 2 · M2 | P0 | Aclarar la evidencia y su compatibilidad. Añadir versión de esquema, fuente de evidencia, observación y motivo de indeterminación al informe; distinguir inventario del propietario de consulta administrativa IAM. | M1 y casos sintéticos de regresión | El lector nuevo acepta inventarios v0.1 sin esos campos. La migración documenta que binarios v0.1 rechazan registros con campos desconocidos y evita reemplazar inventarios antes de actualizar los lectores consumidores. La salida atribuye `inventory` o `aws_iam` solo cuando esa procedencia está respaldada; no infiere permisos efectivos a partir del estado activo. Pruebas cubren activo, inactivo, ausente, vencido, futuro, error de AWS y coincidencia no exacta. Una integración real con claves de ensayo se ejecuta solo en un job autorizado con credenciales separadas; un error del proveedor nunca actualiza el inventario como exitoso. |
| 3 · M3 | P0 | Entregar el flujo de PR: escaneo de rango, salida SARIF 2.1.0, rutas relativas al repositorio y estado de ejecución incompleta. Conservar JSONL por defecto para Jenkins y automatizaciones existentes. | M1 y M2 | Un PR de prueba solo reporta versiones tocadas entre base y head, sin volver a bloquearse por secretos antiguos ajenos al PR. GitHub anota el archivo y línea correctos; la alerta se resuelve al corregir la exposición. Los hallazgos del historial completo siguen disponibles en el modo histórico. SARIF incluye fingerprints estables que no revelan el secreto ni un hash directo del valor; los hallazgos sin HMAC conservan una identidad útil usando ruta, detector y contexto no secreto. Un análisis incompleto queda indicado en SARIF (`executionSuccessful=false`) y produce exit 2, incluso si hubo resultados parciales. |
| 4 · M4 | P1 | Medir precisión y cobertura con un corpus local etiquetado; comparar con una versión fijada de TruffleHog y validación remota desactivada. | M1 | Informe reproducible por familia (API keys, tokens, contraseñas de bases de datos, claves privadas multilínea), con positivos, negativos realistas, falsos positivos, omisiones, precisión y sensibilidad. Cada diferencia se rastrea a un caso; el informe registra versiones y separa cantidad de reglas compiladas de tipos probados. Esta comparación no bloquea v0.2. |
| 5 · M5 | P2 | Incorporar fuentes remotas de forma incremental: primero repositorio GitHub explícito y sus issues, PR y comentarios; después S3 limitado a bucket y prefijo. Registrar cobertura por fuente. | v0.2 aceptada | Por conector, dos páginas, una repetida y una interrupción recuperable producen todos los documentos esperados sin duplicados. Una página inaccesible deja constancia de cobertura incompleta y devuelve código 2. |

**Corte de entrega.** Publicar v0.2 cuando M1, M2 y M3 estén completos y se pueda repetir la prueba del PR. M1 ya está cerrado; M4 es medición P1 y no bloquea v0.2; M5 es expansión de fuentes posterior. El próximo paso es diseñar el cambio de M2 para la procedencia y compatibilidad del inventario.

## Qué significa «verificado»

Conservar `--only-verified` y `--results=verified` con su semántica actual durante v0.2: una huella HMAC exacta, con registro de estado activo y observación suficientemente reciente, produce `verified`. Ausencia de coincidencia, evidencia futura o vencida nunca pasa el filtro. La futura procedencia debe separar `inventory` (estado declarado por el propietario) de `aws_iam` (estado respaldado por una consulta administrativa reciente). Si se requiere exigir una fuente concreta, usar un filtro explícito. Los permisos siguen siendo etiquetas declaradas por el propietario, no permisos efectivos comprobados.

Un token sin vínculo conocido permanece como candidato en el modo general; así puede detectarse una filtración nueva aunque no esté en el inventario. La comprobación universal en vivo de cualquier valor y la evaluación automática de permisos efectivos no forman parte de v0.2.

Como extensión posterior, evaluar importar alertas de GitHub Secret Scanning con el valor oculto. Conservar el identificador y la validez comunicada por GitHub. Una coincidencia aproximada de archivo y línea puede relacionar alertas, pero no atribuir el estado de una credencial específica. [API de alertas de GitHub](https://docs.github.com/en/rest/secret-scanning/secret-scanning) · [ListAccessKeys de AWS IAM](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListAccessKeys.html)

## Requisitos de salida y compatibilidad

- JSONL sigue siendo la salida predeterminada y conserva los códigos 0 (sin hallazgos), 1 (hallazgos) y 2 (entrada o análisis incompleto).
- Compartir un modelo de hallazgo entre JSONL y SARIF. Distinguir rutas del checkout, objetos históricos y comentarios remotos; nunca publicar rutas absolutas del runner cuando se espera una ruta de repositorio.
- SARIF, stdout, stderr y artefactos de CI no contienen el valor detectado. No usar hashes simples del secreto como fingerprint, porque valores de baja entropía podrían recuperarse por fuerza bruta.
- Escanear PR de forks sin secretos de CI. No usar `pull_request_target` para ejecutar contenido no confiable. Si el token del PR no puede subir SARIF, conservar el resultado como artefacto o salida descargable, sin elevar permisos. La anotación mediante code scanning se verifica en repositorios donde esa función esté habilitada; documentar la limitación de GitHub Advanced Security para repositorios privados que la requieran.
- Si el escaneo produce resultados parciales y exit 2, el job debe preservar y publicar esa evidencia; el paso de publicación debe ejecutarse aunque falle el escaneo (`if: always()` con comprobación del artefacto existente).
- Probar compatibilidad con inventario v0.1 y con sus consumidores. Cualquier campo nuevo debe tener una regla de versión/compatibilidad definida antes de cambiar el formato emitido.
- La detección del PR debe usar base y head explícitos y evitar notificar exposiciones históricas ajenas al rango. Probar commits múltiples, archivo renombrado, secreto añadido y luego eliminado dentro del PR, archivo borrado y paths con espacios.

## Medición

- Etiquetar los fixtures por familia, archivo y ubicación esperada. Varias reglas que detectan el mismo secreto cuentan como una exposición. Incluir negativos con IDs públicos, hashes, placeholders y ejemplos de documentación.
- Medir por separado archivos preparados para commit y el historial completo. Registrar tamaño del repositorio, número de versiones de archivos, duración, memoria máxima y versión de herramienta. Definir presupuestos de rendimiento después de una primera medición.
- Ejecutar la detección en PR externos sin secretos de CI. Las pruebas con proveedores reales requieren autorización, claves de ensayo y credenciales independientes.

## Backlog posterior

- **M5:** conectores GitHub y S3 descritos arriba. Después priorizar fuentes adicionales —gists/forks seleccionados, Hugging Face y exportaciones de colaboración— según incidentes y costo de mantenimiento.
- **Investigación separada:** cobertura de objetos Git inalcanzables en copias locales bajo custodia del equipo. Documentar clon, retención y recolección de basura antes de prometer cobertura.
- **Contexto de remediación:** añadir entorno junto a responsable, runbook, antigüedad y procedencia de permisos. Medir si reduce el tiempo hasta la rotación.
