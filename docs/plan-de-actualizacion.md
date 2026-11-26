# Plan de actualización de Basset Hunt

**Meta de v0.2.** En un pull request de un repositorio propio, el equipo puede ubicar un secreto de prueba en el archivo y la línea correctos, distinguir una coincidencia de una exposición confirmada y saber cuándo el análisis quedó incompleto. La misma versión también permite auditar el historial fuera del pipeline del PR.

## Punto de partida

El paquete v0.1.0 ya tiene entradas para archivos, stdin, registros JSONL, historial Git e índice de Git. El motor está fijado a secrets_scanner 0.2.3. El CLI exige al menos 800 reglas compiladas. La cantidad de tipos distintos que detecta con precisión sigue sin medirse. La verificación actual usa huellas HMAC y un inventario con fecha. El adaptador de AWS actualiza el estado para claves IAM previamente vinculadas durante su aprovisionamiento.

El proyecto incluye un workflow, un hook, un Jenkinsfile y un Dockerfile. Las pruebas de comandos Git, adaptadores de exportación y respuestas simuladas de IAM pasaron. Quedaron pendientes la compilación de Rust y las pruebas de extremo a extremo. La versión inicial no incluye Cargo.lock y el Dockerfile copia explícitamente los archivos de compilación.

## Hitos y criterios de aceptación

| Orden | Trabajo | Depende de | Listo cuando |
|---|---|---|---|
| 1 · P0 | Estabilizar v0.1. Fijar una versión de Rust comprobada, generar y versionar Cargo.lock, actualizar CI, Dockerfile y .dockerignore para usarlo. | Paquete actual | Un runner limpio ejecuta cargo build --release --locked, cargo test --locked y ambas suites Python. La imagen compila con el mismo lockfile. Un clon superficial devuelve código 2 y un hallazgo en un archivo borrado se ubica en el commit correcto. |
| 2 · P0 | Construir un conjunto de pruebas etiquetadas. Incluir API keys, tokens, contraseñas de base de datos y claves privadas multilínea, junto con ejemplos negativos realistas. Ejecutar Basset Hunt y una versión fijada de TruffleHog contra el mismo contenido local con validación remota desactivada. | 1 | Hay una tabla por familia con verdaderos positivos, falsos positivos, omisiones, precisión y sensibilidad. Cada diferencia se puede rastrear a un caso. El informe indica versiones y separa reglas compiladas de tipos probados. |
| 3 · P0 | Aclarar la evidencia detrás de cada estado. Ampliar el informe con versión de esquema, origen de evidencia, fecha de observación y motivo de indeterminación. Reutilizar el adaptador IAM con una identidad de auditoría independiente y vínculos de aprovisionamiento. | 1; usar los casos del hito 2 | Una prueba de integración autorizada con una clave de ensayo distingue activa e inactiva después de actualizar el inventario. Un error de AWS impide declarar éxito en esa actualización. Ausencia, datos vencidos y detecciones sin coincidencia exacta nunca pasan el filtro de verificados. |
| 4 · P0 | Entregar el flujo de PR. Agregar salida SARIF 2.1.0, usar rutas relativas al repositorio y separar el escaneo del cambio del análisis histórico. Conservar JSONL para Jenkins y automatizaciones existentes. | 1 y 2; incorporar los campos de 3 | En un PR de prueba, GitHub muestra una anotación en una línea modificada. Corregir el secreto resuelve la alerta en el siguiente análisis. El historial sigue informando la exposición pasada. Ninguna salida contiene el valor sintético. |
| 5 · P1 | Incorporar fuentes directas de forma incremental. Primero un repositorio explícito de GitHub y sus issues, PR y comentarios. Después S3 limitado a bucket y prefijo. Aprovechar la entrada de documentos existente y registrar cobertura por fuente. | v0.2 aceptada | Por conector, dos páginas de datos, una repetida y una interrupción recuperable producen todos los documentos esperados sin duplicados en el resultado final. Una página inaccesible deja constancia de cobertura incompleta y devuelve código 2. |

**Corte de entrega.** Publicar v0.2 cuando pasen los hitos 1 a 4 y el equipo pueda repetir la prueba del PR. El hito 5 corresponde a v0.3. El orden prioriza un flujo comprobable antes de ampliar el volumen de fuentes.

## Qué significa «verificado»

Conservar `--only-verified` y `--results=verified` con su semántica actual durante v0.2. Publicar de dónde sale el estado. Un match exacto con inventario reciente puede llevar `evidence.source=inventory`. Una clave IAM vinculada por huella y respaldada por una consulta administrativa reciente puede llevar `evidence.source=aws_iam`. Si se necesita exigir ese respaldo concreto, agregar un filtro explícito por fuente. Los permisos declarados por el propietario deben indicar esa procedencia. El estado activo de una clave no demuestra sus permisos efectivos.

Un token sin vínculo conocido queda como candidato y sigue apareciendo en el informe general. Así, el pipeline de prevención puede bloquear una filtración nueva aun cuando nadie la haya cargado en el inventario. La comprobación en vivo universal de cualquier valor descubierto y el análisis automático de sus permisos efectivos quedan como brechas frente al pedido original.

Como extensión posterior, evaluar importar alertas del repositorio desde GitHub Secret Scanning con el valor oculto. Conservar el identificador y la validez que informa GitHub. Una coincidencia aproximada de archivo y línea sirve para relacionar alertas, pero no alcanza para atribuirle a un hallazgo local el estado de una credencial específica. [API de alertas de GitHub](https://docs.github.com/en/rest/secret-scanning/secret-scanning) · [ListAccessKeys de AWS IAM](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListAccessKeys.html)

## Medición y compatibilidad

- Etiquetar cada caso con familia, archivo y ubicación esperada. Dos reglas que detectan el mismo secreto cuentan como una exposición. Añadir negativos con IDs públicos, hashes, placeholders y ejemplos de documentación.
- Medir por separado el código preparado para commit y un historial completo. Registrar tamaño del repositorio, cantidad de versiones de archivos, tiempo, memoria máxima y versión de la herramienta. Definir los presupuestos de rendimiento después de la primera medición.
- Mantener las invocaciones actuales, JSONL por defecto y los códigos de salida 0, 1 y 2. Un escaneo parcial prevalece sobre un resultado aparentemente limpio. Probar compatibilidad con un inventario generado por v0.1.
- Compartir un modelo de hallazgo entre JSONL y SARIF. Diferenciar una ruta del checkout de un archivo histórico o de un comentario remoto. Adjuntar commit y enlace de origen cuando corresponda.
- Ejecutar detección sobre PR externos sin secretos de CI. Reservar las pruebas de integración con proveedores para un trabajo autorizado con credenciales independientes. Comprobar por pruebas que stdout, stderr, SARIF y artefactos de CI omiten el valor del secreto.

## Backlog posterior

- **v0.3:** GitHub por repositorio y S3 por prefijo. Separar los resultados de código, comentarios y objetos. Reutilizar los adaptadores locales cuando el equipo ya dispone de exportaciones.
- **Siguiente prioridad:** repositorios de una organización mediante una lista administrada, gists y forks propios seleccionados, Hugging Face y exportaciones de colaboración. Priorizar cada fuente según incidentes reales y costo de mantenerla.
- **Investigación separada:** cobertura de objetos Git no alcanzables en copias locales bajo custodia del equipo. Documentar las limitaciones del clon, la retención y el recolector de basura antes de prometer cobertura.
- **Contexto de remediación:** responsable, entorno, runbook de rotación, antigüedad de la evidencia y permisos con procedencia. Medir si estos datos reducen el tiempo desde la alerta hasta la rotación.

## Primer cambio listo para convertir en PR

**Título:** Hacer reproducible la compilación y ejecutar las pruebas de extremo a extremo en CI.

**Archivos:** Cargo.lock, configuración de toolchain, .github/workflows/check.yml, Dockerfile, .dockerignore y las correcciones mínimas que revele la compilación.

**Evidencia de cierre:** registrar versiones, resultado de compilación y pruebas, salida de basset rules y resultado de tres casos sintéticos con códigos 0, 1 y 2. Incluir un archivo eliminado en otra rama y un archivo preparado cuyo contenido difiera del directorio de trabajo. Adjuntar la ejecución del runner que obtuvo esos resultados.

**Referencia funcional:** [repositorio oficial de TruffleHog](https://github.com/trufflesecurity/trufflehog). La comparación de detección se hace sobre el mismo corpus y configuración documentada.
