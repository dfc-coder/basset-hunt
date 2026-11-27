# Benchmark comparativo

Mide la detección de Basset frente a Gitleaks 8.30.1 y TruffleHog 3.100.1 (sin verificación remota) sobre el mismo corpus sintético. Es el criterio de aceptación de la versión 1.0.

## Uso

```bash
cargo build --release --locked
python3 bench/run.py /tmp/bench              # escribe report.json y report.md
python3 bench/gate.py /tmp/bench/report.json # exit 0 solo si se cumplen los umbrales
```

`run.py` exige las versiones fijadas de `gitleaks` y `trufflehog` en el `PATH`, o en `--gitleaks` y `--trufflehog`. Si falta alguna, falla sin producir informe. En CI, el job `benchmark` las descarga y verifica su SHA-256.

## Corpus

`generate.py` crea, a partir de una semilla, credenciales aleatorias sin uso real y negativos realistas, y escribe `labels.json`. El corpus incluye:

- archivos de configuración;
- contenido codificado (`base64`, `hex`, `base64>hex`);
- archivos comprimidos (zip, `tar.gz`);
- un repositorio Git con secretos en archivos, mensajes, notas, una rama importada por merge y una resolución de conflicto;
- claves RSA PKCS#1 válidas de 2048 bits y pares sintéticos de credenciales AWS.

El corpus no se versiona: se genera en cada ejecución. Los valores solo se guardan en archivos temporales del benchmark para comprobar que Basset no los imprime; no se incluyen en el informe.

Un hallazgo cuenta si coincide con la ruta y la línea etiquetadas. Varias reglas sobre el mismo secreto cuentan una sola vez. En los archivos comprimidos basta con que el hallazgo esté dentro del archivo. Todo hallazgo que no coincide con un positivo es un falso positivo. Gitleaks se ejecuta con `--max-archive-depth 3` para compararlo con su mejor configuración.

## Umbrales de la versión 1.0 (`gate.py`)

1. Sensibilidad de Basset en cada familia mayor o igual que la del mejor rival.
2. Precisión global mayor o igual que la de Gitleaks.
3. Tiempo total como máximo el doble que el de Gitleaks.
4. Ningún valor secreto en stdout ni stderr de Basset.

## Línea base v0.1.0

Informe del job `benchmark` de la ejecución [45943494163](https://github.com/dfc-coder/basset-hunt/actions/runs/45943494163), para el commit `d2c4626`, en un runner `ubuntu-latest`. El gate falla en `recall[api-key]`, `recall[token]` y el tiempo.

### Recall by family

| | basset | gitleaks | trufflehog |
|---|---|---|---|
| api-key | 0.9167 | 1.0 | 0.75 |
| db-connection | 1.0 | 0.0 | 0.5 |
| private-key | 1.0 | 1.0 | 1.0 |
| token | 0.7895 | 0.8947 | 0.8947 |

### Recall by category

| | basset | gitleaks | trufflehog |
|---|---|---|---|
| archive | 0.0 | 1.0 | 1.0 |
| encoded | 0.0 | 1.0 | 0.3333 |
| git-file | 1.0 | 1.0 | 1.0 |
| git-message | 0.0 | 0.0 | 1.0 |
| git-notes | 1.0 | 1.0 | 1.0 |
| merge-resolution | 1.0 | 0.0 | 0.0 |
| plain | 1.0 | 0.8571 | 0.8095 |

### Overall

| | precision | recall | false positives | time (s) | peak RSS (MB) |
|---|---|---|---|---|---|
| basset | 1.0 | 0.8846 | 0 | 3.984 | 670 |
| gitleaks | 1.0 | 0.8462 | 0 | 0.565 | 66 |
| trufflehog | 1.0 | 0.7885 | 0 | 2.665 | 207 |

### Missed cases

- **basset**: arc-tar, arc-zip, enc-github, enc-gitlab, enc-stripe, git-message
- **gitleaks**: git-merge-resolution, git-message, pos-mysql-0, pos-mysql-1, pos-mysql-2, pos-postgres-0, pos-postgres-1, pos-postgres-2
- **trufflehog**: enc-gitlab, enc-stripe, git-merge-resolution, pos-azure-0, pos-google-0, pos-google-1, pos-google-2, pos-mysql-0, pos-mysql-1, pos-mysql-2, pos-openai-2

Basset no imprimió ningún valor secreto. Gitleaks (con `--redact`) tampoco. TruffleHog incluyó valores en su salida JSON; el runner no publica sus salidas sin procesar.

## Perfilado de compilación de reglas

Perfil local de la compilación de cada regex de las reglas empaquetadas (987 reglas con patrón), usando `regex` 1.13.2, `RegexBuilder` con el mismo límite de 100 MiB que `secrets_scanner`, compilación `--release` y un asignador que registra el pico de bytes vivos por regla. Se midió en tres pasadas: el total de compilación fue 3,072–3,133 s; las 987 regex compilaron correctamente. Los tiempos absolutos son de esta máquina (Rust 1.99.0, Linux x86_64), no del runner de CI.

| Regla | Compilación | Pico de asignaciones de esa regex |
|---|---:|---:|
| `pypi-upload-token` | 364 ms | 105,8 MB |
| `vault-batch-token` | 87 ms | 25,9 MB |
| `generic-api-key` | 69 ms | 27,0 MB |
| `okta-access-token` | 54 ms | 13,0 MB |
| `sumologic-access-id` | 43 ms | 13,4 MB |
| `cisco-meraki-api-key` | 40 ms | 13,4 MB |
| `privateai-api-token` | 38 ms | 13,4 MB |
| `cohere-api-token` | 35 ms | 13,4 MB |
| `vault-service-token` | 34 ms | 13,3 MB |
| `kingfisher.anthropic.1` | 27 ms | 13,6 MB |

Los tres mayores outliers de memoria/tiempo son `pypi-upload-token`, `vault-batch-token` y `generic-api-key`; después aparece un grupo de reglas de unos 13 MB cada una. El patrón de PyPI admite hasta 1000 caracteres (`[\\w-]{50,1000}`), y el `size_limit` de 100 MiB no impide que compile con un pico ligeramente mayor. Los picos por regla son mediciones aisladas y **no se suman como RSS del proceso**; la cifra acumulada de asignaciones independientes fue 1.198 GB. La medición del proceso Basset completo en CI fue 670 MB RSS. La evidencia apunta a que la compilación eager de regex domina el arranque y justifica probar compilación diferida; no demuestra por sí sola qué optimización dará el mejor resultado.

### Reproducibilidad y limitaciones

Los casos de RSA son claves válidas y los casos AWS contienen access key ID y secret access key sintéticos. Los valores usan aleatoriedad determinista con semilla; no son credenciales reales. Las métricas funcionales son reproducibles; tiempo y memoria dependen del runner. Esta línea base corresponde al corpus de la semilla 1 y versiones fijadas indicadas arriba.
