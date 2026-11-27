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

### Reproducibilidad y limitaciones

Los casos de RSA son claves válidas y los casos AWS contienen access key ID y secret access key sintéticos. Los valores usan aleatoriedad determinista con semilla; no son credenciales reales. Las métricas funcionales son reproducibles; tiempo y memoria dependen del runner. Esta línea base corresponde al corpus de la semilla 1 y versiones fijadas indicadas arriba.
