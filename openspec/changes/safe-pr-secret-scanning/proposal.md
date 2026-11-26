# Proposal

## Why

El escaneo Git actual analiza el historial completo incluso en cada PR, lo que puede volver a señalar exposiciones antiguas ajenas al cambio. Además, el motor honra por defecto `gitleaks:allow`, permitiendo que contenido analizado oculte silenciosamente un hallazgo. TruffleHog v3.100.1 demuestra un patrón útil para PR —rango explícito base/head y parches—, pero Basset debe preservar su salida sin secretos y sus verificaciones offline.

## What Changes

- **BREAKING:** dejar de honrar marcas inline como `gitleaks:allow` en todos los modos de escaneo; una marca no suprime el hallazgo.
- Añadir escaneo Git de rango con base y head explícitos, procesando líneas añadidas de commits no-merge alcanzables desde head pero no base. Omitir el diff del commit merge, como TruffleHog v3.100.1; los secretos introducidos solo al resolver conflictos en el merge quedan fuera de cobertura. Mantener `basset git` como auditoría del historial completo y `basset staged` sin cambios de semántica.
- Añadir salida SARIF 2.1.0 para el escaneo de rango: URI relativa al repositorio, ubicación de línea, fingerprints que no incorporan ni derivan del valor detectado, y estado de ejecución incompleta cuando el resultado es parcial. Mantener JSONL como salida predeterminada.
- Ejecutar el escaneo por rango en PR de GitHub con permisos mínimos. Si el contexto del evento no permite subir SARIF —por ejemplo, PR de fork—, conservar los resultados como artefacto sin elevar permisos ni ejecutar código no confiable con secretos.
- Actualizar pruebas y `docs/plan-de-actualizacion.md` para fijar la semántica y diferenciar la medición externa de TruffleHog de cualquier código o detector de terceros.

## Capabilities

### New Capabilities
- `git-range-scanning`: analizar cambios añadidos entre dos commits y emitir hallazgos SARIF seguros para el flujo de PR.
- `inline-suppression-policy`: definir que las marcas inline no suprimen hallazgos en ningún modo de escaneo.

### Modified Capabilities

Ninguna. El repositorio aún no tiene specs principales.

## Impact

Afecta `src/git.rs`, la configuración del `Scanner` en `src/main.rs`, el CLI, serialización de hallazgos, `.github/workflows/check.yml`, `tests/e2e.py`, y `docs/plan-de-actualizacion.md`. `secrets_scanner` 0.2.3 ya ofrece salida SARIF y configuración de marcas inline; su fingerprint SARIF sin clave usa un hash del secreto, por lo que no se debe reutilizar sin reemplazar esa parte. No se añade una dependencia ni se contactan proveedores de credenciales. TruffleHog v3.100.1 se usa solo como referencia externa fijada para el diseño y la comparación futura.