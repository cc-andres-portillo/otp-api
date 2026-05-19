# Project Review - Revision Tecnica

## Que es

API de autenticacion de dos factores (2FA) basada en TOTP (RFC 6238) con codigos de
recuperacion como mecanismo de respaldo. Modulo `github.com/cc-andres-portillo/otp-api`.
Expone endpoints HTTP para configurar, activar, verificar y desactivar 2FA sobre cuentas
de usuario persistidas en MongoDB.

El repositorio contiene **dos implementaciones independientes y no intercambiables** del
mismo conjunto de funcionalidades:

- `cmd/api`: implementacion actual, arquitectura hexagonal. Es donde va el trabajo nuevo.
- `cmd/legacy`: implementacion vieja, procedural, con acceso directo a MongoDB.

No comparten datos: `cmd/api` usa la coleccion `account_security` y `cmd/legacy` usa
`otp_secrets` (esquemas distintos). Un usuario configurado por una no es visible para la otra.

## Arquitectura

`cmd/api` sigue Ports & Adapters (hexagonal). Las dependencias apuntan hacia adentro: la
logica de negocio solo conoce interfaces (`ports`), nunca MongoDB ni la libreria OTP.

```
            ┌──────────────────────────────────────────────┐
            │                INFRAESTRUCTURA                │
            │  Handlers HTTP            Repositorio Mongo    │
            │  Adaptador OTP            (cmd/api/handlers,    │
            │  (internal/.../lib)        .../mongocc)         │
            │        │                        │              │
            │   ─────┼──── PUERTOS (interfaces) ┼─────         │
            │        ▼                        ▼              │
            │            APPLICATION (casos de uso)          │
            │                  DOMAIN (entidades)            │
            └──────────────────────────────────────────────┘
```

El cableado de dependencias es manual en `cmd/api/main.go` (sin framework de inyeccion ni
router): se construye adaptador, repositorio, aplicacion y handler, y se registran rutas
sobre el `ServeMux` estandar con patrones por metodo (Go 1.22+). No hay middleware.

## Stack tecnico

| Componente | Tecnologia |
|---|---|
| Lenguaje | Go 1.24 |
| Base de datos | MongoDB (driver `go.mongodb.org/mongo-driver` v1.17.4) |
| TOTP / OTP | `github.com/pquerna/otp` v1.5.0 |
| QR | `github.com/skip2/go-qrcode` + `image/png` estandar |
| IDs | `github.com/google/uuid` v1.6.0 |
| HTTP | `net/http` estandar (sin framework) |
| Tests | paquete `testing` estandar (`testify` es dependencia indirecta, no usada) |

## Estructura del proyecto

```
cmd/
  api/                      # Implementacion actual (hexagonal)
    main.go                 # Wiring + rutas, conexion Mongo hardcodeada
    cookies.go              # Helpers de cookie segura (NO usados)
    handlers/account_security/
      handler.go            # Struct del handler + writeJSON/writeError
      *.handler.go          # Un archivo por endpoint
  legacy/
    main.go                 # Implementacion vieja, rutas legacy
internal/
  core/account_security/    # Dominio 2FA
    domain.go               # Entidades
    ports/                  # Interfaces (application, repository, otp.adapter)
    application/            # Casos de uso (un archivo por caso)
    infrastructure/
      lib/                  # Adaptador OTP (otp.adapter.go, otp.disable.adapter.go) + tests
      mongocc/              # Repositorio MongoDB (un archivo por metodo)
  core/user/                # Dominio usuario (misma estructura)
  db/mongo.go               # Conexion Mongo global
  legacy/                   # Handlers, services, models, utils de cmd/legacy
docs/                       # Documentacion (no versionada en git)
```

## Endpoints / API

### cmd/api (actual)

| Metodo | Path | Descripcion |
|---|---|---|
| POST | `/login` | Busca usuario por email y setea cookie de sesion `tk-session` |
| POST | `/2fa/setup` | Genera secreto TOTP + QR (devuelve `secret` y `qr`) |
| POST | `/2fa/activate` | Activa 2FA validando el primer token |
| POST | `/2fa/disable` | Desactiva 2FA y elimina datos OTP |
| POST | `/recovery-codes/generate` | Genera nuevos codigos de recuperacion |
| POST | `/recovery-codes/use` | Consume un codigo de recuperacion |

### cmd/legacy (viejo)

| Metodo | Path | Descripcion |
|---|---|---|
| POST | `/2fa/setup` | Genera secreto + recovery codes (busca por email o username) |
| POST | `/2fa/verify` | Verifica token; activa 2FA si aun no estaba |
| POST | `/2fa/recovery-codes` | Devuelve los codigos de recuperacion |
| POST | `/2fa/generate-recovery-codes` | Regenera codigos de recuperacion |
| POST | `/2fa/validate-recovery-code` | Valida y consume un codigo |
| POST | `/2fa/disable` | Desactiva 2FA |

Ambas implementaciones escuchan en `:8080` (no pueden correr a la vez).

## Autenticacion y autorizacion

- **Sesion**: el endpoint `/login` (cmd/api) guarda el `userId` crudo en la cookie
  `tk-session` (`HttpOnly`, sin firmar, sin cifrar).
- **Sin middleware**: no existe guardia de autenticacion. Rutas descritas como
  protegidas en la documentacion conceptual no estan realmente protegidas; cada handler
  lee la cookie por su cuenta cuando la necesita.
- **Parametros TOTP**: SHA-1, 6 digitos, periodo 30s, secreto de 20 bytes, Skew 1
  (tolerancia de reloj de +/- 30s, RFC 6238 §5.2). Todos viven en el struct del adaptador
  como unica fuente de verdad, compartidos por generacion y validacion.
- **Errores del adaptador**: sentinels exportados (`ErrOTPKeyGeneration`,
  `ErrQRImageGeneration`, `ErrPNGEncoding`) que envuelven la causa raiz y se pueden
  matchear con `errors.Is`. `New(0)` devuelve un adaptador deshabilitado (null-object).

## Modelos de dominio

### AccountSecurity (`internal/core/account_security/domain.go`)

| Campo | Tipo | Notas |
|---|---|---|
| ID | string | UUID |
| UserID | string | Referencia al usuario |
| Type | string | `otp` o `recoveryCode` |
| OTP | objeto | `Secret`, `Issuer` |
| RecoveryCodes | objeto | `Available[]`, `Used[]` |
| IsRemoved | bool | Soft delete |
| CreatedAt / UpdatedAt | int64 | Unix timestamp |

### User (`internal/core/user/domain.go`)

| Campo | Tipo | Notas |
|---|---|---|
| ID | string | `_id` en coleccion `profile` |
| Email | string | Identificador de login |
| Is2FAEnabled | bool | Flag de 2FA activo |

Colecciones MongoDB: `profile` (usuarios), `account_security` (cmd/api), `otp_secrets`
(cmd/legacy). Base de datos `futurapps`.

## Configuracion

| Variable | Uso | Estado |
|---|---|---|
| `ENV` | `cmd/api/cookies.go` ajusta dominio de cookie si es `production`/`testing` | Leida pero los helpers de cookie no se usan |
| URI MongoDB | `mongodb://root:12345abc@localhost:27017/...` | **Hardcodeada** en ambos `main.go` |
| Nombre DB | `futurapps` | **Hardcodeada** |

No hay carga de configuracion por archivo ni `.env`. No hay `Makefile`, CI ni linter.

## Observaciones y mejoras potenciales

### Urgentes

- **Credenciales en codigo fuente**: usuario/clave de MongoDB hardcodeados en los dos
  `main.go`. Si el repo se filtra, acceso total a la base.
- **Cookie de sesion insegura**: guarda el `userId` en texto plano, sin firmar ni cifrar.
  Cualquiera que conozca o adivine un `userId` puede impersonar al usuario seteando la
  cookie manualmente.
- **Sin guardia de autenticacion**: no hay middleware; endpoints sensibles
  (`/2fa/disable`, `/recovery-codes/generate`) no exigen prueba de identidad fuerte.
- **Secreto TOTP en texto plano** en MongoDB: si la base se compromete, se pueden generar
  tokens validos para cualquier usuario.
- **Sin rate limiting**: la verificacion de tokens y codigos es vulnerable a fuerza bruta.

### Recomendadas

- **Dos implementaciones divergentes**: `cmd/legacy` y `cmd/api` no comparten datos
  (`otp_secrets` vs `account_security`). Definir un plan de migracion y deprecacion del
  legacy para evitar inconsistencias.
- **Cobertura de tests baja**: la unica suite es `otp.adapter_test.go`. Faltan tests de
  aplicacion, repositorio y handlers.
- **Sin proteccion contra replay**: un token valido puede reusarse dentro de su ventana.
- **Codigos de recuperacion sin hashear**: se guardan en claro; conviene hashearlos.
- **`cmd/api/cookies.go`**: helpers `SetSecureCookie`/`ClearSecureCookie` definidos pero
  no cableados; `login.handler.go` setea la cookie inline.
- **Null-adapter (`New(0)`)**: conservado para uso futuro; hoy `New(0)` haria que se
  persista un secreto vacio en silencio. No cablearlo en produccion.
- **`fmt.Println` de debug**: ya removido del flujo de verificacion; mantener vigilancia
  de que no se reintroduzcan fugas de secreto a logs.
- **Logging de auditoria**: sumar registro de eventos sensibles (activar/desactivar 2FA,
  generar recovery codes) con IP y timestamp.

## Desarrollo

```bash
go run ./cmd/api        # API actual (hexagonal) en :8080
go run ./cmd/legacy     # API vieja en :8080 (no correr ambas a la vez)
go build ./...          # Compilar todo
go vet ./...            # Analisis estatico
go test ./internal/core/account_security/infrastructure/lib/...   # Suite del adaptador
```

Requiere una instancia local de MongoDB en `localhost:27017` con credenciales
`root` / `12345abc` y base `futurapps`. No hay hot reload configurado.
