# ThreatIntel Pro Architecture

## System Pattern

The project is being migrated to a Clean Architecture / DDD-lite structure.
Legacy modules remain available while features are moved into the new layers.

## Backend Layers

- `app/api`: FastAPI delivery layer. Routes, dependencies and middleware only.
- `app/core`: cross-cutting concerns such as config, database sessions, security, logging and exceptions.
- `app/domain`: business entities, repository contracts and domain services.
- `app/use_cases`: application orchestration. Use cases coordinate domain services, repositories and external services.
- `app/infrastructure`: concrete adapters for database, external APIs and workers.
- `app/schemas`: API DTOs and response contracts.
- `app/routers`: legacy route modules kept for compatibility during migration.
- `core`: legacy service modules kept behind infrastructure wrappers.

## Request Flow

HTTP request -> API route -> dependency injection -> use case -> domain service/repository contract -> infrastructure repository -> PostgreSQL.

## Migration Rule

New features should not add business logic to routers. Add a use case, a repository contract, an infrastructure implementation and a schema. Legacy routes may call the new use case until all routes are moved to `app/api/routes/v1`.

## Database Strategy

The project now has Alembic scaffolding. Existing SQLModel tables remain active for compatibility. New persistence should prefer explicit SQLAlchemy models under `app/infrastructure/database/models` and Alembic migrations.

## Frontend Structure

- `src/api`: Axios client and interceptors.
- `src/services`: backend API services.
- `src/features`: feature-specific hooks and components.
- `src/routes`: route composition and protected routes.
- `src/layouts`: app shell layout.
- `src/components/ui`: reusable presentational primitives.
- `src/components/shared`: reusable domain-aware components.

## Compatibility

Legacy imports such as `frontend/src/api.js`, `core/engine.py`, `core/session.py` and `app/dependencies.py` remain as shims to avoid a breaking migration.
