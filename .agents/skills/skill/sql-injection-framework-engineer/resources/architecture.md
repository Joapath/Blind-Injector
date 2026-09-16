# Blind-Injector Architecture Guidelines

## Project Overview

Blind-Injector is a modular SQL Injection research framework designed to automate SQL Injection detection and data extraction techniques.

The project must be developed as an extensible security framework, not as a single-purpose script.

Future extensions should allow:

- New SQL Injection techniques.
- New database engines.
- New detection strategies.
- New extraction algorithms.
- New transport layers.

---

# Architectural Principles

Always prioritize:

- High cohesion.
- Low coupling.
- Single Responsibility Principle.
- Dependency inversion.
- Explicit contracts.
- Testability.
- Extensibility.

Avoid quick implementations that create technical debt.

---

# Module Responsibilities

## cli/

Responsibility:

Application entry point and user interaction.

Allowed:

- Argument parsing.
- Configuration creation.
- Application startup.

Forbidden:

- SQL Injection logic.
- Payload generation.
- HTTP handling.
- Extraction algorithms.

---

## config/

Responsibility:

Dependency composition and object creation.

Contains:

- Factories.
- Application configuration.
- Dependency wiring.

The config layer decides which implementations are used.

---

## core/

Responsibility:

Application logic and attack orchestration.

Contains:

- Attack engine.
- Extraction workflow.
- Injection strategies.
- Search algorithms.
- Technique abstractions.

The core layer should not know implementation details of HTTP clients.

---

## detection/

Responsibility:

Analyze server responses and classify results.

Examples:

- Text difference detection.
- Response length detection.
- HTTP status detection.
- Error detection.
- Timing detection.

Detection modules receive responses and return decisions.

They must not:

- Build payloads.
- Perform HTTP requests.
- Control extraction flow.

---

## payloads/

Responsibility:

Generate SQL Injection payloads.

Contains:

- Payload builders.
- SQL expressions.
- Database-specific syntax.

Payload generation must be independent from transport and extraction.

Example:

Correct:

Payload Generator
        |
        ↓
HTTP Client

Incorrect:

Payload Generator
        |
        ↓
HTTP Request
        |
        ↓
Response Analysis

---

## models/

Responsibility:

Define domain objects.

Models represent:

- Target.
- HTTP data.
- Injection points.
- Attack configuration.
- Evidence.
- Timing information.

Models should not contain complex business logic.

---

## transport/

Responsibility:

HTTP communication layer.

Handles:

- Requests.
- Cookies.
- Headers.
- Sessions.
- Proxy.
- Timeout.
- Retry logic.
- SSL options.

The transport layer should be reusable independently.

---

## tests/

Every important module must be testable without requiring a real vulnerable target.

Prefer:

- Unit tests.
- Mock responses.
- Deterministic behavior.

---

# Extension Rules

When adding a new SQL Injection technique:

Do not modify existing techniques.

Create:

- New strategy implementation.
- New payload builder if required.
- New tests.

Follow the Open/Closed Principle.

---

# Dependency Direction

Preferred dependency flow:

CLI

↓

Configuration

↓

Core

↓

Domain Models

↓

Infrastructure

Transport and external dependencies should remain at the edges.
