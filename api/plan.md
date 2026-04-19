# Beacon API - Development Skeleton Plan

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│  HANDLER LAYER                                           │
│  - Receives HTTP request                                 │
│  - Validates input (schema, types, limits)               │
│  - Calls service layer                                   │
│  - Formats HTTP response                                 │
│  - Handles errors → HTTP status codes                    │
└──────────────────────────────────────────────────────────┘
                            ↓
┌──────────────────────────────────────────────────────────┐
│  SERVICE LAYER                                           │
│  - Business logic (routing rules)                        │
│  - Orchestrates provider calls                           │
│  - No HTTP knowledge (no req/res objects)                │
│  - Returns plain objects                                 │
└──────────────────────────────────────────────────────────┘
                            ↓
┌──────────────────────────────────────────────────────────┐
│  PROVIDER LAYER (Data Layer)                             │
│  - External integrations (LLMs)                          │
│  - Each provider implements same interface               │
│  - Handles API calls, retries, timeouts                  │
│  - Returns normalized response                           │
└──────────────────────────────────────────────────────────┘
```

**Rule:** Each layer only imports from the layer below it.

---

## Directory Structure

```
api/src/
├── index.ts                    # Express app setup
│
├── handlers/
│   └── analyzeHandler.ts       # HTTP concerns for /v1/analyze
│
├── services/
│   └── analyzeService.ts       # Business logic + routing
│
├── providers/
│   ├── types.ts                # Provider interface
│   └── mockProvider.ts         # Mock for development
│
├── middleware/
│   └── validate.ts             # Request schema validation
│
└── types/
    └── api.ts                  # Shared types
```

---

## Layer Responsibilities

### Handler (`handlers/analyzeHandler.ts`)
```
- Extract data from req.body
- Call analyzeService.analyze(data)
- Return res.json(result) or res.status(x).json({error})
```

### Service (`services/analyzeService.ts`)
```
- Receive plain object (not req/res)
- Apply routing rules (score >= 0.85 → external, etc.)
- Call appropriate provider
- Return plain result object
```

### Provider (`providers/*.ts`)
```
- Implement Provider interface
- Make external API call (or mock)
- Return { risk_score, label, action, reason }
```

---

## Implementation Steps

### Step 1: Types
Create shared types for request/response.
- [ ] `src/types/api.ts`

### Step 2: Provider Layer
Define interface and mock implementation.
- [ ] `src/providers/types.ts`
- [ ] `src/providers/mockProvider.ts`

### Step 3: Service Layer
Routing logic, calls provider.
- [ ] `src/services/analyzeService.ts`

### Step 4: Handler Layer
HTTP handling, calls service.
- [ ] `src/handlers/analyzeHandler.ts`
- [ ] `src/middleware/validate.ts`

### Step 5: Wire Up
Register route in Express.
- [ ] Update `src/index.ts`

---

## File Checklist

- [ ] `src/types/api.ts`
- [ ] `src/providers/types.ts`
- [ ] `src/providers/mockProvider.ts`
- [ ] `src/services/analyzeService.ts`
- [ ] `src/handlers/analyzeHandler.ts`
- [ ] `src/middleware/validate.ts`
- [ ] Update `src/index.ts`
