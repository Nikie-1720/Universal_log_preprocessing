# ULPF React Frontend — Architecture

The React console is intentionally a presentation layer over the existing deterministic ULPF API.

```text
React/Vite console
   │
   ├── /api/normalize ───────────┐
   ├── /api/events                │
   ├── /api/events/:id/lineage    ├──> ULPF Python pipeline
   ├── /api/plugins               │       ├─ detection
   ├── /api/stats                 │       ├─ parsing
   └── /api/normalize-system ────┘       ├─ normalization
                                          ├─ validation
                                          └─ trace/sha256
```

## UI implementation

- React component state controls samples, theme, events, search and forensic drawer.
- Framer Motion animates event cards and the forensic drawer.
- Lucide React provides consistent operator/security icons.
- Recharts provides the throughput visualization.
- CSS variables implement both dark and light themes.
- Vite proxies `/api` to the ULPF backend during development.

## Forensic click path

`EventCard` flattens the ULPF `ues` object into clickable fields.

When a field is clicked:

```text
GET /api/events/{trace_id}/lineage
```

The drawer resolves the selected lineage item and shows:

- normalized field/value
- original field
- mapping rule
- extraction information
- confidence
- parser version
- raw evidence
- SHA-256 prefix

The frontend does not fabricate lineage; it reads it from the ULPF pipeline response.

## Why React instead of putting all UI logic in Python?

The Python service remains small and air-gap friendly. React provides the richer interactive operator experience while keeping the processing engine independent of the UI technology.

This separation also lets a future SIEM/data-lake integration consume the same API without depending on the browser.
