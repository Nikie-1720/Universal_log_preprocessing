# ULPF React Console

A React/Vite operator console for the Universal Log Pre-processing Framework.

## Libraries

- React 18 + Vite
- Framer Motion — micro-interactions and forensic drawer animation
- Lucide React — consistent security/operations icons
- Recharts — lightweight event activity visualization

## Development

Start the ULPF API in one terminal:

```bash
docker compose up --build
```

The API/air-gap console is available at `http://localhost:5173`.

Then open a second terminal:

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:3000`.

Vite proxies `/api/*` to `http://localhost:5173`, so the React console talks to the same ULPF engine.

## Production / air-gap packaging

Build the React console on a connected build machine:

```bash
cd frontend
npm install
npm run build
```

Then copy `frontend/dist/*` into the `web/` directory of the ULPF image/package (or configure your deployment to serve `frontend/dist`).

After that, the generated frontend assets are static and can be transported into an air-gapped environment. The ULPF core itself never requires a cloud API.

## Demo path

1. Select FortiGate traffic.
2. Click **Normalize**.
3. Open a normalized event.
4. Click `destination.port`.
5. Show the original field (`dstport`), mapping rule, parser, confidence and SHA-256-linked raw evidence.
6. Run **System logs** to show local log normalization.
