# Welcome to your Lovable project

This project was built with [Lovable](https://lovable.dev).

## Build with Lovable

Open your project in the [Lovable editor](https://lovable.dev) and keep building.

- **Ship faster**: describe what you want to build and Lovable handles the code.
- **Stay in sync**: connect the project to GitHub and every change made in Lovable is committed straight to your repository.
- **Full ownership**: this code is yours. Push to your repository and your changes sync back into Lovable, ready for your next prompt.

## Development

Prefer working locally? You need Node.js and npm — [install with nvm](https://github.com/nvm-sh/nvm#installing-and-updating).

```sh
git clone <this-repository-url>
cd <repository-name>
npm i
npm run dev
```

## Built with

- TanStack Start
- TypeScript
- React
- Tailwind CSS

## Login Pattern Radar

A browser-based dashboard for exploring login activity, investigating unusual sign-ins, and scanning files for suspicious patterns.

- `src/python/lpr/` — the analysis engine, written in Python (anomaly model, demo data, CSV import/export, file and security-log scanner). It runs in the browser with [Pyodide](https://pyodide.org); nothing is sent to a server.
- `src/components/radar/`, `src/routes/` — the pages (Overview, Activity, Test a login, Scan files).
- `tests/python/` — regression tests, including the LogTriage security-log sample corpus (CC BY 4.0, see `tests/fixtures/security-log-samples/LICENSE`).

Run the Python tests with `python3 -m unittest discover -s tests/python` (or `bun run test:python`).
