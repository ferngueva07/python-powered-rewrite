<!-- LOVABLE:BEGIN -->
> [!IMPORTANT]
> This project is connected to [Lovable](https://lovable.dev). Avoid rewriting
> published git history — force pushing, or rebasing/amending/squashing commits
> that are already pushed — as it rewrites history on Lovable's side and the
> user will likely lose their project history.
>
> Commits you push to the connected branch sync back to Lovable and show up in
> the editor, so keep the branch in a working state.

## What Lovable manages

Rules outside this block are the project's own. Change the pieces below in
Lovable, not by hand. With the [Lovable MCP](https://mcp.lovable.dev)
connected, `send_message` asks Lovable to do it; otherwise ask the user to
use the editor.

- **Database.** Do not add or edit `supabase/migrations/` or `drizzle/`.
  Ask Lovable to change the schema.
- **Generated files.** Do not edit a file whose header says it is automatically
  generated.
- **AI gateway.** Keep model calls on Lovable's gateway, and keep
  `LOVABLE_API_KEY` out of browser code.
- **Connectors.** Lovable provides native connectors. `list_connectors` shows
  which are enabled; `add_connector` only returns the dashboard link. When a
  connector is enabled, calls go through the connector gateway and need
  `LOVABLE_API_KEY`. When Lovable does not provide one, users can bring their
  own key and store it in Secrets.
- **Secrets.** Lovable manages them. Do not put secret values in the repo.
<!-- LOVABLE:END -->

## Project rules

- Analysis logic (anomaly model, sample data, CSV import/export, file and security-log scanning) lives in Python under `src/python/lpr`; React code only renders and calls it. Why: the owner works in Python.
- Python runs in the browser through Pyodide, loaded by `src/lib/radar/engine.ts`, which bundles `src/python/lpr/**/*.py` as text and calls the JSON functions in `lpr/api.py`. Why: the app has no server and must keep analysis on the device.
- Python code may only use the standard library and numpy, because only packages Pyodide ships can load; change `PYODIDE_VERSION` in `engine.ts` deliberately and re-run the tests. Why: an unavailable package breaks the whole page.
- Reproduce JavaScript semantics with the helpers in `lpr/jsutil.py` (`date_parse`, `iso_string`, `js_round`, `to_fixed`, `js_string`, `R()` for regexes, `mulberry32`) instead of plain Python equivalents. Why: scores, timestamps and wording must stay identical to the original JavaScript app.
- `src/routes/__root.tsx` renders `Workspace` (`src/components/radar/workspace.tsx`), which owns the frame and shared state; route files render page components through `useWorkspace()`. Why: page state (scan results, filters) must survive navigation like the original single-component app.
- Page markup and `src/styles.css` were carried over from the original app; keep `lucide-react` pinned to the original version. Why: screenshots matched the original pixel for pixel and newer icons render differently.
- After changing Python code run `bun run test:python` (unittest, includes the 114-file LogTriage corpus in `tests/fixtures`). Why: these are the original regression tests.
