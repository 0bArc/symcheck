# IDE hooks

Copy or merge `ide/vscode/tasks.json` into `.vscode/tasks.json`.

- **SymCheck: ci** — run project checks; problem matcher picks `[error]` / `[warning]` lines
- **SymCheck: ci SARIF** — emit SARIF for GitHub Code Scanning / IDE SARIF viewers

CLI:

```bat
symcheck.bat ci --discover
symcheck.bat ci --log link.log --sarif
```
