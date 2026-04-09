# AuthMatrix v2

AuthMatrix v2 is a complete rewrite of [AuthMatrix](https://github.com/SecurityInnovation/AuthMatrix) — a Burp Suite extension for testing authorization in web applications. It lets testers define matrices of users, roles, and requests, then runs all combinations and color-codes results to surface authorization vulnerabilities.

## What changed from AuthMatrix v1

### Platform

| | v1 | v2 |
|---|---|---|
| Language | Jython (Python 2.7) | Java 21 |
| API | Legacy Burp Extender API | Montoya API (2025.12) |
| Build | Single `.py` file, no build step | Gradle, produces a JAR |
| Jython dependency | Required | None |

### Removed features

- **Chains** — The chain mechanism (CSRF token extraction, cross-user resource testing, automated authentication) has been removed. This includes chain sources, static values, and the chain table.
- **Legacy state file loading** — Old serialized Jython state files (pre-v0.6.3) are not supported. JSON state files are still supported with a new v2 format.

### New features

- **Run for a specific role** — Right-click a single role cell to run that request only for users belonging to that role. Only that cell's color is updated; other results are preserved.
- **Bulk toggle role checkboxes** — Select multiple requests, right-click, and check/uncheck a role across all selected rows at once. Mixed state defaults to uncheck.
- **Live color re-evaluation** — Toggling a role checkbox re-evaluates colors immediately using existing run results, instead of clearing all colors.
- **Progress indicator** — A status bar shows `Request 2/5 — User 3/4 (alice)` during runs.
- **Tab highlight** — The AuthMatrix tab flashes orange for 3 seconds when requests are sent from other Burp tabs.
- **Auto-scroll on send** — After sending requests via "Send to AuthMatrix", the table scrolls to the newly added row.
- **Repeater support** — "Send to AuthMatrix" works from Repeater's message editor, not just table-based views.
- **Keyboard shortcut (Ctrl+Shift+M)** — Sends the currently selected request(s) to AuthMatrix from any Burp tab. Works with single and multiple selections.
- **Persistent run results** — Run results and color coding are saved/loaded with the JSON state file, so colors survive a reload.
- **Clean extension unloading** — Background threads and keyboard listeners are properly cleaned up.

### Architecture improvements

- **No soft-delete** — Items are removed from lists directly. No deleted counts, no index tracking, no gaps in arrays.
- **Object references as map keys** — Roles and users are referenced by identity, not by integer index. No more fragile index-based cross-references.
- **Thread safety** — `ReentrantLock` with `lock()`/`unlock()` in try-finally blocks instead of manual `acquire()`/`release()`.
- **EDT safety** — UI updates from background threads are dispatched via `SwingUtilities.invokeLater()`.
- **Self-contained renderers** — Color-coded checkbox renderer extends `JCheckBox` directly and returns `this`, avoiding delegation chain issues.
- **Proper ActionListener classes** — All action listeners are named classes, avoiding Jython's double-firing issue with function-based proxies.

## Installation

1. Build the JAR: `./gradlew jar`
2. In Burp Suite: Extensions > Installed > Add > Select the JAR from `build/libs/`

No Jython installation required.

## Usage

Usage is the same as AuthMatrix v1, minus the chain features:

1. Create roles for all privilege levels (Admin, User, Anonymous, etc.)
2. Create users and assign them to roles via checkboxes
3. Enter session tokens in the Cookies column (or add custom headers via "New Header")
4. Right-click requests in Proxy History, Repeater, or Site Map and select "Send to AuthMatrix" (or press Ctrl+Shift+M)
5. Check the roles authorized for each request
6. Customize the response regex per request
7. Click Run and review the color-coded results

### Color coding

| Color | Meaning |
|---|---|
| Green | Role result matches expectations — no vulnerability detected |
| Red | Unauthorized role succeeded — potential vulnerability |
| Blue | Authorized role failed — likely false positive (bad token / expired session) |
| Gray | Disabled request or user |
| Purple | Failure regex mode indicator on the regex column |

## Building

```bash
./gradlew build    # Build and test
./gradlew jar      # Create the JAR (output in build/libs/)
./gradlew clean    # Clean build artifacts
```
