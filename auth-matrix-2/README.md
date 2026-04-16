# AuthMatrix v2

AuthMatrix v2 is a complete rewrite of [AuthMatrix](https://github.com/SecurityInnovation/AuthMatrix) — a Burp Suite extension for testing authorization in web applications. It lets testers define matrices of users, roles, and requests, then runs all combinations and color-codes results to surface authorization vulnerabilities.

## What changed from AuthMatrix v0.8

### Platform

| | v0.8 | v2 |
|---|---|---|
| Language | Jython (Python 2.7) | Java 21 |
| API | Legacy Burp Extender API | Montoya API (2025.12) |
| Build | Single `.py` file, no build step | Gradle, produces a JAR |
| Jython dependency | Required | None |

### Removed features

- **Chains** — The chain mechanism (CSRF token extraction, cross-user resource testing, automated authentication) has been removed. This includes chain sources, static values, and the chain table.
- **Legacy state file loading** — Old serialized Jython state files (pre-v0.6.3) are not supported. JSON state files are still supported with a new v2 format.

### New features

#### Sections
- **Request sections** — Organize requests into named, colored sections. Each section has its own table with a colored header bar.
- **Collapsible sections** — Click the section header arrow to collapse/expand.
- **Drag-and-drop between sections** — Drag single or multiple requests between sections or to root level.
- **"Send to section" from context menu** — Right-click in Proxy History/Repeater to send requests directly into a specific section.
- **Run section** — Right-click a section header or a request within a section to run only that section's requests.
- **Section management** — Rename, delete sections via right-click on the section header.

#### Run improvements
- **Run for a specific role** — Right-click a single role cell to run that request only for users belonging to that role. Only that cell's color is updated; other results are preserved.
- **Progress indicator** — A status bar shows `Request 2/5 — User 3/4 (alice)` during runs.
- **Persistent run results** — Run results and color coding are saved/loaded with the JSON state file, so colors survive a reload.

#### Bulk operations
- **Check all roles / Uncheck all roles** — Select multiple requests, right-click to check or uncheck all roles at once.
- **Per-role bulk toggle** — Check/uncheck a specific role across all selected rows. Both "Check" and "Uncheck" options shown when state is mixed.
- **Bulk select/unselect from column header** — Right-click a role column header to check or uncheck that role for all (or selected) requests.

#### Color & evaluation
- **Live color re-evaluation** — Toggling a role checkbox re-evaluates colors immediately using existing run results, instead of clearing all colors.
- **Consistent bulk colors** — Bulk check/uncheck operations produce the same colors as individual toggles.
- **Checkbox click precision** — Checkboxes only toggle when clicking the checkbox itself, not anywhere on the cell.

#### Sending requests
- **Repeater support** — "Send to AuthMatrix" works from Repeater's message editor, not just table-based views.
- **Keyboard shortcut (Ctrl+Shift+M)** — Sends the currently selected request(s) to AuthMatrix from any Burp tab. Works with single and multiple selections.
- **Tab highlight** — The AuthMatrix tab flashes orange for 3 seconds when requests are sent from other Burp tabs.
- **Auto-scroll on send** — After sending requests, the table scrolls to the newly added row.

#### Role management
- **Rename/delete roles** — Right-click any role column header (in either the user table or request table) to rename or delete a role.

#### Discovery
- **Highlight New Paths** — Toggle button that highlights proxy requests whose path is not already in AuthMatrix. Helps spot untested endpoints during browsing.

#### Other
- **Multi-row drag-and-drop** — Select and drag multiple requests at once to reorder or move between sections.
- **Clean extension unloading** — Background threads and keyboard listeners are properly cleaned up.

### Architecture improvements

- **No soft-delete** — Items are removed from lists directly. No deleted counts, no index tracking, no gaps in arrays.
- **Object references as map keys** — Roles and users are referenced by identity, not by integer index. No more fragile index-based cross-references.
- **Thread safety** — `ReentrantLock` with `lock()`/`unlock()` in try-finally blocks instead of manual `acquire()`/`release()`.
- **EDT safety** — UI updates from background threads are dispatched via `SwingUtilities.invokeLater()`.
- **Multi-table section UI** — Each section is its own JTable with shared column model and synchronized selection, stacked in a single scrollable container with a sticky column header.

## Installation

1. Build the JAR: `./gradlew jar`
2. In Burp Suite: Extensions > Installed > Add > Select the JAR from `build/libs/`

No Jython installation required.

## Usage

1. Create roles for all privilege levels (Admin, User, Anonymous, etc.)
2. Create users and assign them to roles via checkboxes
3. Enter session tokens in the Cookies column (or add custom headers via "New Header")
4. Optionally create sections to organize requests by feature area
5. Right-click requests in Proxy History, Repeater, or Site Map and select "Send to AuthMatrix" (or press Ctrl+Shift+M). You can send directly into a section.
6. Check the roles authorized for each request
7. Customize the response regex per request
8. Click Run and review the color-coded results

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
