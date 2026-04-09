# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

AuthMatrix is a Burp Suite extension (v0.8.2) for testing authorization in web applications. It lets testers define matrices of users, roles, and requests, then runs all combinations and color-codes results to surface authorization vulnerabilities. It is distributed via the Burp Suite BApp Store.

## Runtime Environment

- **Language:** Jython (Python 2.7 running on the JVM via Jython 2.7.0+)
- **Framework:** Burp Suite Extender API — imports from `burp` (IBurpExtender, ITab, IMessageEditorController, IContextMenuFactory, IHttpRequestResponse)
- **UI:** Java Swing (JTable, JPanel, JScrollPane, etc.) accessed through Jython
- **Entry point:** `AuthMatrix.py` — the entire extension is a single file (~3200 lines)
- **No build step, no tests, no linter.** The extension is loaded directly by Burp Suite's Extender tab.

## Architecture

The codebase is a single `AuthMatrix.py` file organized into these key classes:

- **`BurpExtender`** (line ~87): Main entry point implementing Burp interfaces. Sets up the UI (three tables + button bar), context menus, popup actions, and the run/thread logic (`runMessagesThread`). Contains deeply nested inner classes for Swing action listeners.
- **`MatrixDB`** (line ~1266): Central data store holding `ArrayList`s of messages, roles, users, and chains. All mutations go through this class. Uses a `threading.Lock` for thread safety. Handles JSON serialization/deserialization for save/load.
- **`MessageEntry`** / **`UserEntry`** / **`RoleEntry`** / **`ChainEntry`**: Domain model classes representing rows in the respective tables.
- **Table models** (`UserTableModel`, `MessageTableModel`, `ChainTableModel`): Swing `AbstractTableModel` subclasses that bridge `MatrixDB` data to the UI tables.
- **Table classes** (`UserTable`, `MessageTable`, `ChainTable`): Custom `JTable` subclasses with renderers and right-click menus.
- **`ModifyMessage`** (line ~1153): Handles HTTP request modification — substituting cookies, headers, and chain values for each user before sending.
- **`RequestResponseStored`**: Implements `IHttpRequestResponse` for caching request/response pairs.
- **`MatrixDBData`** / `*EntryData`: Serialization-friendly data classes used for JSON state save/load.

### Key Concepts

- **Chains**: A mechanism to copy values (static or extracted via regex from responses) between requests. Used for CSRF tokens, cross-user resource IDs, and automated authentication. Chain dependencies affect request execution order.
- **Regex modes**: Each request has either a Success Regex (default) or Failure Regex mode, toggled via right-click. Results are color-coded: green (safe), red (vulnerability), blue (false positive / bad token).
- **State persistence**: Configurations are saved/loaded as JSON files. Structure is documented in `JsonState.md`.

## Development Notes

- To test changes, load `AuthMatrix.py` in Burp Suite via Extender tab > Add > Python type.
- The entire codebase is Jython/Python 2 syntax — no f-strings, no `print()` as function (though `print` works as statement), use `urllib` not `urllib.parse`.
- Swing UI code is verbose due to Jython's Java interop; inner classes are used extensively as event handlers.
- Thread safety: all data mutations should go through `MatrixDB` and respect `self.lock`.
