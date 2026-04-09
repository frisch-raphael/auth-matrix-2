# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

AuthMatrix v2 is a Burp Suite extension for testing authorization in web applications. It lets testers define matrices of users, roles, and requests, then runs all combinations and color-codes results to surface authorization vulnerabilities. This is a Java rewrite of the original Jython-based AuthMatrix using the Montoya API.

## Runtime Environment

- **Language:** Java 21
- **Framework:** Burp Suite Montoya API (2025.12)
- **UI:** Java Swing (JTable, JSplitPane, etc.)
- **Build System:** Gradle with Kotlin DSL
- **Dependencies:** Montoya API (compile-only), Gson (bundled in JAR)

## Key Development Commands

```bash
./gradlew build    # Build and test the extension
./gradlew jar      # Create the extension JAR file (build/libs/)
./gradlew clean    # Clean build artifacts
```

## Architecture

```
authmatrix/
  Extension.java           - BurpExtension entry point, context menu provider
  RunEngine.java           - Request execution, cookie/header substitution, result evaluation
  StateManager.java        - JSON save/load (Gson-based)
  model/
    MatrixDB.java          - Central data store, CRUD operations, thread-safe with ReentrantLock
    UserEntry.java         - User: name, cookies, headers, role assignments
    RoleEntry.java         - Role: name + singleUser flag
    MessageEntry.java      - Request entry: HTTP data, authorized roles, run results
  ui/
    AuthMatrixTab.java     - Main UI panel: tables, buttons, popups, request/response viewers
    UserTableModel.java    - User table: Name, Cookies, Headers..., Roles (checkboxes)
    MessageTableModel.java - Message table: ID, Name, Regex, Roles (color-coded checkboxes)
    Renderers.java         - Cell renderers for color coding (green/red/blue) and disabled state
    RowTransferHandler.java - Drag-and-drop row reordering
```

### Key Design Decisions (vs. original v1)

- **No soft-delete**: Items are removed from lists directly (no deleted counts or index tracking)
- **Object references as map keys**: Roles/users referenced by identity, not by integer index
- **No chains**: Chain/CSRF-token/auth-automation features were deliberately excluded
- **Montoya API**: Uses immutable `HttpRequest` with `with*` methods for header manipulation
- **Proper ActionListener classes**: Always use named classes (not lambdas passed to `addActionListener`) to avoid Jython-style double-firing issues — though in Java this is less of a concern, we follow the pattern for consistency

### Color Coding Logic

- **Green**: Role result matches expectations (authorized roles succeed, unauthorized roles fail)
- **Red**: Vulnerability — unauthorized role succeeded (or authorized role failed in failure mode)
- **Blue**: Likely false positive — authorized role failed (bad token / expired session)
- **Gray**: Disabled request or user
- **Purple**: Failure regex mode indicator on the regex column

## Extension Loading in Burp

1. Build the JAR: `./gradlew jar`
2. In Burp: Extensions > Installed > Add > Select JAR from `build/libs/`
3. Service loader file at `META-INF/services/burp.api.montoya.BurpExtension` points to `authmatrix.Extension`
