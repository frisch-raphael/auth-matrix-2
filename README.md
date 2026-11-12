# AuthMatrix

A Java 21 Burp Suite extension for testing authorization across users, roles and requests. Uses the Montoya API; no Jython dependency.

Build and test from `auth-matrix-2`:

```powershell
.\gradlew.bat build
```

Load `auth-matrix-2/build/libs/auth-matrix.jar` through Burp's **Extensions > Installed > Add > Java**.

The current implementation and full usage guide are in [auth-matrix-2](auth-matrix-2/README.md). The previous Python implementation has been removed.

- Automatic session recovery restores users, roles, requests, results and UI layout after a Burp restart.
- **File > Merge matrix** adds a saved v2 JSON matrix to current work; **Replace matrix** opens it instead.
- **Add** groups user, role, header and section actions. **Options** contains proxy path highlighting.

See [JSON state format](JsonState.md) for compatibility and merge behavior.
