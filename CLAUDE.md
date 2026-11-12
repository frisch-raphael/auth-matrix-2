# Repository guidance

AuthMatrix is a Java 21 Burp Suite extension using the Montoya API. The maintained source, Gradle build and tests are under `auth-matrix-2/`; see [its development guidance](auth-matrix-2/CLAUDE.md).

Build and test: `auth-matrix-2/gradlew.bat -p auth-matrix-2 build` on Windows, or `auth-matrix-2/gradlew -p auth-matrix-2 build` on Unix.

The original Jython application and its screenshots have been removed. Do not reintroduce a Python entry point. Root BApp metadata points to the Java JAR. JSON state documentation is in `JsonState.md`.
