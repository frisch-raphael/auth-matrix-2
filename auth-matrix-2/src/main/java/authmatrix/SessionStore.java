package authmatrix;

import burp.api.montoya.MontoyaApi;
import java.io.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.HexFormat;

/** Project-scoped Burp storage with a local recovery copy for Community/temporary projects. */
public final class SessionStore {
    static final String KEY = "authmatrix.state.v2";
    private final MontoyaApi api;
    private final Path recovery;
    private String lastSaved;

    public SessionStore(MontoyaApi api) {
        this(api, Path.of(System.getProperty("user.home"), ".authmatrix", "sessions"));
    }

    SessionStore(MontoyaApi api, Path directory) {
        this.api = api;
        String name = api.project().name();
        // Montoya exposes no temporary-project flag. Burp's default temporary name and
        // Community projects use a shared recovery slot; named projects use their stable ID.
        String scope = name == null || name.isBlank() || name.equalsIgnoreCase("Temporary Project")
                ? "temporary" : "project:" + api.project().id();
        try {
            String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(scope.getBytes(StandardCharsets.UTF_8)));
            recovery = directory.resolve(hash + ".json");
        } catch (NoSuchAlgorithmException ex) { throw new IllegalStateException(ex); }
    }

    public String load() throws IOException {
        String json = null;
        try { json = api.persistence().extensionData().getString(KEY); }
        catch (RuntimeException ex) { api.logging().logToOutput("Using local AuthMatrix session recovery."); }
        if (json == null && Files.exists(recovery)) json = Files.readString(recovery, StandardCharsets.UTF_8);
        lastSaved = json;
        return json;
    }

    public void save(String json) throws IOException {
        if (json.equals(lastSaved)) return;
        // Write recovery first, so a project-store failure still leaves a complete snapshot.
        Files.createDirectories(recovery.getParent());
        StateManager.writeAtomically(recovery.toFile(), json);
        try { api.persistence().extensionData().setString(KEY, json); }
        catch (RuntimeException ex) { api.logging().logToOutput("AuthMatrix saved to local session recovery."); }
        lastSaved = json;
    }
}
