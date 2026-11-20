package authmatrix;

import burp.api.montoya.MontoyaApi;
import authmatrix.model.MatrixDB;
import com.google.gson.JsonObject;
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
    private boolean restoreBlocked;

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

    /** Restore before permitting checkpoints, so a parse failure cannot erase the saved session. */
    public JsonObject restore(MatrixDB db) throws IOException {
        restoreBlocked = true;
        IOException failure = null;
        String projectJson = null;
        try { projectJson = api.persistence().extensionData().getString(KEY); }
        catch (RuntimeException ex) { failure = new IOException("Could not read Burp project state.", ex); }
        if (projectJson != null) {
            try {
                JsonObject ui = StateManager.restore(db, projectJson);
                // A project read does not prove that its local recovery copy exists.
                lastSaved = null;
                restoreBlocked = false;
                api.logging().logToOutput("Restored AuthMatrix from Burp project data (" + db.getMessages().size() + " requests).");
                return ui;
            } catch (IOException ex) { failure = ex; }
        }
        try {
            String recoveryJson = Files.readString(recovery, StandardCharsets.UTF_8);
            JsonObject ui = StateManager.restore(db, recoveryJson);
            // Repair the project copy on the next successful checkpoint.
            lastSaved = null;
            restoreBlocked = false;
            api.logging().logToOutput("Restored AuthMatrix from local recovery (" + db.getMessages().size()
                    + " requests): " + recovery);
            return ui;
        } catch (NoSuchFileException absent) {
            // A genuinely missing recovery file is different from an unreadable one.
        } catch (IOException | RuntimeException ex) {
            IOException recoveryFailure = new IOException("Could not restore local recovery: " + recovery, ex);
            if (failure != null) recoveryFailure.addSuppressed(failure);
            failure = recoveryFailure;
        }
        if (failure != null) {
            throw new IOException("Session restore failed. Automatic saving is paused and saved data has been preserved. "
                    + "Use File > Replace matrix or Clear matrix to resume. " + failure.getMessage(), failure);
        }
        restoreBlocked = false;
        api.logging().logToOutput("No saved AuthMatrix session found. Local recovery path: " + recovery);
        return new JsonObject();
    }

    public boolean isRestoreBlocked() { return restoreBlocked; }

    /** Called only after a successful explicit replacement or a confirmed clear. */
    public void resumeAfterExplicitReplacement() {
        restoreBlocked = false;
        lastSaved = null;
    }

    public void save(String json) throws IOException {
        if (restoreBlocked) throw new IOException("Automatic saving is paused because the previous session could not be restored.");
        if (json.equals(lastSaved)) return;
        IOException recoveryFailure = null;
        try {
            Files.createDirectories(recovery.getParent());
            StateManager.writeAtomically(recovery.toFile(), json);
        } catch (IOException | RuntimeException ex) {
            recoveryFailure = new IOException("Could not write local recovery: " + recovery, ex);
        }
        try { api.persistence().extensionData().setString(KEY, json); }
        catch (RuntimeException ex) {
            if (recoveryFailure != null) {
                IOException failure = new IOException("Could not save to Burp project data or local recovery.", ex);
                failure.addSuppressed(recoveryFailure);
                throw failure;
            }
            api.logging().logToOutput("AuthMatrix saved to local session recovery; Burp project save failed: " + ex.getClass().getSimpleName());
        }
        if (recoveryFailure != null) api.logging().logToError("AuthMatrix saved to Burp project data, but local recovery failed: " + recovery);
        lastSaved = json;
    }
}
