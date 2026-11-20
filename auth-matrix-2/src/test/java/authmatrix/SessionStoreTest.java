package authmatrix;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.util.*;
import java.io.IOException;
import authmatrix.model.MatrixDB;
import authmatrix.ui.AuthMatrixTab;
import com.google.gson.JsonObject;
import javax.swing.SwingUtilities;
import static org.junit.jupiter.api.Assertions.*;

class SessionStoreTest {
    @TempDir Path directory;
    @Test void readsSnapshotFromTheSameMockedProjectStore() throws Exception {
        Map<String,String> projectData = new HashMap<>();
        SessionStore original = new SessionStore(TestApi.create("Engagement", "stable", projectData), directory);
        original.save("snapshot");
        assertEquals("snapshot", new SessionStore(TestApi.create("Engagement", "stable", projectData), directory).load());
    }
    @Test void temporarySessionRecoversAcrossNewBurpIds() throws Exception {
        new SessionStore(TestApi.create("Temporary Project", "old", new HashMap<>()), directory).save("temporary state");
        assertEquals("temporary state", new SessionStore(TestApi.create("Temporary Project", "new", new HashMap<>()), directory).load());
        assertNull(new SessionStore(TestApi.create("Unrelated", "other", new HashMap<>()), directory).load());
    }
    @Test void namedProjectRecoveryStaysIsolatedAndSurvivesRename() throws Exception {
        new SessionStore(TestApi.create("One", "1", new HashMap<>()), directory).save("one");
        new SessionStore(TestApi.create("Two", "2", new HashMap<>()), directory).save("two");
        assertEquals("one", new SessionStore(TestApi.create("Renamed", "1", new HashMap<>()), directory).load());
        assertEquals("two", new SessionStore(TestApi.create("Two", "2", new HashMap<>()), directory).load());
    }
    @Test void explicitEmptyStateOverridesRecovery() throws Exception {
        new SessionStore(TestApi.create("One", "1", new HashMap<>()), directory).save("old");
        Map<String,String> data = new HashMap<>(); data.put(SessionStore.KEY, "empty matrix");
        assertEquals("empty matrix", new SessionStore(TestApi.create("One", "1", data), directory).load());
    }

    @Test void failedStartupMustNotOverwriteUnrestorableProjectAndRecovery() throws Exception {
        Map<String,String> projectData = new HashMap<>();
        var api = TestApi.create("Engagement", "stable", projectData);
        String damaged = "{broken saved data";
        new SessionStore(api, directory).save(damaged);
        SessionStore reopened = new SessionStore(api, directory);
        MatrixDB empty = new MatrixDB();
        // Reproduce initialization's failed restore followed by its empty checkpoint.
        assertThrows(IOException.class, () -> reopened.restore(empty));
        SwingUtilities.invokeAndWait(() -> {
            AuthMatrixTab tab = new AuthMatrixTab(api, empty, reopened, new JsonObject());
            tab.shutdown();
        });
        assertEquals(damaged, projectData.get(SessionStore.KEY));
        assertTrue(reopened.isRestoreBlocked());
        assertThrows(IOException.class, () -> reopened.save(StateManager.serialize(empty, null)));
        try (var files = Files.list(directory)) {
            assertEquals(damaged, Files.readString(files.findFirst().orElseThrow()));
        }
    }

    @Test void projectCheckpointDoesNotDependOnAWritableRecoveryDirectory() throws Exception {
        Map<String,String> projectData = new HashMap<>();
        Path unavailableDirectory = directory.resolve("not-a-directory");
        Files.writeString(unavailableDirectory, "fixture");
        SessionStore store = new SessionStore(TestApi.create("Engagement", "stable", projectData), unavailableDirectory);
        store.save("snapshot");
        assertEquals("snapshot", projectData.get(SessionStore.KEY));
    }

    @Test void corruptProjectStateFallsBackToValidRecoveryBeforeAnyCheckpoint() throws Exception {
        Map<String,String> projectData = new HashMap<>();
        var api = TestApi.create("Engagement", "stable", projectData);
        String snapshot = StateManager.serialize(StateManagerTest.matrix("fixture"), new JsonObject());
        new SessionStore(api, directory).save(snapshot);
        projectData.put(SessionStore.KEY, "{broken project state");
        SessionStore reopened = new SessionStore(api, directory);
        MatrixDB restored = new MatrixDB();
        reopened.restore(restored);
        assertEquals(2, restored.getMessages().size());
        assertEquals("fixture", restored.getUsers().getFirst().getCookies());
        assertFalse(reopened.isRestoreBlocked());
        reopened.save(snapshot);
        assertEquals(snapshot, projectData.get(SessionStore.KEY));
    }

    @Test void deliberatelyReplacingAnUnrestorableSessionResumesCheckpointing() throws Exception {
        Map<String,String> projectData = new HashMap<>();
        var api = TestApi.create("Engagement", "stable", projectData);
        new SessionStore(api, directory).save("{damaged");
        SessionStore reopened = new SessionStore(api, directory);
        assertThrows(IOException.class, () -> reopened.restore(new MatrixDB()));
        String replacement = StateManager.serialize(StateManagerTest.matrix("replacement"), null);
        reopened.resumeAfterExplicitReplacement();
        reopened.save(replacement);
        assertFalse(reopened.isRestoreBlocked());
        assertEquals(replacement, projectData.get(SessionStore.KEY));
    }

    @Test void validProjectDataDoesNotDependOnReadableRecovery() throws Exception {
        Map<String,String> projectData = new HashMap<>();
        var api = TestApi.create("Engagement", "stable", projectData);
        String snapshot = StateManager.serialize(StateManagerTest.matrix("fixture"), null);
        projectData.put(SessionStore.KEY, snapshot);
        Path unavailable = directory.resolve("file-not-directory");
        Files.writeString(unavailable, "fixture");
        SessionStore store = new SessionStore(api, unavailable);
        MatrixDB restored = new MatrixDB();
        store.restore(restored);
        assertEquals(2, restored.getMessages().size());
        assertFalse(store.isRestoreBlocked());
    }

    @Test void newProjectWithNoSnapshotCanStartAndSaveNormally() throws Exception {
        Map<String,String> projectData = new HashMap<>();
        SessionStore store = new SessionStore(TestApi.create("New project", "new", projectData), directory);
        MatrixDB db = new MatrixDB();
        assertEquals(new JsonObject(), store.restore(db));
        assertFalse(store.isRestoreBlocked());
        String snapshot = StateManager.serialize(db, null);
        store.save(snapshot);
        assertEquals(snapshot, projectData.get(SessionStore.KEY));
    }

    @Test void firstCheckpointAfterProjectRestoreCreatesTheMissingRecoveryCopy() throws Exception {
        Map<String,String> projectData = new HashMap<>();
        String snapshot = StateManager.serialize(StateManagerTest.matrix("fixture"), null);
        projectData.put(SessionStore.KEY, snapshot);
        SessionStore store = new SessionStore(TestApi.create("Engagement", "stable", projectData), directory);
        store.restore(new MatrixDB());
        store.save(snapshot);
        try (var files = Files.list(directory)) {
            assertEquals(snapshot, Files.readString(files.findFirst().orElseThrow()));
        }
    }
}
