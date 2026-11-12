package authmatrix;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class SessionStoreTest {
    @TempDir Path directory;
    @Test void survivesExtensionReloadAndBurpProjectReopen() throws Exception {
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
}
