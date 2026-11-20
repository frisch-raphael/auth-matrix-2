package authmatrix;

import authmatrix.model.MatrixDB;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class LegacyStateTest {
    @TempDir Path temp;

    @Test void importsPythonSnapshotIntoCurrentMatrixAndPreservesHttpBytes() throws IOException {
        byte[] request = {71, 69, 84, 13, 10, 0, (byte) 0x80, (byte) 0xff};
        byte[] response = {72, 84, 84, 80, 13, 10, (byte) 0xe9};
        String snapshot = """
                {
                  "version": "0.8.2",
                  "arrayOfRoles": [
                    {"index": 0, "deleted": True, "column": null, "name": null},
                    {"index": 1, "column": 1, "name": "Reader"},
                    {"index": 2, "column": 0, "name": "Writer"}
                  ],
                  "arrayOfUsers": [
                    {"index": 8, "tableRow": 1, "name": "alice", "roles": {"1": true}},
                    {"index": 4, "tableRow": 0, "name": "bob", "roles": {"0": true, "2": true},
                     "enabled": False, "cookiesBase64": "%s", "headerBase64": "%s"}
                  ],
                  "arrayOfMessages": [
                    {"index": 2, "tableRow": 1, "name": "Second", "host": "example.test", "port": 80,
                     "protocol": "http", "requestBase64": "%s", "roles": {}},
                    {"index": 3, "deleted": true, "requestBase64": null},
                    /* The Python loader also accepts comments. */
                    {"index": 7, "tableRow": 0, "name": "First", "host": "example.test", "port": 8443,
                     "protocol": "https", "requestBase64": "%s", "roles": {"2": true},
                     "enabled": false, "failureRegexMode": true, "regexBase64": "%s",
                     "runBase64ForUserID": {"4": {"request": "%s", "response": "%s"},
                                            "8": {"request": "%s", "response": null}},
                     "runResultForRoleID": {"2": true}}
                  ],
                  "arrayOfChains": [{"deleted": true}, {"name": "Unsupported chain"}],
                  "arrayOfChainSources": [{"name": "Unsupported source"}]
                }
                """.formatted(text("session=café"), text("X-User: café"), http(request), http(request), text("denied"),
                http(request), http(response), http(request));
        Path file = Files.writeString(temp.resolve("old-matrix"), snapshot);
        MatrixDB db = new MatrixDB();
        var current = db.createMessage("example.test", 443, true, request, null, "Current", "");
        var section = db.createSection("Current section");
        var result = StateManager.mergeLegacy(db, file.toFile());

        assertEquals(new StateManager.MergeResult(2, 2, 2), result.merged());
        assertTrue(result.skippedChainData());
        assertSame(current, db.getMessages().getFirst());
        assertEquals(List.of("Current", "First", "Second"), db.getRootMessages().stream().map(m -> m.getName()).toList());
        assertSame(section, db.getSections().getFirst());
        assertEquals(List.of("Writer", "Reader"), db.getAllRoles().stream().map(r -> r.getName()).toList());
        var bob = db.getUsers().getFirst();
        assertEquals("bob", bob.getName());
        assertFalse(bob.isEnabled());
        assertEquals("session=café", bob.getCookies());
        assertEquals(List.of("X-User: café"), bob.getHeaders());
        assertTrue(bob.hasRole(db.findRoleByName("Writer")));
        assertEquals(List.of(""), db.getUsers().getLast().getHeaders());
        var imported = db.getMessages().get(1);
        assertEquals("example.test", imported.getHost());
        assertEquals(8443, imported.getPort());
        assertTrue(imported.isSecure());
        assertFalse(imported.isEnabled());
        assertTrue(imported.isFailureRegexMode());
        assertEquals("denied", imported.getRegex());
        assertTrue(imported.isRoleAuthorized(db.findRoleByName("Writer")));
        assertArrayEquals(request, imported.getRequest());
        assertArrayEquals(request, imported.getUserRuns().get(bob).request());
        assertArrayEquals(response, imported.getUserRuns().get(bob).response());
        assertNull(imported.getUserRuns().get(db.findUserByName("alice")).response());
        assertNull(imported.getResponse());
    }

    @Test void invalidAndBinaryFilesLeaveTheCurrentMatrixIntact() throws IOException {
        MatrixDB db = StateManagerTest.matrix("keep");
        String before = StateManager.serialize(db, null);
        Path file = temp.resolve("invalid");
        for (String invalid : List.of("{", "{}", before,
                """
                {"version": "0.8.2", "arrayOfRoles": [{"index": 0, "column": 0, "name": "Valid"}],
                 "arrayOfMessages": [{"index": 0, "tableRow": 0, "name": "Broken", "host": "example.test",
                  "port": 80, "protocol": "http", "requestBase64": "???"}]}
                """)) {
            Files.writeString(file, invalid);
            assertThrows(IOException.class, () -> StateManager.mergeLegacy(db, file.toFile()));
            assertEquals(before, StateManager.serialize(db, null));
        }
        Files.write(file, new byte[]{(byte) 0xac, (byte) 0xed, 0, 5});
        IOException error = assertThrows(IOException.class, () -> StateManager.mergeLegacy(db, file.toFile()));
        assertTrue(error.getMessage().contains("binary"));
        assertEquals(before, StateManager.serialize(db, null));
    }

    private static String text(String value) {
        return Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private static String http(byte[] bytes) {
        return text(new String(bytes, StandardCharsets.ISO_8859_1));
    }
}
