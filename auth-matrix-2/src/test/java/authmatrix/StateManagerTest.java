package authmatrix;

import authmatrix.model.*;
import com.google.gson.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.awt.Color;
import static org.junit.jupiter.api.Assertions.*;

class StateManagerTest {
    @TempDir Path temp;
    private static byte[] bytes(String s) { return s.getBytes(StandardCharsets.UTF_8); }
    static MatrixDB matrix(String cookie) {
        MatrixDB db = new MatrixDB();
        RoleEntry role = db.getOrCreateRole("Admin");
        UserEntry user = db.getOrCreateUser("alice");
        user.setCookies(cookie);
        user.setRole(role, true);
        db.addHeader();
        user.getHeaders().set(0, "Authorization: Bearer fixture");
        MessageEntry root = db.createMessage("example.test", 443, true,
                bytes("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"), bytes("original response"), "GET /", "200");
        root.setRoleAuthorized(role, true);
        root.setFailureRegexMode(true);
        root.addRunResult(user, bytes("run request"), new byte[]{0, -1, 13, 10});
        root.setRoleResult(role, false);
        SectionEntry section = db.createSection("Account");
        section.setCollapsed(true);
        db.createMessageInSection(section, "example.test", 80, false, bytes("GET /account"), null, "Account", "denied").setEnabled(false);
        return db;
    }

    @Test void roundTripPreservesHttpDataResultsAndUi() throws Exception {
        MatrixDB db = matrix("session=fixture");
        JsonObject ui = new JsonObject();
        ui.addProperty("mainDivider", 320);
        ui.addProperty("highlightNewPaths", true);
        Path file = temp.resolve("state.json");
        StateManager.writeAtomically(file.toFile(), StateManager.serialize(db, ui));
        MatrixDB restored = new MatrixDB();
        assertEquals(ui, StateManager.load(restored, file.toFile()));
        assertEquals(StateManager.serialize(db, ui), StateManager.serialize(restored, ui));
        assertArrayEquals(bytes("original response"), restored.getMessages().getFirst().getResponse());
        assertArrayEquals(new byte[]{0, -1, 13, 10}, restored.getMessages().getFirst().getUserRuns().get(restored.getUsers().getFirst()).response());
        assertTrue(restored.getSections().getFirst().isCollapsed());
        assertFalse(restored.getMessages().getLast().isEnabled());
    }

    @Test void emptyHeadersSurviveWithoutUsers() throws Exception {
        MatrixDB db = new MatrixDB(); db.addHeader(); db.addHeader();
        MatrixDB restored = new MatrixDB();
        StateManager.restore(restored, StateManager.serialize(db, null));
        assertEquals(2, restored.getHeaderCount());
        assertEquals(2, restored.getOrCreateUser("new").getHeaders().size());
    }

    @Test void malformedStateDoesNotEraseWork() throws Exception {
        MatrixDB db = matrix("keep");
        String before = StateManager.serialize(db, null);
        for (String invalid : new String[]{"{", "{}", "[]", "{\"roles\":[],\"users\":[],\"rows\":[{\"name\":\"broken\"}]}",
                before.replace("cnVuIHJlcXVlc3Q", "invalid%base64")}) {
            assertThrows(java.io.IOException.class, () -> StateManager.restore(db, invalid));
            assertEquals(before, StateManager.serialize(db, null));
        }
    }

    @Test void readsEarlierV2MessageFormatAndPadsHeaders() throws Exception {
        JsonObject old = JsonParser.parseString(StateManager.serialize(matrix("cookie"), null)).getAsJsonObject();
        old.remove("headerCount");
        JsonArray messages = new JsonArray();
        for (JsonElement row : old.getAsJsonArray("rows")) {
            if (row.getAsJsonObject().get("type").getAsString().equals("message")) {
                row.getAsJsonObject().remove("type");
                row.getAsJsonObject().remove("responseBase64");
                row.getAsJsonObject().remove("id");
                messages.add(row);
            }
        }
        old.remove("rows"); old.add("messages", messages);
        MatrixDB db = new MatrixDB(); StateManager.restore(db, old.toString());
        assertEquals(2, db.getMessages().size());
        assertNotEquals(db.getMessages().get(0).getId(), db.getMessages().get(1).getId());
        assertEquals(1, db.getHeaderCount());
        assertNull(db.getMessages().getFirst().getResponse());
    }

    @Test void mergeKeepsCredentialsAndRemapsConflictingUsersAndSingleRoles() throws Exception {
        MatrixDB db = matrix("current");
        MessageEntry existing = db.getMessages().getFirst();
        UserEntry current = db.getUsers().getFirst();
        MatrixDB imported = matrix("imported");
        Path file = temp.resolve("import.json"); StateManager.save(imported, file.toFile());
        StateManager.MergeResult result = StateManager.merge(db, file.toFile());
        assertEquals(1, result.users()); assertEquals(1, result.roles()); assertEquals(2, result.requests());
        assertSame(current, db.findUserByName("alice")); assertEquals("current", current.getCookies());
        UserEntry added = db.findUserByName("alice (imported 2)"); assertNotNull(added);
        assertEquals("imported", added.getCookies());
        assertTrue(added.hasRole(db.findRoleByName("alice (imported 2) (only)")));
        assertFalse(current.hasRole(db.findRoleByName("alice (imported 2) (only)")));
        assertSame(existing, db.getMessages().getFirst());
        assertEquals(2, db.getRootMessages().size()); assertEquals(1, db.getSections().size());
        assertEquals(2, db.getMessagesInSection(db.getSections().getFirst()).size());
        MessageEntry importedRoot = db.getRootMessages().getLast();
        assertTrue(importedRoot.getUserRuns().containsKey(added));
        assertFalse(importedRoot.getUserRuns().containsKey(current));
        assertEquals(4, db.getMessages().stream().map(MessageEntry::getId).distinct().count());
        assertTrue(db.createMessage("h",80,false,null,null,"new","").getId() > db.getMessages().get(3).getId());
    }

    @Test void identicalUsersAndRolesAreReusedAndUnrunImportsStayUncolored() {
        MatrixDB db = matrix("same"), incoming = matrix("same");
        incoming.getMessages().forEach(MessageEntry::clearResults);
        StateManager.MergeResult result = StateManager.merge(db, incoming);
        assertEquals(0, result.users()); assertEquals(0, result.roles());
        assertEquals(1, db.getUsers().size());
        assertTrue(db.getRootMessages().getLast().getRoleResults().isEmpty());
    }

    @Test void malformedMergePreservesCurrentMatrix() throws Exception {
        MatrixDB db = matrix("keep"); String before = StateManager.serialize(db, null);
        Path bad = temp.resolve("bad.json"); Files.writeString(bad, "{}");
        assertThrows(java.io.IOException.class, () -> StateManager.merge(db, bad.toFile()));
        assertEquals(before, StateManager.serialize(db, null));
    }
    @Test void generatedUserNamesDoNotCollideWithOtherImportedNames() {
        MatrixDB db = matrix("current"), incoming = matrix("imported");
        incoming.getOrCreateUser("alice (imported 2)").setCookies("another");
        StateManager.merge(db, incoming);
        assertEquals("imported", db.findUserByName("alice (imported 3)").getCookies());
        assertEquals("another", db.findUserByName("alice (imported 2)").getCookies());
    }

    @Test void roleKindConflictsRemainSeparate() {
        MatrixDB db = new MatrixDB(), incoming = new MatrixDB();
        RoleEntry existing = db.getOrCreateRole("Shared", false);
        RoleEntry imported = incoming.getOrCreateRole("Shared", true);
        UserEntry user = incoming.getOrCreateUser("bob"); user.setRole(imported, true);
        StateManager.merge(db, incoming);
        assertSame(existing, db.findRoleByName("Shared"));
        assertFalse(existing.isSingleUser());
        RoleEntry renamed = db.findRoleByName("Shared (imported 2)");
        assertTrue(renamed.isSingleUser());
        assertTrue(db.findUserByName("bob").hasRole(renamed));
        assertFalse(db.findUserByName("bob").hasRole(existing));
    }

    @Test void newlyMergedRolesStayUncoloredUntilTheirUsersRun() {
        MatrixDB db = matrix("current"), incoming = matrix("different");
        incoming.getUsers().getFirst().setRole(incoming.findRoleByName("Admin"), false);
        StateManager.merge(db, incoming);
        RoleEntry importedRole = db.findRoleByName("alice (imported 2) (only)");
        assertFalse(db.getMessages().getFirst().getRoleResults().containsKey(importedRole));
    }

    @Test void incompleteRequestGivesAnActionableImportError() {
        MatrixDB db = new MatrixDB();
        java.io.IOException error = assertThrows(java.io.IOException.class, () -> StateManager.restore(db,
                "{\"roles\":[],\"users\":[],\"rows\":[{}]}"));
        assertEquals("Invalid AuthMatrix state: A request is missing its name.", error.getMessage());
    }

}
