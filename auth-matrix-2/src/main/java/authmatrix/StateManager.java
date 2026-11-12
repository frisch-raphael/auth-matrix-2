package authmatrix;

import authmatrix.model.*;
import com.google.gson.*;

import java.awt.Color;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

public class StateManager {
    private static final String VERSION = "2.0.0";

    public static void save(MatrixDB db, File file) throws IOException {
        writeAtomically(file, serialize(db, null));
    }

    public static String serialize(MatrixDB db, JsonObject ui) {
        JsonObject root = new JsonObject();
        root.addProperty("version", VERSION);

        root.addProperty("headerCount", db.getHeaderCount());
        if (ui != null) root.add("ui", ui);

        // Roles
        JsonArray rolesArr = new JsonArray();
        for (RoleEntry role : db.getAllRoles()) {
            JsonObject r = new JsonObject();
            r.addProperty("name", role.getName());
            r.addProperty("singleUser", role.isSingleUser());
            rolesArr.add(r);
        }
        root.add("roles", rolesArr);

        // Users
        JsonArray usersArr = new JsonArray();
        for (UserEntry user : db.getUsers()) {
            JsonObject u = new JsonObject();
            u.addProperty("name", user.getName());
            u.addProperty("cookiesBase64", b64Encode(user.getCookies()));
            u.addProperty("enabled", user.isEnabled());
            JsonArray headers = new JsonArray();
            for (String h : user.getHeaders()) headers.add(b64Encode(h));
            u.add("headersBase64", headers);
            JsonObject roles = new JsonObject();
            for (RoleEntry role : db.getAllRoles()) {
                roles.addProperty(role.getName(), user.hasRole(role));
            }
            u.add("roles", roles);
            usersArr.add(u);
        }
        root.add("users", usersArr);

        // Rows: sections and messages interleaved in display order
        JsonArray rowsArr = new JsonArray();
        for (Object row : db.getRows()) {
            if (row instanceof SectionEntry s) {
                JsonObject obj = new JsonObject();
                obj.addProperty("type", "section");
                obj.addProperty("name", s.getName());
                obj.addProperty("color", String.format("#%06X", s.getColor().getRGB() & 0xFFFFFF));
                obj.addProperty("collapsed", s.isCollapsed());
                rowsArr.add(obj);
            } else if (row instanceof MessageEntry msg) {
                JsonObject m = new JsonObject();
                m.addProperty("type", "message");
                m.addProperty("id", msg.getId());
                m.addProperty("name", msg.getName());
                m.addProperty("host", msg.getHost());
                m.addProperty("port", msg.getPort());
                m.addProperty("secure", msg.isSecure());
                m.addProperty("requestBase64", b64Encode(msg.getRequest()));
                m.addProperty("responseBase64", b64Encode(msg.getResponse()));
                m.addProperty("regexBase64", b64Encode(msg.getRegex()));
                m.addProperty("failureRegexMode", msg.isFailureRegexMode());
                m.addProperty("enabled", msg.isEnabled());
                JsonObject roles = new JsonObject();
                for (RoleEntry role : db.getAllRoles()) {
                    roles.addProperty(role.getName(), msg.isRoleAuthorized(role));
                }
                m.add("roles", roles);
                JsonObject runs = new JsonObject();
                for (var runEntry : msg.getUserRuns().entrySet()) {
                    UserEntry user = runEntry.getKey();
                    MessageEntry.RunResult run = runEntry.getValue();
                    JsonObject runObj = new JsonObject();
                    runObj.addProperty("requestBase64", b64Encode(run.request()));
                    runObj.addProperty("responseBase64", b64Encode(run.response()));
                    runs.add(user.getName(), runObj);
                }
                m.add("userRuns", runs);
                JsonObject roleResults = new JsonObject();
                for (var resultEntry : msg.getRoleResults().entrySet()) {
                    roleResults.addProperty(resultEntry.getKey().getName(), resultEntry.getValue());
                }
                m.add("roleResults", roleResults);
                rowsArr.add(m);
            }
        }
        root.add("rows", rowsArr);

        return new GsonBuilder().setPrettyPrinting().create().toJson(root);
    }

    public static void writeAtomically(File file, String json) throws IOException {
        Path target = file.toPath().toAbsolutePath();
        Path temp = Files.createTempFile(target.getParent(), ".authmatrix-", ".tmp");
        try {
            Files.writeString(temp, json, StandardCharsets.UTF_8);
            try {
                Files.move(temp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException ex) {
                Files.move(temp, target, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    public static JsonObject load(MatrixDB db, File file) throws IOException {
        return restore(db, Files.readString(file.toPath(), StandardCharsets.UTF_8));
    }

    /** Parse into an isolated matrix first: a malformed import must never erase current work. */
    public static JsonObject restore(MatrixDB db, String json) throws IOException {
        try {
            JsonObject root = JsonParser.parseString(json).getAsJsonObject();
            if (!root.has("roles") || !root.has("users") || (!root.has("rows") && !root.has("messages")))
                throw new IllegalArgumentException("Not an AuthMatrix v2 state file");
            MatrixDB incoming = new MatrixDB();
            read(incoming, root);
            JsonObject ui = root.has("ui") ? root.getAsJsonObject("ui") : new JsonObject();
            db.replaceWith(incoming);
            return ui;
        } catch (RuntimeException ex) {
            throw new IOException("Invalid AuthMatrix state: " + ex.getMessage(), ex);
        }
    }

    private static void read(MatrixDB db, JsonObject root) {
        if (root.has("headerCount")) db.setHeaderCount(Math.max(0, root.get("headerCount").getAsInt()));
        // Roles
        if (root.has("roles")) {
            for (JsonElement el : root.getAsJsonArray("roles")) {
                JsonObject r = el.getAsJsonObject();
                if (db.findRoleByName(requiredString(r, "name", "role")) != null)
                    throw new IllegalArgumentException("Duplicate role name");
                db.addRoleDirect(new RoleEntry(
                        requiredString(r, "name", "role"),
                        r.has("singleUser") && r.get("singleUser").getAsBoolean()));
            }
        }

        // Users
        if (root.has("users")) {
            for (JsonElement el : root.getAsJsonArray("users")) {
                JsonObject u = el.getAsJsonObject();
                List<String> headers = new ArrayList<>();
                if (u.has("headersBase64")) {
                    for (JsonElement h : u.getAsJsonArray("headersBase64")) {
                        headers.add(b64Decode(h.getAsString()));
                    }
                }
                db.setHeaderCount(Math.max(db.getHeaderCount(), headers.size()));

                UserEntry user = new UserEntry(
                        requiredString(u, "name", "user"),
                        u.has("cookiesBase64") ? b64Decode(u.get("cookiesBase64").getAsString()) : "",
                        headers,
                        !u.has("enabled") || u.get("enabled").getAsBoolean());

                // Assign roles
                if (u.has("roles")) {
                    JsonObject rolesObj = u.getAsJsonObject("roles");
                    for (RoleEntry role : db.getAllRoles()) {
                        boolean checked = rolesObj.has(role.getName()) && rolesObj.get(role.getName()).getAsBoolean();
                        user.setRole(role, checked);
                    }
                }
                if (db.findUserByName(user.getName()) != null) throw new IllegalArgumentException("Duplicate user name");
                db.addUserDirect(user);
            }
        }

        // Rows: mixed sections + messages. Backward compat: old files use "messages" key.
        JsonArray rowsArr = root.has("rows") ? root.getAsJsonArray("rows")
                : root.has("messages") ? root.getAsJsonArray("messages") : null;

        int maxId = 0;
        Set<Integer> ids = new HashSet<>();
        if (rowsArr != null) {
            for (JsonElement el : rowsArr) {
                JsonObject obj = el.getAsJsonObject();
                String type = obj.has("type") ? obj.get("type").getAsString() : "message";

                if ("section".equals(type)) {
                    String sName = obj.get("name").getAsString();
                    Color sColor = null;
                    if (obj.has("color")) {
                        try { sColor = Color.decode(obj.get("color").getAsString()); } catch (NumberFormatException ignored) {}
                    }
                    SectionEntry section = sColor != null ? new SectionEntry(sName, sColor) : new SectionEntry(sName);
                    section.setCollapsed(obj.has("collapsed") && obj.get("collapsed").getAsBoolean());
                    db.addSectionDirect(section);
                    continue;
                }

                // message
                JsonObject m = obj;
                int id = m.has("id") ? m.get("id").getAsInt() : maxId;
                if (id < 0 || ids.contains(id)) id = maxId;
                ids.add(id);
                maxId = Math.max(maxId, id + 1);

                String regex = m.has("regexBase64") ? b64Decode(m.get("regexBase64").getAsString()) : "";
                byte[] request = m.has("requestBase64") && !m.get("requestBase64").getAsString().isEmpty()
                        ? Base64.getDecoder().decode(m.get("requestBase64").getAsString()) : null;

                MessageEntry msg = new MessageEntry(id, requiredString(m, "name", "request"),
                        requiredString(m, "host", "request"), m.get("port").getAsInt(),
                        m.has("secure") && m.get("secure").getAsBoolean(),
                        request, decodeBytes(m, "responseBase64"), regex);

                msg.setFailureRegexMode(m.has("failureRegexMode") && m.get("failureRegexMode").getAsBoolean());
                msg.setEnabled(!m.has("enabled") || m.get("enabled").getAsBoolean());

                if (m.has("roles")) {
                    JsonObject rolesObj = m.getAsJsonObject("roles");
                    for (RoleEntry role : db.getAllRoles()) {
                        msg.setRoleAuthorized(role, rolesObj.has(role.getName()) && rolesObj.get(role.getName()).getAsBoolean());
                    }
                }
                db.addRegexIfNew(regex);
                db.addMessageDirect(msg);

                if (m.has("userRuns")) {
                    JsonObject runsObj = m.getAsJsonObject("userRuns");
                    for (String userName : runsObj.keySet()) {
                        UserEntry user = db.findUserByName(userName);
                        if (user == null) continue;
                        JsonObject runObj = runsObj.getAsJsonObject(userName);
                        byte[] runReq = runObj.has("requestBase64") && !runObj.get("requestBase64").getAsString().isEmpty()
                                ? Base64.getDecoder().decode(runObj.get("requestBase64").getAsString()) : null;
                        byte[] runResp = runObj.has("responseBase64") && !runObj.get("responseBase64").getAsString().isEmpty()
                                ? Base64.getDecoder().decode(runObj.get("responseBase64").getAsString()) : null;
                        msg.addRunResult(user, runReq, runResp);
                    }
                }
                if (m.has("roleResults")) {
                    JsonObject roleResultsObj = m.getAsJsonObject("roleResults");
                    for (RoleEntry role : db.getAllRoles()) {
                        if (roleResultsObj.has(role.getName()))
                            msg.setRoleResult(role, roleResultsObj.get(role.getName()).getAsBoolean());
                    }
                }
            }
        }
        for (UserEntry user : db.getUsers()) user.ensureHeaderCount(db.getHeaderCount());
        db.setNextMessageId(maxId);
    }

    public static MergeResult merge(MatrixDB db, File file) throws IOException {
        MatrixDB incoming = new MatrixDB();
        load(incoming, file);
        return merge(db, incoming);
    }

    /** Reuse identical users, rename conflicting users, and never overwrite current credentials. */
    public static MergeResult merge(MatrixDB db, MatrixDB incoming) {
        Map<RoleEntry, RoleEntry> roles = new IdentityHashMap<>();
        Map<UserEntry, UserEntry> users = new IdentityHashMap<>();
        int addedRoles = 0, addedUsers = 0;
        // Decide user names before mapping their automatically generated single-user roles.
        Map<UserEntry, String> names = new IdentityHashMap<>();
        Set<String> reserved = new HashSet<>();
        for (UserEntry user : db.getUsers()) reserved.add(user.getName());
        for (UserEntry user : incoming.getUsers()) reserved.add(user.getName());
        for (UserEntry user : incoming.getUsers()) {
            String name = user.getName();
            UserEntry existing = db.findUserByName(name);
            if (existing != null && !sameUser(existing, user)) {
                int suffix = 2;
                while (reserved.contains(name = user.getName() + " (imported " + suffix++ + ")")) { }
            }
            names.put(user, name);
            reserved.add(name);
        }
        for (RoleEntry role : incoming.getAllRoles()) {
            String name = role.getName();
            if (role.isSingleUser()) {
                for (UserEntry user : incoming.getUsers()) {
                    if (name.equals(user.getName() + MatrixDB.SINGLE_USER_SUFFIX)) {
                        name = names.get(user) + MatrixDB.SINGLE_USER_SUFFIX;
                        break;
                    }
                }
            }
            RoleEntry mapped = db.findRoleByName(name);
            if (mapped != null && mapped.isSingleUser() != role.isSingleUser()) {
                String base = name;
                int suffix = 2;
                while (db.findRoleByName(name = base + " (imported " + suffix++ + ")") != null) { }
                mapped = null;
            }
            if (mapped == null) {
                mapped = db.getOrCreateRole(name, role.isSingleUser());
                addedRoles++;
            }
            roles.put(role, mapped);
        }
        db.setHeaderCount(Math.max(db.getHeaderCount(), incoming.getHeaderCount()));
        for (UserEntry user : incoming.getUsers()) {
            UserEntry mapped = db.findUserByName(names.get(user));
            if (mapped == null) {
                mapped = new UserEntry(names.get(user), user.getCookies(), user.getHeaders(), user.isEnabled());
                db.addUserDirect(mapped);
                addedUsers++;
            }
            for (RoleEntry role : incoming.getAllRoles()) {
                if (user.hasRole(role)) mapped.setRole(roles.get(role), true);
            }
            users.put(user, mapped);
        }
        for (UserEntry user : db.getUsers()) user.ensureHeaderCount(db.getHeaderCount());
        SectionEntry current = null;
        for (Object row : incoming.getRows()) {
            if (row instanceof SectionEntry section) {
                current = db.findSectionByName(section.getName());
                if (current == null) {
                    current = new SectionEntry(section.getName(), section.getColor());
                    current.setCollapsed(section.isCollapsed());
                    db.addSectionDirect(current);
                }
            } else if (row instanceof MessageEntry msg) {
                MessageEntry copy = db.createMessageInSection(current, msg.getHost(), msg.getPort(), msg.isSecure(),
                        msg.getRequest(), msg.getResponse(), msg.getName(), msg.getRegex());
                // Root imports belong before the first section, regardless of the current matrix layout.
                if (current == null) {
                    db.getRows().remove(copy);
                    db.getRows().add(db.getRootMessages().size(), copy);
                }
                copy.setEnabled(msg.isEnabled());
                copy.setFailureRegexMode(msg.isFailureRegexMode());
                roles.forEach((source, target) -> copy.setRoleAuthorized(target, msg.isRoleAuthorized(source)));
                msg.getUserRuns().forEach((user, run) -> copy.addRunResult(users.get(user), run.request(), run.response()));
            }
        }
        // Re-evaluate against the combined matrix rather than trusting stale imported colors.
        for (MessageEntry msg : db.getMessages()) {
            if (!msg.getUserRuns().isEmpty()) RunEngine.evaluateRoleResults(db, msg);
        }
        return new MergeResult(addedUsers, addedRoles, incoming.getMessages().size());
    }

    private static boolean sameUser(UserEntry a, UserEntry b) {
        if (!Objects.equals(a.getCookies(), b.getCookies()) || a.isEnabled() != b.isEnabled()) return false;
        List<String> ah = new ArrayList<>(a.getHeaders()), bh = new ArrayList<>(b.getHeaders());
        while (!ah.isEmpty() && ah.getLast().isEmpty()) ah.removeLast();
        while (!bh.isEmpty() && bh.getLast().isEmpty()) bh.removeLast();
        if (!ah.equals(bh)) return false;
        Set<String> ar = new HashSet<>(), br = new HashSet<>();
        a.getRoles().forEach((role, enabled) -> { if (enabled) ar.add(role.getName()); });
        b.getRoles().forEach((role, enabled) -> { if (enabled) br.add(role.getName()); });
        return ar.equals(br);
    }

    public record MergeResult(int users, int roles, int requests) { }

    private static String requiredString(JsonObject object, String key, String item) {
        if (!object.has(key) || object.get(key).isJsonNull() || !object.get(key).isJsonPrimitive())
            throw new IllegalArgumentException("A " + item + " is missing its " + key + ".");
        return object.get(key).getAsString();
    }

    private static byte[] decodeBytes(JsonObject object, String key) {
        return object.has(key) && !object.get(key).getAsString().isEmpty()
                ? Base64.getDecoder().decode(object.get(key).getAsString()) : null;
    }

    private static String b64Encode(String s) {
        if (s == null || s.isEmpty()) return "";
        return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    private static String b64Encode(byte[] b) {
        if (b == null || b.length == 0) return "";
        return Base64.getEncoder().encodeToString(b);
    }

    private static String b64Decode(String s) {
        if (s == null || s.isEmpty()) return "";
        return new String(Base64.getDecoder().decode(s), StandardCharsets.UTF_8);
    }
}
