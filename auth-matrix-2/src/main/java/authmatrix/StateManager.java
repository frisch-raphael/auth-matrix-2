package authmatrix;

import authmatrix.model.*;
import com.google.gson.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class StateManager {
    private static final String VERSION = "2.0.0";

    public static void save(MatrixDB db, File file) throws IOException {
        JsonObject root = new JsonObject();
        root.addProperty("version", VERSION);

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

        // Messages
        JsonArray messagesArr = new JsonArray();
        for (MessageEntry msg : db.getMessages()) {
            JsonObject m = new JsonObject();
            m.addProperty("id", msg.getId());
            m.addProperty("name", msg.getName());
            m.addProperty("host", msg.getHost());
            m.addProperty("port", msg.getPort());
            m.addProperty("secure", msg.isSecure());
            m.addProperty("requestBase64", b64Encode(msg.getRequest()));
            m.addProperty("regexBase64", b64Encode(msg.getRegex()));
            m.addProperty("failureRegexMode", msg.isFailureRegexMode());
            m.addProperty("enabled", msg.isEnabled());
            JsonObject roles = new JsonObject();
            for (RoleEntry role : db.getAllRoles()) {
                roles.addProperty(role.getName(), msg.isRoleAuthorized(role));
            }
            m.add("roles", roles);

            // Run results per user
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

            // Role results (color coding)
            JsonObject roleResults = new JsonObject();
            for (var resultEntry : msg.getRoleResults().entrySet()) {
                roleResults.addProperty(resultEntry.getKey().getName(), resultEntry.getValue());
            }
            m.add("roleResults", roleResults);

            messagesArr.add(m);
        }
        root.add("messages", messagesArr);

        try (Writer writer = new BufferedWriter(new FileWriter(file, StandardCharsets.UTF_8))) {
            writer.write(new GsonBuilder().setPrettyPrinting().create().toJson(root));
        }
    }

    public static void load(MatrixDB db, File file) throws IOException {
        String json;
        try (BufferedReader reader = new BufferedReader(new FileReader(file, StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) sb.append(line);
            json = sb.toString();
        }

        JsonObject root = JsonParser.parseString(json).getAsJsonObject();

        db.clear();

        // Roles
        if (root.has("roles")) {
            for (JsonElement el : root.getAsJsonArray("roles")) {
                JsonObject r = el.getAsJsonObject();
                db.addRoleDirect(new RoleEntry(
                        r.get("name").getAsString(),
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
                        u.get("name").getAsString(),
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
                db.addUserDirect(user);
            }
        }

        // Messages
        int maxId = 0;
        if (root.has("messages")) {
            for (JsonElement el : root.getAsJsonArray("messages")) {
                JsonObject m = el.getAsJsonObject();
                int id = m.has("id") ? m.get("id").getAsInt() : 0;
                maxId = Math.max(maxId, id + 1);

                String regex = m.has("regexBase64") ? b64Decode(m.get("regexBase64").getAsString()) : "";
                byte[] request = m.has("requestBase64") && !m.get("requestBase64").getAsString().isEmpty()
                        ? Base64.getDecoder().decode(m.get("requestBase64").getAsString()) : null;

                MessageEntry msg = new MessageEntry(
                        id,
                        m.get("name").getAsString(),
                        m.get("host").getAsString(),
                        m.get("port").getAsInt(),
                        m.has("secure") && m.get("secure").getAsBoolean(),
                        request, null, regex);

                msg.setFailureRegexMode(m.has("failureRegexMode") && m.get("failureRegexMode").getAsBoolean());
                msg.setEnabled(!m.has("enabled") || m.get("enabled").getAsBoolean());

                if (m.has("roles")) {
                    JsonObject rolesObj = m.getAsJsonObject("roles");
                    for (RoleEntry role : db.getAllRoles()) {
                        boolean checked = rolesObj.has(role.getName()) && rolesObj.get(role.getName()).getAsBoolean();
                        msg.setRoleAuthorized(role, checked);
                    }
                }

                db.addRegexIfNew(regex);
                db.addMessageDirect(msg);

                // Restore run results
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

                // Restore role results (color coding)
                if (m.has("roleResults")) {
                    JsonObject roleResultsObj = m.getAsJsonObject("roleResults");
                    for (RoleEntry role : db.getAllRoles()) {
                        if (roleResultsObj.has(role.getName())) {
                            msg.setRoleResult(role, roleResultsObj.get(role.getName()).getAsBoolean());
                        }
                    }
                }
            }
        }
        db.setNextMessageId(maxId);
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
