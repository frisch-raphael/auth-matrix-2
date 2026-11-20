package authmatrix;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/** Converts Python-era JSON into the current state format before it reaches the live matrix. */
final class LegacyState {
    private LegacyState() { }

    record Converted(JsonObject state, boolean skippedChainData) { }

    static Converted read(Path file) throws IOException {
        try {
            return convert(JsonParser.parseString(Files.readString(file, StandardCharsets.UTF_8)).getAsJsonObject());
        } catch (CharacterCodingException ex) {
            throw new IOException("Choose a legacy AuthMatrix JSON save. Older binary saves cannot be imported.", ex);
        } catch (RuntimeException ex) {
            throw new IOException("Invalid legacy AuthMatrix JSON. Choose a readable Python-era AuthMatrix save.", ex);
        }
    }

    private static Converted convert(JsonObject legacy) {
        if (!text(legacy, "version").matches("0\\.\\d+(\\.\\d+)?")
                || !(legacy.has("arrayOfRoles") || legacy.has("arrayOfUsers") || legacy.has("arrayOfMessages"))) {
            throw new IllegalArgumentException();
        }

        Map<String, String> roleNames = new HashMap<>();
        Map<String, String> userNames = new HashMap<>();
        JsonObject state = new JsonObject();
        JsonArray roles = new JsonArray();
        JsonArray users = new JsonArray();
        JsonArray rows = new JsonArray();
        state.add("roles", roles);
        state.add("users", users);
        state.add("rows", rows);

        for (JsonObject source : activeInOrder(legacy, "arrayOfRoles", "column")) {
            JsonObject role = named(source, roleNames);
            role.addProperty("singleUser", flag(source, "singleUser", false));
            roles.add(role);
        }
        boolean skippedChainData = !activeInOrder(legacy, "arrayOfChains", "tableRow").isEmpty()
                || !array(legacy, "arrayOfChainSources").isEmpty() || !array(legacy, "arrayOfSVs").isEmpty();
        for (JsonObject source : activeInOrder(legacy, "arrayOfUsers", "tableRow")) {
            JsonObject user = named(source, userNames);
            user.addProperty("enabled", flag(source, "enabled", true));
            copyOptional(source, user, "cookiesBase64");
            if (source.has("headersBase64")) {
                user.add("headersBase64", array(source, "headersBase64"));
            } else if (source.has("headerBase64") && !source.get("headerBase64").isJsonNull()) {
                JsonArray headers = new JsonArray();
                headers.add(source.get("headerBase64"));
                user.add("headersBase64", headers);
            }
            user.add("roles", remap(source, "roles", roleNames, Function.identity()));
            skippedChainData |= !object(source, "chainResults").isEmpty();
            users.add(user);
        }
        for (JsonObject source : activeInOrder(legacy, "arrayOfMessages", "tableRow")) {
            JsonObject row = new JsonObject();
            row.addProperty("type", "message");
            row.addProperty("name", text(source, "name"));
            row.addProperty("host", text(source, "host"));
            int port = number(source, "port");
            String protocol = text(source, "protocol");
            if (port < 1 || port > 65535 || !(protocol.equals("http") || protocol.equals("https"))) {
                throw new IllegalArgumentException();
            }
            row.addProperty("port", port);
            row.addProperty("secure", protocol.equals("https"));
            row.addProperty("enabled", flag(source, "enabled", true));
            row.addProperty("failureRegexMode", flag(source, "failureRegexMode", false));
            row.addProperty("requestBase64", httpBytes(text(source, "requestBase64")));
            copyOptional(source, row, "regexBase64");
            row.add("roles", remap(source, "roles", roleNames, Function.identity()));
            row.add("userRuns", remap(source, "runBase64ForUserID", userNames, LegacyState::run));
            rows.add(row);
        }
        return new Converted(state, skippedChainData);
    }

    private static JsonObject run(JsonElement value) {
        JsonObject source = value.getAsJsonObject();
        JsonObject run = new JsonObject();
        for (String key : List.of("request", "response")) {
            if (source.has(key) && !source.get(key).isJsonNull()) {
                run.addProperty(key + "Base64", httpBytes(text(source, key)));
            }
        }
        return run;
    }

    private static String httpBytes(String encoded) {
        // Python saved Jython StringUtil's one-character-per-byte string as UTF-8 before Base64.
        try {
            byte[] utf8 = Base64.getDecoder().decode(encoded);
            var text = StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(utf8));
            ByteBuffer original = StandardCharsets.ISO_8859_1.newEncoder().encode(text);
            byte[] bytes = new byte[original.remaining()];
            original.get(bytes);
            return Base64.getEncoder().encodeToString(bytes);
        } catch (CharacterCodingException ex) {
            throw new IllegalArgumentException("Invalid legacy HTTP bytes", ex);
        }
    }

    private static JsonObject named(JsonObject source, Map<String, String> names) {
        String name = text(source, "name");
        if (names.putIfAbsent(Integer.toString(number(source, "index")), name) != null) {
            throw new IllegalArgumentException("Duplicate legacy index");
        }
        JsonObject row = new JsonObject();
        row.addProperty("name", name);
        return row;
    }

    private static JsonObject remap(JsonObject source, String key, Map<String, String> names,
                                    Function<JsonElement, JsonElement> convert) {
        JsonObject mapped = new JsonObject();
        object(source, key).entrySet().forEach(entry -> {
            String name = names.get(entry.getKey());
            if (name != null && !entry.getValue().isJsonNull()) mapped.add(name, convert.apply(entry.getValue()));
        });
        return mapped;
    }

    private static List<JsonObject> activeInOrder(JsonObject state, String key, String position) {
        List<JsonObject> active = new ArrayList<>();
        for (JsonElement item : array(state, key)) {
            JsonObject row = item.getAsJsonObject();
            if (!flag(row, "deleted", false)) active.add(row);
        }
        active.sort(Comparator.comparingInt(row -> row.has(position) ? number(row, position) : Integer.MAX_VALUE));
        return active;
    }

    private static String text(JsonObject object, String key) {
        if (!object.has(key) || !object.get(key).isJsonPrimitive() || !object.getAsJsonPrimitive(key).isString()) {
            throw new IllegalArgumentException("Missing legacy text field: " + key);
        }
        return object.get(key).getAsString();
    }

    private static int number(JsonObject object, String key) {
        return Integer.parseInt(object.get(key).getAsString());
    }

    private static JsonArray array(JsonObject object, String key) {
        return object.has(key) ? object.getAsJsonArray(key) : new JsonArray();
    }

    private static JsonObject object(JsonObject object, String key) {
        return object.has(key) ? object.getAsJsonObject(key) : new JsonObject();
    }

    private static boolean flag(JsonObject object, String key, boolean fallback) {
        return object.has(key) && !object.get(key).isJsonNull() ? object.get(key).getAsBoolean() : fallback;
    }

    private static void copyOptional(JsonObject from, JsonObject to, String key) {
        if (from.has(key) && !from.get(key).isJsonNull()) to.addProperty(key, text(from, key));
    }
}
