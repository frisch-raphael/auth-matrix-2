package authmatrix;

import authmatrix.model.*;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.core.ByteArray;

import java.util.*;
import java.util.function.Consumer;
import java.util.regex.*;

public class RunEngine {
    private static final long REQUEST_TIMEOUT_MS = 10_000;
    private static final String RANDOM_PLACEHOLDER = "#{AUTHMATRIX:RANDOM}";

    private final MontoyaApi api;
    private final MatrixDB db;
    private volatile boolean cancelled;

    public RunEngine(MontoyaApi api, MatrixDB db) {
        this.api = api;
        this.db = db;
    }

    public void cancel() { cancelled = true; }

    /**
     * Run messages. If messagesToRun is null, runs all enabled messages.
     * Callbacks are invoked on the calling thread (expected to be a background thread).
     */
    public void run(List<MessageEntry> messagesToRun, Consumer<Boolean> onRunningChanged, Runnable onComplete) {
        db.getLock().lock();
        try {
            onRunningChanged.accept(true);
            cancelled = false;

            List<MessageEntry> targets = messagesToRun != null
                    ? messagesToRun
                    : new ArrayList<>(db.getMessages());

            // Clear previous results for targeted messages
            for (MessageEntry msg : targets) msg.clearResults();

            for (MessageEntry msg : db.getMessages()) {
                if (cancelled) break;
                if (!targets.contains(msg) || !msg.isEnabled()) continue;
                runMessage(msg);
            }
        } catch (Exception e) {
            api.logging().logToError("Run error: " + e.getMessage());
        } finally {
            onRunningChanged.accept(false);
            db.getLock().unlock();
            onComplete.run();
        }
    }

    private void runMessage(MessageEntry msg) {
        msg.clearResults();

        for (UserEntry user : db.getUsers()) {
            if (cancelled) return;
            if (!user.isEnabled()) continue;

            HttpRequest request = buildModifiedRequest(msg, user);
            byte[] sentRequest = request.toByteArray().getBytes();
            byte[] responseBytes = null;

            try {
                // Send with timeout
                HttpRequestResponse[] result = { null };
                Thread sender = new Thread(() -> {
                    try {
                        result[0] = api.http().sendRequest(request);
                    } catch (RuntimeException ex) {
                        api.logging().logToError("Request error for #" + msg.getId() + ": " + ex.getMessage());
                    }
                });
                sender.start();
                sender.join(REQUEST_TIMEOUT_MS);

                if (sender.isAlive()) {
                    api.logging().logToOutput("Timeout for Request #" + msg.getId() + " / User " + user.getName());
                } else if (result[0] != null && result[0].response() != null) {
                    responseBytes = result[0].response().toByteArray().getBytes();
                    sentRequest = result[0].request().toByteArray().getBytes();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }

            msg.addRunResult(user, sentRequest, responseBytes);
        }

        // Evaluate role results
        List<RoleEntry> authorizedRoles = new ArrayList<>();
        for (RoleEntry role : db.getAllRoles()) {
            if (msg.isRoleAuthorized(role)) authorizedRoles.add(role);
        }
        for (RoleEntry role : db.getAllRoles()) {
            boolean passed = checkResult(msg, role, authorizedRoles);
            msg.setRoleResult(role, passed);
        }
    }

    /**
     * Build a modified request with user's cookies and custom headers substituted.
     */
    private HttpRequest buildModifiedRequest(MessageEntry msg, UserEntry user) {
        HttpRequest request = HttpRequest.httpRequest(
                HttpService.httpService(msg.getHost(), msg.getPort(), msg.isSecure()),
                ByteArray.byteArray(msg.getRequest()));

        // Substitute cookies
        String userCookies = user.getCookies();
        if (userCookies != null && !userCookies.isEmpty()) {
            String existingCookies = "";
            for (HttpHeader h : request.headers()) {
                if (h.name().equalsIgnoreCase("Cookie")) {
                    existingCookies = h.value();
                    break;
                }
            }
            String merged = mergeCookies(existingCookies, userCookies);
            request = request.withRemovedHeader("Cookie")
                             .withAddedHeader(HttpHeader.httpHeader("Cookie", merged));
        }

        // Substitute custom headers
        for (String header : user.getHeaders()) {
            if (header == null || header.trim().isEmpty()) continue;
            int colon = header.indexOf(':');
            if (colon > 0) {
                String name = header.substring(0, colon).trim();
                String value = header.substring(colon + 1).trim();
                request = request.withRemovedHeader(name)
                                 .withAddedHeader(HttpHeader.httpHeader(name, value));
            }
        }

        // Random placeholder replacement
        String requestStr = new String(request.toByteArray().getBytes());
        if (requestStr.contains(RANDOM_PLACEHOLDER)) {
            String random = String.format("%04d", new Random().nextInt(10000));
            requestStr = requestStr.replace(RANDOM_PLACEHOLDER, random);
            request = HttpRequest.httpRequest(request.httpService(),
                    ByteArray.byteArray(requestStr.getBytes()));
        }

        return request;
    }

    /**
     * Evaluate whether the results for a given role meet expectations.
     * Returns true if all users exclusively in this role behaved as expected.
     */
    private boolean checkResult(MessageEntry msg, RoleEntry role, List<RoleEntry> authorizedRoles) {
        for (UserEntry user : db.getUsers()) {
            if (!user.isEnabled()) continue;
            if (!user.hasRole(role)) continue;

            // Skip users who belong to any OTHER authorized role (can't isolate this role's effect)
            boolean inOtherAuthorizedRole = false;
            for (RoleEntry otherRole : db.getAllRoles()) {
                if (otherRole != role && user.hasRole(otherRole) && authorizedRoles.contains(otherRole)) {
                    inOtherAuthorizedRole = true;
                    break;
                }
            }
            if (inOtherAuthorizedRole) continue;

            MessageEntry.RunResult run = msg.getUserRuns().get(user);
            if (run == null) return false;
            if (run.response() == null) return false;

            String response = new String(run.response());
            boolean regexFound = false;
            try {
                regexFound = Pattern.compile(msg.getRegex(), Pattern.DOTALL).matcher(response).find();
            } catch (PatternSyntaxException e) {
                // Bad regex -> treat as not found
            }

            boolean roleIsAuthorized = authorizedRoles.contains(role);
            // In failure regex mode, the regex detects UNAUTHORIZED access
            boolean shouldSucceed = msg.isFailureRegexMode() ? !roleIsAuthorized : roleIsAuthorized;
            boolean succeeded = shouldSucceed ? regexFound : !regexFound;

            if (!succeeded) return false;
        }
        return true;
    }

    // --- Static utilities ---

    /**
     * Merge two cookie strings, with newCookies overriding matching names in oldCookies.
     */
    public static String mergeCookies(String oldCookies, String newCookies) {
        Map<String, String> cookieMap = new LinkedHashMap<>();
        parseCookies(oldCookies, cookieMap);
        parseCookies(newCookies, cookieMap);  // new values override old
        StringBuilder sb = new StringBuilder();
        for (var entry : cookieMap.entrySet()) {
            if (sb.length() > 0) sb.append("; ");
            sb.append(entry.getKey()).append("=").append(entry.getValue());
        }
        return sb.toString();
    }

    private static void parseCookies(String cookieStr, Map<String, String> out) {
        if (cookieStr == null || cookieStr.isEmpty()) return;
        for (String part : cookieStr.split(";")) {
            String trimmed = part.trim();
            int eq = trimmed.indexOf('=');
            if (eq > 0) {
                out.put(trimmed.substring(0, eq).trim(), trimmed.substring(eq + 1).trim());
            }
        }
    }

    /**
     * Replace the Host header in raw HTTP request bytes.
     */
    public static byte[] replaceHostHeader(byte[] requestBytes, String newHost) {
        String request = new String(requestBytes);
        // Replace existing Host header
        request = request.replaceFirst("(?im)^Host:.*$", "Host: " + newHost);
        return request.getBytes();
    }
}
