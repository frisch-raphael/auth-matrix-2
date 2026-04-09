package authmatrix.model;

import java.util.*;

public class MessageEntry {
    private final int id;
    private String name;
    private String regex;
    private boolean failureRegexMode;
    private boolean enabled;

    // Stored HTTP data
    private String host;
    private int port;
    private boolean secure;
    private byte[] request;
    private byte[] response;

    // Which roles are authorized (checked in the matrix)
    private final Map<RoleEntry, Boolean> authorizedRoles = new LinkedHashMap<>();

    // Run results per user
    private final Map<UserEntry, RunResult> userRuns = new LinkedHashMap<>();
    // Evaluated result per role (true = saw expected results)
    private final Map<RoleEntry, Boolean> roleResults = new LinkedHashMap<>();

    public MessageEntry(int id, String name, String host, int port, boolean secure,
                        byte[] request, byte[] response, String regex) {
        this.id = id;
        this.name = name;
        this.host = host;
        this.port = port;
        this.secure = secure;
        this.request = request;
        this.response = response;
        this.regex = regex;
        this.failureRegexMode = false;
        this.enabled = true;
    }

    public int getId() { return id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getRegex() { return regex; }
    public void setRegex(String regex) { this.regex = regex; }
    public boolean isFailureRegexMode() { return failureRegexMode; }
    public void setFailureRegexMode(boolean mode) { this.failureRegexMode = mode; }
    public void toggleFailureRegexMode() { this.failureRegexMode = !this.failureRegexMode; }
    public boolean isEnabled() { return enabled; }
    public void toggleEnabled() { this.enabled = !this.enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    public String getHost() { return host; }
    public void setHost(String host) { this.host = host; }
    public int getPort() { return port; }
    public void setPort(int port) { this.port = port; }
    public boolean isSecure() { return secure; }
    public void setSecure(boolean secure) { this.secure = secure; }
    public byte[] getRequest() { return request; }
    public void setRequest(byte[] request) { this.request = request; }
    public byte[] getResponse() { return response; }

    public Map<RoleEntry, Boolean> getAuthorizedRoles() { return authorizedRoles; }

    public boolean isRoleAuthorized(RoleEntry role) {
        return Boolean.TRUE.equals(authorizedRoles.get(role));
    }

    public void setRoleAuthorized(RoleEntry role, boolean authorized) {
        authorizedRoles.put(role, authorized);
    }

    public Map<UserEntry, RunResult> getUserRuns() { return userRuns; }
    public Map<RoleEntry, Boolean> getRoleResults() { return roleResults; }

    public void addRunResult(UserEntry user, byte[] request, byte[] response) {
        userRuns.put(user, new RunResult(request, response));
    }

    public void setRoleResult(RoleEntry role, boolean passed) {
        roleResults.put(role, passed);
    }

    public void clearResults() {
        userRuns.clear();
        roleResults.clear();
    }

    public record RunResult(byte[] request, byte[] response) {}
}
