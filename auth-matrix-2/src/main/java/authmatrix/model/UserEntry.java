package authmatrix.model;

import java.util.*;

public class UserEntry {
    private String name;
    private String cookies;
    private final List<String> headers;
    private boolean enabled;
    private final Map<RoleEntry, Boolean> roles = new LinkedHashMap<>();

    public UserEntry(String name, int headerCount) {
        this.name = name;
        this.cookies = "";
        this.headers = new ArrayList<>(Collections.nCopies(headerCount, ""));
        this.enabled = true;
    }

    public UserEntry(String name, String cookies, List<String> headers, boolean enabled) {
        this.name = name;
        this.cookies = cookies;
        this.headers = new ArrayList<>(headers);
        this.enabled = enabled;
    }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getCookies() { return cookies; }
    public void setCookies(String cookies) { this.cookies = cookies; }
    public List<String> getHeaders() { return headers; }
    public boolean isEnabled() { return enabled; }
    public void toggleEnabled() { this.enabled = !this.enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public Map<RoleEntry, Boolean> getRoles() { return roles; }

    public boolean hasRole(RoleEntry role) {
        return Boolean.TRUE.equals(roles.get(role));
    }

    public void setRole(RoleEntry role, boolean value) {
        roles.put(role, value);
    }

    public void ensureHeaderCount(int count) {
        while (headers.size() < count) headers.add("");
    }
}
