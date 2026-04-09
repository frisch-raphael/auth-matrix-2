package authmatrix.model;

import java.util.*;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Collectors;

public class MatrixDB {
    private final List<UserEntry> users = new ArrayList<>();
    private final List<RoleEntry> roles = new ArrayList<>();
    private final List<MessageEntry> messages = new ArrayList<>();
    private int headerCount = 0;
    private final List<String> knownRegexes = new ArrayList<>();
    private final ReentrantLock lock = new ReentrantLock();
    private int nextMessageId = 0;

    public static final String SINGLE_USER_SUFFIX = " (only)";

    public ReentrantLock getLock() { return lock; }
    public List<UserEntry> getUsers() { return users; }
    public List<MessageEntry> getMessages() { return messages; }
    public int getHeaderCount() { return headerCount; }
    public List<String> getKnownRegexes() { return knownRegexes; }

    /** Regular roles first, then single-user roles. */
    public List<RoleEntry> getAllRoles() { return roles; }

    public List<RoleEntry> getRegularRoles() {
        return roles.stream().filter(r -> !r.isSingleUser()).collect(Collectors.toList());
    }

    public List<RoleEntry> getSingleUserRoles() {
        return roles.stream().filter(RoleEntry::isSingleUser).collect(Collectors.toList());
    }

    // --- Users ---

    public UserEntry getOrCreateUser(String name) {
        lock.lock();
        try {
            for (UserEntry u : users) {
                if (u.getName().equals(name)) return u;
            }
            UserEntry user = new UserEntry(name, headerCount);
            users.add(user);

            // Create single-user role
            RoleEntry singleRole = getOrCreateRoleInternal(name + SINGLE_USER_SUFFIX, true);

            // Assign all existing roles as unchecked, except the single-user role
            for (RoleEntry role : roles) {
                user.setRole(role, role == singleRole);
            }
            return user;
        } finally {
            lock.unlock();
        }
    }

    public UserEntry findUserByName(String name) {
        for (UserEntry u : users) {
            if (u.getName().equals(name)) return u;
        }
        return null;
    }

    public void deleteUser(UserEntry user) {
        lock.lock();
        try {
            users.remove(user);
        } finally {
            lock.unlock();
        }
    }

    public void moveUser(int fromIndex, int toIndex) {
        lock.lock();
        try {
            if (fromIndex < 0 || fromIndex >= users.size()) return;
            if (toIndex < 0) toIndex = 0;
            if (toIndex > users.size()) toIndex = users.size();
            UserEntry user = users.remove(fromIndex);
            if (toIndex > fromIndex) toIndex--;
            users.add(toIndex, user);
        } finally {
            lock.unlock();
        }
    }

    // --- Roles ---

    public RoleEntry getOrCreateRole(String name) {
        return getOrCreateRole(name, false);
    }

    public RoleEntry getOrCreateRole(String name, boolean singleUser) {
        lock.lock();
        try {
            return getOrCreateRoleInternal(name, singleUser);
        } finally {
            lock.unlock();
        }
    }

    private RoleEntry getOrCreateRoleInternal(String name, boolean singleUser) {
        for (RoleEntry r : roles) {
            if (r.getName().equals(name)) return r;
        }
        RoleEntry role = new RoleEntry(name, singleUser);

        // Insert: regular roles before single-user roles
        if (!singleUser) {
            int insertAt = 0;
            for (int i = 0; i < roles.size(); i++) {
                if (!roles.get(i).isSingleUser()) insertAt = i + 1;
            }
            roles.add(insertAt, role);
        } else {
            roles.add(role);
        }

        // Add to all existing users (unchecked, unless it's their own single-user role)
        for (UserEntry user : users) {
            boolean checked = singleUser && name.equals(user.getName() + SINGLE_USER_SUFFIX);
            user.setRole(role, checked);
        }
        // Add to all existing messages (unchecked)
        for (MessageEntry msg : messages) {
            msg.setRoleAuthorized(role, false);
        }
        return role;
    }

    public void deleteRole(RoleEntry role) {
        lock.lock();
        try {
            roles.remove(role);
            for (UserEntry user : users) user.getRoles().remove(role);
            for (MessageEntry msg : messages) {
                msg.getAuthorizedRoles().remove(role);
                msg.getRoleResults().remove(role);
            }
        } finally {
            lock.unlock();
        }
    }

    public RoleEntry findRoleByName(String name) {
        for (RoleEntry r : roles) {
            if (r.getName().equals(name)) return r;
        }
        return null;
    }

    // --- Messages ---

    public MessageEntry createMessage(String host, int port, boolean secure,
                                       byte[] request, byte[] response,
                                       String name, String regex) {
        lock.lock();
        try {
            MessageEntry msg = new MessageEntry(nextMessageId++, name, host, port, secure,
                    request, response, regex);
            for (RoleEntry role : roles) {
                msg.setRoleAuthorized(role, false);
            }
            if (regex != null && !regex.isEmpty() && !knownRegexes.contains(regex)) {
                knownRegexes.add(regex);
            }
            messages.add(msg);
            return msg;
        } finally {
            lock.unlock();
        }
    }

    public void deleteMessage(MessageEntry msg) {
        lock.lock();
        try {
            messages.remove(msg);
        } finally {
            lock.unlock();
        }
    }

    public void moveMessage(int fromIndex, int toIndex) {
        lock.lock();
        try {
            if (fromIndex < 0 || fromIndex >= messages.size()) return;
            if (toIndex < 0) toIndex = 0;
            if (toIndex > messages.size()) toIndex = messages.size();
            MessageEntry msg = messages.remove(fromIndex);
            if (toIndex > fromIndex) toIndex--;
            messages.add(toIndex, msg);
        } finally {
            lock.unlock();
        }
    }

    // --- Headers ---

    public void addHeader() {
        lock.lock();
        try {
            headerCount++;
            for (UserEntry user : users) user.ensureHeaderCount(headerCount);
        } finally {
            lock.unlock();
        }
    }

    public void deleteHeader(int headerIndex) {
        lock.lock();
        try {
            if (headerIndex >= 0 && headerIndex < headerCount) {
                for (UserEntry user : users) {
                    if (headerIndex < user.getHeaders().size()) {
                        user.getHeaders().remove(headerIndex);
                    }
                }
                headerCount--;
            }
        } finally {
            lock.unlock();
        }
    }

    // --- Regexes ---

    public void addRegexIfNew(String regex) {
        if (regex != null && !regex.isEmpty() && !knownRegexes.contains(regex)) {
            knownRegexes.add(regex);
        }
    }

    // --- Bulk operations ---

    public void setRoleForAllSelectedMessages(List<MessageEntry> messages, RoleEntry role, boolean value) {
        lock.lock();
        try {
            for (MessageEntry msg : messages) {
                msg.setRoleAuthorized(role, value);
            }
        } finally {
            lock.unlock();
        }
    }

    public void clear() {
        lock.lock();
        try {
            users.clear();
            roles.clear();
            messages.clear();
            headerCount = 0;
            knownRegexes.clear();
            nextMessageId = 0;
        } finally {
            lock.unlock();
        }
    }

    public void setNextMessageId(int id) {
        this.nextMessageId = id;
    }

    public void setHeaderCount(int count) {
        this.headerCount = count;
    }

    /** Add a role and user directly (used by StateManager during load). */
    public void addRoleDirect(RoleEntry role) { roles.add(role); }
    public void addUserDirect(UserEntry user) { users.add(user); }
    public void addMessageDirect(MessageEntry msg) { messages.add(msg); }
}
