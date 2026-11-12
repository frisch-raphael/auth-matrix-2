package authmatrix.model;

import java.util.*;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Collectors;

public class MatrixDB {
    private final List<UserEntry> users = new ArrayList<>();
    private final List<RoleEntry> roles = new ArrayList<>();
    // Mixed list: SectionEntry (headers) and MessageEntry (requests) in display order
    private final List<Object> rows = new ArrayList<>();
    private int headerCount = 0;
    private final List<String> knownRegexes = new ArrayList<>();
    private final ReentrantLock lock = new ReentrantLock();
    private int nextMessageId = 0;

    public static final String SINGLE_USER_SUFFIX = " (only)";

    public ReentrantLock getLock() { return lock; }
    public List<UserEntry> getUsers() { return users; }
    public List<Object> getRows() { return rows; }
    public int getHeaderCount() { return headerCount; }
    public List<String> getKnownRegexes() { return knownRegexes; }

    /** All MessageEntry objects in row order (skipping section headers). */
    public List<MessageEntry> getMessages() {
        return rows.stream().filter(r -> r instanceof MessageEntry)
                .map(r -> (MessageEntry) r).collect(Collectors.toList());
    }

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
            RoleEntry singleRole = getOrCreateRoleInternal(name + SINGLE_USER_SUFFIX, true);
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
            if (!users.remove(user)) return;
            RoleEntry ownRole = findRoleByName(user.getName() + SINGLE_USER_SUFFIX);
            if (ownRole != null && ownRole.isSingleUser()) deleteRole(ownRole);
            for (MessageEntry msg : getMessages()) {
                msg.getUserRuns().remove(user);
                msg.getRoleResults().clear();
            }
        } finally { lock.unlock(); }
    }

    public void renameUser(UserEntry user, String name) {
        lock.lock();
        try {
            name = name == null ? "" : name.trim();
            if (name.isEmpty()) throw new IllegalArgumentException("Enter a user name.");
            UserEntry duplicate = findUserByName(name);
            if (duplicate != null && duplicate != user) throw new IllegalArgumentException("A user already has that name.");
            RoleEntry own = findRoleByName(user.getName() + SINGLE_USER_SUFFIX);
            RoleEntry conflict = findRoleByName(name + SINGLE_USER_SUFFIX);
            if (conflict != null && conflict != own) throw new IllegalArgumentException("A role already uses that user name.");
            if (own != null && own.isSingleUser()) own.setName(name + SINGLE_USER_SUFFIX);
            user.setName(name);
        } finally { lock.unlock(); }
    }

    public UserEntry duplicateUser(UserEntry source) {
        lock.lock();
        try {
            int number = 1;
            String name;
            do { name = source.getName() + (number == 1 ? " (copy)" : " (copy " + number + ")"); number++; }
            while (findUserByName(name) != null || findRoleByName(name + SINGLE_USER_SUFFIX) != null);
            UserEntry copy = getOrCreateUser(name);
            copy.setCookies(source.getCookies());
            copy.setEnabled(source.isEnabled());
            for (int i = 0; i < headerCount; i++) copy.getHeaders().set(i, source.getHeaders().get(i));
            RoleEntry originalOwn = findRoleByName(source.getName() + SINGLE_USER_SUFFIX);
            RoleEntry copyOwn = findRoleByName(name + SINGLE_USER_SUFFIX);
            for (RoleEntry role : roles) copy.setRole(role, role == copyOwn || role != originalOwn && source.hasRole(role));
            for (MessageEntry msg : getMessages()) msg.setRoleAuthorized(copyOwn, msg.isRoleAuthorized(originalOwn));
            return copy;
        } finally { lock.unlock(); }
    }

    /** Move selected users one place, retaining their relative order. */
    public void shiftUsers(List<UserEntry> selected, int direction) {
        lock.lock();
        try { shift(users, selected, direction); } finally { lock.unlock(); }
    }

    public void moveUsersBefore(List<UserEntry> selected, UserEntry before) {
        lock.lock();
        try {
            if (selected.contains(before)) return;
            List<UserEntry> ordered = users.stream().filter(selected::contains).toList();
            if (before != null && !users.contains(before)) return;
            users.removeAll(ordered);
            users.addAll(before == null ? users.size() : users.indexOf(before), ordered);
        } finally { lock.unlock(); }
    }

    private static <T> void shift(List<T> list, List<?> selected, int direction) {
        if (direction < 0) {
            for (int i = 1; i < list.size(); i++)
                if (selected.contains(list.get(i)) && !selected.contains(list.get(i - 1))) Collections.swap(list, i, i - 1);
        } else {
            for (int i = list.size() - 2; i >= 0; i--)
                if (selected.contains(list.get(i)) && !selected.contains(list.get(i + 1))) Collections.swap(list, i, i + 1);
        }
    }

    // --- Roles ---

    public RoleEntry getOrCreateRole(String name) { return getOrCreateRole(name, false); }

    public RoleEntry getOrCreateRole(String name, boolean singleUser) {
        lock.lock();
        try { return getOrCreateRoleInternal(name, singleUser); } finally { lock.unlock(); }
    }

    private RoleEntry getOrCreateRoleInternal(String name, boolean singleUser) {
        for (RoleEntry r : roles) {
            if (r.getName().equals(name)) return r;
        }
        RoleEntry role = new RoleEntry(name, singleUser);
        if (!singleUser) {
            int insertAt = 0;
            for (int i = 0; i < roles.size(); i++) {
                if (!roles.get(i).isSingleUser()) insertAt = i + 1;
            }
            roles.add(insertAt, role);
        } else {
            roles.add(role);
        }
        for (UserEntry user : users) {
            boolean checked = singleUser && name.equals(user.getName() + SINGLE_USER_SUFFIX);
            user.setRole(role, checked);
        }
        for (MessageEntry msg : getMessages()) {
            msg.setRoleAuthorized(role, false);
        }
        return role;
    }

    public void deleteRole(RoleEntry role) {
        lock.lock();
        try {
            roles.remove(role);
            for (UserEntry user : users) user.getRoles().remove(role);
            for (MessageEntry msg : getMessages()) {
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
            for (RoleEntry role : roles) msg.setRoleAuthorized(role, false);
            if (regex != null && !regex.isEmpty() && !knownRegexes.contains(regex))
                knownRegexes.add(regex);
            rows.add(msg);
            return msg;
        } finally {
            lock.unlock();
        }
    }

    /** Create a message and place it at the end of a section's block. */
    public MessageEntry createMessageInSection(SectionEntry section, String host, int port, boolean secure,
                                                byte[] request, byte[] response, String name, String regex) {
        lock.lock();
        try {
            MessageEntry msg = new MessageEntry(nextMessageId++, name, host, port, secure, request, response, regex);
            for (RoleEntry role : roles) msg.setRoleAuthorized(role, false);
            if (regex != null && !regex.isEmpty() && !knownRegexes.contains(regex)) knownRegexes.add(regex);
            // Insert after the last message in the section
            int sectionIdx = rows.indexOf(section);
            if (sectionIdx < 0) { rows.add(msg); return msg; }
            int insertAt = sectionIdx + 1;
            while (insertAt < rows.size() && rows.get(insertAt) instanceof MessageEntry) insertAt++;
            rows.add(insertAt, msg);
            return msg;
        } finally {
            lock.unlock();
        }
    }

    public void deleteMessage(MessageEntry msg) {
        lock.lock();
        try { rows.remove(msg); } finally { lock.unlock(); }
    }

    // --- Sections ---

    public List<SectionEntry> getSections() {
        return rows.stream().filter(r -> r instanceof SectionEntry)
                .map(r -> (SectionEntry) r).collect(Collectors.toList());
    }

    public SectionEntry createSection(String name) {
        lock.lock();
        try {
            SectionEntry section = new SectionEntry(name);
            rows.add(section);
            return section;
        } finally {
            lock.unlock();
        }
    }

    /** Removing a section keeps its requests explicitly at root, never in the preceding section. */
    public void deleteSection(SectionEntry section) { deleteSection(section, false); }

    public void deleteSection(SectionEntry section, boolean deleteRequests) {
        lock.lock();
        try {
            if (!rows.contains(section)) return;
            List<MessageEntry> messages = getMessagesInSection(section);
            rows.removeAll(messages);
            rows.remove(section);
            if (!deleteRequests) rows.addAll(getRootMessages().size(), messages);
        } finally { lock.unlock(); }
    }

    /** Reorder a complete section block while keeping root requests at root. */
    public void moveSection(SectionEntry section, int index) {
        lock.lock();
        try {
            if (!rows.contains(section)) return;
            int start = rows.indexOf(section), end = start + 1;
            while (end < rows.size() && rows.get(end) instanceof MessageEntry) end++;
            List<Object> block = new ArrayList<>(rows.subList(start, end));
            rows.subList(start, end).clear();
            List<SectionEntry> remaining = getSections();
            index = Math.max(0, Math.min(index, remaining.size()));
            int insertAt = index == remaining.size() ? rows.size() : rows.indexOf(remaining.get(index));
            rows.addAll(insertAt, block);
        } finally { lock.unlock(); }
    }

    public void moveMessagesToSection(List<MessageEntry> selected, SectionEntry target, MessageEntry before) {
        lock.lock();
        try {
            if (target != null && !rows.contains(target) || selected.contains(before)) return;
            if (before != null && (!rows.contains(before) || getSectionForMessage(before) != target)) return;
            List<MessageEntry> ordered = getMessages().stream().filter(selected::contains).toList();
            rows.removeAll(ordered);
            int insertAt;
            if (before != null) insertAt = rows.indexOf(before);
            else if (target == null) insertAt = getRootMessages().size();
            else insertAt = rows.indexOf(target) + 1 + getMessagesInSection(target).size();
            rows.addAll(insertAt, ordered);
        } finally { lock.unlock(); }
    }

    public void shiftMessages(List<MessageEntry> selected, int direction) {
        lock.lock();
        try {
            List<SectionEntry> sections = new ArrayList<>(); sections.add(null); sections.addAll(getSections());
            for (SectionEntry section : sections) {
                List<MessageEntry> messages = section == null ? getRootMessages() : getMessagesInSection(section);
                if (messages.isEmpty()) continue;
                int start = rows.indexOf(messages.getFirst());
                shift(messages, selected, direction);
                for (int i = 0; i < messages.size(); i++) rows.set(start + i, messages.get(i));
            }
        } finally { lock.unlock(); }
    }

    public MessageEntry duplicateMessage(MessageEntry source) {
        lock.lock();
        try {
            MessageEntry copy = new MessageEntry(nextMessageId++, source.getName() + " (copy)", source.getHost(),
                    source.getPort(), source.isSecure(), source.getRequest() == null ? null : source.getRequest().clone(),
                    source.getResponse() == null ? null : source.getResponse().clone(), source.getRegex());
            copy.setEnabled(source.isEnabled()); copy.setFailureRegexMode(source.isFailureRegexMode());
            for (RoleEntry role : roles) copy.setRoleAuthorized(role, source.isRoleAuthorized(role));
            rows.add(rows.indexOf(source) + 1, copy);
            return copy;
        } finally { lock.unlock(); }
    }

    public SectionEntry findSectionByName(String name) {
        for (SectionEntry s : getSections()) {
            if (s.getName().equals(name)) return s;
        }
        return null;
    }

    /** Get the section a message belongs to (the nearest SectionEntry above it, or null). */
    public SectionEntry getSectionForMessage(MessageEntry msg) {
        SectionEntry current = null;
        for (Object row : rows) {
            if (row instanceof SectionEntry s) current = s;
            if (row == msg) return current;
        }
        return null;
    }

    /** Get messages not in any section (before the first SectionEntry). */
    public List<MessageEntry> getRootMessages() {
        List<MessageEntry> result = new ArrayList<>();
        for (Object row : rows) {
            if (row instanceof SectionEntry) break;
            if (row instanceof MessageEntry m) result.add(m);
        }
        return result;
    }

    /** Get all messages under a section header (between it and the next section/end). */
    public List<MessageEntry> getMessagesInSection(SectionEntry section) {
        List<MessageEntry> result = new ArrayList<>();
        boolean inSection = false;
        for (Object row : rows) {
            if (row instanceof SectionEntry s) {
                if (s == section) { inSection = true; continue; }
                else if (inSection) break;
            }
            if (inSection && row instanceof MessageEntry m) result.add(m);
        }
        return result;
    }

    /** Check if any message already covers this URL path. */
    public boolean hasPath(String path) {
        if (path == null) return false;
        for (MessageEntry msg : getMessages()) {
            if (msg.getRequest() == null) continue;
            // Extract path from stored request name (format: "METHOD  /path")
            String name = msg.getName();
            int space = name.indexOf('/');
            if (space >= 0) {
                String existingPath = name.substring(space);
                if (existingPath.equals(path)) return true;
            }
        }
        return false;
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
                    if (headerIndex < user.getHeaders().size()) user.getHeaders().remove(headerIndex);
                }
                headerCount--;
            }
        } finally {
            lock.unlock();
        }
    }

    // --- Regexes ---

    public void addRegexIfNew(String regex) {
        if (regex != null && !regex.isEmpty() && !knownRegexes.contains(regex)) knownRegexes.add(regex);
    }

    // --- Bulk operations ---

    public void setRoleForAllSelectedMessages(List<MessageEntry> messages, RoleEntry role, boolean value) {
        lock.lock();
        try { for (MessageEntry msg : messages) msg.setRoleAuthorized(role, value); } finally { lock.unlock(); }
    }

    public void clear() {
        lock.lock();
        try {
            users.clear();
            roles.clear();
            rows.clear();
            SectionEntry.resetColorIndex();
            headerCount = 0;
            knownRegexes.clear();
            nextMessageId = 0;
        } finally {
            lock.unlock();
        }
    }

    public void replaceWith(MatrixDB source) {
        lock.lock();
        try {
            clear();
            users.addAll(source.users);
            roles.addAll(source.roles);
            rows.addAll(source.rows);
            headerCount = source.headerCount;
            knownRegexes.addAll(source.knownRegexes);
            nextMessageId = source.nextMessageId;
        } finally { lock.unlock(); }
    }

    public void setNextMessageId(int id) { this.nextMessageId = id; }
    public void setHeaderCount(int count) { this.headerCount = count; }

    public void addRoleDirect(RoleEntry role) { roles.add(role); }
    public void addUserDirect(UserEntry user) { users.add(user); }
    public void addMessageDirect(MessageEntry msg) { rows.add(msg); }
    public void addSectionDirect(SectionEntry section) { rows.add(section); }
}
