package authmatrix.model;

public class RoleEntry {
    private String name;
    private final boolean singleUser;

    public RoleEntry(String name, boolean singleUser) {
        this.name = name;
        this.singleUser = singleUser;
    }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public boolean isSingleUser() { return singleUser; }
}
