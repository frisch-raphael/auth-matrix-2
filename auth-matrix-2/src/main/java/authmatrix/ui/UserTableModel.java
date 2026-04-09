package authmatrix.ui;

import authmatrix.model.*;
import javax.swing.table.AbstractTableModel;
import java.util.List;

public class UserTableModel extends AbstractTableModel {
    private final MatrixDB db;

    // Fixed columns: Name, Cookies
    private static final int COL_NAME = 0;
    private static final int COL_COOKIES = 1;
    private static final int STATIC_COLS = 2;

    public UserTableModel(MatrixDB db) {
        this.db = db;
    }

    @Override
    public int getRowCount() {
        return db.getUsers().size();
    }

    @Override
    public int getColumnCount() {
        return STATIC_COLS + db.getHeaderCount() + db.getRegularRoles().size();
    }

    @Override
    public String getColumnName(int col) {
        if (col == COL_NAME) return "User Name";
        if (col == COL_COOKIES) return "Cookies";
        int headerIdx = col - STATIC_COLS;
        if (headerIdx >= 0 && headerIdx < db.getHeaderCount()) return "HTTP Header";
        RoleEntry role = getRoleForColumn(col);
        return role != null ? role.getName() : "";
    }

    @Override
    public Object getValueAt(int row, int col) {
        UserEntry user = db.getUsers().get(row);
        if (col == COL_NAME) return user.getName();
        if (col == COL_COOKIES) return user.getCookies();
        int headerIdx = col - STATIC_COLS;
        if (headerIdx >= 0 && headerIdx < db.getHeaderCount()) {
            return headerIdx < user.getHeaders().size() ? user.getHeaders().get(headerIdx) : "";
        }
        RoleEntry role = getRoleForColumn(col);
        return role != null && user.hasRole(role);
    }

    @Override
    public void setValueAt(Object val, int row, int col) {
        if (db.getLock().isLocked()) return;
        UserEntry user = db.getUsers().get(row);
        if (col == COL_NAME) {
            String newName = (String) val;
            if (db.findUserByName(newName) == null) {
                // Rename single-user role too
                RoleEntry singleRole = db.findRoleByName(user.getName() + MatrixDB.SINGLE_USER_SUFFIX);
                if (singleRole != null) singleRole.setName(newName + MatrixDB.SINGLE_USER_SUFFIX);
                user.setName(newName);
            }
        } else if (col == COL_COOKIES) {
            user.setCookies((String) val);
        } else {
            int headerIdx = col - STATIC_COLS;
            if (headerIdx >= 0 && headerIdx < db.getHeaderCount()) {
                user.getHeaders().set(headerIdx, (String) val);
            } else {
                RoleEntry role = getRoleForColumn(col);
                if (role != null) user.setRole(role, (Boolean) val);
            }
        }
        fireTableCellUpdated(row, col);
    }

    @Override
    public boolean isCellEditable(int row, int col) {
        return true;
    }

    @Override
    public Class<?> getColumnClass(int col) {
        if (col < STATIC_COLS + db.getHeaderCount()) return String.class;
        return Boolean.class;
    }

    public RoleEntry getRoleForColumn(int col) {
        int roleIdx = col - STATIC_COLS - db.getHeaderCount();
        List<RoleEntry> regular = db.getRegularRoles();
        if (roleIdx >= 0 && roleIdx < regular.size()) return regular.get(roleIdx);
        return null;
    }

    public boolean isRoleColumn(int col) {
        return col >= STATIC_COLS + db.getHeaderCount();
    }

    public boolean isHeaderColumn(int col) {
        int headerIdx = col - STATIC_COLS;
        return headerIdx >= 0 && headerIdx < db.getHeaderCount();
    }
}
