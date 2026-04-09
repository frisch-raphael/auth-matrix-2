package authmatrix.ui;

import authmatrix.model.*;
import authmatrix.RunEngine;
import javax.swing.table.AbstractTableModel;
import java.util.List;

public class MessageTableModel extends AbstractTableModel {
    private final MatrixDB db;

    public static final int COL_ID = 0;
    public static final int COL_NAME = 1;
    public static final int COL_REGEX = 2;
    public static final int STATIC_COLS = 3;

    public MessageTableModel(MatrixDB db) {
        this.db = db;
    }

    @Override
    public int getRowCount() {
        return db.getMessages().size();
    }

    @Override
    public int getColumnCount() {
        return STATIC_COLS + db.getAllRoles().size();
    }

    @Override
    public String getColumnName(int col) {
        if (col == COL_ID) return "ID";
        if (col == COL_NAME) return "Request Name";
        if (col == COL_REGEX) return "Response Regex";
        RoleEntry role = getRoleForColumn(col);
        return role != null ? role.getName() : "";
    }

    @Override
    public Object getValueAt(int row, int col) {
        MessageEntry msg = db.getMessages().get(row);
        if (col == COL_ID) return String.valueOf(msg.getId());
        if (col == COL_NAME) return msg.getName();
        if (col == COL_REGEX) return msg.getRegex();
        RoleEntry role = getRoleForColumn(col);
        return role != null && msg.isRoleAuthorized(role);
    }

    @Override
    public void setValueAt(Object val, int row, int col) {
        if (db.getLock().isLocked()) return;
        MessageEntry msg = db.getMessages().get(row);
        if (col == COL_NAME) {
            msg.setName((String) val);
        } else if (col == COL_REGEX) {
            msg.setRegex((String) val);
            db.addRegexIfNew((String) val);
            // Clear results when regex changes
            msg.clearResults();
            fireRoleColumnsUpdated(row);
        } else if (col >= STATIC_COLS) {
            RoleEntry role = getRoleForColumn(col);
            if (role != null) {
                msg.setRoleAuthorized(role, (Boolean) val);
                // Re-evaluate colors if we have run results, rather than clearing them
                if (!msg.getUserRuns().isEmpty()) {
                    reEvaluateRoleResults(msg);
                }
                fireRoleColumnsUpdated(row);
            }
        }
        fireTableCellUpdated(row, col);
    }

    @Override
    public boolean isCellEditable(int row, int col) {
        return col >= COL_NAME; // ID is not editable
    }

    @Override
    public Class<?> getColumnClass(int col) {
        return col < STATIC_COLS ? String.class : Boolean.class;
    }

    public RoleEntry getRoleForColumn(int col) {
        int roleIdx = col - STATIC_COLS;
        List<RoleEntry> allRoles = db.getAllRoles();
        if (roleIdx >= 0 && roleIdx < allRoles.size()) return allRoles.get(roleIdx);
        return null;
    }

    public boolean isRoleColumn(int col) {
        return col >= STATIC_COLS;
    }

    private void reEvaluateRoleResults(MessageEntry msg) {
        RunEngine.evaluateRoleResults(db, msg);
    }

    private void fireRoleColumnsUpdated(int row) {
        for (int i = STATIC_COLS; i < getColumnCount(); i++) {
            fireTableCellUpdated(row, i);
        }
    }
}
