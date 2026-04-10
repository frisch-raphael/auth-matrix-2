package authmatrix.ui;

import authmatrix.model.*;
import authmatrix.RunEngine;
import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * Table model for a single section's (or root's) messages.
 * Shares column logic with MessageTableModel constants.
 */
public class SectionMessageTableModel extends AbstractTableModel {
    private final MatrixDB db;
    private List<MessageEntry> messages = new ArrayList<>();

    public SectionMessageTableModel(MatrixDB db) {
        this.db = db;
    }

    public void setMessages(List<MessageEntry> messages) {
        this.messages = new ArrayList<>(messages);
        fireTableDataChanged();
    }

    public List<MessageEntry> getMessageList() { return messages; }

    @Override public int getRowCount() { return messages.size(); }

    @Override public int getColumnCount() {
        return MessageTableModel.STATIC_COLS + db.getAllRoles().size();
    }

    @Override public String getColumnName(int col) {
        if (col == MessageTableModel.COL_ID) return "ID";
        if (col == MessageTableModel.COL_NAME) return "Request Name";
        if (col == MessageTableModel.COL_REGEX) return "Response Regex";
        RoleEntry role = getRoleForColumn(col);
        return role != null ? role.getName() : "";
    }

    @Override public Object getValueAt(int row, int col) {
        MessageEntry msg = messages.get(row);
        if (col == MessageTableModel.COL_ID) return String.valueOf(msg.getId());
        if (col == MessageTableModel.COL_NAME) return msg.getName();
        if (col == MessageTableModel.COL_REGEX) return msg.getRegex();
        RoleEntry role = getRoleForColumn(col);
        return role != null && msg.isRoleAuthorized(role);
    }

    @Override public void setValueAt(Object val, int row, int col) {
        if (db.getLock().isLocked()) return;
        MessageEntry msg = messages.get(row);
        if (col == MessageTableModel.COL_NAME) {
            msg.setName((String) val);
        } else if (col == MessageTableModel.COL_REGEX) {
            msg.setRegex((String) val);
            db.addRegexIfNew((String) val);
            msg.clearResults();
            fireRoleColumnsUpdated(row);
        } else if (col >= MessageTableModel.STATIC_COLS) {
            RoleEntry role = getRoleForColumn(col);
            if (role != null) {
                msg.setRoleAuthorized(role, (Boolean) val);
                if (!msg.getUserRuns().isEmpty()) {
                    // Remember which roles had results before, re-evaluate, then remove any newly added
                    java.util.Set<RoleEntry> previouslyEvaluated = new java.util.HashSet<>(msg.getRoleResults().keySet());
                    RunEngine.evaluateRoleResults(db, msg);
                    msg.getRoleResults().keySet().retainAll(previouslyEvaluated);
                }
                fireRoleColumnsUpdated(row);
            }
        }
        fireTableCellUpdated(row, col);
    }

    @Override public boolean isCellEditable(int row, int col) {
        return col >= MessageTableModel.COL_NAME;
    }

    @Override public Class<?> getColumnClass(int col) {
        return col < MessageTableModel.STATIC_COLS ? String.class : Boolean.class;
    }

    public RoleEntry getRoleForColumn(int col) {
        int roleIdx = col - MessageTableModel.STATIC_COLS;
        List<RoleEntry> allRoles = db.getAllRoles();
        if (roleIdx >= 0 && roleIdx < allRoles.size()) return allRoles.get(roleIdx);
        return null;
    }

    public boolean isRoleColumn(int col) { return col >= MessageTableModel.STATIC_COLS; }

    public MessageEntry getMessageAt(int row) {
        return (row >= 0 && row < messages.size()) ? messages.get(row) : null;
    }

    private void fireRoleColumnsUpdated(int row) {
        for (int i = MessageTableModel.STATIC_COLS; i < getColumnCount(); i++)
            fireTableCellUpdated(row, i);
    }
}
