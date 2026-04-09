package authmatrix.ui;

import authmatrix.model.*;
import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableCellRenderer;
import java.awt.*;

public final class Renderers {

    private Renderers() {}

    // Colors matching the original AuthMatrix
    private static final Color GREEN           = new Color(0x87, 0xF7, 0x17);
    private static final Color GREEN_SELECTED  = new Color(0xC8, 0xE0, 0x51);
    private static final Color RED             = new Color(0xFF, 0x32, 0x17);
    private static final Color RED_SELECTED    = new Color(0xFF, 0x87, 0x51);
    private static final Color BLUE            = new Color(0x00, 0xCC, 0xFF);
    private static final Color BLUE_SELECTED   = new Color(0x8B, 0xCD, 0xBA);
    private static final Color DISABLED        = Color.GRAY;
    private static final Color DISABLED_SEL    = new Color(0xD1, 0xB5, 0xA3);
    private static final Color FAILURE_REGEX   = new Color(0x99, 0x99, 0xCC);

    /**
     * Renders role-result checkboxes in the message table with color coding:
     * Green = pass, Red = vulnerability, Blue = likely false positive, Gray = disabled.
     */
    public static class ResultCheckboxRenderer extends JCheckBox implements TableCellRenderer {
        private final TableCellRenderer delegate;
        private final MatrixDB db;

        public ResultCheckboxRenderer(TableCellRenderer delegate, MatrixDB db) {
            this.delegate = delegate;
            this.db = db;
            setOpaque(true);
            setHorizontalAlignment(CENTER);
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                boolean isSelected, boolean hasFocus, int row, int col) {
            Component cell = delegate.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
            if (cell instanceof JCheckBox cb) {
                cb.setSelected(Boolean.TRUE.equals(value));
            }
            setBackground(isSelected, cell, table);

            // Only color role columns
            MessageTableModel model = (MessageTableModel) table.getModel();
            if (!model.isRoleColumn(col)) return cell;

            MessageEntry msg = db.getMessages().get(row);
            if (!msg.isEnabled()) {
                cell.setBackground(isSelected ? DISABLED_SEL : DISABLED);
                return cell;
            }

            RoleEntry role = model.getRoleForColumn(col);
            if (role == null || !msg.getRoleResults().containsKey(role)) return cell;

            boolean passed = msg.getRoleResults().get(role);
            boolean authorized = msg.isRoleAuthorized(role);
            if (passed) {
                cell.setBackground(isSelected ? GREEN_SELECTED : GREEN);
            } else if (authorized) {
                // Role is checked as authorized but failed -> likely false positive (bad token)
                cell.setBackground(isSelected ? BLUE_SELECTED : BLUE);
            } else {
                // Role is NOT authorized but succeeded -> vulnerability
                cell.setBackground(isSelected ? RED_SELECTED : RED);
            }
            return cell;
        }

        private void setBackground(boolean isSelected, Component cell, JTable table) {
            cell.setForeground(isSelected ? table.getSelectionForeground() : table.getForeground());
            cell.setBackground(isSelected ? table.getSelectionBackground() : table.getBackground());
        }
    }

    /**
     * Renders string cells in the message table. Purple background for failure regex mode,
     * gray for disabled rows.
     */
    public static class RegexCellRenderer extends DefaultTableCellRenderer {
        private final MatrixDB db;

        public RegexCellRenderer(MatrixDB db) {
            this.db = db;
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                boolean isSelected, boolean hasFocus, int row, int col) {
            Component cell = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
            MessageEntry msg = db.getMessages().get(row);

            if (!msg.isEnabled()) {
                cell.setBackground(isSelected ? DISABLED_SEL : DISABLED);
            } else if (col == MessageTableModel.COL_REGEX && msg.isFailureRegexMode()) {
                cell.setBackground(isSelected ? DISABLED_SEL : FAILURE_REGEX);
            } else {
                cell.setBackground(isSelected ? table.getSelectionBackground() : table.getBackground());
            }
            return cell;
        }
    }

    /**
     * Renders cells in the user table. Gray for disabled users.
     */
    public static class UserCellRenderer implements TableCellRenderer {
        private final TableCellRenderer delegate;
        private final MatrixDB db;

        public UserCellRenderer(TableCellRenderer delegate, MatrixDB db) {
            this.delegate = delegate;
            this.db = db;
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                boolean isSelected, boolean hasFocus, int row, int col) {
            Component cell = delegate.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
            UserEntry user = db.getUsers().get(row);
            if (!user.isEnabled()) {
                cell.setBackground(isSelected ? DISABLED_SEL : DISABLED);
            } else {
                cell.setBackground(isSelected ? table.getSelectionBackground() : table.getBackground());
            }
            return cell;
        }
    }
}
