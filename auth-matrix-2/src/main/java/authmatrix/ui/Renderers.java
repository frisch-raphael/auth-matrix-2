package authmatrix.ui;

import authmatrix.model.*;
import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableCellRenderer;
import java.awt.*;

public final class Renderers {

    private Renderers() {}

    private static final Color GREEN           = new Color(0x87, 0xF7, 0x17);
    private static final Color GREEN_SELECTED  = new Color(0xC8, 0xE0, 0x51);
    private static final Color RED             = new Color(0xFF, 0x32, 0x17);
    private static final Color RED_SELECTED    = new Color(0xFF, 0x87, 0x51);
    private static final Color BLUE            = new Color(0x00, 0xCC, 0xFF);
    private static final Color BLUE_SELECTED   = new Color(0x8B, 0xCD, 0xBA);
    private static final Color DISABLED        = Color.GRAY;
    private static final Color DISABLED_SEL    = new Color(0xD1, 0xB5, 0xA3);
    private static final Color FAILURE_REGEX   = new Color(0x99, 0x99, 0xCC);

    /** Pick a readable foreground for a given background. */
    private static Color contrastForeground(Color bg) {
        double luminance = 0.299 * bg.getRed() + 0.587 * bg.getGreen() + 0.114 * bg.getBlue();
        return luminance > 140 ? Color.BLACK : Color.WHITE;
    }

    public static class ResultCheckboxRenderer extends JCheckBox implements TableCellRenderer {

        public ResultCheckboxRenderer() {
            setOpaque(true);
            setHorizontalAlignment(CENTER);
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                boolean isSelected, boolean hasFocus, int row, int col) {
            setSelected(Boolean.TRUE.equals(value));
            setForeground(isSelected ? table.getSelectionForeground() : table.getForeground());
            setBackground(isSelected ? table.getSelectionBackground() : table.getBackground());

            SectionMessageTableModel model = (SectionMessageTableModel) table.getModel();
            MessageEntry msg = model.getMessageAt(row);
            if (msg == null || !model.isRoleColumn(col)) return this;

            if (!msg.isEnabled()) {
                setBackground(isSelected ? DISABLED_SEL : DISABLED);
                setForeground(contrastForeground(getBackground()));
                return this;
            }

            RoleEntry role = model.getRoleForColumn(col);
            if (role != null && msg.getRoleResults().containsKey(role)) {
                boolean passed = msg.getRoleResults().get(role);
                boolean authorized = msg.isRoleAuthorized(role);
                if (passed) setBackground(isSelected ? GREEN_SELECTED : GREEN);
                else if (authorized) setBackground(isSelected ? BLUE_SELECTED : BLUE);
                else setBackground(isSelected ? RED_SELECTED : RED);
                setForeground(contrastForeground(getBackground()));
            }
            return this;
        }
    }

    public static class RegexCellRenderer extends DefaultTableCellRenderer {

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                boolean isSelected, boolean hasFocus, int row, int col) {
            Component cell = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
            // Always ensure foreground matches the table theme
            cell.setForeground(isSelected ? table.getSelectionForeground() : table.getForeground());
            cell.setBackground(isSelected ? table.getSelectionBackground() : table.getBackground());

            SectionMessageTableModel model = (SectionMessageTableModel) table.getModel();
            MessageEntry msg = model.getMessageAt(row);
            if (msg == null) return cell;

            if (!msg.isEnabled()) {
                cell.setBackground(isSelected ? DISABLED_SEL : DISABLED);
                cell.setForeground(contrastForeground(cell.getBackground()));
            } else if (col == MessageTableModel.COL_REGEX && msg.isFailureRegexMode()) {
                cell.setBackground(isSelected ? DISABLED_SEL : FAILURE_REGEX);
                cell.setForeground(contrastForeground(cell.getBackground()));
            }
            return cell;
        }
    }

    public static class UserCellRenderer extends JLabel implements TableCellRenderer {
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
            if (row < 0 || row >= db.getUsers().size()) return cell;
            UserEntry user = db.getUsers().get(row);
            if (!user.isEnabled()) {
                cell.setBackground(isSelected ? DISABLED_SEL : DISABLED);
                cell.setForeground(contrastForeground(cell.getBackground()));
            } else {
                cell.setForeground(isSelected ? table.getSelectionForeground() : table.getForeground());
                cell.setBackground(isSelected ? table.getSelectionBackground() : table.getBackground());
            }
            return cell;
        }
    }
}
