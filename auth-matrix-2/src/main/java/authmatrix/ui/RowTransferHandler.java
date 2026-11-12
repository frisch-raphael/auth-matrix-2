package authmatrix.ui;

import authmatrix.model.*;
import javax.swing.*;
import java.awt.datatransfer.*;
import java.util.*;
import java.util.List;

/** Only accepts rows from this matrix and the same table kind. */
public class RowTransferHandler extends TransferHandler {
    private static final DataFlavor ROWS = new DataFlavor(Selection.class, "AuthMatrix rows");
    private record Selection(MatrixDB source, boolean messages, List<?> items) { }
    private final JTable table;
    private final MatrixDB db;
    private final boolean messages;
    private final SectionEntry section;
    private Runnable onDropComplete;

    public RowTransferHandler(JTable table, MatrixDB db, boolean messages, SectionEntry section) {
        this.table = table; this.db = db; this.messages = messages; this.section = section;
    }
    public RowTransferHandler(JTable table, MatrixDB db, boolean messages) { this(table, db, messages, null); }
    public void setOnDropComplete(Runnable callback) { onDropComplete = callback; }

    @Override protected Transferable createTransferable(JComponent component) {
        if (db.getLock().isLocked()) return null;
        List<Object> items = new ArrayList<>();
        for (int row : table.getSelectedRows()) {
            if (messages) items.add(((SectionMessageTableModel) table.getModel()).getMessageAt(row));
            else items.add(db.getUsers().get(row));
        }
        if (items.isEmpty()) return null;
        Selection data = new Selection(db, messages, items);
        return new Transferable() {
            public DataFlavor[] getTransferDataFlavors() { return new DataFlavor[]{ROWS}; }
            public boolean isDataFlavorSupported(DataFlavor flavor) { return ROWS.equals(flavor); }
            public Object getTransferData(DataFlavor flavor) throws UnsupportedFlavorException {
                if (!isDataFlavorSupported(flavor)) throw new UnsupportedFlavorException(flavor);
                return data;
            }
        };
    }
    @Override public int getSourceActions(JComponent component) { return MOVE; }
    @Override public boolean canImport(TransferSupport support) {
        if (!support.isDrop() || !support.isDataFlavorSupported(ROWS) || db.getLock().isLocked()) return false;
        try {
            Selection data = (Selection) support.getTransferable().getTransferData(ROWS);
            return data.source() == db && data.messages() == messages;
        } catch (Exception ex) { return false; }
    }
    @Override public boolean importData(TransferSupport support) {
        if (!canImport(support)) return false;
        try {
            Selection data = (Selection) support.getTransferable().getTransferData(ROWS);
            int row = ((JTable.DropLocation) support.getDropLocation()).getRow();
            if (messages) {
                List<MessageEntry> selected = data.items().stream().map(MessageEntry.class::cast).toList();
                MessageEntry before = ((SectionMessageTableModel) table.getModel()).getMessageAt(row);
                db.moveMessagesToSection(selected, section, before);
                if (section != null) section.setCollapsed(false);
            } else {
                UserEntry before = row < db.getUsers().size() ? db.getUsers().get(row) : null;
                db.moveUsersBefore(data.items().stream().map(UserEntry.class::cast).toList(), before);
            }
            if (onDropComplete != null) SwingUtilities.invokeLater(onDropComplete);
            return true;
        } catch (Exception ex) { return false; }
    }
}
