package authmatrix.ui;

import authmatrix.model.MatrixDB;
import authmatrix.model.MessageEntry;
import authmatrix.model.SectionEntry;
import javax.swing.*;
import java.awt.datatransfer.*;
import java.util.*;
import java.util.stream.Collectors;

public class RowTransferHandler extends TransferHandler {
    private final JTable table;
    private final MatrixDB db;
    private final boolean isMessageTable;
    private final SectionEntry section;
    private Runnable onDropComplete;

    public RowTransferHandler(JTable table, MatrixDB db, boolean isMessageTable, SectionEntry section) {
        this.table = table;
        this.db = db;
        this.isMessageTable = isMessageTable;
        this.section = section;
    }

    public RowTransferHandler(JTable table, MatrixDB db, boolean isMessageTable) {
        this(table, db, isMessageTable, null);
    }

    public void setOnDropComplete(Runnable onDropComplete) {
        this.onDropComplete = onDropComplete;
    }

    @Override
    protected Transferable createTransferable(JComponent c) {
        if (isMessageTable) {
            // Encode ALL selected rows as comma-separated global indices
            SectionMessageTableModel model = (SectionMessageTableModel) table.getModel();
            int[] selectedRows = table.getSelectedRows();
            StringJoiner joiner = new StringJoiner(",");
            for (int localRow : selectedRows) {
                MessageEntry msg = model.getMessageAt(localRow);
                if (msg != null) joiner.add(String.valueOf(db.getRows().indexOf(msg)));
            }
            String encoded = joiner.toString();
            return encoded.isEmpty() ? null : new StringSelection(encoded);
        }
        return new StringSelection(String.valueOf(table.getSelectedRow()));
    }

    @Override
    public int getSourceActions(JComponent c) { return MOVE; }

    @Override
    public boolean canImport(TransferSupport info) {
        return info.isDrop() && info.isDataFlavorSupported(DataFlavor.stringFlavor)
                && info.getComponent() instanceof JTable;
    }

    @Override
    public boolean importData(TransferSupport info) {
        if (!canImport(info)) return false;
        try {
            String data = (String) info.getTransferable().getTransferData(DataFlavor.stringFlavor);

            if (isMessageTable) {
                // Parse global indices
                List<Integer> globalIndices = Arrays.stream(data.split(","))
                        .map(String::trim).filter(s -> !s.isEmpty())
                        .map(Integer::parseInt).collect(Collectors.toList());
                if (globalIndices.isEmpty()) return false;

                // Collect the actual MessageEntry objects (in order)
                List<MessageEntry> movedMessages = new ArrayList<>();
                for (int idx : globalIndices) {
                    Object row = db.getRows().get(idx);
                    if (row instanceof MessageEntry m) movedMessages.add(m);
                }
                if (movedMessages.isEmpty()) return false;

                // Determine target insert point
                JTable targetTable = (JTable) info.getComponent();
                SectionMessageTableModel targetModel = (SectionMessageTableModel) targetTable.getModel();
                int localDropRow = ((JTable.DropLocation) info.getDropLocation()).getRow();

                // Find global insert point BEFORE removing
                int globalInsert;
                if (localDropRow >= targetModel.getRowCount() || targetModel.getRowCount() == 0) {
                    if (targetModel.getRowCount() > 0) {
                        MessageEntry lastMsg = targetModel.getMessageAt(targetModel.getRowCount() - 1);
                        globalInsert = db.getRows().indexOf(lastMsg) + 1;
                    } else {
                        globalInsert = findInsertPointForEmptySection(targetTable);
                    }
                } else {
                    MessageEntry targetMsg = targetModel.getMessageAt(localDropRow);
                    globalInsert = targetMsg != null ? db.getRows().indexOf(targetMsg) : db.getRows().size();
                }

                // Remove all moved messages from the rows list
                db.getRows().removeAll(movedMessages);

                // Recalculate insert point (indices shifted after removal)
                // Find the reference object that was at globalInsert before removal
                // Simpler: just clamp and insert
                if (globalInsert > db.getRows().size()) globalInsert = db.getRows().size();

                // Find correct position: if we had a target message, find where it is now
                if (localDropRow < targetModel.getRowCount() && localDropRow >= 0) {
                    MessageEntry targetMsg = targetModel.getMessageAt(localDropRow);
                    if (targetMsg != null && !movedMessages.contains(targetMsg)) {
                        globalInsert = db.getRows().indexOf(targetMsg);
                        if (globalInsert < 0) globalInsert = db.getRows().size();
                    }
                } else {
                    // Dropping at end of section
                    TransferHandler th = targetTable.getTransferHandler();
                    SectionEntry targetSection = (th instanceof RowTransferHandler rth) ? rth.section : null;
                    if (targetSection != null) {
                        int secIdx = db.getRows().indexOf(targetSection);
                        if (secIdx >= 0) {
                            globalInsert = secIdx + 1;
                            while (globalInsert < db.getRows().size()
                                    && db.getRows().get(globalInsert) instanceof MessageEntry) globalInsert++;
                        }
                    } else {
                        // Root: insert before first section
                        globalInsert = 0;
                        for (int i = 0; i < db.getRows().size(); i++) {
                            if (db.getRows().get(i) instanceof SectionEntry) { globalInsert = i; break; }
                            globalInsert = i + 1;
                        }
                    }
                }

                // Insert all moved messages at the target position
                db.getRows().addAll(globalInsert, movedMessages);
            } else {
                int fromRow = Integer.parseInt(data);
                int toRow = ((JTable.DropLocation) info.getDropLocation()).getRow();
                int max = table.getModel().getRowCount();
                if (toRow < 0 || toRow > max) toRow = max;
                db.moveUser(fromRow, toRow);
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private int findInsertPointForEmptySection(JTable targetTable) {
        TransferHandler th = targetTable.getTransferHandler();
        SectionEntry targetSection = (th instanceof RowTransferHandler rth) ? rth.section : null;
        if (targetSection != null) {
            int idx = db.getRows().indexOf(targetSection);
            return idx >= 0 ? idx + 1 : db.getRows().size();
        }
        return 0;
    }

    @Override
    protected void exportDone(JComponent source, Transferable data, int action) {
        if (onDropComplete != null) onDropComplete.run();
    }
}
