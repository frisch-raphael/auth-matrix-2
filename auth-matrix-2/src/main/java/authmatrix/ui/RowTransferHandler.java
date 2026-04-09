package authmatrix.ui;

import authmatrix.model.MatrixDB;
import javax.swing.*;
import java.awt.datatransfer.*;

public class RowTransferHandler extends TransferHandler {
    private final JTable table;
    private final MatrixDB db;
    private final boolean isMessageTable;

    public RowTransferHandler(JTable table, MatrixDB db, boolean isMessageTable) {
        this.table = table;
        this.db = db;
        this.isMessageTable = isMessageTable;
    }

    @Override
    protected Transferable createTransferable(JComponent c) {
        return new StringSelection(String.valueOf(table.getSelectedRow()));
    }

    @Override
    public int getSourceActions(JComponent c) {
        return MOVE;
    }

    @Override
    public boolean canImport(TransferSupport info) {
        return info.getComponent() == table && info.isDrop()
                && info.isDataFlavorSupported(DataFlavor.stringFlavor);
    }

    @Override
    public boolean importData(TransferSupport info) {
        if (!canImport(info)) return false;
        try {
            int fromRow = Integer.parseInt(
                    (String) info.getTransferable().getTransferData(DataFlavor.stringFlavor));
            int toRow = ((JTable.DropLocation) info.getDropLocation()).getRow();
            int max = table.getModel().getRowCount();
            if (toRow < 0 || toRow > max) toRow = max;

            if (isMessageTable) {
                db.moveMessage(fromRow, toRow);
            } else {
                db.moveUser(fromRow, toRow);
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    protected void exportDone(JComponent source, Transferable data, int action) {
        if (table.getModel() instanceof javax.swing.table.AbstractTableModel model) {
            model.fireTableStructureChanged();
        }
    }
}
