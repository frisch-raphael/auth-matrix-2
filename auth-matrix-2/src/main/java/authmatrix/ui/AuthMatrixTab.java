package authmatrix.ui;

import authmatrix.model.*;
import authmatrix.HtmlExporter;
import authmatrix.RunEngine;
import authmatrix.StateManager;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.api.montoya.ui.editor.EditorOptions;

import javax.swing.*;
import javax.swing.table.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.util.*;
import java.util.List;

public class AuthMatrixTab extends JPanel {
    private final MontoyaApi api;
    private final MatrixDB db;
    private final RunEngine engine;

    private final JTable userTable;
    private final UserTableModel userModel;
    private final JTabbedPane viewerTabs;
    private final JButton runButton;
    private final JButton cancelButton;
    private final JLabel statusLabel;
    private final JFileChooser fileChooser = new JFileChooser();

    // Multi-table section UI
    private final Box sectionsBox = new Box(BoxLayout.Y_AXIS);
    private final JScrollPane messageScrollPane;
    private final List<SectionPanel> sectionPanels = new ArrayList<>();
    private JTable activeMessageTable;
    private TableColumnModel sharedColumnModel;

    private final Map<MessageEntry, HttpRequestEditor> editableEditors = new HashMap<>();
    private final JToggleButton highlightNewPathsToggle;
    private TableCellRenderer origUserStringRenderer;
    private TableCellRenderer origUserBooleanRenderer;

    public boolean isHighlightNewPathsEnabled() { return highlightNewPathsToggle.isSelected(); }

    public AuthMatrixTab(MontoyaApi api, MatrixDB db) {
        super(new BorderLayout());
        this.api = api;
        this.db = db;
        this.engine = new RunEngine(api, db);

        // --- User Table ---
        userModel = new UserTableModel(db);
        userTable = new JTable(userModel);
        userTable.setDragEnabled(true);
        userTable.setDropMode(DropMode.INSERT_ROWS);
        userTable.setTransferHandler(new RowTransferHandler(userTable, db, false));
        userTable.getTableHeader().setReorderingAllowed(false);

        // --- Message sections container ---
        messageScrollPane = new JScrollPane(sectionsBox);
        messageScrollPane.getVerticalScrollBar().setUnitIncrement(16);

        // --- Viewer Tabs ---
        viewerTabs = new JTabbedPane();

        // --- Buttons ---
        runButton = new JButton("Run");
        cancelButton = new JButton("Cancel");
        cancelButton.setEnabled(false);
        JButton newUserBtn = new JButton("New User");
        JButton newRoleBtn = new JButton("New Role");
        JButton newHeaderBtn = new JButton("New Header");
        JButton newSectionBtn = new JButton("New Section");
        JButton saveBtn = new JButton("Save");
        JButton loadBtn = new JButton("Load");
        JButton exportBtn = new JButton("Export HTML");
        JButton clearBtn = new JButton("Clear");

        statusLabel = new JLabel(" ");
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.ITALIC));
        statusLabel.setForeground(new Color(0x66, 0x66, 0x99));

        runButton.addActionListener(e -> onRun());
        cancelButton.addActionListener(e -> engine.cancel());
        newUserBtn.addActionListener(e -> onNewUser());
        newRoleBtn.addActionListener(e -> onNewRole());
        newHeaderBtn.addActionListener(e -> onNewHeader());
        newSectionBtn.addActionListener(e -> onNewSection());
        saveBtn.addActionListener(e -> onSave());
        loadBtn.addActionListener(e -> onLoad());
        exportBtn.addActionListener(e -> onExportHtml());
        clearBtn.addActionListener(e -> onClear());

        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        buttonRow.add(runButton); buttonRow.add(cancelButton);
        buttonRow.add(createSeparator());
        buttonRow.add(newUserBtn); buttonRow.add(newRoleBtn);
        buttonRow.add(newHeaderBtn); buttonRow.add(newSectionBtn);
        buttonRow.add(createSeparator());
        buttonRow.add(saveBtn); buttonRow.add(loadBtn); buttonRow.add(exportBtn); buttonRow.add(clearBtn);
        buttonRow.add(createSeparator());
        highlightNewPathsToggle = new JToggleButton("Highlight New Paths");
        highlightNewPathsToggle.setToolTipText(
                "When enabled, proxy requests whose path is not already in AuthMatrix " +
                "are highlighted orange in Proxy History. Helps spot untested endpoints.");
        buttonRow.add(highlightNewPathsToggle);

        JPanel buttons = new JPanel(new BorderLayout());
        buttons.add(buttonRow, BorderLayout.CENTER);
        buttons.add(statusLabel, BorderLayout.SOUTH);

        // --- Layout ---
        JScrollPane userScroll = new JScrollPane(userTable);
        JSplitPane topSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, userScroll, messageScrollPane);
        topSplit.setResizeWeight(0.3);

        JPanel bottomPanel = new JPanel(new BorderLayout());
        bottomPanel.add(viewerTabs, BorderLayout.CENTER);
        bottomPanel.add(buttons, BorderLayout.SOUTH);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, topSplit, bottomPanel);
        mainSplit.setResizeWeight(0.5);

        add(mainSplit, BorderLayout.CENTER);

        origUserStringRenderer = userTable.getDefaultRenderer(String.class);
        origUserBooleanRenderer = userTable.getDefaultRenderer(Boolean.class);
        applyUserRenderers();
        rebuildSectionPanels();
    }

    // ========== Section Panel Management ==========

    private void rebuildSectionPanels() {
        sectionsBox.removeAll();
        sectionPanels.clear();
        sharedColumnModel = null;
        activeMessageTable = null;

        // Root section (messages before any SectionEntry)
        addSectionPanel(null);
        // Named sections
        for (SectionEntry section : db.getSections()) {
            addSectionPanel(section);
        }

        // Sticky column header from the first table
        if (!sectionPanels.isEmpty()) {
            JTable firstTable = sectionPanels.get(0).table;
            JTableHeader header = firstTable.getTableHeader();
            installMessageHeaderPopup(header, firstTable);
            messageScrollPane.setColumnHeaderView(header);
        }

        sectionsBox.revalidate();
        sectionsBox.repaint();
    }

    private void addSectionPanel(SectionEntry section) {
        SectionPanel panel = new SectionPanel(section);
        sectionPanels.add(panel);

        // Share column model across all tables
        if (sharedColumnModel == null) {
            sharedColumnModel = panel.table.getColumnModel();
            applyColumnWidths(sharedColumnModel);
        } else {
            panel.table.setColumnModel(sharedColumnModel);
        }
        // Hide individual table headers (sticky header from first table is used)
        if (sectionPanels.size() > 1) {
            panel.table.setTableHeader(null);
        }

        sectionsBox.add(panel);
    }

    private void applyColumnWidths(TableColumnModel colModel) {
        if (colModel.getColumnCount() > 0) {
            colModel.getColumn(0).setMinWidth(30);
            colModel.getColumn(0).setMaxWidth(45);
            colModel.getColumn(1).setMinWidth(300);
            colModel.getColumn(2).setMinWidth(150);
        }
        if (colModel.getColumnCount() > 2) {
            JComboBox<String> regexCombo = new JComboBox<>(db.getKnownRegexes().toArray(new String[0]));
            regexCombo.setEditable(true);
            colModel.getColumn(2).setCellEditor(new DefaultCellEditor(regexCombo));
        }
    }

    private void refreshSectionData() {
        for (SectionPanel panel : sectionPanels) {
            List<MessageEntry> msgs = panel.section == null
                    ? db.getRootMessages() : db.getMessagesInSection(panel.section);
            panel.model.setMessages(msgs);
            panel.resizeToFit();
        }
        sectionsBox.revalidate();
        sectionsBox.repaint();
    }

    // ========== Section Panel Inner Class ==========

    private class SectionPanel extends JPanel {
        final SectionEntry section; // null = root
        final SectionMessageTableModel model;
        final JTable table;
        private boolean collapsed = false;
        private JLabel headerLabel;
        private static final int HEADER_HEIGHT = 24;
        private static final int EMPTY_ROW_HEIGHT = 22; // min height when empty (drop target)

        SectionPanel(SectionEntry section) {
            super(new BorderLayout());
            this.section = section;
            this.model = new SectionMessageTableModel(db);

            List<MessageEntry> msgs = section == null ? db.getRootMessages() : db.getMessagesInSection(section);
            model.setMessages(msgs);

            // Table — override editCellAt to only toggle checkboxes when clicking the checkbox area
            table = new JTable(model) {
                @Override
                public boolean editCellAt(int row, int col, java.util.EventObject e) {
                    if (getColumnClass(col) == Boolean.class && e instanceof MouseEvent me) {
                        // Only toggle if click is within the checkbox bounds (center 20px)
                        Rectangle cellRect = getCellRect(row, col, false);
                        int checkboxSize = 20;
                        int centerX = cellRect.x + cellRect.width / 2;
                        if (Math.abs(me.getX() - centerX) > checkboxSize / 2) return false;
                    }
                    return super.editCellAt(row, col, e);
                }
            };
            table.setDragEnabled(true);
            table.setDropMode(DropMode.INSERT_ROWS);
            RowTransferHandler handler = new RowTransferHandler(table, db, true, section);
            handler.setOnDropComplete(AuthMatrixTab.this::refreshSectionData);
            table.setTransferHandler(handler);
            table.getTableHeader().setReorderingAllowed(false);
            table.setFillsViewportHeight(false);
            table.setDefaultRenderer(Boolean.class, new Renderers.ResultCheckboxRenderer());
            table.setDefaultRenderer(String.class, new Renderers.RegexCellRenderer());

            // Selection sync
            table.getSelectionModel().addListSelectionListener(e -> {
                if (!e.getValueIsAdjusting() && table.getSelectedRow() >= 0) {
                    for (SectionPanel other : sectionPanels) {
                        if (other.table != table) other.table.clearSelection();
                    }
                    activeMessageTable = table;
                    onMessageSelected(table, table.getSelectedRow());
                }
            });

            table.setComponentPopupMenu(createMessagePopup());

            // Section colored border around the table
            if (section != null) {
                table.setBorder(BorderFactory.createMatteBorder(0, 3, 1, 1, section.getColor()));

                // Header label with collapse toggle
                headerLabel = new JLabel(getHeaderText());
                headerLabel.setOpaque(true);
                headerLabel.setBackground(section.getColor());
                headerLabel.setForeground(Color.WHITE);
                headerLabel.setFont(headerLabel.getFont().deriveFont(Font.BOLD, 13f));
                headerLabel.setPreferredSize(new Dimension(0, HEADER_HEIGHT));
                headerLabel.setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 4));
                headerLabel.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));

                // Click to collapse/expand
                headerLabel.addMouseListener(new MouseAdapter() {
                    @Override public void mouseClicked(MouseEvent e) {
                        if (SwingUtilities.isLeftMouseButton(e)) toggleCollapse();
                    }
                });

                // Header right-click
                JPopupMenu headerPopup = new JPopupMenu();
                addItem(headerPopup, "Run section", ev -> {
                    List<MessageEntry> sectionMsgs = db.getMessagesInSection(section);
                    if (!sectionMsgs.isEmpty())
                        new Thread(() -> engine.run(sectionMsgs, AuthMatrixTab.this::setRunning,
                                AuthMatrixTab.this::setProgress, AuthMatrixTab.this::redrawAll)).start();
                });
                addItem(headerPopup, "Rename section", ev -> {
                    String name = JOptionPane.showInputDialog(AuthMatrixTab.this, "Section Name:", section.getName());
                    if (name != null && !name.trim().isEmpty()) {
                        section.setName(name.trim());
                        headerLabel.setText(getHeaderText());
                    }
                });
                addItem(headerPopup, "Delete section", ev -> { db.deleteSection(section); redrawAll(); });
                headerLabel.setComponentPopupMenu(headerPopup);

                add(headerLabel, BorderLayout.NORTH);
            }

            add(table, BorderLayout.CENTER);
            resizeToFit();
        }

        private String getHeaderText() {
            return "  " + (collapsed ? "\u25B6 " : "\u25BC ") + section.getName();
        }

        private void toggleCollapse() {
            collapsed = !collapsed;
            table.setVisible(!collapsed);
            if (headerLabel != null) headerLabel.setText(getHeaderText());
            resizeToFit();
            sectionsBox.revalidate();
            sectionsBox.repaint();
        }

        void resizeToFit() {
            if (collapsed) {
                int h = section != null ? HEADER_HEIGHT : 0;
                setMaximumSize(new Dimension(Integer.MAX_VALUE, h));
                setPreferredSize(new Dimension(0, h));
            } else {
                int rows = model.getRowCount();
                int tableHeight = rows > 0 ? rows * table.getRowHeight() : EMPTY_ROW_HEIGHT;
                table.setPreferredScrollableViewportSize(new Dimension(0, tableHeight));
                table.setPreferredSize(new Dimension(0, tableHeight));
                int totalHeight = tableHeight + (section != null ? HEADER_HEIGHT : 0);
                setMaximumSize(new Dimension(Integer.MAX_VALUE, totalHeight));
                setPreferredSize(new Dimension(0, totalHeight));
            }
            revalidate();
        }
    }

    // ========== Renderers ==========

    private void applyUserRenderers() {
        userTable.setDefaultRenderer(String.class, new Renderers.UserCellRenderer(origUserStringRenderer, db));
        userTable.setDefaultRenderer(Boolean.class, new Renderers.UserCellRenderer(origUserBooleanRenderer, db));
    }

    public void redrawAll() {
        Runnable doRedraw = () -> {
            saveEditorChanges();
            userModel.fireTableStructureChanged();
            applyUserRenderers();
            applyUserColumnWidths();
            rebuildSectionPanels();
        };
        if (SwingUtilities.isEventDispatchThread()) doRedraw.run();
        else SwingUtilities.invokeLater(doRedraw);
    }

    private void applyUserColumnWidths() {
        if (userTable.getColumnCount() > 1) {
            userTable.getColumnModel().getColumn(0).setMinWidth(150);
            userTable.getColumnModel().getColumn(0).setMaxWidth(1000);
            userTable.getColumnModel().getColumn(1).setMinWidth(150);
            userTable.getColumnModel().getColumn(1).setMaxWidth(1500);
        }
    }

    // ========== Message Selection ==========

    private void onMessageSelected(JTable table, int row) {
        saveEditorChanges();
        viewerTabs.removeAll();
        editableEditors.clear();
        if (db.getLock().isLocked()) return;

        SectionMessageTableModel model = (SectionMessageTableModel) table.getModel();
        MessageEntry msg = model.getMessageAt(row);
        if (msg == null) return;

        JTabbedPane originalTab = createViewerTab(msg, true);
        originalTab.setSelectedIndex(0);
        viewerTabs.addTab("Original", originalTab);

        for (UserEntry user : db.getUsers()) {
            MessageEntry.RunResult run = msg.getUserRuns().get(user);
            if (run != null) {
                JTabbedPane userTab = createViewerTab(msg, run);
                userTab.setSelectedIndex(1);
                viewerTabs.addTab(user.getName(), userTab);
            }
        }
    }

    private JTabbedPane createViewerTab(MessageEntry msg, boolean editable) {
        HttpRequestEditor reqEditor = editable
                ? api.userInterface().createHttpRequestEditor()
                : api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        HttpResponseEditor respEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
        if (msg.getRequest() != null) reqEditor.setRequest(buildHttpRequest(msg));
        if (msg.getResponse() != null)
            respEditor.setResponse(HttpResponse.httpResponse(ByteArray.byteArray(msg.getResponse())));
        if (editable) editableEditors.put(msg, reqEditor);
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Request", reqEditor.uiComponent());
        tabs.addTab("Response", respEditor.uiComponent());
        return tabs;
    }

    private JTabbedPane createViewerTab(MessageEntry msg, MessageEntry.RunResult run) {
        HttpRequestEditor reqEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        HttpResponseEditor respEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
        if (run.request() != null)
            reqEditor.setRequest(HttpRequest.httpRequest(
                    burp.api.montoya.http.HttpService.httpService(msg.getHost(), msg.getPort(), msg.isSecure()),
                    ByteArray.byteArray(run.request())));
        if (run.response() != null)
            respEditor.setResponse(HttpResponse.httpResponse(ByteArray.byteArray(run.response())));
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Request", reqEditor.uiComponent());
        tabs.addTab("Response", respEditor.uiComponent());
        return tabs;
    }

    private void saveEditorChanges() {
        for (var entry : editableEditors.entrySet()) {
            HttpRequestEditor editor = entry.getValue();
            if (editor.isModified()) entry.getKey().setRequest(editor.getRequest().toByteArray().getBytes());
        }
        editableEditors.clear();
    }

    private HttpRequest buildHttpRequest(MessageEntry msg) {
        return HttpRequest.httpRequest(
                burp.api.montoya.http.HttpService.httpService(msg.getHost(), msg.getPort(), msg.isSecure()),
                ByteArray.byteArray(msg.getRequest()));
    }

    // ========== Popup Menus ==========

    private JPopupMenu createMessagePopup() {
        JPopupMenu popup = new JPopupMenu();
        addItem(popup, "Disable/Enable Request(s)", e -> {
            for (MessageEntry msg : getSelectedMessages()) msg.toggleEnabled();
            refreshSectionData();
        });
        addItem(popup, "Run Request(s)", e -> {
            List<MessageEntry> selected = getSelectedMessages();
            if (!selected.isEmpty())
                new Thread(() -> engine.run(selected, this::setRunning, this::setProgress, this::redrawAll)).start();
        });
        addItem(popup, "Toggle Regex Mode (Success/Failure)", e -> {
            for (MessageEntry msg : getSelectedMessages()) { msg.toggleFailureRegexMode(); msg.clearResults(); }
            refreshSectionData();
        });
        addItem(popup, "Change Regexes", e -> onChangeRegexes());
        addItem(popup, "Change Target Domain", e -> onChangeDomain());
        addItem(popup, "Remove Request(s)", e -> {
            for (MessageEntry msg : getSelectedMessages()) db.deleteMessage(msg);
            redrawAll();
        });
        popup.addSeparator();

        // Dynamic items
        popup.addPopupMenuListener(new javax.swing.event.PopupMenuListener() {
            private final List<Component> dynamicItems = new ArrayList<>();
            @Override public void popupMenuWillBecomeVisible(javax.swing.event.PopupMenuEvent e) {
                for (Component item : dynamicItems) popup.remove(item);
                dynamicItems.clear();
                List<MessageEntry> selected = getSelectedMessages();

                // "Run for [role]" — single role cell
                if (activeMessageTable != null && selected.size() == 1) {
                    Point mouse = activeMessageTable.getMousePosition();
                    if (mouse != null) {
                        int col = activeMessageTable.columnAtPoint(mouse);
                        SectionMessageTableModel model = (SectionMessageTableModel) activeMessageTable.getModel();
                        RoleEntry clickedRole = model.getRoleForColumn(col);
                        if (clickedRole != null) {
                            MessageEntry msg = selected.get(0);
                            JMenuItem item = new JMenuItem("Run for: " + clickedRole.getName());
                            item.addActionListener(ev -> new Thread(() ->
                                engine.runForRole(msg, clickedRole, AuthMatrixTab.this::setRunning,
                                        AuthMatrixTab.this::setProgress, AuthMatrixTab.this::redrawAll)).start());
                            dynamicItems.add(item);
                            popup.add(item);
                        }
                    }
                }

                // "Send to [section]" items + "Run section"
                if (!selected.isEmpty()) {
                    List<SectionEntry> sections = db.getSections();
                    if (!sections.isEmpty()) {
                        JSeparator sep = new JSeparator();
                        dynamicItems.add(sep); popup.add(sep);
                        for (SectionEntry section : sections) {
                            JMenuItem item = new JMenuItem("Send to section: " + section.getName());
                            item.setForeground(section.getColor());
                            item.addActionListener(ev -> {
                                moveMessagesToSection(selected, section);
                                refreshSectionData();
                            });
                            dynamicItems.add(item); popup.add(item);
                        }
                        JMenuItem root = new JMenuItem("Send to root (no section)");
                        root.addActionListener(ev -> {
                            moveMessagesToRoot(selected);
                            refreshSectionData();
                        });
                        dynamicItems.add(root); popup.add(root);
                    }

                    // "Run section" — determine which section the active table belongs to
                    if (activeMessageTable != null) {
                        for (SectionPanel panel : sectionPanels) {
                            if (panel.table == activeMessageTable && panel.section != null) {
                                SectionEntry sec = panel.section;
                                JMenuItem runSec = new JMenuItem("Run section: " + sec.getName());
                                runSec.addActionListener(ev -> {
                                    List<MessageEntry> sectionMsgs = db.getMessagesInSection(sec);
                                    if (!sectionMsgs.isEmpty())
                                        new Thread(() -> engine.run(sectionMsgs, AuthMatrixTab.this::setRunning,
                                                AuthMatrixTab.this::setProgress, AuthMatrixTab.this::redrawAll)).start();
                                });
                                dynamicItems.add(runSec); popup.add(runSec);
                                break;
                            }
                        }
                    }
                }

                // Bulk toggle — multiple rows
                if (selected.size() >= 2) {
                    JSeparator sep = new JSeparator();
                    dynamicItems.add(sep); popup.add(sep);

                    // Check all / Uncheck all (all roles at once) — always show both
                    JMenuItem checkAll = new JMenuItem("Check all roles");
                    checkAll.addActionListener(ev -> {
                        for (RoleEntry r : db.getAllRoles()) bulkSetAuthorized(selected, r, true);
                        refreshSectionData();
                    });
                    dynamicItems.add(checkAll); popup.add(checkAll);

                    JMenuItem uncheckAll = new JMenuItem("Uncheck all roles");
                    uncheckAll.addActionListener(ev -> {
                        for (RoleEntry r : db.getAllRoles()) bulkSetAuthorized(selected, r, false);
                        refreshSectionData();
                    });
                    dynamicItems.add(uncheckAll); popup.add(uncheckAll);

                    // Per-role: always show both check and uncheck
                    for (RoleEntry role : db.getAllRoles()) {
                        boolean allChecked = selected.stream().allMatch(m -> m.isRoleAuthorized(role));
                        boolean allUnchecked = selected.stream().noneMatch(m -> m.isRoleAuthorized(role));

                        if (!allChecked) {
                            JMenuItem item = new JMenuItem("Check all for: " + role.getName());
                            item.addActionListener(ev -> { bulkSetAuthorized(selected, role, true); refreshSectionData(); });
                            dynamicItems.add(item); popup.add(item);
                        }
                        if (!allUnchecked) {
                            JMenuItem item = new JMenuItem("Uncheck all for: " + role.getName());
                            item.addActionListener(ev -> { bulkSetAuthorized(selected, role, false); refreshSectionData(); });
                            dynamicItems.add(item); popup.add(item);
                        }
                    }
                }
            }
            @Override public void popupMenuWillBecomeInvisible(javax.swing.event.PopupMenuEvent e) {}
            @Override public void popupMenuCanceled(javax.swing.event.PopupMenuEvent e) {}
        });
        return popup;
    }

    // ========== Role Header Actions (shared between message + user table headers) ==========

    private RoleEntry clickedHeaderRole; // set by header mouse listener before popup shows

    private void promptRenameRole() {
        if (clickedHeaderRole == null) return;
        String name = JOptionPane.showInputDialog(this, "New Role Name:", clickedHeaderRole.getName());
        if (name != null && !name.trim().isEmpty()) { clickedHeaderRole.setName(name.trim()); redrawAll(); }
    }

    private void deleteClickedRole() {
        if (clickedHeaderRole != null) { db.deleteRole(clickedHeaderRole); redrawAll(); }
    }

    /** Set a role's authorization on multiple messages and re-evaluate colors. */
    private void bulkSetAuthorized(List<MessageEntry> msgs, RoleEntry role, boolean value) {
        for (MessageEntry msg : msgs) {
            msg.setRoleAuthorized(role, value);
            if (!msg.getUserRuns().isEmpty()) {
                java.util.Set<RoleEntry> prev = new java.util.HashSet<>(msg.getRoleResults().keySet());
                RunEngine.evaluateRoleResults(db, msg);
                msg.getRoleResults().keySet().retainAll(prev);
            }
        }
    }

    private void bulkSetRole(RoleEntry role, boolean value) {
        if (role == null) return;
        List<MessageEntry> msgs = getSelectedMessages();
        if (msgs.isEmpty()) msgs = db.getMessages();
        bulkSetAuthorized(msgs, role, value);
        refreshSectionData();
    }

    /** Install a role-only right-click popup on any table header. extraItems adds table-specific items. */
    private void installRoleHeaderPopup(JTableHeader header, int staticColCount, java.util.function.Consumer<JPopupMenu> extraItems) {
        JPopupMenu popup = new JPopupMenu();
        addItem(popup, "Rename Role", e -> promptRenameRole());
        addItem(popup, "Delete Role", e -> deleteClickedRole());
        if (extraItems != null) extraItems.accept(popup);

        header.addMouseListener(new MouseAdapter() {
            @Override public void mousePressed(MouseEvent e) { maybeShowPopup(e); }
            @Override public void mouseReleased(MouseEvent e) { maybeShowPopup(e); }
            private void maybeShowPopup(MouseEvent e) {
                if (!e.isPopupTrigger()) return;
                int col = header.columnAtPoint(e.getPoint());
                if (col < staticColCount) return;
                int roleIdx = col - staticColCount;
                // For user table, account for header columns
                List<RoleEntry> roles;
                if (staticColCount == MessageTableModel.STATIC_COLS) {
                    roles = db.getAllRoles();
                } else {
                    // User table: roles start after static cols + header count
                    roles = db.getRegularRoles();
                    roleIdx = col - (2 + db.getHeaderCount()); // UserTableModel.STATIC_COLS=2 + headers
                }
                if (roleIdx < 0 || roleIdx >= roles.size()) return;
                clickedHeaderRole = roles.get(roleIdx);
                popup.show(header, e.getX(), e.getY());
            }
        });
    }

    private void installMessageHeaderPopup(JTableHeader header, JTable headerTable) {
        installRoleHeaderPopup(header, MessageTableModel.STATIC_COLS, popup -> {
            popup.addSeparator();
            addItem(popup, "Bulk Select Checkboxes", e -> bulkSetRole(clickedHeaderRole, true));
            addItem(popup, "Bulk Unselect Checkboxes", e -> bulkSetRole(clickedHeaderRole, false));
        });
    }

    // ========== Section Move Helpers ==========

    private void moveMessagesToSection(List<MessageEntry> msgs, SectionEntry section) {
        List<Object> rows = db.getRows();
        rows.removeAll(msgs);
        int sectionIdx = rows.indexOf(section);
        if (sectionIdx < 0) return;
        int insertAt = sectionIdx + 1;
        while (insertAt < rows.size() && rows.get(insertAt) instanceof MessageEntry) insertAt++;
        rows.addAll(insertAt, msgs);
    }

    private void moveMessagesToRoot(List<MessageEntry> msgs) {
        List<Object> rows = db.getRows();
        rows.removeAll(msgs);
        int firstSection = rows.size();
        for (int i = 0; i < rows.size(); i++) {
            if (rows.get(i) instanceof SectionEntry) { firstSection = i; break; }
        }
        rows.addAll(firstSection, msgs);
    }

    // ========== User Table Popups ==========

    private void installUserPopups() {
        JPopupMenu popup = new JPopupMenu();
        addItem(popup, "Disable/Enable User(s)", e -> {
            for (int row : userTable.getSelectedRows()) db.getUsers().get(row).toggleEnabled();
            redrawAll();
        });
        addItem(popup, "Remove User(s)", e -> {
            List<UserEntry> toRemove = new ArrayList<>();
            for (int row : userTable.getSelectedRows()) toRemove.add(db.getUsers().get(row));
            toRemove.forEach(db::deleteUser);
            redrawAll();
        });
        userTable.setComponentPopupMenu(popup);

        installRoleHeaderPopup(userTable.getTableHeader(), 2 + db.getHeaderCount(), null);
    }

    // ========== Button Actions ==========

    private void onRun() {
        saveEditorChanges(); viewerTabs.removeAll();
        new Thread(() -> engine.run(null, this::setRunning, this::setProgress, this::redrawAll)).start();
    }

    private void setRunning(boolean running) {
        SwingUtilities.invokeLater(() -> { runButton.setEnabled(!running); cancelButton.setEnabled(running); });
    }

    private void setProgress(String text) {
        SwingUtilities.invokeLater(() -> statusLabel.setText(text == null || text.isEmpty() ? " " : text));
    }

    public void highlightTab() {
        SwingUtilities.invokeLater(() -> {
            Container parent = this.getParent();
            while (parent != null && !(parent instanceof JTabbedPane)) parent = parent.getParent();
            if (parent instanceof JTabbedPane tp) {
                int idx = tp.indexOfComponent(this);
                if (idx >= 0) {
                    Color orig = tp.getBackgroundAt(idx);
                    tp.setBackgroundAt(idx, new Color(0xFF, 0x66, 0x33));
                    javax.swing.Timer t = new javax.swing.Timer(3000, e -> tp.setBackgroundAt(idx, orig));
                    t.setRepeats(false); t.start();
                }
            }
        });
    }

    public void scrollToLastMessage() {
        SwingUtilities.invokeLater(() -> {
            if (!sectionPanels.isEmpty()) {
                SectionPanel last = sectionPanels.get(sectionPanels.size() - 1);
                int lastRow = last.table.getRowCount() - 1;
                if (lastRow >= 0) {
                    last.table.scrollRectToVisible(last.table.getCellRect(lastRow, 0, true));
                    last.table.setRowSelectionInterval(lastRow, lastRow);
                    activeMessageTable = last.table;
                }
                sectionsBox.scrollRectToVisible(last.getBounds());
            }
        });
    }

    private void onNewUser() {
        String name = JOptionPane.showInputDialog(this, "Enter New User:");
        if (name != null && !name.trim().isEmpty()) { db.getOrCreateUser(name.trim()); redrawAll(); }
    }

    private void onNewRole() {
        String name = JOptionPane.showInputDialog(this, "Enter New Role:");
        if (name != null && !name.trim().isEmpty()) { db.getOrCreateRole(name.trim()); redrawAll(); }
    }

    private void onNewHeader() { db.addHeader(); redrawAll(); }

    private void onNewSection() {
        String name = JOptionPane.showInputDialog(this, "Enter Section Name:");
        if (name != null && !name.trim().isEmpty()) { db.createSection(name.trim()); redrawAll(); }
    }

    private void onSave() {
        saveEditorChanges();
        int result = fileChooser.showSaveDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) return;
        File file = fileChooser.getSelectedFile();
        if (file.exists()) {
            int confirm = JOptionPane.showConfirmDialog(this, "The file exists, overwrite?", "Existing File", JOptionPane.YES_NO_OPTION);
            if (confirm != JOptionPane.YES_OPTION) return;
        }
        try { StateManager.save(db, file); }
        catch (IOException ex) {
            api.logging().logToError("Save failed: " + ex.getMessage());
            JOptionPane.showMessageDialog(this, "Save failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void onExportHtml() {
        saveEditorChanges();
        JFileChooser chooser = new JFileChooser(fileChooser.getCurrentDirectory());
        String stamp = new java.text.SimpleDateFormat("yyyyMMdd-HHmm").format(new java.util.Date());
        chooser.setSelectedFile(new File("authmatrix-report-" + stamp + ".html"));
        int result = chooser.showSaveDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) return;
        File file = chooser.getSelectedFile();
        if (!file.getName().toLowerCase().endsWith(".html") && !file.getName().toLowerCase().endsWith(".htm")) {
            file = new File(file.getParentFile(), file.getName() + ".html");
        }
        if (file.exists()) {
            int confirm = JOptionPane.showConfirmDialog(this, "The file exists, overwrite?", "Existing File", JOptionPane.YES_NO_OPTION);
            if (confirm != JOptionPane.YES_OPTION) return;
        }
        try {
            HtmlExporter.export(db, file);
            statusLabel.setText("Exported HTML: " + file.getName());
        } catch (IOException ex) {
            api.logging().logToError("HTML export failed: " + ex.getMessage());
            JOptionPane.showMessageDialog(this, "Export failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void onLoad() {
        int result = fileChooser.showOpenDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) return;
        try { StateManager.load(db, fileChooser.getSelectedFile()); redrawAll(); }
        catch (IOException ex) {
            api.logging().logToError("Load failed: " + ex.getMessage());
            JOptionPane.showMessageDialog(this, "Load failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void onClear() {
        int result = JOptionPane.showConfirmDialog(this, "Clear AuthMatrix Configuration?", "Clear Config", JOptionPane.YES_NO_OPTION);
        if (result == JOptionPane.YES_OPTION) { db.clear(); viewerTabs.removeAll(); editableEditors.clear(); redrawAll(); }
    }

    private void onChangeRegexes() {
        JComboBox<String> regexCombo = new JComboBox<>(db.getKnownRegexes().toArray(new String[0]));
        regexCombo.setEditable(true);
        JCheckBox failureMode = new JCheckBox("Regex Detects Unauthorized Requests (Failure Mode)");
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.add(new JLabel("Select a Regex for all selected Requests:"));
        panel.add(regexCombo); panel.add(failureMode);
        int result = JOptionPane.showConfirmDialog(this, panel, "Select Response Regex", JOptionPane.OK_CANCEL_OPTION);
        if (result != JOptionPane.OK_OPTION) return;
        String regex = (String) regexCombo.getSelectedItem();
        if (regex == null || regex.isEmpty()) return;
        for (MessageEntry msg : getSelectedMessages()) { msg.setRegex(regex); msg.setFailureRegexMode(failureMode.isSelected()); }
        db.addRegexIfNew(regex);
        refreshSectionData();
    }

    private void onChangeDomain() {
        List<MessageEntry> selected = getSelectedMessages();
        if (selected.isEmpty()) return;
        MessageEntry first = selected.get(0);
        JTextField hostField = new JTextField(first.getHost(), 25);
        JTextField portField = new JTextField(String.valueOf(first.getPort()), 25);
        JCheckBox tlsBox = new JCheckBox("Use HTTPS", first.isSecure());
        JCheckBox replaceHostBox = new JCheckBox("Replace Host in HTTP header", true);
        tlsBox.addItemListener(e -> {
            if (e.getStateChange() == ItemEvent.SELECTED && "80".equals(portField.getText())) portField.setText("443");
            else if (e.getStateChange() == ItemEvent.DESELECTED && "443".equals(portField.getText())) portField.setText("80");
        });
        JPanel panel = new JPanel(); panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.add(labeled("Host:", hostField)); panel.add(labeled("Port:", portField));
        panel.add(tlsBox); panel.add(replaceHostBox);
        int result = JOptionPane.showConfirmDialog(this, panel, "Configure target details", JOptionPane.OK_CANCEL_OPTION);
        if (result != JOptionPane.OK_OPTION) return;
        String host = hostField.getText().trim();
        if (host.isEmpty()) return;
        int port; try { port = Integer.parseInt(portField.getText().trim()); }
        catch (NumberFormatException ex) { port = tlsBox.isSelected() ? 443 : 80; }
        boolean secure = tlsBox.isSelected();
        for (MessageEntry msg : selected) {
            if (replaceHostBox.isSelected() && msg.getRequest() != null) msg.setRequest(RunEngine.replaceHostHeader(msg.getRequest(), host));
            msg.setHost(host); msg.setPort(port); msg.setSecure(secure); msg.clearResults();
        }
        refreshSectionData();
    }

    // ========== Helpers ==========

    private List<MessageEntry> getSelectedMessages() {
        if (activeMessageTable == null) return List.of();
        int[] rows = activeMessageTable.getSelectedRows();
        SectionMessageTableModel model = (SectionMessageTableModel) activeMessageTable.getModel();
        List<MessageEntry> result = new ArrayList<>();
        for (int row : rows) {
            MessageEntry msg = model.getMessageAt(row);
            if (msg != null) result.add(msg);
        }
        return result;
    }

    private static JPanel labeled(String label, JComponent field) {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT));
        p.add(new JLabel(label)); p.add(field);
        return p;
    }

    private static JSeparator createSeparator() {
        JSeparator sep = new JSeparator(SwingConstants.VERTICAL);
        sep.setPreferredSize(new Dimension(25, 0));
        return sep;
    }

    private static void addItem(JPopupMenu menu, String label, ActionListener action) {
        JMenuItem item = new JMenuItem(label);
        item.addActionListener(action);
        menu.add(item);
    }

    {
        // Deferred user popup install (needs userTable to be initialized)
        SwingUtilities.invokeLater(this::installUserPopups);
    }
}
