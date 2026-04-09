package authmatrix.ui;

import authmatrix.model.*;
import authmatrix.RunEngine;
import authmatrix.StateManager;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.api.montoya.ui.editor.EditorOptions;

import javax.swing.*;
import javax.swing.event.*;
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
    private final JTable messageTable;
    private final UserTableModel userModel;
    private final MessageTableModel messageModel;
    private final JTabbedPane viewerTabs;
    private final JButton runButton;
    private final JButton cancelButton;
    private final JFileChooser fileChooser = new JFileChooser();

    // Track the editable original-request editor for saving user modifications
    private final Map<MessageEntry, HttpRequestEditor> editableEditors = new HashMap<>();

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

        // --- Message Table ---
        messageModel = new MessageTableModel(db);
        messageTable = new JTable(messageModel) {
            @Override
            public void changeSelection(int row, int col, boolean toggle, boolean extend) {
                super.changeSelection(row, col, toggle, extend);
                onMessageSelected(row);
            }
        };
        messageTable.setDragEnabled(true);
        messageTable.setDropMode(DropMode.INSERT_ROWS);
        messageTable.setTransferHandler(new RowTransferHandler(messageTable, db, true));
        messageTable.getTableHeader().setReorderingAllowed(false);

        // --- Viewer Tabs (bottom) ---
        viewerTabs = new JTabbedPane();

        // --- Buttons ---
        runButton = new JButton("Run");
        cancelButton = new JButton("Cancel");
        cancelButton.setEnabled(false);
        JButton newUserBtn = new JButton("New User");
        JButton newRoleBtn = new JButton("New Role");
        JButton newHeaderBtn = new JButton("New Header");
        JButton saveBtn = new JButton("Save");
        JButton loadBtn = new JButton("Load");
        JButton clearBtn = new JButton("Clear");

        runButton.addActionListener(e -> onRun());
        cancelButton.addActionListener(e -> engine.cancel());
        newUserBtn.addActionListener(e -> onNewUser());
        newRoleBtn.addActionListener(e -> onNewRole());
        newHeaderBtn.addActionListener(e -> onNewHeader());
        saveBtn.addActionListener(e -> onSave());
        loadBtn.addActionListener(e -> onLoad());
        clearBtn.addActionListener(e -> onClear());

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        buttons.add(runButton);
        buttons.add(cancelButton);
        buttons.add(createSeparator());
        buttons.add(newUserBtn);
        buttons.add(newRoleBtn);
        buttons.add(newHeaderBtn);
        buttons.add(createSeparator());
        buttons.add(saveBtn);
        buttons.add(loadBtn);
        buttons.add(clearBtn);

        // --- Popup Menus ---
        installMessagePopup();
        installMessageHeaderPopup();
        installUserPopup();
        installUserHeaderPopup();

        // --- Layout ---
        JScrollPane userScroll = new JScrollPane(userTable);
        JScrollPane messageScroll = new JScrollPane(messageTable);

        JSplitPane topSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, userScroll, messageScroll);
        topSplit.setResizeWeight(0.35);

        JPanel bottomPanel = new JPanel(new BorderLayout());
        bottomPanel.add(viewerTabs, BorderLayout.CENTER);
        bottomPanel.add(buttons, BorderLayout.SOUTH);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, topSplit, bottomPanel);
        mainSplit.setResizeWeight(0.5);

        add(mainSplit, BorderLayout.CENTER);

        applyRenderers();
    }

    // --- Renderers ---

    private void applyRenderers() {
        messageTable.setDefaultRenderer(Boolean.class,
                new Renderers.ResultCheckboxRenderer(messageTable.getDefaultRenderer(Boolean.class), db));
        messageTable.setDefaultRenderer(String.class,
                new Renderers.RegexCellRenderer(db));
        userTable.setDefaultRenderer(String.class,
                new Renderers.UserCellRenderer(userTable.getDefaultRenderer(String.class), db));
        userTable.setDefaultRenderer(Boolean.class,
                new Renderers.UserCellRenderer(userTable.getDefaultRenderer(Boolean.class), db));
    }

    public void redrawAll() {
        saveEditorChanges();
        userModel.fireTableStructureChanged();
        messageModel.fireTableStructureChanged();
        applyRenderers();
        applyMessageColumnWidths();
        applyUserColumnWidths();
    }

    private void applyMessageColumnWidths() {
        if (messageTable.getColumnCount() > 0) {
            messageTable.getColumnModel().getColumn(0).setMinWidth(30);
            messageTable.getColumnModel().getColumn(0).setMaxWidth(45);
            messageTable.getColumnModel().getColumn(1).setMinWidth(300);
            messageTable.getColumnModel().getColumn(2).setMinWidth(150);
        }
        // Regex combobox editor
        if (messageTable.getColumnCount() > 2) {
            JComboBox<String> regexCombo = new JComboBox<>(db.getKnownRegexes().toArray(new String[0]));
            regexCombo.setEditable(true);
            messageTable.getColumnModel().getColumn(2).setCellEditor(new DefaultCellEditor(regexCombo));
        }
        messageTable.getTableHeader().getDefaultRenderer().getTableCellRendererComponent(
                messageTable, "", false, false, -1, 0);
    }

    private void applyUserColumnWidths() {
        if (userTable.getColumnCount() > 1) {
            userTable.getColumnModel().getColumn(0).setMinWidth(150);
            userTable.getColumnModel().getColumn(0).setMaxWidth(1000);
            userTable.getColumnModel().getColumn(1).setMinWidth(150);
            userTable.getColumnModel().getColumn(1).setMaxWidth(1500);
        }
    }

    // --- Message Selection -> Viewer Tabs ---

    private void onMessageSelected(int row) {
        saveEditorChanges();
        viewerTabs.removeAll();
        editableEditors.clear();

        if (db.getLock().isLocked()) return;
        if (row < 0 || row >= db.getMessages().size()) return;

        MessageEntry msg = db.getMessages().get(row);

        // Original tab (editable request)
        JTabbedPane originalTab = createViewerTab(msg, true);
        originalTab.setSelectedIndex(0); // default to Request tab
        viewerTabs.addTab("Original", originalTab);

        // Per-user result tabs
        for (UserEntry user : db.getUsers()) {
            MessageEntry.RunResult run = msg.getUserRuns().get(user);
            if (run != null) {
                JTabbedPane userTab = createViewerTab(msg, run);
                userTab.setSelectedIndex(1); // default to Response tab
                viewerTabs.addTab(user.getName(), userTab);
            }
        }
    }

    private JTabbedPane createViewerTab(MessageEntry msg, boolean editable) {
        HttpRequestEditor reqEditor = editable
                ? api.userInterface().createHttpRequestEditor()
                : api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        HttpResponseEditor respEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);

        if (msg.getRequest() != null) {
            reqEditor.setRequest(buildHttpRequest(msg));
        }
        if (msg.getResponse() != null) {
            respEditor.setResponse(HttpResponse.httpResponse(ByteArray.byteArray(msg.getResponse())));
        }

        if (editable) editableEditors.put(msg, reqEditor);

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Request", reqEditor.uiComponent());
        tabs.addTab("Response", respEditor.uiComponent());
        return tabs;
    }

    private JTabbedPane createViewerTab(MessageEntry msg, MessageEntry.RunResult run) {
        HttpRequestEditor reqEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        HttpResponseEditor respEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);

        if (run.request() != null) {
            reqEditor.setRequest(HttpRequest.httpRequest(
                    burp.api.montoya.http.HttpService.httpService(msg.getHost(), msg.getPort(), msg.isSecure()),
                    ByteArray.byteArray(run.request())));
        }
        if (run.response() != null) {
            respEditor.setResponse(HttpResponse.httpResponse(ByteArray.byteArray(run.response())));
        }

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Request", reqEditor.uiComponent());
        tabs.addTab("Response", respEditor.uiComponent());
        return tabs;
    }

    /** Save any modifications the user made in the editable request editor. */
    private void saveEditorChanges() {
        for (var entry : editableEditors.entrySet()) {
            HttpRequestEditor editor = entry.getValue();
            if (editor.isModified()) {
                MessageEntry msg = entry.getKey();
                HttpRequest modified = editor.getRequest();
                msg.setRequest(modified.toByteArray().getBytes());
            }
        }
        editableEditors.clear();
    }

    private HttpRequest buildHttpRequest(MessageEntry msg) {
        return HttpRequest.httpRequest(
                burp.api.montoya.http.HttpService.httpService(msg.getHost(), msg.getPort(), msg.isSecure()),
                ByteArray.byteArray(msg.getRequest()));
    }

    // --- Popup Menus ---

    private void installMessagePopup() {
        JPopupMenu popup = new JPopupMenu();
        addItem(popup, "Disable/Enable Request(s)", e -> {
            for (MessageEntry msg : getSelectedMessages()) msg.toggleEnabled();
            redrawAll();
        });
        addItem(popup, "Run Request(s)", e -> {
            List<MessageEntry> selected = getSelectedMessages();
            new Thread(() -> {
                engine.run(selected, this::setRunning, this::redrawAll);
            }).start();
        });
        addItem(popup, "Toggle Regex Mode (Success/Failure)", e -> {
            for (MessageEntry msg : getSelectedMessages()) {
                msg.toggleFailureRegexMode();
                msg.clearResults();
            }
            redrawAll();
        });
        addItem(popup, "Change Regexes", e -> onChangeRegexes());
        addItem(popup, "Change Target Domain", e -> onChangeDomain());
        addItem(popup, "Remove Request(s)", e -> {
            for (MessageEntry msg : getSelectedMessages()) db.deleteMessage(msg);
            redrawAll();
        });
        messageTable.setComponentPopupMenu(popup);
    }

    private void installMessageHeaderPopup() {
        JPopupMenu popup = new JPopupMenu();
        addItem(popup, "Remove Role", e -> {
            int col = messageTable.columnAtPoint(messageTable.getMousePosition());
            RoleEntry role = messageModel.getRoleForColumn(col);
            if (role != null) { db.deleteRole(role); redrawAll(); }
        });
        addItem(popup, "Bulk Select Checkboxes", e -> bulkSetRole(true));
        addItem(popup, "Bulk Unselect Checkboxes", e -> bulkSetRole(false));
        messageTable.getTableHeader().setComponentPopupMenu(popup);
    }

    private void installUserPopup() {
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
    }

    private void installUserHeaderPopup() {
        JPopupMenu popup = new JPopupMenu();
        addItem(popup, "Remove", e -> {
            int col = userTable.columnAtPoint(userTable.getMousePosition());
            if (userModel.isRoleColumn(col)) {
                RoleEntry role = userModel.getRoleForColumn(col);
                if (role != null) { db.deleteRole(role); redrawAll(); }
            } else if (userModel.isHeaderColumn(col)) {
                int headerIdx = col - 2; // STATIC_COLS = 2
                db.deleteHeader(headerIdx);
                redrawAll();
            }
        });
        userTable.getTableHeader().setComponentPopupMenu(popup);
    }

    private void bulkSetRole(boolean value) {
        int col = messageTable.columnAtPoint(messageTable.getMousePosition());
        RoleEntry role = messageModel.getRoleForColumn(col);
        if (role != null) {
            db.setRoleForAllSelectedMessages(getSelectedMessages(), role, value);
            redrawAll();
        }
    }

    // --- Button Actions ---

    private void onRun() {
        saveEditorChanges();
        viewerTabs.removeAll();
        new Thread(() -> engine.run(null, this::setRunning, this::redrawAll)).start();
    }

    private void setRunning(boolean running) {
        SwingUtilities.invokeLater(() -> {
            runButton.setEnabled(!running);
            cancelButton.setEnabled(running);
        });
    }

    private void onNewUser() {
        String name = JOptionPane.showInputDialog(this, "Enter New User:");
        if (name != null && !name.trim().isEmpty()) {
            db.getOrCreateUser(name.trim());
            redrawAll();
        }
    }

    private void onNewRole() {
        String name = JOptionPane.showInputDialog(this, "Enter New Role:");
        if (name != null && !name.trim().isEmpty()) {
            db.getOrCreateRole(name.trim());
            redrawAll();
        }
    }

    private void onNewHeader() {
        db.addHeader();
        redrawAll();
    }

    private void onSave() {
        saveEditorChanges();
        int result = fileChooser.showSaveDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) return;
        File file = fileChooser.getSelectedFile();
        if (file.exists()) {
            int confirm = JOptionPane.showConfirmDialog(this,
                    "The file exists, overwrite?", "Existing File", JOptionPane.YES_NO_OPTION);
            if (confirm != JOptionPane.YES_OPTION) return;
        }
        try {
            StateManager.save(db, file);
        } catch (IOException ex) {
            api.logging().logToError("Save failed: " + ex.getMessage());
            JOptionPane.showMessageDialog(this, "Save failed: " + ex.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void onLoad() {
        int result = fileChooser.showOpenDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) return;
        try {
            StateManager.load(db, fileChooser.getSelectedFile());
            redrawAll();
        } catch (IOException ex) {
            api.logging().logToError("Load failed: " + ex.getMessage());
            JOptionPane.showMessageDialog(this, "Load failed: " + ex.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void onClear() {
        int result = JOptionPane.showConfirmDialog(this,
                "Clear AuthMatrix Configuration?", "Clear Config", JOptionPane.YES_NO_OPTION);
        if (result == JOptionPane.YES_OPTION) {
            db.clear();
            viewerTabs.removeAll();
            editableEditors.clear();
            redrawAll();
        }
    }

    private void onChangeRegexes() {
        JComboBox<String> regexCombo = new JComboBox<>(db.getKnownRegexes().toArray(new String[0]));
        regexCombo.setEditable(true);
        JCheckBox failureMode = new JCheckBox("Regex Detects Unauthorized Requests (Failure Mode)");

        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.add(new JLabel("Select a Regex for all selected Requests:"));
        panel.add(regexCombo);
        panel.add(failureMode);

        int result = JOptionPane.showConfirmDialog(this, panel,
                "Select Response Regex", JOptionPane.OK_CANCEL_OPTION);
        if (result != JOptionPane.OK_OPTION) return;
        String regex = (String) regexCombo.getSelectedItem();
        if (regex == null || regex.isEmpty()) return;

        for (MessageEntry msg : getSelectedMessages()) {
            msg.setRegex(regex);
            msg.setFailureRegexMode(failureMode.isSelected());
        }
        db.addRegexIfNew(regex);
        redrawAll();
    }

    private void onChangeDomain() {
        List<MessageEntry> selected = getSelectedMessages();
        if (selected.isEmpty()) return;

        // Autofill from first message
        MessageEntry first = selected.get(0);
        JTextField hostField = new JTextField(first.getHost(), 25);
        JTextField portField = new JTextField(String.valueOf(first.getPort()), 25);
        JCheckBox tlsBox = new JCheckBox("Use HTTPS", first.isSecure());
        JCheckBox replaceHostBox = new JCheckBox("Replace Host in HTTP header", true);

        tlsBox.addItemListener(e -> {
            if (e.getStateChange() == ItemEvent.SELECTED && "80".equals(portField.getText()))
                portField.setText("443");
            else if (e.getStateChange() == ItemEvent.DESELECTED && "443".equals(portField.getText()))
                portField.setText("80");
        });

        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.add(labeled("Host:", hostField));
        panel.add(labeled("Port:", portField));
        panel.add(tlsBox);
        panel.add(replaceHostBox);

        int result = JOptionPane.showConfirmDialog(this, panel,
                "Configure target details", JOptionPane.OK_CANCEL_OPTION);
        if (result != JOptionPane.OK_OPTION) return;

        String host = hostField.getText().trim();
        if (host.isEmpty()) return;
        int port;
        try {
            port = Integer.parseInt(portField.getText().trim());
        } catch (NumberFormatException ex) {
            port = tlsBox.isSelected() ? 443 : 80;
        }
        boolean secure = tlsBox.isSelected();

        for (MessageEntry msg : selected) {
            if (replaceHostBox.isSelected() && msg.getRequest() != null) {
                msg.setRequest(RunEngine.replaceHostHeader(msg.getRequest(), host));
            }
            msg.setHost(host);
            msg.setPort(port);
            msg.setSecure(secure);
            msg.clearResults();
        }
        redrawAll();
    }

    // --- Helpers ---

    private List<MessageEntry> getSelectedMessages() {
        int[] rows = messageTable.getSelectedRows();
        List<MessageEntry> result = new ArrayList<>();
        for (int row : rows) {
            if (row >= 0 && row < db.getMessages().size()) {
                result.add(db.getMessages().get(row));
            }
        }
        return result;
    }

    private static JPanel labeled(String label, JComponent field) {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT));
        p.add(new JLabel(label));
        p.add(field);
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
}
