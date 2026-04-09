package authmatrix;

import authmatrix.model.*;
import authmatrix.ui.AuthMatrixTab;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public class Extension implements BurpExtension {
    private static final String VERSION = "2.0.0";

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("AuthMatrix - v" + VERSION);

        MatrixDB db = new MatrixDB();
        AuthMatrixTab tab = new AuthMatrixTab(api, db);

        api.userInterface().registerSuiteTab("AuthMatrix", tab);

        AuthMatrixContextMenu contextMenu = new AuthMatrixContextMenu(api, db, tab);
        api.userInterface().registerContextMenuItemsProvider(contextMenu);

        KeyboardShortcutHandler shortcutHandler = new KeyboardShortcutHandler(contextMenu);
        KeyboardFocusManager.getCurrentKeyboardFocusManager().addKeyEventDispatcher(shortcutHandler);

        api.extension().registerUnloadingHandler(() ->
                KeyboardFocusManager.getCurrentKeyboardFocusManager().removeKeyEventDispatcher(shortcutHandler));

        api.logging().logToOutput("AuthMatrix v" + VERSION + " loaded. Use Ctrl+Shift+M to send selected request(s).");
    }

    // --- Keyboard Shortcut ---
    // When Ctrl+Shift+M is pressed, we simulate a right-click via Robot.
    // This triggers Burp's context menu mechanism which calls provideMenuItems
    // with the correct current selection. We intercept it there, send to AuthMatrix,
    // and dismiss the context menu.

    private static class KeyboardShortcutHandler implements KeyEventDispatcher {
        private final AuthMatrixContextMenu contextMenu;

        KeyboardShortcutHandler(AuthMatrixContextMenu contextMenu) {
            this.contextMenu = contextMenu;
        }

        @Override
        public boolean dispatchKeyEvent(KeyEvent e) {
            if (e.getID() != KeyEvent.KEY_PRESSED) return false;
            if (!e.isControlDown() || !e.isShiftDown() || e.getKeyCode() != KeyEvent.VK_M) return false;

            contextMenu.pendingKeyboardSend = true;
            try {
                Robot robot = new Robot();
                robot.mousePress(InputEvent.BUTTON3_DOWN_MASK);
                robot.mouseRelease(InputEvent.BUTTON3_DOWN_MASK);
            } catch (AWTException ex) {
                contextMenu.pendingKeyboardSend = false;
            }
            // Safety: reset flag if provideMenuItems wasn't called within 500ms
            javax.swing.Timer timeout = new javax.swing.Timer(500, evt -> contextMenu.pendingKeyboardSend = false);
            timeout.setRepeats(false);
            timeout.start();
            return true;
        }
    }

    // --- Context Menu ---

    static class AuthMatrixContextMenu implements ContextMenuItemsProvider {
        private final MontoyaApi api;
        private final MatrixDB db;
        private final AuthMatrixTab tab;
        volatile boolean pendingKeyboardSend = false;

        AuthMatrixContextMenu(MontoyaApi api, MatrixDB db, AuthMatrixTab tab) {
            this.api = api;
            this.db = db;
            this.tab = tab;
        }

        @Override
        public List<Component> provideMenuItems(ContextMenuEvent event) {
            List<HttpRequestResponse> selected = new ArrayList<>(event.selectedRequestResponses());

            // Also capture from message editor context (Repeater, etc.)
            event.messageEditorRequestResponse().ifPresent(editorReqResp -> {
                HttpRequestResponse reqResp = editorReqResp.requestResponse();
                if (reqResp != null && !selected.contains(reqResp)) {
                    selected.add(reqResp);
                }
            });

            if (selected.isEmpty()) return List.of();

            // If triggered by keyboard shortcut: send immediately, suppress context menu
            if (pendingKeyboardSend) {
                pendingKeyboardSend = false;
                SwingUtilities.invokeLater(() -> {
                    sendToAuthMatrix(api, db, tab, selected);
                    // Dismiss the context menu that appeared from the simulated right-click
                    MenuSelectionManager.defaultManager().clearSelectedPath();
                });
                return List.of();
            }

            // Normal right-click: show menu items
            List<Component> items = new ArrayList<>();

            JMenuItem sendItem = new JMenuItem("Send request(s) to AuthMatrix    Ctrl+Shift+M");
            sendItem.addActionListener(new SendToAuthMatrixAction(api, db, tab, selected));
            items.add(sendItem);

            if (selected.size() == 1) {
                for (UserEntry user : db.getUsers()) {
                    JMenuItem cookieItem = new JMenuItem("Send cookies to AuthMatrix user: " + user.getName());
                    cookieItem.addActionListener(new SendCookiesAction(api, db, tab, selected.get(0), user));
                    items.add(cookieItem);
                }
            }

            return items;
        }
    }

    // --- Shared send logic ---

    static void sendToAuthMatrix(MontoyaApi api, MatrixDB db, AuthMatrixTab tab, List<HttpRequestResponse> selected) {
        for (HttpRequestResponse reqResp : selected) {
            HttpRequest req = reqResp.request();
            if (req == null) continue;

            String method = req.method() != null ? req.method() : "GET";
            String path = req.path() != null ? req.path() : "/";
            String name = String.format("%-8s%s", method, path);

            String regex = "^HTTP/1\\.1 200 OK";
            if (reqResp.response() != null) {
                String statusLine = reqResp.response().toString().split("\r?\n")[0];
                if (!statusLine.isEmpty()) {
                    regex = "^" + Pattern.quote(statusLine);
                }
            }

            byte[] requestBytes = req.toByteArray().getBytes();
            byte[] responseBytes = reqResp.response() != null
                    ? reqResp.response().toByteArray().getBytes() : null;
            String host = req.httpService() != null ? req.httpService().host() : "localhost";
            int port = req.httpService() != null ? req.httpService().port() : 443;
            boolean secure = req.httpService() != null && req.httpService().secure();

            db.createMessage(host, port, secure, requestBytes, responseBytes, name, regex);
        }
        tab.redrawAll();
        tab.highlightTab();
        tab.scrollToLastMessage();
    }

    // --- Action Listeners ---

    private static class SendToAuthMatrixAction implements ActionListener {
        private final MontoyaApi api;
        private final MatrixDB db;
        private final AuthMatrixTab tab;
        private final List<HttpRequestResponse> selected;

        SendToAuthMatrixAction(MontoyaApi api, MatrixDB db, AuthMatrixTab tab, List<HttpRequestResponse> selected) {
            this.api = api;
            this.db = db;
            this.tab = tab;
            this.selected = selected;
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            sendToAuthMatrix(api, db, tab, selected);
        }
    }

    private static class SendCookiesAction implements ActionListener {
        private final MontoyaApi api;
        private final MatrixDB db;
        private final AuthMatrixTab tab;
        private final HttpRequestResponse reqResp;
        private final UserEntry user;

        SendCookiesAction(MontoyaApi api, MatrixDB db, AuthMatrixTab tab,
                          HttpRequestResponse reqResp, UserEntry user) {
            this.api = api;
            this.db = db;
            this.tab = tab;
            this.reqResp = reqResp;
            this.user = user;
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            String cookieVal = "";
            if (reqResp.request() != null) {
                for (HttpHeader header : reqResp.request().headers()) {
                    if (header.name().equalsIgnoreCase("Cookie")) {
                        cookieVal = header.value();
                        break;
                    }
                }
            }
            if (reqResp.response() != null) {
                StringBuilder setCookies = new StringBuilder();
                for (HttpHeader header : reqResp.response().headers()) {
                    if (header.name().equalsIgnoreCase("Set-Cookie")) {
                        String value = header.value();
                        int semi = value.indexOf(';');
                        if (semi > 0) value = value.substring(0, semi);
                        if (setCookies.length() > 0) setCookies.append("; ");
                        setCookies.append(value.trim());
                    }
                }
                if (setCookies.length() > 0) {
                    cookieVal = RunEngine.mergeCookies(cookieVal, setCookies.toString());
                }
            }
            user.setCookies(cookieVal);
            tab.redrawAll();
        }
    }
}
