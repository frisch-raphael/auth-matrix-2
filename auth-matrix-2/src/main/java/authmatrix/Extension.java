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
import java.util.Collections;
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

        // Global keyboard shortcut: Ctrl+Shift+M sends last right-clicked selection to AuthMatrix
        KeyboardShortcutHandler shortcutHandler = new KeyboardShortcutHandler(api, db, tab, contextMenu);
        KeyboardFocusManager.getCurrentKeyboardFocusManager().addKeyEventDispatcher(shortcutHandler);

        // Clean up the dispatcher on extension unload
        api.extension().registerUnloadingHandler(() -> {
            KeyboardFocusManager.getCurrentKeyboardFocusManager().removeKeyEventDispatcher(shortcutHandler);
        });

        api.logging().logToOutput("AuthMatrix v" + VERSION + " loaded. Shortcut: Ctrl+Shift+M to send last right-clicked request(s).");
    }

    // --- Keyboard Shortcut ---

    private static class KeyboardShortcutHandler implements KeyEventDispatcher {
        private final MontoyaApi api;
        private final MatrixDB db;
        private final AuthMatrixTab tab;
        private final AuthMatrixContextMenu contextMenu;

        KeyboardShortcutHandler(MontoyaApi api, MatrixDB db, AuthMatrixTab tab, AuthMatrixContextMenu contextMenu) {
            this.api = api;
            this.db = db;
            this.tab = tab;
            this.contextMenu = contextMenu;
        }

        @Override
        public boolean dispatchKeyEvent(KeyEvent e) {
            // Ctrl+Shift+M on key press
            if (e.getID() != KeyEvent.KEY_PRESSED) return false;
            if (!e.isControlDown() || !e.isShiftDown() || e.getKeyCode() != KeyEvent.VK_M) return false;

            List<HttpRequestResponse> lastSelection = contextMenu.getLastSelection();
            if (lastSelection == null || lastSelection.isEmpty()) {
                api.logging().logToOutput("No request selection available. Right-click on request(s) first, then use Ctrl+Shift+M.");
                return true; // consumed
            }

            sendToAuthMatrix(api, db, tab, lastSelection);
            return true; // consumed
        }
    }

    // --- Context Menu ---

    static class AuthMatrixContextMenu implements ContextMenuItemsProvider {
        private final MontoyaApi api;
        private final MatrixDB db;
        private final AuthMatrixTab tab;

        // Stores the most recent right-click selection for keyboard shortcut use
        private volatile List<HttpRequestResponse> lastSelection = Collections.emptyList();

        AuthMatrixContextMenu(MontoyaApi api, MatrixDB db, AuthMatrixTab tab) {
            this.api = api;
            this.db = db;
            this.tab = tab;
        }

        List<HttpRequestResponse> getLastSelection() {
            return lastSelection;
        }

        @Override
        public List<Component> provideMenuItems(ContextMenuEvent event) {
            List<HttpRequestResponse> selected = new ArrayList<>(event.selectedRequestResponses());

            // Also capture from message editor context (Repeater, etc.)
            event.messageEditorRequestResponse().ifPresent(editorReqResp ->  {
                HttpRequestResponse reqResp = editorReqResp.requestResponse();
                if (reqResp != null && !selected.contains(reqResp)) {
                    selected.add(reqResp);
                }
            });

            if (selected.isEmpty()) return List.of();

            // Capture selection for keyboard shortcut
            lastSelection = List.copyOf(selected);

            List<Component> items = new ArrayList<>();

            // "Send request(s) to AuthMatrix" with shortcut hint
            JMenuItem sendItem = new JMenuItem("Send request(s) to AuthMatrix");
            sendItem.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_M, InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK));
            sendItem.addActionListener(new SendToAuthMatrixAction(api, db, tab, selected));
            items.add(sendItem);

            // "Send cookies to user" (only for single selection)
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

            // Default regex from response status line
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

            // Get Cookie header from request
            if (reqResp.request() != null) {
                for (HttpHeader header : reqResp.request().headers()) {
                    if (header.name().equalsIgnoreCase("Cookie")) {
                        cookieVal = header.value();
                        break;
                    }
                }
            }

            // Get Set-Cookie headers from response
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
