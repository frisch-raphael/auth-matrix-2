package authmatrix;

import authmatrix.model.MatrixDB;
import authmatrix.ui.AuthMatrixTab;
import authmatrix.ui.PathMaskEditor;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import com.google.gson.JsonObject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.swing.*;
import java.awt.Component;
import java.lang.reflect.Proxy;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiFunction;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.*;

class ExtensionContextMenuTest {
    @TempDir Path temp;

    @Test void ignoresSelectedPathsWithoutAddingRequestsAndPersistsUntilResumed() throws Exception {
        var stored = new HashMap<String, String>();
        var api = TestApi.create("Highlight fixture", "highlights", stored);
        MatrixDB db = new MatrixDB();
        String before = StateManager.serialize(db, null);
        var firstColor = new AtomicReference<>(HighlightColor.ORANGE);
        var secondColor = new AtomicReference<>(HighlightColor.ORANGE);
        HttpRequestResponse first = message("/account?id=1", firstColor);
        HttpRequestResponse second = message("/logout", secondColor);
        SwingUtilities.invokeAndWait(() -> {
            var store = new SessionStore(api, temp);
            AuthMatrixTab tab = new AuthMatrixTab(api, db, store, new JsonObject());
            AuthMatrixTab restored = null;
            try {
                tab.setIgnoredHighlightPathPatterns(List.of("/users/*/profile", "/search?nonce=*"));
                assertTrue(tab.isHighlightPathIgnored("/users/first-guid/profile"));
                assertTrue(tab.isHighlightPathIgnored("/users/second-guid/profile"));
                assertTrue(tab.isHighlightPathIgnored("/search?nonce=changed"));
                assertFalse(tab.isHighlightPathIgnored("/users/id/settings"));
                assertThrows(IllegalArgumentException.class,
                        () -> tab.setIgnoredHighlightPathPatterns(List.of("/valid/*", "missing-leading-slash")));
                assertTrue(tab.isHighlightPathIgnored("/users/first-guid/profile"));
                var menu = new Extension.AuthMatrixContextMenu(api, db, tab);
                // The editor can also expose a row already in the table selection.
                item(menu.provideMenuItems(event(List.of(first, second), first)),
                        "Stop highlighting request path(s)").doClick();
                assertEquals(HighlightColor.NONE, firstColor.get());
                assertEquals(HighlightColor.NONE, secondColor.get());
                assertEquals("Keep this note", first.annotations().notes());
                assertEquals(before, StateManager.serialize(db, null));
                assertTrue(tab.isHighlightPathIgnored("/account?id=1"));
                assertTrue(tab.isHighlightPathIgnored("/logout"));
                assertFalse(tab.isHighlightPathIgnored("/account?id=2"));
                assertFalse(tab.isHighlightPathIgnored("/other"));
                // Test the ordinary capture path after the tab has been laid out.
                tab.setSize(1200, 800);
                tab.dispatchEvent(new java.awt.event.ComponentEvent(tab,
                        java.awt.event.ComponentEvent.COMPONENT_RESIZED));
                assertEquals(2, tab.captureUiState().getAsJsonArray("ignoredHighlightPaths").size());
                tab.persistSession();
                MatrixDB restoredDb = new MatrixDB();
                JsonObject ui = StateManager.restore(restoredDb, store.load());
                restored = new AuthMatrixTab(api, restoredDb, new SessionStore(api, temp), ui);
                assertTrue(restored.isHighlightPathIgnored("/logout"));
                assertTrue(restored.isHighlightPathIgnored("/users/another-guid/profile"));
                assertTrue(restored.isHighlightPathIgnored("/search?nonce=another-value"));
                JMenuBar menus = findMenus(restored);
                item(List.of(menus.getMenu(2).getMenuComponents()),
                        "Resume highlighting ignored paths").doClick();
                assertFalse(restored.isHighlightPathIgnored("/logout"));
                assertFalse(restored.isHighlightPathIgnored("/users/another-guid/profile"));
                JsonObject resumed = StateManager.restore(new MatrixDB(), store.load());
                assertEquals(0, resumed.getAsJsonArray("ignoredHighlightPaths").size());
                assertEquals(0, resumed.getAsJsonArray("ignoredHighlightPathPatterns").size());
            } catch (java.io.IOException ex) {
                throw new RuntimeException(ex);
            } finally {
                if (restored != null) restored.shutdown();
                tab.shutdown();
            }
        });
    }

    @Test void patternDialogSavesAndCancelsWithoutAddingRequests() throws Exception {
        var api = TestApi.create("Pattern fixture", "patterns", new HashMap<>());
        var color = new AtomicReference<>(HighlightColor.ORANGE);
        HttpRequestResponse selected = message("/users/8924e84e-8b89-4aec-b213-54d8e98aef17/profile", color);
        SwingUtilities.invokeAndWait(() -> {
            MatrixDB db = new MatrixDB();
            AuthMatrixTab tab = new AuthMatrixTab(api, db, new SessionStore(api, temp), new JsonObject());
            try {
                String before = StateManager.serialize(db, null);
                var menu = new Extension.AuthMatrixContextMenu(api, db, tab);
                JMenuItem action = item(menu.provideMenuItems(event(List.of(selected), null)), "Ignore path pattern...");
                driveDialog(action::doClick, editor -> {
                    JTextArea patterns = PathMaskEditorTest.find(editor, JTextArea.class, "Ignored path patterns (one per line)");
                    assertTrue(patterns.getText().contains("8924e84e"));
                    patterns.setText("/users/*/profile");
                }, "Cancel");
                assertEquals(HighlightColor.ORANGE, color.get());
                assertFalse(tab.isHighlightPathIgnored("/users/new-guid/profile"));
                driveDialog(action::doClick, editor -> {
                    JTextArea patterns = PathMaskEditorTest.find(editor, JTextArea.class, "Ignored path patterns (one per line)");
                    patterns.setText("/users/*/profile");
                }, "Save patterns");
                assertEquals(HighlightColor.NONE, color.get());
                assertTrue(tab.isHighlightPathIgnored("/users/new-guid/profile"));
                assertEquals(before, StateManager.serialize(db, null));
                assertEquals("Keep this note", selected.annotations().notes());
            } finally { tab.shutdown(); }
        });
    }

    private static void driveDialog(Runnable open, Consumer<PathMaskEditor> edit, String button) {
        AtomicReference<Throwable> failure = new AtomicReference<>();
        Timer driver = new Timer(150, e -> {
            JDialog dialog = java.util.Arrays.stream(java.awt.Window.getWindows())
                    .filter(w -> w instanceof JDialog d && d.isShowing() && "Ignore path patterns".equals(d.getTitle()))
                    .map(JDialog.class::cast).findFirst().orElseThrow();
            try {
                PathMaskEditor editor = (PathMaskEditor) dialog.getContentPane();
                edit.accept(editor);
                JButton action = PathMaskEditorTest.find(editor, JButton.class, button);
                assertTrue(action.isEnabled());
                action.doClick();
            } catch (Throwable ex) { failure.set(ex); }
            finally { dialog.dispose(); }
        });
        driver.setRepeats(false);
        driver.start();
        try { open.run(); }
        finally { driver.stop(); }
        if (failure.get() != null) throw new AssertionError("Pattern dialog interaction failed", failure.get());
    }

    @Test void supportsEditorOnlySelectionAndEmptyMenus() throws Exception {
        var api = TestApi.create("Editor fixture", "editor", new HashMap<>());
        var color = new AtomicReference<>(HighlightColor.ORANGE);
        HttpRequestResponse selected = message("/editor", color);
        SwingUtilities.invokeAndWait(() -> {
            MatrixDB db = new MatrixDB();
            AuthMatrixTab tab = new AuthMatrixTab(api, db, new SessionStore(api, temp), new JsonObject());
            try {
                var menu = new Extension.AuthMatrixContextMenu(api, db, tab);
                assertTrue(menu.provideMenuItems(event(List.of(), null)).isEmpty());
                item(menu.provideMenuItems(event(List.of(), selected)),
                        "Stop highlighting request path(s)").doClick();
                assertEquals(HighlightColor.NONE, color.get());
                assertTrue(tab.isHighlightPathIgnored("/editor"));
                tab.ignoreHighlightPath(null);
                assertFalse(tab.isHighlightPathIgnored(null));
                assertEquals(1, tab.captureUiState().getAsJsonArray("ignoredHighlightPaths").size());
                assertTrue(db.getMessages().isEmpty());
            } finally { tab.shutdown(); }
        });
    }

    private static JMenuItem item(List<Component> items, String label) {
        return items.stream().filter(c -> c instanceof JMenuItem i && label.equals(i.getText()))
                .map(JMenuItem.class::cast).findFirst().orElseThrow();
    }

    private static JMenuBar findMenus(java.awt.Container parent) {
        for (Component child : parent.getComponents()) {
            if (child instanceof JMenuBar bar) return bar;
            if (child instanceof java.awt.Container container) {
                JMenuBar bar = findMenus(container);
                if (bar != null) return bar;
            }
        }
        return null;
    }

    private static ContextMenuEvent event(List<HttpRequestResponse> selected, HttpRequestResponse editor) {
        MessageEditorHttpRequestResponse messageEditor = stub(MessageEditorHttpRequestResponse.class,
                (name, args) -> name.equals("requestResponse") ? editor : null);
        return stub(ContextMenuEvent.class, (name, args) -> switch (name) {
            case "selectedRequestResponses" -> selected;
            case "messageEditorRequestResponse" -> editor == null ? Optional.empty() : Optional.of(messageEditor);
            default -> null;
        });
    }

    private static HttpRequestResponse message(String path, AtomicReference<HighlightColor> color) {
        HttpRequest request = stub(HttpRequest.class, (name, args) -> name.equals("path") ? path : null);
        Annotations annotations = stub(Annotations.class, (name, args) -> switch (name) {
            case "highlightColor" -> color.get();
            case "setHighlightColor" -> { color.set((HighlightColor) args[0]); yield null; }
            case "notes" -> "Keep this note";
            case "setNotes" -> throw new AssertionError("Notes must remain unchanged");
            default -> null;
        });
        return stub(HttpRequestResponse.class, (name, args) -> switch (name) {
            case "request" -> request;
            case "annotations" -> annotations;
            default -> null;
        });
    }

    private static <T> T stub(Class<T> type, BiFunction<String, Object[], Object> calls) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, (object, method, args) ->
                switch (method.getName()) {
                    case "equals" -> object == args[0];
                    case "hashCode" -> System.identityHashCode(object);
                    case "toString" -> type.getSimpleName();
                    default -> calls.apply(method.getName(), args);
                }));
    }
}
