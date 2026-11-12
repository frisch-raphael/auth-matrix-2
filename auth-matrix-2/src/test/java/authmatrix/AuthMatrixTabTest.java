package authmatrix;

import authmatrix.model.*;
import authmatrix.ui.AuthMatrixTab;
import com.google.gson.*;
import org.junit.jupiter.api.Test;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.util.*;
import javax.imageio.ImageIO;
import javax.swing.*;
import static org.junit.jupiter.api.Assertions.*;

class AuthMatrixTabTest {
    private static <T extends Component> T find(Container parent, Class<T> type) {
        for (Component c : parent.getComponents()) {
            if (type.isInstance(c)) return type.cast(c);
            if (c instanceof Container container) {
                T result = find(container, type);
                if (result != null) return result;
            }
        }
        return null;
    }
    private static void layout(Container parent) {
        parent.doLayout();
        for (Component c : parent.getComponents()) if (c instanceof Container container) layout(container);
    }
    @Test void rendersCompactActionsAndRestoresLayout() throws Exception {
        var api = TestApi.create("UI fixture", "ui", new HashMap<>());
        MatrixDB db = new MatrixDB();
        db.getOrCreateRole("Administrator"); db.getOrCreateRole("Member"); db.getOrCreateRole("Anonymous");
        db.getOrCreateUser("alice").setCookies("session=example-admin");
        db.getOrCreateUser("bob").setCookies("session=example-member");
        db.createMessage("example.test",443,true,null,null,"GET     /api/account","^HTTP/1.1 200");
        SectionEntry section = db.createSection("Account management");
        db.createMessageInSection(section,"example.test",443,true,null,null,"POST    /api/account/settings","^HTTP/1.1 200")
                .addRunResult(db.getUsers().getFirst(), null, null);
        db.createSection("Administration").setCollapsed(true);
        AuthMatrixTab[] ref = new AuthMatrixTab[1];
        JsonObject ui = new JsonObject(); ui.addProperty("mainDivider", 400); ui.addProperty("topDivider", 130);
        ui.addProperty("highlightNewPaths", true);
        ui.addProperty("selectedRequest", 1); ui.addProperty("viewerTab", 1); ui.addProperty("messageTab", 1);
        ui.add("userWidths", JsonParser.parseString("[180,260,120,120,120]"));
        SwingUtilities.invokeAndWait(() -> {
            ref[0] = new AuthMatrixTab(api, db, new SessionStore(api, java.nio.file.Path.of("build", "ui-session")), ui);
            ref[0].setSize(1200,800); layout(ref[0]);
        });
        SwingUtilities.invokeAndWait(() -> { });
        SwingUtilities.invokeAndWait(() -> {
            AuthMatrixTab tab = ref[0]; layout(tab);
            assertTrue(tab.isHighlightNewPathsEnabled());
            JMenuBar menus = find(tab, JMenuBar.class); assertNotNull(menus);
            assertEquals(3, menus.getMenuCount());
            assertEquals("Add", menus.getMenu(0).getText());
            assertEquals("Merge matrix...", menus.getMenu(1).getItem(1).getText());
            assertEquals(400, tab.captureUiState().get("mainDivider").getAsInt());
            assertEquals(1, tab.captureUiState().get("selectedRequest").getAsInt());
            assertEquals(1, tab.captureUiState().get("viewerTab").getAsInt());
            assertEquals(1, tab.captureUiState().get("messageTab").getAsInt());
            tab.redrawAll();
            assertEquals(1, tab.captureUiState().get("selectedRequest").getAsInt());
            assertEquals(1, tab.captureUiState().get("viewerTab").getAsInt());
            assertEquals(180, tab.captureUiState().getAsJsonArray("userWidths").get(0).getAsInt());
            try {
                for (int width : new int[]{1200,640}) {
                    tab.setSize(width, 800); layout(tab);
                    BufferedImage image = new BufferedImage(width,800,BufferedImage.TYPE_INT_RGB);
                    Graphics2D graphics = image.createGraphics(); tab.printAll(graphics); graphics.dispose();
                    File file = new File("build/ui-preview-" + width + ".png");
                    ImageIO.write(image,"png",file);
                    assertTrue(menus.getParent().getBounds().width >= menus.getX() + menus.getWidth());
                }
            } catch (java.io.IOException ex) { throw new RuntimeException(ex); }
            tab.shutdown();
        });
    }
}
