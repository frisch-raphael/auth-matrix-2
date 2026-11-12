package authmatrix;

import authmatrix.ui.PathMaskEditor;
import org.junit.jupiter.api.Test;
import javax.swing.*;
import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class PathMaskEditorTest {
    static <T extends Component> T find(Container parent, Class<T> type, String name) {
        for (Component child : parent.getComponents()) {
            if (type.isInstance(child) && (name == null || name.equals(child.getAccessibleContext().getAccessibleName()))) {
                return type.cast(child);
            }
            if (child instanceof Container container) {
                T match = find(container, type, name);
                if (match != null) return match;
            }
        }
        return null;
    }

    private static void layout(Container parent) {
        parent.doLayout();
        for (Component child : parent.getComponents()) if (child instanceof Container container) layout(container);
    }

    @Test void previewsMatchesAndBlocksInvalidRulesWithoutBlockingAnEmptyList() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            PathMaskEditor editor = new PathMaskEditor(List.of("/api/users/*/profile"), "/api/users/42/profile");
            JTextArea patterns = find(editor, JTextArea.class, "Ignored path patterns (one per line)");
            JTextArea feedback = find(editor, JTextArea.class, "Pattern match result");
            JButton save = find(editor, JButton.class, "Save patterns");
            assertTrue(feedback.getText().startsWith("Matches:"));
            patterns.setText("/other/*\n/api/users/*/profile\n/api/users/*/profile\n");
            assertEquals(2, editor.patternExpressions().size());
            assertTrue(feedback.getText().startsWith("Matches:"));
            patterns.setText("/other/*");
            assertTrue(feedback.getText().startsWith("No match:"));
            patterns.setText("users/*");
            assertFalse(save.isEnabled());
            assertTrue(feedback.getText().contains("Start the pattern with /"));
            patterns.setText("");
            assertTrue(save.isEnabled());
            assertEquals(List.of(), editor.patternExpressions());
            assertTrue(feedback.getText().startsWith("No patterns."));
        });
    }

    @Test void rendersPatternEditorAtNormalAndMinimumWidths() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            PathMaskEditor editor = new PathMaskEditor(List.of("/api/users/*/profile", "/search?nonce=*"),
                    "/api/users/8924e84e-8b89-4aec-b213-54d8e98aef17/profile");
            for (int width : new int[]{700, 560}) {
                editor.setSize(width, 500);
                layout(editor);
                BufferedImage image = new BufferedImage(width, 500, BufferedImage.TYPE_INT_RGB);
                Graphics2D graphics = image.createGraphics();
                editor.printAll(graphics);
                graphics.dispose();
                try { ImageIO.write(image, "png", new File("build/path-mask-editor-" + width + ".png")); }
                catch (java.io.IOException ex) { throw new RuntimeException(ex); }
                JButton save = find(editor, JButton.class, "Save patterns");
                Rectangle saveBounds = SwingUtilities.convertRectangle(save.getParent(), save.getBounds(), editor);
                assertTrue(new Rectangle(0, 0, width, 500).contains(saveBounds));
                JTextArea patterns = find(editor, JTextArea.class, "Ignored path patterns (one per line)");
                assertTrue(patterns.getVisibleRect().height >= 60, () -> hierarchy(editor));
            }
        });
    }

    private static String hierarchy(Container parent) {
        StringBuilder text = new StringBuilder(parent.getClass().getSimpleName() + " " + parent.getBounds() + " preferred=" + parent.getPreferredSize() + "\n");
        for (Component child : parent.getComponents()) {
            if (child instanceof Container container) text.append(hierarchy(container));
        }
        return text.toString();
    }
}
