package authmatrix.ui;

import authmatrix.PathMask;
import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.util.List;
import java.util.Optional;

/** Shared editor for creating, testing and removing ignored path patterns. */
public final class PathMaskEditor extends JPanel {
    private final JTextArea patterns = new JTextArea(7, 48);
    private final JTextField example = new JTextField(48);
    private final JTextArea feedback = new JTextArea(3, 1);
    private final JButton save = new JButton("Save patterns");
    private final JButton cancel = new JButton("Cancel");
    private final Color normalFeedback;

    public PathMaskEditor(List<String> initial, String examplePath) {
        super(new BorderLayout(0, 12));
        setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));
        JTextArea help = new JTextArea("Replace changing IDs or values with *. Use ** to include multiple path segments or the whole query string.\n"
                + "Examples: /api/users/*/profile   /search?nonce=*   /api/users/*?**\n"
                + "Patterns match the full path, including the query string, across hosts and methods.");
        help.setEditable(false);
        help.setFocusable(false);
        help.setLineWrap(true);
        help.setWrapStyleWord(true);
        help.setOpaque(false);
        help.setFont(UIManager.getFont("Label.font"));
        help.setRows(7);
        // Wrapped text has no usable width during the dialog's first layout pass.
        help.setPreferredSize(new Dimension(0, help.getFontMetrics(help.getFont()).getHeight() * 7));
        add(help, BorderLayout.NORTH);

        JPanel fields = new JPanel(new BorderLayout(0, 12));
        JPanel patternGroup = new JPanel(new BorderLayout(0, 6));
        JLabel patternLabel = new JLabel("Ignored path patterns (one per line)");
        patternLabel.setLabelFor(patterns);
        patterns.getAccessibleContext().setAccessibleName("Ignored path patterns (one per line)");
        patterns.setText(String.join("\n", initial));
        patterns.setCaretPosition(patterns.getText().length());
        patternGroup.add(patternLabel, BorderLayout.NORTH);
        patternGroup.add(new JScrollPane(patterns), BorderLayout.CENTER);
        fields.add(patternGroup, BorderLayout.CENTER);

        JPanel exampleGroup = new JPanel(new BorderLayout(0, 6));
        JLabel exampleLabel = new JLabel("Test a request path");
        exampleLabel.setLabelFor(example);
        example.setText(examplePath == null ? "" : examplePath);
        exampleGroup.add(exampleLabel, BorderLayout.NORTH);
        exampleGroup.add(example, BorderLayout.CENTER);
        feedback.setEditable(false);
        feedback.setFocusable(false);
        feedback.setLineWrap(true);
        feedback.setWrapStyleWord(true);
        feedback.setOpaque(false);
        feedback.setFont(UIManager.getFont("Label.font"));
        feedback.setPreferredSize(new Dimension(0, feedback.getFontMetrics(feedback.getFont()).getHeight() * 3));
        feedback.getAccessibleContext().setAccessibleName("Pattern match result");
        exampleGroup.add(feedback, BorderLayout.SOUTH);
        fields.add(exampleGroup, BorderLayout.SOUTH);
        add(fields, BorderLayout.CENTER);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        buttons.add(cancel);
        buttons.add(save);
        add(buttons, BorderLayout.SOUTH);
        normalFeedback = feedback.getForeground();
        patterns.getDocument().addDocumentListener(new ValidationListener());
        example.getDocument().addDocumentListener(new ValidationListener());
        updateFeedback();
    }

    public List<String> patternExpressions() {
        List<String> result = patterns.getText().lines().map(String::strip).filter(s -> !s.isEmpty()).distinct().toList();
        for (int i = 0; i < result.size(); i++) {
            try { new PathMask(result.get(i)); }
            catch (IllegalArgumentException ex) { throw new IllegalArgumentException("Pattern " + (i + 1) + ": " + ex.getMessage()); }
        }
        return result;
    }

    private void updateFeedback() {
        try {
            List<String> expressions = patternExpressions();
            boolean matches = expressions.stream().anyMatch(p -> new PathMask(p).matches(example.getText()));
            feedback.setForeground(normalFeedback);
            feedback.setText(expressions.isEmpty() ? "No patterns. Paths will only be ignored by exact-path rules."
                    : example.getText().isEmpty() ? "Enter a path to test these patterns."
                    : matches ? "Matches: this path will be ignored." : "No match: these patterns will not ignore this path.");
            save.setEnabled(true);
        } catch (IllegalArgumentException ex) {
            feedback.setForeground(new Color(160, 0, 0));
            feedback.setText(ex.getMessage());
            save.setEnabled(false);
        }
    }

    public static Optional<List<String>> showDialog(Component owner, List<String> initial, String examplePath) {
        PathMaskEditor editor = new PathMaskEditor(initial, examplePath);
        Window window = SwingUtilities.getWindowAncestor(owner);
        JDialog dialog = new JDialog(window, "Ignore path patterns", Dialog.ModalityType.APPLICATION_MODAL);
        boolean[] saved = {false};
        editor.save.addActionListener(new CallbackAction(() -> { saved[0] = true; dialog.dispose(); }));
        CallbackAction dismiss = new CallbackAction(dialog::dispose);
        editor.cancel.addActionListener(dismiss);
        dialog.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        dialog.setContentPane(editor);
        dialog.getRootPane().setDefaultButton(editor.save);
        dialog.getRootPane().registerKeyboardAction(dismiss, KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
                JComponent.WHEN_IN_FOCUSED_WINDOW);
        dialog.pack();
        dialog.setMinimumSize(new Dimension(560, 480));
        dialog.setLocationRelativeTo(owner);
        SwingUtilities.invokeLater(editor.patterns::requestFocusInWindow);
        dialog.setVisible(true);
        return saved[0] ? Optional.of(editor.patternExpressions()) : Optional.empty();
    }

    private class ValidationListener implements DocumentListener {
        @Override public void insertUpdate(DocumentEvent e) { updateFeedback(); }
        @Override public void removeUpdate(DocumentEvent e) { updateFeedback(); }
        @Override public void changedUpdate(DocumentEvent e) { updateFeedback(); }
    }

    private static class CallbackAction implements ActionListener {
        private final Runnable callback;
        CallbackAction(Runnable callback) { this.callback = callback; }
        @Override public void actionPerformed(ActionEvent e) { callback.run(); }
    }
}
