package authmatrix;

import java.util.ArrayList;
import java.util.List;

/** A full-path glob: * stays within a segment/value; ** may cross delimiters. */
public final class PathMask {
    private static final int STAR = -1;
    private static final int DEEP_STAR = -2;
    private final String expression;
    private final int[] tokens;

    public PathMask(String expression) {
        if (expression == null || !expression.startsWith("/")) {
            throw new IllegalArgumentException("Start the pattern with /, for example /api/users/*/profile.");
        }
        this.expression = expression;
        List<Integer> parsed = new ArrayList<>();
        for (int i = 0; i < expression.length(); i++) {
            char c = expression.charAt(i);
            if (c == '\\') {
                if (++i == expression.length()) {
                    throw new IllegalArgumentException("Add a character after the final backslash, or use two backslashes.");
                }
                parsed.add((int) expression.charAt(i));
            } else if (c == '*') {
                boolean deep = i + 1 < expression.length() && expression.charAt(i + 1) == '*';
                while (i + 1 < expression.length() && expression.charAt(i + 1) == '*') i++;
                parsed.add(deep ? DEEP_STAR : STAR);
            } else {
                parsed.add((int) c);
            }
        }
        tokens = parsed.stream().mapToInt(Integer::intValue).toArray();
    }

    public String expression() { return expression; }

    public static String literal(String path) {
        return path.replace("\\", "\\\\").replace("*", "\\*");
    }

    public boolean matches(String path) {
        if (path == null) return false;
        // Dynamic programming avoids regex backtracking on long paths and masks.
        boolean[] reachable = new boolean[path.length() + 1];
        reachable[0] = true;
        for (int token : tokens) {
            if (token == STAR || token == DEEP_STAR) {
                for (int j = 1; j <= path.length(); j++) {
                    char c = path.charAt(j - 1);
                    boolean allowed = token == DEEP_STAR || (c != '/' && c != '?' && c != '&' && c != '#' && c != '=');
                    reachable[j] = reachable[j] || (reachable[j - 1] && allowed);
                }
            } else {
                for (int j = path.length(); j > 0; j--) {
                    reachable[j] = reachable[j - 1] && path.charAt(j - 1) == token;
                }
                reachable[0] = false;
            }
        }
        return reachable[path.length()];
    }
}
