package authmatrix;

import authmatrix.model.*;

import java.awt.Color;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Single-file, self-contained HTML report of the AuthMatrix state.
 * Renders the matrix tables with the same color coding used in the UI,
 * and embeds each message's request/response (original + per-user) as
 * base64 data for an interactive detail drawer.
 */
public final class HtmlExporter {

    private HtmlExporter() {}

    public static void export(MatrixDB db, File file) throws IOException {
        String html = buildHtml(db);
        try (Writer w = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(file), StandardCharsets.UTF_8))) {
            w.write(html);
        }
    }

    // ========== Top-level HTML ==========

    private static String buildHtml(MatrixDB db) {
        StringBuilder sb = new StringBuilder();
        sb.append("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n");
        sb.append("<title>AuthMatrix Report</title>\n");
        sb.append("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n");
        sb.append("<style>").append(CSS).append("</style>\n");
        sb.append("</head><body>\n");

        Stats stats = computeStats(db);
        buildHeader(sb, db, stats);
        buildMain(sb, db);
        buildDrawer(sb);

        sb.append("<script id=\"authmatrix-data\" type=\"application/json\">");
        sb.append(buildDataJson(db));
        sb.append("</script>\n");
        sb.append("<script>").append(JS).append("</script>\n");
        sb.append("</body></html>\n");
        return sb.toString();
    }

    // ========== Header ==========

    private static void buildHeader(StringBuilder sb, MatrixDB db, Stats stats) {
        String target = summaryTarget(db);
        String now = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm"));

        sb.append("<header class=\"top\">\n");
        sb.append("  <div class=\"title\">\n");
        sb.append("    <h1>AuthMatrix Report</h1>\n");
        sb.append("    <div class=\"meta\">").append(esc(target)).append(" &middot; ").append(esc(now)).append("</div>\n");
        sb.append("  </div>\n");
        sb.append("  <div class=\"stats\">\n");
        chip(sb, "total",  stats.total + " requests");
        chip(sb, "green",  stats.passed + " passed");
        chip(sb, "red",    stats.vulns + " potential vulns");
        chip(sb, "blue",   stats.badTokens + " bad tokens");
        chip(sb, "muted",  stats.notRun + " not run");
        sb.append("  </div>\n");
        sb.append("  <div class=\"toolbar\">\n");
        sb.append("    <input id=\"filter\" type=\"search\" placeholder=\"Filter requests by name, host, or regex…\">\n");
        sb.append("    <label class=\"togg\"><input type=\"checkbox\" id=\"vulns-only\"> Show vulns only</label>\n");
        sb.append("    <div class=\"legend\">\n");
        sb.append("      <span class=\"sw green\"></span>Safe");
        sb.append("      <span class=\"sw red\"></span>Vulnerability");
        sb.append("      <span class=\"sw blue\"></span>Bad token");
        sb.append("      <span class=\"sw failure\"></span>Failure regex");
        sb.append("    </div>\n");
        sb.append("  </div>\n");
        sb.append("</header>\n");
    }

    private static void chip(StringBuilder sb, String cls, String text) {
        sb.append("    <span class=\"chip ").append(cls).append("\">").append(esc(text)).append("</span>\n");
    }

    // ========== Main (sections + matrix tables) ==========

    private static void buildMain(StringBuilder sb, MatrixDB db) {
        sb.append("<main>\n");
        List<RoleEntry> roles = db.getAllRoles();

        // Root section
        List<MessageEntry> root = db.getRootMessages();
        if (!root.isEmpty()) buildSection(sb, null, root, roles);

        for (SectionEntry sec : db.getSections()) {
            List<MessageEntry> msgs = db.getMessagesInSection(sec);
            buildSection(sb, sec, msgs, roles);
        }

        if (db.getMessages().isEmpty()) {
            sb.append("  <div class=\"empty\">No requests in this matrix.</div>\n");
        }
        sb.append("</main>\n");
    }

    private static void buildSection(StringBuilder sb, SectionEntry sec, List<MessageEntry> msgs, List<RoleEntry> roles) {
        String color = sec != null ? hex(sec.getColor()) : "#5a6a7a";
        String name = sec != null ? sec.getName() : "Unsectioned";
        sb.append("<section class=\"sec\" data-section=\"").append(esc(name)).append("\">\n");
        sb.append("  <div class=\"sec-head\" style=\"background:").append(color).append("\" data-toggle=\"sec\">\n");
        sb.append("    <span class=\"caret\">&#9660;</span><span class=\"sec-name\">").append(esc(name)).append("</span>");
        sb.append("    <span class=\"sec-count\">").append(msgs.size()).append(" req").append(msgs.size() == 1 ? "" : "s").append("</span>\n");
        sb.append("  </div>\n");

        sb.append("  <div class=\"sec-body\">\n");
        sb.append("  <table class=\"matrix\"><thead><tr>");
        sb.append("<th class=\"id\">#</th>");
        sb.append("<th class=\"name\">Request</th>");
        sb.append("<th class=\"regex\">Regex</th>");
        for (RoleEntry r : roles) {
            sb.append("<th class=\"role").append(r.isSingleUser() ? " single" : "").append("\">")
                    .append(esc(r.getName())).append("</th>");
        }
        sb.append("</tr></thead><tbody>\n");

        for (MessageEntry m : msgs) {
            sb.append("    <tr class=\"row").append(m.isEnabled() ? "" : " disabled").append("\" data-id=\"")
                    .append(m.getId()).append("\" data-name=\"").append(esc(m.getName())).append("\" data-host=\"")
                    .append(esc(m.getHost())).append("\" data-regex=\"").append(esc(m.getRegex())).append("\">");
            sb.append("<td class=\"id\">").append(m.getId()).append("</td>");
            sb.append("<td class=\"name\"><span class=\"method\">").append(esc(methodOf(m))).append("</span>")
                    .append("<span class=\"path\">").append(esc(pathOf(m))).append("</span></td>");
            String regexCls = "regex" + (m.isFailureRegexMode() ? " failure" : "");
            sb.append("<td class=\"").append(regexCls).append("\">").append(esc(m.getRegex()));
            if (m.isFailureRegexMode()) sb.append(" <span class=\"fmark\">failure</span>");
            sb.append("</td>");
            for (RoleEntry r : roles) {
                sb.append(renderCell(m, r));
            }
            sb.append("</tr>\n");
        }
        sb.append("  </tbody></table>\n");
        sb.append("  </div>\n");
        sb.append("</section>\n");
    }

    /**
     * Matrix result cell — matches Renderers.ResultCheckboxRenderer logic:
     * disabled → gray, has result → green/red/blue, no result → just checked/unchecked.
     */
    private static String renderCell(MessageEntry m, RoleEntry r) {
        boolean authorized = m.isRoleAuthorized(r);
        String state = "empty";
        String mark = authorized ? "&#10004;" : "";

        if (!m.isEnabled()) {
            state = "disabled";
        } else if (m.getRoleResults().containsKey(r)) {
            boolean passed = Boolean.TRUE.equals(m.getRoleResults().get(r));
            if (passed) state = "green";
            else if (authorized) state = "blue";
            else state = "red";
        } else {
            state = authorized ? "auth" : "empty";
        }
        return "<td class=\"cell " + state + "\" title=\"" + esc(r.getName()) + cellTooltip(m, r) + "\">" + mark + "</td>";
    }

    private static String cellTooltip(MessageEntry m, RoleEntry r) {
        StringBuilder t = new StringBuilder();
        t.append(" &mdash; ").append(m.isRoleAuthorized(r) ? "authorized" : "not authorized");
        if (m.getRoleResults().containsKey(r)) {
            boolean passed = Boolean.TRUE.equals(m.getRoleResults().get(r));
            t.append(", ").append(passed ? "passed" : "failed");
        }
        return t.toString();
    }

    // ========== Drawer (request/response viewer) ==========

    private static void buildDrawer(StringBuilder sb) {
        sb.append("<aside id=\"drawer\" class=\"drawer hidden\" aria-hidden=\"true\">\n");
        sb.append("  <div class=\"drawer-resize\" id=\"resize\"></div>\n");
        sb.append("  <div class=\"drawer-head\">\n");
        sb.append("    <div class=\"drawer-title\">\n");
        sb.append("      <h2 id=\"d-title\">&nbsp;</h2>\n");
        sb.append("      <div class=\"meta\" id=\"d-meta\">&nbsp;</div>\n");
        sb.append("    </div>\n");
        sb.append("    <button class=\"btn-close\" id=\"d-close\" title=\"Close (Esc)\">&times;</button>\n");
        sb.append("  </div>\n");
        sb.append("  <nav class=\"tabs users\" id=\"d-users\"></nav>\n");
        sb.append("  <nav class=\"tabs rr\" id=\"d-rr\">\n");
        sb.append("    <button class=\"active\" data-rr=\"request\">Request</button>\n");
        sb.append("    <button data-rr=\"response\">Response</button>\n");
        sb.append("    <div class=\"rr-actions\"><button id=\"d-copy\" title=\"Copy to clipboard\">Copy</button></div>\n");
        sb.append("  </nav>\n");
        sb.append("  <pre id=\"d-body\" class=\"body\"></pre>\n");
        sb.append("</aside>\n");
    }

    // ========== JSON data payload ==========

    private static String buildDataJson(MatrixDB db) {
        StringBuilder j = new StringBuilder();
        j.append('{');
        j.append("\"messages\":{");
        boolean firstMsg = true;
        for (MessageEntry m : db.getMessages()) {
            if (!firstMsg) j.append(',');
            firstMsg = false;
            j.append('"').append(m.getId()).append("\":");
            appendMessageJson(j, db, m);
        }
        j.append('}');
        j.append('}');
        return j.toString();
    }

    private static void appendMessageJson(StringBuilder j, MatrixDB db, MessageEntry m) {
        j.append('{');
        j.append("\"id\":").append(m.getId()).append(',');
        j.append("\"name\":\"").append(jsonEsc(m.getName())).append("\",");
        j.append("\"host\":\"").append(jsonEsc(m.getHost())).append("\",");
        j.append("\"port\":").append(m.getPort()).append(',');
        j.append("\"secure\":").append(m.isSecure()).append(',');
        j.append("\"regex\":\"").append(jsonEsc(m.getRegex())).append("\",");
        j.append("\"failureMode\":").append(m.isFailureRegexMode()).append(',');
        j.append("\"enabled\":").append(m.isEnabled()).append(',');
        j.append("\"url\":\"").append(jsonEsc(urlOf(m))).append("\",");

        // Original request/response
        j.append("\"runs\":[");
        j.append('{');
        j.append("\"user\":\"Original\",");
        j.append("\"request\":\"").append(b64(m.getRequest())).append("\",");
        j.append("\"response\":\"").append(b64(m.getResponse())).append("\",");
        j.append("\"status\":\"original\"");
        j.append('}');

        // Per-user runs
        for (UserEntry u : db.getUsers()) {
            MessageEntry.RunResult r = m.getUserRuns().get(u);
            if (r == null) continue;
            j.append(',');
            j.append('{');
            j.append("\"user\":\"").append(jsonEsc(u.getName())).append("\",");
            j.append("\"request\":\"").append(b64(r.request())).append("\",");
            j.append("\"response\":\"").append(b64(r.response())).append("\",");
            j.append("\"status\":\"").append(userStatus(m, u, db)).append("\"");
            j.append('}');
        }
        j.append("],");

        // Authorized roles
        j.append("\"authorizedRoles\":[");
        boolean first = true;
        for (RoleEntry role : db.getAllRoles()) {
            if (!m.isRoleAuthorized(role)) continue;
            if (!first) j.append(',');
            first = false;
            j.append('"').append(jsonEsc(role.getName())).append('"');
        }
        j.append("],");

        // Role results
        j.append("\"roleResults\":{");
        first = true;
        for (Map.Entry<RoleEntry, Boolean> e : m.getRoleResults().entrySet()) {
            if (!first) j.append(',');
            first = false;
            j.append('"').append(jsonEsc(e.getKey().getName())).append("\":").append(e.getValue());
        }
        j.append('}');

        j.append('}');
    }

    /** Summarize a user's run outcome by checking roles they belong to. */
    private static String userStatus(MessageEntry m, UserEntry u, MatrixDB db) {
        boolean anyVuln = false, anyBad = false, anyPass = false;
        for (RoleEntry role : db.getAllRoles()) {
            if (!u.hasRole(role)) continue;
            if (!m.getRoleResults().containsKey(role)) continue;
            boolean passed = Boolean.TRUE.equals(m.getRoleResults().get(role));
            boolean authorized = m.isRoleAuthorized(role);
            if (passed) anyPass = true;
            else if (authorized) anyBad = true;
            else anyVuln = true;
        }
        if (anyVuln) return "red";
        if (anyBad) return "blue";
        if (anyPass) return "green";
        return "none";
    }

    // ========== Helpers ==========

    private record Stats(int total, int passed, int vulns, int badTokens, int notRun) {}

    private static Stats computeStats(MatrixDB db) {
        int total = 0, passed = 0, vulns = 0, bad = 0, notRun = 0;
        for (MessageEntry m : db.getMessages()) {
            total++;
            if (m.getRoleResults().isEmpty()) { notRun++; continue; }
            boolean anyVuln = false, anyBad = false;
            for (Map.Entry<RoleEntry, Boolean> e : m.getRoleResults().entrySet()) {
                boolean pass = Boolean.TRUE.equals(e.getValue());
                boolean auth = m.isRoleAuthorized(e.getKey());
                if (!pass && !auth) anyVuln = true;
                else if (!pass && auth) anyBad = true;
            }
            if (anyVuln) vulns++;
            else if (anyBad) bad++;
            else passed++;
        }
        return new Stats(total, passed, vulns, bad, notRun);
    }

    private static String summaryTarget(MatrixDB db) {
        Set<String> hosts = new LinkedHashSet<>();
        for (MessageEntry m : db.getMessages()) {
            if (m.getHost() != null && !m.getHost().isEmpty()) hosts.add(m.getHost());
            if (hosts.size() >= 3) break;
        }
        if (hosts.isEmpty()) return "(no target set)";
        return String.join(", ", hosts) + (db.getMessages().stream()
                .map(MessageEntry::getHost).distinct().count() > 3 ? ", …" : "");
    }

    private static String urlOf(MessageEntry m) {
        String scheme = m.isSecure() ? "https" : "http";
        int port = m.getPort();
        boolean defaultPort = (m.isSecure() && port == 443) || (!m.isSecure() && port == 80);
        String hostPart = defaultPort ? m.getHost() : m.getHost() + ":" + port;
        return scheme + "://" + hostPart + pathOf(m);
    }

    private static String methodOf(MessageEntry m) {
        String n = m.getName();
        if (n == null) return "";
        int space = n.indexOf(' ');
        return space > 0 ? n.substring(0, space) : "";
    }

    private static String pathOf(MessageEntry m) {
        String n = m.getName();
        if (n == null) return "";
        int slash = n.indexOf('/');
        return slash >= 0 ? n.substring(slash) : n;
    }

    private static String hex(Color c) {
        return String.format("#%02x%02x%02x", c.getRed(), c.getGreen(), c.getBlue());
    }

    private static String b64(byte[] data) {
        if (data == null) return "";
        return Base64.getEncoder().encodeToString(data);
    }

    private static String esc(String s) {
        if (s == null) return "";
        StringBuilder out = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '&' -> out.append("&amp;");
                case '<' -> out.append("&lt;");
                case '>' -> out.append("&gt;");
                case '"' -> out.append("&quot;");
                case '\'' -> out.append("&#39;");
                default  -> out.append(c);
            }
        }
        return out.toString();
    }

    private static String jsonEsc(String s) {
        if (s == null) return "";
        StringBuilder out = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"'  -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                case '/'  -> out.append("\\/"); // prevents </script> in JSON breaking out
                default -> {
                    if (c < 0x20) out.append(String.format("\\u%04x", (int) c));
                    else out.append(c);
                }
            }
        }
        return out.toString();
    }

    // ========== Inline CSS ==========

    private static final String CSS = """
            *,*::before,*::after{box-sizing:border-box}
            html,body{margin:0;height:100%}
            body{font:13px/1.4 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;
                 background:#fafbfc;color:#222;}
            code,pre,.mono{font-family:ui-monospace,'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace}
            header.top{position:sticky;top:0;z-index:5;background:#fff;border-bottom:1px solid #e5e7eb;
                       padding:14px 20px 10px;box-shadow:0 1px 0 rgba(0,0,0,.02)}
            .title{display:flex;align-items:baseline;gap:14px;flex-wrap:wrap}
            .title h1{margin:0;font-size:18px;letter-spacing:.2px}
            .meta{color:#667085;font-size:12px}
            .stats{display:flex;gap:8px;margin-top:10px;flex-wrap:wrap}
            .chip{padding:3px 10px;border-radius:999px;font-size:12px;font-weight:600;
                  border:1px solid rgba(0,0,0,.06)}
            .chip.total{background:#eef2ff;color:#3730a3}
            .chip.green{background:#e8fbe0;color:#216a2a}
            .chip.red{background:#ffecec;color:#a61b1b}
            .chip.blue{background:#e0f7ff;color:#055880}
            .chip.muted{background:#f2f4f7;color:#475467}
            .toolbar{display:flex;align-items:center;gap:12px;margin-top:10px;flex-wrap:wrap}
            .toolbar input[type=search]{flex:1;min-width:240px;padding:7px 10px;border:1px solid #d0d5dd;
                   border-radius:6px;font-size:13px;background:#fcfcfd}
            .toolbar input[type=search]:focus{outline:none;border-color:#7c9bff;box-shadow:0 0 0 3px rgba(124,155,255,.2)}
            .togg{font-size:12px;color:#344054;display:flex;align-items:center;gap:6px;cursor:pointer}
            .legend{display:flex;gap:10px;font-size:11px;color:#475467;align-items:center;margin-left:auto}
            .sw{display:inline-block;width:12px;height:12px;border-radius:3px;margin:0 4px 0 10px;border:1px solid rgba(0,0,0,.1);vertical-align:middle}
            .sw.green{background:#87f717}.sw.red{background:#ff3217}.sw.blue{background:#00ccff}
            .sw.failure{background:#9999cc}
            main{padding:16px 20px 60vh}
            section.sec{margin-bottom:18px;background:#fff;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden;
                        box-shadow:0 1px 2px rgba(16,24,40,.04)}
            .sec-head{color:#fff;padding:8px 12px;font-weight:600;font-size:13px;cursor:pointer;
                      display:flex;align-items:center;gap:8px;user-select:none;letter-spacing:.2px}
            .caret{display:inline-block;transition:transform .15s ease;font-size:9px;opacity:.9}
            section.collapsed .caret{transform:rotate(-90deg)}
            section.collapsed .sec-body{display:none}
            .sec-count{margin-left:auto;opacity:.85;font-weight:500;font-size:11px;
                       background:rgba(255,255,255,.18);padding:2px 8px;border-radius:10px}
            .sec-body{overflow-x:auto}
            table.matrix{border-collapse:collapse;width:100%;font-size:12.5px;table-layout:fixed}
            table.matrix thead th{position:sticky;top:0;background:#f8fafc;text-align:left;padding:8px 10px;
                 font-weight:600;color:#344054;border-bottom:1px solid #e5e7eb;white-space:nowrap}
            table.matrix th.id,table.matrix td.id{width:46px;text-align:right;color:#98a2b3;font-variant-numeric:tabular-nums}
            table.matrix th.name{width:32%}
            table.matrix th.regex{width:18%}
            table.matrix th.role{width:90px;text-align:center}
            table.matrix th.role.single{color:#667085;font-weight:500;font-style:italic}
            table.matrix td{padding:7px 10px;border-bottom:1px solid #f2f4f7;vertical-align:middle}
            table.matrix tr.row{cursor:pointer;transition:background .08s}
            table.matrix tr.row:hover{background:#f8fafc}
            table.matrix tr.row.active{background:#eef2ff}
            table.matrix tr.disabled{color:#9aa0aa;background:#f9fafb}
            table.matrix td.name{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
            .method{display:inline-block;font-family:ui-monospace,monospace;font-size:11px;font-weight:700;
                    padding:1px 6px;border-radius:3px;margin-right:8px;background:#eef2ff;color:#3730a3;
                    min-width:44px;text-align:center}
            .path{font-family:ui-monospace,monospace;color:#344054}
            td.regex{font-family:ui-monospace,monospace;font-size:11.5px;color:#475467;
                     overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
            td.regex.failure{background:#eceafb}
            .fmark{font-size:10px;background:#9999cc;color:#fff;padding:1px 5px;border-radius:3px;margin-left:4px;font-style:normal}
            td.cell{text-align:center;font-weight:700;color:#fff;font-size:12px;border-left:1px solid #fff}
            td.cell.empty{background:#fff;color:#cfd4dc}
            td.cell.auth{background:#cfd8e3;color:#fff}
            td.cell.green{background:#87f717;color:#0e3b00}
            td.cell.red{background:#ff3217;color:#fff}
            td.cell.blue{background:#00ccff;color:#064a66}
            td.cell.disabled{background:#cbd0d9;color:#fff}
            tr.row.active td.cell.green{background:#9dec55}
            tr.row.active td.cell.red{background:#ff6a52}
            tr.row.active td.cell.blue{background:#60d9f6}
            .empty{padding:40px;text-align:center;color:#667085}

            /* Drawer */
            .drawer{position:fixed;left:0;right:0;bottom:0;height:48vh;min-height:220px;max-height:85vh;
                    background:#fff;border-top:1px solid #d0d5dd;box-shadow:0 -4px 16px rgba(16,24,40,.08);
                    display:flex;flex-direction:column;transform:translateY(100%);transition:transform .18s ease;z-index:10}
            .drawer.open{transform:translateY(0)}
            .drawer.hidden{display:none}
            .drawer-resize{position:absolute;top:-3px;left:0;right:0;height:6px;cursor:ns-resize;z-index:3}
            .drawer-resize::before{content:"";display:block;width:40px;height:3px;border-radius:3px;background:#d0d5dd;
                                   margin:2px auto 0;opacity:.6}
            .drawer-head{padding:10px 16px 8px;border-bottom:1px solid #eef0f3;display:flex;align-items:center;gap:10px}
            .drawer-title h2{margin:0;font-size:14px;color:#101828;font-family:ui-monospace,monospace;font-weight:600;
                             overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
            .drawer-title{flex:1;min-width:0}
            .btn-close{border:none;background:#f2f4f7;color:#475467;width:28px;height:28px;border-radius:4px;
                       font-size:18px;line-height:1;cursor:pointer}
            .btn-close:hover{background:#e4e7ec;color:#101828}
            .tabs{display:flex;gap:0;border-bottom:1px solid #eef0f3;background:#fcfcfd;padding:0 8px;overflow-x:auto}
            .tabs button{appearance:none;background:transparent;border:none;padding:8px 12px;font-size:12px;
                          color:#667085;cursor:pointer;border-bottom:2px solid transparent;font-weight:500;white-space:nowrap}
            .tabs button:hover{color:#101828}
            .tabs button.active{color:#101828;border-bottom-color:#3730a3}
            .tabs.users button .dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;background:#cfd4dc;vertical-align:middle}
            .tabs.users button .dot.green{background:#59a14f}
            .tabs.users button .dot.red{background:#e15759}
            .tabs.users button .dot.blue{background:#00ccff}
            .rr-actions{margin-left:auto;display:flex;align-items:center;padding:4px 0}
            .rr-actions button{background:#f2f4f7;border:1px solid #e4e7ec;border-radius:4px;
                                padding:3px 10px;font-size:11px;cursor:pointer;color:#344054}
            .rr-actions button:hover{background:#e4e7ec}
            pre.body{flex:1;margin:0;padding:14px 18px;overflow:auto;white-space:pre-wrap;word-break:break-word;
                     background:#0e1420;color:#e4e7ec;font-size:12.5px;line-height:1.45}
            pre.body .hdr-key{color:#7fd4ff}
            pre.body .status{color:#87f717;font-weight:600}
            pre.body .status.err{color:#ff6a52}
            .hidden{display:none}
            @media (prefers-color-scheme: dark) {
              body{background:#0f1115;color:#e4e7ec}
              header.top{background:#151821;border-color:#2a2f3a}
              .meta{color:#98a2b3}
              .toolbar input[type=search]{background:#1c1f2a;color:#e4e7ec;border-color:#2a2f3a}
              section.sec{background:#151821;border-color:#2a2f3a}
              table.matrix thead th{background:#1c1f2a;color:#c1c7cf;border-color:#2a2f3a}
              table.matrix td{border-color:#23283a}
              table.matrix tr.row:hover{background:#1a1f2b}
              table.matrix tr.row.active{background:#1f2740}
              .path{color:#c1c7cf}
              td.regex{color:#98a2b3}
              td.cell.empty{background:#151821;color:#3a4052}
              .drawer{background:#151821;border-color:#2a2f3a}
              .drawer-head{border-color:#2a2f3a}
              .drawer-title h2{color:#e4e7ec}
              .btn-close{background:#23283a;color:#98a2b3}
              .btn-close:hover{background:#2a2f3a;color:#e4e7ec}
              .tabs{background:#151821;border-color:#2a2f3a}
              .tabs button{color:#98a2b3}
              .tabs button:hover{color:#e4e7ec}
              .tabs button.active{color:#e4e7ec;border-bottom-color:#7c9bff}
              .rr-actions button{background:#23283a;color:#c1c7cf;border-color:#2a2f3a}
              .rr-actions button:hover{background:#2a2f3a}
              .method{background:#23283a;color:#a5b4fc}
              td.cell.auth{background:#3a4052;color:#e4e7ec}
              td.cell.disabled{background:#2a2f3a;color:#98a2b3}
              td.regex.failure{background:#2a2438;color:#cdc4ff}
            }
            """;

    // ========== Inline JS ==========

    private static final String JS = """
            (function(){
              var raw = document.getElementById('authmatrix-data').textContent || '{}';
              var DATA = JSON.parse(raw);
              var drawer = document.getElementById('drawer');
              var dTitle = document.getElementById('d-title');
              var dMeta  = document.getElementById('d-meta');
              var dUsers = document.getElementById('d-users');
              var dRR    = document.getElementById('d-rr');
              var dBody  = document.getElementById('d-body');
              var dCopy  = document.getElementById('d-copy');
              var currentMsg = null;
              var currentUserIdx = 0;
              var currentView = 'request';

              function decodeB64(s){
                if (!s) return '';
                try {
                  var bin = atob(s);
                  var bytes = new Uint8Array(bin.length);
                  for (var i=0;i<bin.length;i++) bytes[i] = bin.charCodeAt(i);
                  return new TextDecoder('utf-8',{fatal:false}).decode(bytes);
                } catch(e){ return '[decode error]'; }
              }

              function openMessage(id){
                var msg = DATA.messages[id];
                if (!msg) return;
                currentMsg = msg;
                currentUserIdx = 0;
                currentView = 'request';

                // Highlight row
                document.querySelectorAll('tr.row.active').forEach(function(r){r.classList.remove('active');});
                var row = document.querySelector('tr.row[data-id="'+id+'"]');
                if (row) row.classList.add('active');

                // Title + meta
                dTitle.textContent = msg.name || ('Request #'+msg.id);
                var authed = (msg.authorizedRoles||[]).join(', ') || '—';
                var mode = msg.failureMode ? 'failure regex' : 'success regex';
                dMeta.innerHTML = '<span>'+escapeHtml(msg.url)+'</span> &middot; '
                                 +'<span>authorized: '+escapeHtml(authed)+'</span> &middot; '
                                 +'<span>'+mode+': <code>'+escapeHtml(msg.regex||'')+'</code></span>';

                // User tabs
                dUsers.innerHTML = '';
                (msg.runs || []).forEach(function(run, idx){
                  var b = document.createElement('button');
                  if (idx === 0) b.classList.add('active');
                  b.dataset.idx = idx;
                  var dotCls = run.status === 'original' ? '' : run.status;
                  b.innerHTML = '<span class="dot '+dotCls+'"></span>'+escapeHtml(run.user);
                  b.addEventListener('click', function(){ selectUser(idx); });
                  dUsers.appendChild(b);
                });

                // Reset RR tabs to Request
                dRR.querySelectorAll('button[data-rr]').forEach(function(btn){
                  btn.classList.toggle('active', btn.dataset.rr === 'request');
                });

                drawer.classList.remove('hidden');
                requestAnimationFrame(function(){ drawer.classList.add('open'); drawer.setAttribute('aria-hidden','false'); });
                renderBody();
              }

              function selectUser(idx){
                currentUserIdx = idx;
                dUsers.querySelectorAll('button').forEach(function(b,i){ b.classList.toggle('active', i===idx); });
                renderBody();
              }

              function selectRR(view){
                currentView = view;
                dRR.querySelectorAll('button[data-rr]').forEach(function(b){
                  b.classList.toggle('active', b.dataset.rr === view);
                });
                renderBody();
              }

              function renderBody(){
                if (!currentMsg) return;
                var run = currentMsg.runs[currentUserIdx];
                if (!run) { dBody.textContent = ''; return; }
                var text = decodeB64(currentView === 'request' ? run.request : run.response);
                if (!text) {
                  dBody.innerHTML = '<span style="color:#667085">(no '+currentView+' data)</span>';
                  return;
                }
                dBody.textContent = text;
              }

              function closeDrawer(){
                drawer.classList.remove('open');
                drawer.setAttribute('aria-hidden','true');
                setTimeout(function(){ drawer.classList.add('hidden'); }, 180);
                document.querySelectorAll('tr.row.active').forEach(function(r){r.classList.remove('active');});
              }

              function escapeHtml(s){
                return (s||'').replace(/[&<>"']/g, function(c){
                  return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;','\\'':'&#39;'})[c];
                });
              }

              // Row clicks
              document.querySelectorAll('tr.row').forEach(function(r){
                r.addEventListener('click', function(){ openMessage(r.dataset.id); });
              });

              // Close button & Esc
              document.getElementById('d-close').addEventListener('click', closeDrawer);
              document.addEventListener('keydown', function(e){
                if (e.key === 'Escape' && !drawer.classList.contains('hidden')) closeDrawer();
                // j/k navigate rows within filtered set
                if ((e.key === 'j' || e.key === 'k') && !drawer.classList.contains('hidden')) {
                  var visibleRows = Array.from(document.querySelectorAll('tr.row')).filter(function(r){return r.style.display !== 'none';});
                  var current = document.querySelector('tr.row.active');
                  var idx = visibleRows.indexOf(current);
                  if (idx < 0) return;
                  var next = e.key === 'j' ? visibleRows[idx+1] : visibleRows[idx-1];
                  if (next) { openMessage(next.dataset.id); next.scrollIntoView({block:'nearest'}); e.preventDefault(); }
                }
              });

              // RR tabs
              dRR.querySelectorAll('button[data-rr]').forEach(function(b){
                b.addEventListener('click', function(){ selectRR(b.dataset.rr); });
              });

              // Copy
              dCopy.addEventListener('click', function(){
                var text = dBody.textContent || '';
                if (navigator.clipboard) {
                  navigator.clipboard.writeText(text).then(function(){
                    dCopy.textContent = 'Copied'; setTimeout(function(){dCopy.textContent='Copy';}, 1200);
                  });
                }
              });

              // Resize drawer
              var resizer = document.getElementById('resize');
              var resizing = false, startY = 0, startH = 0;
              resizer.addEventListener('mousedown', function(e){
                resizing = true; startY = e.clientY; startH = drawer.offsetHeight;
                document.body.style.userSelect = 'none';
              });
              document.addEventListener('mousemove', function(e){
                if (!resizing) return;
                var newH = startH + (startY - e.clientY);
                var vh = window.innerHeight;
                newH = Math.max(180, Math.min(vh*0.9, newH));
                drawer.style.height = newH + 'px';
              });
              document.addEventListener('mouseup', function(){
                resizing = false; document.body.style.userSelect = '';
              });

              // Section collapse
              document.querySelectorAll('.sec-head').forEach(function(h){
                h.addEventListener('click', function(){
                  h.parentElement.classList.toggle('collapsed');
                });
              });

              // Filter
              var filter = document.getElementById('filter');
              var vulnsOnly = document.getElementById('vulns-only');
              function applyFilter(){
                var q = (filter.value || '').toLowerCase().trim();
                var onlyVulns = vulnsOnly.checked;
                document.querySelectorAll('section.sec').forEach(function(sec){
                  var anyVisible = false;
                  sec.querySelectorAll('tr.row').forEach(function(r){
                    var matchQ = !q
                      || (r.dataset.name||'').toLowerCase().indexOf(q) >= 0
                      || (r.dataset.host||'').toLowerCase().indexOf(q) >= 0
                      || (r.dataset.regex||'').toLowerCase().indexOf(q) >= 0;
                    var matchV = !onlyVulns || r.querySelector('td.cell.red');
                    var show = matchQ && matchV;
                    r.style.display = show ? '' : 'none';
                    if (show) anyVisible = true;
                  });
                  sec.style.display = anyVisible ? '' : 'none';
                });
              }
              filter.addEventListener('input', applyFilter);
              vulnsOnly.addEventListener('change', applyFilter);
            })();
            """;
}
