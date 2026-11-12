# AuthMatrix v2 JSON state

Use **File > Save matrix** to export the current matrix and layout. Files use UTF-8 JSON and version `2.0.0`. Earlier v2 files without UI data, header counts, original responses or sections still load. Jython v1 state files are unsupported.

## Structure

- `version`: format version.
- `headerCount`: number of custom HTTP header columns, including empty columns.
- `roles`: ordered objects with `name` and `singleUser`.
- `users`: ordered objects with `name`, `cookiesBase64`, `headersBase64`, `enabled`, and `roles` (role name to boolean).
- `rows`: display-ordered sections and requests. Earlier v2 `messages` arrays are also accepted.
- `ui`: split positions, user/request column widths, request scroll offsets, selected request ID, viewer tab indices, proxy highlighting preference, `ignoredHighlightPaths` (an array of exact request paths, including query strings), and `ignoredHighlightPathPatterns` (an array of full-path glob patterns). `*` matches within a segment or query key/value; `**` can cross path and query delimiters. Backslash escapes the next character. Earlier files without these arrays load with empty ignore lists. Both lists are preserved during merge and restored on replace or session recovery.

Section rows have `type: "section"`, `name`, `color` (hex RGB) and `collapsed`.

Request rows have `type: "message"`, `id`, `name`, `host`, `port`, `secure`, `requestBase64`, `responseBase64` (original response), `regexBase64`, `failureRegexMode`, `enabled`, `roles`, `userRuns` and `roleResults`. `userRuns` maps user names to objects containing `requestBase64` and `responseBase64`; `roleResults` maps role names to result booleans.

HTTP payloads are stored as Base64 bytes; cookies, regexes and header strings use Base64 UTF-8. Base64 is an encoding, not encryption.

## Merge behavior

**File > Merge matrix** preserves current work and its UI layout:

- Roles with the same name and kind are reused. Conflicting role kinds receive unique imported names.
- Identical users are reused. Same-name users with different credentials, enabled state or role assignments receive names such as `alice (imported 2)`. Their single-user roles and run references are remapped.
- Sections with the same name are combined, retaining the current section's color and collapsed state.
- Requests are appended within their matching section, with fresh unique IDs. Imported root requests remain at root. Requests are not deduplicated, so separate test cases are retained.
- Existing and imported run responses remain available. Result colors are re-evaluated against the combined matrix; requests with no runs remain uncolored.
- Invalid imports leave the current matrix intact. Replacing a nonempty matrix requires confirmation.

## Automatic persistence

Every two seconds, and after matrix redraws or a clean extension unload, AuthMatrix checkpoints its session. A running matrix is saved after its run finishes. Burp project data is the primary store. A local recovery copy is also written atomically under `~/.authmatrix/sessions/`.

Named projects use a hashed stable project ID for their recovery file. Burp's default **Temporary Project** uses a shared recovery slot so it can recover after a new Burp process starts, including Community Edition. Concurrent default temporary projects share this slot; the most recent save wins. Montoya does not expose a temporary-project flag, so renamed temporary projects use their project ID instead and should be exported before closing.

Session recovery includes credentials and HTTP content. **File > Clear matrix** clears the current session and its next recovery snapshot. A hard process kill may lose changes since the last checkpoint.
