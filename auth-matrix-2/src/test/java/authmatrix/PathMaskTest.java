package authmatrix;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import java.util.Random;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

class PathMaskTest {
    static Stream<Arguments> paths() {
        return Stream.of(
                Arguments.of("/users/*/profile", "/users/8924e84e-8b89-4aec-b213-54d8e98aef17/profile", true),
                Arguments.of("/users/*/profile", "/users/42/profile", true),
                Arguments.of("/users/*/profile", "/users/42/other/profile", false),
                Arguments.of("/users/*/profile", "/users/42/profile?nonce=123", false),
                Arguments.of("/users/*?**", "/users/42?nonce=123&sort=desc", true),
                Arguments.of("/users/*?**", "/users/42", false),
                Arguments.of("/search?nonce=*", "/search?nonce=changing-guid", true),
                Arguments.of("/search?nonce=*", "/search?nonce=123&admin=true", false),
                Arguments.of("/search?nonce=*&sort=asc", "/search?nonce=123&sort=asc", true),
                Arguments.of("/search?nonce=*&sort=asc", "/search?nonce=123&sort=desc", false),
                Arguments.of("/files/**", "/files/a/b/c?download=true", true),
                Arguments.of("/**", "/", true),
                Arguments.of("/*", "/", true),
                Arguments.of("/*", "/a/b", false),
                Arguments.of("/*", "/a?x=1", false),
                Arguments.of("/files/*.json", "/files/report.json", true),
                Arguments.of("/files/*.json", "/files/reportXjson", false),
                Arguments.of("/files/[id](1)+$", "/files/[id](1)+$", true),
                Arguments.of("/prefix", "/prefix/extra", false),
                Arguments.of("/Users/*", "/users/42", false),
                Arguments.of("/literal/\\*", "/literal/*", true),
                Arguments.of("/literal/\\*", "/literal/42", false),
                Arguments.of("/a*b*c", "/abc", true),
                Arguments.of("/a*b*c", "/axybzc", true));
    }

    @ParameterizedTest @MethodSource("paths")
    void matchesWholePathsWithExplicitWildcardBoundaries(String mask, String path, boolean expected) {
        assertEquals(expected, new PathMask(mask).matches(path));
    }

    @Test void literalMasksRoundTripGeneratedPathsWithoutWideningThem() {
        Random random = new Random(928471L);
        String alphabet = "abc012/*?=&#[].()+$^\\é用户\n";
        for (int sample = 0; sample < 500; sample++) {
            StringBuilder path = new StringBuilder("/");
            int length = random.nextInt(64);
            for (int i = 0; i < length; i++) path.append(alphabet.charAt(random.nextInt(alphabet.length())));
            PathMask mask = new PathMask(PathMask.literal(path.toString()));
            assertTrue(mask.matches(path.toString()), path.toString());
            assertFalse(mask.matches(path + "/extra"), path.toString());
        }
    }

    @Test void arbitraryDynamicValuesStayInsideTheMaskedSegment() {
        Random random = new Random(452812L);
        String alphabet = "abc012-_.%é用户";
        PathMask mask = new PathMask("/accounts/*/profile?nonce=*&sort=asc");
        for (int sample = 0; sample < 500; sample++) {
            StringBuilder value = new StringBuilder();
            for (int i = random.nextInt(64); i > 0; i--) value.append(alphabet.charAt(random.nextInt(alphabet.length())));
            assertTrue(mask.matches("/accounts/" + value + "/profile?nonce=" + value + "&sort=asc"));
            assertFalse(mask.matches("/accounts/" + value + "/extra/profile?nonce=" + value + "&sort=asc"));
            assertFalse(mask.matches("/accounts/" + value + "/profile?nonce=" + value + "&extra=1&sort=asc"));
        }
    }

    @Test void validatesIncompleteMasksAndHandlesMissingPaths() {
        for (String invalid : new String[]{null, "", "users/*", "/users/\\"}) {
            assertThrows(IllegalArgumentException.class, () -> new PathMask(invalid));
        }
        assertFalse(new PathMask("/**").matches(null));
    }
}
