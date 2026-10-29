package dev.aib.broker.support;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class CanonicalJsonTest {

    @Test
    void sortsKeysByUtf16CodeUnitsAsInRfc8785() {
        // The key-sorting example from RFC 8785 section 3.2.3
        Map<String, Object> input = new LinkedHashMap<>();
        input.put("\u20ac", "Euro Sign");
        input.put("\r", "Carriage Return");
        input.put("\ufb33", "Hebrew Letter Dalet With Dagesh");
        input.put("1", "One");
        input.put("\ud83d\ude00", "Emoji: Grinning Face");
        input.put("\u0080", "Control");
        input.put("\u00f6", "Latin Small Letter O With Diaeresis");

        String json = CanonicalJson.write(input);

        assertThat(json).isEqualTo("{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u0080\":\"Control\","
                + "\"\u00f6\":\"Latin Small Letter O With Diaeresis\",\"\u20ac\":\"Euro Sign\","
                + "\"\ud83d\ude00\":\"Emoji: Grinning Face\",\"\ufb33\":\"Hebrew Letter Dalet With Dagesh\"}");
    }

    @Test
    void writesNestedValuesWithoutWhitespace() {
        Map<String, Object> input = new LinkedHashMap<>();
        input.put("b", List.of(1L, true, "x"));
        input.put("a", Map.of("z", 2, "y", "\u0001\"\\\n"));
        input.put("c", null);

        assertThat(CanonicalJson.write(input))
                .isEqualTo("{\"a\":{\"y\":\"\\u0001\\\"\\\\\\n\",\"z\":2},\"b\":[1,true,\"x\"],\"c\":null}");
    }

    @Test
    void sameContentInAnyKeyOrderGivesTheSameOutput() {
        Map<String, Object> one = new LinkedHashMap<>();
        one.put("x", 1L);
        one.put("y", Arrays.asList("a", null));
        Map<String, Object> two = new LinkedHashMap<>();
        two.put("y", Arrays.asList("a", null));
        two.put("x", 1);

        assertThat(CanonicalJson.write(one)).isEqualTo(CanonicalJson.write(two));
    }

    @Test
    void rejectsFloatingPointNumbers() {
        assertThatThrownBy(() -> CanonicalJson.write(Map.of("amount", 30.5)))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
