package dev.aib.broker.support;

import java.util.Collection;
import java.util.Map;
import java.util.TreeMap;

/**
 * RFC 8785 (JSON Canonicalization Scheme) for the values the audit log stores: strings,
 * whole numbers, booleans, null, objects and arrays. Floating-point numbers, the hard part
 * of JCS, are rejected rather than half-supported.
 */
public final class CanonicalJson {

    private CanonicalJson() {}

    public static String write(Object value) {
        StringBuilder out = new StringBuilder();
        write(value, out);
        return out.toString();
    }

    private static void write(Object value, StringBuilder out) {
        switch (value) {
            case null -> out.append("null");
            case Boolean b -> out.append(b);
            case Long l -> out.append(l);
            case Integer i -> out.append(i);
            case String s -> writeString(s, out);
            case Map<?, ?> map -> writeObject(map, out);
            case Collection<?> list -> writeArray(list, out);
            default -> throw new IllegalArgumentException("Cannot canonicalize " + value.getClass().getName());
        }
    }

    /** Keys sorted by UTF-16 code units, which is what String.compareTo does. */
    private static void writeObject(Map<?, ?> map, StringBuilder out) {
        TreeMap<String, Object> sorted = new TreeMap<>();
        map.forEach((k, v) -> {
            if (!(k instanceof String key)) {
                throw new IllegalArgumentException("Object keys must be strings");
            }
            sorted.put(key, v);
        });
        out.append('{');
        boolean first = true;
        for (Map.Entry<String, Object> entry : sorted.entrySet()) {
            if (!first) {
                out.append(',');
            }
            first = false;
            writeString(entry.getKey(), out);
            out.append(':');
            write(entry.getValue(), out);
        }
        out.append('}');
    }

    private static void writeArray(Collection<?> list, StringBuilder out) {
        out.append('[');
        boolean first = true;
        for (Object item : list) {
            if (!first) {
                out.append(',');
            }
            first = false;
            write(item, out);
        }
        out.append(']');
    }

    /** Escapes exactly as ECMAScript JSON.stringify does, as RFC 8785 requires. */
    private static void writeString(String s, StringBuilder out) {
        out.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
    }
}
