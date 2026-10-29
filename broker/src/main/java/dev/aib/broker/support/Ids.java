package dev.aib.broker.support;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HexFormat;

public final class Ids {

    private static final SecureRandom RANDOM = new SecureRandom();

    private Ids() {}

    /** A random, prefixed identifier such as {@code agt_3f9a0c...}. */
    public static String newId(String prefix) {
        byte[] bytes = new byte[10];
        RANDOM.nextBytes(bytes);
        return prefix + "_" + HexFormat.of().formatHex(bytes);
    }

    /** Hex SHA-256, used to look tokens up without storing them. */
    public static String sha256(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
