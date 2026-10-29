package dev.aib.broker.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.text.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Loads the broker's ES256 signing key. Dev-only key management: production would keep
 * this key in a KMS or HSM (see the roadmap).
 */
final class SigningKeys {

    private static final Logger log = LoggerFactory.getLogger(SigningKeys.class);

    private SigningKeys() {}

    static ECKey load(String keyFile) {
        if (keyFile == null || keyFile.isBlank()) {
            log.warn("BROKER_SIGNING_KEY_FILE is not set; using a throwaway signing key. Tokens will not survive a restart.");
            return generate();
        }
        Path path = Path.of(keyFile);
        try {
            if (Files.exists(path)) {
                return ECKey.parse(Files.readString(path));
            }
            ECKey key = generate();
            Files.createDirectories(path.toAbsolutePath().getParent());
            Files.writeString(path, key.toJSONString());
            trySetOwnerOnly(path);
            log.info("Generated a new signing key at {}", path);
            return key;
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot read or write signing key at " + path, e);
        } catch (ParseException e) {
            throw new IllegalStateException("Signing key file " + path + " is not a valid EC JWK", e);
        }
    }

    private static ECKey generate() {
        try {
            ECKey key = new ECKeyGenerator(Curve.P_256)
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(JWSAlgorithm.ES256)
                    .generate();
            return new ECKey.Builder(key).keyIDFromThumbprint().build();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    private static void trySetOwnerOnly(Path path) throws IOException {
        try {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException ignored) {
            // Non-POSIX file system
        }
    }
}
