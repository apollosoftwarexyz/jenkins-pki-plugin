package xyz.apollosoftware.jenkins.pki.x500;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1String;

import javax.naming.ldap.Rdn;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Objects;
import java.util.Set;
import java.util.logging.Logger;

/**
 * A string-normalized relative distinguished name (RDN).
 *
 * <p>For example, C=GB would become {@code RelativeDN("C", "GB")}.
 *
 * @param key of the RDN (also known as the type).
 * @param value of the RDN - may be null though, preferably, an entry would not exist in these cases.
 */
public record RelativeDN(@Nonnull String key, @Nullable String value) {

    public static final Logger LOGGER = Logger.getLogger(RelativeDN.class.getName());

    public RelativeDN {
        key = Objects.requireNonNull(key, "the relative DN key must be specified").toUpperCase();
    }

    /**
     * Normalize an LDAP {@link Rdn} into a {@link RelativeDN}.
     *
     * @param rdn to build the {@link RelativeDN} from.
     * @param customRDNTypes to parse from a BER-encoded string (the default set from RFC 2253 are always parsed by
     *                       the Java LDAP library).
     * @return the normalized {@link RelativeDN}.
     */
    public static RelativeDN fromLdapRdn(@Nonnull Rdn rdn, @Nonnull Set<String> customRDNTypes) {
        final var key = rdn.getType();
        final var value = rdn.getValue();

        if (value instanceof String valueString) {
            return new RelativeDN(key, valueString);
        }

        if (customRDNTypes.contains(key) && value instanceof byte[] valueRawBytes) {
            final var valueStream = new ASN1InputStream(new ByteArrayInputStream(valueRawBytes));

            try (valueStream) {
                final var valueObject = valueStream.readObject();

                // Check if the object implements the generic ASN1String interface. If it does, use BouncyCastle to
                // parse it.
                if (valueObject instanceof ASN1String valueASN1String) {
                    return new RelativeDN(
                            key,
                            valueASN1String.getString()
                    );
                }
            } catch (IOException ex) {
                LOGGER.warning("Failed to parse custom RDN type (%s): %s".formatted(key, ex.getMessage()));
                return null;
            }

        }

        return null;
    }

}
