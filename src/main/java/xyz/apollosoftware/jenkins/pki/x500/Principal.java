package xyz.apollosoftware.jenkins.pki.x500;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.security.auth.x500.X500Principal;
import java.util.*;

import static java.util.Collections.unmodifiableMap;
import static java.util.stream.Collectors.*;
import static xyz.apollosoftware.jenkins.pki.x500.RelativeDN.fromLdapRdn;

/**
 * A string-normalized X.500 principal.
 *
 * @param relativeDNs that constitute the principal.
 * @see RelativeDN
 */
public record Principal(@Nonnull String dn, @Nonnull Map<String, Set<String>> relativeDNs) {

    private static final String COMMON_NAME_ATTRIBUTE = "CN";

    /**
     * Returns the Common Name ({@code CN}), or null if it is not present.
     *
     * @return the Principal Common Name, or null.
     */
    @Nullable
    public String getCommonName() {
        return getValueForAttribute(COMMON_NAME_ATTRIBUTE);
    }

    /**
     * Returns the first attribute value for the given attribute type.
     *
     * <p>If the attribute type has no values in the {@link Principal}, returns null.
     *
     * @param attribute type to search for.
     * @return the first value for the attribute, or {@code null}.
     */
    @Nullable
    public String getValueForAttribute(@Nonnull final String attribute) {
        return getValuesForAttribute(attribute).stream().findFirst().orElse(null);
    }

    /**
     * Returns the set of attribute values for the given attribute type.
     *
     * <p>If the attribute type has no values in the {@link Principal}, the empty set is returned.
     *
     * @param attribute type to search for.
     * @return the set of attribute values.
     */
    @Nonnull
    public Set<String> getValuesForAttribute(@Nonnull final String attribute) {
        final var values = relativeDNs.get(attribute);
        return Optional.ofNullable(values).orElse(Collections.emptySet());
    }

    /**
     * Return the mapping of relative DN type (attribute) to set of values.
     *
     * @return the internal mapping of "stringified" relative DNs.
     */
    @Nonnull
    public Map<String, Set<String>> getRelativeDNs() {
        return relativeDNs;
    }

    /**
     * Parse the X.500 principal into a set of key-value pairs ({@link Map}).
     *
     * <p>If the principal cannot be parsed, this function returns null.
     *
     * @param principal to parse.
     * @param customRDNTypes to decode from BER as a string.
     * @return the key-value pairs.
     */
    @Nullable
    public static Principal parse(
        @Nonnull X500Principal principal,
        @Nonnull Set<String> customRDNTypes
    ) {
        try {
            LdapName ldapName = new LdapName(principal.getName());
            return new Principal(
                    principal.getName(),
                    unmodifiableMap(ldapName.getRdns().stream()
                        .map(rdn -> fromLdapRdn(rdn, customRDNTypes))
                        .filter(Objects::nonNull)
                        .collect(groupingBy(RelativeDN::key, mapping(RelativeDN::value, toUnmodifiableSet())))));
        } catch (InvalidNameException ex) {
            return null;
        }
    }

}
