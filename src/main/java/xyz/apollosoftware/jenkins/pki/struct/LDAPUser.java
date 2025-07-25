package xyz.apollosoftware.jenkins.pki.struct;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import org.springframework.ldap.core.ContextMapper;
import org.springframework.ldap.core.DirContextAdapter;

import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;

public record LDAPUser(@Nonnull String dn, @Nullable String username, @Nullable String name, @Nullable String email, Set<String> groups) {

    public static LDAPUserMapper mapper(final LDAPMapping mapping) {
        return new LDAPUserMapper(mapping);
    }

    public LDAPUser {
        groups = Optional.ofNullable(groups).orElseGet(Collections::emptySet);
    }

    public boolean hasUsername() {
        return username != null && !username.isBlank();
    }

    public boolean hasName() {
        return name != null && !name.isBlank();
    }

    public boolean hasEmail() {
        return email != null && !email.isBlank();
    }

    public boolean hasGroups() {
        return groups != null && !groups.isEmpty();
    }

    @Override
    @Nonnull
    public Set<String> groups() {
        assert groups != null; // by constructor
        return groups;
    }

    public LDAPUser withGroups(Set<String> groups) {
        return new LDAPUser(this.dn, this.username, this.name, this.email, groups);
    }

    public static final class LDAPUserMapper implements ContextMapper<LDAPUser> {

        private final LDAPMapping mapping;

        public LDAPUserMapper(final LDAPMapping mapping) {
            this.mapping = mapping;
        }

        @Override
        public LDAPUser mapFromContext(Object ctx) {
            if (!(ctx instanceof DirContextAdapter dirContext)) {
                throw new UnsupportedOperationException("LDAPUserMapper only supports the DirContextAdapter context");
            }

            final var attributes = dirContext.getAttributes();

            return new LDAPUser(
                dirContext.getNameInNamespace(),
                tryGetAttribute(attributes, mapping.usernameField()),
                tryGetAttribute(attributes, mapping.nameField()),
                tryGetAttribute(attributes, mapping.emailField()),
                null
            );
        }

        private String tryGetAttribute(final Attributes attributes, final String name) {
            if (name == null || name.isBlank()) return null;

            final var attribute = attributes.get(name);
            if (attribute == null) return null;

            try {
                return attribute.get().toString();
            } catch (NamingException ex) {
                return null;
            }
        }
    }

}
