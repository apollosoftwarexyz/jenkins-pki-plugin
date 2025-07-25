package xyz.apollosoftware.jenkins.pki.struct;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.util.Collections;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

public record PKIUser(@Nonnull String dn, @Nullable String username, @Nullable String name, @Nullable Set<String> groups, @Nullable String email) {

    public PKIUser {
        dn = Objects.requireNonNull(dn, "A distinguished name (DN) is required for a PKIUser");
        groups = Optional.ofNullable(groups).orElseGet(Collections::emptySet);
    }

    @Override
    @Nonnull
    public Set<String> groups() {
        assert groups != null; // by constructor
        return groups;
    }

    public static final class Builder {
        private String dn;
        private String username;
        private String name;
        private Set<String> groups;
        private String email;

        public Builder() {
        }

        public Builder(PKIUser pkiUser) {
            this.dn = pkiUser.dn();
            this.username = pkiUser.username();
            this.name = pkiUser.name();
            this.groups = pkiUser.groups();
            this.email = pkiUser.email();
        }

        public Builder dn(@Nonnull String dn) {
            this.dn = dn;
            return this;
        }

        public Builder username(@Nonnull String username) {
            this.username = username;
            return this;
        }

        public Builder name(@Nonnull String name) {
            this.name = name;
            return this;
        }

        public Builder group(@Nullable String group) {
            this.groups = group != null ? Set.of(group) : null;
            return this;
        }

        public Builder groups(@Nullable Set<String> groups) {
            this.groups = groups;
            return this;
        }

        public Builder email(String email) {
            this.email = email;
            return this;
        }

        public PKIUser build() {
            return new PKIUser(dn, username, name, groups, email);
        }
    }

}
