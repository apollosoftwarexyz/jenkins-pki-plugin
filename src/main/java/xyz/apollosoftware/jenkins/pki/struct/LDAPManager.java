package xyz.apollosoftware.jenkins.pki.struct;

import hudson.util.Secret;
import jakarta.annotation.Nullable;
import org.springframework.ldap.core.AuthenticationSource;

public record LDAPManager(String dn, Secret password) implements AuthenticationSource {

    @Override
    public String getPrincipal() {
        return dn;
    }

    @Override
    public String getCredentials() {
        return password.getPlainText();
    }

    public static final class Builder {
        private String dn;
        private Secret password;

        public Builder() {
        }

        public Builder dn(String dn) {
            this.dn = dn;
            return this;
        }

        public Builder password(Secret password) {
            this.password = password;
            return this;
        }

        @Nullable
        public LDAPManager build() {
            if ((dn == null || dn.isBlank()) && password == null) {
                return null;
            }

            return new LDAPManager(dn, password);
        }
    }

}
