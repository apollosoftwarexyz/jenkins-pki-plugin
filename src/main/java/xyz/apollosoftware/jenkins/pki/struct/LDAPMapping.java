package xyz.apollosoftware.jenkins.pki.struct;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

public record LDAPMapping(
    @Nullable String usernameField,
    @Nullable String nameField,
    @Nullable String emailField,
    @Nonnull LDAPSettings settings
) {

    /**
     * Returns true if and only if one of the mapping fields is defined.
     *
     * <p>If none of the mappings are defined, there is no need to enable LDAP.
     * @return true if there is a mapping to an LDAP attribute.
     */
    public boolean hasMapping() {
        return isFieldDefined(usernameField) || isFieldDefined(nameField) || isFieldDefined(emailField);
    }

    /**
     * Whether to use LDAP mapping.
     *
     * <p>This field is true when the explicit {@link LDAPSettings#enabled()} property is set to true <b>and</b> when
     * {@link #hasMapping()} is true.
     *
     * @return true if LDAP mapping is enabled.
     */
    public boolean isEnabled() {
        return this.settings.enabled() && hasMapping();
    }

    /**
     * Check whether the field is non-null and non-blank.
     *
     * @param field to check.
     * @return true if the field is non-null and non-blank.
     */
    private boolean isFieldDefined(@Nullable String field) {
        return field != null && !field.isBlank();
    }

    public static final class Builder {
        private String usernameField;
        private String nameField;
        private String emailField;
        private LDAPSettings settings;

        public Builder() {
        }

        public Builder usernameField(String usernameField) {
            this.usernameField = usernameField;
            return this;
        }

        public Builder nameField(String nameField) {
            this.nameField = nameField;
            return this;
        }

        public Builder emailField(String emailField) {
            this.emailField = emailField;
            return this;
        }

        public Builder withSettings(LDAPSettings settings) {
            this.settings = settings;
            return this;
        }

        public LDAPMapping build() {
            return new LDAPMapping(usernameField, nameField, emailField, settings);
        }
    }

}
