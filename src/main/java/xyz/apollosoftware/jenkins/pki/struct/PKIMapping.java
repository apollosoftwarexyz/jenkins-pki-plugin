package xyz.apollosoftware.jenkins.pki.struct;

import jakarta.annotation.Nullable;
import xyz.apollosoftware.jenkins.pki.settings.CustomAttributeSelector;

import java.util.Optional;
import java.util.Set;

public record PKIMapping(
    @Nullable String usernameField,
    @Nullable String nameField,
    @Nullable String groupField,
    @Nullable String emailField,
    @Nullable Set<CustomAttributeSelector> customAttributes
) {

    public PKIMapping {
        usernameField = Optional.ofNullable(usernameField).map(String::toUpperCase).orElse(null);
        nameField = Optional.ofNullable(nameField).map(String::toUpperCase).orElse(null);
        groupField = Optional.ofNullable(groupField).map(String::toUpperCase).orElse(null);
        emailField = Optional.ofNullable(emailField).map(String::toUpperCase).orElse(null);
    }

    @Override
    @Nullable
    public String usernameField() {
        return normalizeField(usernameField);
    }

    @Override
    @Nullable
    public String nameField() {
        return normalizeField(nameField);
    }

    @Override
    @Nullable
    public String groupField() {
        return normalizeField(groupField);
    }

    @Override
    @Nullable
    public String emailField() {
        return normalizeField(emailField);
    }

    private String normalizeField(final String field) {
        if (customAttributes != null) {
            final var customField = customAttributes.stream()
                    .filter(customAttribute -> customAttribute.getName().equalsIgnoreCase(field))
                    .findAny();

            if (customField.isPresent()) {
                return customField.get().getOid();
            }
        }

        return field;
    }

    public static final class Builder {
        private String usernameField;
        private String nameField;
        private String groupField;
        private String emailField;
        private Set<CustomAttributeSelector> customAttributes;

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

        public Builder groupField(String groupField) {
            this.groupField = groupField;
            return this;
        }

        public Builder emailField(String emailField) {
            this.emailField = emailField;
            return this;
        }

        public Builder customAttributes(Set<CustomAttributeSelector> customAttributes) {
            this.customAttributes = customAttributes;
            return this;
        }

        public PKIMapping build() {
            return new PKIMapping(usernameField, nameField, groupField, emailField, customAttributes);
        }
    }

}
