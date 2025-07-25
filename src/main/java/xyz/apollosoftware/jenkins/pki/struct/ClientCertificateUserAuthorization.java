package xyz.apollosoftware.jenkins.pki.struct;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;
import hudson.model.userproperty.UserPropertyCategory;
import xyz.apollosoftware.jenkins.pki.Messages;

import java.util.Set;

public class ClientCertificateUserAuthorization extends UserProperty {

    /**
     * The user's PKI DN.
     */
    private final String pkiDistinguishedName;

    /**
     * The user's groups.
     */
    private final Set<String> groups;

    public ClientCertificateUserAuthorization(
        final String pkiDistinguishedName,
        final Set<String> groups
    ) {
        this.pkiDistinguishedName = pkiDistinguishedName;
        this.groups = groups;
    }

    public boolean isPresent() {
        return pkiDistinguishedName != null &&
                !pkiDistinguishedName.isEmpty() &&
                groups != null;
    }

    public String getPKIDistinguishedName() {
        return pkiDistinguishedName;
    }

    public Set<String> getGroups() {
        return groups;
    }

    @Extension
    public static class ClientCertificateUserAuthorizationDescriptor extends UserPropertyDescriptor {

        @NonNull
        @Override
        public String getDisplayName() {
            return Messages.clientCertificateUserAuthorization_displayName();
        }

        @Override
        public UserProperty newInstance(User user) {
            return new ClientCertificateUserAuthorization(null, null);
        }

        @NonNull
        @Override
        public UserPropertyCategory getUserPropertyCategory() {
            return new UserPropertyCategory.Invisible();
        }
    }

}
