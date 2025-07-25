package xyz.apollosoftware.jenkins.pki;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.Descriptor;
import hudson.security.SecurityRealm;
import hudson.util.Secret;
import jakarta.annotation.Nullable;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterConfig;
import jenkins.security.HexStringConfidentialKey;
import org.kohsuke.stapler.DataBoundConstructor;
import org.springframework.security.authentication.*;
import xyz.apollosoftware.jenkins.pki.struct.LDAPManager;
import xyz.apollosoftware.jenkins.pki.struct.LDAPMapping;
import xyz.apollosoftware.jenkins.pki.struct.LDAPSettings;
import xyz.apollosoftware.jenkins.pki.struct.PKIMapping;
import xyz.apollosoftware.jenkins.pki.userdetails.ClientCertificateUserDetailsService;
import xyz.apollosoftware.jenkins.pki.settings.CustomAttributeSelector;

import java.util.ArrayList;
import java.util.Set;

public class ClientCertificateSecurityRealm extends SecurityRealm {

    public static final String ANONYMOUS_USER_KEY = "anonymous";
    public static final String REMEMBER_ME_KEY = "rememberMe";
    public static final int REMEMBER_ME_KEY_LENGTH = 64;

    private final String usernameField;
    private final String nameField;
    private final String groupField;
    private final String emailField;
    private final Set<CustomAttributeSelector> customAttributes;

    @Nullable
    private final Boolean ldapEnabled;
    private final Integer ldapCacheDuration;
    private final String ldapManagerDN;
    private final Secret ldapManagerPassword;
    private final String ldapServerUrl;
    private final String ldapBaseDN;
    private final String userSearchBase;
    private final String userSearchFilter;
    private final String groupSearchBase;
    private final String groupSearchFilter;
    private final String ldapUsernameField;
    private final String ldapNameField;
    private final String ldapEmailField;

    @DataBoundConstructor
    public ClientCertificateSecurityRealm(
        final String usernameField,
        final String nameField,
        final String groupField,
        final String emailField,
        final Set<CustomAttributeSelector> customAttributes,

        final boolean ldapEnabled,
        final Integer ldapCacheDuration,
        final String ldapManagerDN,
        final Secret ldapManagerPassword,
        final String ldapServerUrl,
        final String ldapBaseDN,
        final String userSearchBase,
        final String userSearchFilter,
        final String groupSearchBase,
        final String groupSearchFilter,
        final String ldapUsernameField,
        final String ldapNameField,
        final String ldapEmailField
    ) {
        this.usernameField = usernameField;
        this.nameField = nameField;
        this.groupField = groupField;
        this.emailField = emailField;
        this.customAttributes = customAttributes;

        this.ldapEnabled = ldapEnabled;
        this.ldapCacheDuration = ldapCacheDuration;
        this.ldapManagerDN = ldapManagerDN;
        this.ldapManagerPassword = ldapManagerPassword;
        this.ldapServerUrl = ldapServerUrl;
        this.ldapBaseDN = ldapBaseDN;
        this.userSearchBase = userSearchBase;
        this.userSearchFilter = userSearchFilter;
        this.groupSearchBase = groupSearchBase;
        this.groupSearchFilter = groupSearchFilter;
        this.ldapUsernameField = ldapUsernameField;
        this.ldapNameField = ldapNameField;
        this.ldapEmailField = ldapEmailField;
    }

    public String getUsernameField() {
        return usernameField;
    }

    public String getNameField() {
        return nameField;
    }

    public String getGroupField() {
        return groupField;
    }

    public String getEmailField() {
        return emailField;
    }

    public Set<CustomAttributeSelector> getCustomAttributes() {
        return customAttributes;
    }

    public boolean isLdapEnabled() {
        return ldapEnabled != null ? ldapEnabled : false;
    }

    public Integer getLdapCacheDuration() {
        return ldapCacheDuration;
    }

    public String getLdapServerUrl() {
        return ldapServerUrl;
    }

    public String getLdapBaseDN() {
        return ldapBaseDN;
    }

    public String getLdapManagerDN() {
        return ldapManagerDN;
    }

    public Secret getLdapManagerPassword() {
        return ldapManagerPassword;
    }

    public String getUserSearchBase() {
        return userSearchBase;
    }

    public String getUserSearchFilter() {
        return userSearchFilter;
    }

    public String getGroupSearchBase() {
        return groupSearchBase;
    }

    public String getGroupSearchFilter() {
        return groupSearchFilter;
    }

    public String getLdapUsernameField() {
        return ldapUsernameField;
    }

    public String getLdapNameField() {
        return ldapNameField;
    }

    public String getLdapEmailField() {
        return ldapEmailField;
    }

    @Override
    public boolean canLogOut() {
        return false;
    }

    @Override
    public Filter createFilter(FilterConfig filterConfig) {
        return new ClientCertificateFilter(
            new PKIMapping.Builder()
                .usernameField(getUsernameField())
                .nameField(getNameField())
                .groupField(getGroupField())
                .emailField(getEmailField())
                .customAttributes(getCustomAttributes())
                .build(),
            new LDAPMapping.Builder()
                .usernameField(getLdapUsernameField())
                .nameField(getLdapNameField())
                .emailField(getLdapEmailField())
                .withSettings(
                    new LDAPSettings.Builder()
                        .enabled(isLdapEnabled())
                        .cacheDuration(getLdapCacheDuration())
                        .url(getLdapServerUrl())
                        .baseDN(getLdapBaseDN())
                        .manager(
                            new LDAPManager.Builder()
                                .dn(getLdapManagerDN())
                                .password(getLdapManagerPassword())
                                .build())
                        .userSearchBase(getUserSearchBase())
                        .userSearchFilter(getUserSearchFilter())
                        .groupSearchBase(getGroupSearchBase())
                        .groupSearchFilter(getGroupSearchFilter())
                        .build())
                .build());
    }

    @Override
    public SecurityComponents createSecurityComponents() {
        // TODO: investigate authentication mechanism again (want client auth vs must client auth?)
        final var providers = new ArrayList<AuthenticationProvider>();

        providers.add(new RememberMeAuthenticationProvider(new HexStringConfidentialKey(
            this.getClass(),
            REMEMBER_ME_KEY,
            REMEMBER_ME_KEY_LENGTH
        ).get()));

        providers.add(new AnonymousAuthenticationProvider(ANONYMOUS_USER_KEY));

        return new SecurityComponents(new ProviderManager(providers), new ClientCertificateUserDetailsService());
    }

    @Extension
    public static class ClientCertificateSecurityRealmDescriptor extends Descriptor<SecurityRealm> {
        @NonNull
        @Override
        public String getDisplayName() {
            return Messages.clientCertificateSecurityRealm_displayName();
        }
    }

}
