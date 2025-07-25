package xyz.apollosoftware.jenkins.pki;

import hudson.model.User;
import hudson.tasks.Mailer;
import hudson.util.Scrambler;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jenkins.model.Jenkins;
import jenkins.security.ApiTokenProperty;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapClient;
import org.springframework.ldap.core.support.DefaultDirObjectFactory;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import xyz.apollosoftware.jenkins.pki.services.LDAPCache;
import xyz.apollosoftware.jenkins.pki.settings.CustomAttributeSelector;
import xyz.apollosoftware.jenkins.pki.struct.*;
import xyz.apollosoftware.jenkins.pki.x500.Principal;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.function.Supplier;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import static org.springframework.ldap.query.LdapQueryBuilder.query;
import static xyz.apollosoftware.jenkins.pki.struct.LDAPSettings.*;

public class ClientCertificateFilter implements Filter {

    private static final Logger LOGGER = Logger.getLogger(ClientCertificateFilter.class.getName());

    /**
     * The name of the attribute that contains a {@link ServletRequest}'s X.509 certificate (where there is one).
     */
    private static final String X509_CERTIFICATE_ATTRIBUTE = "jakarta.servlet.request.X509Certificate";

    private final PKIMapping pkiMapping;
    private final LDAPMapping ldapMapping;

    public ClientCertificateFilter(PKIMapping pkiMapping, LDAPMapping ldapMapping) {
        this.pkiMapping = pkiMapping;
        this.ldapMapping = ldapMapping;
    }

    @Nullable
    private PKIUser handleAPIToken(final ServletRequest request) {
        if (!(request instanceof HttpServletRequest r)) return null;

        final String authorizationHeader = r.getHeader("Authorization");
        if (authorizationHeader == null || !authorizationHeader.toLowerCase().startsWith("basic ")) return null;

        final var basicAuth = Scrambler.descramble(authorizationHeader.substring(6));
        final var basicAuthComponents = basicAuth.split(":");
        if (basicAuthComponents.length == 2) {
            final var username = basicAuthComponents[0];
            final var password = basicAuthComponents[1];

            if (username.isEmpty()) return null;

            // Look up the user and attempt to resolve their API token.
            final var user = User.get(username, false, Collections.emptyMap());
            if (user == null) return null;

            final var authorization = user.getProperty(ClientCertificateUserAuthorization.class);
            if (authorization == null || !authorization.isPresent()) return null;

            final var apiToken = user.getProperty(ApiTokenProperty.class);
            if (apiToken != null && apiToken.matchesPassword(password)) {
                return new PKIUser.Builder()
                    .dn(authorization.getPKIDistinguishedName())
                    .username(user.getId())
                    .name(user.getFullName())
                    .email(Optional.ofNullable(user.getProperty(Mailer.UserProperty.class)).map(Mailer.UserProperty::getEmailAddress).orElse(null))
                    .groups(authorization.getGroups())
                    .build();
            }
        }

        return null;
    }

    @Override
    public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain filterChain) throws ServletException, IOException {
        final var authentication = Optional.ofNullable(handleAPIToken(request)).or(() -> Optional.ofNullable(locateX500Subject(request))).map(pkiUser -> {
            // Derive user information from the X.509 certificate and LDAP entry.
            String username = pkiUser.username();
            String name = pkiUser.name();
            String emailAddress = pkiUser.email();
            Set<String> groups = new HashSet<>(pkiUser.groups());

            if (ldapMapping.isEnabled()) {
                final Supplier<LDAPUser> searchForLDAPUser = () -> searchLDAP(ldapMapping, pkiUser);

                final LDAPUser ldapUser;
                if (ldapMapping.settings().isCacheEnabled()) {
                    final var cacheDuration = ldapMapping.settings().cacheDuration();
                    LDAPCache.get().removeExpiredEntries(cacheDuration);
                    ldapUser = LDAPCache.get().getOrUpdate(pkiUser, searchForLDAPUser, cacheDuration);
                } else {
                    ldapUser = searchForLDAPUser.get();
                }

                if (ldapUser.hasUsername()) username = ldapUser.username();
                if (ldapUser.hasName()) name = ldapUser.name();
                if (ldapUser.hasEmail()) emailAddress = ldapUser.email();
                if (ldapUser.hasGroups()) {
                    groups.addAll(ldapUser.groups());
                }
            }

            // Create the user's authentication token.
            final var token = createToken(
                Objects.requireNonNull(username, "Failed to derive username for user."),
                groups
            );
            final var user = User.get2(token);
            if (user == null) {
                LOGGER.severe("Failed to map PKI user to Jenkins user: %s".formatted(pkiUser));
                return null;
            }

            // Apply the user's display name.
            user.setFullName(name);

            try {
                // Apply the email address to the user.
                if (emailAddress != null) {
                    final var emailProperty = user.getProperty(Mailer.UserProperty.class);
                    if (emailProperty == null || !emailAddress.equals(emailProperty.getEmailAddress())) {
                        user.addProperty(new Mailer.UserProperty(emailAddress));
                    }
                }

                user.addProperty(new ClientCertificateUserAuthorization(
                    pkiUser.dn(),
                    groups
                ));

                user.save();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

            return token;
        }).orElse(Jenkins.ANONYMOUS2);

        SecurityContextHolder.getContext().setAuthentication(authentication);
        filterChain.doFilter(request, response);
    }

    LdapClient createLdapClient(final LDAPSettings settings) {
        LdapContextSource ldapContextSource = new LdapContextSource();
        ldapContextSource.setUrl(settings.url());
        ldapContextSource.setBase(settings.baseDN());

        final var manager = settings.manager();
        if (manager == null) {
            ldapContextSource.setAnonymousReadOnly(true);
        } else {
            ldapContextSource.setAuthenticationSource(settings.manager());
        }

        ldapContextSource.setDirObjectFactory(DefaultDirObjectFactory.class);
        ldapContextSource.afterPropertiesSet();

        return LdapClient.builder().contextSource(ldapContextSource).build();
    }

    @Nonnull
    LDAPUser searchLDAP(final LDAPMapping mapping, final PKIUser pkiUser) {
        ClassLoader originalClassLoader = Thread.currentThread().getContextClassLoader();
        Thread.currentThread().setContextClassLoader(this.getClass().getClassLoader());

        try {
            final var settings = mapping.settings();
            final var client = createLdapClient(settings);

            final var user = client.search()
                    .query(query()
                            .countLimit(LDAP_SINGLE_ENTRY_LIMIT)
                            .timeLimit(LDAP_TIME_LIMIT_MILLIS)
                            .base(settings.userSearchBase())
                            .filter(settings.userSearchFilter(), pkiUser.dn(), pkiUser.username(), pkiUser.email()))
                    .toList(LDAPUser.mapper(mapping))
                    .stream().findFirst().orElseThrow(() -> new UsernameNotFoundException("User could not be found in LDAP"));

            final var groups = client.search()
                    .query(query()
                            .countLimit(LDAP_LIST_ENTRY_LIMIT)
                            .timeLimit(LDAP_TIME_LIMIT_MILLIS)
                            .base(settings.groupSearchBase())
                            .filter(settings.groupSearchFilter(), user.dn()))
                    .toList((AttributesMapper<String>) attribute -> {
                        final var value = attribute.get("CN");
                        if (value != null) return value.get().toString();
                        return null;
                    }).stream().filter(Objects::nonNull).collect(Collectors.toSet());

            return user.withGroups(groups);
        } finally {
            Thread.currentThread().setContextClassLoader(originalClassLoader);
        }
    }

    /**
     * Locate the X.500 subject from the user certificate presented during the {@link ServletRequest}.
     *
     * <p>If authentication fails, log messages are produced and null is returned - to indicate anonymous authentication
     * should be used instead.
     *
     * @param request to locate the X.500 subject from.
     * @return an X.500 subject, using information gained from the X.509 certificate supplied in the request (or null).
     */
    @Nullable
    PKIUser locateX500Subject(final ServletRequest request) {
        final Object maybeChain = request.getAttribute(X509_CERTIFICATE_ATTRIBUTE);

        // Ensure the chain is a) supplied, b) castable to an X509Certificate array.
        if (!(maybeChain instanceof X509Certificate[] chain)) {
            if (maybeChain == null) {
                LOGGER.warning("Missing X.509 certificate - returning ANONYMOUS as user");
            } else {
                LOGGER.severe("Invalid X.509 certificate chain value (for key = '%s') on request - returning ANONYMOUS as user".formatted(X509_CERTIFICATE_ATTRIBUTE));
            }

            return null;
        }

        // Ensure the chain includes a user certificate...
        if (chain.length == 0 || chain[0] == null) {
            LOGGER.warning("Empty X.509 certificate chain on request - returning ANONYMOUS as user");
            return null;
        }

        // If there is a certificate in the chain, the user certificate (leaf) will be the first entry.
        final var subject = Principal.parse(chain[0].getSubjectX500Principal(), Optional.ofNullable(pkiMapping.customAttributes())
                .map(customAttributes -> customAttributes.stream()
                        .map(CustomAttributeSelector::getOid)
                        .collect(Collectors.toSet())
                ).orElse(Collections.emptySet()));

        if (subject == null) {
            LOGGER.warning("Failed to parse X.500 subject from X.509 certificate - returning ANONYMOUS as user");
            return null;
        }

        // Extract the user's information from the subject.
        Optional<String> username = Optional.ofNullable(pkiMapping.usernameField()).map(subject::getValueForAttribute);
        Optional<String> name = Optional.ofNullable(pkiMapping.nameField()).map(subject::getValueForAttribute);

        // If the username has not been specified, attempt to derive it from the common name of the certificate.
        //
        // This is a last-resort (for something sensible), so if we can't get the common name in this case, we'll just
        // error and refuse to authenticate.
        //
        // An alternative could be to use the Issuer DN and certificate serial number - but that is not really usable,
        // so we haven't bothered implementing that.
        if (username.isEmpty()) {
            final var commonName = subject.getCommonName();
            if (commonName == null) {
                LOGGER.warning("Failed to extract username from X.500 subject of X.509 certificate - returning ANONYMOUS as user");
                return null;
            }
            username = Optional.of(commonName);
        }

        // Now we can safely fallback to using the username instead of the name.
        if (name.isEmpty()) name = username;

        return new PKIUser.Builder()
                .dn(subject.dn())
                .username(username.get())
                .name(name.get())
                .group(Optional.ofNullable(pkiMapping.groupField()).map(subject::getValueForAttribute).orElse(null))
                .email(Optional.ofNullable(pkiMapping.emailField()).map(subject::getValueForAttribute).orElse(null))
                .build();
    }

    /**
     * Create an {@link Authentication} token for the given username.
     *
     * <p>The username must be non-null.
     *
     * @param username to create the token for.
     * @return the created {@link Authentication} token.
     */
    private static Authentication createToken(@Nonnull final String username, @Nonnull Set<String> groups) {
        final Set<GrantedAuthority> authorities = groups.stream().map(group -> new SimpleGrantedAuthority(String.format("%s", group))).collect(Collectors.toCollection(HashSet::new));
        authorities.add(ClientCertificateSecurityRealm.AUTHENTICATED_AUTHORITY2);
        return new OneTimeTokenAuthenticationToken(username, authorities);
    }

}
