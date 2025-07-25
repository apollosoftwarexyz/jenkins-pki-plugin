package xyz.apollosoftware.jenkins.pki.userdetails;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serial;
import java.util.Collection;

public class ClientCertificateUserDetails implements UserDetails {

    @Serial
    private static final long serialVersionUID = 7880296294685062373L;

    private final String username;
    private final Collection<GrantedAuthority> authorities;

    public ClientCertificateUserDetails(final String username, final Collection<GrantedAuthority> authorities) {
        this.username = username;
        this.authorities = authorities;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public String getPassword() {
        return null;
    }
}
