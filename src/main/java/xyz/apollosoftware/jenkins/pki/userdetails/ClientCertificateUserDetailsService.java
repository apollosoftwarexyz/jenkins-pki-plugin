package xyz.apollosoftware.jenkins.pki.userdetails;

import hudson.security.SecurityRealm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Collections;

public class ClientCertificateUserDetailsService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return new ClientCertificateUserDetails(username, Collections.singleton(SecurityRealm.AUTHENTICATED_AUTHORITY2));
    }

}
