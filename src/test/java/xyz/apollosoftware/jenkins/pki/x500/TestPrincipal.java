package xyz.apollosoftware.jenkins.pki.x500;

import org.junit.jupiter.api.Test;

import javax.security.auth.x500.X500Principal;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

class TestPrincipal {

    @Test
    void testParseX500PrincipalEmpty() {
        assertEquals(Map.of(), Objects.requireNonNull(Principal.parse(new X500Principal(""), Collections.emptySet())).getRelativeDNs());
    }

    @Test
    void testParseX500Principal() {
        assertEquals(Map.of(
                "CN", Set.of("foo"),
                "C", Set.of("GB")
        ), Objects.requireNonNull(Principal.parse(new X500Principal("CN=foo,C=GB"), Collections.emptySet())).getRelativeDNs());

        assertEquals(Map.of(
                "CN", Collections.singleton("foo")
        ), Objects.requireNonNull(Principal.parse(new X500Principal("CN=foo"), Collections.emptySet())).getRelativeDNs());

        assertEquals(Map.of(
                "UID", Collections.singleton("foo")
        ), Objects.requireNonNull(Principal.parse(new X500Principal("UID=foo"), Collections.emptySet())).getRelativeDNs());
    }

    @Test
    void testParseX500PrincipalDuplicateFields() {
        assertEquals(Map.of(
                "CN", Set.of("foo", "bar")
        ), Objects.requireNonNull(Principal.parse(new X500Principal("CN=foo,CN=bar"), Collections.emptySet())).getRelativeDNs());
    }

    @Test
    void testParseX500PrincipalCustomField() {
        // Test without supplying custom field OID.
        assertEquals(Map.of(
                "CN", Collections.singleton("foo")
        ), Objects.requireNonNull(Principal.parse(new X500Principal("CN=foo"), Collections.emptySet())).getRelativeDNs());

        // Test with supplying custom field OID.
        assertEquals(Map.of(
                "CN", Collections.singleton("foo"),
                "1.2.840.113549.1.9.1", Collections.singleton("foo@bar.com")
        ), Objects.requireNonNull(Principal.parse(new X500Principal("CN=foo,1.2.840.113549.1.9.1=foo@bar.com"), Collections.singleton("1.2.840.113549.1.9.1"))).getRelativeDNs());
    }

    @Test
    void testParseX500PrincipalBadCharacters() {
        assertEquals(Map.of(
                "CN", Collections.singleton("foo=")
        ), Objects.requireNonNull(Principal.parse(new X500Principal("CN=foo="), Collections.emptySet())).getRelativeDNs());
    }

}
