package xyz.apollosoftware.jenkins.pki.services;

import jakarta.annotation.Nonnull;
import xyz.apollosoftware.jenkins.pki.struct.LDAPUser;
import xyz.apollosoftware.jenkins.pki.struct.PKIUser;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

public class LDAPCache {

    private static final LDAPCache INSTANCE = new LDAPCache();

    private final ConcurrentHashMap<Integer, CacheEntry> cache = new ConcurrentHashMap<>();

    /**
     * Get the global LDAP user cache.
     *
     * @return the {@link LDAPCache} singleton instance.
     */
    public static LDAPCache get() {
        return INSTANCE;
    }

    /**
     * Get or update the {@link LDAPUser} (LDAP directory entry) for the given {@link PKIUser}.
     *
     * @param pkiUser to look up.
     * @param searchForLDAPUser function that returns an LDAPUser to cache.
     * @param cacheDuration after which the {@link LDAPUser} cache entry should be disregarded.
     * @return the {@link LDAPUser} from the cache, or newly fetched using the searchForLDAPUser function.
     */
    public synchronized LDAPUser getOrUpdate(
        final PKIUser pkiUser,
        @Nonnull final Supplier<LDAPUser> searchForLDAPUser,
        int cacheDuration
    ) {
        final var key = pkiUser.hashCode();

        if (cache.containsKey(key)) {
            final var entry = cache.get(key);
            if (!entry.hasExpired(cacheDuration)) {
                return entry.user;
            } else {
                cache.remove(key);
            }
        }

        final var user = searchForLDAPUser.get();
        cache.put(key, new CacheEntry(user, System.currentTimeMillis()));
        return user;
    }

    /**
     * Remove all entries that have been cached for longer than the {@code cacheDuration}.
     *
     * @param cacheDuration after which the {@link LDAPUser} cache entry should be disregarded.
     */
    public synchronized void removeExpiredEntries(int cacheDuration) {
        Set<Integer> expired = new HashSet<>();

        cache.forEach((key, value) -> {
            if (value.hasExpired(cacheDuration)) {
                expired.add(key);
            }
        });

        expired.forEach(cache::remove);
    }

    private record CacheEntry(LDAPUser user, long cachedAt) {

        /**
         * Returns true if the entry has expired, relative to the given cacheDuration.
         *
         * @param cacheDuration in seconds.
         * @return true if the entry has been cached for longer than the given cacheDuration.
         */
        public boolean hasExpired(int cacheDuration) {
            return System.currentTimeMillis() > cachedAt + (cacheDuration * 1000L);
        }

    }

}
