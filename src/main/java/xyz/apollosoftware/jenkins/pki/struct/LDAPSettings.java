package xyz.apollosoftware.jenkins.pki.struct;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

public record LDAPSettings(
    boolean enabled,
    int cacheDuration,
    String url,
    String baseDN,
    @Nullable LDAPManager manager,
    String userSearchBase,
    String userSearchFilter,
    String groupSearchBase,
    String groupSearchFilter
) {

    public static final String FALLBACK_USER_SEARCH_BASE = "OU=people";
    public static final String FALLBACK_USER_SEARCH_FILTER = "DN={0}";
    public static final String FALLBACK_GROUP_SEARCH_BASE = "OU=groups";
    public static final String FALLBACK_GROUP_SEARCH_FILTER = "(&(|(objectclass=groupOfUniqueNames)(objectclass=group))(|(uniqueMember={0})(member={0})))";

    public static final int CACHE_DURATION_DEFAULT = 30; // 30 seconds
    public static final int CACHE_DURATION_MAX = 86400; // 1 day

    public static final int LDAP_SINGLE_ENTRY_LIMIT = 1;
    public static final int LDAP_LIST_ENTRY_LIMIT = 100;
    public static final int LDAP_TIME_LIMIT_MILLIS = 5000;

    public LDAPSettings {
        if ((url.isBlank() || baseDN.isBlank()) && enabled) {
            enabled = false;
        }

        if (cacheDuration < 0) {
            cacheDuration = CACHE_DURATION_DEFAULT;
        } else if (cacheDuration >= CACHE_DURATION_MAX) {
            cacheDuration = CACHE_DURATION_MAX;
        }

        if (userSearchBase.isBlank() && enabled) {
            userSearchBase = FALLBACK_USER_SEARCH_BASE;
        }

        if (userSearchFilter.isBlank() && enabled) {
            userSearchFilter = FALLBACK_USER_SEARCH_FILTER;
        }

        if (groupSearchBase.isBlank() && enabled) {
            groupSearchBase = FALLBACK_GROUP_SEARCH_BASE;
        }

        if (groupSearchFilter.isBlank() && enabled) {
            groupSearchFilter = FALLBACK_GROUP_SEARCH_FILTER;
        }
    }

    public boolean isCacheEnabled() {
        return this.cacheDuration != 0;
    }

    public static final class Builder {
        private boolean enabled;
        private int cacheDuration;
        private String url;
        private String baseDN;
        private LDAPManager manager;
        private String userSearchBase;
        private String userSearchFilter;
        private String groupSearchBase;
        private String groupSearchFilter;

        public Builder() {
            enabled = true;
        }

        public Builder enabled(Boolean enabled) {
            this.enabled = enabled != null ? enabled : false;
            return this;
        }

        public Builder cacheDuration(Integer cacheDuration) {
            this.cacheDuration = cacheDuration != null ? cacheDuration : CACHE_DURATION_DEFAULT;
            return this;
        }

        public Builder url(String url) {
            this.url = url;
            return this;
        }

        public Builder baseDN(String baseDN) {
            this.baseDN = baseDN;
            return this;
        }

        public Builder manager(LDAPManager manager) {
            this.manager = manager;
            return this;
        }

        public Builder userSearchBase(String userSearchBase) {
            this.userSearchBase = userSearchBase;
            return this;
        }

        public Builder userSearchFilter(String userSearchFilter) {
            this.userSearchFilter = userSearchFilter;
            return this;
        }

        public Builder groupSearchBase(String groupSearchBase) {
            this.groupSearchBase = groupSearchBase;
            return this;
        }

        public Builder groupSearchFilter(String groupSearchFilter) {
            this.groupSearchFilter = groupSearchFilter;
            return this;
        }

        @Nonnull
        public LDAPSettings build() {
            return new LDAPSettings(
                enabled,
                cacheDuration,
                url,
                baseDN,
                manager,
                userSearchBase,
                userSearchFilter,
                groupSearchBase,
                groupSearchFilter
            );
        }
    }

}
