package xyz.apollosoftware.jenkins.pki.settings;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import org.kohsuke.stapler.DataBoundConstructor;
import xyz.apollosoftware.jenkins.pki.Messages;

import java.io.Serial;
import java.io.Serializable;
import java.util.Objects;

/**
 * A custom attribute mapping.
 *
 * <p>The CustomAttributeSelector contains an individual mapping between an OID and a friendly name.
 */
public final class CustomAttributeSelector extends AbstractDescribableImpl<CustomAttributeSelector> implements Serializable {
    @Serial
    private static final long serialVersionUID = -3673457248230346462L;

    /**
     * The Object Identifier (OID).
     *
     * <p>This is the underlying value that is stored in the X.500 subject data.
     */
    private final String oid;

    /**
     * The friendly name.
     *
     * <p>This is an alias (for example in RFC 2253) that can be used in place of the {@link #oid} when this mapping is
     * enabled.
     */
    private final String name;

    /**
     * Construct a {@link CustomAttributeSelector} mapping.
     * @param oid to map.
     * @param name that will be used in place of the OID.
     */
    @DataBoundConstructor
    public CustomAttributeSelector(String oid, String name) {
        this.oid = oid;
        this.name = name.toUpperCase();
    }

    /**
     * Get the Object Identifier (OID) in the mapping.
     * @return the object identifier of the mapping.
     */
    public String getOid() {
        return oid;
    }

    /**
     * Get the friendly name in the mapping.
     * @return the friendly name of the mapping.
     */
    public String getName() {
        return name;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;
        var that = (CustomAttributeSelector) obj;
        return Objects.equals(this.oid, that.oid) &&
                Objects.equals(this.name, that.name);
    }

    @Override
    public int hashCode() {
        return Objects.hash(oid, name);
    }

    @Override
    public String toString() {
        return "CustomAttributeSelector[" +
                "oid=" + oid + ", " +
                "name=" + name + ']';
    }


    @Extension
    public static class CustomAttributeSelectorDescriptor extends Descriptor<CustomAttributeSelector> {
        @NonNull
        @Override
        public String getDisplayName() {
            return Messages.customAttribute_displayName();
        }
    }

}
