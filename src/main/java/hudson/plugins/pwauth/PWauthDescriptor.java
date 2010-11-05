/**
 * 
 */
package hudson.plugins.pwauth;

import hudson.Extension;
import hudson.model.Descriptor;
import hudson.security.SecurityRealm;
import hudson.util.FormValidation;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;

@Extension
public final class PWauthDescriptor extends Descriptor<SecurityRealm> {
	public PWauthDescriptor() {
		super(PWauthSecurityRealm.class);
		this.load();
	}
	
	public String getDisplayName() {
		return "PWauth Authentication";
	}
	
	public FormValidation doTest(
			@QueryParameter final String pwauthPath,
			@QueryParameter final String whitelist,
			@QueryParameter final String grepPath,
			@QueryParameter final String catPath,
			@QueryParameter final String groupsPath,
			@QueryParameter final String idPath) {
		if (!PWauthValidation.validatePath(pwauthPath))
			return FormValidation.error("pwauth Path Invalid");
		if (!PWauthValidation.validatePath(grepPath))
			return FormValidation.error("grep Path Invalid");
		if (!PWauthValidation.validatePath(catPath))
			return FormValidation.error("cat Path Invalid");
		if (!PWauthValidation.validatePath(groupsPath))
			return FormValidation.error("groups Path Invalid");
		if (!PWauthValidation.validatePath(idPath))
			return FormValidation.error("id Path Invalid");
		if (whitelist != null)
			if (!PWauthValidation.validateWhitelist(whitelist))
				return FormValidation.error("IPs Invalid");
		return FormValidation.ok("Success");
	}
	
    public boolean configure(StaplerRequest req, JSONObject json) throws FormException {
    	this.save();
		return true;
	};
}