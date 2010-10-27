package hudson.plugins.pwauth;

import hudson.Extension;
import hudson.Functions;
import hudson.model.Descriptor;
import hudson.security.AbstractPasswordBasedSecurityRealm;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;
import hudson.util.FormValidation;
import java.io.IOException;
import javax.servlet.Filter;
import javax.servlet.FilterConfig;
import net.sf.json.JSONObject;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.User;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.springframework.dao.DataAccessException;


/** 
 * TODO Replace String Messages with Property Messages<br />
 * TODO additional to whitelist, support username:password@host URL-Authetication in {@link PWauthFilter}<br />
 * TODO allow hostnames in whitelist<br />
 * @author gairorav
 *
 */
public class PWauthSecurityRealm extends AbstractPasswordBasedSecurityRealm {
	public final String pwauthPath;
	public final String whitelist;
	public final String idPath;
	public final String groupsPath;
	public final String catPath;
	public final String grepPath;
	
	@DataBoundConstructor
	public PWauthSecurityRealm(final String pwauthPath, final String whitelist, final String idPath, final String groupsPath,
		final String catPath, final String grepPath) {
		this.pwauthPath = pwauthPath;
		this.whitelist = whitelist;
		this.grepPath = grepPath;
		this.catPath = catPath;
		this.groupsPath = groupsPath;
		this.idPath = idPath;
		if (PWauthValidation.validatePath(pwauthPath))
			PWauthUtils.setPwAuthPath(pwauthPath);
		if (PWauthValidation.validatePath(grepPath))
			PWauthUtils.setGrepPath(grepPath);
		if (PWauthValidation.validatePath(catPath))
			PWauthUtils.setCatPath(catPath);
		if (PWauthValidation.validatePath(groupsPath))
			PWauthUtils.setGroupsPath(groupsPath);
		if (PWauthValidation.validatePath(idPath))
			PWauthUtils.setIdPath(idPath);
	}
	
	@Override
	public SecurityComponents createSecurityComponents() {
		return new SecurityComponents(
			new PWauthAthenticationManager(),
			new UserDetailsService() {
				public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
					try {
						if (PWauthUtils.userExists(username))
							return new User(username, "", true, true, true, true,
								new GrantedAuthority[] { AUTHENTICATED_AUTHORITY });
					} catch (IOException e) {}
					throw new UsernameNotFoundException("No such Unix user: " + username);
				}
			});
	}
	
	@Override
	protected UserDetails authenticate(String username, String password) throws AuthenticationException {
		try {
			if (PWauthUtils.isUserValid(username, password))
				return new User(username, "", true, true, true, true,
					new GrantedAuthority[] { AUTHENTICATED_AUTHORITY });
		} catch (Exception e) {
			throw new AuthenticationException("User could not be authenticated", e) {
				private static final long serialVersionUID = 8636276439158457192L;
			};
		}
		return null;
	}
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
		try {
			if (PWauthUtils.userExists(username))
				return new User(username, "", true, true, true, true,
					new GrantedAuthority[] { AUTHENTICATED_AUTHORITY });
		} catch (IOException e) {}
		throw new UsernameNotFoundException("No such Unix user: " + username);
	}
	
	@Override
	public GroupDetails loadGroupByGroupname(final String groupname) throws UsernameNotFoundException, DataAccessException {
		if (PWauthUtils.groupExists(groupname))
			throw new UsernameNotFoundException(groupname);
		return new GroupDetails() {
			@Override
			public String getName() {
				return groupname;
			}
		};
	}
	
	@Override
	public Filter createFilter(FilterConfig filterConfig) {
		return new PWauthFilter(super.createFilter(filterConfig), this.whitelist);
	}
	
	@Extension
    public static DescriptorImpl install() {
        if(!Functions.isWindows()) 
        	return new DescriptorImpl();
        return null;
    }
	
	public static final class DescriptorImpl extends Descriptor<SecurityRealm> {
		public DescriptorImpl() {
			this.load();
		}
		
		public String getDisplayName() {
			return "PWauth Authentication 2";
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
}
