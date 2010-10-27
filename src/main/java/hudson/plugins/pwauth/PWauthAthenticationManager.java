package hudson.plugins.pwauth;

import java.io.IOException;
import java.util.List;
import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;

public class PWauthAthenticationManager implements AuthenticationManager {
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		String username = authentication.getPrincipal().toString();
        String password = authentication.getCredentials().toString();
        
		try {
	        if (PWauthUtils.isUserValid(username, password)) {
	        	List<String> groups;
					groups = PWauthUtils.getUserGroups(username);
				
	        	GrantedAuthority[] authoroties = new GrantedAuthority[groups.size()];
	            int i=0;
	            for (String g : groups)
	            	authoroties[i++] = new GrantedAuthorityImpl(g);
	        	return new UsernamePasswordAuthenticationToken(username, password, authoroties);
	        }
        } catch (IOException e) {
        	throw new BadCredentialsException("Can't read system password. Access Denied!", e);        	
        }
        throw new BadCredentialsException("User Credentials are incorrect.");
	}
}
