/**
 * 
 */
package hudson.plugins.pwauth;

import hudson.model.Hudson;
import hudson.security.AuthorizationStrategy;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

class PWauthFilter implements Filter {
	private Set<String> ipWhitelist = new HashSet<String>();
	private Filter superFilter;
	
	public PWauthFilter(Filter superFilter, String whitelist) {
		this.superFilter = superFilter;
		if (whitelist != null)
			for (String ip : whitelist.split(PWauthValidation.listSperatorEx)) 
	    		if (PWauthValidation.validateIP(ip))
	    			this.ipWhitelist.add(ip.trim());
	}

	public void init(FilterConfig filterConfig) throws ServletException {}
	
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
		for (String whitelistedId : this.ipWhitelist)
			if (whitelistedId.equals(request.getRemoteAddr())) {
				AuthorizationStrategy strategy = Hudson.getInstance().getAuthorizationStrategy();
				Hudson.getInstance().setAuthorizationStrategy(AuthorizationStrategy.UNSECURED);
		        this.superFilter.doFilter(request, response, chain);
		        Hudson.getInstance().setAuthorizationStrategy(strategy);
				return;
			}
		
        this.superFilter.doFilter(request, response, chain);
	}
	
	public void destroy() {}
}