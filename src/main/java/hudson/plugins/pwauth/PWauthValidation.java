package hudson.plugins.pwauth;

import java.io.File;
import java.util.regex.Pattern;

public class PWauthValidation {
	static final String listSperatorEx = "(\\s)*[,|;|\\s](\\s)*";
	private static final String ipEx = "^\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b$";
	
	static boolean validateIP(String ip) {
		if (ip == null)
			return false;
		return Pattern.matches(ipEx, ip);
	}

	static boolean validateWhitelist(String whitelist) {
		if (whitelist != null && !whitelist.isEmpty())
			for (String ip : whitelist.split(listSperatorEx))
				if (!validateIP(ip.trim()))
					return false;
		return true;
	}

	static boolean validatePath(String path) {
		if (path == null || path.isEmpty())
			return true;
		try {
			File s = new File(path.trim());
	        return s.isFile() && s.canExecute();
	    } catch (Exception e) {
	    	return false;
	    }
	}
}
