package hudson.plugins.pwauth;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.util.List;
import java.util.Vector;

class PWauthUtils {
	private static String pwAuthPath = "/usr/local/bin/pwauth";
	private static String idPath = "/usr/bin/id";
	private static String groupsPath = "/usr/bin/groups";
	private static String catPath = "/bin/cat";
	private static String grepPath = "/bin/grep";

	static boolean userExists(String username) throws IOException {
		Process p = Runtime.getRuntime().exec(idPath + " " + username);
		if (getProcessExitStatus(p) != -1) {
			String result = new BufferedReader(new InputStreamReader(p.getInputStream())).readLine();
			return result != null && result.contains("uid=");
		}
		return false;
	}

	static boolean isUserValid(String username, String password) throws IOException {
		Process p = Runtime.getRuntime().exec(pwAuthPath);
		PrintWriter pw = new PrintWriter(p.getOutputStream());
		pw.write(username + System.getProperty("line.separator"));
		pw.write(password + System.getProperty("line.separator"));
		pw.flush();
		return getProcessExitStatus(p) == 0;
	}
	
	static List<String> getUserGroups(String username) throws IOException {
		List<String> groups = new Vector<String>();
		Process p = Runtime.getRuntime().exec(groupsPath + " " + username);
		if (getProcessExitStatus(p) == 0) {
			String result = new BufferedReader(new InputStreamReader(p.getInputStream())).readLine();
			if (result != null) {
				result = result.substring(result.indexOf(":")+1);
				for (String group : result.split("\\ "))
					if (group.trim().length() > 0)
						groups.add(group.trim());
			}
		}
		return groups;
	}
	
	static boolean groupExists(String group) {
		try {
			String cmd = String.format("%1$s /etc/group |%2$s %3$s:", catPath, grepPath, group);
			// String cmd = catPath + " /etc/group |" + grepPath + " " + group + ":";
			Process p = Runtime.getRuntime().exec(cmd);
			if (getProcessExitStatus(p) == 0) {
				String result = new BufferedReader(new InputStreamReader(p.getInputStream())).readLine();
				return result.trim().length() > 0;
			}
		} catch (IOException e) {}
		return false;
	}
	
	private static int getProcessExitStatus(Process p) {
		int result = -1;
		boolean exited = false;
		while (!exited) {
			try {
				p.waitFor();
				result = p.exitValue();
				exited = true;
			} catch (Exception e) {
				exited = true;
			}
		}
		return result;
	}
	
	/**
	 * @param path the pwAuthPath to set
	 */
	static void setPwAuthPath(String path) {
		if (path != null && !path.isEmpty())
			pwAuthPath = path.trim();
	}
	
	/**
	 * @return the idPath
	 */
	public static final String getIdPath() {
		return idPath;
	}

	/**
	 * @param path the idPath to set
	 */
	public static final void setIdPath(String path) {
		if (path != null && !path.isEmpty())
			PWauthUtils.idPath = path.trim();
	}

	/**
	 * @return the groupsPath
	 */
	public static final String getGroupsPath() {
		return groupsPath;
	}

	/**
	 * @param path the groupsPath to set
	 */
	public static final void setGroupsPath(String path) {
		if (path != null && !path.isEmpty())
			PWauthUtils.groupsPath = path.trim();
	}

	/**
	 * @return the catPath
	 */
	public static final String getCatPath() {
		return catPath;
	}

	/**
	 * @param path the catPath to set
	 */
	public static final void setCatPath(String path) {
		if (path != null && !path.isEmpty())
			PWauthUtils.catPath = path.trim();
	}

	/**
	 * @return the grepPath
	 */
	public static final String getGrepPath() {
		return grepPath;
	}

	/**
	 * @param path the grepPath to set
	 */
	public static final void setGrepPath(String path) {
		if (path != null && !path.isEmpty())
			PWauthUtils.grepPath = path.trim();
	}

	/**
	 * @return the pwAuthPath
	 */
	public static final String getPwAuthPath() {
		return pwAuthPath;
	}
}
