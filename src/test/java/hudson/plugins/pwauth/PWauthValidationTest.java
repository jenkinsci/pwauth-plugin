/**
 * 
 */
package hudson.plugins.pwauth;

import static org.junit.Assert.*;
import hudson.Functions;
import hudson.plugins.pwauth.PWauthValidation;

import org.junit.Test;

/**
 * @author gairorav
 *
 */
public class PWauthValidationTest {

	/**
	 * Test method for {@link hudson.plugins.pwauth.PWauthValidation#validateIP(java.lang.String)}.
	 */
	@Test
	public void testValidateIP() {
		assertTrue(PWauthValidation.validateIP("1.2.3.4"));
		assertTrue(PWauthValidation.validateIP("0.0.0.0"));
		assertTrue(PWauthValidation.validateIP("255.255.255.255"));
		
		assertFalse(PWauthValidation.validateIP(null));
		assertFalse(PWauthValidation.validateIP("1.2.3.4.5"));
		assertFalse(PWauthValidation.validateIP("1.2.3"));
		assertFalse(PWauthValidation.validateIP("1.2"));
		assertFalse(PWauthValidation.validateIP("1"));
		assertFalse(PWauthValidation.validateIP("1.2.3.4."));
		assertFalse(PWauthValidation.validateIP("1.2.3."));
		assertFalse(PWauthValidation.validateIP("1.2."));
		assertFalse(PWauthValidation.validateIP("1."));
		assertFalse(PWauthValidation.validateIP(""));
	}

	/**
	 * Test method for {@link hudson.plugins.pwauth.PWauthValidation#validateWhitelist(java.lang.String[])}.
	 */
	@Test
	public void testValidateWhitelist() {
		assertTrue(PWauthValidation.validateWhitelist("1.2.3.4,1.2.3.5,1.2.3.6,1.2.3.7"));
		assertTrue(PWauthValidation.validateWhitelist("1.2.3.4;1.2.3.5;1.2.3.6;1.2.3.7"));
		assertTrue(PWauthValidation.validateWhitelist("1.2.3.4 1.2.3.5 1.2.3.6 1.2.3.7"));
		assertTrue(PWauthValidation.validateWhitelist("1.2.3.4, 1.2.3.5, 1.2.3.6, 1.2.3.7"));
		assertTrue(PWauthValidation.validateWhitelist("1.2.3.4,1.2.3.5;1.2.3.6 1.2.3.7"));
		assertTrue(PWauthValidation.validateWhitelist("1.2.3.4, 1.2.3.5; 1.2.3.6   1.2.3.7"));
		assertTrue(PWauthValidation.validateWhitelist("1.2.3.4	1.2.3.5	1.2.3.6	1.2.3.7"));
		assertTrue(PWauthValidation.validateWhitelist(""));
		assertTrue(PWauthValidation.validateWhitelist(" "));
		assertTrue(PWauthValidation.validateWhitelist(null));
		assertTrue(PWauthValidation.validateWhitelist(","));
		
		assertFalse(PWauthValidation.validateWhitelist("1.2.3.,"));
		assertFalse(PWauthValidation.validateWhitelist("1,2,3,4"));
		assertFalse(PWauthValidation.validateWhitelist("1.2.3.4,1.2.3."));
		assertFalse(PWauthValidation.validateWhitelist("1.2.3.4,1.2.3,4"));
	}
	
	/**
	 * Test method for {@link hudson.plugins.pwauth.PWauthValidation#validatePath(java.lang.String[])}.
	 */
	@Test
	public void testValidatePath() {
		if (Functions.isWindows())
			return;
		
		// TODO do the testing
	}
}
