import java.io.FileOutputStream;
import java.io.PrintStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Properties;
import java.util.Random;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.naming.Context;

public class password {
	
	/*
	 * weak hash MD5
	 * no salt
	 */	
	private static byte[] hashPassword1(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(password.getBytes());
        return md.digest();
	}
	
	
	/*
	 * weak hash SHA1
	 * weak PRNG random
	 * static seed 0
	 * short salt, 4 bytes
	 */
	private static byte[] hashPassword2(String password) throws NoSuchAlgorithmException {
        Random r = new Random(0);
        byte [] salt = new byte[4];
		r.nextBytes(salt);
		byte[] saltedPassword = new byte[password.length() + salt.length];
		System.arraycopy(password.getBytes(), 0, saltedPassword, 0, password.length());
		System.arraycopy(salt, 0, saltedPassword, password.length(), salt.length);
        MessageDigest md = MessageDigest.getInstance("SHA1");
        md.update(saltedPassword);
        return md.digest();
	}

	
	/*
	 * custom salt derived from password
	 * fewer iterations password length
	 */
 	private PBEKeySpec getPBEParameterSpec(String password) throws Throwable {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] saltGen = md.digest(password.getBytes());
        byte[] salt = new byte[10];
        System.arraycopy(saltGen, 0, salt, 0, 10);
        int iteration = password.toCharArray().length + 1;
        return new PBEKeySpec(password.toCharArray(), salt, iteration);
	}
 	
 	public static void main(String args[]) {
 		Random r = new Random(0);
 		System.out.println(r.nextInt());
 	}
  
  private String SECRET_PASSWORD = "letMeIn!";
	
	static String generateSecretToken() {
	    Random r = new Random();
	    return Long.toHexString(r.nextLong());
	}
	
	static String generateSecretToken2() {
		byte seed[] = {'0'};
	    SecureRandom r = new SecureRandom(seed);
	    return Long.toHexString(r.nextLong());
	}
	
	byte[] getMD5Hash(String password) {
		try {
			MessageDigest md5Digest = MessageDigest.getInstance("MD5");
			md5Digest.update(password.getBytes());
		    byte[] hashValue = md5Digest.digest();
		    return hashValue;
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	    return null;
	}
	
	byte[] getSHA1Hash(String password) {
		FileOutputStream fout = null; 
		PrintStream out = null;
		try {
			MessageDigest sha1Digest = MessageDigest.getInstance("SHA1");
		    sha1Digest.update(password.getBytes());
		    byte[] hashValue = sha1Digest.digest();
		    fout = new FileOutputStream("file.txt");
		    out = new PrintStream(fout);
		    out.print(password);
		    return hashValue;
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace(out);			
		} finally {
			out.close();
		}
	    return null;
	}
	
	Properties getPassword() {
		Properties props = new Properties();
		props.put(Context.SECURITY_CREDENTIALS, "p@ssw0rd");
		return props;
	}
	
	boolean compare(String password) {
		String hashValue = new String(getMD5Hash(password));
		String actualValue = new String(getMD5Hash("p@ssw0rd"));
		if(hashValue.equals(actualValue))
			return true;
		return false;		
	}
	
	static PBEParameterSpec salt() {
		byte b = '0';
		PBEParameterSpec pbeParamSpec = null;
		byte[] salt = {b,b};
		int count = 1020;
		pbeParamSpec = new PBEParameterSpec(salt, count);
	    return pbeParamSpec;
	}
	
}
