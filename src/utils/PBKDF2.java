package utils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;

/**
 * SWE 681 Final Project.
 * <br/>Group 12
 * <br/>Generates the cryptographic key for Scrypt encryption.
 * Algorithm referenced from wikipedia.
 * <a href="https://en.wikipedia.org/wiki/PBKDF2#Key_derivation_process"><br/>Algorithm Link</a>
 *
 * @author Mani Shah
 */
public class PBKDF2 {

	/**
	 * Password
	 */
	private char[] password;
	/**
	 * Unaltered original password
	 */
	private String orgPassword;
	/**
	 * SecureRandom Salt
	 */
	private byte[] salt;
	/**
	 * Number of iterations
	 */
	private int iterations;
	/**
	 * Length of the derived key
	 */
	private int dklen;
	/**
	 * Derived Key
	 */
	private byte[] derivedKey;
	/**
	 * HMAC-SHA256 pseudorandom algorithm
	 */
	private String prfAlgo;

	/**
	 *
	 * Validates and inits the object
	 *
	 * @param password char array of the password
	 * @param salt byte array of salt
	 * @param iterations number of iterations
	 * @param keyLength length of the derived key
	 * @param prfAlgorithm pseudorandom algorithm
	 *
	 *
	 */
	public PBKDF2(char[] password, byte[] salt, int iterations, int keyLength, String prfAlgorithm)
	{
		if(validInputParams(password,salt,iterations,keyLength,prfAlgorithm)) {
			initValues(password, salt, iterations, keyLength, prfAlgorithm);
		}else{
			System.err.println("Invalid parameters.");
		}

	}

	/**
	 *
	 * Validates all the provided inputs
	 *
	 * @param password char array of the password
	 * @param salt byte array of salt
	 * @param iterations number of iterations
	 * @param keyLength length of the derived key
	 * @param prfAlgorithm pseudorandom algorithm
	 * @return true if all inputs are valid. False otherwise.
	 */
	private boolean validInputParams(char[] password, byte[] salt, int iterations, int keyLength, String prfAlgorithm)
	{
		return password.length > 0 && salt.length > 0
				&& iterations > 0 && keyLength > 0 && prfAlgorithm != null && !prfAlgorithm.isEmpty();
	}

	/**
	 * Actually initializes the values
	 *
	 * @param password char array of the password
	 * @param salt byte array of salt
	 * @param iterations number of iterations
	 * @param keyLength length of the derived key
	 * @param prfAlgorithm pseudorandom algorithm
	 */
	private void initValues( char[] password, byte[] salt, int iterations, int keyLength, String prfAlgorithm)
	{
		this.password = password;
		this.orgPassword = Arrays.toString(password);
		this.salt = salt;
		this.iterations = iterations;
		this.dklen = keyLength;
		this.prfAlgo = prfAlgorithm;
		this.derivedKey = new byte[dklen];
	}

	/**
	 * gets the PBKDF2 key
	 * @return derivedKey
	 */
	public String getDerivedKey()
	{
		return getHexKey(Objects.requireNonNull(generatePBKDF2()));
	}

	/**
	 * DK = T1 + T2 + ⋯ + Tdklen/hlen
	 * <br/>Ti = F(Password, Salt, c, i)
	 * @return derivedKey
	 */
	private byte[] generatePBKDF2() {

		try {
			Mac prf = Mac.getInstance(prfAlgo);
			prf.init(new SecretKeySpec(orgPassword.getBytes(StandardCharsets.UTF_8), prfAlgo));

			byte[] Tprev = prf.doFinal(salt);

			for (int i = 1; i < iterations; i++) {
				byte[] Ti = prf.doFinal(Tprev);
				Tprev = xorBytes(Tprev, Ti);
			}

			System.arraycopy(Tprev, 0, derivedKey, 0, dklen);
			return derivedKey;
		} catch (Exception e) {
			return null;
		}
	}

	/**
	 * F(Password, Salt, c, i) = Ui ^ Ui+1 ^ ⋯ ^ Ui+n
	 * @param U1 Ui
	 * @param U2 Ui+1
	 * @return Ui ^ Ui+1
	 */
	private byte[] xorBytes(byte[] U1, byte[] U2) {
		if(U1.length == 0 || U2.length == 0){
			System.err.println("Invalid Arrays");
			return null;
		}
		byte[] xorArr = new byte[U1.length];
		for (int i = 0; i < U1.length; i++) {
			xorArr[i] = (byte) (U1[i] ^ U2[i]);
		}
		return xorArr;
	}

	/**
	 *
	 * @param derivedKey byte[]
	 * @return derivedKey in String
	 */
	private String getHexKey(byte[] derivedKey)
	{
		StringBuilder stringBuilder = new StringBuilder();
		for (byte i : derivedKey) {
			stringBuilder.append(String.format("%02x", i));
		}
		return stringBuilder.toString();
	}

}
