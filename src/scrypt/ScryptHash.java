package scrypt;

import utils.PBKDF2;

import java.security.SecureRandom;

public class ScryptHash
{
	private String username;
	private byte[] passphrase; // string of characters to be hashed
	private byte[] salt;  // random salt
	private int costFactor; // CPU/Memory cost, must be power of 2
	private int blockSizeFactor;
	private int parallelizationFactor; // (1..232-1 * hLen/MFlen)
	private int desiredKeyLen; // Desired key length in bytes
	private static final String PRF_ALGORITHM = "HmacSHA256";



	ScryptHash()
	{
		// Default might be useful
	}

	public ScryptHash(String username, String plainTextPassword)
	{
		this.username = username;
		this.passphrase = plainTextPassword.getBytes();
	}

	public boolean verifyUser()
	{
		return false;
	}


	private String getUsername()
	{
		return this.username;
	}

	private String getPlaintextPassword()
	{
		return new String(passphrase);
	}

	private byte[] getPassphrase()
	{
		return this.passphrase;
	}

}
