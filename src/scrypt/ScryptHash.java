package scrypt;

import utils.PBKDF2;

import java.security.SecureRandom;


/**
 * Scrypt is a slow-by-design key derivation function designed to create strong cryptographic keys.
 * Simply put, the purpose of the Scrypt hash is to create a fingerprint of its input data but to do it very slowly.
 * A common use-case is to create a strong private key from a password, where the new private key is longer and more secure.
 *
 * <a href="https://blog.boot.dev/cryptography/very-basic-intro-to-the-scrypt-hash/"><br/>Reference Link</a>
 * @author Joshua Vaz
 */
public class ScryptHash
{

	private final String username;
	private final byte[] passphrase; // string of characters to be hashed
	private final String orgPass;
	private byte[] salt;  // random salt
	private int costFactor; // CPU/Memory cost, must be power of 2
	private int blockSizeFactor;
	private int parallelizationFactor; // Parallelization parameter. (1 .. 2<sup>32</sup>-1 * hLen/MFlen)
	private int desiredKeyLen; // Desired key length in bytes (Intended output length in octets of the derived key; a positive integer satisfying dkLen ≤ (232− 1) * hLen.)
	private final String PRF_ALGORITHM = "HmacSHA256";
	private int blockSize; // blocksize parameter, which fine-tunes sequential memory read size and performance.
	private final int hLen = 32; // The length in octets of the hash function (32 for SHA256).
	private int MFlen; // The length in octets of the output of the mixing function

	// Testing
	public static void main(String[] args)
	{
		ScryptHash scryptHash = new ScryptHash("mshah22","password");
		scryptHash.encryptPassword();
	}


	/**
	 * Main Constructor
	 * @param username Username
	 * @param plainTextPassword Password
	 */
	public ScryptHash(String username, String plainTextPassword)
	{
		this.orgPass = plainTextPassword;
		this.username = username;
		this.passphrase = plainTextPassword.getBytes();
		init();

	}

	/**
	 * Inits stuff
	 */
	private void init()
	{
		costFactor = 16384;
		blockSizeFactor = 8;
		parallelizationFactor = 3;
		salt = randomSalt();
		desiredKeyLen = 32;
		MFlen = blockSizeFactor*128;
	}


	/**
	 * Gets the initial salt using PBKDF2
	 * <a href="https://blog.boot.dev/cryptography/very-basic-intro-to-the-scrypt-hash/#2---generate-initial-salt"><br/>
	 * Explanation</a>
	 * @return initial salt
	 */
	private byte[] getInitialSalt()
	{
		// Define blocksize
		blockSize = 128*blockSizeFactor;
		PBKDF2 pbkdf2 = new PBKDF2(orgPass,salt,1,blockSize*parallelizationFactor,PRF_ALGORITHM);
		return pbkdf2.createExpensiveSalt();
	}

	/**
	 * Rest of the algorithm.
	 * TODO Step 3,4 from the blog
	 */
	private void encryptPassword()
	{
		byte[] initialSalt = getInitialSalt();
		//checking initial salt to be sure.
		// DELETE LATER
		System.out.println(initialSalt.length);
		for(int i = 0; i< initialSalt.length; i++){
			System.out.print(initialSalt[i]+",");
		}

		//TODO MixSalt -> Finalize Salt
	}

	/**
	 * Creates a Secure Random salt to be used to create the expensive salt
	 * @return randomSalt
	 */
	private byte[] randomSalt() {
		SecureRandom secureRandom = new SecureRandom();
		byte[] randomSalt = new byte[16]; //128 bits
		secureRandom.nextBytes(randomSalt);
		return randomSalt;
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
