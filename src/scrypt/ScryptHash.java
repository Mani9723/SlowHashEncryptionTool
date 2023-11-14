package scrypt;

import utils.PBKDF2;

import java.security.SecureRandom;
import java.util.ArrayList;


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
	private byte[] passHash;
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
		//scryptHash.encryptPassword();
		// Mani: Avoid string->byte[]->string conversion. messes up the values.
//		String temp = new String(scryptHash.salt);
		ScryptHash scryptHash2 = new ScryptHash("mshah22","password", scryptHash.getRandomSalt()); // Same Salt needs to be passed

//		temp = new String(scryptHash.passHash);
		String temp = new String(scryptHash.passHash);
//		String temp2 = new String(scryptHash2.salt);
		String temp2 = new String(scryptHash2.passHash);
		if(temp.equals(temp2)) {
			System.out.println("Yippie ");
		}else {
			System.out.println("BOOOO ");
		}
	}


	public byte[] getRandomSalt()
	{
		return this.salt;
	}

	public void setSalt(byte[] salt)
	{
		this.salt = salt;
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
		long start=System.currentTimeMillis();
		encryptPassword();
		long end=System.currentTimeMillis();
		System.out.println("Time:"+(end-start));
	}
	
	
	public ScryptHash(String username, String plainTextPassword,byte[] salt)
	{
		this.orgPass = plainTextPassword;
		this.username = username;
		this.passphrase = plainTextPassword.getBytes();
		init(); // creates brand new salt.
		setSalt(salt); // reset this so that it uses the parameter byte[] instead
		long start=System.currentTimeMillis();
		encryptPassword();
		long end=System.currentTimeMillis();
		System.out.println("Time:"+(end-start));
	}

	/**
	 * Inits stuff
	 */
	private void init()
	{
		costFactor = 16384*2000;
		blockSizeFactor = 8;
		parallelizationFactor = 3;
		blockSize = 128*blockSizeFactor*parallelizationFactor;
		salt = randomSalt(); // we need to keep track of this value. ie store in Database
		desiredKeyLen = 32;
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
		
		PBKDF2 pbkdf2 = new PBKDF2(orgPass,salt,1,blockSize,PRF_ALGORITHM);
		byte [] toReturn=pbkdf2.createExpensiveSalt();
		return toReturn;
	}

	/**
	 * Rest of the algorithm.
	 * TODO Step 3,4 from the blog
	 */
	private void encryptPassword()
	{
		//Step 1 Get Initial Salt
		byte[] salt = getInitialSalt();
		byte[] pass = orgPass.getBytes();
		
		
		
		//Step 2 Mix Salt and Key
		byte[][] saltBlocks = PBKDF2.divideArray(salt,blockSize);
		byte[][] passBlocks = PBKDF2.divideArray(pass,blockSize);
		
		//Row Mix
		
		for(int i =0; i<saltBlocks.length;i++) {
			rowMix(passBlocks[i],saltBlocks[i]);
		}
		//Step 3 Get Final Key
		
		
		PBKDF2 pbkdf2 = new PBKDF2(orgPass,salt,1,blockSize,PRF_ALGORITHM);
		this.passHash = pbkdf2.createExpensiveSalt();
		
		//Expensive Salt
		
		 
		//TODO MixSalt -> Finalize Salt
	}


	private byte[] rowMix(byte[] passBlocks,byte[] saltBlocks) {
		
		byte[] mixBlock = new byte[blockSize];
        byte[] xorBlock = new byte[blockSize];
        
        System.arraycopy(passBlocks, 0, mixBlock, 0, passBlocks.length);
		
		for (int i = 0; i < costFactor; i++) {
			//block mix
			blockMix(mixBlock, saltBlocks);

            // XOR the results together
            for (int j = 0; j < blockSize; j++) {
                xorBlock[j] ^= mixBlock[j];
            }
        }
		return xorBlock;
	}
	private void blockMix(byte[] block1, byte[] block2) {
        for (int i = 0; i < parallelizationFactor; i++) {
        	block1[i] = (byte) (block1[i] ^ block2[i]);
        }
    }
	
	
	private static byte[] xorBlocks(byte[] block1, byte[] block2) {
        byte[] result = new byte[block1.length];
        for (int i = 0; i < block1.length; i++) {
            result[i] = (byte) (block1[i] ^ block2[i]);
        }
        return result;
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
	public boolean verifyUser() {
		return true;
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
