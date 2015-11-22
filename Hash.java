import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * My hashing system used to hash sensitive data. Use createHash to create a
 * hash of given String. Use validate to hash a String and match it with a given
 * hash (should be taken from database). Hashes created are in the format of
 * salt:hash:iterations
 * 
 * @author Philip
 *
 */
public class Hash {

	// Which Hashing Algorithm to use
	private static final String HASH_ALGORITHM = "PBKDF2WithHmacSHA1";

	private static final int SALT_SIZE = 128; // How many bits is the salt
	private static final int HASH_SIZE = 128; // How many bits is the hash
	// How many iterations to slow down brute force attacks
	private static final int ITERATIONS = 1000;

	/**
	 * Creates a PBKDF2 hash with salt attached.
	 * 
	 * @param data
	 *            the string to hash
	 * 
	 * @return the hash of string
	 */
	public static String createHash(char[] data) throws NoSuchAlgorithmException, InvalidKeySpecException {
		// Create a new salt to attach to hash
		SecureRandom random = new SecureRandom();
		byte[] salt = new byte[SALT_SIZE / 8];
		random.nextBytes(salt);
		// Create a new hash from the data
		byte[] hash = hash(HASH_ALGORITHM, data, salt, ITERATIONS, HASH_SIZE);
		return byteToHex(salt) + ":" + byteToHex(hash) + ":" + ITERATIONS;
	}

	/**
	 * Hashes a char array into a byte array.
	 * 
	 * @param data
	 *            data to hash
	 * @param salt
	 *            salt to use
	 * @param iterations
	 *            number of iterations for slowness
	 * @param hashSize
	 *            length of hash in bits
	 */
	public static byte[] hash(String hashAlgorithm, char[] data, byte[] salt, int iterations, int hashSize)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		SecretKeyFactory key = SecretKeyFactory.getInstance(HASH_ALGORITHM);
		PBEKeySpec spec = new PBEKeySpec(data, salt, iterations, hashSize);
		return key.generateSecret(spec).getEncoded();

	}

	private static final char[] hexLookup = "0123456789ABCDEF".toCharArray();

	/**
	 * Converts byte array to hexadecimal String.
	 * 
	 * @param bytes
	 * @return a String encoded from the byte array
	 */
	public static String byteToHex(byte[] bytes) {
		char[] hexChars = new char[bytes.length * 2];
		for (int i = 0; i < bytes.length; i++) {
			int j = bytes[i] & 0xFF;
			hexChars[i * 2] = hexLookup[j >>> 4];
			hexChars[i * 2 + 1] = hexLookup[j & 0x0F];
		}
		return new String(hexChars);
	}

	/**
	 * Converts hexadecimal String to byte array.
	 * 
	 * @param hex
	 * @return a byte array decoded from the String
	 */
	public static byte[] hexToBytes(String hex) {
		byte[] bytes = new byte[hex.length() / 2];
		for (int i = 0; i < bytes.length; i++) {
			bytes[i] = (byte) ((Character.digit(hex.charAt(i * 2), 16) << 4)
					+ Character.digit(hex.charAt(i * 2 + 1), 16));
		}
		return bytes;
	}

	/**
	 * Validates if given char array matches the given hash
	 * 
	 * @param data
	 * @param correctHash
	 * @return true if data matches, false if not
	 */
	public static boolean validate(char[] data, String correctHash)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		String[] parameters = correctHash.split(":");
		byte[] salt = hexToBytes(parameters[0]);
		byte[] hash = hexToBytes(parameters[1]);
		int iterations = Integer.parseInt(parameters[2]);
		byte[] hashData = hash(HASH_ALGORITHM, data, salt, iterations, hash.length);
		return timeConstantCompare(hashData, hash);
	}

	/**
	 * Time-constant comparison between two hashes. Compares the entire byte
	 * array instead of returning immediately when a false is found, preventing
	 * timing-attacks by hackers to guess each byte individually by the return
	 * time.
	 * 
	 * @return true if equal, false if not
	 */
	public static boolean timeConstantCompare(byte[] hash1, byte[] hash2) {
		// Use XOR to compare lengths, if same return 0, else return 1
		int difference = hash1.length ^ hash2.length;
		for (int i = 0; i < hash1.length && i < hash2.length; i++) {
			// |= Execution time does not depend on equality of integers
			difference |= hash1[i] ^ hash2[i];
		}
		return difference == 0; // Returns true if all XOR operations returned
								// 0, if one XOR returned 1 it will return false
	}
}
