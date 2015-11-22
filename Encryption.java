import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * My Encryption System used to encode user data. Use createEncryption() to
 * encrypt and createDecryption() to decrypt data with my defaults, or use your
 * own specified Key, Encryption Algorithm and IV to encrypt and decrypt the
 * data using encrypt() and decrypt().
 * 
 * @author Philip
 *
 */
public class Encryption {

	// Which Encryption Algorithm, we use Java's 128 Bit AES
	private static final String ENCRYPTION_ALGORITHM = "AES/CBC/PKCS5Padding";
	// 16 Byte Key == 128 Bit
	private static final byte[] SECRET_KEY = "ABCD1234ABCD1234".getBytes();
	private static final String KEY_SPEC = "AES"; // Key Spec
	// 16 Byte Iv
	private static final byte[] IV = "16byte static iv".getBytes();

	/**
	 * Creates a encrypted / cipher text form from a plain text String.
	 * 
	 * @param plainText
	 * @return cipher text of plainText
	 */
	public static String createEncryption(String plainText)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException,
			IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		SecretKeySpec key = new SecretKeySpec(SECRET_KEY, KEY_SPEC);
		return encrypt(key, ENCRYPTION_ALGORITHM, plainText, new IvParameterSpec(IV));
	}

	/**
	 * Encrypts a String using the key, encryption algorithm and IV.
	 * 
	 * @param key
	 * @param encryptionAlgorithm
	 * @param plainText
	 * @param iv
	 *            IV to prevent encrypted data from being similar with other
	 *            encrypted data
	 * @return cipher text of plainText
	 */
	public static String encrypt(Key key, String encryptionAlgorithm, String plainText, IvParameterSpec iv)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException,
			IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		Cipher cipher = Cipher.getInstance(encryptionAlgorithm);
		cipher.init(Cipher.ENCRYPT_MODE, key, iv);
		String cipherText = new String(cipher.doFinal(plainText.getBytes()));
		return cipherText;
	}

	/**
	 * Creates a decrypted / plain text form from a cipher text String.
	 * 
	 * @param cipherText
	 * @return plain text of cipherText
	 */
	public static String createDecryption(String cipherText)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException,
			IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		SecretKeySpec key = new SecretKeySpec(SECRET_KEY, KEY_SPEC);
		return decrypt(key, ENCRYPTION_ALGORITHM, cipherText, new IvParameterSpec(IV));
	}

	/**
	 * Decrypts a String using the key, encryption algorithm and IV.
	 * 
	 * @param key
	 * @param encryptionAlgorithm
	 * @param cipherText
	 * @param iv
	 * @return plain text of cipherText
	 */
	public static String decrypt(Key key, String encryptionAlgorithm, String cipherText, IvParameterSpec iv)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException,
			IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		Cipher cipher = Cipher.getInstance(encryptionAlgorithm);
		cipher.init(Cipher.DECRYPT_MODE, key, iv);
		String plainText = new String(cipher.doFinal(cipherText.getBytes()));
		return plainText;
	}

	public static void main(String[] args)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException,
			IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
			
	}
}
