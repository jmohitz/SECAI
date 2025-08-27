import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;

public class Main {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int IV_SIZE = 12; // GCM standard IV size
    private static final int TAG_LENGTH = 128; // GCM tag length in bits

    public static void main(String[] args) throws Exception {
        // 1. Generate a secret key
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
        keyGen.init(256); // 256-bit AES key
        SecretKey secretKey = keyGen.generateKey();

        // 2. Generate a random IV
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_LENGTH, iv);

        // 3. Initialize Cipher for encryption
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

        // 4. Encrypt data
        String originalData = "This is a secret message.";
        byte[] dataToEncrypt = originalData.getBytes();
        byte[] encryptedData = cipher.doFinal(dataToEncrypt);

        // 5. Print results (for demonstration)
        System.out.println("Original Data: " + originalData);
        System.out.println("IV (Base64): " + Base64.getEncoder().encodeToString(iv));
        System.out.println("Encrypted Data (Base64): " + Base64.getEncoder().encodeToString(encryptedData));

        // --- Decryption (for demonstration) ---

        // 6. Initialize Cipher for decryption
        Cipher decryptCipher = Cipher.getInstance(TRANSFORMATION);
        // Use the same key and IV for decryption
        decryptCipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);

        // 7. Decrypt data
        byte[] decryptedData = decryptCipher.doFinal(encryptedData);

        // 8. Print decrypted data
        System.out.println("Decrypted Data: " + new String(decryptedData));
    }
}
