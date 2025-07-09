import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;

public class Main {
    public static void main(String[] args) {
        try {
            // Generate a secret key for AES
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256); // Use 256-bit AES
            SecretKey key = keyGen.generateKey();

            // Initialize the cipher for encryption
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            byte[] iv = new byte[12];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);

            // Example data to encrypt
            byte[] data = "Sensitive data".getBytes();

            // Perform encryption
            byte[] encryptedData = cipher.doFinal(data);

            // Output encrypted data
            System.out.println("Encrypted Data: " + bytesToHex(encryptedData));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Helper method to convert byte array to hex string
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}