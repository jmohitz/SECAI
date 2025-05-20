import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.SecureRandom;

public class Main {
    public static void main(String[] args) {
        try {
            SecureRandom secureRandom = new SecureRandom();
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256, secureRandom);
            SecretKey secretKey = keyGen.generateKey();
            
            // Use the secretKey as needed
            System.out.println("Secret Key Generated: " + bytesToHex(secretKey.getEncoded()));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }
}