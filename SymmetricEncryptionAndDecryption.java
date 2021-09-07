import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Erik Costlow , Modified by Frances Julaton
 */

public class Pt1FileEncryptor{
    private static final Logger LOG = Logger.getLogger(Pt1FileEncryptor.class.getSimpleName());

    private static final String ALGORITHM = "AES";
    private static final String CIPHER = "AES/CBC/PKCS5PADDING";

    //encrypt
    public static void encrypt(String inputFile, String outputFile, Path tempDir) throws NoSuchAlgorithmException, NoSuchPaddingException,
        InvalidKeyException, InvalidAlgorithmParameterException {

        //Create random key, and IV
        //This snippet is literally copied from SymmetrixExample
        SecureRandom sr = new SecureRandom();
        byte[] key = new byte[16];
        sr.nextBytes(key); // 128 bit key
        byte[] initVector = new byte[16];
        sr.nextBytes(initVector); // 16 bytes IV

        //Print out secret key and IV and encode
        System.out.println("Random key " + Base64.getEncoder().encodeToString(key));
        System.out.println("initVector " + Base64.getEncoder().encodeToString(initVector));

        //Initialise the cipher(Cipher) and key(SecretKeySpec) to specified algorithm: AES for key and AES/CBC/PKCS5PADDING for cipher
        IvParameterSpec iv = new IvParameterSpec(initVector);
        SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

        final Path encryptedPath = tempDir.resolve(outputFile);

        //read plaintext content and use the cipherOut to convert plain text into encrypted text using the cipher.
        try (InputStream fin = Pt1FileEncryptor.class.getResourceAsStream(inputFile);
             //create a file output stream
             OutputStream fout = Files.newOutputStream(encryptedPath);
             CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher) {
             }) {
            fout.write(initVector);
            final byte[] bytes = new byte[1024];
            for(int length=fin.read(bytes); length!=-1; length = fin.read(bytes)){
                cipherOut.write(bytes, 0, length);
            }
        } catch (IOException e) {
            LOG.log(Level.INFO, "Unable to encrypt", e);
        }

        LOG.info("Encryption finished, saved at " + encryptedPath);

    }

    //decrypt
    public static void decrypt(String inputFile, String outputFile, Path tempDir, String keyString, String IVString)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, IOException {

        //Decode the key and Iv from string to bytes
        byte[] key = Base64.getDecoder().decode(keyString);
        byte[] initVector = Base64.getDecoder().decode(IVString);
        byte[] encIV = new byte[16];

        //Initialise the Encrypted and decrypt paths
        final Path encryptedPath = tempDir.resolve(inputFile);
        final Path decryptedPath = tempDir.resolve(outputFile);


        //generate  secret key and initialize cipher
        IvParameterSpec iv = new IvParameterSpec(initVector);
        SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

        //Read the cipher text (from encryptedPath), then translate the cipher text to plaintext by using decryptedOut function
        try(
                InputStream encryptedData = Files.newInputStream(encryptedPath);
            CipherInputStream decryptStream = new CipherInputStream(encryptedData, cipher);
            OutputStream decryptedOut = Files.newOutputStream(decryptedPath))   {

            encryptedData.read(encIV);
            final byte[] bytes = new byte[1024];

            for(int length=decryptStream.read(bytes); length!=-1; length = decryptStream.read(bytes)){
                decryptedOut.write(bytes, 0, length);
            }
        } catch (IOException ex) {
            Logger.getLogger(Pt1FileEncryptor.class.getName()).log(Level.SEVERE, "Unable to decrypt", ex);
        }

        LOG.info("Decryption complete, open " + decryptedPath);
    }

    public static void main(String[] args) {
        String inputFile, outputFile, IVString, keyString;
        Path tempDir = Paths.get("");
        String enc = "enc";
        String dec = "dec";
        try{
            if (args.length >= 1) {
                if (args[0].equals(enc)) {
                    inputFile = args[1];
                    outputFile = args[2];
                    encrypt(inputFile, outputFile, tempDir);
                }
                if (args[0].equals(dec)) {
                    keyString = args[1];
                    IVString = args[2];
                    inputFile = args[3];
                    outputFile = args[4];
                    decrypt(inputFile, outputFile, tempDir, keyString, IVString);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}



