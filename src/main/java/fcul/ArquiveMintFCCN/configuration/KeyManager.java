package fcul.ArquiveMintFCCN.configuration;

import fcul.ArchiveMintUtils.Utils.CryptoUtils;
import fcul.ArchiveMintUtils.Utils.Utils;
import jakarta.annotation.PostConstruct;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

@Component
@Data
@Slf4j
public class KeyManager {
    public static int RSA_BIT_SIZE = 2048;
    @Autowired
    Configuration nodeConfig;

    private PublicKey publicKey;
    private PrivateKey privateKey;
    private SecretKey AESKey;
    private SecretKey HMACKey;

    @PostConstruct
    public void init() {
        loadKeys();
    }

    public void loadKeys() {
        try {
            KeyPair pair = CryptoUtils.generateKeys(nodeConfig.getFccnMnemonic());
            publicKey = pair.getPublic();
            privateKey = pair.getPrivate();
            AESKey = CryptoUtils.getAESKey(nodeConfig.getFccnMnemonic());
            HMACKey = CryptoUtils.getHMACKey(nodeConfig.getFccnMnemonic());
            System.out.println("Loaded Keys");
            System.out.println(Utils.GREEN + "Loaded Mnemonic: " + nodeConfig.getFccnMnemonic() + Utils.RESET);
        } catch (Exception e) {
            throw new RuntimeException("Error processing keys", e);
        }
    }

}
