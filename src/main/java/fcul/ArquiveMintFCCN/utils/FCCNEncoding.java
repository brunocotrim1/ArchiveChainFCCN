package fcul.ArquiveMintFCCN.utils;

import fcul.ArchiveMintUtils.Model.StorageContract;
import fcul.ArchiveMintUtils.Model.StorageType;
import fcul.ArchiveMintUtils.Utils.AESEncode;
import fcul.ArchiveMintUtils.Utils.CryptoUtils;
import fcul.ArchiveMintUtils.Utils.PoDp;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.time.Instant;

public class FCCNEncoding {
    private static final int PROVING_FREQUENCY = 5;//parameter of the system


    public static byte[] AESEncode(byte[] file, SecretKey key, SecretKey hmacKey, String normalizedFileName,
                                   String farmerAddress) throws Exception {
        String salt = normalizedFileName + farmerAddress;
        byte[] iv = CryptoUtils.getTruncatedHASHIV(salt.getBytes());
        return AESEncode.encrypt(file, key, hmacKey, iv);
    }

    public static byte[] AESDecode(byte[] file, SecretKey key, SecretKey hmacKey, String normalizedFileName,
                                   String farmerAddress) throws Exception {
        String salt = normalizedFileName + farmerAddress;
        byte[] iv = CryptoUtils.getTruncatedHASHIV(salt.getBytes());
        return AESEncode.decrypt(file, key, hmacKey, iv);
    }

    public static StorageContract getStorageContract(String url, byte[] data, PrivateKey privateKey,
                                                     String storerAddress, StorageType type) {
        byte[] merkleRoot = PoDp.merkleRootFromData(data);
        String merkleRootHex = Hex.encodeHexString(merkleRoot);
        StorageContract contract = StorageContract.builder()
                .proofFrequency(PROVING_FREQUENCY)
                .merkleRoot(merkleRootHex)
                .value(BigInteger.valueOf(25))
                .fileUrl(url)
                .timestamp(Instant.now())
                .storerAddress(storerAddress)
                .storageType(type)
                .build();
        contract.setFccnSignature(Hex.encodeHexString(CryptoUtils.ecdsaSign(contract.getHash(), privateKey)));
        return contract;
    }
}
