package fcul.wrapper;

import fcul.ArchiveMintUtils.Utils.CryptoUtils;
import fcul.ArchiveMintUtils.Utils.PoS;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Random;

public class FileEncodeProcess {
    public static int CHUNK_SIZE = PoS.CHUNK_SIZE;
    private static Sloth sloth = new Sloth();
    private static int averageTimePerChunkMS = 195; //Tested in McBookM1 and its an hyperparameter of the system 200 iterations
    private static int defaultChunkIteration = 200;
    private static int goalTimePerChunkMS = 60000;

    public static byte[] encodeFileVDE(byte[] file, byte[] iv, int iterationsPerChunk) {
        try {
            int numChunks = (int) Math.ceil((double) file.length / CHUNK_SIZE);
            ByteBuffer buffer = ByteBuffer.allocate(numChunks * CHUNK_SIZE+Integer.BYTES); // Preallocate space
            byte[] ivCopy = Arrays.copyOf(iv, iv.length);
            int padding = 0;
            for (int i = 0; i < file.length; i += CHUNK_SIZE) {
                int remainingBytes = Math.min(file.length - i, CHUNK_SIZE);
                byte[] chunk = Arrays.copyOfRange(file, i, i + remainingBytes);
                if (remainingBytes < CHUNK_SIZE) {
                    padding = CHUNK_SIZE - remainingBytes;
                    chunk = pad(chunk);
                }
                byte[] encodedChunk = sloth.encode(chunk, ivCopy, iterationsPerChunk);
                buffer.put(encodedChunk);
                ivCopy = CryptoUtils.hash256(encodedChunk);
            }
            buffer.putInt(padding);
            return buffer.array();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] decodeFileVDD(byte[] file, byte[] iv, int iterationsPerChunk) {
        try {
            int paddingAdded = ByteBuffer.wrap(file, file.length - 4, 4).getInt();
            byte[] ivCopy = Arrays.copyOf(iv, iv.length);
            ByteBuffer byteStream = ByteBuffer.allocate(file.length - Integer.BYTES);
            for (int i = 0; i < file.length - Integer.BYTES; i += CHUNK_SIZE) {
                int remainingBytes = Math.min(file.length - i, CHUNK_SIZE);
                byte[] chunk = Arrays.copyOfRange(file, i, i + remainingBytes);
                byte[] decodedChunk = sloth.decode(chunk, ivCopy, iterationsPerChunk);
                byteStream.put(decodedChunk);
                ivCopy = CryptoUtils.hash256(chunk);
            }
            byte[] decodedFile = byteStream.array();
            decodedFile = unpad(decodedFile, paddingAdded);
            return decodedFile;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] pad(byte[] original) {
        byte[] padded = new byte[CHUNK_SIZE];
        System.arraycopy(original, 0, padded, 0, original.length);
        return padded;
    }

    private static byte[] unpad(byte[] original, int padding) {
        byte[] unpadded = new byte[original.length - padding];
        System.arraycopy(original, 0, unpadded, 0, unpadded.length);
        return unpadded;
    }



    public static int iterationsPerChunk(int fileSize) {
        int chunkAmount = (fileSize / CHUNK_SIZE) + 1;
        double totalIterationsGoal = (double) (goalTimePerChunkMS * defaultChunkIteration) / averageTimePerChunkMS;
        return (int) Math.max(Math.ceil(totalIterationsGoal / chunkAmount), 1);

    }

    public static boolean verifySLOTH(byte[] encodedBytes, String originalFileHash,
                                      String normalizedFileName, String farmerAddress,int iterationsPerChunk) {
        String salt = normalizedFileName + farmerAddress;
        byte[] iv = CryptoUtils.hash256(salt.getBytes());
        byte[] decodedFile = decodeFileVDD(encodedBytes, iv, iterationsPerChunk);
        String decodedFileHash = Hex.encodeHexString(CryptoUtils.hash256(decodedFile));
        return originalFileHash.equals(decodedFileHash);
    }


    public static void main(String[] args) throws Exception {
        Random random = new Random(123);
        byte[] file = new byte[122880000]; //Files.readAllBytes(Path.of("TestFiles/relatorio_preliminar.pdf"));
        int fileSize = file.length;
        System.out.println("File size: " + fileSize);
        random.nextBytes(file);
        byte[] iv = new byte[32];       // Example 32 byte IV
        int iterationsPerChunk =iterationsPerChunk(fileSize);              // Example number of layers
        System.out.println("Iterations per chunk: " + iterationsPerChunk);
        random.nextBytes(iv);
        long startTime = System.nanoTime();
        byte[] encodedFile = encodeFileVDE(file, iv, iterationsPerChunk);
        System.out.println("Time taken encode: " + (System.nanoTime() - startTime) / 1000000 + "ms");
        startTime = System.nanoTime();
        byte[] decodedFile = decodeFileVDD(encodedFile, iv, iterationsPerChunk);
        System.out.println("Time taken decode: " + (System.nanoTime() - startTime) / 1000000 + "ms");
        System.out.println("Valid VDE: "+Arrays.equals(file, decodedFile));
    }


}
