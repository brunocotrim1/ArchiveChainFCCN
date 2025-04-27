package fcul.ArquiveMintFCCN.service;

import fcul.ArchiveMintUtils.Model.PeerRegistration;
import fcul.ArchiveMintUtils.Model.StorageContract;
import fcul.ArchiveMintUtils.Model.StorageType;
import fcul.ArchiveMintUtils.Model.transactions.StorageContractSubmission;
import fcul.ArchiveMintUtils.Utils.CryptoUtils;
import fcul.ArchiveMintUtils.Utils.Utils;
import fcul.ArquiveMintFCCN.configuration.Configuration;
import fcul.ArquiveMintFCCN.configuration.KeyManager;
import fcul.ArquiveMintFCCN.utils.FCCNEncoding;
import fcul.ArquiveMintFCCN.utils.RandomCdxjReader;
import fcul.wrapper.FileEncodeProcess;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import jnr.ffi.Struct.socklen_t;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.mapdb.DB;
import org.mapdb.DBMaker;
import org.mapdb.HTreeMap;
import org.mapdb.Serializer;
import org.python.antlr.ast.For;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.SQLException;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@Service
@Slf4j
public class StorageService {

    @Autowired
    private Configuration configuration;
    @Autowired
    private KeyManager keyManager;

    // MapDB database instance
    private DB db;
    // Persistent HTreeMaps replacing ConcurrentHashMaps
    private HTreeMap<String, PeerRegistration> farmers;
    private HTreeMap<String, Long> storageAccesses;
    private HTreeMap<String, List<StorageContract>> storageContracts;
    private HTreeMap<String, List<String>> pendingStorers;
    private HTreeMap<String, String> originalFileHashes;
    private HTreeMap<String, String> vdeContracts;

    private static final int VDE_THRESHOLD = 150000000; // 1 MB Threshold for testing
    private static final String ARCHIVAL_ENDPOINT = "/blockchain/archiveFile";
    private final RestTemplate restTemplate = new RestTemplate();

    public String test() {
        return configuration.getStoragePath();
    }

    @PostConstruct
    public void onInit() throws SQLException {
        // Initialize MapDB with a file-based database
        db = DBMaker.fileDB(configuration.getStoragePath() + "/storage_service.db")
                .fileMmapEnableIfSupported() // Use memory-mapped files for better performance
                .closeOnJvmShutdown() // Automatically close on JVM shutdown
                .make();

        // Initialize persistent HTreeMaps
        farmers = db.hashMap("farmers")
                .keySerializer(Serializer.STRING)
                .valueSerializer(Serializer.JAVA)
                .createOrOpen();
        storageAccesses = db.hashMap("storageAccesses")
                .keySerializer(Serializer.STRING)
                .valueSerializer(Serializer.LONG)
                .createOrOpen();
        storageContracts = db.hashMap("storageContracts")
                .keySerializer(Serializer.STRING)
                .valueSerializer(Serializer.JAVA)
                .createOrOpen();
        pendingStorers = db.hashMap("pendingStorers")
                .keySerializer(Serializer.STRING)
                .valueSerializer(Serializer.JAVA)
                .createOrOpen();
        originalFileHashes = db.hashMap("originalFileHashes")
                .keySerializer(Serializer.STRING)
                .valueSerializer(Serializer.STRING)
                .createOrOpen();
        vdeContracts = db.hashMap("vdeContracts")
                .keySerializer(Serializer.STRING)
                .valueSerializer(Serializer.STRING)
                .createOrOpen();

        
        Path CDXJ_Folder = Paths.get(configuration.getCdxjFolder());
        if (configuration.isConvertCDXJ()) {
            System.out.println(Utils.GREEN + "Converting CDXJ files to FCCN format" + Utils.RESET);
            RandomCdxjReader.initializeDatabaseIfNotExists();
            RandomCdxjReader.convertCDXJFolder(CDXJ_Folder, CDXJ_Folder);
            System.out.println(Utils.GREEN + "CDXJ files converted to FCCN format" + Utils.RESET);
        }


    }

    @PreDestroy
    public void onDestroy() {
        // Commit changes and close the database
        if (db != null && !db.isClosed()) {
            db.commit();
            db.close();
        }
    }

    public ResponseEntity<String> archiveFile(MultipartFile file) {
        try {
            byte[] fileBytes = file.getInputStream().readAllBytes();
            String normalizedFileName = Normalizer.normalize(file.getOriginalFilename(), Normalizer.Form.NFC);
            originalFileHashes.putIfAbsent(normalizedFileName, Hex.encodeHexString(CryptoUtils.hash256(fileBytes)));
            db.commit(); // Commit hash to disk

            PeerRegistration farmer;
            synchronized (pendingStorers) {  // Synchronize to prevent race condition
                farmer = getFarmerForArchival(normalizedFileName);
                if (farmer == null) {
                    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                            .body("No farmer available for archival");
                }
                pendingStorers.computeIfAbsent(normalizedFileName, k -> new ArrayList<>())
                        .add(farmer.getWalletAddress());
                db.commit(); // Commit pending storers to disk
            }

            int fileSize = fileBytes.length;
            ResponseEntity<String> response = fileSize < VDE_THRESHOLD
                    ? aesProcess(fileBytes, farmer, keyManager, file.getOriginalFilename())
                    : vdeProcess(fileBytes, farmer, keyManager, file.getOriginalFilename());

            log.info("Response from archiving file: {} from {}", response.getBody(), farmer.getWalletAddress());
            return ResponseEntity.status(response.getStatusCode()).body(response.getBody());
        } catch (Exception e) {
            log.error("Error while archiving file", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }

    private ResponseEntity<String> vdeProcess(byte[] fileBytes, PeerRegistration farmer, KeyManager keyManager,
                                             String fileOriginalName) {
        String normalizedFileName = Normalizer.normalize(fileOriginalName, Normalizer.Form.NFC);
        StorageContract storageContract = FCCNEncoding.getStorageContract(fileOriginalName, fileBytes,
                keyManager.getPrivateKey(), farmer.getWalletAddress(), StorageType.VDE);

        MultiValueMap<String, Object> body = prepareMultipartBody(fileBytes, fileOriginalName, storageContract);
        return sendRequest(farmer.getNetworkAddress() + ARCHIVAL_ENDPOINT, body);
    }

    public ResponseEntity<StorageContract> signVDE(MultipartFile file, String farmerPublicKey)
            throws IOException, DecoderException {
        PeerRegistration farmer = farmers.get(CryptoUtils.getWalletAddress(farmerPublicKey));
        if (farmer == null) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        }

        String normalizedFileName = Normalizer.normalize(file.getOriginalFilename(), Normalizer.Form.NFC);
        byte[] fileBytes = file.getInputStream().readAllBytes();

        List<String> pending = pendingStorers.get(normalizedFileName);
        if (pending == null || !pending.contains(farmer.getWalletAddress())) {
            log.error("File not pending for Storage");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        }

        if (!FileEncodeProcess.verifySLOTH(fileBytes, originalFileHashes.get(normalizedFileName),
                normalizedFileName, farmer.getWalletAddress(), 1)) {
            log.error("Invalid VDE Encoding");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        }

        StorageContract storageContract = FCCNEncoding.getStorageContract(file.getOriginalFilename(), fileBytes,
                keyManager.getPrivateKey(), farmer.getWalletAddress(), StorageType.VDE);

        String salt = normalizedFileName + farmer.getWalletAddress();
        byte[] iv = CryptoUtils.hash256(salt.getBytes());
        String fileHash = Hex.encodeHexString(CryptoUtils.hash256(fileBytes));
        vdeContracts.put(fileHash + farmer.getWalletAddress(), Hex.encodeHexString(iv));
        db.commit(); // Commit VDE contract to disk

        registerStorage(storageContract, normalizedFileName);
        return ResponseEntity.ok(storageContract);
    }

    private ResponseEntity<String> aesProcess(byte[] fileBytes, PeerRegistration farmer, KeyManager keyManager,
                                             String fileOriginalName) throws Exception {
        String normalizedFileName = Normalizer.normalize(fileOriginalName, Normalizer.Form.NFC);
        byte[] fileAESEncoded = FCCNEncoding.AESEncode(fileBytes, keyManager.getAESKey(),
                keyManager.getHMACKey(), normalizedFileName, farmer.getWalletAddress());

        StorageContract storageContract = FCCNEncoding.getStorageContract(fileOriginalName, fileAESEncoded,
                keyManager.getPrivateKey(), farmer.getWalletAddress(), StorageType.AES);

        MultiValueMap<String, Object> body = prepareMultipartBody(fileAESEncoded, fileOriginalName, storageContract);
        return sendRequest(farmer.getNetworkAddress() + ARCHIVAL_ENDPOINT, body);
    }

    public ResponseEntity<byte[]> downloadFile(String fileName) {
        try {

            List<String> files = storageContracts.keySet().stream().toList();
            for (String file : files) {
                System.out.println("File: " + file);
            }


            String normalizedFileName = Normalizer.normalize(fileName, Normalizer.Form.NFC);
            List<StorageContract> contracts = storageContracts.get(normalizedFileName);
            if (contracts == null || contracts.isEmpty()) {
                System.out.println("No contracts available for retrieval: " + normalizedFileName);
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new byte[0]);
            }

            PeerRegistration farmer = getFarmerForRetrieval(normalizedFileName);
            if (farmer == null) {
                System.out.println("No farmer available for retrieval: " + normalizedFileName);
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body("No farmer available for retrieval".getBytes());
            }

            StorageContract contract = contracts.stream()
                    .filter(c -> c.getStorerAddress().equals(farmer.getWalletAddress()))
                    .findFirst()
                    .orElse(null);

    

            if (contract == null) {
                System.out.println("No contract available for retrieval: " + normalizedFileName);
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body("No contract available for retrieval".getBytes());
            }

            String targetUrl = UriComponentsBuilder.fromHttpUrl(farmer.getNetworkAddress())
                    .path("/blockchain/download")
                    .queryParam("fileUrl", normalizedFileName)
                    .toUriString();

            ResponseEntity<byte[]> response = restTemplate.exchange(targetUrl, HttpMethod.GET, null, byte[].class);
            byte[] file = response.getBody();
            if (file == null) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new byte[0]);
            }

            String fileHash = Hex.encodeHexString(CryptoUtils.hash256(file));
            byte[] decoded = decodeFile(file, fileHash, normalizedFileName, farmer, contract.getStorageType());

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(response.getHeaders().getContentType());
            headers.setContentLength(decoded.length);

            log.info("Downloaded file: {} from {} of type: {}", normalizedFileName,
                    farmer.getWalletAddress(), contract.getStorageType());

            return ResponseEntity.status(response.getStatusCode())
                    .headers(headers)
                    .body(decoded);
        } catch (Exception e) {
            log.error("Error while downloading file", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new byte[0]);
        }
    }

    private byte[] decodeFile(byte[] file, String fileHash, String fileName,
                             PeerRegistration farmer, StorageType type) throws Exception {
        if (type == StorageType.VDE) {
            String iv = vdeContracts.get(fileHash + farmer.getWalletAddress());
            return FileEncodeProcess.decodeFileVDD(file, Hex.decodeHex(iv), 1);
        } else {
            return FCCNEncoding.AESDecode(file, keyManager.getAESKey(), keyManager.getHMACKey(),
                    fileName, farmer.getWalletAddress());
        }
    }

    public PeerRegistration getFarmerForArchival(String fileId) {
        List<StorageContract> contracts = storageContracts.get(fileId);
        List<String> pending = pendingStorers.get(fileId);

        return farmers.values().stream()
                .filter(farmer -> (contracts == null || contracts.stream()
                        .noneMatch(c -> c.getStorerAddress().equals(farmer.getWalletAddress())))
                        && (pending == null || !pending.contains(farmer.getWalletAddress())))
                .findAny()
                .orElse(null);
    }

    public synchronized PeerRegistration getFarmerForRetrieval(String fileId) {
        List<StorageContract> contracts = storageContracts.get(fileId);
        if (contracts == null || contracts.isEmpty()) {
            return null;
        }

        List<String> farmerAddresses = contracts.stream()
                .map(StorageContract::getStorerAddress)
                .toList();

        Long lastAccessed = storageAccesses.getOrDefault(fileId, -1L);
        long newAccessId = (lastAccessed + 1) % farmerAddresses.size();
        storageAccesses.put(fileId, newAccessId);
        db.commit(); // Commit storage access update to disk

        String farmerAddress = farmerAddresses.get((int) newAccessId);
        return farmers.get(farmerAddress);
    }

    public void registerStorage(StorageContract storageContract, String normalizedFileName) {
        synchronized (pendingStorers) {  // Synchronize to ensure atomicity
            // Explicitly get or create the list
            List<StorageContract> contracts = storageContracts.get(normalizedFileName);
            if (contracts == null) {
                contracts = new ArrayList<>();
                storageContracts.put(normalizedFileName, contracts);
            }
            // Add the storage contract to the list
            contracts.add(storageContract);
            // Update the map to ensure the modified list is persisted
            storageContracts.put(normalizedFileName, contracts);
            log.info("Added storage contract for file: {}, list size: {}", normalizedFileName, contracts.size());

            // Update storage accesses
            storageAccesses.putIfAbsent(normalizedFileName, 0L);

            // Remove from pending storers
            List<String> pending = pendingStorers.get(normalizedFileName);
            if (pending != null) {
                pending.remove(storageContract.getStorerAddress());
                if (pending.isEmpty()) {
                    pendingStorers.remove(normalizedFileName);
                } else {
                    pendingStorers.put(normalizedFileName, pending);
                }
            }

            // Commit changes to disk
            db.commit();
            log.info("Committed storage contract for file: {}, current contracts: {}", normalizedFileName, storageContracts.get(normalizedFileName));
        }

        log.info("Storage contract registered: {} from {} of type: {}",
                storageContract.getFileUrl(), storageContract.getStorerAddress(),
                storageContract.getStorageType());
    }

    public boolean registerFarmer(PeerRegistration farmerAddress) {
        try {
            if (farmers.containsKey(farmerAddress.getWalletAddress())) {
                log.error("Farmer already registered");
                return true;
            }

            String address = CryptoUtils.getWalletAddress(farmerAddress.getPublicKey());
            String data = farmerAddress.getNetworkAddress() + address + farmerAddress.getDedicatedStorage();

            if (!CryptoUtils.ecdsaVerify(Hex.decodeHex(farmerAddress.getSignature()), data.getBytes(),
                    Hex.decodeHex(farmerAddress.getPublicKey()))) {
                log.error("Invalid signature");
                return false;
            }

            farmers.put(farmerAddress.getWalletAddress(), farmerAddress);
            db.commit(); // Commit farmer registration to disk
            log.info("Farmer registered: {}", farmerAddress.getWalletAddress());
            if (farmerAddress.isFillStorageNow()) {
                Thread t = new Thread(() -> {
                    long startTime = System.currentTimeMillis();
                    archiveRandomDataForFarmer(farmerAddress);
                    long endTime = System.currentTimeMillis();
                    long duration = endTime - startTime;
                    log.info("Time taken to fill storage: {} ms", duration);
                    db.commit(); // Commit changes after archiving
                });
                t.start();
            }
            return true;
        } catch (DecoderException e) {
            throw new RuntimeException(e);
        }
    }

    public void archiveRandomDataForFarmer(PeerRegistration farmer) {
        try {
            // Fetch random replay URLs up to maxBytes
            Set<String> replayUrls = RandomCdxjReader.getRandomReplayUrlsByBytes(new BigInteger(String.valueOf(farmer.getDedicatedStorage())));
            if (replayUrls.isEmpty()) {
                log.error("No replay URLs retrieved for farmer {}", farmer.getWalletAddress());
                ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body("No archival data available");
                return;
            }

            int successCount = 0;
            int failureCount = 0;

            for (String replayUrl : replayUrls) {
                try {
                    // Fetch file content from archive
                    String fileName = replayUrl;
                    replayUrl = removeLastExtension(replayUrl);
                    String fileUrl = configuration.getArchiveBaseUrl() + replayUrl;
                    ResponseEntity<byte[]> fileResponse = restTemplate.getForEntity(fileUrl, byte[].class);
                    if (!fileResponse.getStatusCode().is2xxSuccessful() || fileResponse.getBody() == null) {
                        log.error("Failed to fetch file for replayUrl: {}", replayUrl);
                        failureCount++;
                        continue;
                    }

                    byte[] fileBytes = fileResponse.getBody();
                    // Generate normalized filename from replayUrl
                    //String normalizedFileName = URLDecoder.decode(fileName, StandardCharsets.UTF_8);
                    //normalizedFileName = Normalizer.normalize(normalizedFileName, Normalizer.Form.NFC);
                    String normalizedFileName = fileName;
                    // Store original hash
                    originalFileHashes.putIfAbsent(normalizedFileName, Hex.encodeHexString(CryptoUtils.hash256(fileBytes)));
                    db.commit(); // Commit hash to disk

                    // Add farmer to pending storers
                    synchronized (pendingStorers) {
                        pendingStorers.computeIfAbsent(normalizedFileName, k -> new ArrayList<>())
                                .add(farmer.getWalletAddress());
                        db.commit(); // Commit pending storers to disk
                    }

                    // Choose encoding based on file size
                    int fileSize = fileBytes.length;
                    ResponseEntity<String> response = fileSize < VDE_THRESHOLD
                            ? aesProcess(fileBytes, farmer, keyManager, fileName)
                            : vdeProcess(fileBytes, farmer, keyManager, fileName);

                    if (response.getStatusCode().is2xxSuccessful()) {
                        log.info("Archived file {} for farmer {}", normalizedFileName, farmer.getWalletAddress());
                        successCount++;
                    } else {
                        log.error("Failed to archive file {} for farmer {}", normalizedFileName,
                                farmer.getWalletAddress());
                        failureCount++;
                    }
                } catch (Exception e) {
                    log.error("Error archiving replayUrl {} for farmer {}", replayUrl,
                            farmer.getWalletAddress());
                    failureCount++;
                }
            }

            String result = String.format("Archived %d files successfully, %d failed for farmer %s",
                    successCount, failureCount, farmer.getWalletAddress());
            log.info(result);
            ResponseEntity.ok(result);
        } catch (SQLException e) {
            log.error("Database error while retrieving replay URLs for farmer {}: {}", farmer.getWalletAddress(), e.getMessage());
            ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Database error: " + e.getMessage());
        } catch (Exception e) {
            log.error("Error archiving random data for farmer {}: {}", farmer.getWalletAddress(), e.getMessage());
            ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error archiving data: " + e.getMessage());
        }
    }

    public static String removeLastExtension(String filename) {
        if (filename == null || filename.isEmpty()) return filename;

        int lastDotIndex = filename.lastIndexOf('.');
        if (lastDotIndex == -1) {
            return filename; // no extension found
        }

        return filename.substring(0, lastDotIndex);
    }

    public ResponseEntity<Boolean> validateAES(StorageContractSubmission storageContractSubmission) {
        try {
            StorageContract storageContract = storageContractSubmission.getContract();
            if (storageContract.getStorageType() != StorageType.AES) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(false);
            }

            byte[] hash = storageContract.getHash();
            if (!CryptoUtils.ecdsaVerify(Hex.decodeHex(storageContract.getStorerSignature()), hash,
                    Hex.decodeHex(storageContractSubmission.getStorerPublicKey())) ||
                    !CryptoUtils.ecdsaVerify(Hex.decodeHex(storageContract.getFccnSignature()), hash,
                            keyManager.getPublicKey().getEncoded())) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(false);
            }

            String normalizedFileName = Normalizer.normalize(storageContract.getFileUrl(), Normalizer.Form.NFC);
            registerStorage(storageContract, normalizedFileName);
            return ResponseEntity.ok(true);
        } catch (DecoderException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(false);
        }
    }

    private MultiValueMap<String, Object> prepareMultipartBody(byte[] fileBytes, String fileName,
                                                              StorageContract storageContract) {
        MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
        ByteArrayResource resource = new ByteArrayResource(fileBytes) {
            @Override
            public String getFilename() {
                return fileName;
            }

            @Override
            public long contentLength() {
                return fileBytes.length;
            }
        };
        body.add("ArchivalFile", resource);
        body.add("data", storageContract);
        return body;
    }

    private ResponseEntity<String> sendRequest(String url, MultiValueMap<String, Object> body) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.MULTIPART_FORM_DATA);
        HttpEntity<MultiValueMap<String, Object>> requestEntity = new HttpEntity<>(body, headers);
        return restTemplate.exchange(url, HttpMethod.POST, requestEntity, String.class);
    }
}