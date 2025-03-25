package fcul.ArquiveMintFCCN.service;

import fcul.ArchiveMintUtils.Model.PeerRegistration;
import fcul.ArchiveMintUtils.Model.StorageContract;
import fcul.ArchiveMintUtils.Model.StorageType;
import fcul.ArchiveMintUtils.Model.transactions.StorageContractSubmission;
import fcul.ArchiveMintUtils.Utils.CryptoUtils;
import fcul.ArquiveMintFCCN.configuration.Configuration;
import fcul.ArquiveMintFCCN.configuration.KeyManager;
import fcul.ArquiveMintFCCN.utils.FCCNEncoding;
import fcul.wrapper.FileEncodeProcess;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
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
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

@Service
@Slf4j
public class StorageService {

    @Autowired
    private Configuration configuration;
    @Autowired
    private KeyManager keyManager;

    private final ConcurrentHashMap<String, PeerRegistration> farmers = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Long> storageAccesses = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, List<StorageContract>> storageContracts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, List<String>> pendingStorers = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> originalFileHashes = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> vdeContracts = new ConcurrentHashMap<>();

    private static final int VDE_THRESHOLD = 1024 * 1024; //1 MB ThresHold for testing
    private static final String ARCHIVAL_ENDPOINT = "/blockchain/archiveFile";
    private final RestTemplate restTemplate = new RestTemplate();

    public String test() {
        return configuration.getStoragePath();
    }

    public ResponseEntity<String> archiveFile(MultipartFile file) {
        try {
            byte[] fileBytes = file.getInputStream().readAllBytes();
            String normalizedFileName = Normalizer.normalize(file.getOriginalFilename(), Normalizer.Form.NFC);
            originalFileHashes.putIfAbsent(normalizedFileName, Hex.encodeHexString(CryptoUtils.hash256(fileBytes)));

            PeerRegistration farmer;
            synchronized (pendingStorers) {  // Synchronize to prevent race condition
                farmer = getFarmerForArchival(normalizedFileName);
                if (farmer == null) {
                    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                            .body("No farmer available for archival");
                }
                pendingStorers.computeIfAbsent(normalizedFileName, k -> new ArrayList<>())
                        .add(farmer.getWalletAddress());
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

        String farmerAddress = farmerAddresses.get((int) newAccessId);
        return farmers.get(farmerAddress);
    }

    public void registerStorage(StorageContract storageContract, String normalizedFileName) {
        synchronized (pendingStorers) {  // Synchronize to ensure pending removal is atomic with contract addition
            storageContracts.computeIfAbsent(normalizedFileName, k -> new ArrayList<>())
                    .add(storageContract);
            storageAccesses.putIfAbsent(normalizedFileName, 0L);

            List<String> pending = pendingStorers.get(normalizedFileName);
            if (pending != null) {
                pending.remove(storageContract.getStorerAddress());
            }
        }

        log.info("Storage contract registered: {} from {} of type: {}",
                storageContract.getFileUrl(), storageContract.getStorerAddress(),
                storageContract.getStorageType());
    }

    public boolean registerFarmer(PeerRegistration farmerAddress) {
        try {
            if (farmers.containsKey(farmerAddress.getWalletAddress())) {
                log.error("Farmer already registered");
                return false;
            }

            String address = CryptoUtils.getWalletAddress(farmerAddress.getPublicKey());
            String data = farmerAddress.getNetworkAddress() + address + farmerAddress.getDedicatedStorage();

            if (!CryptoUtils.ecdsaVerify(Hex.decodeHex(farmerAddress.getSignature()), data.getBytes(),
                    Hex.decodeHex(farmerAddress.getPublicKey()))) {
                log.error("Invalid signature");
                return false;
            }

            farmers.put(farmerAddress.getWalletAddress(), farmerAddress);
            log.info("Farmer registered: {}", farmerAddress.getWalletAddress());
            return true;
        } catch (DecoderException e) {
            throw new RuntimeException(e);
        }
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