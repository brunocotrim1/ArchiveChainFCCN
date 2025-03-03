package fcul.ArquiveMintFCCN.service;

import fcul.ArchiveMintUtils.Model.PeerRegistration;
import fcul.ArchiveMintUtils.Model.StorageContract;
import fcul.ArchiveMintUtils.Model.StorageType;
import fcul.ArchiveMintUtils.Utils.CryptoUtils;
import fcul.ArquiveMintFCCN.configuration.Configuration;
import fcul.ArquiveMintFCCN.configuration.KeyManager;
import fcul.ArquiveMintFCCN.utils.FCCNEncoding;
import fcul.wrapper.FileEncodeProcess;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.coyote.Response;
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
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Service
@Slf4j
public class StorageService {

    @Autowired
    private Configuration configuration;
    @Autowired
    private KeyManager keyManager;

    private final ConcurrentHashMap<String, PeerRegistration> farmers = new ConcurrentHashMap<>();

    //Map that stores miners that archive a file
    private final ConcurrentHashMap<String, List<String>> storageMap = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Long> storageAcesses = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> originalFileHashes = new ConcurrentHashMap<>();

    // Map that stores fileRoot->VDEIV
    private final ConcurrentHashMap<String, String> VDEContracts = new ConcurrentHashMap<>();

    private final int VDE_TRESHOLD = 122880000; // 120MB as a lowerbound of 60s to calculate VDE

    public String test() {
        return configuration.getStoragePath();
    }

    public static String archivalEndpoint = "/blockchain/archiveFile";
    private RestTemplate restTemplate = new RestTemplate();

    public ResponseEntity<String> archiveFile(MultipartFile file) {
        try {
            byte[] fileBytes = file.getInputStream().readAllBytes();
            String normalizedFileName = Normalizer.normalize(file.getOriginalFilename(), Normalizer.Form.NFC);
            originalFileHashes.putIfAbsent(normalizedFileName, Hex.encodeHexString(CryptoUtils.hash256(fileBytes)));
            PeerRegistration farmer = getFarmerForArchival(normalizedFileName);
            if (farmer == null) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("No farmer available for archival");
            }

            int fileSize = fileBytes.length;
            ResponseEntity<String> response = null;
            if (fileSize < VDE_TRESHOLD) {
                response = AESProcess(fileBytes, farmer, keyManager, file.getOriginalFilename());
                registerStorage(normalizedFileName, farmer.getWalletAddress());
            } else {
                response = VDEProcess(fileBytes, farmer, keyManager, file.getOriginalFilename());
            }


            log.info("Response from archiving file: " + response.getBody() + " from " + farmer.getWalletAddress());
            return ResponseEntity.status(response.getStatusCode()).body(response.getBody());
        } catch (Exception e) {
            log.error("Error while archiving file", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }

    private ResponseEntity<String> VDEProcess(byte[] fileBytes, PeerRegistration farmer, KeyManager keyManager,
                                              String fileOriginalName) {
        String normalizedFileName = Normalizer.normalize(fileOriginalName, Normalizer.Form.NFC);
        MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
        ByteArrayResource resource = new ByteArrayResource(fileBytes) {
            @Override
            public String getFilename() {
                return fileOriginalName; // Preserve original filename
            }

            @Override
            public long contentLength() {
                return fileBytes.length;
            }
        };
        //Storage Contract to carry information for miner side validation but not the end contract used in the blockchain
        //Since merkle root of the encoded needs to be recalculated
        StorageContract storageContract = FCCNEncoding.getStorageContract(fileOriginalName, fileBytes,
                keyManager.getPrivateKey(), farmer.getWalletAddress(), StorageType.VDE);
        body.add("ArchivalFile", resource);
        body.add("data", storageContract);
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.MULTIPART_FORM_DATA);
        HttpEntity<MultiValueMap<String, Object>> requestEntity = new HttpEntity<>(body, headers);
        // Forward the request to another service

        String targetUrl = farmer.getNetworkAddress() + archivalEndpoint;
        return restTemplate.exchange(targetUrl, HttpMethod.POST, requestEntity, String.class);
    }

    public ResponseEntity<StorageContract> signVDE(MultipartFile file, String farmerPublicKey) throws IOException, DecoderException {
        PeerRegistration farmer = farmers.get(CryptoUtils.getWalletAddress(farmerPublicKey));
        if (farmer == null) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        }
        String normalizedFileName = Normalizer.normalize(file.getOriginalFilename(), Normalizer.Form.NFC);
        byte[] fileBytes = file.getInputStream().readAllBytes();
        if (!originalFileHashes.containsKey(normalizedFileName)) {
            System.out.println("File not pending for Storage");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        }

        if (!FileEncodeProcess.verifySLOTH(fileBytes, originalFileHashes.get(normalizedFileName), normalizedFileName,
                farmer.getWalletAddress(), 1)) {
            System.out.println("Invalide VDE Encoding");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        }


        StorageContract storageContract = FCCNEncoding.getStorageContract(file.getOriginalFilename(), fileBytes,
                keyManager.getPrivateKey(), farmer.getWalletAddress(), StorageType.VDE);
        registerStorage(normalizedFileName, farmer.getWalletAddress());
        String salt = normalizedFileName + farmer.getWalletAddress();
        byte[] iv = CryptoUtils.hash256(salt.getBytes());
        VDEContracts.putIfAbsent(Hex.encodeHexString(CryptoUtils.hash256(fileBytes)), Hex.encodeHexString(iv));
        System.out.println("VDE successfully validated and contract signaded for: " + farmer.getWalletAddress() + " for file: " + file.getOriginalFilename());
        return ResponseEntity.ok(storageContract);
    }


    private ResponseEntity<String> AESProcess(byte[] fileBytes, PeerRegistration farmer, KeyManager keyManager,
                                              String fileOriginalName) throws Exception {
        String normalizedFileName = Normalizer.normalize(fileOriginalName, Normalizer.Form.NFC);
        byte[] fileAESEncoded = FCCNEncoding.AESEncode(fileBytes, keyManager.getAESKey(),
                keyManager.getHMACKey(), normalizedFileName, farmer.getWalletAddress());
        MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
        StorageContract storageContract = FCCNEncoding.getStorageContract(fileOriginalName, fileAESEncoded,
                keyManager.getPrivateKey(), farmer.getWalletAddress(), StorageType.AES);

        ByteArrayResource resource = new ByteArrayResource(fileAESEncoded) {
            @Override
            public String getFilename() {
                return fileOriginalName; // Preserve original filename
            }

            @Override
            public long contentLength() {
                return fileAESEncoded.length;
            }
        };
        body.add("ArchivalFile", resource);
        body.add("data", storageContract);
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.MULTIPART_FORM_DATA);
        HttpEntity<MultiValueMap<String, Object>> requestEntity = new HttpEntity<>(body, headers);
        // Forward the request to another service

        String targetUrl = farmer.getNetworkAddress() + archivalEndpoint;
        return restTemplate.exchange(targetUrl, HttpMethod.POST, requestEntity, String.class);
    }


    public ResponseEntity<byte[]> downloadFile(String fileName) {
        try {
            fileName = Normalizer.normalize(fileName, Normalizer.Form.NFC);

            PeerRegistration farmer = getFarmerForRetrieval(fileName);
            if (farmer == null) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body("No farmer available for retrieval".getBytes());
            }

            String targetUrl = UriComponentsBuilder.fromHttpUrl(farmer.getNetworkAddress())
                    .path("/blockchain/download")
                    .queryParam("fileUrl", fileName)
                    .toUriString();
            ResponseEntity<byte[]> response = restTemplate.exchange(
                    targetUrl, HttpMethod.GET, null, byte[].class);

            byte[] file = response.getBody();
            String fileHash = Hex.encodeHexString(CryptoUtils.hash256(file));
            byte[] decoded;
            StorageType type = null;
            if (VDEContracts.containsKey(fileHash)) {
                String iv = VDEContracts.get(fileHash);
                decoded = FileEncodeProcess.decodeFileVDD(file, Hex.decodeHex(iv), 1);
                type = StorageType.VDE;
            } else {
                decoded = FCCNEncoding.AESDecode(file, keyManager.getAESKey(), keyManager.getHMACKey(),
                        fileName, farmer.getWalletAddress());
                type = StorageType.AES;
            }
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(response.getHeaders().getContentType());
            headers.setContentLength(decoded.length);
            log.info("Downloaded file: " + fileName + " from " + farmer.getWalletAddress() + " of type: " + type);
            return ResponseEntity
                    .status(response.getStatusCode())
                    .headers(headers)
                    .body(decoded);
        } catch (Exception e) {
            log.error("Error while downloading file", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new byte[0]);
        }
    }


    public PeerRegistration getFarmerForArchival(String fileId) {

        if (!storageMap.containsKey(fileId)) {
            try {
                String address = farmers.keySet().iterator().next();
                return farmers.get(address);
            } catch (Exception e) {
                return null;
            }
        }
        List<String> farmersArchivingFile = storageMap.get(fileId);
        Set<String> farmersSet = farmers.keySet();
        for (String farmer : farmersSet) {
            if (!farmersArchivingFile.contains(farmer)) {
                return farmers.get(farmer);
            }
        }
        return null;
    }

    public synchronized PeerRegistration getFarmerForRetrieval(String fileId) {
        if (!storageMap.containsKey(fileId)) {
            return null;
        }
        long lastAcessedFarmer = storageAcesses.get(fileId);
        List<String> farmersArchivingFile = storageMap.get(fileId);
        long newAcessId = (lastAcessedFarmer + 1) % farmersArchivingFile.size();
        storageAcesses.put(fileId, newAcessId);
        String farmerAddress = farmersArchivingFile.get((int) newAcessId);
        return farmers.containsKey(farmerAddress) ? farmers.get(farmerAddress) : null;
    }

    public synchronized void registerStorage(String fileId, String farmerAddress) {
        if (storageMap.containsKey(fileId)) {
            storageMap.get(fileId).add(farmerAddress);
            return;
        }
        List<String> farmers = new ArrayList<>();
        farmers.add(farmerAddress);
        storageMap.put(fileId, farmers);
        storageAcesses.put(fileId, 0L);
    }


    public boolean registerFarmer(PeerRegistration farmerAddress) {

        try {
            if (farmers.containsKey(farmerAddress.getWalletAddress())) {
                log.error("Farmer already registered");
                return false;
            }
            String address = CryptoUtils.getWalletAddress(farmerAddress.getPublicKey());
            String data = farmerAddress.getNetworkAddress() + address +
                    farmerAddress.getDedicatedStorage();
            if (!CryptoUtils.ecdsaVerify(Hex.decodeHex(farmerAddress.getSignature()), data.getBytes(),
                    Hex.decodeHex(farmerAddress.getPublicKey()))) {
                log.error("Invalid signature");
                return false;
            }
            farmers.put(farmerAddress.getWalletAddress(), farmerAddress);
            log.info("Farmer registered: " + farmerAddress.getWalletAddress());
        } catch (DecoderException e) {
            throw new RuntimeException(e);
        }
        return true;
    }
}
