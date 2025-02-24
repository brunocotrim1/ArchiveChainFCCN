package fcul.ArquiveMintFCCN.service;

import fcul.ArchiveMintUtils.Model.PeerRegistration;
import fcul.ArchiveMintUtils.Model.StorageContract;
import fcul.ArchiveMintUtils.Utils.CryptoUtils;
import fcul.ArquiveMintFCCN.configuration.Configuration;
import fcul.ArquiveMintFCCN.configuration.KeyManager;
import fcul.ArquiveMintFCCN.utils.FCCNEncoding;
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

    public String test() {
        return configuration.getStoragePath();
    }

    public static String archivalEndpoint = "/blockchain/archiveFile";
    private RestTemplate restTemplate = new RestTemplate();

    public ResponseEntity<String> archiveFile(MultipartFile file) {
        try {
            byte[] fileBytes = file.getInputStream().readAllBytes();
            String normalizedFileName = Normalizer.normalize(file.getOriginalFilename(), Normalizer.Form.NFC);

            PeerRegistration farmer = getFarmerForArchival(normalizedFileName);
            if (farmer == null) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("No farmer available for archival");
            }

            byte[] fileAESEncoded = FCCNEncoding.AESEncode(fileBytes, keyManager.getAESKey(),
                    keyManager.getHMACKey(), normalizedFileName, farmer.getWalletAddress());
            MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
            StorageContract storageContract = FCCNEncoding.getStorageContract(file.getOriginalFilename(), fileAESEncoded,
                    keyManager.getPrivateKey(), farmer.getWalletAddress());

            ByteArrayResource resource = new ByteArrayResource(fileAESEncoded) {
                @Override
                public String getFilename() {
                    return file.getOriginalFilename(); // Preserve original filename
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
            ResponseEntity<String> response = restTemplate.exchange(targetUrl, HttpMethod.POST, requestEntity, String.class);
            log.info("Response from archiving file: " + response.getBody() + " from " + farmer.getWalletAddress());
            registerStorage(normalizedFileName, farmer.getWalletAddress());
            return ResponseEntity.status(response.getStatusCode()).body(response.getBody());
        } catch (Exception e) {
            log.error("Error while archiving file", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
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


            byte[] decoded = FCCNEncoding.AESDecode(response.getBody(), keyManager.getAESKey(), keyManager.getHMACKey(),
                    fileName, farmer.getWalletAddress());
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(response.getHeaders().getContentType());
            headers.setContentLength(decoded.length);
            log.info("Downloaded file: " + fileName + " from " + farmer.getWalletAddress());
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
            String address = farmers.keySet().iterator().next();
            return farmers.get(address);
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
