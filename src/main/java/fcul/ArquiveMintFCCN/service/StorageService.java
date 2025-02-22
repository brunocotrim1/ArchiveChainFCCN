package fcul.ArquiveMintFCCN.service;

import fcul.ArchiveMintUtils.Model.StorageContract;
import fcul.ArchiveMintUtils.Utils.AESEncode;
import fcul.ArchiveMintUtils.Utils.CryptoUtils;
import fcul.ArchiveMintUtils.Utils.PoDp;
import fcul.ArchiveMintUtils.Utils.Utils;
import fcul.ArquiveMintFCCN.configuration.Configuration;
import fcul.ArquiveMintFCCN.configuration.KeyManager;
import io.swagger.v3.oas.models.headers.Header;
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

import java.math.BigInteger;
import java.security.PrivateKey;

@Service
public class StorageService {

    @Autowired
    private Configuration configuration;
    @Autowired
    private KeyManager keyManager;

    public String test() {
        return configuration.getStoragePath();
    }

    public static String archivalEndpoint = "/blockchain/archiveFile";
    private RestTemplate restTemplate = new RestTemplate();

    public ResponseEntity<String> archiveFile(MultipartFile file) {
        try {
            byte[] fileBytes = file.getInputStream().readAllBytes();
            byte[] fileName = file.getOriginalFilename().getBytes();
            byte[] fileAESEncoded = AESEncode.encrypt(fileBytes, keyManager.getAESKey(),
                    keyManager.getHMACKey(), CryptoUtils.getTruncatedHASHIV(fileName));

            MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
            StorageContract storageContract = getStorageContract(file.getOriginalFilename(), fileAESEncoded,
                    keyManager.getPrivateKey(), "e1c94c37ac886f5aeb7433c3bc4a5d088c7fc4ed1b69fe0d092c7a67e3d99897");

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
            String targetUrl = configuration.getSeedNodes().get(0) + archivalEndpoint; // Replace with actual endpoint
            ResponseEntity<String> response = restTemplate.exchange(targetUrl, HttpMethod.POST, requestEntity, String.class);

            return ResponseEntity.status(response.getStatusCode()).body(response.getBody());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public ResponseEntity<byte[]> downloadFile(String fileName) {
        try {
            String targetUrl = UriComponentsBuilder.fromHttpUrl(configuration.getSeedNodes().get(0))
                    .path("/blockchain/download")
                    .queryParam("fileUrl", fileName)
                    .toUriString();
            ResponseEntity<byte[]> response = restTemplate.exchange(
                    targetUrl, HttpMethod.GET, null, byte[].class);
            byte[] decoded = AESEncode.decrypt(response.getBody(), keyManager.getAESKey(),
                    keyManager.getHMACKey(), CryptoUtils.getTruncatedHASHIV(fileName.getBytes()));
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(response.getHeaders().getContentType());
            headers.setContentLength(decoded.length);
            // Forward response with headers and status code
            System.out.println("Type: " + response.getHeaders().getContentType());
            return ResponseEntity
                    .status(response.getStatusCode())
                    .headers(headers)
                    .body(decoded);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static StorageContract getStorageContract(String url, byte[] data, PrivateKey privateKey, String storerAddress) {
        byte[] merkleRoot = PoDp.merkleRootFromData(data);
        String merkleRootHex = Hex.encodeHexString(merkleRoot);
        StorageContract contract = StorageContract.builder()
                .merkleRoot(merkleRootHex)
                .value(BigInteger.valueOf(25))
                .fileUrl(url)
                .timestamp(BigInteger.valueOf(System.currentTimeMillis()))
                .storerAddress(storerAddress)
                .build();
        contract.setFccnSignature(Hex.encodeHexString(CryptoUtils.ecdsaSign(contract.getHash(), privateKey)));
        return contract;
    }
}
