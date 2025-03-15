package fcul.ArquiveMintFCCN.controller;

import fcul.ArchiveMintUtils.Model.PeerRegistration;
import fcul.ArchiveMintUtils.Model.StorageContract;
import fcul.ArchiveMintUtils.Model.transactions.StorageContractSubmission;
import fcul.ArquiveMintFCCN.service.StorageService;
import org.apache.commons.codec.DecoderException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

@RestController
@RequestMapping("/storage")
public class StorageController {
    @Autowired
    private StorageService storageService;

    @PostMapping(consumes = "multipart/form-data", value = "/archiveFile")
    public ResponseEntity<String> handleFileUpload(
            @RequestPart("ArchivalFile") MultipartFile file) {
        return storageService.archiveFile(file);
    }

    @PostMapping(consumes = "multipart/form-data", value = "/signVDE")
    public ResponseEntity<StorageContract> validateVDE(
            @RequestPart("ArchivalFile") MultipartFile file,
            @RequestPart("farmerPublicKey") String publicKey) throws DecoderException, IOException {
        return storageService.signVDE(file, publicKey);
    }


    @GetMapping("/retrieveFile/{filename}")
    public ResponseEntity<byte[]> downloadFile(@PathVariable String filename) {
        return storageService.downloadFile(filename);
    }

    @PostMapping("/registerFarmer")
    public boolean registerFarmer(@RequestBody PeerRegistration peer) {
        return storageService.registerFarmer(peer);
    }

    @PostMapping("/validateAES")
    public ResponseEntity<Boolean> validateAES(
            @RequestBody StorageContractSubmission storageContract) throws DecoderException, IOException {
        return storageService.validateAES(storageContract);
    }

}
