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
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Collectors;

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


    @GetMapping("/retrieveFile")
    public ResponseEntity<byte[]> downloadFile(@RequestParam String filename) {
        //filename = URLDecoder.decode(filename, StandardCharsets.UTF_8);
        return storageService.downloadFile(filename);
    }

    @PostMapping("/registerFarmer")
    public boolean registerFarmer(@RequestBody PeerRegistration peer) {
        return storageService.registerFarmer(peer);
    }

    @PostMapping("/requestMoreFiles")
    public ResponseEntity<Boolean> requestMoreFiles(@RequestBody PeerRegistration peer) {
        return storageService.requestMoreFiles(peer);
    }

    @PostMapping("/validateAES")
    public ResponseEntity<Boolean> validateAES(
            @RequestBody StorageContractSubmission storageContract) throws DecoderException, IOException {
        return storageService.validateAES(storageContract);
    }

    @GetMapping("/amountOfContracts")
    public ResponseEntity<Long> getAmountOfContracts() {
        List<List<StorageContract>> contracts = storageService.getStorageContracts().values().stream().toList();
        long total = 0;
        for (List<StorageContract> contractList : contracts) {
            total += contractList.size();
        }
        return ResponseEntity.ok(total);
    }

    @GetMapping("getRegisteredFarmers")
    public ResponseEntity<List<PeerRegistration>> getRegisteredFarmers() {
        return ResponseEntity.ok(storageService.getFarmers().values().stream().collect(Collectors.toList()));
    }

    @DeleteMapping("/deleteFarmerAddress")
    public ResponseEntity<String> deleteFarmerAddress(@RequestParam String farmerAddress) {
        return storageService.deleteFarmerAddress(farmerAddress);
    }
}


