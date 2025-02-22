package fcul.ArquiveMintFCCN.controller;

import fcul.ArchiveMintUtils.Model.StorageContract;
import fcul.ArquiveMintFCCN.service.StorageService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

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

    @GetMapping("/retrieveFile")
    public ResponseEntity<byte[]> downloadFile(@RequestParam String fileUrl) {
        return storageService.downloadFile(fileUrl);
    }

}
