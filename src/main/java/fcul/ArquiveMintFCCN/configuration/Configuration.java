package fcul.ArquiveMintFCCN.configuration;

import jakarta.annotation.PostConstruct;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

@Component
@NoArgsConstructor
@ConfigurationProperties(prefix = "app")
@Data
@Slf4j
public class Configuration {
    @PostConstruct
    public void init() {
        try{
            if(!Files.exists(Path.of(storagePath))){
                Files.createDirectories(Paths.get(storagePath));
            }
            log.info("Created Node Folder at "+storagePath);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    private String id;
    private String storagePath;
    private List<String> seedNodes;
    private String fccnMnemonic;
}
