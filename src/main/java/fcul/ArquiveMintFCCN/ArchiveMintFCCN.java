package fcul.ArquiveMintFCCN;


import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableAsync
public class ArchiveMintFCCN {

    public static void main(String[] args) {
        SpringApplication.run(ArchiveMintFCCN.class, args);
    }

}
