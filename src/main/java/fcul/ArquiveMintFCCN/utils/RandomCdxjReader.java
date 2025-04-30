package fcul.ArquiveMintFCCN.utils;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;

import java.io.BufferedReader;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.*;
import java.sql.*;
import java.util.*;

class CdxjMetadata {
    public String url, mime, digest, length, offset, filename, collection;

    public String getReplayUrl(String timestamp) {
        return timestamp + "/" + url;
    }

    @Override
    public String toString() {
        return "URL: " + url + "\nMIME: " + mime + "\nFilename: " + filename + "\nCollection: " + collection;
    }
}

public class RandomCdxjReader {
    private static final Gson gson = new Gson();
    private static final Path CDXJ_FOLDER = Paths.get("fccn/files");
    private static final Path DB_PATH = CDXJ_FOLDER.resolve("archive.db");
    private static final Random random = new Random();
    private static final int BATCH_SIZE = 100_000; // Batch size for database inserts
    private static final Map<String, String> MIME_EXTENSION_MAP = new HashMap<>();

    static {
        MIME_EXTENSION_MAP.put("application/pdf", ".pdf");
        MIME_EXTENSION_MAP.put("image/jpeg", ".jpg");
        MIME_EXTENSION_MAP.put("image/png", ".png");
        MIME_EXTENSION_MAP.put("image/gif", ".gif");
        MIME_EXTENSION_MAP.put("text/html", ".html");
        MIME_EXTENSION_MAP.put("text/plain", ".txt");
        MIME_EXTENSION_MAP.put("application/json", ".json");
        MIME_EXTENSION_MAP.put("application/xml", ".xml");
    }
    private static Connection getDbConnection() throws SQLException {
        try {
            Class.forName("org.sqlite.JDBC"); // Ensure driver is loaded
            Connection conn = DriverManager.getConnection("jdbc:sqlite:" + DB_PATH);
            conn.setAutoCommit(true); // Default to auto-commit
            return conn;
        } catch (ClassNotFoundException e) {
            System.err.println("SQLite JDBC driver not found in classpath: " + e.getMessage());
            throw new SQLException("No SQLite JDBC driver available", e);
        } catch (SQLException e) {
            System.err.println("Failed to connect to database at " + DB_PATH + ": " + (e.getMessage() != null ? e.getMessage() : "Unknown database error"));
            throw e;
        }
    }

    public static Set<String> getRandomReplayUrlsByBytes(BigInteger maxBytes) throws SQLException {
        Set<String> results = new HashSet<>();
        BigInteger[] totalBytes = {BigInteger.ZERO};
        long count = 0;

        try (Connection conn = getDbConnection();
             PreparedStatement pstmt = conn.prepareStatement(
                     "SELECT replayUrl, filesize FROM records ORDER BY RANDOM()")) {
            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next() && totalBytes[0].compareTo(maxBytes) < 0) {
                    String replayUrl = rs.getString("replayUrl");
                    BigInteger filesize = new BigInteger(rs.getString("filesize"));
                    totalBytes[0] = totalBytes[0].add(filesize);
                    results.add(replayUrl);
                    count++;
                }
            } catch (SQLException e) {
                System.err.println("Error reading random records: " + (e.getMessage() != null ? e.getMessage() : "Unknown database error"));
                throw e;
            }
        } catch (SQLException e) {
            System.err.println("Error querying database: " + (e.getMessage() != null ? e.getMessage() : "Unknown database error"));
            throw e;
        }

        System.out.println("Total bytes selected: " + totalBytes[0] + ", records selected: " + count);
        return results;
    }

    public static void convertCdxjToReplayUrls(Path inputPath, Path outputPath) throws IOException, SQLException {
        String fileName = inputPath.getFileName().toString();
        List<Object[]> batch = new ArrayList<>();
        long currentLine = 0;
        long validRecords = 0;

        try (BufferedReader reader = Files.newBufferedReader(inputPath)) {
            String line;
            while ((line = reader.readLine()) != null) {
                currentLine++;
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                String[] parts = line.split(" ", 3);
                if (parts.length < 3) {
                    System.err.println("Invalid line format at line " + currentLine + " in " + fileName + ": " + line);
                    continue;
                }
                try {
                    CdxjMetadata metadata = gson.fromJson(parts[2], CdxjMetadata.class);
                    if (metadata.url != null && metadata.length != null ) {
                        if (!MIME_EXTENSION_MAP.containsKey(metadata.mime)) {
                            continue;
                        } else {
                        }
                        BigInteger length = new BigInteger(metadata.length);
                        batch.add(new Object[]{metadata.getReplayUrl(parts[1]), length.toString()});
                        validRecords++;
                        if (batch.size() >= BATCH_SIZE) {
                            insertBatch(batch);
                            batch.clear();
                        }
                    } else {
                        System.err.println("Missing url or length at line " + currentLine + " in " + fileName + ": " + line);
                    }
                } catch (JsonSyntaxException e) {
                    System.err.println("JSON parsing error at line " + currentLine + " in " + fileName + ": " + line + ", error: " + e.getMessage());
                } catch (NumberFormatException e) {
                    System.err.println("Invalid filesize format at line " + currentLine + " in " + fileName + ": " + line + ", error: " + e.getMessage());
                } catch (Exception e) {
                    System.err.println("Unexpected error at line " + currentLine + " in " + fileName + ": " + line + ", error: " + e.getMessage());
                }
            }
        } catch (IOException e) {
            System.err.println("Error reading input file " + fileName + ": " + (e.getMessage() != null ? e.getMessage() : "Unknown I/O error"));
            throw e;
        }

        if (!batch.isEmpty()) {
            insertBatch(batch);
        }

        System.out.println("Processed: " + fileName + " -> " + validRecords + " records");
    }
    private static String getFileExtension(String url) {
        if (url == null || url.isEmpty()) {
            return null; // Handle null or empty URL
        }

        // Find the last slash to isolate the file name
        int lastSlashIndex = url.lastIndexOf('/');
        String fileName = lastSlashIndex != -1 ? url.substring(lastSlashIndex + 1) : url;

        // Find the query parameter start (if any)
        int queryIndex = fileName.indexOf('?');
        String baseName = queryIndex != -1 ? fileName.substring(0, queryIndex) : fileName;
        String queryParams = queryIndex != -1 ? fileName.substring(queryIndex) : "";

        // Find the last dot in the base name (before query parameters)
        int lastDotIndex = baseName.lastIndexOf('.');
        if (lastDotIndex != -1 && lastDotIndex < baseName.length() - 1) {
            String extension = baseName.substring(lastDotIndex + 1).toLowerCase();
            // If there are query parameters, append the extension at the end
            if (!queryParams.isEmpty()) {
                return fileName + "." + extension;
            }
            return extension; // Return just the extension if no query parameters
        }

        return null; // No extension found
    }
    public static void convertSpecificCdxjFile(String fileName) throws IOException, SQLException {
        if (fileName == null || !fileName.toLowerCase().endsWith(".cdxj")) {
            throw new IOException("Invalid file name: " + fileName + ". Must be a .cdxj file.");
        }

        Path inputPath = CDXJ_FOLDER.resolve(fileName);
        if (!Files.exists(inputPath) || !Files.isRegularFile(inputPath)) {
            throw new IOException("File does not exist or is not a regular file: " + inputPath);
        }
        convertCdxjToReplayUrls(inputPath, CDXJ_FOLDER.resolve(fileName));
    }

    public static void initializeDatabaseIfNotExists() throws SQLException {
        //Delete old database if it exists
        if (Files.exists(DB_PATH)) {
            try {
                Files.delete(DB_PATH);
            } catch (IOException e) {
                System.err.println("Failed to delete old database file: " + e.getMessage());
            }
        }

        try (Connection conn = getDbConnection();
             Statement stmt = conn.createStatement()) {
            // Check if records table exists
            ResultSet rs = stmt.executeQuery("SELECT name FROM sqlite_master WHERE type='table' AND name='records'");
            if (!rs.next()) {
                // Table doesn't exist, create it
                stmt.execute("CREATE TABLE records (" +
                        "replayUrl TEXT PRIMARY KEY, " +
                        "filesize BIGINT NOT NULL)");
            }
            // Drop old files table if it exists (for backward compatibility)
            stmt.execute("DROP TABLE IF EXISTS files");
        } catch (SQLException e) {
            System.err.println("Error checking or initializing database at " + DB_PATH + ": " + (e.getMessage() != null ? e.getMessage() : "Unknown database error"));
            throw e;
        }
    }

    private static void insertBatch(List<Object[]> batch) throws SQLException {
        try (Connection conn = getDbConnection();
             PreparedStatement pstmt = conn.prepareStatement(
                     "INSERT OR IGNORE INTO records (replayUrl, filesize) VALUES (?, ?)")) {
            conn.setAutoCommit(false);
            int skipped = 0;
            for (Object[] record : batch) {
                pstmt.setString(1, (String) record[0]);
                pstmt.setString(2, (String) record[1]);
                pstmt.addBatch();
            }
            int[] results = pstmt.executeBatch();
            conn.commit();
            // Count skipped records (duplicates)
            for (int result : results) {
                if (result == 0) {
                    skipped++;
                }
            }
            if (skipped > 0) {
                System.out.println("Skipped " + skipped + " duplicate replayUrl records");
            }
        } catch (SQLException e) {
            System.err.println("Error inserting batch into database: " + (e.getMessage() != null ? e.getMessage() : "Unknown database error"));
            throw e;
        }
    }

    public static void convertCDXJFolder(Path inputPath, Path outputPath) {
        try {
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(inputPath, "*.cdxj")) {
                for (Path cdxjFile : stream) {
                    convertCdxjToReplayUrls(cdxjFile, outputPath.resolve(cdxjFile.getFileName()));
                }
            }
        } catch (IOException e) {
            System.err.println("Error processing CDXJ folder: " + (e.getMessage() != null ? e.getMessage() : "Unknown I/O error"));
        } catch (SQLException e) {
            System.err.println("Error initializing database: " + (e.getMessage() != null ? e.getMessage() : "Unknown database error"));
        }
    }

    public static void main(String[] args) {
        try {
            convertSpecificCdxjFile("BN.cdxj");
            convertCDXJFolder(CDXJ_FOLDER, CDXJ_FOLDER);
            // Example of using convertSpecificCdxjFile
            convertSpecificCdxjFile("BN.cdxj");
            //convertSpecificCdxjFile("RAQ2019.cdxj");
            BigInteger sixtyGigabytes = new BigInteger("60000000000"); // 60GB
            Set<String> randomUrls = getRandomReplayUrlsByBytes(sixtyGigabytes);
            //randomUrls.forEach(url -> System.out.println("Replay URL: " + url));
            System.out.println("Total URLs read: " + randomUrls.size());
        } catch (SQLException e) {
            System.err.println("Error in main: " + (e.getMessage() != null ? e.getMessage() : "Unknown database error"));
            e.printStackTrace();
        } catch (Exception e) {
            System.err.println("Error processing specific file: " + (e.getMessage() != null ? e.getMessage() : "Unknown I/O error"));
            e.printStackTrace();
        }
    }
}