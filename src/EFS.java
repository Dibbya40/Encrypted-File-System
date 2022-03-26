/**
 * @author Albert Jean, Dibbya Saha, Manasa Bhat

 */
import java.io.File;
import java.nio.ByteBuffer;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
public class EFS extends Utility{
    
	public class MetaData {

	    // Global constants that our implementation follows.
	    // can be changed to fit potential future modifications:

	    // Disk block size is 1024 bytes:
	    private static final int DISK_BLOCK_SIZE = 1024;

	    private static final int USERNAME_PASSWORD_MAX_LENGTH = 128;
	    private static final int PASSWORD_SALT_SIZE = 64;
	    private static final int METADATA_HASH_OUTPUT_SIZE = 64;

	    // AES key size is 16 bytes and so is the block size:
	    private static final int AES_BLOCK_SIZE = 16;
	    private static final int AES_KEY_SIZE = 16;

	    private static final int MAX_FILE_BYTES = 64;

	    private static final int IV_SIZE = 16;

	    //private static final BigInteger MAXIMUM_KEY_MOD = new BigInteger("170141183460469231731687303715884105727");

	    public static final int NON_ENCRYPTED_DATA_BUFFER_SIZE = 208;
	    public static final int ENCRYPTED_DATA_BUFFER_SIZE = 216+64+16;

	    public static final int RANDOM_PADDING_SIZE = DISK_BLOCK_SIZE - (NON_ENCRYPTED_DATA_BUFFER_SIZE + ENCRYPTED_DATA_BUFFER_SIZE);

	    // Metadata fields (They are in order of how they should appear within the file (Total size = 208)
	    // 128-byte username and password:
	    private byte[] username;

	    // 64-byte password salt size:
	    private byte[] passwordSalt;

	    // 16-byte metadata IV:
	    private byte[] metaDataIV;

	    // ** ENCRYPTED FIELDS START HERE: ** (Total size of this section in bytes is: (216 bytes)
	    // Hashed (username || password || salt) (64 bytes):
	    private byte[] hashedUserPassSalt;

	    // The total length of data (in bytes):
	    private byte[] totalLengthOfData;

	    // How many blocks (# of data files) we have stored as a long (8 bytes):
	    private long totalDataBlocks;

	    // Starting IV for CTR mode (16 bytes):
	    private byte[] startingIV;

	    // Starting key used for encrypting / decrypting the data blocks:
	    private byte[] startingDataKey;

	    // Hash of ALL the data blocks (64-bytes):
	    private byte[] allDataHash;

	    // Hash of all the fields within the metadata (64-bytes):
	    private byte[] metaDataHash;

	    // The spare space is how much padding we need to add at the end of the file:
	    private byte[] randomPadding;

	    // End metadata fields

	    // Encryption related fields, NOT stored in the metadata file:
	    // This is the starting number for the metadata encryption (16 bytes):
	    private byte[] password;
	    private byte[] startingMetaDataKey;

	    // Constructor to create a new metadata file:
	    public MetaData(byte[] username, byte[] password) throws Exception {

	        // Convert and pad the usernames and passwords to the max length:
	        this.username = padByteArray(USERNAME_PASSWORD_MAX_LENGTH, username);
	        this.password = padByteArray(USERNAME_PASSWORD_MAX_LENGTH, password);

	        if(this.username == null || this.password == null) {
	            throw new Exception("Username or password has a length that exceeds the maximum size: " + USERNAME_PASSWORD_MAX_LENGTH);
	        }

	        // This is a new file, so we don't have any data blocks yet:
	        this.totalDataBlocks = 0;
	        this.totalLengthOfData = new byte[MAX_FILE_BYTES];

	        // We will calculate the integrity hashes later. For now, just allocate:
	        this.allDataHash = new byte[METADATA_HASH_OUTPUT_SIZE];

	        generateRandomCredentials();

	    }

	    // Constructor to load pre-existing metadata file by file path:
	    public MetaData(File file, byte[] password) throws Exception {

	        this.password = padByteArray(USERNAME_PASSWORD_MAX_LENGTH, password);

	        ByteBuffer fileData = ByteBuffer.wrap( read_from_file(file));

	        if(fileData.capacity() != DISK_BLOCK_SIZE) {
	            throw new Exception("Metadata file is the incorrect size.");
	        }

	        // Read in the username:
	        this.username = new byte[USERNAME_PASSWORD_MAX_LENGTH];
	        fileData.get(this.username);

	        // Read in the password salt:
	        this.passwordSalt = new byte[PASSWORD_SALT_SIZE];
	        fileData.get(this.passwordSalt);

	        // Read in the meta data IV:
	        this.metaDataIV = new byte[IV_SIZE];
	        fileData.get(this.metaDataIV);

	        // The remaining data in the buffer is encrypted:
	        byte[] encryptedData = new byte[fileData.remaining()];
	        fileData.get(encryptedData);

	        // Take the password and derive a starting 128-bit key (just for the metadata):
	        this.startingMetaDataKey = deriveAESKeyFromPassword(this.password);

	        // Restore the remaining encrypted data:
	        restoreDecryptedData(encryptedData);

	    }

	    private void generateRandomCredentials() throws Exception {

	        // Securely randomly generate a new password salt & meta data starting IV:
	        this.passwordSalt =  secureRandomNumber(PASSWORD_SALT_SIZE);
	        this.metaDataIV =  secureRandomNumber(IV_SIZE);

	        // This integrity hash = HASH512(username || password || salt):
	        this.hashedUserPassSalt = calculateHashedUserPassSalt();

	        // Securely randomly generate a random starting counter IV:
	        this.startingIV =  secureRandomNumber(IV_SIZE);
	        this.startingDataKey =  secureRandomNumber(AES_KEY_SIZE);

	        // Take the password and derive a starting 128-bit key (just for the metadata):
	        this.startingMetaDataKey = deriveAESKeyFromPassword(this.password);

	        this.randomPadding =  secureRandomNumber(RANDOM_PADDING_SIZE);

	        // Calculate the metadata hash:
	        this.metaDataHash = calculateMetaDataHash();
	    }

	    private byte[] calculateHashedUserPassSalt() throws Exception {
	        return  hash_SHA512(concatenateArrays(this.password, this.passwordSalt));
	    }

	    public String getUsername() {
	        return convertNullTerminatedString(this.username);
	    }

	    public byte[] getRawUsername() {
	        return this.username;
	    }

	    public byte[] getPassword() {
	        return this.password;
	    }

	    public byte[] getPasswordSalt() {
	        return this.passwordSalt;
	    }

	    public byte[] getStartingDataKey() {
	        return this.startingDataKey;
	    }

	    public void setStartingDataKey(byte[] startingDataKey) {
	        this.startingDataKey = startingDataKey;
	    }

	    public byte[] getMetaDataIV() {
	        return this.metaDataIV;
	    }

	    public byte[] getHashedUserPassSalt() {
	        return this.hashedUserPassSalt;
	    }

	    public BigInteger getFileLength() {
	        return new BigInteger(this.totalLengthOfData);
	    }

	    public void setFileLength(BigInteger length) {

	        // Reset our total length array:
	        Arrays.fill(this.totalLengthOfData, (byte) 0x00);
	        byte[] lengthBytes = length.toByteArray();

	        // Start copying into truncate from this index:
	        int copyFrom = this.totalLengthOfData.length - lengthBytes.length;

	        // lengthBytes is longer than truncate:
	        if(copyFrom < 0) {
	            copyFrom = 0;
	        }

	        // Copy over all the data until you hit the limit:
	        for(int x=copyFrom; x<this.totalLengthOfData.length; x++) {
	            this.totalLengthOfData[x] = lengthBytes[x - copyFrom];
	        }

	    }

	    public long getTotalDataBlocks() {
	        return this.totalDataBlocks;
	    }

	    public void setTotalDataBlocks(long totalDataBlocks) {
	        this.totalDataBlocks = totalDataBlocks;
	    }

	    public byte[] getStartingIV() {
	        return this.startingIV;
	    }

	    public void setAllDataHash(byte[] allDataHash) {
	        this.allDataHash = allDataHash;
	    }

	    public byte[] getAllDataHash() {
	        return this.allDataHash;
	    }

	    public byte[] getMetaDataHash() {
	        return this.metaDataHash;
	    }

	    // Change the username, which will only recalculate the hash
	    // for username || password || salt && the final meta data hash.
	    public void setUsername(byte[] username) throws Exception {

	        if(username != null) {
	            this.username = padByteArray(USERNAME_PASSWORD_MAX_LENGTH, username);
	            this.hashedUserPassSalt = calculateHashedUserPassSalt();
	        }

	        if(this.username == null) {
	            throw new Exception("Username has a length that exceeds the maximum size: " + USERNAME_PASSWORD_MAX_LENGTH);
	        }

	    }

	    // Change the password of the file.
	    // Note that changing the password will reset all IVs and encryption
	    // will have to be re-done on everything.
	    public void setPassword(byte[] password) throws Exception {

	        if(password != null) {
	            this.password = padByteArray(USERNAME_PASSWORD_MAX_LENGTH, password);
	            generateRandomCredentials();
	        }

	        if(this.password == null) {
	            throw new Exception("Password has a length that exceeds the maximum size: " + USERNAME_PASSWORD_MAX_LENGTH);
	        }

	    }

	    // Returns true if the password is correct, false otherwise:
	    public boolean isPasswordCorrect() throws Exception {
	        return Arrays.equals(this.hashedUserPassSalt, calculateHashedUserPassSalt());
	    }

	    // Verify that none of the metadata fields have been tampered with.
	    // Return true if the data is intact, false otherwise.
	    public boolean isMetaDataIntact() throws Exception {
	        return Arrays.equals(calculateMetaDataHash(), this.metaDataHash);
	    }

	    // Save the metadata to a file:
	    public void saveFile(File file) throws Exception {
	         save_to_file(concatenateArrays(username, passwordSalt, metaDataIV, getEncryptedData()), file);
	    }

	    private byte[] calculateMetaDataHash() throws Exception {
	        ByteBuffer metaDataFields = ByteBuffer.allocate(
	                NON_ENCRYPTED_DATA_BUFFER_SIZE + ENCRYPTED_DATA_BUFFER_SIZE + USERNAME_PASSWORD_MAX_LENGTH + RANDOM_PADDING_SIZE - METADATA_HASH_OUTPUT_SIZE);

	        metaDataFields
	                .put(this.username)
	                .put(this.passwordSalt)
	                .put(this.metaDataIV)
	                .put(this.hashedUserPassSalt)
	                .put(this.totalLengthOfData)
	                .putLong(this.totalDataBlocks)
	                .put(this.startingIV)
	                .put(this.startingDataKey)
	                .put(this.allDataHash)
	                .put(this.randomPadding)
	                .put(this.password);

	        return  hash_SHA512(metaDataFields.array());
	    }

	    // Given a byte array of encrypted data, restore all encrypted fields to this object:
	    private void restoreDecryptedData(byte[] encryptedData) throws Exception {

	        // Allocate space the size of the encrypted data:
	        ByteBuffer decryptedResult = ByteBuffer.allocate(encryptedData.length);

	        // Iterate block by block:
	        BigInteger blockKeyOffset = new BigInteger(startingMetaDataKey);
	        BigInteger metaDataIVOffset = new BigInteger(metaDataIV);
	        for(int blockCounter=0; blockCounter<encryptedData.length; blockCounter+=AES_BLOCK_SIZE) {

	            // The upper bound that should be copied:
	            int maxCopyIndex = blockCounter;

	            // Encrypt an entire block and put it into the encrypted result buffer:
	            while(maxCopyIndex<encryptedData.length && maxCopyIndex<(blockCounter + AES_BLOCK_SIZE)) {
	                maxCopyIndex++;
	            }

	            // Slice the array from the blockCounter to the maxCopyIndex (non-inclusive):
	            byte[] slicedArray = Arrays.copyOfRange(encryptedData, blockCounter, maxCopyIndex);

	            // Put the encrypted result in the encrypted buffer:
	            byte[] encryptedIV =  encript_AES(metaDataIVOffset.toByteArray(), blockKeyOffset.toByteArray());
	            decryptedResult.put(XOR(slicedArray, encryptedIV));

	            // Increment the password key:
	            blockKeyOffset = blockKeyOffset.add(BigInteger.ONE).mod(MAXIMUM_KEY_MOD);
	            metaDataIVOffset = metaDataIVOffset.add(BigInteger.ONE).mod(MAXIMUM_KEY_MOD);

	        }

	        // Prepare to extract data:
	        decryptedResult.flip();

	        // Load the integrity hash = HASH512(username || password || salt):
	        this.hashedUserPassSalt = new byte[64];
	        decryptedResult.get(this.hashedUserPassSalt);

	        // Load the data size:
	        this.totalLengthOfData = new byte[MAX_FILE_BYTES];
	        decryptedResult.get(this.totalLengthOfData);

	        // Load the total data blocks:
	        this.totalDataBlocks = decryptedResult.getLong();

	        // Load the random starting counter IV:
	        this.startingIV = new byte[IV_SIZE];
	        decryptedResult.get(this.startingIV);

	        this.startingDataKey = new byte[AES_KEY_SIZE];
	        decryptedResult.get(this.startingDataKey);

	        // Restore the integrity hash information:
	        this.allDataHash = new byte[METADATA_HASH_OUTPUT_SIZE];
	        decryptedResult.get(this.allDataHash);

	        this.metaDataHash = new byte[METADATA_HASH_OUTPUT_SIZE];
	        decryptedResult.get(this.metaDataHash);

	        this.randomPadding = new byte[RANDOM_PADDING_SIZE];
	        decryptedResult.get(randomPadding);
	    }

	    // Get the encrypted data portion of the file only:
	    private byte[] getEncryptedData() throws Exception {

	        // Allocate space the size of the encrypted data:
	        ByteBuffer toBeEncryptedBuffer = ByteBuffer.allocate(ENCRYPTED_DATA_BUFFER_SIZE + RANDOM_PADDING_SIZE);
	        ByteBuffer encryptedResult = ByteBuffer.allocate(ENCRYPTED_DATA_BUFFER_SIZE + RANDOM_PADDING_SIZE);

	        // Add all the fields in that need to be encrypted:
	        toBeEncryptedBuffer
	                .put(this.hashedUserPassSalt)
	                .put(this.totalLengthOfData)
	                .putLong(this.totalDataBlocks)
	                .put(this.startingIV)
	                .put(this.startingDataKey)
	                .put(this.allDataHash);

	        // Integrity check for all fields within the metadata file:
	        this.metaDataHash = calculateMetaDataHash();

	        // Put the integrity hash into the buffer, as it will be encrypted:
	        toBeEncryptedBuffer.put(this.metaDataHash);

	        // Add the random number padding at the end:
	        toBeEncryptedBuffer.put(this.randomPadding);

	        byte[] toBeEncrypted = toBeEncryptedBuffer.array();

	        // Iterate block by block:
	        BigInteger blockKeyOffset = new BigInteger(startingMetaDataKey);
	        BigInteger metaDataIVOffset = new BigInteger(metaDataIV);
	        for(int blockCounter=0; blockCounter<toBeEncrypted.length; blockCounter+=AES_BLOCK_SIZE) {

	            // The upper bound that should be copied:
	            int maxCopyIndex = blockCounter;

	            // Encrypt an entire block and put it into the encrypted result buffer:
	            while(maxCopyIndex<toBeEncrypted.length && maxCopyIndex<(blockCounter + AES_BLOCK_SIZE)) {
	                maxCopyIndex++;
	            }

	            // Slice the array from the blockCounter to the maxCopyIndex (non-inclusive):
	            byte[] slicedArray = Arrays.copyOfRange(toBeEncrypted, blockCounter, maxCopyIndex);

	            // Put the encrypted result in the encrypted buffer:   slicedArray
	            byte[] encryptedIV =  encript_AES(metaDataIVOffset.toByteArray(), blockKeyOffset.toByteArray());
	            encryptedResult.put(XOR(slicedArray, encryptedIV));

	            // Increment the password key:
	            blockKeyOffset = blockKeyOffset.add(BigInteger.ONE).mod(MAXIMUM_KEY_MOD);
	            metaDataIVOffset = metaDataIVOffset.add(BigInteger.ONE).mod(MAXIMUM_KEY_MOD);

	        }

	        return encryptedResult.array();
	    }

	    // Given an array "inputArray", pad it with null terminators (0) until it is "paddedSize" length.
	    // Returns null if the length of the input array is greater than the padded size.
	    private byte[] padByteArray(int paddedSize, byte[] inputArray) {

	        // The given array to be padded cannot exceed the size of the padded array:
	        if(inputArray.length > paddedSize) {
	            return null;
	        }

	        // Allocate new padded array with 0s:
	        byte[] paddedArray = new byte[paddedSize];
	        // Fill it with the null terminator:
	        Arrays.fill(paddedArray, (byte) 0x00);

	        // Copy over the original array contents:
	        System.arraycopy(inputArray, 0, paddedArray, 0, inputArray.length);

	        return paddedArray;
	    }

	    // Given a UTF-8 encoded byte string, convert it to a String object.
	    // Only the portions up to the null-terminator (ASCII 0) will be converted.
	    private String convertNullTerminatedString(byte[] utf8ByteString) {

	        int convertUpTo = -1;

	        // Find the index of the null terminator:
	        for(int x=0; x<utf8ByteString.length; x++) {
	            if(utf8ByteString[x] == (byte) 0x00) {
	                convertUpTo = x;
	                break;
	            }
	        }

	        // Convert up to the entire buffer length if there is no null terminator, or up to the variable if
	        // null terminator is found:
	        return new String(utf8ByteString, 0, convertUpTo == -1 ? utf8ByteString.length : convertUpTo);

	    }

	    // Concatenate an arbitrary amount of arrays. Return null if
	    // overflow occurs when combining the size of the arrays together.
	    private byte[] concatenateArrays(byte[]... arrays) {

	        // Find the total size of all the given arrays:
	        int totalSize = 0;

	        for(byte[] array : arrays) {

	            // If the arrays are too big to fit, return null:
	            if(totalSize == Integer.MAX_VALUE) {
	                return null;
	            }

	            totalSize += array.length;
	        }

	        // Allocate space for the total size:
	        byte[] combinedArray = new byte[totalSize];

	        // Copy data of each array into the bigger one:
	        int accumulator = 0;
	        for(byte[] array : arrays) {

	            for(byte b : array) {
	                combinedArray[accumulator++] = b;
	            }

	        }

	        return combinedArray;
	    }

	    // Given a password of maximum 128 bytes in length, derive a 128-bit key for AES:
	    private byte[] deriveAESKeyFromPassword(byte[] password) throws Exception {

	        byte[] result = new byte[16];
	        byte[] hashedPassword =  hash_SHA256(password);

	        // Copy the first 128 bits into the result array:
	        System.arraycopy(hashedPassword, 0, result, 0, result.length);

	        // XOR the remaining 128 bits:
	        for(int x=0; x<result.length; x++) {
	            result[x] = (byte) (result[x] ^ hashedPassword[x + result.length]);
	        }

	        return result;

	    }

	    // XOR two arrays:
	    private byte[] XOR(byte[] array1, byte[] array2) {

	        if(array1.length != array2.length) {
	            return null;
	        }

	        byte[] result = new byte[array1.length];

	        for(int x=0; x<array1.length; x++) {
	            result[x] = (byte) (array1[x] ^ array2[x]);
	        }

	        return result;
	    }

	    // Convert a byte array into a long:
	    private long getLongFromByteArray(byte[] array) {
	        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
	        buffer.put(array);
	        buffer.flip();
	        return buffer.getLong();
	    }

	    // Equality check for testing purposes:
	    @Override
	    public boolean equals(Object obj) {
//            MetaData other = MetaData();
//	        if(!(obj.getClass().equals(other.class))) {
//	            return false;
//	        }
//
//	        if(Arrays.equals(this.username, other.username) &&
//	                Arrays.equals(this.password, other.password) &&
//	                Arrays.equals(this.passwordSalt, other.passwordSalt) &&
//	                Arrays.equals(this.metaDataIV, other.metaDataIV) &&
//	                Arrays.equals(this.hashedUserPassSalt, other.hashedUserPassSalt) &&
//	                Arrays.equals(this.totalLengthOfData, other.totalLengthOfData) &&
//	                this.totalDataBlocks == other.totalDataBlocks &&
//	                Arrays.equals(this.startingIV, other.startingIV) &&
//	                Arrays.equals(this.allDataHash, other.allDataHash) &&
//	                Arrays.equals(this.metaDataHash, other.metaDataHash)) {
//	            return true;
//	        }

	        return false;
	    }

	}
	private static final BigInteger MAXIMUM_KEY_MOD = new BigInteger("170141183460469231731687303715884105727");
	private static final int AES_BLOCK_SIZE = 16;
	private static final int DATA_HASH_SIZE = 32;
	private static final int DATA_FILE_SIZE = Config.BLOCK_SIZE - DATA_HASH_SIZE;

	public EFS(Editor e)
    {
        super(e);
        set_username_password();
    }

    private class ReadResult{

        byte[] result;
        int fileBlocks;
        ReadResult(byte[] a, int f){
        result = a; 
        fileBlocks = f; 
}

    } 
    /**
     * Steps to consider... <p>
     *  - add padded username and password salt to header <p>
     *  - add password hash and file length to secret data <p>
     *  - AES encrypt padded secret data <p>
     *  - add header and encrypted secret data to metadata <p>
     *  - compute HMAC for integrity check of metadata <p>
     *  - add metadata and HMAC to metadata file block <p>
     */
    @Override
    public void create(String file_name, String user_name, String password) throws Exception {
    	if(user_name.length() > 128 || password.length() > 128) throw new Exception("Username and password must have length of 128 characters at most.");
        dir = new File(file_name);
        dir.mkdirs();
        
        //Create a new metadata file
        try{
            MetaData metaData = new MetaData(username.getBytes(), password.getBytes());
            //save the metadata file as the 0th file in the directory
            File metaFile = new File(dir, "0");
            metaData.saveFile(metaFile);
        }catch(Exception e){
            System.out.println(e.getMessage());
        }
    }

    /**
     * Steps to consider... <p>
     *  - check if metadata file size is valid <p>
     *  - get username from metadata <p>
     */
    @Override
    public String findUser(String file_name) throws Exception {

        File metaDataFile = new File(new File(file_name), "0");

        if(metaDataFile.isDirectory() || !metaDataFile.exists()) {
            throw new Exception("The metadata file specified does not exist.");
        }

        // Normally, we would require a password when loading the metadata file to decrypt it.
        // This is a special case since we don't have a password as the function parameter, so we can ignore.
        // Note that because we don't have a password, we can't verify metadata integrity though.
        MetaData metaData = new MetaData(metaDataFile, new byte[128]);

        return metaData.getUsername();

    }

    /**
     * Steps to consider...:<p>
     *  - get password, salt then AES key <p>     
     *  - decrypt password hash out of encrypted secret data <p>
     *  - check the equality of the two password hash values <p>
     *  - decrypt file length out of encrypted secret data
     */
    @Override
    public int length(String file_name, String password) throws Exception {

        File metaDataFile = new File(new File(file_name), "0");

        if(metaDataFile.isDirectory() || !metaDataFile.exists()) {
            throw new Exception("The metadata file specified does not exist.");
        }

        MetaData metaData = new MetaData(metaDataFile, password.getBytes(StandardCharsets.UTF_8));

        if(!metaData.isMetaDataIntact()) {
            throw new Exception("The metadata has been tampered with.");
        }

        if(!metaData.isPasswordCorrect()) {
            throw new PasswordIncorrectException();
        }

        return metaData.getFileLength().intValue();

    }

    /**
     * Steps to consider...:<p>
     *  - verify password <p>
     *  - check check if requested starting position and length are valid <p>
     *  - decrypt content data of requested length 
     */
    @Override
    public byte[] read(String file_name, int starting_position, int len, String password) throws Exception {
        
    	// Get current length
        // Note: the length method checks the integrity of meta file, checks if it exists, and password correctness
        int fileLen = length(file_name, password);
        if(len+starting_position>fileLen ) throw new Exception("Can not read beyond file size");
        // Get the metadata file
        File metaFile = new File(new File(file_name), "0");
        MetaData metaData = new MetaData(metaFile, password.getBytes());

        int fileLocation = starting_position / DATA_FILE_SIZE + 1;
        
        int startInFile = starting_position % DATA_FILE_SIZE + DATA_HASH_SIZE;
        
        int fileBlocks = (DATA_FILE_SIZE/AES_BLOCK_SIZE) * ( fileLocation - 1) + (starting_position % DATA_FILE_SIZE) / AES_BLOCK_SIZE +1; //+1 assuming starting from 0
        int bytesCopied = 0;       

        ByteBuffer decryptedResult = ByteBuffer.allocate(len);

        while(bytesCopied < len){
        	int curFileLen = (int) (fileLocation * DATA_FILE_SIZE <= fileLen? DATA_FILE_SIZE :(fileLen % DATA_FILE_SIZE));
            int leninfile=Math.min(curFileLen,len-bytesCopied);
        	ReadResult temp= decryptFromPhysicalFile(file_name+"/"+fileLocation, leninfile, startInFile, metaData, fileBlocks, curFileLen);
            decryptedResult.put(temp.result);
            bytesCopied += temp.result.length;
            fileLocation++;
            startInFile=DATA_HASH_SIZE;
            fileBlocks=temp.fileBlocks;
            
        }
        
     return decryptedResult.array(); 
    }
     
         
    /**
     * Steps to consider...:<p>
	 *	- verify password <p>
     *  - check check if requested starting position and length are valid <p>
     *  - ### main procedure for update the encrypted content ### <p>
     *  - compute new HMAC and update metadata 
     */
    @Override
    public void write(String file_name, int starting_position, byte[] content, String password) throws Exception {
        if(content.length == 0) return; //This case is when write is called for save action without any content
    	// Get current length
        // Note: the length method checks the integrity of meta file, checks if it exists, and password correctness
        int fileLen = length(file_name, password);
        if(fileLen < starting_position) throw new Exception("Starting position is invalid.");
        
        // Get the metadata file
        File metaFile = new File(new File(file_name), "0");
        MetaData metaData = new MetaData(metaFile, password.getBytes());
        
        int fileLocation = starting_position / DATA_FILE_SIZE + 1;
       
        int startInFile = starting_position % DATA_FILE_SIZE;
        
        int fileBlocks = (DATA_FILE_SIZE/AES_BLOCK_SIZE) * ( fileLocation - 1) + (starting_position % DATA_FILE_SIZE) / AES_BLOCK_SIZE + 1; //+1 for the block to be encrypted
        
        int bytesCopied = 0; 
        byte[] contentInFile = Arrays.copyOfRange(content,0,Math.min(content.length,DATA_FILE_SIZE-startInFile));
        
        int curFileLen = Math.min(DATA_FILE_SIZE , fileLen);
        int curFileCopied = 0;
        while(bytesCopied < content.length){
        	fileBlocks = writeToDataFile(file_name, fileLocation,password, curFileLen,contentInFile, startInFile, metaData, fileBlocks);
            bytesCopied += contentInFile.length;
            contentInFile = Arrays.copyOfRange(content,bytesCopied, bytesCopied + Math.min(DATA_FILE_SIZE, content.length - bytesCopied ));
            fileLocation++;
            startInFile = 0;
            curFileCopied += curFileLen;
            curFileLen = Math.min(DATA_FILE_SIZE , fileLen-curFileCopied);           
        }
        fileLen = fileLen > content.length + starting_position? fileLen: content.length + starting_position;
        updateMetaData( metaFile,  metaData,  fileBlocks-1,  fileLen,  password, file_name);
        
    }
    private byte[] computeAllDataHash(String file_name, String password, long fileLen, byte[] key) throws Exception {
 
    	byte[] hashResult = new byte[64];
   
        int fileCount = (int)Math.ceil( Double.valueOf(fileLen) / Double.valueOf(DATA_FILE_SIZE));
        
        System.arraycopy(getHashOfDataFile(file_name,1),0,hashResult,0,32);
       
        for(int i=2; i<=fileCount; i++) {
        	byte[] hash = new byte[64]; 
        	System.arraycopy(getHashOfDataFile(file_name,i),0,hash,0,32);
        	hashResult = hash_SHA512(XOR(hash,hashResult));
        }
        byte[] concatenatedHash = new byte[hashResult.length + key.length];
        System.arraycopy(hashResult,0,concatenatedHash,0,hashResult.length);
        System.arraycopy(key,0,concatenatedHash,hashResult.length, key.length);
        
        hashResult = hash_SHA512(concatenatedHash);
		return hashResult;
	}

    private byte[] getHashOfDataFile(String file_name, int file_location) throws Exception {
    	
    	byte[] content;
		try {
			File file = new File(new File(file_name), String.valueOf(file_location));
			content =  read_from_file(file);
			return Arrays.copyOfRange(content,0,DATA_HASH_SIZE);
		} catch (Exception e) {
			e.printStackTrace();
		}
        throw new Exception("Unable to open file.");
    }
    private int writeToDataFile(String file_name,int file_location,String password, int curFileLen, byte[] content, int start_position, MetaData metaData, int fileBlocks) throws Exception{
        
        
        BigInteger IV = new BigInteger(metaData.getStartingIV()).add(BigInteger.valueOf(fileBlocks)).mod(MAXIMUM_KEY_MOD);
        
        File dataFile = new File(file_name+"/"+file_location);
        //read existing data into the byte data array
        byte[] fileData = new byte[Config.BLOCK_SIZE];
        if(dataFile.exists()) {
        	fileData =  read_from_file(dataFile); 
        } 
	       
        byte[] key = metaData.getStartingDataKey(); 
        int bytesCopied = 0;
        //if the encryption does not start at the beginning of a new block, copy the prefix content from existing file
        int startingBlock = (start_position) / AES_BLOCK_SIZE;
        int endingBlock = (start_position + content.length) / AES_BLOCK_SIZE;
        
        // Encrypt each block and find the hash simulateneously
        for(int i=startingBlock; i<=endingBlock && i != DATA_FILE_SIZE/AES_BLOCK_SIZE; i++){ 
        	byte[] contentBlock = new byte[AES_BLOCK_SIZE];
        	//decrypt only required part of the file - in the below two situations
        	//if new content starts in between the start block 
        	if(i == endingBlock && curFileLen > content.length+start_position) {
            	int startIndex = endingBlock*AES_BLOCK_SIZE + DATA_HASH_SIZE;
            	contentBlock = XOR(encript_AES(IV.toByteArray(),key), Arrays.copyOfRange(fileData,startIndex,startIndex+AES_BLOCK_SIZE));	
            }
        	else if(i==startingBlock && (startingBlock * AES_BLOCK_SIZE  != (start_position)) ) {   	
            	int startIndex = startingBlock*AES_BLOCK_SIZE + DATA_HASH_SIZE;
            	contentBlock = XOR(encript_AES(IV.toByteArray(),key), Arrays.copyOfRange(fileData,startIndex,startIndex+AES_BLOCK_SIZE));	
            }
        	
        	int copyPosition = i == startingBlock? start_position%AES_BLOCK_SIZE: 0;
        	int blockLen = Math.min(content.length-bytesCopied, AES_BLOCK_SIZE-copyPosition); // if content length is greater than block length choose block length, else if it is lesser choose the content length
        	// second part occurs only for start block, when content length is greater than block length but content to be copied is less than block length
        	System.arraycopy(content,bytesCopied,contentBlock, copyPosition,blockLen);
            
        	byte[] encryptedKey = encript_AES(IV.toByteArray(),key);
            System.arraycopy(XOR(contentBlock,encryptedKey), 0, fileData, (i)* AES_BLOCK_SIZE + DATA_HASH_SIZE, AES_BLOCK_SIZE);
            IV = IV.add(BigInteger.ONE).mod(MAXIMUM_KEY_MOD);
            bytesCopied += blockLen;
            fileBlocks++;
            
        }
        
        //add random string at end, if this is a new file
        if(curFileLen == 0) { //implies that this is a new file
        	int randomLen = DATA_FILE_SIZE - content.length - start_position ;
            if(randomLen > 0) {
            	 byte[] randomBytes =  secureRandomNumber(randomLen);
            	 System.arraycopy(randomBytes, 0, fileData, content.length+DATA_HASH_SIZE+start_position, randomLen);
            }
        }
   
        // Compute the hash for the file
       
        byte[] dataForHash = new byte[Math.max(curFileLen, content.length+start_position)];
        if(curFileLen != 0) {
        	if(start_position != 0) {
            	byte[] decryptedData = read(file_name, (file_location-1)*DATA_FILE_SIZE, start_position, password);
            	System.arraycopy(decryptedData, 0, dataForHash, 0, start_position);
            }
        	if(curFileLen > content.length+start_position ) {
        		int len = curFileLen - (content.length+start_position);
        		int startIdx =  (file_location-1)*DATA_FILE_SIZE+content.length+start_position;
        		byte[] decryptedData = read(file_name,startIdx, len, password);
            	System.arraycopy(decryptedData, 0, dataForHash, content.length+start_position, len);
        	}
        }
        
        System.arraycopy(content,0,dataForHash, start_position,content.length);
        System.arraycopy(hash_SHA256(dataForHash), 0, fileData, 0, DATA_HASH_SIZE);
        
        save_to_file(fileData, dataFile);
        return fileBlocks;
    }
    
	private ReadResult decryptFromPhysicalFile(String file_name, int len, int start_position, MetaData metaData, int fileBlocks, int curFileLen) throws Exception{
        
        
        BigInteger IV = new BigInteger(metaData.getStartingIV()).add(BigInteger.valueOf(fileBlocks)).mod(MAXIMUM_KEY_MOD);
        
        File dataFile = new File(file_name);
        byte[] encryptedData = new byte[Config.BLOCK_SIZE];
        //read existing data into the byte data array
        if(!dataFile.exists()) {
        	throw new Exception("Datafile does not exist");
        } 
        byte[] fileData =  read_from_file(dataFile); 
        //System.arraycopy(fileData, 0, encryptedData, 0, DATA_HASH_SIZE+curFileLen);
	        
        byte[] key = metaData.getStartingDataKey(); 
        int bytesCopied = 0;
        //if the encryption does not start at the beginning of a new block, copy the prefix content from existing file
        int startingBlock = (start_position - DATA_HASH_SIZE) / AES_BLOCK_SIZE;
        int endingBlock = (start_position - DATA_HASH_SIZE + len) / AES_BLOCK_SIZE;
        ByteBuffer result = ByteBuffer.allocate(len);
        int startindex;
        
        // Encrypt each block and find the hash simulateneously
        for(int i=startingBlock; i<=endingBlock && i != DATA_FILE_SIZE/AES_BLOCK_SIZE; i++){ //TODO: verify if equalto is needed
        	byte[] contentBlock = new byte[AES_BLOCK_SIZE];
        	int blockLen = Math.min(len-bytesCopied, AES_BLOCK_SIZE); // if content length is greater than block length choose block length, else if it is lesser choose the len
        	int copyPosition = i == startingBlock? start_position%AES_BLOCK_SIZE: 0;
        	blockLen = Math.min(blockLen,AES_BLOCK_SIZE-copyPosition); // this case occurs only for start block, when content length is greater than block length but content to be copied is less than block length
        	
            startindex=i*AES_BLOCK_SIZE+DATA_HASH_SIZE;
            byte[] temp = XOR(encript_AES(IV.toByteArray(),key), Arrays.copyOfRange(fileData,startindex,startindex+AES_BLOCK_SIZE));
            result.put(Arrays.copyOfRange(temp, copyPosition, copyPosition+blockLen));       
            IV = IV.add(BigInteger.ONE).mod(MAXIMUM_KEY_MOD);
            bytesCopied += blockLen;
            fileBlocks++;
            
        }
         
        return new ReadResult(result.array(),fileBlocks);
    }
    private static byte[] XOR(byte[] arr1, byte[] arr2) {
      byte[] res = new byte[arr1.length];
      for(int i=0; i<arr1.length; i++) {
    	  res[i] = (byte) (arr1[i] ^ arr2[i]);
      }
      return res;
	}


	/**
     * Steps to consider...:<p>
  	 *  - verify password <p>
     *  - check the equality of the computed and stored HMAC values for metadata and physical file blocks<p>
     */
    @Override
    public boolean check_integrity(String file_name, String password) throws Exception {
    	// Get current length
        // Note: the length method checks the integrity of meta file, checks if it exists, and password correctness
        int fileLen = length(file_name, password);
        
        // Get the metadata file
        
    	File metaFile = new File(new File(file_name), "0");
        MetaData metaData = new MetaData(metaFile, password.getBytes());
        //metadata check
        if(!metaData.isMetaDataIntact()) {
            throw new Exception("The metadata has been tampered with.");
        }

        if(!metaData.isPasswordCorrect()) {
            throw new PasswordIncorrectException();
        }
        byte[] computedHash = computeAllDataHash(file_name, password,fileLen,metaData.getStartingDataKey());
        
    	// Note: the computeAllDataHash method checks the integrity of meta file, checks if it exists, and password correctness
        
        //First step : saved hash check
    	byte[] savedHash = metaData.getAllDataHash();
    	
    	for(int i=0; i<computedHash.length; i++) {
    		if(savedHash[i] != computedHash[i]) return false;
    	}
    	
    	//Second step: check data in each physical file
    	int file_location = 1;
    	int curFileLen = Math.min(DATA_FILE_SIZE , fileLen);
        int curFileCopied = 0;
        while(curFileCopied < fileLen){
        	byte[] decryptedData = read(file_name, (file_location-1)*DATA_FILE_SIZE, curFileLen,password);
        	byte[] computed = hash_SHA256(decryptedData);
        	byte[] saved = getHashOfDataFile(file_name, file_location);
        	for(int i=0; i<computed.length; i++) {
        		if(computed[i] != saved[i]) return false;
        	}
        	file_location++;
            curFileCopied += curFileLen;
            curFileLen = Math.min(DATA_FILE_SIZE , fileLen-curFileCopied);           
        }
    	return true;
  }

    /**
     * Steps to consider... <p>
     *  - verify password <p>
     *  - truncate the content after the specified length <p>
     *  - re-pad, update metadata and HMAC <p>
     */
    @Override
    public void cut(String file_name, int length, String password) throws Exception {
    	// Get current length
        // Note: the length method checks the integrity of meta file, checks if it exists, and password correctness
        long fileLen = length(file_name, password);
        
        if(length > fileLen) throw new Exception("Length is invalid.");
        if(length == fileLen) return;
        
        // Get the metadata file
        File metaFile = new File(new File(file_name), "0");
        MetaData metaData = new MetaData(metaFile, password.getBytes());
        
        
        int lastFileAfterCut = (int) Math.ceil(length/Double.valueOf(DATA_FILE_SIZE));
        int lastFileBeforeCut = (int) Math.ceil(fileLen/Double.valueOf(DATA_FILE_SIZE));
        // Delete files which are no longer needed
        while(lastFileBeforeCut > lastFileAfterCut) {
        	File file = new File(file_name+"/"+lastFileBeforeCut); 
            if (!file.delete()) throw new Exception("cut operation failed.");
        	lastFileBeforeCut--;
        }
        // After length fill with random values till the end of the physical file and update hash
        addRandomString(file_name,lastFileAfterCut,length, password );
        
        // Update overall hash and file length
        int fileBlocks = (int) Math.ceil(Double.valueOf(length) / AES_BLOCK_SIZE);
        updateMetaData( metaFile,  metaData,  fileBlocks,  length,  password, file_name);

    }
    private void updateMetaData(File metaFile, MetaData metaData, int fileBlocks, int fileLen, String password, String file_name) throws Exception {
    	
        metaData.setFileLength(BigInteger.valueOf(fileLen));
        metaData.setTotalDataBlocks(fileBlocks);
        // Increment blocks and recalculate hash in meta file. 
        byte[] allDataHash = computeAllDataHash(file_name, password, fileLen, metaData.getStartingDataKey());
        metaData.setAllDataHash(allDataHash);
        //metaData.calculateMetaDataHash();
        metaData.saveFile(metaFile);
    }
    
    private void addRandomString(String file_name, int file_location, int length,String password) throws Exception{
    	
        File dataFile = new File(file_name+"/"+file_location);
        //read existing data into the byte data array
        if(!dataFile.exists()) throw new Exception("cut operation failed");
        byte[] fileData =  read_from_file(dataFile); 
        byte[] decryptedData =  read(file_name, (file_location-1)*DATA_FILE_SIZE, length % DATA_FILE_SIZE,password);
        
        int lengthInFile = length % DATA_FILE_SIZE;
        if(length != 0 && length % DATA_FILE_SIZE == 0) lengthInFile = DATA_FILE_SIZE;
        
        int randomLen = DATA_FILE_SIZE - lengthInFile;
        if(randomLen > 0) {
        	 byte[] randomBytes =  secureRandomNumber(randomLen);
        	 System.arraycopy(randomBytes, 0, fileData, lengthInFile+DATA_HASH_SIZE, randomLen);
        }
        
        // Compute the hash for the file
        
        System.arraycopy(hash_SHA256(decryptedData), 0, fileData, 0, DATA_HASH_SIZE);
        
        save_to_file(fileData, dataFile);
    }
    
}