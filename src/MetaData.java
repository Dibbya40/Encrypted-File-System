import java.io.File;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;

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

    private static final BigInteger MAXIMUM_KEY_MOD = new BigInteger("170141183460469231731687303715884105727");

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

        ByteBuffer fileData = ByteBuffer.wrap(Utility.read_from_file(file));

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
        this.passwordSalt = Utility.secureRandomNumber(PASSWORD_SALT_SIZE);
        this.metaDataIV = Utility.secureRandomNumber(IV_SIZE);

        // This integrity hash = HASH512(username || password || salt):
        this.hashedUserPassSalt = calculateHashedUserPassSalt();

        // Securely randomly generate a random starting counter IV:
        this.startingIV = Utility.secureRandomNumber(IV_SIZE);
        this.startingDataKey = Utility.secureRandomNumber(AES_KEY_SIZE);

        // Take the password and derive a starting 128-bit key (just for the metadata):
        this.startingMetaDataKey = deriveAESKeyFromPassword(this.password);

        this.randomPadding = Utility.secureRandomNumber(RANDOM_PADDING_SIZE);

        // Calculate the metadata hash:
        this.metaDataHash = calculateMetaDataHash();
    }

    private byte[] calculateHashedUserPassSalt() throws Exception {
        return Utility.hash_SHA512(concatenateArrays(this.password, this.passwordSalt));
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
        Utility.save_to_file(concatenateArrays(username, passwordSalt, metaDataIV, getEncryptedData()), file);
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

        return Utility.hash_SHA512(metaDataFields.array());
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
            byte[] encryptedIV = Utility.encript_AES(metaDataIVOffset.toByteArray(), blockKeyOffset.toByteArray());
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
            byte[] encryptedIV = Utility.encript_AES(metaDataIVOffset.toByteArray(), blockKeyOffset.toByteArray());
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
        byte[] hashedPassword = Utility.hash_SHA256(password);

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
    /*
        if(!(obj instanceof MetaData other)) {
            return false;
        }

        if(Arrays.equals(this.username, other.username) &&
                Arrays.equals(this.password, other.password) &&
                Arrays.equals(this.passwordSalt, other.passwordSalt) &&
                Arrays.equals(this.metaDataIV, other.metaDataIV) &&
                Arrays.equals(this.hashedUserPassSalt, other.hashedUserPassSalt) &&
                Arrays.equals(this.totalLengthOfData, other.totalLengthOfData) &&
                this.totalDataBlocks == other.totalDataBlocks &&
                Arrays.equals(this.startingIV, other.startingIV) &&
                Arrays.equals(this.allDataHash, other.allDataHash) &&
                Arrays.equals(this.metaDataHash, other.metaDataHash)) {
            return true;
        }
        */

        return false;
    }

}
