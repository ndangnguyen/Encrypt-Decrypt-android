 public static String Encoded(String k) {
  try {
   return _encrypt(k, String.valueOf(getSecreteKey(Utils.getDeviceId()))).trim();
  } catch (Exception e) {
   e.printStackTrace();
  }
  return "";
 }

 public static String Decode(String k) {
  try {
   String content = _decrypt(k, String.valueOf(getSecreteKey(Utils.getDeviceId())));
   // Log.d("","#cloud decode" + content);
   return content.trim();
  } catch (Exception e) {
   e.printStackTrace();
  }
  return "";
 }
 
 //    public static String ALGO = "DESede/CBC/PKCS7Padding";
 public static String ALGO = "DESede/ECB/PKCS7Padding";
 
 public static String _encrypt(String message, String secretKey) throws Exception {

  Cipher cipher = Cipher.getInstance(ALGO);
  cipher.init(Cipher.ENCRYPT_MODE, getSecreteKey(secretKey));
  byte[] plainTextBytes = message.getBytes("UTF-8");
  byte[] buf = cipher.doFinal(plainTextBytes);
  byte[] base64Bytes = android.util.Base64.encode(buf, android.util.Base64.DEFAULT);
  String base64EncryptedString = new String(base64Bytes);
  // Log.d("","#cloud _encrypt" + base64EncryptedString);
  return base64EncryptedString;
 }

 public static String _decrypt(String encryptedText, String secretKey) throws Exception {

  byte[] message = android.util.Base64.decode(encryptedText.getBytes(), android.util.Base64.DEFAULT);

  Cipher decipher = Cipher.getInstance(ALGO);
  decipher.init(Cipher.DECRYPT_MODE, getSecreteKey(secretKey));

  byte[] plainText = decipher.doFinal(message);

  return new String(plainText, "UTF-8");
 }

 public static SecretKey getSecreteKey(String secretKey) throws Exception {
  MessageDigest md = MessageDigest.getInstance("SHA-1");
  byte[] digestOfPassword = md.digest(secretKey.getBytes("utf-8"));
  byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
  SecretKey key = new SecretKeySpec(keyBytes, "DESede");
  return key;
 }
