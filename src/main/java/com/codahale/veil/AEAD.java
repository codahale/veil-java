package com.codahale.veil;

import com.google.common.primitives.Longs;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.digests.SHA512tDigest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

class AEAD {

  static final int KEY_LEN = 32;
  private static final int NONCE_LEN = 32;
  private static final int MAC_LEN = 32;
  static final int OVERHEAD = NONCE_LEN + NONCE_LEN + MAC_LEN;
  private static final String MAC_ALG = "HmacSHA512/256";
  private static final String ENC_ALG = "AES/CTR/NoPadding";
  private static final String ENC_KEY_ALG = "AES";
  private static final byte[] ZERO_IV = new byte[16];

  static byte[] encrypt(byte[] key, byte[] plaintext, byte[] data) {
    try {
      // preallocate the output
      var out = new byte[NONCE_LEN + plaintext.length + MAC_LEN];

      // generate a random nonce
      var nonce = Veil.random(NONCE_LEN);
      System.arraycopy(nonce, 0, out, 0, NONCE_LEN);

      // derive subkeys from key and nonce
      var encKey = new byte[KEY_LEN];
      var hmacKey = new byte[KEY_LEN];
      generateSubkeys(key, nonce, encKey, hmacKey);

      // encrypt the plaintext w/ AES-CTR-256 and an all-zero IV
      var cipher = Cipher.getInstance(ENC_ALG);
      final IvParameterSpec ivSpec = new IvParameterSpec(ZERO_IV, 0, ZERO_IV.length);
      cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(encKey, ENC_KEY_ALG), ivSpec);
      cipher.doFinal(plaintext, 0, plaintext.length, out, NONCE_LEN);

      // calculate the mac
      var len = NONCE_LEN + plaintext.length;
      mac(hmacKey, out, len, data, out, len);

      // return nonce + ciphertext + mac
      return out;
    } catch (NoSuchAlgorithmException
        | NoSuchPaddingException
        | InvalidKeyException
        | InvalidAlgorithmParameterException
        | IllegalBlockSizeException
        | BadPaddingException
        | ShortBufferException e) {
      throw new UnsupportedOperationException(e);
    }
  }

  static byte[] decrypt(byte[] key, byte[] ciphertext, byte[] data) {
    try {
      // generate the subkeys
      var nonce = Arrays.copyOfRange(ciphertext, 0, NONCE_LEN);
      var encKey = new byte[KEY_LEN];
      var hmacKey = new byte[KEY_LEN];
      generateSubkeys(key, nonce, encKey, hmacKey);

      // calculate the AEAD mac and compare
      var calculatedMac = new byte[MAC_LEN];
      mac(hmacKey, ciphertext, ciphertext.length - MAC_LEN, data, calculatedMac, 0);
      var extractedMac = new byte[MAC_LEN];
      System.arraycopy(ciphertext, ciphertext.length - MAC_LEN, extractedMac, 0, MAC_LEN);
      if (!MessageDigest.isEqual(extractedMac, calculatedMac)) {
        return null;
      }

      // decrypt ciphertext
      var cipher = Cipher.getInstance(ENC_ALG);
      var params = new IvParameterSpec(ZERO_IV, 0, ZERO_IV.length);
      cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(encKey, ENC_KEY_ALG), params);
      return cipher.doFinal(ciphertext, NONCE_LEN, ciphertext.length - NONCE_LEN - MAC_LEN);
    } catch (NoSuchAlgorithmException
        | InvalidKeyException
        | NoSuchPaddingException
        | InvalidAlgorithmParameterException
        | IllegalBlockSizeException
        | BadPaddingException e) {
      throw new UnsupportedOperationException(e);
    }
  }

  // use the same AEAD construction from draft-mcgrew-aead-aes-cbc-hmac-sha2-05
  private static void mac(byte[] key, byte[] ctxt, int ctxLen, byte[] ad, byte[] out, int outOff) {
    try {
      var hmac = Mac.getInstance(MAC_ALG);
      hmac.init(new SecretKeySpec(key, MAC_ALG));
      hmac.update(ad);
      hmac.update(ctxt, 0, ctxLen);
      hmac.update(Longs.toByteArray(ad.length * 8L));
      hmac.doFinal(out, outOff);
    } catch (NoSuchAlgorithmException | InvalidKeyException | ShortBufferException e) {
      throw new UnsupportedOperationException(e);
    }
  }

  private static void generateSubkeys(byte[] key, byte[] nonce, byte[] encKey, byte[] hmacKey) {
    var hkdf = new HKDFBytesGenerator(new SHA512tDigest(256));
    hkdf.init(new HKDFParameters(key, nonce, null));
    hkdf.generateBytes(encKey, 0, encKey.length);
    hkdf.generateBytes(hmacKey, 0, hmacKey.length);
  }
}
