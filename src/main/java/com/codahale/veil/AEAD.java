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

class AEAD {

  static final int KEY_LEN = 64;
  private static final int NONCE_LEN = 16;
  private static final int MAC_LEN = 32;
  static final int OVERHEAD = NONCE_LEN + MAC_LEN;
  private static final String MAC_ALG = "HmacSHA512/256";
  private static final String ENC_ALG = "AES/CTR/NoPadding";
  private static final String ENC_KEY_ALG = "AES";

  static byte[] encrypt(byte[] key, byte[] plaintext, byte[] data) {
    if (data == null) {
      data = new byte[0];
    }
    try {
      // preallocate the output
      var out = new byte[NONCE_LEN + plaintext.length + MAC_LEN];

      // derive subkeys from key
      var encKey = Arrays.copyOf(key, 32);
      var hmacKey = Arrays.copyOfRange(key, 32, KEY_LEN);

      // generate a random nonce
      var nonce = Veil.random(NONCE_LEN);
      System.arraycopy(nonce, 0, out, 0, NONCE_LEN);

      // encrypt the plaintext w/ AES-CTR-256 and the random nonce
      var cipher = Cipher.getInstance(ENC_ALG);
      final IvParameterSpec ivSpec = new IvParameterSpec(nonce, 0, NONCE_LEN);
      cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(encKey, ENC_KEY_ALG), ivSpec);
      cipher.doFinal(plaintext, 0, plaintext.length, out, NONCE_LEN);

      // calculate the mac
      mac(hmacKey, out, NONCE_LEN + plaintext.length, data, out, NONCE_LEN + plaintext.length);

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
    if (data == null) {
      data = new byte[0];
    }
    try {
      // derive subkeys from key
      var encKey = Arrays.copyOf(key, 32);
      var hmacKey = Arrays.copyOfRange(key, 32, KEY_LEN);

      // calculate the AEAD mac and compare
      var calculatedMac = new byte[MAC_LEN];
      mac(hmacKey, ciphertext, ciphertext.length - MAC_LEN, data, calculatedMac, 0);
      var extractedMac = new byte[MAC_LEN];
      System.arraycopy(ciphertext, ciphertext.length - MAC_LEN, extractedMac, 0, MAC_LEN);
      if (!MessageDigest.isEqual(extractedMac, calculatedMac)) {
        return null;
      }

      // extract nonce
      var nonce = Arrays.copyOfRange(ciphertext, 0, NONCE_LEN);

      // decrypt ciphertext
      var cipher = Cipher.getInstance(ENC_ALG);
      var params = new IvParameterSpec(nonce, 0, NONCE_LEN);
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
}
