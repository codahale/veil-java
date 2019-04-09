package com.codahale.veil;

import com.google.common.primitives.Ints;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

class AEAD {
  static final int KEY_LEN = 32;
  private static final int NONCE_LEN = 16;
  private static final int MAC_LEN = 32;
  static final int OVERHEAD = NONCE_LEN + NONCE_LEN + MAC_LEN;
  private static final String MAC_ALG = "HmacSHA512/256";
  private static final String ENC_ALG = "AES/CTR/NoPadding";
  private static final String KDF_ALG = "PBKDF2WithHmacSHA512";
  private static final String ENC_KEY_ALG = "AES";

  static byte[] encrypt(byte[] key, byte[] plaintext, byte[] data) {
    try {
      // preallocate the output
      var out = new byte[NONCE_LEN + NONCE_LEN + plaintext.length + MAC_LEN];

      // generate a random salt
      var salt = Veil.random(NONCE_LEN);
      System.arraycopy(salt, 0, out, 0, NONCE_LEN);

      // derive subkeys from key and salt
      var encKey = new byte[KEY_LEN];
      var hmacKey = new byte[KEY_LEN];
      generateSubkeys(key, salt, encKey, hmacKey);

      // generate a random nonce
      var nonce = Veil.random(NONCE_LEN);
      System.arraycopy(nonce, 0, out, NONCE_LEN, NONCE_LEN);

      // encrypt the plaintext w/ AES-CTR-256
      var cipher = Cipher.getInstance(ENC_ALG);
      final IvParameterSpec ivSpec = new IvParameterSpec(nonce, 0, NONCE_LEN);
      cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(encKey, ENC_KEY_ALG), ivSpec);
      cipher.doFinal(plaintext, 0, plaintext.length, out, NONCE_LEN + NONCE_LEN);

      // hash the data, salt, nonce and ciphertext w/ HMAC-SHA512/256
      final int len = NONCE_LEN + NONCE_LEN + plaintext.length;
      var hmac = Mac.getInstance(MAC_ALG);
      hmac.init(new SecretKeySpec(hmacKey, MAC_ALG));
      hmac.update(Ints.toByteArray(data.length));
      hmac.update(data);
      hmac.update(out, 0, len);
      hmac.doFinal(out, len);

      // return salt + nonce + ciphertext + digest
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
      var salt = Arrays.copyOfRange(ciphertext, 0, NONCE_LEN);
      var encKey = new byte[KEY_LEN];
      var hmacKey = new byte[KEY_LEN];
      generateSubkeys(key, salt, encKey, hmacKey);

      // hash the data, salt, nonce and ciphertext w/ HMAC-SHA512/256
      var hmac = Mac.getInstance(MAC_ALG);
      hmac.init(new SecretKeySpec(hmacKey, MAC_ALG));
      hmac.update(Ints.toByteArray(data.length));
      hmac.update(data);
      hmac.update(ciphertext, 0, ciphertext.length - MAC_LEN);

      // compare digests
      var digest = Arrays.copyOfRange(ciphertext, ciphertext.length - MAC_LEN, ciphertext.length);
      if (!MessageDigest.isEqual(digest, hmac.doFinal())) {
        return null;
      }

      // decrypt ciphertext
      var nonce = Arrays.copyOfRange(ciphertext, NONCE_LEN, NONCE_LEN + NONCE_LEN);
      var cipher = Cipher.getInstance(ENC_ALG);
      var params = new IvParameterSpec(nonce, 0, NONCE_LEN);
      cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(encKey, ENC_KEY_ALG), params);
      return cipher.doFinal(
          ciphertext, NONCE_LEN + NONCE_LEN, ciphertext.length - NONCE_LEN - NONCE_LEN - MAC_LEN);
    } catch (NoSuchAlgorithmException
        | InvalidKeyException
        | NoSuchPaddingException
        | InvalidAlgorithmParameterException
        | IllegalBlockSizeException
        | BadPaddingException e) {
      throw new UnsupportedOperationException(e);
    }
  }

  private static void generateSubkeys(byte[] key, byte[] data, byte[] encKey, byte[] hmacKey) {
    try {
      var factory = SecretKeyFactory.getInstance(KDF_ALG);
      var password = new char[key.length];
      for (int i = 0; i < key.length; i++) {
        password[i] = (char) key[i];
      }
      var keySpec = new PBEKeySpec(password, data, 1024, AEAD.KEY_LEN * 8 * 2);
      var subkeys = factory.generateSecret(keySpec).getEncoded();
      System.arraycopy(subkeys, 0, encKey, 0, AEAD.KEY_LEN);
      System.arraycopy(subkeys, AEAD.KEY_LEN, hmacKey, 0, AEAD.KEY_LEN);
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new UnsupportedOperationException(e);
    }
  }
}
