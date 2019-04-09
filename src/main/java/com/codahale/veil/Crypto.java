package com.codahale.veil;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

class Crypto {

  private static final SecureRandom RANDOM = new SecureRandom();
  private static final int NONCE_LENGTH = 16;
  static final int KEY_LENGTH = 32;
  private static final int MAC_LENGTH = 32;
  static final int OVERHEAD = NONCE_LENGTH + NONCE_LENGTH + MAC_LENGTH;
  static final int SIG_LENGTH = 512;
  private static final String SIG_ALG = "SHA512withRSA";
  private static final String DH_ALG = "X448";
  private static final String SIG_KEY_ALG = "RSA";
  private static final String KDF_ALG = "PBKDF2WithHmacSHA512";
  private static final String ENC_ALG = "AES/CTR/NoPadding";
  private static final String MAC_ALG = "HmacSHA512/256";
  private static final String ENC_KEY_ALG = "AES";

  static byte[] random(int size) {
    var buf = new byte[size];
    RANDOM.nextBytes(buf);
    return buf;
  }

  static byte[] encrypt(byte[] key, byte[] plaintext, byte[] data) {
    try {
      // preallocate the output
      var out = new byte[NONCE_LENGTH + NONCE_LENGTH + plaintext.length + MAC_LENGTH];

      // generate a random salt
      var salt = random(NONCE_LENGTH);
      System.arraycopy(salt, 0, out, 0, NONCE_LENGTH);

      // derive subkeys from key and salt
      var encKey = new byte[KEY_LENGTH];
      var hmacKey = new byte[KEY_LENGTH];
      generateSubkeys(key, salt, encKey, hmacKey);

      // generate a random nonce
      var nonce = random(NONCE_LENGTH);
      System.arraycopy(nonce, 0, out, NONCE_LENGTH, NONCE_LENGTH);

      // encrypt the plaintext w/ AES-CTR-256
      var cipher = Cipher.getInstance(ENC_ALG);
      final IvParameterSpec ivSpec = new IvParameterSpec(nonce, 0, NONCE_LENGTH);
      cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(encKey, ENC_KEY_ALG), ivSpec);
      cipher.doFinal(plaintext, 0, plaintext.length, out, NONCE_LENGTH + NONCE_LENGTH);

      // hash the data, salt, nonce and ciphertext w/ HMAC-SHA512/256
      var hmac = Mac.getInstance(MAC_ALG);
      hmac.init(new SecretKeySpec(hmacKey, MAC_ALG));
      hmac.update(data);
      hmac.update(out, 0, NONCE_LENGTH + NONCE_LENGTH + plaintext.length);
      hmac.doFinal(out, NONCE_LENGTH + NONCE_LENGTH + plaintext.length);

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
      var salt = Arrays.copyOfRange(ciphertext, 0, NONCE_LENGTH);
      var encKey = new byte[KEY_LENGTH];
      var hmacKey = new byte[KEY_LENGTH];
      generateSubkeys(key, salt, encKey, hmacKey);

      // hash the data + salt + nonce + ciphertext w/ HMAC-SHA512/256
      var hmac = Mac.getInstance(MAC_ALG);
      hmac.init(new SecretKeySpec(hmacKey, MAC_ALG));
      hmac.update(data);
      hmac.update(ciphertext, 0, ciphertext.length - MAC_LENGTH);

      var digest =
          Arrays.copyOfRange(ciphertext, ciphertext.length - MAC_LENGTH, ciphertext.length);
      if (!MessageDigest.isEqual(digest, hmac.doFinal())) {
        return null;
      }

      var nonce = Arrays.copyOfRange(ciphertext, NONCE_LENGTH, NONCE_LENGTH + NONCE_LENGTH);
      var cipher = Cipher.getInstance(ENC_ALG);
      var params = new IvParameterSpec(nonce, 0, NONCE_LENGTH);
      cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(encKey, ENC_KEY_ALG), params);
      return cipher.doFinal(
          ciphertext,
          NONCE_LENGTH + NONCE_LENGTH,
          ciphertext.length - NONCE_LENGTH - NONCE_LENGTH - MAC_LENGTH);
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
      var keySpec = new PBEKeySpec(password, data, 1024, KEY_LENGTH * 8 * 2);
      var subkeys = factory.generateSecret(keySpec).getEncoded();
      System.arraycopy(subkeys, 0, encKey, 0, KEY_LENGTH);
      System.arraycopy(subkeys, KEY_LENGTH, hmacKey, 0, KEY_LENGTH);
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new UnsupportedOperationException(e);
    }
  }

  static KeyPair generateEncryptionKeys() {
    try {
      var generator = KeyPairGenerator.getInstance(DH_ALG);
      return generator.generateKeyPair();
    } catch (NoSuchAlgorithmException e) {
      throw new UnsupportedOperationException(e);
    }
  }

  static KeyPair generateSigningKeys() {
    try {
      var generator = KeyPairGenerator.getInstance(SIG_KEY_ALG);
      generator.initialize(4096);
      return generator.generateKeyPair();
    } catch (NoSuchAlgorithmException e) {
      throw new UnsupportedOperationException(e);
    }
  }

  static byte[] sharedSecret(PrivateKey privateKey, PublicKey publicKey) {
    try {
      var agreement = KeyAgreement.getInstance(DH_ALG);
      agreement.init(privateKey);
      agreement.doPhase(publicKey, true);
      return agreement.generateSecret();
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      throw new UnsupportedOperationException(e);
    }
  }

  static byte[] sign(PrivateKey privateKey, byte[] message) {
    try {
      var sig = Signature.getInstance(SIG_ALG);
      sig.initSign(privateKey);
      sig.update(message);
      return sig.sign();
    } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
      throw new UnsupportedOperationException(e);
    }
  }

  static boolean verify(PublicKey publicKey, byte[] message, byte[] signature) {
    try {
      var sig = Signature.getInstance(SIG_ALG);
      sig.initVerify(publicKey);
      sig.update(message);
      return sig.verify(signature);
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      throw new UnsupportedOperationException(e);
    } catch (SignatureException e) {
      return false;
    }
  }
}
