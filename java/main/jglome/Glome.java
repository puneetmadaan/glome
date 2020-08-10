// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package jglome;

import static java.lang.System.arraycopy;
import static java.security.spec.NamedParameterSpec.X25519;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;
import java.util.Optional;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Class, which encapsulates the logic of GLOME protocol.
 */
public class Glome {

  private XECPublicKey peerKey;
  private Mac userMacKey;
  private Mac peerMacKey;
  private int minPeerTagLength;

  private final KeyPair userKeys;

  private final static int MIN_CNT_VALUE = 0;
  private final static int MAX_CNT_VALUE = 255;
  private final static int MAX_TAG_LENGTH = 32;
  private final static int MIN_TAG_LENGTH = 1;

  /**
   * First Glome constructor. Generates a pair of private/public keys for the user, calculates
   * user's and peer's MAC keys.
   *
   * @param peerKey peer's public key.
   * @param minPeerTagLength minimum allowed peer's tag length.
   */
  public Glome(XECPublicKey peerKey, int minPeerTagLength)
      throws MinPeerTagLengthOutOfBoundsException {
    this.userKeys = generateKeys();

    initMacKeys(peerKey, minPeerTagLength);
  }

  /**
   * Second Glome constructor. Derives the user's public key from the {@code privateKey}, calculates
   * user's and peer's MAC keys.
   *
   * @param peerKey peer's public key.
   * @param userPrivateKey user's private key.
   * @param minPeerTagLength minimum allowed peer's tag length.
   */
  public Glome(XECPublicKey peerKey, XECPrivateKey userPrivateKey, int minPeerTagLength)
      throws MinPeerTagLengthOutOfBoundsException {
    XECPublicKey userPublicKey = derivePublicKeyFromPrivate(userPrivateKey);
    this.userKeys = new KeyPair(userPublicKey, userPrivateKey);

    initMacKeys(peerKey, minPeerTagLength);
  }

  public KeyPair userKeys() {
    return userKeys;
  }

  public XECPublicKey peerKey() {
    return peerKey;
  }

  public XECPublicKey userPublicKey() {
    return (XECPublicKey) userKeys.getPublic();
  }

  public XECPrivateKey userPrivateKey() {
    return (XECPrivateKey) userKeys.getPrivate();
  }

  /**
   * Generates a user's tag corresponding to the given message {@code msg} and the counter {@code
   * cnt}.
   *
   * @param msg message from a peer.
   * @param cnt number of previously sent messages from the user to the peer.
   * @throws CounterOutOfBoundsException if {@code cnt} is out of [0..255] range.
   */
  public byte[] generateTag(byte[] msg, int cnt) throws CounterOutOfBoundsException {
    return generateTag(msg, cnt, this.userMacKey);
  }

  /**
   * Checks whether the peer's tag matches received message and some counter.
   *
   * @param peerTag tag from a peer.
   * @param msg message from a peer.
   * @param cnt number of previously sent messages from the peer to the user.
   * @throws CounterOutOfBoundsException if {@code cnt} is out of [0..255] range.
   * @throws WrongTagException if the peer's tag has invalid length (less than {@code
   * minPeerTagLength} or more than {@code MAX_TAG_LENGTH}) or it's not equal to the prefix of a
   * correct tag.
   */
  public void checkTag(byte[] peerTag, byte[] msg, int cnt)
      throws CounterOutOfBoundsException, WrongTagException {
    if (peerTag.length < minPeerTagLength || peerTag.length > MAX_TAG_LENGTH) {
      throw new WrongTagException(
          "The received tag has invalid length. Expected " + minPeerTagLength + " or more, got "
              + peerTag.length + ".");
    }

    byte[] truncatedTag = Arrays.copyOf(generateTag(msg, cnt, this.peerMacKey), peerTag.length);
    if (!Arrays.equals(peerTag, truncatedTag)) {
      throw new WrongTagException("The received tag doesn't match the expected tag.");
    }
  }

  /**
   * Common part of the constructors. Initialises peer's public key, minimum length of a peer's tag,
   * base point for Curve25519 curve. Calculates user's and peer's MAC keys.
   *
   * @param peerKey peer's public key.
   * @param minPeerTagLength minimum length of a peer's tag.
   * @throws MinPeerTagLengthOutOfBoundsException if {@code minPeerTagLength} is out of [1..32]
   * range.
   */
  private void initMacKeys(XECPublicKey peerKey, int minPeerTagLength)
      throws MinPeerTagLengthOutOfBoundsException {
    this.peerKey = peerKey;
    if (minPeerTagLength < MIN_TAG_LENGTH || minPeerTagLength > MAX_TAG_LENGTH) {
      throw new MinPeerTagLengthOutOfBoundsException(
          "minPeerTagLength argument should be in [1..32] range. Got " + minPeerTagLength + ".");
    }
    this.minPeerTagLength = minPeerTagLength;

    KeyAgreement ka;
    try {
      ka = KeyAgreement.getInstance("XDH");
    } catch (NoSuchAlgorithmException e) {
      throw new AssertionError(e.getMessage());
    }

    try {
      ka.init(userPrivateKey());
      ka.doPhase(peerKey, true);
    } catch (InvalidKeyException e) {
      throw new AssertionError(e.getMessage());
    }

    byte[] sharedSecret = ka.generateSecret();
    byte[] userMac = reverseByteArray(
        getU32Bytes(userPublicKey())); // in order to have <i>little-endian</i> byte-order;
    byte[] peerMac = reverseByteArray(getU32Bytes(peerKey)); // the same

    this.userMacKey = getMacKey(sharedSecret, peerMac, userMac);
    this.peerMacKey = getMacKey(sharedSecret, userMac, peerMac);
  }

  private byte[] getU32Bytes(XECPublicKey pk) {
    byte[] userUInBytes = pk.getU().toByteArray();
    byte[] userU32Bytes = new byte[32];
    System.arraycopy(userUInBytes, 0, userU32Bytes, 32 - userUInBytes.length, userUInBytes.length);

    return userU32Bytes;
  }

  private XECPublicKey derivePublicKeyFromPrivate(XECPrivateKey privateKey) {
    KeyPairGenerator keyPairGenerator;
    try {
      keyPairGenerator = KeyPairGenerator.getInstance("X25519");
    } catch (NoSuchAlgorithmException e) {
      throw new AssertionError(e.getMessage());
    }

    try {
      keyPairGenerator
          .initialize(X25519, new StaticSecureRandom(privateKey.getScalar()));
    } catch (InvalidAlgorithmParameterException e) {
      throw new AssertionError(e.getMessage());
    }
    return (XECPublicKey) keyPairGenerator.generateKeyPair().getPublic();
  }

  /**
   * @return a pair of user's public/private keys.
   */
  private KeyPair generateKeys() {
    NamedParameterSpec spec = new NamedParameterSpec("X25519");

    KeyPairGenerator kpg;
    try {
      kpg = KeyPairGenerator.getInstance("XDH");
    } catch (NoSuchAlgorithmException e) {
      throw new AssertionError(e.getMessage());
    }

    try {
      kpg.initialize(spec);
    } catch (InvalidAlgorithmParameterException e) {
      throw new AssertionError(e.getMessage());
    }

    return kpg.generateKeyPair();
  }

  /**
   * Calculates the MAC key.
   *
   * @param sharedSecret some shared secret.
   * @param receiverPublicKey receiver's public key.
   * @param senderPublicKey sender's public key.
   * @return corresponding MAC key.
   */
  private Mac getMacKey(byte[] sharedSecret, byte[] receiverPublicKey, byte[] senderPublicKey) {
    byte[] key = generateMacMsg(sharedSecret, receiverPublicKey, senderPublicKey);

    Mac mac;
    try {
      mac = Mac.getInstance("HmacSHA256");
    } catch (NoSuchAlgorithmException e) {
      throw new AssertionError(e.getMessage());
    }

    try {
      SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA256");
      mac.init(keySpec);
    } catch (InvalidKeyException e) {
      throw new AssertionError(e.getMessage());
    }

    return mac;
  }

  /**
   * Generates a message for MAC by concatenating shared secret and two keys.
   *
   * @param sharedSecret some shard secret.
   * @param receiverPublicKey receiver's public key.
   * @param senderPublicKey sender's public key.
   * @return generated MAC message.
   */
  private byte[] generateMacMsg(byte[] sharedSecret, byte[] receiverPublicKey,
      byte[] senderPublicKey) {
    return ByteBuffer
        .allocate(sharedSecret.length + receiverPublicKey.length + senderPublicKey.length)
        .put(sharedSecret)
        .put(receiverPublicKey)
        .put(senderPublicKey)
        .array();
  }

  private byte[] reverseByteArray(byte[] arr) {
    for (int i = 0; i < arr.length / 2; i++) {
      byte tmp = arr[i];
      arr[i] = arr[arr.length - i - 1];
      arr[arr.length - i - 1] = tmp;
    }

    return arr;
  }

  /**
   * Generates a tag corresponding to the given message {@code msg} and the counter {@code cnt}.
   *
   * @param msg message from a peer.
   * @param cnt number of previously sent messages from the user to the peer.
   * @param mac MAC key of a sender.
   * @throws CounterOutOfBoundsException if {@code cnt} is out of [0..255] range.
   */
  private byte[] generateTag(byte[] msg, int cnt, Mac mac) throws CounterOutOfBoundsException {
    if (cnt < MIN_CNT_VALUE || cnt > MAX_CNT_VALUE) {
      throw new CounterOutOfBoundsException(
          "Counter should be in [0..255] range. Got " + cnt + ".");
    }

    byte[] finalMsg = new byte[msg.length + 1];
    finalMsg[0] = (byte) cnt; // for [0..255] range do `& 0xFF`
    arraycopy(msg, 0, finalMsg, 1, msg.length);

    return mac.doFinal(finalMsg);
  }

  /**
   * Exception, which is thrown whenever a counter is out of [0..255] range.
   */
  public static class CounterOutOfBoundsException extends Exception {

    CounterOutOfBoundsException(String msg) {
      super(msg);
    }

  }

  /**
   * Exception, which is thrown whenever a minimum tag length is out of [1..32] range.
   */
  public static class MinPeerTagLengthOutOfBoundsException extends Exception {

    MinPeerTagLengthOutOfBoundsException(String msg) {
      super(msg);
    }

  }

  /**
   * Exception, which is thrown whenever the received tag has invalid length or it's not equal to
   * the prefix of a correct tag.
   */
  public static class WrongTagException extends Exception {

    WrongTagException(String msg) {
      super(msg);
    }

  }

  /**
   * This class provides static private key, so doesn't generate a new random one.
   */
  public static class StaticSecureRandom extends SecureRandom {

    private final byte[] privateKey;

    /**
     * Stores the given private key.
     *
     * @param privateKey private key to be stored.
     */
    public StaticSecureRandom(Optional<byte[]> privateKey) {
      this.privateKey = privateKey.map(byte[]::clone).orElse(null);
    }

    /**
     * Copies the private key to the given byte array.
     *
     * @param bytes an array where the private key is copied.
     */
    @Override
    public void nextBytes(byte[] bytes) {
      arraycopy(privateKey, 0, bytes, 0, privateKey.length);
    }

  }

}