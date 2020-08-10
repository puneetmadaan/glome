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

import static java.security.spec.NamedParameterSpec.X25519;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static jglome.TestVector.testVector1;
import static jglome.TestVector.testVector2;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.util.Arrays;
import java.util.Optional;
import jglome.Glome.WrongTagException;
import org.junit.jupiter.api.Test;
import jglome.Glome.CounterOutOfBoundsException;
import jglome.Glome.MinPeerTagLengthOutOfBoundsException;
import jglome.Glome.StaticSecureRandom;

/**
 * Class, which contains tests for main.jglome.Glome functionality.
 */
public class GlomeTest {

  final static int N_TEST_VECTORS = 2;

  TestVector[] testVectors = {testVector1, testVector2};
  Glome[][] glomeManagers = new Glome[N_TEST_VECTORS][2]; // first is for A, second is for B
  KeyPair[] aKeys = new KeyPair[N_TEST_VECTORS];
  KeyPair[] bKeys = new KeyPair[N_TEST_VECTORS];

  GlomeTest() throws MinPeerTagLengthOutOfBoundsException {
    for (int i = 0; i < N_TEST_VECTORS; i++) {
      aKeys[i] = deriveKeysFromPrivate(testVectors[i].kah);
      bKeys[i] = deriveKeysFromPrivate(testVectors[i].kbh);
      glomeManagers[i][0] = new Glome((XECPublicKey) bKeys[i].getPublic(),
          (XECPrivateKey) aKeys[i].getPrivate(), 32);
      glomeManagers[i][1] = new Glome((XECPublicKey) aKeys[i].getPublic(),
          (XECPrivateKey) bKeys[i].getPrivate(), 28);
    }
  }

  @Test
  public void testShouldFailWhenMinPeerTagLengthIsOutOfBounds() {
    try {
      new Glome((XECPublicKey) aKeys[0].getPublic(), (XECPrivateKey) bKeys[0].getPrivate(), 0);
    } catch (MinPeerTagLengthOutOfBoundsException e) {
      assertEquals(e.getMessage(), "minPeerTagLength argument should be in [1..32] range. Got 0.");
    }

    try {
      new Glome((XECPublicKey) aKeys[0].getPublic(), (XECPrivateKey) bKeys[0].getPrivate(), 33);
    } catch (MinPeerTagLengthOutOfBoundsException e) {
      assertEquals(e.getMessage(), "minPeerTagLength argument should be in [1..32] range. Got 33.");
    }
  }

  @Test
  public void testShouldFailWhenCounterIsOutOfBounds() {
    TestVector vector = testVectors[0];
    try {
      assertArrayEquals(vector.tag, glomeManagers[0][0].generateTag(vector.msg, -1));
    } catch (CounterOutOfBoundsException e) {
      assertEquals(e.getMessage(), "Counter should be in [0..255] range. Got -1.");
    }

    try {
      assertArrayEquals(vector.msg, glomeManagers[0][0].generateTag(vector.msg, 256));
    } catch (CounterOutOfBoundsException e) {
      assertEquals(e.getMessage(), "Counter should be in [0..255] range. Got 256.");
    }
  }

  @Test
  public void derivedKeyShouldEqualOriginalKey() {
    for (int i = 0; i < N_TEST_VECTORS; i++) {
      assertEquals(aKeys[i].getPublic(), glomeManagers[i][0].userKeys().getPublic());
      assertEquals(bKeys[i].getPublic(), glomeManagers[i][1].userKeys().getPublic());
    }
  }

  @Test
  public void testTagGeneration() throws CounterOutOfBoundsException {
    for (int i = 0; i < N_TEST_VECTORS; i++) {
      TestVector vector = testVectors[i];
      int sender = i % 2 == 0 ? 0 : 1;
      assertArrayEquals(vector.tag, glomeManagers[i][sender].generateTag(vector.msg, vector.cnt));
    }
  }

  @Test
  public void testCheckTag() throws WrongTagException, CounterOutOfBoundsException {
    for (int i = 0; i < N_TEST_VECTORS; i++) {
      TestVector vector = testVectors[i];
      int receiver = i % 2 == 0 ? 1 : 0;
      glomeManagers[i][receiver].checkTag(vector.tag, vector.msg, vector.cnt);
    }
  }

  @Test
  public void testCorrectTruncatedTag() throws CounterOutOfBoundsException, WrongTagException {
    TestVector vector = testVectors[0];
    glomeManagers[0][1].checkTag(Arrays.copyOf(vector.tag, 29), vector.msg, vector.cnt);
  }

  @Test
  public void testShouldFailWhenIncorrectTruncatedTag()
      throws CounterOutOfBoundsException {
    TestVector vector = testVectors[0];
    byte[] truncatedTag = Arrays.copyOf(vector.tag, 29);
    truncatedTag[28] = 0;

    try {
      glomeManagers[0][1].checkTag(truncatedTag, vector.msg, vector.cnt);
    } catch (WrongTagException e) {
      assertEquals("The received tag doesn't match the expected tag.", e.getMessage());
    }
  }

  private KeyPair deriveKeysFromPrivate(byte[] privateKey) {
    KeyPairGenerator keyPairGenerator;
    try {
      keyPairGenerator = KeyPairGenerator.getInstance("X25519");
    } catch (NoSuchAlgorithmException e) {
      throw new AssertionError(e.getMessage());
    }

    try {
      keyPairGenerator.initialize(X25519, new StaticSecureRandom(Optional.of(privateKey)));
    } catch (InvalidAlgorithmParameterException e) {
      throw new AssertionError(e.getMessage());
    }

    return keyPairGenerator.generateKeyPair();
  }
}
