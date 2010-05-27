/**
 * Copyright 2009 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.waveprotocol.wave.examples.fedone.waveserver;

import static org.easymock.classextension.EasyMock.createStrictMock;
import static org.easymock.classextension.EasyMock.replay;
import static org.easymock.classextension.EasyMock.verify;

import com.google.common.collect.ImmutableList;
import com.google.protobuf.InvalidProtocolBufferException;

import junit.framework.TestCase;

import org.waveprotocol.wave.examples.fedone.common.HashedVersion;
import org.waveprotocol.wave.examples.fedone.common.WaveletOperationSerializer;
import org.waveprotocol.wave.examples.fedone.crypto.CertConstantUtil;
import org.waveprotocol.wave.examples.fedone.crypto.SignerInfo;
import org.waveprotocol.wave.examples.fedone.crypto.WaveSigner;
import org.waveprotocol.wave.examples.fedone.waveserver.CertificateManager.SignatureResultListener;
import org.waveprotocol.wave.protocol.common.ProtocolSignature;
import org.waveprotocol.wave.protocol.common.ProtocolSignedDelta;
import org.waveprotocol.wave.protocol.common.ProtocolWaveletDelta;
import org.waveprotocol.wave.protocol.common.ProtocolSignature.SignatureAlgorithm;
import org.waveprotocol.wave.protocol.common.ProtocolSignerInfo.HashAlgorithm;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Tests {@link BundlingDeltaSigner} and {@link DeltaSignerProvider}.
 */
public class DeltaSignerTest extends TestCase {
  static private final String DOMAIN = "example.com";

  // EasyMocking this with the generics involved became a pain, so roll our own...
  class InstrumentedScheduler extends ScheduledThreadPoolExecutor {
    public Runnable command = null;
    public ScheduledFuture<?> future = null;

    public InstrumentedScheduler(int corePoolSize) {
      super(corePoolSize);
    }
    @Override
    public ScheduledFuture<?> schedule(final Runnable command, long delay, TimeUnit unit) {
      future = super.schedule(command, delay, unit);
      this.command = command;
      return future;
    }
  }


  private final WaveSigner signer;
  private final SignerInfo signerInfo;

  public DeltaSignerTest() throws Exception {
    signerInfo = new SignerInfo(HashAlgorithm.SHA256,
        ImmutableList.of(CertConstantUtil.SERVER_PUB_CERT,
            CertConstantUtil.INTERMEDIATE_PUB_CERT), DOMAIN);
    signer = new WaveSigner(SignatureAlgorithm.SHA1_RSA,
        CertConstantUtil.SERVER_PRIV_KEY, signerInfo);
  }


  @Override
  protected void setUp() throws Exception {
    super.setUp();
  }

  /** Test the simple signer (no bundling). */
  public void testSimpleSigner() throws Exception {
    simpleSignerTest(DeltaSignerProvider.getSimpleDeltaSigner(signer));
  }

  /**
   * For signers with bundle size = 1 we expect a simple signer (i.e. non-bundling), ensure the
   * signatures returned are of non-bundled type.
   */
  public void testBundleSizeOne() throws Exception {
    ScheduledExecutorService executor = createStrictMock(ScheduledExecutorService.class);
    replay(executor);  // expect NO calls to executor.
    simpleSignerTest(utilGetSigner(executor, 1, 0));
    verify(executor);
  }

  /** The simpler signer always uses a regular SHA1 signature, and signs on the calling thread */
  private void simpleSignerTest(DeltaSigner ds) throws Exception {
    final AtomicBoolean gotSig = new AtomicBoolean(false);
    ds.sign(utilMakeDelta(10), new SignatureResultListener() {
      @Override public void signatureResult(ProtocolSignedDelta signedDelta) {
        gotSig.set(true);
        for (ProtocolSignature sig : signedDelta.getSignatureList()) {
          assertEquals(SignatureAlgorithm.SHA1_RSA, sig.getSignatureAlgorithm());
        }
      }
    });
    assertTrue(gotSig.get());
  }

  /**
   * Start filling up a bundle, but time out before it's full. (We simulate the timeout.)
   */
  public void testBundlingSignerBelowBundleSizeWithTimeout() throws Exception {
    int bundleSize = 10;
    int signingTimeout = 60000;
    final Set<Long> callbacks = new HashSet<Long>();

    InstrumentedScheduler executor = new InstrumentedScheduler(2);
    DeltaSigner ds = utilGetSigner(executor, bundleSize, signingTimeout);

    final CountDownLatch latch = new CountDownLatch(bundleSize - 1);
    for (int i = 0; i < bundleSize - 1; i++) {
      ds.sign(utilMakeDelta(i), new SignatureResultListener() {
        @Override
        public void signatureResult(ProtocolSignedDelta signedDelta) {
          callbacks.add(utilExtractVersion(signedDelta));
          latch.countDown();
        }
      });
    }

    // Verify that there was no timeout at this point.
    assertFalse(executor.future.isCancelled());
    assertTrue(executor.future.cancel(false));
    assertEquals(0, callbacks.size());
    // Simulate timer firing.
    executor.command.run();
    latch.await(500, TimeUnit.MILLISECONDS);
    assertEquals(bundleSize - 1, callbacks.size());
  }

  /**
   * We expect two different bundles to be made. The first one should be signed when the max
   * bundle size is hit. The second contains one delta only, and we simulate a timeout on that one.
   */
  public void testBundlingSignerOverBundleSize() throws Exception {
    final int bundleSize = 10;
    int signingTimeout = 60000;
    final Set<Long> callbacks = new HashSet<Long>();
    ScheduledFuture<?> oldFuture = null;

    InstrumentedScheduler executor = new InstrumentedScheduler(2);
    BundlingDeltaSigner ds = (BundlingDeltaSigner) utilGetSigner(executor, bundleSize, signingTimeout);

    final CountDownLatch latch1 = new CountDownLatch(bundleSize);
    final CountDownLatch latch2 = new CountDownLatch(1);
    for (int i = 0; i < bundleSize + 1; i++) {
      ds.sign(utilMakeDelta(i), new SignatureResultListener() {
        @Override
        public void signatureResult(ProtocolSignedDelta signedDelta) {
          callbacks.add(utilExtractVersion(signedDelta));
          if (utilExtractVersion(signedDelta) < bundleSize) {
            latch1.countDown();
          } else {
            latch2.countDown();
          }
        }
      });
      // Get the future for the first bundle.
      if (oldFuture == null) {
        oldFuture = executor.future;
      }
    }

    // Assert that the first bundle was all signed.
    assertTrue(oldFuture.isCancelled());
    assertTrue(latch1.await(5000, TimeUnit.MILLISECONDS));
    assertEquals(bundleSize, callbacks.size());

    // Now simulate a timeout for the second bundle.
    assertFalse(executor.future.isCancelled());
    assertTrue(executor.future.cancel(false));
    assertEquals(bundleSize, callbacks.size());
    // Simulate timer firing.
    executor.command.run();
    latch2.await(5000, TimeUnit.MILLISECONDS);
    assertEquals(bundleSize + 1, callbacks.size());
  }

  // ===================== utility methods below ==================

  private DeltaSigner utilGetSigner(ScheduledExecutorService executor,
      int maxBundleSize, int maxSignerTimeout) {
    return new DeltaSignerProvider(executor, maxBundleSize, maxSignerTimeout, signer).get();
  }

  private static ByteStringMessage<ProtocolWaveletDelta> utilMakeDelta(long version)
      throws Exception {
    ProtocolWaveletDelta delta = ProtocolWaveletDelta.newBuilder()
    .setHashedVersion(WaveletOperationSerializer.serialize(HashedVersion.unsigned(version)))
    .setAuthor("sinbad@acmewave.com")
    .build();
    ByteStringMessage<ProtocolWaveletDelta> canonicalDelta = ByteStringMessage.from(
          ProtocolWaveletDelta.getDefaultInstance(), delta.toByteString());
    return canonicalDelta;
  }

  private static long utilExtractVersion(ProtocolSignedDelta signedDelta) {
    ProtocolWaveletDelta delta;
    try {
      delta = ProtocolWaveletDelta.parseFrom(signedDelta.getDelta());
    } catch (InvalidProtocolBufferException e) {
      throw new RuntimeException(e);
    }
    return delta.getHashedVersion().getVersion();
  }
}
