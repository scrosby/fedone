/**
 * Copyright 2010 Google Inc.
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

package org.waveprotocol.wave.federation.xmpp;

import com.google.common.collect.Lists;
import com.google.protobuf.ByteString;

import junit.framework.TestCase;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import org.waveprotocol.wave.waveserver.ProtocolHashedVersionFactory;
import org.waveprotocol.wave.federation.FederationErrorProto.FederationError;
import org.waveprotocol.wave.federation.xmpp.MockDisco.PendingMockDisco;
import org.waveprotocol.wave.federation.Proto.ProtocolHashedVersion;
import org.waveprotocol.wave.model.id.WaveId;
import org.waveprotocol.wave.model.id.WaveletId;
import org.waveprotocol.wave.model.id.WaveletName;
import org.waveprotocol.wave.waveserver.WaveletFederationListener;
import org.xmpp.packet.Packet;

import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;

/**
 * Tests for {@link XmppFederationHostForDomain}.
 *
 * @author arb@google.com (Anthony Baxter)
 * @author thorogood@google.com (Sam Thorogood)
 */
public class XmppFederationHostForDomainTest extends TestCase {

  private final static String LOCAL_DOMAIN = "acmewave.com";
  private final static String LOCAL_JID = "wave." + LOCAL_DOMAIN;
  private final static String REMOTE_DOMAIN = "initech-corp.com";
  private final static String REMOTE_JID = "wave." + REMOTE_DOMAIN;

  private final static WaveletName WAVELET_NAME =
      WaveletName.of(new WaveId(REMOTE_DOMAIN, "wave"), new WaveletId(REMOTE_DOMAIN, "wavelet"));
  private final static ProtocolHashedVersion WAVELET_VERSION =
      ProtocolHashedVersionFactory.createVersionZero(WAVELET_NAME);
  private final static ByteString DELTA_BYTESTRING =
      ByteString.copyFromUtf8("Irrelevant delta bytes");

  private final static String TEST_ID_SUFFIX = "-1-sometestID";


  private MockDisco disco;
  private XmppFederationHostForDomain fedHost;
  private MockOutgoingPacketTransport transport;
  private XmppManager manager;

  private static final String EXPECTED_UPDATE_MESSAGE =
      "\n<message type=\"normal\" from=\"" + LOCAL_JID + "\""
      + " to=\"" + REMOTE_JID + "\" id=\"" + "1" + TEST_ID_SUFFIX + "\">\n"
      + "  <request xmlns=\"urn:xmpp:receipts\"/>\n"
      + "  <event xmlns=\"http://jabber.org/protocol/pubsub#event\">\n"
      + "    <items>\n"
      + "      <item>\n"
      + "        <wavelet-update"
      + " xmlns=\"http://waveprotocol.org/protocol/0.2/waveserver\""
      + " wavelet-name=\"" + XmppUtil.waveletNameCodec.encode(WAVELET_NAME) + "\">\n"
      + "          <applied-delta>"
      + "<![CDATA[" + Base64Util.encode(DELTA_BYTESTRING) + "]]></applied-delta>\n"
      + "        </wavelet-update>\n"
      + "      </item>\n"
      + "    </items>\n"
      + "  </event>\n"
      + "</message>";

  private static final List<ByteString> NO_DELTAS = Collections.emptyList();

  @Override
  public void setUp() {
    XmppUtil.fakeIdGenerator = new Callable<String>() {
      private int idCounter = 0;

      public String call() throws Exception {
        idCounter++;
        return idCounter + TEST_ID_SUFFIX;
      }
    };

    disco = new MockDisco(null);
    transport = new MockOutgoingPacketTransport();
    manager = new XmppManager(mock(XmppFederationHost.class), mock(XmppFederationRemote.class),
                              disco, transport, LOCAL_JID);
    fedHost = new XmppFederationHostForDomain(REMOTE_DOMAIN, manager, disco, LOCAL_JID);
  }

  @Override
  protected void tearDown() throws Exception {
    super.tearDown();
    XmppUtil.fakeIdGenerator = null; // reset so as to not leave the class in a bad state.
  }

  /**
   * Tests that commit sends a correctly formatted XMPP packet.
   */
  public void testCommit() throws Exception {
    commit(null);
    assertEquals(0, transport.packetsSent);

    successDiscoRequest();
    checkCommitMessage();
  }

  /**
   * Test we don't fall in a heap if disco fails.
   */
  public void testCommitWithFailedDisco() throws Exception {
    WaveletFederationListener.WaveletUpdateCallback callback =
        mock(WaveletFederationListener.WaveletUpdateCallback.class);
    commit(callback);
    failDiscoRequest();

    // No packets should be sent.
    verify(callback).onFailure((FederationError) any());
    assertEquals(0, transport.packetsSent);
  }

  /**
   * Tests that update sends a correctly formatted XMPP packet.
   */
  public void testUpdate() throws Exception {
    update(null);
    assertEquals(0, transport.packetsSent);

    successDiscoRequest();
    checkUpdateMessage();
  }

  /**
   * Tests that update sends a correctly formatted XMPP packet.
   */
  public void testUpdateAndCommit() throws Exception {

    update(new WaveletFederationListener.WaveletUpdateCallback() {

      public void onSuccess() {
        // expected
      }

      public void onFailure(FederationError error) {
        fail("update failed: " + error);
      }
    });
    commit(new WaveletFederationListener.WaveletUpdateCallback() {

      public void onSuccess() {
        // expected
      }

      public void onFailure(FederationError error) {
        fail("commit failed: " + error);
      }
    });
    assertEquals(0, transport.packetsSent);

    successDiscoRequest();
    checkUpdateAndCommit();
  }


  /**
   * Test we don't fall in a heap if disco fails.
   */
  public void testUpdateWithFailedDisco() throws Exception {
    WaveletFederationListener.WaveletUpdateCallback callback =
      mock(WaveletFederationListener.WaveletUpdateCallback.class);
    update(callback);
    failDiscoRequest();

    // No packets should be sent.
    verify(callback).onFailure((FederationError) any());
    assertEquals(0, transport.packetsSent);
  }

  /**
   * Send a single commit notice containing a dummy version via {@link #fedHost}.
   */
  private void commit(WaveletFederationListener.WaveletUpdateCallback updateCallback) {
    fedHost.waveletUpdate(WAVELET_NAME, NO_DELTAS, WAVELET_VERSION, updateCallback);
  }

  /**
   * Send a single update message containing a dummy delta via {@link #fedHost}.
   * .
   */
  private void update(WaveletFederationListener.WaveletUpdateCallback updateCallback) {
    fedHost.waveletUpdate(WAVELET_NAME, Lists.newArrayList(DELTA_BYTESTRING), null,
        updateCallback);
  }

  /**
   * Confirm that there is one outstanding disco request to REMOTE_DOMAIN, and
   * force its success.
   */
  private void successDiscoRequest() {
    assertEquals(1, disco.pending.size());
    PendingMockDisco v = disco.pending.poll();
    assertEquals(REMOTE_DOMAIN, v.remoteDomain);
    v.callback.onSuccess(REMOTE_JID);
  }

  /**
   * Confirm that there is one outstanding disco request to REMOTE_DOMAIN, and
   * force its failure.
   */
  private void failDiscoRequest() {
    assertEquals(1, disco.pending.size());
    PendingMockDisco v = disco.pending.poll();
    assertEquals(REMOTE_DOMAIN, v.remoteDomain);
    v.callback.onFailure("Forced failure");
  }

  /**
   * Check the commit message is as expected.
   */
  private void checkCommitMessage() {
    assertEquals(1, transport.packetsSent);
    Packet packet = transport.lastPacketSent;
    assertEquals(REMOTE_JID, packet.getTo().toString());
    assertEquals(LOCAL_JID, packet.getFrom().toString());
    assertEquals(generateExpectedCommitMessage("1" + TEST_ID_SUFFIX), packet.toString());
  }

  /**
   * Checks the update message is as expected.
   */
  private void checkUpdateMessage() {
    assertEquals(1, transport.packetsSent);
    Packet packet = transport.lastPacketSent;
    assertEquals(REMOTE_JID, packet.getTo().toString());
    assertEquals(LOCAL_JID, packet.getFrom().toString());
    assertEquals(EXPECTED_UPDATE_MESSAGE, packet.toString());

    /*
    XmppTestUtil
        .assertEqualsWithoutCData(EXPECTED_UPDATE_MESSAGE, packet.toString());
    XmppTestUtil.verifyTestAppliedWaveletDelta(
        XmppTestUtil.extractCData(packet.toString()));
        */
  }

  /**
   * Checks an update and then a commit message were sent.
   */
  private void checkUpdateAndCommit() {
    assertEquals(2, transport.packetsSent);
    Packet packet = transport.packets.poll();
    assertEquals(REMOTE_JID, packet.getTo().toString());
    assertEquals(LOCAL_JID, packet.getFrom().toString());
    assertEquals(EXPECTED_UPDATE_MESSAGE, packet.toString());

    packet = transport.packets.poll();
    assertEquals(REMOTE_JID, packet.getTo().toString());
    assertEquals(LOCAL_JID, packet.getFrom().toString());
    assertEquals(generateExpectedCommitMessage("2" + TEST_ID_SUFFIX), packet.toString());
  }

  private static String generateExpectedCommitMessage(String testId) {
    return
      "\n<message type=\"normal\" from=\"" + LOCAL_JID + "\""
      + " to=\"" + REMOTE_JID + "\" id=\"" + testId + "\">\n"
      + "  <request xmlns=\"urn:xmpp:receipts\"/>\n"
      + "  <event xmlns=\"http://jabber.org/protocol/pubsub#event\">\n"
      + "    <items>\n"
      + "      <item>\n"
      + "        <wavelet-update"
      + " xmlns=\"http://waveprotocol.org/protocol/0.2/waveserver\""
      + " wavelet-name=\"" + XmppUtil.waveletNameCodec.encode(WAVELET_NAME) + "\">\n"
      + "          <commit-notice version=\"" + WAVELET_VERSION.getVersion() + "\" history-hash=\""
      + Base64Util.encode(WAVELET_VERSION.getHistoryHash())
      + "\"/>\n"
      + "        </wavelet-update>\n"
      + "      </item>\n"
      + "    </items>\n"
      + "  </event>\n"
      + "</message>";
  }
}
