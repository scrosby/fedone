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

package org.waveprotocol.wave.examples.fedone.agents.echoey;

import com.google.common.base.Function;
import com.google.common.collect.Lists;
import com.google.common.collect.MapMaker;
import com.google.inject.internal.Sets;

import org.waveprotocol.wave.examples.fedone.agents.agent.AbstractAgent;
import org.waveprotocol.wave.examples.fedone.agents.agent.AgentConnection;
import org.waveprotocol.wave.examples.fedone.common.DocumentConstants;
import org.waveprotocol.wave.examples.fedone.util.Log;
import org.waveprotocol.wave.examples.fedone.waveclient.common.ClientUtils;
import org.waveprotocol.wave.model.document.operation.BufferedDocOp;
import org.waveprotocol.wave.model.id.IdConstants;
import org.waveprotocol.wave.model.id.WaveletName;
import org.waveprotocol.wave.model.operation.wave.WaveletDelta;
import org.waveprotocol.wave.model.operation.wave.WaveletDocumentOperation;
import org.waveprotocol.wave.model.operation.wave.WaveletOperation;
import org.waveprotocol.wave.model.wave.ParticipantId;
import org.waveprotocol.wave.model.wave.data.WaveletData;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Example agent that echoes back operations.
 */
public class Echoey extends AbstractAgent {

  private static final Log LOG = Log.get(Echoey.class);

  private final Map<WaveletName, Set<String>> documentsSeen = new MapMaker().makeComputingMap(
      new Function<WaveletName, Set<String>>() {
        @Override
        public Set<String> apply(WaveletName waveletName) {
          return Sets.newHashSet();
        }
      });

  /**
   * @return the suffix that Echoey adds to each document it is editing
   */
  private String getEchoeyDocumentSuffix() {
    return IdConstants.TOKEN_SEPARATOR + getParticipantId().getAddress();
  }

  /**
   * Main entry point.
   *
   * @param args program arguments.
   */
  public static void main(String[] args) {
    try {
      if (args.length == 3) {
        int port;
        try {
          port = Integer.parseInt(args[2]);
        } catch (NumberFormatException e) {
          throw new IllegalArgumentException("Must provide valid port.");
        }

        Echoey agent = new Echoey(args[0], args[1], port);
        agent.run();
      } else {
        System.out.println("usage: java Echoey <username> <hostname> <port>");
      }
    } catch (Exception e) {
      LOG.severe("Catastrophic failure", e);
      System.exit(1);
    }

    System.exit(0);
  }

  private Echoey(String username, String hostname, int port) {
    super(AgentConnection.newConnection(username, hostname, port));
  }

  @Override
  public void onDocumentChanged(WaveletData wavelet, WaveletDocumentOperation documentOperation) {
    final String docId = documentOperation.getDocumentId();
    LOG.info("onDocumentChanged: " + wavelet.getWaveletName() + ", " + docId);

    if (docId.equals(DocumentConstants.MANIFEST_DOCUMENT_ID)) {
      // Don't echo anything on the manifest document
    } else if (docId.endsWith(getEchoeyDocumentSuffix())) {
      // Don't echo any document that we created
    } else {
      String echoDocId = docId + getEchoeyDocumentSuffix();
      List<WaveletOperation> ops = Lists.newArrayList();

      // Echo the change to the other document
      ops.add(new WaveletDocumentOperation(echoDocId, documentOperation.getOperation()));

      // Write the document into the manifest if it isn't already there
      if (documentsSeen.get(wavelet.getWaveletName()).add(docId)) {
        BufferedDocOp manifest = wavelet.getDocuments().get(DocumentConstants.MANIFEST_DOCUMENT_ID);
        ops.add(ClientUtils.appendToManifest(manifest, echoDocId));
      }

      sendAndAwaitWaveletDelta(wavelet.getWaveletName(), new WaveletDelta(getParticipantId(), ops));
    }
  }

  /**
   * Append a new blip to a wavelet with the given contents.
   */
  private void appendText(WaveletData wavelet, String text) {
    String docId = getNewDocumentId() + getEchoeyDocumentSuffix();
    WaveletDelta delta = ClientUtils.createAppendBlipDelta(wavelet.getDocuments().get(
        DocumentConstants.MANIFEST_DOCUMENT_ID), getParticipantId(), docId, text);
    sendAndAwaitWaveletDelta(wavelet.getWaveletName(), delta);
  }

  @Override
  public void onParticipantAdded(WaveletData wavelet, ParticipantId participant) {
    LOG.info("onParticipantAdded: " + participant.getAddress());
    appendText(wavelet, participant.getAddress() + " was added to this wavelet.");
  }

  @Override
  public void onParticipantRemoved(WaveletData wavelet, ParticipantId participant) {
    LOG.info("onParticipantRemoved: " + participant.getAddress());
    appendText(wavelet, participant.getAddress() + " was removed from this wavelet.");
  }

  @Override
  public void onSelfAdded(WaveletData wavelet) {
    LOG.info("onSelfAdded: " + wavelet.getWaveletName());
    appendText(wavelet, "I'm listening.");
  }

  @Override
  public void onSelfRemoved(WaveletData wavelet) {
    LOG.info("onSelfRemoved: " + wavelet.getWaveletName());
    appendText(wavelet, "Goodbye.");
  }
}
