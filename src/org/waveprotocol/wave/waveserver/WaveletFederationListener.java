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

package org.waveprotocol.wave.waveserver;

import com.google.protobuf.ByteString;

import org.waveprotocol.wave.federation.FederationErrorProto.FederationError;
import org.waveprotocol.wave.federation.Proto.ProtocolHashedVersion;
import org.waveprotocol.wave.model.id.WaveletName;

import java.util.List;

/**
 * These are the methods supported by a Wavelet Federation Listener:
 * it acts as a receiver of updates i.e. the WaveServer receives from
 * a Federation Remote or Federation Remote receives from a Federation Host.
 *
 *
 */
public interface WaveletFederationListener {

  /**
   * Factory interface for retrieving instantiations.
   */
  interface Factory {
    /**
     * @param domain the recipient domain for the updates
     */
    WaveletFederationListener listenerForDomain(String domain);
  }

  /**
   * This message is passed when one or more new deltas are applied to a specific wavelet.
   *
   * @param waveletName name of wavelet.
   * @param deltas UNTRANSFORMED, {@code ByteString} serialised representation of {@code
   *        ProtocolAppliedWaveletDelta}s that were applied to the given wavelet. Note that the
   *        deltas are NOT TRANSFORMED to the current version of the wavelet. May be empty if
   *        committedVersion is not null, namely when the caller only wants to communicate that the
   *        wavelet was committed.
   * @param callback is eventually invoked when the callee has processed the information or failed
   *        to do so.
   */
  void waveletDeltaUpdate(WaveletName waveletName, List<ByteString> deltas,
      WaveletUpdateCallback callback);

  /**
   * This message is passed if the wavelet is committed to persistent storage.
   *
   * @param waveletName name of wavelet.
   * @param committedVersion notifies the listener that hosting provider has reliably
   *        committed the wavelet to persistent storage up to the specified version.
   * @param callback is eventually invoked when the callee has processed the information or failed
   *        to do so.
   */
  void waveletCommitUpdate(WaveletName waveletName, ProtocolHashedVersion committedVersion,
      WaveletUpdateCallback callback);

  /**
   * Is eventually called by the callee of waveletUpdate().
   * If the committedVersion of the corresponding waveletUpdate() call was not null, then
   * (1) an onSuccess() call implies that this information was persisted by the
   * waveletUpdate() callee so the caller need not call it again, whereas
   * (2) an onFailure() call obligates the caller to repeat the call, eventually.
   *
   * TODO: refine this "SLA" (can't keep re-calling in all eternity)
   */
  interface WaveletUpdateCallback {
    void onSuccess();
    void onFailure(FederationError error);
  }
}
