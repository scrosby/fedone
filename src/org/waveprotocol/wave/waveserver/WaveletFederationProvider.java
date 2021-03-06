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
import org.waveprotocol.wave.federation.Proto.ProtocolSignedDelta;
import org.waveprotocol.wave.federation.Proto.ProtocolSignerInfo;
import org.waveprotocol.wave.model.id.WaveletName;

import java.util.List;

/**
 * These are the methods supported by a Wavelet Federation Provider:
 * it acts as a host of wavelets i.e. the WaveServer and Federation Remote.
 *
 *
 */
public interface WaveletFederationProvider {
  /**
   * Request submission of signed delta.
   *
   * @param waveletName name of wavelet.
   * @param delta delta signed by the submitting WSP.
   * @param listener callback for the result.
   */
  void submitRequest(WaveletName waveletName, ProtocolSignedDelta delta,
      SubmitResultListener listener);

  /**
   * Retrieve delta history for the given wavelet.
   *
   * @param waveletName name of wavelet.
   * @param domain the domain of the requester, used to determine whether there is
   *        a user on the wavelet matching the domain to the requester.
   * @param startVersion beginning of range (inclusive), minimum 0.
   * @param endVersion end of range (exclusive).
   * @param lengthLimit estimated size, in bytes, as an upper limit on the amount of data
   *        returned.
   * @param listener callback for the result.
   */
  void requestHistory(WaveletName waveletName, String domain,
      ProtocolHashedVersion startVersion, ProtocolHashedVersion endVersion,
      long lengthLimit, HistoryResponseListener listener);

  interface HistoryResponseListener {
    /**
     * @param deltaList of serialised {@code ProtocolAppliedWaveletDelta}s, represented as
     *        {@code ByteString}s.  Note that these are not guaranteed to parse correctly as
     *        applied deltas, so it is up to the implementation of onSuccess to deal with this.
     * @param lastCommittedVersion of the wavelet that is committed to persistent
     *        storage, if smaller than the end version of deltas, null otherwise
     * @param versionTruncatedAt the end version of the deltas if less than the
     *        requested endVersion in the call to {@code requestHistory}
     */
    void onSuccess(List<ByteString> deltaList,
                   ProtocolHashedVersion lastCommittedVersion, long versionTruncatedAt);
    void onFailure(FederationError errorMessage);
  }

  /**
   * Retrieve info for a signer of an applied delta.
   *
   * This is called by a federation remote when it receives an applied delta from
   * a call to requestHistory or from a wavelet update and it doesn't already have
   * the info for a signer of the delta.
   *
   * If you host a wavelet, you MUST maintain a copy of the SignerInfo of every signer used to
   * sign any applied delta in the delta history and serve it to anyone who knows the hashed
   * version of the wavelet immediately after the delta was applied.
   *
   * @param signerId the identifier of the signer (the hash of its certificate chain)
   * @param waveletName name of wavelet that the delta belongs to.
   * @param deltaEndVersion the version of the wavelet immediately after the delta was applied.
   * @param listener callback for the result.
   */
  void getDeltaSignerInfo(ByteString signerId,
      WaveletName waveletName, ProtocolHashedVersion deltaEndVersion,
      DeltaSignerInfoResponseListener listener);

  interface DeltaSignerInfoResponseListener {
    void onSuccess(ProtocolSignerInfo signerInfo);
    void onFailure(FederationError errorMessage);
  }

  /**
   * Post signer info. This should be called in advance of any call to submitRequest
   * with a delta signed by the signer with this info.
   *
   * @param destinationDomain the domain to post this signer info to.
   * @param signerInfo info of a signer.
   * @param listener callback for the result.
   */
  void postSignerInfo(String destinationDomain, ProtocolSignerInfo signerInfo,
      PostSignerInfoResponseListener listener);

  interface PostSignerInfoResponseListener {
    void onSuccess();
    void onFailure(FederationError errorMessage);
  }
}
