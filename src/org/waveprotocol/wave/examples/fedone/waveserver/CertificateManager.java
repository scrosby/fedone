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

import com.google.protobuf.ByteString;

import org.waveprotocol.wave.crypto.SignatureException;
import org.waveprotocol.wave.crypto.SignerInfo;
import org.waveprotocol.wave.crypto.UnknownSignerException;
import org.waveprotocol.wave.crypto.WaveSigner;
import org.waveprotocol.wave.federation.FederationErrorProto.FederationError;
import org.waveprotocol.wave.federation.Proto.ProtocolHashedVersion;
import org.waveprotocol.wave.federation.Proto.ProtocolSignedDelta;
import org.waveprotocol.wave.federation.Proto.ProtocolSignerInfo;
import org.waveprotocol.wave.federation.Proto.ProtocolWaveletDelta;
import org.waveprotocol.wave.model.id.WaveletName;
import org.waveprotocol.wave.waveserver.WaveletFederationProvider;

import java.util.Set;

/**
 * Interface for the certificate manager.
 */
public interface CertificateManager {

  Set<String> getLocalDomains();

  /**
   * @return the signer info for the local wave signer.
   */
  WaveSigner getLocalSigner();

  /**
   * Signatures are generated asynchronously. They may be batched into trees and signed in
   * one go. The result will contain all necessary info to send the delta off independently
   * (i.e. the signature tree will have been winnowed, refer
   * http://www.waveprotocol.org/whitepapers/wave-protocol-verification)
   */
  interface SignatureResultListener {
    /**
     * Process the result of a signing. The callee may perform work on the thread.
     * @param signedDelta the delta with signature.
     */
    void signatureResult(ProtocolSignedDelta signedDelta);
  }

  /**
   * Verify the signature in the Signed Delta. Use the local WSP's certificate
   * to sign the delta.
   *
   * @param delta as a byte string (the serialised representation of a ProtocolWaveletDelta)
   * @param resultListener is a callback for receiving the result.
   */
  void signDelta(ByteStringMessage<ProtocolWaveletDelta> delta,
      SignatureResultListener resultListener);


  /**
   * Verify the signature in the Signed Delta. Use the delta's author's WSP
   * address to identify the certificate.
   *
   * @param signedDelta to verify
   * @return verified serialised ProtocolWaveletDelta, if signatures can be verified
   * @throws SignatureException if the signatures cannot be verified.
   */
  ByteStringMessage<ProtocolWaveletDelta> verifyDelta(ProtocolSignedDelta signedDelta)
      throws SignatureException, UnknownSignerException;

  /**
   * Stores information about a signer (i.e., its certificate chain) in a
   * permanent store. In addition to a certificate chain, a {@link SignerInfo}
   * also contains an identifier of hash algorithm. Signers will use the hash
   * of the cert chain to refer to this signer info in their signatures.
   *
   * @param signerInfo
   * @throws SignatureException if the {@link SignerInfo} doesn't check out
   */
  void storeSignerInfo(ProtocolSignerInfo signerInfo) throws SignatureException;

  /**
   * Retrieves information about a signer.
   *
   * @param signerId identifier of the signer (the hash of its certificate chain)
   * @return the signer information, if found, null otherwise
   */
  ProtocolSignerInfo retrieveSignerInfo(ByteString signerId);

  /**
   * Callback interface for {@code prefetchSignerInfo}.
   */
  interface SignerInfoPrefetchResultListener {
    void onSuccess(ProtocolSignerInfo signerInfo);
    void onFailure(FederationError error);
  }

  /**
   * Prefetch the signer info for a signed delta, calling back when the signer info is available.
   * Note that the signer info may be immediately available, in which case the callback is
   * immediately called in the same thread.
   *
   * @param provider of signer information
   * @param signerId to prefetch the signer info for
   * @param deltaEndVersion of delta to use for validating a getDeltaSignerInfo call, if necessary
   * @param waveletName of the wavelet to prefetch the signer info for
   * @param callback when the signer info is available, or on failure
   */
  void prefetchDeltaSignerInfo(WaveletFederationProvider provider, ByteString signerId,
      WaveletName waveletName, ProtocolHashedVersion deltaEndVersion,
      SignerInfoPrefetchResultListener callback);
}
