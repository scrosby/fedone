package wave.util.wavesig;

import org.rice.crosby.historytree.generated.Serialization.TreeSigBlob;
import org.waveprotocol.wave.examples.fedone.waveserver.ByteStringMessage;
import org.waveprotocol.wave.examples.fedone.waveserver.CertificateManager;
import org.waveprotocol.wave.federation.Proto.ProtocolWaveletDelta;

/** Bundle up a ByteStringMessage and a callback to be invoked when the messge is signed */

public class Message {
  final ByteStringMessage<ProtocolWaveletDelta> delta;
  final CertificateManager.SignatureResultListener resultListener;
  
  
  Message(ByteStringMessage<ProtocolWaveletDelta> delta,
      CertificateManager.SignatureResultListener resultListener) {
    this.delta = delta;
    this.resultListener = resultListener;
  }
  
  /** Return the hash value associated with the message that is to be signed. */
	byte [] getData() {
	  return delta.getByteArray();
	}
	
	/** Used by the message signing thread to set the signature when it is computed
	 * 
	 * Note, may be executed concurrently.
	 *
	 * @param message The protocol buffer message denoting the proof. May be null if proof generation failed.
	 * 
	 * */
	void signatureResult(TreeSigBlob message) {
	  // TODO: resultListener.signatureResult(message);
	}
}
