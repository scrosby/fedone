package wave.util.wavesig;

import edu.rice.batchsig.Message;
import edu.rice.historytree.generated.Serialization.TreeSigBlob;
import org.waveprotocol.wave.examples.fedone.waveserver.ByteStringMessage;
import org.waveprotocol.wave.examples.fedone.waveserver.CertificateManager;
import org.waveprotocol.wave.federation.Proto.ProtocolWaveletDelta;

/** Bundle up a ByteStringMessage and a callback to be invoked when the messge is signed */

public class WaveMessage implements Message {
  final ByteStringMessage<ProtocolWaveletDelta> delta;
  final CertificateManager.SignatureResultListener resultListener;
  
  
  WaveMessage(ByteStringMessage<ProtocolWaveletDelta> delta,
      CertificateManager.SignatureResultListener resultListener) {
    this.delta = delta;
    this.resultListener = resultListener;
  }
  
  /** Return the hash value associated with the message that is to be signed. */
	public byte [] getData() {
	  return delta.getByteArray();
	}
	
	/** Used by the message signing thread to set the signature when it is computed
	 * 
	 * Note, may be executed concurrently.
	 *
	 * @param message The protocol buffer message denoting the proof. May be null if proof generation failed.
	 * 
	 * */
	public void signatureResult(TreeSigBlob message) {
	  // TODO: resultListener.signatureResult(message);
	}

  @Override
  public Object getRecipient() {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public TreeSigBlob getSignatureBlob() {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public Object getAuthor() {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public void signatureValidity(boolean valid) {
    // TODO Auto-generated method stub
    
  }
}
