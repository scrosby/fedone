package wave.util.wavesig;

import java.util.ArrayList;
//edu.rice.batchsig.
import edu.rice.batchsig.MerkleQueue;
import edu.rice.batchsig.Message;
import edu.rice.batchsig.QueueBase;
import edu.rice.batchsig.SignaturePrimitives;
import edu.rice.historytree.AggregationInterface;
import edu.rice.historytree.MerkleTree;
import edu.rice.historytree.ProofError;
import edu.rice.historytree.aggs.SHA256Agg;
import edu.rice.historytree.generated.Serialization.PrunedTree;
import edu.rice.historytree.generated.Serialization.SigTreeType;
import edu.rice.historytree.generated.Serialization.TreeSigBlob;
import edu.rice.historytree.generated.Serialization.TreeSigMessage;
import edu.rice.historytree.generated.Serialization.SignatureType;
import edu.rice.historytree.storage.ArrayStore;
import edu.rice.historytree.storage.HashStore;
import org.waveprotocol.wave.crypto.WaveSigner;
import org.waveprotocol.wave.examples.fedone.waveserver.ByteStringMessage;
import org.waveprotocol.wave.examples.fedone.waveserver.DeltaSigner;
import org.waveprotocol.wave.examples.fedone.waveserver.CertificateManager.SignatureResultListener;
import org.waveprotocol.wave.federation.Proto.ProtocolSignature;
import org.waveprotocol.wave.federation.Proto.ProtocolWaveletDelta;

import com.google.protobuf.ByteString;

public class SignerQueue extends MerkleQueue implements DeltaSigner {
	private WaveSigner signer;

	public SignerQueue(WaveSigner signer) {
	  super(null); // TODO, pass it a signer object
		this.signer=signer;
	}
  @Override
  public void sign(ByteStringMessage<ProtocolWaveletDelta> delta,
      SignatureResultListener resultListener) {
    add(new WaveMessage(delta,resultListener));
  }
}
