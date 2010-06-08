package wave.util.wavesig;

import java.util.ArrayList;

import org.rice.crosby.batchsig.MerkleQueue;
import org.rice.crosby.batchsig.Message;
import org.rice.crosby.batchsig.QueueBase;
import org.rice.crosby.batchsig.SignaturePrimitives;
import org.rice.crosby.historytree.AggregationInterface;
import org.rice.crosby.historytree.MerkleTree;
import org.rice.crosby.historytree.ProofError;
import org.rice.crosby.historytree.aggs.SHA256Agg;
import org.rice.crosby.historytree.generated.Serialization.PrunedTree;
import org.rice.crosby.historytree.generated.Serialization.SigTreeType;
import org.rice.crosby.historytree.generated.Serialization.TreeSigBlob;
import org.rice.crosby.historytree.generated.Serialization.TreeSigMessage;
import org.rice.crosby.historytree.generated.Serialization.SignatureType;
import org.rice.crosby.historytree.storage.ArrayStore;
import org.rice.crosby.historytree.storage.HashStore;
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
