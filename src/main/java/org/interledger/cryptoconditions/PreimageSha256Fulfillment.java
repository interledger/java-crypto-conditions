package org.interledger.cryptoconditions;

import java.util.EnumSet;

import org.interledger.cryptoconditions.util.Crypto;

/**
 * Implementation of a PREIMAGE-SHA-256 crypto-condition fulfillment
 * 
 * TODO Safe synchronized access to members?
 * 
 * @author adrianhopebailie
 *
 */
public class PreimageSha256Fulfillment extends FulfillmentBase {

	public static final ConditionType CONDITION_TYPE = ConditionType.PREIMAGE_SHA256;
	
	private static EnumSet<FeatureSuite> BASE_FEATURES = EnumSet.of(
			FeatureSuite.SHA_256, 
			FeatureSuite.PREIMAGE
		);

	private byte[] preimage = null; // TODO:(0) Remove null
			
	public PreimageSha256Fulfillment(byte[] preimage) {
		setPreimage(preimage);
	}

	public void setPreimage(byte[] preimage)
	{
		//TODO - Should this be immutable? Use ArrayCopy?
		this.preimage = preimage;
	}
	
	public byte[] getPreimage() {
		if (preimage == null) 
			throw new RuntimeException("preimage not YET initialized");
		//TODO - Should this object be immutable? Use ArrayCopy?
		return preimage;
	}
	
	@Override
	public ConditionType getType() {
		return ConditionType.PREIMAGE_SHA256;
	}

	@Override
	public byte[] getPayload() {
		return getPreimage();
	}

	@Override
	public Condition generateCondition() {
		byte[] fingerprint = Crypto.getSha256Hash(preimage);
		int maxFulfillmentLength = preimage.length;
	
		return new ConditionImpl(
				CONDITION_TYPE, 
				BASE_FEATURES, 
				fingerprint, 
				maxFulfillmentLength);
	}
	
	@Override
	protected byte[] calculatePayload() {
		return getPreimage();
	}
	
	/**
	 * Validate this fulfillment.
	 *
	 * Copy&Paste from five-bells-condition/src/types/preimage-sha256.js:
	 * """
	 * For a SHA256 hashlock fulfillment, successful parsing implies that the
	 * fulfillment is valid, so this method is a no-op.
	 * """
	 *
	 * @param {byte[]} Message (ignored in this condition type)
	 * @return {boolean} Validation result
	 */
	@Override
	public boolean validate(byte[] message) {
		return true;
	}
}
