package org.interledger.cryptoconditions;

import java.util.Arrays;

import java.util.EnumSet;

import org.interledger.cryptoconditions.util.Crypto;
import org.interledger.cryptoconditions.types.FulfillmentPayload;

/**
 * Implementation of a PREIMAGE-SHA-256 crypto-condition fulfillment
 * 
 * TODO Safe synchronized access to members?
 * 
 * @author adrianhopebailie
 *
 */
public class PreimageSha256Fulfillment extends FulfillmentBase {

	public PreimageSha256Fulfillment(ConditionType type, FulfillmentPayload payload) {
		super(type, payload);
	}

	private static EnumSet<FeatureSuite> BASE_FEATURES = EnumSet.of(
			FeatureSuite.SHA_256, 
			FeatureSuite.PREIMAGE
		);

	public byte[] getPreimage() {
		byte[] result = Arrays.copyOf(payload.payload, payload.payload.length);
		return result;
	}
	
	@Override
	public ConditionType getType() {
		return ConditionType.PREIMAGE_SHA256;
	}

	@Override
	public FulfillmentPayload getPayload() {
		return new FulfillmentPayload(getPreimage());
	}

	@Override
	public Condition generateCondition(FulfillmentPayload payload) {
		byte[] fingerprint = Crypto.getSha256Hash(this.getPreimage());
		int maxFulfillmentLength = this.getPreimage().length;
	
		return new ConditionImpl(
				ConditionType.PREIMAGE_SHA256, 
				BASE_FEATURES, 
				fingerprint, 
				maxFulfillmentLength);
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
