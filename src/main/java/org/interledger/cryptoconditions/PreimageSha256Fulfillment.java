package org.interledger.cryptoconditions;

import org.interledger.cryptoconditions.util.Crypto;

import java.util.EnumSet;

import org.interledger.cryptoconditions.impl.ConditionBase;

/**
 * Implementation of a PREIMAGE-SHA-256 crypto-condition fulfillment
 * 
 * TODO Safe synchronized access to members?
 * 
 * @author adrianhopebailie
 *
 */
public class PreimageSha256Fulfillment implements Fulfillment {
	
	private byte[] preimage;
			
	public PreimageSha256Fulfillment(byte[] preimage) {
		setPreimage(preimage);
	}

	public void setPreimage(byte[] preimage)
	{
		//TODO - Should this be immutable? Use ArrayCopy?
		this.preimage = preimage;
	}
	
	public byte[] getPreimage() {
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
	public ConditionBase generateCondition() {
		byte[] fingerprint = Crypto.getSha256Hash(preimage);
		int maxFulfillmentLength = preimage.length;
		EnumSet<FeatureSuite> features = EnumSet.of(FeatureSuite.SHA_256, FeatureSuite.PREIMAGE);
		return new ConditionBase(ConditionType.PREIMAGE_SHA256, features, fingerprint, maxFulfillmentLength);
	}
}
