package org.interledger.cryptoconditions;

import java.util.EnumSet;


import org.interledger.cryptoconditions.encoding.Base64Url;

public abstract class FulfillmentBase  implements Fulfillment {

	protected final byte[] payload;	
	protected final Condition condition;

	/*
	 * Default constructor. Raise exception to force use of child classes.
	 */
	FulfillmentBase() {
		throw new RuntimeException("Use a child class constructor");
	}
	
	/*
	 * Create from URI-encoded string
	 */
	public FulfillmentBase(ConditionType type, byte[] payload) {
		this.payload = payload;
		if (! type.equals(this.getType())) {
			throw new RuntimeException("Implementation error. Type mismatch. "
					+ "Expected "+this.getType()+" but URI indicates "+type.toString());
		}
		this.condition = this.generateCondition(payload);
	}

	
	@Override
	public ConditionType getType() {
		throw new RuntimeException("getType called in abstract parent class FulfillmentBase");
	}

	@Override
	public byte[] getPayload() {
		if (this.payload == null)
			throw new RuntimeException("Payload not YET initialized");
		
		return this.payload;
	}
	
	@Override
	public EnumSet<FeatureSuite> getFeatures() {
		if (this.condition == null)
			throw new RuntimeException("condition not YET initialized");
		return this.condition.getFeatures();
	}


	@Override
	public String toURI() {
		return 	"cf"
				+ ":" + Integer.toHexString(this.getType().getTypeCode())
				+ ":" + Base64Url.encode(this.getPayload());
	}
	
	@Override
	public String toString() {
		return toURI();
	}	

}
