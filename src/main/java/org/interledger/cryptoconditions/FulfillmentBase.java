package org.interledger.cryptoconditions;

import java.util.EnumSet;

import org.interledger.cryptoconditions.encoding.Base64Url;

public abstract class FulfillmentBase  implements Fulfillment {

	private static final String FULFILLMENT_REGEX = "^cf:([1-9a-f][0-9a-f]{0,3}|0):[a-zA-Z0-9_-]*$";
	private static final java.util.regex.Pattern p = java.util.regex.Pattern.compile(FULFILLMENT_REGEX);

	private final byte[] payload;
	private final Condition condition;

	
	/*
	 * Default constructor. Raise exception to force use of child classes.
	 */
	FulfillmentBase() {
		throw new RuntimeException("Use a child class constructor");
	}
	
	/*
	 * Create from URI-encoded string
	 */
	FulfillmentBase(String URI) {
		// TODO:(0) we must call this constructor in a subclass instance. For that we need first to read the type.
		// This means than an auxiliary Factory for Fulfillments is needed.
		if (URI == null)
			throw new RuntimeException("serializedFulfillment == null");
		if ("".equals(URI.trim()))
			throw new RuntimeException("serializedFulfillment was an empy string");
		if (!URI.startsWith("cf:"))
			throw new RuntimeException("serializedFulfillment must start with 'cf:'");

		java.util.regex.Matcher m = p.matcher(URI);
		if (!m.matches())
			throw new RuntimeException(
					"serializedFulfillment '" + URI + "' doesn't match " + FulfillmentBase.FULFILLMENT_REGEX);
		String[] pieces = URI.split(":");
		
		String BASE16Type = pieces[1];
		String BASE64URLPayload = pieces[2];
		
		ConditionType type = ConditionType.valueOf(Integer.parseInt(BASE16Type, 16));
		if (! type.equals(this.getType())) {
			throw new RuntimeException("Implementation error. Type mismatch. "
					+ "Expected "+this.getType()+" but URI indicates "+type.toString());
		}

		this.payload = Base64Url.decode(BASE64URLPayload);
		this.condition = this.generateCondition();
	}
	abstract protected byte[] calculatePayload();
	
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

}
