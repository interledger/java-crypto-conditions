package org.interledger.cryptoconditions.impl;

import java.util.EnumSet;

import org.interledger.cryptoconditions.Condition;
import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.FeatureSuite;

public class ConditionBase  implements Condition {

	private ConditionType type;
	private EnumSet<FeatureSuite> features;
	private byte[] fingerprint;
	private int maxFulfillmentLength;

	private ConditionBase() {
		/* Avoid default constructor => Force parameterized constructor */
	}

	public ConditionBase(ConditionType type, EnumSet<FeatureSuite> features, byte[] fingerprint,  
			int maxFulfillmentLength) {
		if (type        == null) throw new RuntimeException("null type not allowed"           );
		if (fingerprint == null) throw new RuntimeException("null fingerprint not allowed"    );
		if (features    == null) throw new RuntimeException("features fingerprint not allowed");
		if (maxFulfillmentLength < 0) throw new RuntimeException("maxFulfillmentLength can't be negative");
		// TODO:(0) maxFulfillmentLength can be empty/zero-length ?
		// TODO:(0) fingerprint          can be empty/zero-length ?
		// TODO:(0) features.isEmpty()   allowed ?

		this.type = type;
		this.fingerprint = fingerprint;
		this.features = features;
	}

	public ConditionType getType() {
		return this.type;
	}
	

	public EnumSet<FeatureSuite> getFeatures(){
		return this.features;
	}
	

	public byte[] getFingerprint(){
		return this.fingerprint;
	}

	public int getMaxFulfillmentLength() {
		return this.maxFulfillmentLength;
	}
}
