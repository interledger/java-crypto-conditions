package org.interledger.cryptoconditions;

import java.util.EnumSet;


import org.interledger.cryptoconditions.Condition;
import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.FeatureSuite;
import org.interledger.cryptoconditions.encoding.Base64Url;

public final class ConditionImpl implements Condition {

    // Condition Interface related members 
    private final ConditionType type;
    private final EnumSet<FeatureSuite> features;
    private final byte[] fingerprint;
    private final int maxFulfillmentLength;

    // URISerializable Interface related members
    private static final String CONDITION_REGEX = "^cc:([1-9a-f][0-9a-f]{0,3}|0):[1-9a-f][0-9a-f]{0,15}:[a-zA-Z0-9_-]{0,86}:([1-9][0-9]{0,17}|0)$";
    private static final java.util.regex.Pattern p = java.util.regex.Pattern.compile(CONDITION_REGEX);
    
    @SuppressWarnings("unused")
    private ConditionImpl() {
        throw new RuntimeException("This constructor must never be called");
    };
    
    public ConditionImpl(ConditionType type, EnumSet<FeatureSuite> features, byte[] fingerprint,  
            int maxFulfillmentLength) {
        if (type == null) 
            throw new IllegalArgumentException("Type cannot be null.");
        if (fingerprint == null) 
            throw new IllegalArgumentException("Fingerprint cannot be null.");
        if (features == null) 
            throw new IllegalArgumentException("Features cannot be null.");
        if (maxFulfillmentLength < 0) 
            throw new IllegalArgumentException("MaxFulfillmentLength can't be negative.");
        
        // TODO:(0) maxFulfillmentLength can be empty/zero-length ?
        // TODO:(0) fingerprint          can be empty/zero-length ?
        // TODO:(0) features.isEmpty()   allowed ?

        this.type = type;
        this.fingerprint = fingerprint;
        this.features = features;
        this.maxFulfillmentLength = maxFulfillmentLength;
    }

    public ConditionImpl(String URI) {
        if (URI == null)
            throw new RuntimeException("serializedCondition == null");
        if ("".equals(URI.trim()))
            throw new RuntimeException("serializedCondition was an empy string");
        if (!URI.startsWith("cc:"))
            throw new RuntimeException("serializedCondition must start with 'cc:'");
        
        java.util.regex.Matcher m = p.matcher(URI);
        if (!m.matches())
            throw new RuntimeException(
                    "serializedCondition '" + URI + "' doesn't match " + ConditionImpl.CONDITION_REGEX);

        String[] pieces = URI.split(":");
        if (pieces.length != 5) 
            throw new RuntimeException("The URI for the condition '"+URI+"' was expected to contain 5 fields separated by ':'");

        String BASE16Type = pieces[1], BASE16FeatureBitMask = pieces[2], 
                BASE64URLFingerprint = pieces[3], BASE10MaxFulfillmentLength = pieces[4];
        
        this.type = ConditionType.valueOf(Integer.parseInt(BASE16Type , 16));
        this.features = FeatureSuite.bitMask2EnumSet(Integer.parseInt(BASE16FeatureBitMask, 16));
        this.fingerprint = Base64Url.decode(BASE64URLFingerprint);
        this.maxFulfillmentLength = Integer.parseInt(BASE10MaxFulfillmentLength);
    }

    @Override
    public ConditionType getType() {
        return this.type;
    }
    
    @Override
    public EnumSet<FeatureSuite> getFeatures(){
        return this.features.clone();
    }
    

    @Override
    public byte[] getFingerprint(){
        return this.fingerprint;
    }

    @Override
    public int getMaxFulfillmentLength() {
        return this.maxFulfillmentLength;
    }
    
    @Override
    public String toURI() {
        return     "cc"
                + ":" + Integer.toHexString(this.getType().getTypeCode())
                + ":" + Integer.toHexString(FeatureSuite.EnumSet2bitMask(this.getFeatures())) 
                + ":" + Base64Url.encode(this.getFingerprint())
                + ":" + Integer.toString(this.getMaxFulfillmentLength());
    }
    
    public String toString() {
        return toURI();
    }
}