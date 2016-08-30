package org.interledger.cryptoconditions;

import java.io.ByteArrayOutputStream;

import java.io.IOException;
import java.util.EnumSet;

import org.interledger.cryptoconditions.encoding.ConditionOutputStream;
import org.interledger.cryptoconditions.encoding.FulfillmentOutputStream;
import org.interledger.cryptoconditions.util.Crypto;
import org.interledger.cryptoconditions.types.FulfillmentPayload;

/**
 * Implementation of a PREFIX-SHA-256 crypto-condition fulfillment
 * 
 * TODO Safe synchronized access to members?
 * 
 * @author adrianhopebailie
 *
 */
public class PrefixSha256Fulfillment extends FulfillmentBase {

	public PrefixSha256Fulfillment(ConditionType type, FulfillmentPayload payload) {
		super(type, payload);
	}

	private static EnumSet<FeatureSuite> BASE_FEATURES = EnumSet.of(
			FeatureSuite.SHA_256, 
			FeatureSuite.PREFIX
		);

	private byte[] prefix;
	private Fulfillment subfulfillment;
	
	// TODO:(0) There are two different use-cases with two different constructors:
	//   prefix, subfulfillment (or subfulfillmentURI) 
	//   prefix, condition      (or conditionURI     )
	public PrefixSha256Fulfillment(byte[] prefix, Fulfillment subfulfillment) {
		setPrefix(prefix);
		setSubFulfillment(subfulfillment);
        // TODO:(0) Init this.payload, this.condition
	}

	public void setPrefix(byte[] prefix)
	{
		//TODO - Should this be immutable? Use ArrayCopy?
		this.prefix = prefix.clone();
		// this.payload = null; TODO:(0)
	}
	
	public byte[] getPrefix() {
		//TODO - Should this object be immutable? Use ArrayCopy?
		return prefix;
	}
			
	public void setSubFulfillment(Fulfillment fulfillment)
	{
		this.subfulfillment = fulfillment;
		// this.payload = null; TODO:(0)
	}
	
	public Fulfillment getSubFulfillment()
	{
		return subfulfillment;
	}
	
	@Override
	public ConditionType getType() {
		return ConditionType.PREFIX_SHA256;
	}

	@Override
	public FulfillmentPayload getPayload() {
		// TODO:(0) Use super class.?
		return payload;
	}

	@Override
	public Condition generateCondition(FulfillmentPayload payload) {
		// TODO:(0) parse subfulfillment
		if (subfulfillment == null ) {
			// TODO:(0)
//			parsePayload (reader) {
//				this.setPrefix(reader.readVarOctetString())
//				this.setSubfulfillment(Fulfillment.fromBinary(reader))
//			}
		}
		Condition subcondition = subfulfillment.generateCondition(payload);
		
		EnumSet<FeatureSuite> features = subcondition.getFeatures();
		features.addAll(BASE_FEATURES);

		byte[] fingerprint = Crypto.getSha256Hash(
				calculateFingerPrintContent(
					prefix, 
					subcondition
				)
			);
		
		int maxFulfillmentLength = calculateMaxFulfillmentLength(
				prefix, 
				subcondition
			);
		
		return new ConditionImpl(
				ConditionType.PREFIX_SHA256, 
				features, 
				fingerprint, 
				maxFulfillmentLength);
	}
	
	protected byte[] calculatePayload()
	{
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		FulfillmentOutputStream stream = new FulfillmentOutputStream(buffer);
		
		try {
			stream.writeOctetString(prefix);
			stream.writeFulfillment(subfulfillment);
			stream.flush();
			return buffer.toByteArray();
		} catch (IOException e) {
			throw new RuntimeException(e);
		} finally {
			try {
				stream.close();
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}
	}

	private byte[] calculateFingerPrintContent(byte[] prefix, Condition subcondition)
	{
		
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		ConditionOutputStream stream = new ConditionOutputStream(buffer);
		
		try {
			stream.writeOctetString(prefix);
			stream.writeCondition(subcondition);
			stream.flush();
			return buffer.toByteArray();
		} catch (IOException e) {
			throw new RuntimeException(e);
		} finally {
			try {
				stream.close();
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}
	}
	
	private int calculateMaxFulfillmentLength(byte[] prefix, Condition subcondition)
	{
		int length = prefix.length;
		if(length < 128)
		{
			length = length + 1;
		} else if(length <= 255) {
			length = length + 2;
		} else if (length <= 65535) {
			length = length + 3;
		} else if (length <= 16777215){
			length = length + 4;
		} else {
			throw new IllegalArgumentException("Field lengths of greater than 16777215 are not supported.");
		}
		return length + subcondition.getMaxFulfillmentLength();
	}

	@Override
	public boolean validate(byte[] message) {
		if (this.subfulfillment == null)
			throw new RuntimeException("subfulfillment not yet initialized ");
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
		try {
			outputStream.write( this.prefix);
			outputStream.write( message );
		} catch (IOException e) {
			throw new RuntimeException(e.toString());
		}
		
		return this.subfulfillment.validate(outputStream.toByteArray());
	}
}
