package org.interledger.cryptoconditions;

public class FulfillmentRegistry {

	public static java.util.Map<ConditionType, Class<?>> typeRegistry =
			new java.util.LinkedHashMap<ConditionType, Class<?>>();

	static {
		typeRegistry.put(PrefixSha256Fulfillment  .CONDITION_TYPE , PrefixSha256Fulfillment  .class);
		typeRegistry.put(PreimageSha256Fulfillment.CONDITION_TYPE , PreimageSha256Fulfillment.class);
		// TODO:(0) Add the other conditions.
	}
	
	public static Class<?>  getClass(ConditionType type){
		Class<?> result = typeRegistry.get(type);
		if (result == null) {
			throw new RuntimeException(
				"There is no Fulfillment class associated to the ConditionType "+type + " in the registry");
		}
		return result;
	}
}
