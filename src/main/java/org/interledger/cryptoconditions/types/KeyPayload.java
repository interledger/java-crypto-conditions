package org.interledger.cryptoconditions.types;

/*
 * wrapper arround byte[] to provide type safety.
 * 
 * Used to genereate public/private keys.
 */
public class KeySource {
	public final byte[] payload;
	public KeySource(byte[] source){
		this.payload = source.clone();
	}
}
