package org.interledger.cryptoconditions.oer;

/**
 * Thrown if an illegal OER length indicator is encountered
 *
 * @author adrianhopebailie
 *
 */
public class IllegalOerLengthIndicatorException extends OerDecodingException {

  private static final long serialVersionUID = 2076963320466312387L;

  public IllegalOerLengthIndicatorException(String message) {
    super(message);
  }

}
