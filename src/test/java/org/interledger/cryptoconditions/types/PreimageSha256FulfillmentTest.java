package org.interledger.cryptoconditions.types;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.Fulfillment;
import org.junit.Test;

/**
 * Unit tests {@link PreimageSha256Fulfillment}.
 */
public class PreimageSha256FulfillmentTest {

  @Test(expected = NullPointerException.class)
  public void testNullConstructor() throws Exception {
    new PreimageSha256Fulfillment(null);
  }

  @Test
  public void testGettersAndSetters() throws Exception {
    final PreimageSha256Fulfillment actual = new PreimageSha256Fulfillment(
        "Hello World".getBytes());

    //assertThat(actual.getCondition(), is(expectedCondition));
    //assertThat(actual.getEncoded(), is(expectedCondition));
    assertThat(actual.getPreimage(), is("Hello World".getBytes()));
    assertThat(actual.getType(), is(ConditionType.PREIMAGE_SHA256));
  }

  @Test
  public void equalsHashcode() throws Exception {
    final PreimageSha256Fulfillment fulfillment1 = new PreimageSha256Fulfillment(
        "Hello World".getBytes());
    final PreimageSha256Fulfillment fulfillment2 = new PreimageSha256Fulfillment(
        "Hello World".getBytes());
    final PreimageSha256Fulfillment fulfillment3 = new PreimageSha256Fulfillment(
        "Hello Earth".getBytes());

    this.equalityHashcodeAssertionHelper(fulfillment1, fulfillment2, fulfillment3);

    // Condition is currently lazily-initialized, so we want to ensure equality and hashcode work
    // properly at all times.
    fulfillment1.getCondition();
    this.equalityHashcodeAssertionHelper(fulfillment1, fulfillment2, fulfillment3);

    // Condition is currently lazily-initialized, so we want to ensure equality and hashcode work
    // properly at all times.
    fulfillment2.getCondition();
    this.equalityHashcodeAssertionHelper(fulfillment1, fulfillment2, fulfillment3);

    // Condition is currently lazily-initialized, so we want to ensure equality and hashcode work
    // properly at all times.
    fulfillment3.getCondition();
    this.equalityHashcodeAssertionHelper(fulfillment1, fulfillment2, fulfillment3);
  }

  private void equalityHashcodeAssertionHelper(final Fulfillment fulfillment1,
      final Fulfillment fulfillment2, final Fulfillment fulfillment3) {
    assertThat(fulfillment1.equals(fulfillment1), is(true));
    assertThat(fulfillment2.equals(fulfillment2), is(true));
    assertThat(fulfillment3.equals(fulfillment3), is(true));

    assertThat(fulfillment1.equals(fulfillment2), is(true));
    assertThat(fulfillment1.equals(fulfillment3), is(false));

    assertThat(fulfillment2.equals(fulfillment1), is(true));
    assertThat(fulfillment2.equals(fulfillment3), is(false));

    assertThat(fulfillment3.equals(fulfillment1), is(false));
    assertThat(fulfillment3.equals(fulfillment2), is(false));

    assertThat(fulfillment1.hashCode(), is(fulfillment2.hashCode()));
    assertThat(fulfillment1.hashCode() == fulfillment3.hashCode(), is(false));
  }
}