package org.interledger.cryptoconditions.oer;

import static org.junit.Assert.*;

import java.io.IOException;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;

import org.junit.Test;

public class TestOerDecode {

  private PipedOutputStream outputStream;
  private PipedInputStream pipedStream;
  private OerInputStream oerStream;

  private final void setupStreams() throws IOException {
    outputStream = new PipedOutputStream();
    pipedStream = new PipedInputStream(outputStream);
    oerStream = new OerInputStream(pipedStream);
  }

  public final void closeStreams() throws IOException {
    try {
      oerStream.close();
    } finally {
      try {
        pipedStream.close();
      } finally {
        outputStream.close();
      }
    }
  }

  @Test
  public final void testRead8BitUInt() throws IOException {

    setupStreams();

    outputStream.write(new byte[] {(byte) 0x00, // 0
        (byte) 0x01, // 1
        (byte) 0x80, // 128
        (byte) 0x81, // 129
        (byte) 0xFF, // 255
    });
    outputStream.flush();

    assertEquals(0, oerStream.read8BitUInt());
    assertEquals(1, oerStream.read8BitUInt());
    assertEquals(128, oerStream.read8BitUInt());
    assertEquals(129, oerStream.read8BitUInt());
    assertEquals(255, oerStream.read8BitUInt());

    // TODO Ensure we have consumed all bytes

    closeStreams();
  }

  @Test
  public final void testRead16BitUInt() throws IOException {

    setupStreams();

    outputStream.write(new byte[] {(byte) 0x00, (byte) 0x00, // 0
        (byte) 0x00, (byte) 0x01, // 1
        (byte) 0x00, (byte) 0x80, // 128
        (byte) 0x00, (byte) 0x81, // 129
        (byte) 0x00, (byte) 0xFF, // 255
        (byte) 0x01, (byte) 0x00, // 256
        (byte) 0x01, (byte) 0x01, // 257
        (byte) 0x80, (byte) 0xFF, // 33023
        (byte) 0xFF, (byte) 0xFF, // 65535
    });
    outputStream.flush();

    assertEquals(0, oerStream.read16BitUInt());
    assertEquals(1, oerStream.read16BitUInt());
    assertEquals(128, oerStream.read16BitUInt());
    assertEquals(129, oerStream.read16BitUInt());
    assertEquals(255, oerStream.read16BitUInt());
    assertEquals(256, oerStream.read16BitUInt());
    assertEquals(257, oerStream.read16BitUInt());
    assertEquals(33023, oerStream.read16BitUInt());
    assertEquals(65535, oerStream.read16BitUInt());

    closeStreams();

  }

  @Test
  public final void testRead32BitUInt() throws IOException {

    setupStreams();

    outputStream.write(new byte[] {(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, // 0
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01, // 1
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, // 128
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x81, // 129
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, // 255
        (byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x00, // 256
        (byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x01, // 257
        (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0xFF, // 33023
        (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, // 65535
        (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, // 16843009
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, // 4294967295
    });
    outputStream.flush();

    assertEquals(0, oerStream.read32BitUInt());
    assertEquals(1, oerStream.read32BitUInt());
    assertEquals(128, oerStream.read32BitUInt());
    assertEquals(129, oerStream.read32BitUInt());
    assertEquals(255, oerStream.read32BitUInt());
    assertEquals(256, oerStream.read32BitUInt());
    assertEquals(257, oerStream.read32BitUInt());
    assertEquals(33023, oerStream.read32BitUInt());
    assertEquals(65535, oerStream.read32BitUInt());
    assertEquals(16843009, oerStream.read32BitUInt());
    assertEquals(4294967295L, oerStream.read32BitUInt());

    closeStreams();

  }

  /*
   * TODO Implement decoding unit tests
   * 
   * @Test public final void testReadVarUInt() { fail("Not yet implemented"); // TODO }
   * 
   * @Test public final void testReadBitString() { fail("Not yet implemented"); // TODO }
   * 
   * @Test public final void testReadOctetString() { fail("Not yet implemented"); // TODO }
   * 
   * @Test public final void testReadOctetStringInt() { fail("Not yet implemented"); // TODO }
   * 
   * @Test public final void testReadOctetStringIntInt() { fail("Not yet implemented"); // TODO }
   * 
   * @Test public final void testReadLengthIndicator() { fail("Not yet implemented"); // TODO }
   */

}
