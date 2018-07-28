/*******************************************************************************
 * Copyright 2017 McGill University All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package ca.mcgill.sis.dmas.io.binary;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DmasByteOperation {

	private static Logger logger = LoggerFactory.getLogger(DmasByteOperation.class);

	public static byte[] getBytes(double value) {
		return ByteBuffer.allocate(8).putDouble(value).array();
	}

	public static byte[] getBytes(double[] value) {
		ByteBuffer buffer = ByteBuffer.allocate(8 * value.length);
		Arrays.stream(value).forEach(buffer::putDouble);
		return buffer.array();
	}

	public static byte[] getBytes(long value) {
		return ByteBuffer.allocate(8).putLong(value).array();
	}

	public static byte[] getBytes(int value) {
		byte[] bytesToHash = new byte[4];
		bytesToHash[0] = (byte) (value >> 24);
		bytesToHash[1] = (byte) (value >> 16);
		bytesToHash[2] = (byte) (value >> 8);
		bytesToHash[3] = (byte) value;
		return bytesToHash;
	}

	public static int fromByte(byte[] bytes) {
		return ((bytes[0] & 0xFF) << 24) | ((bytes[1] & 0xFF) << 16) | ((bytes[2] & 0xFF) << 8) | (bytes[3] & 0xFF);
	}

	public static int fromByte(byte[] bytes, int ind) {
		byte b1 = ind + 0 < bytes.length ? bytes[ind + 0] : 0x00;
		byte b2 = ind + 1 < bytes.length ? bytes[ind + 1] : 0x00;
		byte b3 = ind + 2 < bytes.length ? bytes[ind + 2] : 0x00;
		byte b4 = ind + 3 < bytes.length ? bytes[ind + 3] : 0x00;

		return ((b1 & 0xFF) << 24) | ((b2 & 0xFF) << 16) | ((b3 & 0xFF) << 8) | (b4 & 0xFF);
	}

	final protected static char[] encoding = "0123456789ABCDEF".toCharArray();

	public static String toHexs(byte[] arr) {
		char[] encodedChars = new char[arr.length * 2];
		for (int i = 0; i < arr.length; i++) {
			encodedChars[i * 2] = encoding[(arr[i] >>> 4) & 0x0F];
			encodedChars[i * 2 + 1] = encoding[(arr[i]) & 0x0F];
		}
		return new String(encodedChars);
	}

	public static String toHexs(byte[] arr, int numOfBits) {
		int residual = numOfBits % 8;
		int bytes = numOfBits / 8;
		int charLength = bytes * 2;
		if (residual > 0)
			charLength += 2;
		char[] encodedChars = new char[charLength];
		int i = 0;
		for (; i < bytes; i++) {
			encodedChars[i * 2] = encoding[(arr[i] >>> 4) & 0x0F];
			encodedChars[i * 2 + 1] = encoding[(arr[i]) & 0x0F];
		}
		if (residual > 0) {
			byte mask = (byte) (0xFF & (0xFF << (8 - residual)));
			encodedChars[i * 2] = encoding[((arr[i] & mask) >>> 4) & 0x0F];
			encodedChars[i * 2 + 1] = encoding[(arr[i] & mask) & 0x0F];
		}
		return new String(encodedChars);
	}

	public static String toBinary(byte[] arr) {
		char[] encodedChars = new char[arr.length * 8];
		for (int i = 0; i < arr.length; i++) {
			for (int j = 0; j < 8; ++j) {
				encodedChars[i * 2 + j] = encoding[(arr[i] >>> (7 - j)) & 0x01];
			}
		}
		return new String(encodedChars);
	}

	public static int hamming(byte x1, byte x2) {
		int i1 = Byte.toUnsignedInt(x1);
		int i2 = Byte.toUnsignedInt(x2);
		return Integer.bitCount(i1 ^ i2);
	}

	public static void main(String[] args) {
		byte b1 = -1; // 11111111
		byte b2 = -4; // 11111100
		byte b3 = 106;// 01101010
		System.out.println("" + hamming(b1, b2));
		System.out.println("" + hamming(b1, b3));
		System.out.println("" + hamming(b2, b3));
		System.out.println("" + hamming(b2, b1));
	}

	public static byte[] convertToBytes(Object object) throws IOException {
		try (ByteArrayOutputStream bos = new ByteArrayOutputStream(); ObjectOutput out = new ObjectOutputStream(bos)) {
			out.writeObject(object);
			return bos.toByteArray();
		}
	}

	public static Object convertFromBytes(byte[] bytes) throws IOException, ClassNotFoundException {
		try (ByteArrayInputStream bis = new ByteArrayInputStream(bytes); ObjectInput in = new ObjectInputStream(bis)) {
			return in.readObject();
		}
	}

	public static void saveObject(Object object, String file) throws IOException {
		ObjectOutputStream oos = null;
		FileOutputStream fout = null;
		try {
			fout = new FileOutputStream(file);
			oos = new ObjectOutputStream(fout);
			oos.writeObject(object);
			oos.close();
		} catch (Exception ex) {
			logger.error("Failed to save object to file " + file, ex);
		} finally {
			if (oos != null)
				oos.close();
			if (fout != null)
				fout.close();
		}
	}

	@SuppressWarnings("unchecked")
	public static <T> T loadObject(String file) {
		T val = null;
		try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(file))) {
			val = (T) ois.readObject();
			return val;
		} catch (Exception ex) {
			logger.error("Failed to load object from file " + file, ex);
		}
		return val;

	}

}
