package fscript_bytecode.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

public class Base40String implements StructConverter {

	public static String encoding = " 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_-/";
	
	private long a;
	private long b;
	
	public Base40String(long a, long b) {
		this.a = a;
		this.b = b;
	}
	
	public Base40String(BinaryReader reader) throws IOException {
		a = reader.readNextUnsignedInt();
		b = reader.readNextUnsignedInt();
	}
	
	private String decodeUint(long c) {
		char[] ret = new char[6];
		for(int i = 0; i < 6; ++i) {
			int next = (int) (c % 40);
			c /= 40;
			ret[5-i] = encoding.charAt(next);
		}
		return new String(ret);
	}
	
	public String toString() {
		return decodeUint(a).concat(decodeUint(b)).stripTrailing();
	}
	
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return new Base40StringDataType();
	}
	
	public static DataType getDataType() {
		return new Base40StringDataType();
	} 
}