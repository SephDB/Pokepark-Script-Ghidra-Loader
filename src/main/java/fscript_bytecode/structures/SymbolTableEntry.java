package fscript_bytecode.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.data.PointerType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class SymbolTableEntry implements StructConverter {

	Base40String name;
	int pointer_val;
	
	public SymbolTableEntry(BinaryReader reader) throws IOException {
		name = new Base40String(reader);
		pointer_val = reader.readNextInt();
	}
	
	public String getName() {
		return name.toString();
	}
	
	public int getPosition() {
		return pointer_val * 4;
	}
	
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return getDataType();
	}
	
	public static DataType getDataType() {
		Structure struct = new StructureDataType("SymbolTableEntry", 0);
		struct.add(Base40String.getDataType(),"symbol_name","");
		struct.add(Pointer32DataType.dataType.typedefBuilder().type(PointerType.FILE_OFFSET).bitShift(2).build(),"symbol_offset","position of symbol, *4");
		return struct;
	}
	
}
