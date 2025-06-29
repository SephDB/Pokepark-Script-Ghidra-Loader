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

public class Header implements StructConverter {

	public int instruction_offset;
	public int symbol_table_offset;
	int unused_section_offset;
	public int string_section_offset;
	public Base40String script_name;
	
	public Header(BinaryReader reader) throws IOException {
		instruction_offset = reader.readNextInt();
		symbol_table_offset = reader.readNextInt();
		unused_section_offset = reader.readNextInt();
		string_section_offset = reader.readNextInt();
		reader.readNextInt(); //0
		script_name = new Base40String(reader);
	}
	
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		var pointer = Pointer32DataType.dataType.typedefBuilder().type(PointerType.FILE_OFFSET).build();
		
		Structure struct = new StructureDataType("fscript_header", 0);
		
		struct.add(pointer, "instructions", "Start of the instruction section");
		struct.add(pointer, "symbol_table", "Start of the symbol table");
		struct.add(pointer,"unused", null);
		struct.add(pointer, "string_table", "Start of the string table");
		struct.add(DWORD, "unused2", null);
		struct.add(script_name.toDataType(),"script_name", "Encoded name of script");
		struct.add(DWORD, "unused3", null);
		
		return struct;
	}

}
