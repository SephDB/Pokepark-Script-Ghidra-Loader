package fscript_bytecode.structures;

import ghidra.docking.settings.Settings;
import ghidra.program.model.data.BuiltIn;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;

public class Base40StringDataType extends BuiltIn {

	public Base40StringDataType() {
		this(null);
	}

	public Base40StringDataType(DataTypeManager dtm) {
		super(null, "Base40String", dtm);
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new Base40StringDataType(dtm);
	}

	@Override
	public int getLength() {
		return 8;
	}

	@Override
	public String getDescription() {
		return "Base 40 encoded string";
	}
	
	@Override
	public String getMnemonic(Settings settings) {
		return "B40s";
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		return getRepresentation(buf,settings,length);
	}
	
	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		try {
			return new Base40String(buf.getUnsignedInt(0),buf.getUnsignedInt(4)).toString();
		} catch (MemoryAccessException e) {
			// TODO Auto-generated catch block
			return null;
		}
	}

	@Override
	public boolean isEquivalent(DataType dt) {
		if (dt == this) {
			return true;
		}
		if (dt == null) {
			return false;
		}
		return getClass() == dt.getClass();
	}
	
	@Override
	public Class<?> getValueClass(Settings settings) {
		return String.class;
	}
}
