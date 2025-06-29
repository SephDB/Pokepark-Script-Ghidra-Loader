package fscript_bytecode.pcode;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.lang.PcodeInjectLibrary;

public class PcodeInjectLibraryFScript extends PcodeInjectLibrary {

	public PcodeInjectLibraryFScript(SleighLanguage l) {
		super(l);
		
	}
	
	public PcodeInjectLibraryFScript(PcodeInjectLibraryFScript op2) {
		super(op2);
	}

	@Override
	public InjectPayload getPayload(int type, String name) {
		return super.getPayload(type, name);
	}
	
	@Override
	public PcodeInjectLibrary clone() {
		return new PcodeInjectLibraryFScript(this);
	}
}
