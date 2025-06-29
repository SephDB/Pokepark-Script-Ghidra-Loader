/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package fscript_bytecode;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.Undefined4DataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Provide class-level documentation that describes what this analyzer does.
 */
public class FScriptFunctionAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "FScript function analysis";
	private static final String DESCRIPTION = 
			"Uses function intro + return instructions to set function signature and stack fixup";
	
	
	
	public FScriptFunctionAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
		this.setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after());
		this.setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return true;
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor().toString().equals("Fscript");
	}

	@Override
	public void registerOptions(Options options, Program program) {

		// If this analyzer has custom options, register them here

		options.registerOption("Option name goes here", false, null,
			"Option description goes here");
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		// Perform analysis when things get added to the 'program'.  Return true if the
		// analysis succeeded.
		FunctionManager functionManager = program.getFunctionManager();
		FlatProgramAPI api = new FlatProgramAPI(program,monitor);
		DataTypeManager typeManager = program.getDataTypeManager();
		
		for(Function f : functionManager.getFunctions(set, true)) {
			if(f.getSignatureSource().equals(SourceType.DEFAULT) || f.getParameterCount() != 4*f.getStackPurgeSize()) {
				AddressSetView body = f.getBody();
				int num_locals = 0;
				Instruction i = api.getFirstInstruction(f);
				if(i.getMnemonicString().equals("grow_stack")) {
					num_locals = (int)i.getScalar(0).getUnsignedValue();
				}
				
				while(i != null && body.contains(i.getMinAddress()) && !i.getMnemonicString().startsWith("ret")) {
					i = i.getNext();
				}
				
				if(i == null || !body.contains(i.getMinAddress())) {
					log.appendMsg(NAME, "Failed to find return instruction in "+f.getName());
					continue;
				}
				
				int num_popped = (int)i.getScalar(0).getUnsignedValue();
				int num_params = num_popped - num_locals;
				
				f.setStackPurgeSize(num_params*4);
				
				
				var returnType = f.getReturnType();
				
				if(returnType == null || returnType.getLength() != 4 || f.getReturn().getSource().equals(SourceType.DEFAULT)) {
					try {
						f.setCallingConvention("default");
						if(i.getMnemonicString().equals("retv")) {
							f.setReturnType(IntegerDataType.dataType, SourceType.ANALYSIS);
						}
						else {
							f.setReturnType(VoidDataType.dataType, SourceType.ANALYSIS);
						}
					} catch (InvalidInputException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					
				}
				FunctionDefinitionDataType signature = new FunctionDefinitionDataType(f, true);
				
				try {
					signature.setCallingConvention("default");
				} catch (InvalidInputException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				if(f.getParameterCount() != num_params || f.getSignatureSource().equals(SourceType.DEFAULT)) {
					var parameters = new ParameterDefinition[num_params];
					for(int pnum = 0; pnum < num_params; ++pnum) {
						Parameter orig = f.getParameter(pnum);
						ParameterDefinition def;
						if(orig == null || orig.getSource().equals(SourceType.DEFAULT) || orig.getDataType().getLength() != 4 
								|| (pnum == 0 && orig.getDataType().isEquivalent(PointerDataType.getPointer(DataType.DEFAULT, typeManager)))) {
							String name = "param_"+(pnum+1);
							DataType type = Undefined4DataType.dataType;
							if(orig != null && !orig.getSource().equals(SourceType.DEFAULT) && !(pnum == 0 && orig.getDataType().isEquivalent(PointerDataType.getPointer(DataType.DEFAULT, typeManager)))) {
								type = orig.getDataType();
							}
							def = new ParameterDefinitionImpl(name,type,"");
						}
						else {
							def = new ParameterDefinitionImpl("param_"+(pnum+1),orig.getDataType(),orig.getComment());
						}
						parameters[pnum] = def;
					}
					signature.setArguments(parameters);
				}
				
				var cmd = new ApplyFunctionSignatureCmd(f.getEntryPoint(), signature, SourceType.ANALYSIS);
				cmd.applyTo(program);
			}
		}

		return true;
	}
}
