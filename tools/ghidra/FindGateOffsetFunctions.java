//@category UOFlow

import java.util.*;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.task.TaskMonitor;

public class FindGateOffsetFunctions extends GhidraScript {
	private static final long GATE_OFFSET = 0x5C2L;

	private boolean operandHasScalar(Instruction insn, long value) {
		for (int idx = 0; idx < insn.getNumOperands(); idx++) {
			Object[] objs = insn.getOpObjects(idx);
			for (Object obj : objs) {
				if (obj instanceof Scalar) {
					Scalar s = (Scalar) obj;
					if (s.getUnsignedValue() == value) {
						return true;
					}
				}
			}
		}
		return false;
	}

	private String decompile(Function fn) throws Exception {
		DecompInterface ifc = new DecompInterface();
		DecompileOptions options = new DecompileOptions();
		ifc.setOptions(options);
		ifc.openProgram(currentProgram);
		DecompileResults res = ifc.decompileFunction(fn, 30, TaskMonitor.DUMMY);
		if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
			return res.getDecompiledFunction().getC();
		}
		return null;
	}

	@Override
	protected void run() throws Exception {
		List<Function> funcs = new ArrayList<Function>();
		Map<Function, List<Instruction>> hits = new HashMap<Function, List<Instruction>>();

		for (Function fn : currentProgram.getFunctionManager().getFunctions(true)) {
			List<Instruction> refs = new ArrayList<Instruction>();
			for (Instruction insn : currentProgram.getListing().getInstructions(fn.getBody(), true)) {
				if (operandHasScalar(insn, GATE_OFFSET)) {
					refs.add(insn);
				}
			}
			if (!refs.isEmpty()) {
				funcs.add(fn);
				hits.put(fn, refs);
			}
		}

		Collections.sort(funcs, new Comparator<Function>() {
			@Override
			public int compare(Function a, Function b) {
				return a.getEntryPoint().compareTo(b.getEntryPoint());
			}
		});

		println("Functions referencing gate offset 0x5C2 in " + currentProgram.getName());
		println("count = " + funcs.size());
		println("");

		for (Function fn : funcs) {
			println("FUNCTION " + fn.getName() + " @ " + fn.getEntryPoint());
			for (Instruction insn : hits.get(fn)) {
				println("  " + insn.getAddress() + "  " + insn);
			}
			try {
				String c = decompile(fn);
				if (c != null) {
					String[] lines = c.split("\\R");
					println("  decomp excerpt:");
					for (int i = 0; i < lines.length; i++) {
						String lower = lines[i].toLowerCase();
						if (lower.contains("5c2")) {
							int start = Math.max(0, i - 4);
							int end = Math.min(lines.length, i + 6);
							for (int j = start; j < end; j++) {
								println("    " + lines[j]);
							}
							println("    ...");
						}
					}
				}
			}
			catch (Exception ex) {
				println("  decompile failed: " + ex.getMessage());
			}
			println("");
		}
	}
}
