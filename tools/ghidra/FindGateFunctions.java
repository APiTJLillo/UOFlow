// Finds functions that reference the global state pointer at 0x00E3D540
// and/or use the gate offset 0x5C2 so we can identify the real gate writers.
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
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.TaskMonitor;

public class FindGateFunctions extends GhidraScript {

	private static final long GATE_BASE = 0x00E3D540L;
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

	private List<Instruction> getGateBaseRefs(Function fn, Address gateAddr) {
		List<Instruction> refs = new ArrayList<Instruction>();
		for (Instruction insn : currentProgram.getListing().getInstructions(fn.getBody(), true)) {
			Reference[] from = insn.getReferencesFrom();
			for (Reference ref : from) {
				if (gateAddr.equals(ref.getToAddress())) {
					refs.add(insn);
					break;
				}
			}
		}
		return refs;
	}

	private List<Instruction> getGateOffsetRefs(Function fn) {
		List<Instruction> refs = new ArrayList<Instruction>();
		for (Instruction insn : currentProgram.getListing().getInstructions(fn.getBody(), true)) {
			if (operandHasScalar(insn, GATE_OFFSET)) {
				refs.add(insn);
			}
		}
		return refs;
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
		Address gateAddr = toAddr(GATE_BASE);
		List<Function> funcs = new ArrayList<Function>();
		Map<Function, List<Instruction>> baseRefMap = new HashMap<Function, List<Instruction>>();
		Map<Function, List<Instruction>> offsetRefMap = new HashMap<Function, List<Instruction>>();

		for (Function fn : currentProgram.getFunctionManager().getFunctions(true)) {
			List<Instruction> baseRefs = getGateBaseRefs(fn, gateAddr);
			List<Instruction> offsetRefs = getGateOffsetRefs(fn);
			if (!baseRefs.isEmpty() || !offsetRefs.isEmpty()) {
				funcs.add(fn);
				baseRefMap.put(fn, baseRefs);
				offsetRefMap.put(fn, offsetRefs);
			}
		}

		Collections.sort(funcs, new Comparator<Function>() {
			@Override
			public int compare(Function a, Function b) {
				return a.getEntryPoint().compareTo(b.getEntryPoint());
			}
		});

		println("Gate analysis for " + currentProgram.getName());
		println("gate base = " + gateAddr + ", gate offset = 0x" + Long.toHexString(GATE_OFFSET));
		println("candidate functions = " + funcs.size());
		println("");

		for (Function fn : funcs) {
			List<Instruction> baseRefs = baseRefMap.get(fn);
			List<Instruction> offsetRefs = offsetRefMap.get(fn);
			println("FUNCTION " + fn.getName() + " @ " + fn.getEntryPoint());
			println("  base refs : " + baseRefs.size());
			println("  0x5C2 refs: " + offsetRefs.size());

			Set<Address> seen = new HashSet<Address>();
			for (Instruction insn : baseRefs) {
				if (seen.add(insn.getAddress())) {
					println("    " + insn.getAddress() + "  " + insn);
				}
			}
			for (Instruction insn : offsetRefs) {
				if (seen.add(insn.getAddress())) {
					println("    " + insn.getAddress() + "  " + insn);
				}
			}

			String c = null;
			try {
				c = decompile(fn);
			}
			catch (Exception ex) {
				println("  decompile failed: " + ex.getMessage());
			}

			if (c != null) {
				String[] lines = c.split("\\R");
				List<String> interesting = new ArrayList<String>();
				for (int i = 0; i < lines.length; i++) {
					String lower = lines[i].toLowerCase();
					if (lower.contains("5c2") || lower.contains("e3d540") || lines[i].contains("DAT_00e3d540")) {
						int start = Math.max(0, i - 3);
						int end = Math.min(lines.length, i + 4);
						for (int j = start; j < end; j++) {
							interesting.add(lines[j]);
						}
						interesting.add("...");
					}
				}
				if (!interesting.isEmpty()) {
					println("  decomp excerpt:");
					for (int i = 0; i < interesting.size() && i < 80; i++) {
						println("    " + interesting.get(i));
					}
				}
			}
			println("");
		}
	}
}
