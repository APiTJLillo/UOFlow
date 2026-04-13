//@category UOFlow

import java.util.*;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.TaskMonitor;

public class DumpFunctionsAt extends GhidraScript {
	private String decompile(Function fn) throws Exception {
		DecompInterface ifc = new DecompInterface();
		DecompileOptions options = new DecompileOptions();
		ifc.setOptions(options);
		ifc.openProgram(currentProgram);
		DecompileResults res = ifc.decompileFunction(fn, 60, TaskMonitor.DUMMY);
		if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
			return res.getDecompiledFunction().getC();
		}
		return null;
	}

	@Override
	protected void run() throws Exception {
		String[] addrs = getScriptArgs();
		if (addrs == null || addrs.length == 0) {
			printerr("usage: DumpFunctionsAt <addr> [addr...]");
			return;
		}

		for (String arg : addrs) {
			Address addr = toAddr(arg);
			Function fn = getFunctionContaining(addr);
			if (fn == null) {
				println("No function at/containing " + addr);
				continue;
			}

			println("FUNCTION " + fn.getName() + " @ " + fn.getEntryPoint() + " for query " + addr);
			println("CALLERS:");
			Set<Address> seen = new HashSet<Address>();
			Reference[] refs = getReferencesTo(fn.getEntryPoint());
			for (Reference ref : refs) {
				Address from = ref.getFromAddress();
				if (seen.add(from)) {
					Function caller = getFunctionContaining(from);
					println("  " + from + "  caller=" + (caller != null ? caller.getName() + "@" + caller.getEntryPoint() : "<none>"));
				}
			}
			println("DECOMP:");
			String c = decompile(fn);
			if (c != null) {
				println(c);
			} else {
				println("<decompile failed>");
			}
			println("----");
		}
	}
}
