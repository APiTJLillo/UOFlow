// Dumps the register helper, selected callbacks, and references from an
// existing Ghidra project opened headlessly.

import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.ConsoleTaskMonitor;

public class InspectRegisterHelper extends GhidraScript {

    private Function getFunctionFor(long va) {
        Address address = toAddr(va);
        Function fn = getFunctionAt(address);
        if (fn == null) {
            fn = getFunctionContaining(address);
        }
        return fn;
    }

    private void printData(long va) {
        Address address = toAddr(va);
        Data data = getDataAt(address);
        println("DATA " + address + " = " + data);
    }

    private void printRefsTo(long va) {
        Address address = toAddr(va);
        List<Reference> refs = new ArrayList<>();
        for (Reference ref : getReferencesTo(address)) {
            refs.add(ref);
        }
        println("REFERENCES TO " + address + " count=" + refs.size());
        int limit = Math.min(refs.size(), 40);
        for (int i = 0; i < limit; i++) {
            Reference ref = refs.get(i);
            println("  " + ref.getFromAddress() + " " + ref.getReferenceType());
        }
    }

    private void decompile(long va) throws Exception {
        Function fn = getFunctionFor(va);
        println("====================================================================================================");
        println("TARGET 0x" + Long.toHexString(va).toUpperCase());
        if (fn == null) {
            println("  <no function>");
            return;
        }

        println("FUNCTION: " + fn.getName() + " @ " + fn.getEntryPoint());
        println("SIGNATURE: " + fn.getSignature());

        DecompInterface iface = new DecompInterface();
        iface.openProgram(currentProgram);
        DecompileResults results = iface.decompileFunction(fn, 60, new ConsoleTaskMonitor());
        if (!results.decompileCompleted()) {
            println("<decompile failed>");
            return;
        }

        println(results.getDecompiledFunction().getC());
    }

    @Override
    protected void run() throws Exception {
        println("PROGRAM: " + currentProgram.getName());
        println();

        long[] strings = {
            0x00CAFB28L,
            0x00CAFB38L,
            0x00CAFB48L,
            0x00CAFB5CL,
            0x00CAFB6CL
        };
        for (long value : strings) {
            printData(value);
        }

        println();
        printRefsTo(0x00994E1FL);
        println();

        long[] targets = {
            0x00994E1FL,
            0x0052E1A9L,
            0x0052B920L,
            0x005307F0L,
            0x0052B1A0L,
            0x0052B7E0L,
            0x005273D0L, // PrintWStringToChatWindow
            0x00529BE0L, // SendChat
            0x0052AEE0L, // ExitGame
            0x0052F3A0L, // HandleSingleLeftClkTarget
            0x00996FD1L, // argument extraction helper
            0x009969C9L, // per-argument validator
            0x00999835L, // bad-args reporter
            0x00997AEFL, // registration sink
            0x0099D545L, // push boolean-like helper
            0x0099D5F9L, // push numeric-like helper
            0x0099D535L, // callback wrapper / scheduler helper
            0x0099E3D8L  // return finalization helper
        };

        for (long value : targets) {
            decompile(value);
            println();
        }
    }
}
