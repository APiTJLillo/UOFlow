// Dumps movement-related function information for headless Ghidra analysis.
// Usage:
//   analyzeHeadless <projDir> <projName> -process UOSA.exe -scriptPath <this_dir> -postScript DumpMovementInfo.java

import java.util.Arrays;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Reference;

public class DumpMovementInfo extends GhidraScript {
    private void dumpFunction(DecompInterface ifc, long offset) throws Exception {
        Address addr = toAddr(offset);
        Function fn = getFunctionContaining(addr);
        println("");
        println("=== Function @" + addr + " ===");
        if (fn == null) {
            println("No function defined at " + addr);
            return;
        }

        println("Name: " + fn.getName());
        println("Entry: " + fn.getEntryPoint());
        println("Signature: " + fn.getSignature(true));
        println("Calling convention: " + fn.getCallingConventionName());
        println("Stack purge size: " + fn.getStackPurgeSize());

        println("-- References To --");
        Reference[] refs = getReferencesTo(fn.getEntryPoint());
        for (Reference ref : refs) {
            println("  " + ref.getFromAddress());
        }

        println("-- First Instructions --");
        Listing listing = currentProgram.getListing();
        InstructionIterator it = listing.getInstructions(fn.getBody(), true);
        int count = 0;
        while (it.hasNext() && count < 20) {
            Instruction ins = it.next();
            println("  " + ins.getAddress() + "  " + ins);
            count++;
        }

        println("-- Decompiled --");
        DecompileResults results = ifc.decompileFunction(fn, 60, monitor);
        if (!results.decompileCompleted()) {
            println("Decompile failed: " + results.getErrorMessage());
            return;
        }
        println(results.getDecompiledFunction().getC());
    }

    private void dumpDataRefs(long offset) throws Exception {
        Address addr = toAddr(offset);
        println("");
        println("=== References To Data @" + addr + " ===");
        Reference[] refs = getReferencesTo(addr);
        for (Reference ref : refs) {
            println("  " + ref.getFromAddress());
        }
    }

    private void dumpRange(long start, long end) throws Exception {
        println("");
        println("=== Instruction Range @" + toAddr(start) + " .. " + toAddr(end) + " ===");
        Listing listing = currentProgram.getListing();
        Instruction ins = listing.getInstructionAt(toAddr(start));
        if (ins == null) {
            ins = listing.getInstructionAfter(toAddr(start));
        }
        while (ins != null && ins.getAddress().getOffset() <= end) {
            println("  " + ins.getAddress() + "  " + ins);
            ins = ins.getNext();
        }
    }

    @Override
    protected void run() throws Exception {
        DecompInterface ifc = new DecompInterface();
        DecompileOptions opts = new DecompileOptions();
        ifc.setOptions(opts);
        ifc.openProgram(currentProgram);

        List<Long> funcs = Arrays.asList(
            0x005c2230L,
            0x005ed580L,
            0x005f65c0L,
            0x005f7300L,
            0x005f7660L,
            0x005f7690L
        );
        for (long off : funcs) {
            dumpFunction(ifc, off);
        }

        dumpDataRefs(0x00e1a17cL);
        dumpDataRefs(0x00e3d524L);
        dumpRange(0x005ed5d0L, 0x005ed620L);
        dumpRange(0x005ed620L, 0x005ed680L);
        dumpRange(0x005ed680L, 0x005ed6d0L);
        dumpRange(0x005c2230L, 0x005c2268L);

        ifc.dispose();
    }
}
