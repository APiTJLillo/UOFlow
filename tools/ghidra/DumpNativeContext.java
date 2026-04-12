// Dump function/xref/decompilation context for specific addresses in the current program.
// Intended for headless use with analyzeHeadless.
//
// Example:
//   analyzeHeadless.bat C:\Users\dukey uosa -process UOSA.exe -readOnly -noanalysis ^
//     -scriptPath C:\Users\dukey\Source\UOFlow\tools\ghidra ^
//     -postScript DumpNativeContext.java 0053E630 00AA3350 005C9C5C

import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class DumpNativeContext extends GhidraScript {
    private static final int MAX_CALLERS = 24;
    private static final int MAX_DECOMP_CHARS = 14000;

    private Address parseHexAddress(String text) {
        String value = text.trim();
        if (value.startsWith("0x") || value.startsWith("0X")) {
            value = value.substring(2);
        }
        long raw = Long.parseLong(value, 16);
        return toAddr(raw);
    }

    private String safeName(Function function) {
        if (function == null) {
            return "<none>";
        }
        try {
            return function.getName(true);
        }
        catch (Exception ignored) {
            return function.getName();
        }
    }

    private String fmt(Address address) {
        return address == null ? "<none>" : address.toString();
    }

    private void printHeader(String title) {
        println("");
        println("================================================================================");
        println(title);
        println("================================================================================");
    }

    private void dumpRefs(String label, Address address) {
        printHeader(label + " refs -> " + fmt(address));
        Reference[] refs = getReferencesTo(address);
        if (refs == null || refs.length == 0) {
            println("No references.");
            return;
        }
        for (int i = 0; i < refs.length; i++) {
            Reference ref = refs[i];
            Address from = ref.getFromAddress();
            Function func = getFunctionContaining(from);
            Instruction instr = getInstructionAt(from);
            String text = instr != null ? instr.toString() : "<data>";
            println(String.format("[%02d] %s type=%s func=%s :: %s",
                i + 1,
                fmt(from),
                ref.getReferenceType(),
                safeName(func),
                text));
        }
    }

    private void dumpCallers(Function function) {
        println("-- callers --");
        Address entry = function.getEntryPoint();
        List<Reference> callers = new ArrayList<>();
        for (Reference ref : getReferencesTo(entry)) {
            if (ref.getReferenceType().isCall()) {
                callers.add(ref);
            }
        }
        if (callers.isEmpty()) {
            println("  no call refs");
            return;
        }
        int limit = Math.min(callers.size(), MAX_CALLERS);
        for (int i = 0; i < limit; i++) {
            Reference ref = callers.get(i);
            Address from = ref.getFromAddress();
            Function caller = getFunctionContaining(from);
            Instruction instr = getInstructionAt(from);
            println(String.format("  %s func=%s :: %s",
                fmt(from),
                safeName(caller),
                instr != null ? instr.toString() : "<none>"));
        }
        if (callers.size() > MAX_CALLERS) {
            println("  ... truncated at " + MAX_CALLERS + " callers");
        }
    }

    private void dumpFunction(Address address) throws Exception {
        Function function = getFunctionContaining(address);
        if (function == null) {
            function = getFunctionAt(address);
        }
        if (function == null) {
            printHeader("No function for " + fmt(address));
            return;
        }

        printHeader("Function for " + fmt(address));
        println("name      : " + safeName(function));
        println("entry     : " + fmt(function.getEntryPoint()));
        println("signature : " + function.getSignature());
        println("calling   : " + function.getCallingConventionName());
        println("body      : " + function.getBody());
        dumpCallers(function);

        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);
        try {
            DecompileResults result = ifc.decompileFunction(function, 60, monitor);
            if (!result.decompileCompleted()) {
                println("-- decompile failed --");
                println(result.getErrorMessage());
                return;
            }
            String cText = result.getDecompiledFunction().getC();
            if (cText.length() > MAX_DECOMP_CHARS) {
                cText = cText.substring(0, MAX_DECOMP_CHARS) + "\n/* ... truncated ... */";
            }
            println("-- decompile --");
            println(cText);
        }
        finally {
            ifc.dispose();
        }
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args == null || args.length == 0) {
            println("No addresses passed.");
            return;
        }
        for (String arg : args) {
            Address address = parseHexAddress(arg);
            dumpFunction(address);
            dumpRefs("xref", address);
        }
    }
}
