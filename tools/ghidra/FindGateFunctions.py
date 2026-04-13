# Finds functions that reference the global state pointer at 0x00E3D540
# and/or use the gate offset 0x5C2 so we can identify the real gate writers.

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.scalar import Scalar
from ghidra.program.model.listing import CodeUnit

GATE_BASE = 0x00E3D540
GATE_OFFSET = 0x5C2


def operand_has_scalar(insn, value):
    for idx in range(insn.getNumOperands()):
        objs = insn.getOpObjects(idx)
        for obj in objs:
            if isinstance(obj, Scalar) and obj.getUnsignedValue() == value:
                return True
    return False


def function_instructions(fn):
    listing = currentProgram.getListing()
    return listing.getInstructions(fn.getBody(), True)


def function_refs_gate_base(fn, gate_addr):
    refs = []
    for insn in function_instructions(fn):
        for ref in insn.getReferencesFrom():
            if ref.getToAddress() == gate_addr:
                refs.append(insn)
                break
    return refs


def function_gate_offset_insns(fn):
    matches = []
    for insn in function_instructions(fn):
        if operand_has_scalar(insn, GATE_OFFSET):
            matches.append(insn)
    return matches


def decompile_function(fn):
    ifc = DecompInterface()
    ifc.openProgram(currentProgram)
    result = ifc.decompileFunction(fn, 30, monitor)
    if result and result.decompileCompleted():
        return result.getDecompiledFunction().getC()
    return None


gate_addr = toAddr(GATE_BASE)
fm = currentProgram.getFunctionManager()

candidates = []
for fn in fm.getFunctions(True):
    base_refs = function_refs_gate_base(fn, gate_addr)
    offset_refs = function_gate_offset_insns(fn)
    if base_refs or offset_refs:
        candidates.append((fn, base_refs, offset_refs))

print("Gate analysis for %s" % currentProgram.getName())
print("gate base = %s, gate offset = 0x%X" % (gate_addr, GATE_OFFSET))
print("candidate functions = %d" % len(candidates))
print("")

for fn, base_refs, offset_refs in candidates:
    print("FUNCTION %s @ %s" % (fn.getName(), fn.getEntryPoint()))
    print("  base refs : %d" % len(base_refs))
    print("  0x5C2 refs: %d" % len(offset_refs))

    seen = set()
    for insn in base_refs + offset_refs:
        if insn.getAddress() in seen:
            continue
        seen.add(insn.getAddress())
        print("    %s  %s" % (insn.getAddress(), insn))

    c = decompile_function(fn)
    if c:
        lines = c.splitlines()
        interesting = []
        for i, line in enumerate(lines):
            if "5c2" in line.lower() or "e3d540" in line.lower() or "DAT_00e3d540" in line:
                start = max(0, i - 3)
                end = min(len(lines), i + 4)
                interesting.extend(lines[start:end])
                interesting.append("...")
        if interesting:
            print("  decomp excerpt:")
            for line in interesting[:60]:
                print("    %s" % line)
    print("")
