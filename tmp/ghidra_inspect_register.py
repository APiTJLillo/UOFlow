from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.address import Address
from ghidra.util.task import ConsoleTaskMonitor


def addr(value):
    return toAddr(value)


def func_at(value):
    return getFunctionAt(addr(value))


def containing_func(value):
    return getFunctionContaining(addr(value))


def decompile_function(fn):
    if fn is None:
        print("  <no function>")
        return

    print("FUNCTION:", fn.getName(), "@", fn.getEntryPoint())
    print("  signature:", fn.getSignature())

    iface = DecompInterface()
    iface.openProgram(currentProgram)
    result = iface.decompileFunction(fn, 60, ConsoleTaskMonitor())
    if not result.decompileCompleted():
        print("  <decompile failed>")
        return
    print(result.getDecompiledFunction().getC())


def print_refs_to(value):
    target = addr(value)
    refs = list(getReferencesTo(target))
    print("REFERENCES TO", target, "count=", len(refs))
    for ref in refs[:40]:
        print(" ", ref.getFromAddress(), ref.getReferenceType())


def print_defined_data(value):
    data = getDataAt(addr(value))
    print("DATA AT", addr(value), "=", data)


targets = [
    0x00994E1F,  # RegisterLuaFunction helper
    0x0052E1A9,  # specific callsite found from string reference
    0x0052B920,  # GetBuildVersion callback
    0x005307F0,  # GetCurrentDateTime callback
    0x0052B1A0,  # LoadTextFile callback
    0x0052B7E0,  # IsLoginBefore callback
]

print("PROGRAM:", currentProgram.getName())
print()

for s in [0x00CAFB28, 0x00CAFB38, 0x00CAFB48, 0x00CAFB5C, 0x00CAFB6C]:
    print_defined_data(s)

print()
print_refs_to(0x00994E1F)
print()

for value in targets:
    fn = func_at(value)
    if fn is None:
        fn = containing_func(value)
    print("=" * 100)
    print("TARGET:", hex(value))
    decompile_function(fn)
    print()
