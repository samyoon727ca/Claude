// Find the function(s) that read a data table by scanning references TO every
// word in an address range and collecting the code functions that reference it.
// Use to locate an action-dispatch loop that indexes a handler table via a base
// pointer. Decompiles each collected function.
//
// postScript args:  <output_file.c>  <start_hex>  <end_hex>
//   e.g.  find_table_reader.java out.c 0x44400 0x44700
//@category firmware-diff
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.LinkedHashSet;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.task.ConsoleTaskMonitor;

public class find_table_reader extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        String outfile = (a.length >= 1 && !a[0].isEmpty()) ? a[0] : "table_reader.c";
        long start = (a.length >= 2 && !a[1].isEmpty()) ? Long.decode(a[1]) : 0x44400L;
        long end   = (a.length >= 3 && !a[2].isEmpty()) ? Long.decode(a[2]) : 0x44700L;

        DecompInterface deco = new DecompInterface();
        deco.openProgram(currentProgram);
        ConsoleTaskMonitor mon = new ConsoleTaskMonitor();
        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager rm = currentProgram.getReferenceManager();

        Set<Function> want = new LinkedHashSet<>();
        PrintWriter out = new PrintWriter(new FileWriter(outfile));
        out.println("// scanning refs to [" + Long.toHexString(start) + "," + Long.toHexString(end) + ")");
        for (long v = start; v < end; v += 4) {
            Address ta = toAddr(v);
            for (Reference r : rm.getReferencesTo(ta)) {
                Function f = fm.getFunctionContaining(r.getFromAddress());
                if (f != null) {
                    out.println("//  " + ta + " <- " + r.getFromAddress()
                        + " [" + r.getReferenceType() + "] " + f.getName() + "@" + f.getEntryPoint());
                    want.add(f);
                }
            }
        }
        out.println();
        for (Function f : want) {
            out.println("// ===== " + f.getName() + " @ " + f.getEntryPoint() + " =====");
            DecompileResults r = deco.decompileFunction(f, 180, mon);
            if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null)
                out.print(r.getDecompiledFunction().getC());
            else
                out.println("// <decompile failed/timeout>");
            out.println();
            out.println();
        }
        out.close();
        println("[find_table_reader] wrote " + outfile + " (" + want.size() + " functions)");
    }
}
