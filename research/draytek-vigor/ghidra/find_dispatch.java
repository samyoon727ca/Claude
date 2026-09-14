// Find the dispatcher + auth context for an indirectly-called handler.
// Walks references TO a handler address and TO an action string (one level of
// PIC pointer-table indirection each), then decompiles every function that
// reaches them. Use to determine the auth gate on an action-table handler.
//
// postScript args:  <output_file.c>  <handler_addr_hex>  <action_string>
//   e.g.  find_dispatch.java out.c 0x1e9d8 doOpenVPN
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

public class find_dispatch extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        String outfile = (a.length >= 1 && !a[0].isEmpty()) ? a[0] : "dispatch.c";
        long targ = (a.length >= 2 && !a[1].isEmpty()) ? Long.decode(a[1]) : 0x1e9d8L;
        String needle = (a.length >= 3 && !a[2].isEmpty()) ? a[2] : "doOpenVPN";

        DecompInterface deco = new DecompInterface();
        deco.openProgram(currentProgram);
        ConsoleTaskMonitor mon = new ConsoleTaskMonitor();
        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager rm = currentProgram.getReferenceManager();

        Set<Function> want = new LinkedHashSet<>();
        PrintWriter out = new PrintWriter(new FileWriter(outfile));

        // 1) references to the handler address (direct calls or table-slot data refs)
        Address ta = toAddr(targ);
        out.println("// == refs to handler @ " + ta + " ==");
        for (Reference r : rm.getReferencesTo(ta)) {
            Address from = r.getFromAddress();
            Function f = fm.getFunctionContaining(from);
            out.println("//  handler<-" + from + " [" + r.getReferenceType() + "] "
                + (f != null ? f.getName() + "@" + f.getEntryPoint() : "DATA(table slot)"));
            if (f != null) { want.add(f); }
            else {                                  // table slot -> who reads the table
                for (Reference r2 : rm.getReferencesTo(from)) {
                    Function f2 = fm.getFunctionContaining(r2.getFromAddress());
                    out.println("//    tableRead<-" + r2.getFromAddress()
                        + " " + (f2 != null ? f2.getName() : "?"));
                    if (f2 != null) want.add(f2);
                }
            }
        }

        // 2) references to the action string (through PIC pointer slot if needed)
        Address sa = find(needle);
        out.println("// == action string '" + needle + "' @ " + sa + " ==");
        if (sa != null) {
            for (Reference r : rm.getReferencesTo(sa)) {
                Address from = r.getFromAddress();
                Function f = fm.getFunctionContaining(from);
                out.println("//  str<-" + from + " " + (f != null ? f.getName() : "PTR slot"));
                if (f != null) { want.add(f); }
                else {
                    for (Reference r2 : rm.getReferencesTo(from)) {
                        Function f2 = fm.getFunctionContaining(r2.getFromAddress());
                        out.println("//    strPtrRead<-" + r2.getFromAddress()
                            + " " + (f2 != null ? f2.getName() : "?"));
                        if (f2 != null) want.add(f2);
                    }
                }
            }
        }

        // 3) decompile everything we collected
        out.println();
        for (Function f : want) {
            out.println("// ===== " + f.getName() + " @ " + f.getEntryPoint() + " =====");
            DecompileResults r = deco.decompileFunction(f, 150, mon);
            if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null)
                out.print(r.getDecompiledFunction().getC());
            else
                out.println("// <decompile failed/timeout>");
            out.println();
            out.println();
        }
        out.close();
        println("[find_dispatch] wrote " + outfile + " (" + want.size() + " functions)");
    }
}
