// Export decompiled C for every function that calls a target symbol (default:
// access) OR references any anchor token. Run once per binary; diff the two
// outputs to see the patched function side by side.
//
// Java GhidraScript (no Python/PyGhidra needed — Ghidra compiles this with the
// bundled JDK). In the OLD (pre-patch) binary the vulnerable function does NOT
// call access(), so the anchor tokens (.php / HNAP / GetDeviceSettings / ...)
// catch the same logical function there so the diff has both sides.
//
// postScript args:  <output_file.c>  [comma,separated,anchor,tokens]
//@category firmware-diff
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.util.task.ConsoleTaskMonitor;

public class export_callers extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outfile = (args.length >= 1 && !args[0].isEmpty()) ? args[0] : "callers.c";
        String[] anchors = (args.length >= 2 && !args[1].isEmpty())
            ? args[1].split(",")
            : new String[] {"access(", ".php", "GetDeviceSettings", "SOAPAction", "HNAP", "getcfg"};

        DecompInterface deco = new DecompInterface();
        deco.openProgram(currentProgram);
        ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();
        FunctionManager fm = currentProgram.getFunctionManager();

        List<Function> matched = new ArrayList<>();
        Map<Function, String> cmap = new HashMap<>();

        FunctionIterator it = fm.getFunctions(true);
        while (it.hasNext()) {
            Function fn = it.next();
            if (fn.isExternal() || fn.isThunk()) continue;
            DecompileResults r = deco.decompileFunction(fn, 60, monitor);
            if (r == null || !r.decompileCompleted()) continue;
            DecompiledFunction d = r.getDecompiledFunction();
            if (d == null) continue;
            String c = d.getC();
            if (c == null) continue;
            for (String a : anchors) {
                if (!a.isEmpty() && c.contains(a)) { matched.add(fn); cmap.put(fn, c); break; }
            }
        }

        matched.sort((a, b) ->
            Long.compareUnsigned(a.getEntryPoint().getOffset(), b.getEntryPoint().getOffset()));

        PrintWriter out = new PrintWriter(new FileWriter(outfile));
        out.println("// program : " + currentProgram.getName());
        out.println("// anchors : " + String.join(",", anchors));
        out.println("// matched : " + matched.size() + " functions");
        out.println();
        for (Function fn : matched) {
            out.println("// ===== " + fn.getName() + " @ 0x"
                + Long.toHexString(fn.getEntryPoint().getOffset()) + " =====");
            out.print(cmap.get(fn));
            out.println();
            out.println();
        }
        out.close();
        println("[export_callers] wrote " + outfile + " (" + matched.size() + " functions)");
    }
}
