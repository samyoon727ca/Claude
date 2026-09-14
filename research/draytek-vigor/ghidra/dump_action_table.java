// Dump the mainfunction.cgi action-dispatch table and the session-level helpers.
// The dispatcher (PATH_INFO==NULL branch of FUN_000239b4) reads the "action"
// CGI param, finds a 12-byte record {name_ptr, handler, prolog} in a 137-entry
// table via FUN_0000b5cc, and calls prolog() then handler(). This script:
//   (1) resolves the table base (pointer word at 0xb628) and prints all records
//       name / handler / prolog;
//   (2) decompiles the session-level resolver chain and a set of handlers of
//       interest passed as extra args (hex addresses).
//
// postScript args:  <output_file.c>  [handler_hex ...]
//@category firmware-diff
import java.io.FileWriter;
import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

import ghidra.util.task.ConsoleTaskMonitor;

public class dump_action_table extends GhidraScript {

    private String cstr(long ptr) {
        try {
            Address a = toAddr(ptr);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 120; i++) {
                byte b = getByte(a.add(i));
                if (b == 0) break;
                if (b >= 0x20 && b < 0x7f) sb.append((char) b);
                else sb.append('.');
            }
            return sb.toString();
        } catch (Exception e) { return "<unreadable>"; }
    }

    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        String outfile = (a.length >= 1 && !a[0].isEmpty()) ? a[0] : "action_table.c";
        PrintWriter out = new PrintWriter(new FileWriter(outfile));

        DecompInterface deco = new DecompInterface();
        deco.openProgram(currentProgram);
        ConsoleTaskMonitor mon = new ConsoleTaskMonitor();
        FunctionManager fm = currentProgram.getFunctionManager();

        // (1) table base = pointer word at 0xb628
        long base = ((long) getInt(toAddr(0xb628L))) & 0xffffffffL;
        out.println("// action table base = 0x" + Long.toHexString(base) + "  (137 records x 12 bytes)");
        out.println("// idx  name                              handler    prolog");
        for (int i = 0; i < 137; i++) {
            long rec = base + (long) i * 12L;
            long namep = ((long) getInt(toAddr(rec))) & 0xffffffffL;
            long hand  = ((long) getInt(toAddr(rec + 4))) & 0xffffffffL;
            long prol  = ((long) getInt(toAddr(rec + 8))) & 0xffffffffL;
            out.println(String.format("// %3d  %-32s  %08x   %08x", i, cstr(namep), hand, prol));
        }
        out.println();

        // (2) decompile the session-level chain + requested handlers
        long[] fixed = { 0x19164L, 0xdd94L, 0x18dd0L, 0x18590L };
        java.util.LinkedHashSet<Long> tset = new java.util.LinkedHashSet<>();
        for (long t : fixed) tset.add(t);
        for (int i = 1; i < a.length; i++) tset.add(Long.decode(a[i]));

        for (long t : tset) {
            Function f = fm.getFunctionContaining(toAddr(t));
            out.println("// ===== " + String.format("0x%x", t) + " -> "
                + (f != null ? f.getName() + "@" + f.getEntryPoint() : "?") + " =====");
            if (f != null) {
                DecompileResults r = deco.decompileFunction(f, 240, mon);
                if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null)
                    out.print(r.getDecompiledFunction().getC());
                else out.println("// <decompile failed/timeout>");
            }
            out.println();
        }

        // resolve the two env vars FUN_00019164 reads
        out.println("// env vars read by FUN_00019164:");
        long e1 = ((long) getInt(toAddr(0x191c8L))) & 0xffffffffL;
        long e2 = ((long) getInt(toAddr(0x191ccL))) & 0xffffffffL;
        out.println("//  DAT_000191c8 -> \"" + cstr(e1) + "\"");
        out.println("//  DAT_000191cc -> \"" + cstr(e2) + "\"");

        // resolve assorted pointer words of interest (skip-login config, session store)
        out.println("// misc pointer words:");
        long[] ptrs = { 0xddf4L, 0xddf8L, 0xddfcL, 0xde00L, 0x1864cL, 0x18650L, 0x18654L, 0x18e58L,
            // login role-string compares (level assignment): 7,4,1,else=3
            0x2c8f8L, 0x2c8fcL, 0x2c900L, 0x2c904L, 0x2c908L };
        for (long pw : ptrs) {
            long v = ((long) getInt(toAddr(pw))) & 0xffffffffL;
            String s = (v > 0x1000 && v < 0x400000) ? cstr(v) : "";
            out.println(String.format("//  %08x -> %08x  \"%s\"", pw, v, s));
        }

        out.close();
        println("[dump_action_table] wrote " + outfile);
    }
}
