// Resolve the auth model of mainfunction.cgi.
// (1) Decompiles a fixed set of functions relevant to the auth gate.
// (2) Resolves literal-pool pointer words in given ranges to the C strings
//     they point at (Ghidra leaves many DAT_ pool words untyped, so the
//     dispatcher's action names show up only as DAT_xxxx in decompilation).
//
// postScript args:  <output_file.c>
//@category firmware-diff
import java.io.FileWriter;
import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.task.ConsoleTaskMonitor;

public class auth_probe extends GhidraScript {

    private String cstr(long ptr) {
        try {
            Address a = toAddr(ptr);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 200; i++) {
                byte b = getByte(a.add(i));
                if (b == 0) break;
                if (b >= 0x20 && b < 0x7f) sb.append((char) b);
                else sb.append(String.format("\\x%02x", b & 0xff));
            }
            return sb.toString();
        } catch (Exception e) {
            return "<unreadable>";
        }
    }

    private void resolvePool(PrintWriter out, long start, long end) {
        out.println("// -- literal pool [" + Long.toHexString(start) + "," + Long.toHexString(end) + ") resolved --");
        for (long v = start; v < end; v += 4) {
            try {
                int word = getInt(toAddr(v));           // little-endian word = pointer
                long p = ((long) word) & 0xffffffffL;
                String s = "";
                if (p > 0x1000 && p < 0x400000) s = cstr(p);
                out.println(String.format("//  %08x -> %08x  \"%s\"", v, p, s));
            } catch (MemoryAccessException e) {
                out.println(String.format("//  %08x -> <no mem>", v));
            }
        }
        out.println();
    }

    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        String outfile = (a.length >= 1 && !a[0].isEmpty()) ? a[0] : "auth_probe.c";
        PrintWriter out = new PrintWriter(new FileWriter(outfile));

        DecompInterface deco = new DecompInterface();
        deco.openProgram(currentProgram);
        ConsoleTaskMonitor mon = new ConsoleTaskMonitor();
        FunctionManager fm = currentProgram.getFunctionManager();

        // Decompile the gate + helpers + dispatcher.
        long[] targets = { 0x19164L, 0xad8cL, 0xb5ccL, 0x239b4L, 0x13ae4L };
        for (long t : targets) {
            Function f = fm.getFunctionContaining(toAddr(t));
            out.println("// ===== " + String.format("0x%x", t) + " -> "
                + (f != null ? f.getName() + "@" + f.getEntryPoint() : "?") + " =====");
            if (f != null) {
                DecompileResults r = deco.decompileFunction(f, 240, mon);
                if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null)
                    out.print(r.getDecompiledFunction().getC());
                else
                    out.println("// <decompile failed/timeout>");
            }
            out.println();
        }

        // Resolve the dispatcher's action-name pool and the openvpn handler pool.
        resolvePool(out, 0x24040L, 0x24110L);
        resolvePool(out, 0x1eb74L, 0x1ebb0L);

        out.close();
        println("[auth_probe] wrote " + outfile);
    }
}
