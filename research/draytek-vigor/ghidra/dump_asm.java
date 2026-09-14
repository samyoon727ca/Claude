// Dump raw assembly listing for functions containing the given addresses,
// so calling-convention / return-value questions can be settled from the
// instructions rather than the (lossy) decompiler C.
//
// postScript args:  <output_file.txt>  <addr_hex> [addr_hex ...]
//@category firmware-diff
import java.io.FileWriter;
import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;

public class dump_asm extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        PrintWriter out = new PrintWriter(new FileWriter(a[0]));
        FunctionManager fm = currentProgram.getFunctionManager();
        Listing lst = currentProgram.getListing();
        for (int i = 1; i < a.length; i++) {
            long v = Long.decode(a[i]);
            Function f = fm.getFunctionContaining(toAddr(v));
            out.println("// ===== " + a[i] + " -> "
                + (f != null ? f.getName() + "@" + f.getEntryPoint() : "?") + " =====");
            if (f == null) { out.println(); continue; }
            InstructionIterator it = lst.getInstructions(f.getBody(), true);
            while (it.hasNext()) {
                Instruction ins = it.next();
                String cmt = lst.getComment(ghidra.program.model.listing.CodeUnit.EOL_COMMENT, ins.getAddress());
                out.println(String.format("%08x  %-32s %s",
                    ins.getAddress().getOffset(), ins.toString(), cmt != null ? "; " + cmt : ""));
            }
            out.println();
        }
        out.close();
        println("[dump_asm] wrote " + a[0]);
    }
}
