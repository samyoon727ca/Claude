//@category firmware-diff
import java.io.*; import ghidra.app.script.GhidraScript; import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address; import ghidra.program.model.listing.*; import ghidra.util.task.ConsoleTaskMonitor;
public class dump_addrs extends GhidraScript { public void run() throws Exception {
 String[] a=getScriptArgs(); PrintWriter out=new PrintWriter(new FileWriter(a[0]));
 DecompInterface d=new DecompInterface(); d.openProgram(currentProgram); ConsoleTaskMonitor m=new ConsoleTaskMonitor();
 FunctionManager fm=currentProgram.getFunctionManager();
 for(int i=1;i<a.length;i++){ long v=Long.decode(a[i]); Address ad=toAddr(v); Function f=fm.getFunctionContaining(ad);
   out.println("// ===== "+a[i]+" -> "+(f!=null?f.getName()+"@"+f.getEntryPoint():"?")+" =====");
   if(f!=null){ DecompileResults r=d.decompileFunction(f,120,m); if(r!=null&&r.decompileCompleted()&&r.getDecompiledFunction()!=null) out.print(r.getDecompiledFunction().getC()); else out.println("// decompile failed"); }
   out.println(); }
 out.close(); println("wrote "+a[0]); } }
