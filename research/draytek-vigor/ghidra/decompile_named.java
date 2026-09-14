//@category firmware-diff
import java.io.*; import ghidra.app.script.GhidraScript; import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*; import ghidra.util.task.ConsoleTaskMonitor;
public class decompile_named extends GhidraScript { public void run() throws Exception {
 String[] a=getScriptArgs(); PrintWriter out=new PrintWriter(new FileWriter(a[0]));
 java.util.Set<String> names=new java.util.HashSet<>(); for(int i=1;i<a.length;i++) names.add(a[i]);
 DecompInterface d=new DecompInterface(); d.openProgram(currentProgram); ConsoleTaskMonitor m=new ConsoleTaskMonitor();
 FunctionIterator it=currentProgram.getFunctionManager().getFunctions(true);
 while(it.hasNext()){ Function f=it.next(); if(!names.contains(f.getName())) continue;
   out.println("// ===== "+f.getName()+" @ "+f.getEntryPoint()+" =====");
   DecompileResults r=d.decompileFunction(f,240,m);
   if(r!=null&&r.decompileCompleted()&&r.getDecompiledFunction()!=null) out.print(r.getDecompiledFunction().getC()); else out.println("// decompile failed");
   out.println(); }
 out.close(); println("wrote "+a[0]); } }
