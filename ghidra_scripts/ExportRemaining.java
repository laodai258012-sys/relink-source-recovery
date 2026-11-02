import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.parallel.DecompilerCallback;
import ghidra.app.decompiler.parallel.ParallelDecompiler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import java.io.BufferedWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class ExportRemaining extends GhidraScript {
    private int succeeded = 0;
    private int failed = 0;
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        Path root = Path.of(arguments[0]);
        long lower = Long.decode(arguments[1]);
        long upper = Long.decode(arguments[2]);
        boolean leafPass = arguments.length > 3 && arguments[3].equals("leaf");
        String prefix = leafPass ? "leaf" : "remaining";
        List<String> records = Files.readAllLines(root.resolve(leafPass ? "leaf_candidate_index.csv" : "function_index.csv"));
        long started = System.currentTimeMillis();
        try (ZipOutputStream archive = new ZipOutputStream(Files.newOutputStream(root.resolve(prefix + "_decompiled.zip")));
             BufferedWriter status = Files.newBufferedWriter(root.resolve(prefix + "_status.tsv"), StandardCharsets.UTF_8)) {
            status.write("rva\tstatus\tdetail\n");
            DecompilerCallback<Void> callback = new DecompilerCallback<Void>(currentProgram, decompiler -> {
                decompiler.toggleCCode(true);
                decompiler.toggleSyntaxTree(false);
            }) {
                public Void process(DecompileResults result, TaskMonitor taskMonitor) throws Exception {
                    String name = Long.toHexString(result.getFunction().getEntryPoint().getOffset() - 0x140000000L);
                    synchronized (archive) {
                        if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                            archive.putNextEntry(new ZipEntry("decompiled/" + name + ".c"));
                            archive.write(result.getDecompiledFunction().getC().getBytes(StandardCharsets.UTF_8));
                            archive.closeEntry();
                            status.write(name + "\tok\t\n");
                            succeeded++;
                        } else {
                            status.write(name + "\tfailed\t" + result.getErrorMessage().replace('\n', ' ') + "\n");
                            failed++;
                        }
                        status.flush();
                    }
                    return null;
                }
            };
            callback.setTimeout(10);
            try {
                List<Function> batch = new ArrayList<>();
                for (int index = 1; index < records.size(); index++) {
                    if (monitor.isCancelled()) break;
                    String[] columns = records.get(index).split(",");
                    long begin = Long.parseLong(columns[0], 16);
                    long end = Long.parseLong(columns[1], 16);
                    if (begin < lower || begin >= upper) continue;
                    Address entry = toAddr(0x140000000L + begin);
                    AddressSet body = new AddressSet(entry, toAddr(0x140000000L + end - 1));
                    try {
                        new DisassembleCommand(entry, body, true).applyTo(currentProgram, monitor);
                        Function function = currentProgram.getFunctionManager().getFunctionAt(entry);
                        if (function == null) function = currentProgram.getFunctionManager().createFunction("recovered_" + columns[0], entry, body, SourceType.ANALYSIS);
                        batch.add(function);
                    } catch (Exception error) {
                        status.write(columns[0] + "\texception\t" + error.toString().replace('\n', ' ') + "\n");
                        status.flush();
                        failed++;
                    }
                    if (batch.size() >= 256) {
                        ParallelDecompiler.decompileFunctions(callback, batch, monitor);
                        batch.clear();
                        println("RECOVERY_PROGRESS " + succeeded + " ok " + failed + " failed " + ((System.currentTimeMillis()-started)/1000) + " sec");
                    }
                }
                if (!batch.isEmpty()) ParallelDecompiler.decompileFunctions(callback, batch, monitor);
            } finally {
                callback.dispose();
            }
        }
        println("RECOVERY_DONE " + succeeded + " ok " + failed + " failed");
    }
}

