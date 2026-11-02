import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.parallel.DecompilerCallback;
import ghidra.app.decompiler.parallel.ParallelDecompiler;
import ghidra.program.model.listing.Function;
import ghidra.util.task.TaskMonitor;
import java.io.BufferedWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class RetryFailed extends GhidraScript {
    public void run() throws Exception {
        Path root = Path.of(getScriptArgs()[0]);
        List<Function> functions = new ArrayList<>();
        for (String file : new String[]{"decompile_status_1000.tsv", "remaining_status.tsv"}) {
            for (String line : Files.readAllLines(root.resolve(file))) {
                String[] columns = line.split("\t", -1);
                if (columns[0].equals("rva") || columns[1].equals("ok")) continue;
                Function function = currentProgram.getFunctionManager().getFunctionAt(toAddr(0x140000000L + Long.parseLong(columns[0],16)));
                if (function != null) functions.add(function);
            }
        }
        try (ZipOutputStream archive = new ZipOutputStream(Files.newOutputStream(root.resolve("retry_decompiled.zip")));
             BufferedWriter status = Files.newBufferedWriter(root.resolve("retry_status.tsv"), StandardCharsets.UTF_8)) {
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
                            status.write(name + "\tok\t60-second retry with all function boundaries present\n");
                        } else {
                            status.write(name + "\tfailed\t" + result.getErrorMessage().replace('\n', ' ') + "\n");
                        }
                        status.flush();
                    }
                    return null;
                }
            };
            callback.setTimeout(60);
            try {
                ParallelDecompiler.decompileFunctions(callback, functions, monitor);
            } finally {
                callback.dispose();
            }
        }
        println("RETRY_DONE " + functions.size());
    }
}

