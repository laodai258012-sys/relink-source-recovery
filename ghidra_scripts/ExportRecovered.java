import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import java.io.BufferedWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class ExportRecovered extends GhidraScript {
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        Path root = Path.of(arguments[0]);
        long lower = Long.decode(arguments[1]);
        long upper = Long.decode(arguments[2]);
        Path output = root.resolve("decompiled");
        Files.createDirectories(output);
        List<String> records = Files.readAllLines(root.resolve("function_index.csv"));
        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(false);
        decompiler.openProgram(currentProgram);
        int succeeded = 0;
        int failed = 0;
        long started = System.currentTimeMillis();
        try (BufferedWriter status = Files.newBufferedWriter(root.resolve("decompile_status_" + Long.toHexString(lower) + ".tsv"), StandardCharsets.UTF_8)) {
            status.write("rva\tstatus\tdetail\n");
            for (int index = 1; index < records.size(); index++) {
                if (monitor.isCancelled()) break;
                String[] columns = records.get(index).split(",");
                long begin = Long.parseLong(columns[0], 16);
                long end = Long.parseLong(columns[1], 16);
                if (begin < lower || begin >= upper) continue;
                Address entry = toAddr(0x140000000L + begin);
                AddressSet body = new AddressSet(entry, toAddr(0x140000000L + end - 1));
                try {
                    DisassembleCommand command = new DisassembleCommand(entry, body, true);
                    command.applyTo(currentProgram, monitor);
                    Function function = currentProgram.getFunctionManager().getFunctionAt(entry);
                    if (function == null) function = currentProgram.getFunctionManager().createFunction("recovered_" + columns[0], entry, body, SourceType.ANALYSIS);
                    DecompileResults result = decompiler.decompileFunction(function, 20, monitor);
                    if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                        Files.writeString(output.resolve(columns[0] + ".c"), result.getDecompiledFunction().getC(), StandardCharsets.UTF_8);
                        status.write(columns[0] + "\tok\t" + (end - begin) + "\n");
                        succeeded++;
                    } else {
                        status.write(columns[0] + "\tfailed\t" + result.getErrorMessage().replace('\n', ' ') + "\n");
                        failed++;
                    }
                } catch (Exception error) {
                    status.write(columns[0] + "\texception\t" + error.toString().replace('\n', ' ') + "\n");
                    failed++;
                }
                status.flush();
                if ((succeeded + failed) % 100 == 0) println("RECOVERY_PROGRESS " + succeeded + " ok " + failed + " failed " + ((System.currentTimeMillis()-started)/1000) + " sec");
            }
        } finally {
            decompiler.dispose();
        }
        println("RECOVERY_DONE " + succeeded + " ok " + failed + " failed");
    }
}

