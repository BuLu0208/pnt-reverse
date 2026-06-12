// DecompileSecurity.java
// Ghidra headless post-script: finds and decompiles SecurityUtil & encryption methods
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import java.io.*;

public class DecompileSecurity extends GhidraScript {

    @Override
    public void run() throws Exception {
        println("=== Starting decompilation ===");
        
        File outDir = new File("output");
        outDir.mkdirs();
        
        Listing listing = currentProgram.getListing();
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        SymbolTable symTable = currentProgram.getSymbolTable();
        
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        
        // Key class patterns to find
        String[] targetPatterns = {
            "SecurityUtil",
            "TTVNetworkSecurity",
            "TTV_Security",
            "Encryption",
            "AUEncryption",
            "RSA",
            "TXRSA",
            "TXCRSA",
            "JCOREDataSecurity"
        };
        
        // Key method patterns
        String[] methodPatterns = {
            "encrypt", "decrypt", "AES", "hmac", "HMAC",
            "signature", "setAuthToken", "headerCheck",
            "getHeaderCheck", "Ca-", "getParam", "createHeader",
            "requestHeader", "secretHeader"
        };
        
        // Step 1: Find functions by class name (ObjC method prefix)
        println("Searching for class methods...");
        for (String pattern : targetPatterns) {
            for (Function func : funcMgr.getFunctions(true)) {
                String name = func.getName();
                if (name.toLowerCase().contains(pattern.toLowerCase())) {
                    decompileAndSave(decomp, func, outDir);
                }
            }
        }
        
        // Step 2: Find functions by method name pattern
        println("Searching for method name patterns...");
        for (Function func : funcMgr.getFunctions(true)) {
            String name = func.getName().toLowerCase();
            for (String pattern : methodPatterns) {
                if (name.contains(pattern.toLowerCase())) {
                    decompileAndSave(decomp, func, outDir);
                    break;
                }
            }
        }
        
        // Step 3: Find hardcoded strings near encryption functions
        println("Extracting data references...");
        try (PrintWriter pw = new PrintWriter(new FileWriter(new File(outDir, "strings_near_crypto.txt")))) {
            for (Function func : funcMgr.getFunctions(true)) {
                String name = func.getName().toLowerCase();
                boolean isCrypto = false;
                for (String p : methodPatterns) {
                    if (name.contains(p.toLowerCase())) { isCrypto = true; break; }
                }
                for (String p : targetPatterns) {
                    if (name.contains(p.toLowerCase())) { isCrypto = true; break; }
                }
                
                if (!isCrypto) continue;
                
                // Find string references in this function
                AddressSet body = new AddressSet(func.getBody());
                CodeUnitIterator iter = listing.getCodeUnits(body, true);
                while (iter.hasNext()) {
                    CodeUnit cu = iter.next();
                    Reference[] refs = cu.getReferencesFrom();
                    for (Reference ref : refs) {
                        if (ref.getReferenceType().isData()) {
                            Address toAddr = ref.getToAddress();
                            try {
                                Data data = listing.getDataAt(toAddr);
                                if (data != null && data.hasStringValue()) {
                                    String s = data.getDefaultValueRepresentation();
                                    if (s.length() >= 8 && s.length() <= 100) {
                                        pw.println("[" + func.getName() + "] " + s);
                                    }
                                }
                            } catch (Exception e) {}
                        }
                    }
                }
            }
        }
        
        decomp.closeProgram();
        println("=== Done. Check output/ directory ===");
    }
    
    private void decompileAndSave(DecompInterface decomp, Function func, File outDir) throws Exception {
        String safeName = func.getName().replaceAll("[^a-zA-Z0-9_\\-\\[\\]:]", "_");
        if (safeName.length() > 100) safeName = safeName.substring(0, 100);
        
        DecompileResults results = decomp.decompileFunction(func, 60, monitor);
        String code = results.getDecompiledFunction().getC();
        
        if (code != null && code.length() > 10) {
            File outFile = new File(outDir, safeName + ".c");
            try (PrintWriter pw = new PrintWriter(new FileWriter(outFile))) {
                pw.println("// Function: " + func.getName());
                pw.println("// Address: " + func.getEntryPoint());
                pw.println("// Signature: " + func.getSignature());
                pw.println();
                pw.println(code);
            }
            println("  Decompiled: " + safeName + ".c");
        }
    }
}
