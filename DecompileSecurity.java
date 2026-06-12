// DecompileSecurity.java - no-analysis mode
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import java.io.*;

public class DecompileSecurity extends GhidraScript {

    @Override
    public void run() throws Exception {
        println("=== Decompiling encryption functions (no-analysis) ===");
        
        File outDir = new File("output");
        outDir.mkdirs();
        
        SymbolTable symTable = currentProgram.getSymbolTable();
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        
        // Target function name patterns
        String[] patterns = {
            "SecurityUtil", "TTVNetworkSecurity", "Encryption", "AUEncryption",
            "RSA", "TXRSA", "TXCRSA", "TTV_Security",
            "encrypt", "decrypt", "AES", "hmac", "HMAC",
            "setAuthToken", "headerCheck", "getHeaderCheck",
            "signature", "createHeader", "requestHeader", "secretHeader",
            "ttv_addHeader", "addHeaderForSign", "CreateTTVRequest",
            "getTcdnGetParam", "tvChannelPlayUrlWithPk",
            "encrypyAES", "encryptAESData", "encryptAES", "decryptAES",
            "ttv_hmac", "hmacSha256", "hmacBase64",
            "signatureHashWithBody", "base64EncodeHmac"
        };
        
        int found = 0;
        SymbolIterator syms = symTable.getAllSymbols(true);
        
        while (syms.hasNext() && !monitor.isCancelled()) {
            Symbol sym = syms.next();
            if (sym.getSymbolType() != SymbolType.FUNCTION && 
                sym.getSymbolType() != SymbolType.LABEL) continue;
            
            String name = sym.getName().toLowerCase();
            boolean match = false;
            for (String p : patterns) {
                if (name.contains(p.toLowerCase())) {
                    match = true;
                    break;
                }
            }
            if (!match) continue;
            
            // Create function if not exists
            Address addr = sym.getAddress();
            Function func = getFunctionAt(addr);
            if (func == null) {
                try {
                    func = createFunction(addr, sym.getName());
                } catch (Exception e) {
                    continue;
                }
            }
            if (func == null) continue;
            
            // Decompile
            try {
                DecompileResults res = decomp.decompileFunction(func, 30, monitor);
                if (res != null && res.decompileCompleted()) {
                    String code = res.getDecompiledFunction().getC();
                    if (code != null && code.length() > 20) {
                        String safeName = func.getName().replaceAll("[^a-zA-Z0-9_]", "_");
                        if (safeName.length() > 80) safeName = safeName.substring(0, 80);
                        
                        File out = new File(outDir, safeName + ".c");
                        PrintWriter pw = new PrintWriter(new FileWriter(out));
                        pw.println("// " + func.getName());
                        pw.println("// address: " + func.getEntryPoint());
                        pw.println();
                        pw.println(code);
                        pw.close();
                        
                        found++;
                        if (found <= 100) {
                            println("  [" + found + "] " + func.getName() + " (" + code.length() + " chars)");
                        }
                    }
                }
            } catch (Exception e) {
                // skip decompile failures
            }
            
            if (found >= 200) break; // limit output
        }
        
        decomp.closeProgram();
        println("=== Done. " + found + " functions decompiled ===");
    }
}
