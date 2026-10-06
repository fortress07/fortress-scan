package corpus.tier1;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ImportController {

    @PostMapping("/import")
    public Object importBlob(@RequestBody byte[] blob) throws Exception {
        ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(blob));
        return in.readObject(); // fsb-expect: FSB-DESER-001
    }

    @PostMapping("/formula")
    public Object formula(@RequestParam String expression) throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
        return engine.eval(expression); // fsb-expect: FSB-EXEC-001
    }

    @PostMapping("/plugin")
    public Object plugin(@RequestParam("name") String name) throws Exception {
        return Class.forName(name).getDeclaredConstructor().newInstance(); // fsb-expect: FSB-IMPORT-001
    }

    @PostMapping("/plugin-safe")
    public Object pluginSafe(@RequestParam("name") String name) throws Exception {
        if (!"csv".equals(name)) {
            return null;
        }
        return Class.forName("corpus.tier1.CsvPlugin").getDeclaredConstructor().newInstance();
    }
}
