import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Map;

public class PythonProcessBuilder {

    public static void main(String[] args) {
        // Ensure all required arguments are provided
        if (args.length < 4) {
            System.out.println("Usage: java PythonProcessBuilder <jsonFilePath> <codeSnippet> <rule> <message>");
            System.exit(1);
        }

        // Retrieve command-line arguments dynamically
        String jsonFilePath = args[0];
        String codeSnippet = args[1];
        String rule = args[2];
        String message = args[3];

        // Define the Python interpreter command and the path to your Python script (main.py)
        String pythonInterpreter = "python";  // Use "python3" if necessary
        String scriptPath = "D://SECAI//main.py"; // Update with the actual path

        // Build the ProcessBuilder command with dynamic arguments
        ProcessBuilder processBuilder = new ProcessBuilder(
                pythonInterpreter,
                scriptPath,
                "--json_file", jsonFilePath,
                "--code", codeSnippet,
                "--rule", rule,
                "--msg", message
        );

        // Optionally set the working directory to where your Python modules are located
        processBuilder.directory(new File("D://SECAI")); // Update accordingly

        // Set required environment variables (e.g., OPENAI_API_KEY)
        Map<String, String> env = processBuilder.environment();
        env.put("OPENAI_API_KEY", "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"); // Update with your actual API key

        // Redirect error stream to merge with standard output
        processBuilder.redirectErrorStream(true);

        try {
            // Start the process
            Process process = processBuilder.start();

            // Read and print the output from the Python process
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            System.out.println("Output from Python script:");
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }

            // Wait for the process to finish and get the exit code
            int exitCode = process.waitFor();
            System.out.println("Process exited with code: " + exitCode);
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }
}
