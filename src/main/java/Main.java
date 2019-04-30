import net.sourceforge.argparse4j.ArgumentParsers;
import net.sourceforge.argparse4j.inf.ArgumentParser;
import net.sourceforge.argparse4j.inf.ArgumentParserException;
import net.sourceforge.argparse4j.inf.Namespace;

import java.io.File;


public class Main {
    public enum MODE {
        se,sd,hf,hv,ae,ad,cc
    }

    static String infile = "transaction.xml";
    static String outfile = "transaction.cpt";

    public static void main(String[] args) throws Exception{


        ArgumentParser parser = initArgParserHelper();
        Namespace ns = processArgs(args,parser);

        String mode = ns.getString("mode");

        infile = ns.getString("infile");
        outfile = ns.getString("outfile");

        switch( MODE.valueOf( mode ) ) {
            case se:
                System.out.println( "## Symmetric encryption" );
                MyCipher.EncryptFile(new File(infile),ns.getString("password"),outfile);
                break;
            case sd:
                System.out.println( "## Symmetric decryption" );
                MyCipher.DecryptFile(new File(infile),ns.getString("password"),outfile);
                break;
            case hf:
                System.out.println( "## Hash function" );
                break;
            case hv:
                System.out.println( "## Hash verification" );
                break;
            case ae:
                System.out.println( "## Asymmetric encryption" );
                break;
            case ad:
                System.out.println( "## Asymmetric decryption" );
                break;
            case cc:
                System.out.println( "## Certificate creation" );
                break;
            default:
                System.err.println( "## Illegal mode parameter" );
                break;
        }


/*
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance(ns.getString("type"));
        } catch (NoSuchAlgorithmException e) {
            System.err.printf("Could not get instance of algorithm %s: %s",
                    ns.getString("type"), e.getMessage());
            System.exit(1);
        }
        for (String name : ns.<String> getList("file")) {
            Path path = Paths.get(name);
            try (ByteChannel channel = Files.newByteChannel(path,
                    StandardOpenOption.READ);) {
                ByteBuffer buffer = ByteBuffer.allocate(4096);
                while (channel.read(buffer) > 0) {
                    buffer.flip();
                    digest.update(buffer);
                    buffer.clear();
                }
            } catch (IOException e) {
                System.err
                        .printf("%s: failed to read data: %s", e.getMessage());
                continue;
            }
            byte md[] = digest.digest();
            StringBuffer sb = new StringBuffer();
            for (int i = 0, len = md.length; i < len; ++i) {
                String x = Integer.toHexString(0xff & md[i]);
                if (x.length() == 1) {
                    sb.append("0");
                }
                sb.append(x);
            }
            System.out.printf("%s  %s\n", sb.toString(), name);
        }
        */
    }

    private static Namespace processArgs(String[] args,ArgumentParser parser) {


        Namespace ns = null;
        try {
            ns = parser.parseArgs(args);
        } catch (ArgumentParserException e) {
            parser.handleError(e);
            System.exit(1);
        }

        return ns;
    }

    private static ArgumentParser initArgParserHelper() {
        ArgumentParser parser = ArgumentParsers.newFor("cypher").build()
                .defaultHelp(true)
                .description("Cypher is a library to perform cryptographic operations, such as symmetric and asymmetric" +
                        " encryption/decryption, file hashing, creation of certificates among others. " +
                        "\n Select the operation mode (-m) and the input file to operate on (-f) and choose a password (-p) and/or " +
                        " and output file (-o) with the results of the procedure.");

        parser.addArgument("-m","--mode").required(true)
                .choices("se", "sd", "hf", "hv", "ae", "ad", "cc").setDefault("cs")
                .help("Select the crypto operation to perform " +
                        "\n se - Symmetric encryption " +
                        "\n sd - Symmetric decryption " +
                        "\n hf - Hash function " +
                        "\n hv - Hash verification" +
                        "\n ae - Asymmetric encryption " +
                        "\n ad - Asymmetric decryption " +
                        "\n cc - Certificate creation ");
        parser.addArgument("-p","-password").type(String.class)
                .help("Password/key/passphrase.");
        parser.addArgument("-i", "-infile").type(File.class).required(true).metavar("FILE")
                .help("Input file ");
        parser.addArgument("-o", "-outfile").type(File.class).metavar("FILE")
                .help("Output file.");
        return parser;
    }

}
/*
    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());

        System.out.println("******************************");
        System.out.println("******** MULTI-CYPHER ********");


        int swValue;
        System.out.println("******************************");

        System.out.println("Menu:\n");
        System.out.println("1. Option 1 ");
        System.out.println("2. Option 2 ");
        System.out.println("3. Exit\n");

        swValue = Keyin.inInt("Select option: ");

        // Switch construct
        switch (swValue) {
            case 1:
                System.out.println("Option 1 selected");
                break;
            case 2:
                System.out.println("Option 2 selected");
                break;
            case 3:
                System.out.println("Exit selected");
                break;
            default:
                System.out.println("Invalid selection");
                break; // This break is not really necessary
        }
    }
}
*/

/*
class Keyin {

    //*******************************
    //   support methods
    //*******************************
    //Method to display the user's prompt string
    public static void printPrompt(String prompt) {
        System.out.print(prompt + " ");
        System.out.flush();
    }

    //Method to make sure no data is available in the
    //input stream
    public static void inputFlush() {
        int dummy;
        int bAvail;

        try {
            while ((System.in.available()) != 0)
                dummy = System.in.read();
        } catch (java.io.IOException e) {
            System.out.println("Input error");
        }
    }

    public static String inString() {
        int aChar;
        String s = "";
        boolean finished = false;

        while (!finished) {
            try {
                aChar = System.in.read();
                if (aChar < 0 || (char) aChar == '\n')
                    finished = true;
                else if ((char) aChar != '\r')
                    s = s + (char) aChar; // Enter into string
            } catch (java.io.IOException e) {
                System.out.println("Input error");
                finished = true;
            }
        }
        return s;
    }

    public static int inInt(String prompt) {
        while (true) {
            inputFlush();
            printPrompt(prompt);
            try {
                return Integer.valueOf(inString().trim()).intValue();
            } catch (NumberFormatException e) {
                System.out.println("Invalid input. Not an integer");
            }
        }
    }

}*/