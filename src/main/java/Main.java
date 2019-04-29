import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

public class Main {

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

}