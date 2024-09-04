import java.security.SecureRandom;
import java.util.*;
import java.util.function.Predicate;
import java.util.stream.Collectors;

public class Passgen {

    // Default character sets
    private static final String LOWERCASE = "abcdefghijkmnopqrstuvwxyz";
    private static final String UPPERCASE = "ABCDEFGHJKLMNPQRSTUVWXYZ"; // Excludes 'I', 'O'
    private static final String NUMBERS = "23456789"; // Excludes '0'
    private static final String SPECIAL_CHARACTERS = "!@#$%^&*()-_=+<>?";

    private static final Map<String, String> DEFAULT_SETS = Map.of(
        "lowercase", LOWERCASE,
        "uppercase", UPPERCASE,
        "numbers", NUMBERS,
        "special", SPECIAL_CHARACTERS
    );

    private static final Set<String> COMMON_PASSWORDS = Set.of(
        "password", "123456", "123456789", "qwerty", "abc123", "password1",
        "12345678", "12345", "qwerty123", "1234567", "letmein", "monkey", "123123",
        "welcome", "1234567", "password123", "admin", "qwertyuiop", "123321"
    );

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        // Get user preferences
        System.out.print("Enter the desired password length: ");
        int length = scanner.nextInt();
        scanner.nextLine(); // Consume newline

        Map<String, String> customSets = new HashMap<>(DEFAULT_SETS);

        // Collect user preferences
        Map<String, Boolean> includeOptions = Map.of(
            "lowercase", getUserPreference(scanner, "Include lowercase letters? (y/n): "),
            "uppercase", getUserPreference(scanner, "Include uppercase letters? (y/n): "),
            "numbers", getUserPreference(scanner, "Include numbers? (y/n): "),
            "special", getUserPreference(scanner, "Include special characters? (y/n): ")
        );

        // Custom sets input
        if (getUserPreference(scanner, "Use custom character sets? (y/n): ")) {
            customSets.replace("lowercase", getUserInput(scanner, "Enter custom lowercase characters (leave empty for default): ", LOWERCASE));
            customSets.replace("uppercase", getUserInput(scanner, "Enter custom uppercase characters (leave empty for default): ", UPPERCASE));
            customSets.replace("numbers", getUserInput(scanner, "Enter custom numbers characters (leave empty for default): ", NUMBERS));
            customSets.replace("special", getUserInput(scanner, "Enter custom special characters (leave empty for default): ", SPECIAL_CHARACTERS));
        }

        // Generate and display the password
        String password = generatePassword(length, includeOptions, customSets);

        String strength = evaluatePasswordStrength(password);
        double entropy = calculateEntropy(password);

        System.out.println("Generated Password: " + password);
        System.out.println("Password Strength: " + strength);
        System.out.println("Password Entropy: " + entropy + " bits");
        System.out.println("Is the password too common? " + (isCommonPassword(password) ? "Yes" : "No"));

        scanner.close();
    }

    private static boolean getUserPreference(Scanner scanner, String prompt) {
        System.out.print(prompt);
        return scanner.nextLine().toLowerCase().charAt(0) == 'y';
    }

    private static String getUserInput(Scanner scanner, String prompt, String defaultValue) {
        System.out.print(prompt);
        String input = scanner.nextLine();
        return input.isEmpty() ? defaultValue : input;
    }

    private static String generatePassword(int length, Map<String, Boolean> includeOptions, Map<String, String> characterSets) {
        StringBuilder combinedSet = new StringBuilder();
        Map<String, Predicate<String>> requirements = new HashMap<>();
        SecureRandom random = new SecureRandom();

        // Build combined character set and requirements based on user input
        characterSets.forEach((type, chars) -> {
            if (includeOptions.getOrDefault(type, false)) {
                combinedSet.append(chars);
                requirements.put(type, pwd -> containsAny(pwd, chars));
            }
        });

        if (combinedSet.length() == 0) {
            throw new IllegalArgumentException("At least one character set must be included.");
        }

        // Generate the password
        StringBuilder password = new StringBuilder(length);
        while (password.length() < length) {
            int index = random.nextInt(combinedSet.length());
            password.append(combinedSet.charAt(index));
        }

        // Ensure complexity requirements
        requirements.forEach((type, predicate) -> {
            if (!predicate.test(password.toString())) {
                password.setCharAt(random.nextInt(length), combinedSet.charAt(random.nextInt(combinedSet.length())));
            }
        });

        return password.toString();
    }

    private static boolean containsAny(String password, String characterSet) {
        return characterSet.chars().anyMatch(c -> password.indexOf(c) >= 0);
    }

    public static String evaluatePasswordStrength(String password) {
        int length = password.length();
        boolean hasLowercase = containsAny(password, LOWERCASE);
        boolean hasUppercase = containsAny(password, UPPERCASE);
        boolean hasNumbers = containsAny(password, NUMBERS);
        boolean hasSpecialCharacters = containsAny(password, SPECIAL_CHARACTERS);

        if (length >= 12 && hasLowercase && hasUppercase && hasNumbers && hasSpecialCharacters) {
            return "Strong";
        } else if (length >= 8 && (hasLowercase || hasUppercase || hasNumbers || hasSpecialCharacters)) {
            return "Medium";
        } else {
            return "Weak";
        }
    }

    public static boolean isCommonPassword(String password) {
        return COMMON_PASSWORDS.contains(password.toLowerCase());
    }

    public static double calculateEntropy(String password) {
        int length = password.length();
        double charsetSize = LOWERCASE.length() + UPPERCASE.length() + NUMBERS.length() + SPECIAL_CHARACTERS.length();
        double entropy = length * Math.log(charsetSize) / Math.log(2);
        return entropy;
    }
}
