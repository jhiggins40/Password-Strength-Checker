#include <iostream>
#include <string>
#include <regex>
#include <set>
#include <fstream>

enum StrengthLevel { WEAK, MODERATE, STRONG, VERY_STRONG };

// Helper function for common patterns (repeated chars, sequences)
std::string checkCommonPatterns(const std::string& password) {
    if (std::regex_search(password, std::regex("(.)\\1{2,}")))
        return "Avoid using repeated characters.";
    if (std::regex_search(password, std::regex("012|123|234|345|456|567|678|789|890")))
        return "Avoid using sequential numbers.";
    if (std::regex_search(password, std::regex("abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm")))
        return "Avoid using sequential letters.";
    return "";
}

// Check for common dictionary words
std::string checkDictionaryWords(const std::string& password) {
    std::set<std::string> commonWords = {"password", "qwerty", "admin", "welcome", "letmein"};
    for (const auto& word : commonWords) {
        if (password.find(word) != std::string::npos)
            return "Avoid using common dictionary words.";
    }
    return "";
}

// Password strength checker function
StrengthLevel checkPasswordStrength(const std::string& password, std::vector<std::string>& feedback) {
    StrengthLevel strength = WEAK;
    const int MIN_LENGTH = 10;

    // Length check
    if (password.length() < MIN_LENGTH) {
        feedback.push_back("Password must be at least 10 characters.");
        return WEAK;
    } else if (password.length() >= MIN_LENGTH && password.length() < 12) {
        strength = MODERATE;
    } else if (password.length() >= 12 && password.length() < 16) {
        strength = STRONG;
    } else {
        strength = VERY_STRONG;
    }

    // Character type checks
    if (!std::regex_search(password, std::regex("[a-z]"))) {
        feedback.push_back("Pro tip: Add lowercase letters for a stronger password.");
        strength = WEAK;
    }
    if (!std::regex_search(password, std::regex("[A-Z]"))) {
        feedback.push_back("Pro tip: Add uppercase letters for a stronger password.");
        strength = WEAK;
    }
    if (!std::regex_search(password, std::regex("[0-9]"))) {
        feedback.push_back("Consider adding numbers for improved strength.");
        strength = WEAK;
    }
    if (!std::regex_search(password, std::regex("[@#$%^&+=!]"))) {
        feedback.push_back("Consider using special characters like @, #, or $.");
        strength = WEAK;
    }

    // Common pattern and dictionary word checks
    std::string patternFeedback = checkCommonPatterns(password);
    if (!patternFeedback.empty()) {
        feedback.push_back(patternFeedback);
        strength = WEAK;
    }
    
    std::string dictFeedback = checkDictionaryWords(password);
    if (!dictFeedback.empty()) {
        feedback.push_back(dictFeedback);
        strength = WEAK;
    }

    // Length recommendation for Very Strong
    if (password.length() >= 16 && strength == STRONG) {
        feedback.push_back("Great choice! For top security, consider a password 20+ characters long.");
    }

    return strength;
}

// Utility function to convert strength level to a string
std::string strengthToString(StrengthLevel strength) {
    switch (strength) {
        case WEAK: return "Weak";
        case MODERATE: return "Moderate";
        case STRONG: return "Strong";
        case VERY_STRONG: return "Very Strong";
    }
    return "Unknown";
}

// Main function for testing
int main() {
    std::string password;
    std::cout << "Welcome to James' Password Strength Checker!\n";
    std::cout << "Enter a password to check its security strength: ";
    std::getline(std::cin, password);

    std::vector<std::string> feedback;
    StrengthLevel strength = checkPasswordStrength(password, feedback);
    std::cout << "Password Strength: " << strengthToString(strength) << "\n";

    if (!feedback.empty()) {
        std::cout << "Suggestions to make it stronger:\n";
        for (const auto& tip : feedback) {
            std::cout << "- " << tip << "\n";
        }
    }

    // Option to save feedback to file
    std::ofstream output("password_feedback.txt");
    if (output.is_open()) {
        output << "Password Strength Feedback\n";
        output << "Strength: " << strengthToString(strength) << "\n";
        for (const auto& tip : feedback) {
            output << "- " << tip << "\n";
        }
        output.close();
        std::cout << "Feedback saved to password_feedback.txt\n";
    }

    return 0;
}
