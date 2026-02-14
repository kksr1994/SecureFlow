// INTENTIONALLY VULNERABLE JAVASCRIPT
// DO NOT USE IN PRODUCTION!

// VULNERABILITY 1: Hardcoded API keys
const AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const STRIPE_KEY = "sk_live_51H8xK2L3m4N5o6P7q8R9s0T1u2V3w4X5y6Z";

// VULNERABILITY 2: SQL Injection
function searchUsers(username) {
    // BAD: String concatenation in SQL
    const query = "SELECT * FROM users WHERE username = '" + username + "'";
    db.execute(query);  // SQL Injection!
}

// VULNERABILITY 3: XSS vulnerability
function displayMessage(userInput) {
    // BAD: Directly inserting user input into DOM
    document.getElementById('message').innerHTML = userInput;  // XSS!
}

// VULNERABILITY 4: eval() usage
function runCode(code) {
    // BAD: eval() with user input
    eval(code);  // Code injection!
}

// VULNERABILITY 5: Weak random number generation
function generateToken() {
    // BAD: Math.random() is not cryptographically secure
    return Math.random().toString(36).substring(2);
}

// VULNERABILITY 6: Prototype pollution
function merge(target, source) {
    // BAD: No prototype protection
    for (let key in source) {
        target[key] = source[key];  // Prototype pollution!
    }
}

// VULNERABILITY 7: Insecure deserialization
function loadData(serialized) {
    // BAD: Deserializing untrusted data
    return JSON.parse(serialized);
}

// VULNERABILITY 8: Regex DoS
function validateEmail(email) {
    // BAD: Inefficient regex
    const regex = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
    return regex.test(email);
}
