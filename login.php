<?php
session_start();
include("config.php"); // Include your database connection details

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $Email = $_POST["Email"];
    $password = $_POST["password"];

    // Validate and sanitize user input
    $Email = filter_var($Email, FILTER_SANITIZE_EMAIL);

    // Hash the password
    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

    // Check the database for the user
    $stmt = $pdo->prepare("SELECT * FROM users WHERE email = :email");
    $stmt->bindParam(':email', $Email);
    $stmt->execute();
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user && password_verify($password, $user['password'])) {
        // Password is correct, set session and redirect
        $_SESSION['Email'] = $Email;
        header("Location: dashboard.php"); // Redirect to your dashboard page
        exit();
    } else {
        $error_message = "Invalid email or password. Please try again.";
    }
}
?>
