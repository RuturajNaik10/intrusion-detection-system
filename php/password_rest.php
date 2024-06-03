<?php
include 'config.php'; // Include the database connection

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $email = $_POST['email'];

    // Check if the email exists in the database
    $sql = "SELECT * FROM users WHERE email='$email'";
    $result = mysqli_query($link, $sql);

    if (mysqli_num_rows($result) > 0) {
        // Generate a random temporary password
        $tempPassword = substr(md5(mt_rand()), 0, 8); // Change this to a more secure method

        // Update the user's password in the database
        $hashedPassword = password_hash($tempPassword, PASSWORD_DEFAULT);
        $updateSql = "UPDATE users SET password='$hashedPassword' WHERE email='$email'";
        mysqli_query($link, $updateSql);

        // Send the email with the temporary password
        $subject = "Password Reset";
        $message = "Your temporary password is: $tempPassword"; // This should be a more user-friendly message
        $headers = "From: network@example.com"; // Change this to your email address

        if (mail($email, $subject, $message, $headers)) {
            echo "An email with instructions to reset your password has been sent to your email address.";
        } else {
            echo "Failed to send email. Please try again later.";
        }
    } else {
        echo "Email not found in our records. Please try again.";
    }
}

mysqli_close($link); // Close the database connection
?>
