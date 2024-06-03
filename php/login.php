<?php

include 'config.php'; // Include the database connection

// Retrieve username and password from the form
$user = $_POST['username'];
$pass = $_POST['password'];

// Query to check if the username and password match
$sql = "SELECT * FROM users WHERE username='$user' AND password='$pass'";
$result = mysqli_query($link, $sql);


// Check if there's a match
if (mysqli_num_rows($result) > 0) {
    // Redirect to dashboard with username as a query parameter
    header("Location: ../dashboard.html");
    exit();
} else {
    // Redirect back to login page with error message
    header("Location: ../index.html?error=invalid_credentials");
    exit();
}

mysqli_close($link); // Close the database connection
?>
