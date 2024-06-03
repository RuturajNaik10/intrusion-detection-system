<?php
include 'config.php'; // Include the database connection
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['submit'])) {
// Retrieve data from the form
$username = $_POST['username'];
$password = $_POST['password'];
$email = $_POST['email'];
// Insert data into the database
$sql = "INSERT INTO users (username, password, emailid) VALUES ('$username', '$password', '$email')";
if (mysqli_query($link, $sql)) {
//echo "Registration successful!"
header("Location: ../index.html");
exit();
} else {
echo "Error: " . $sql . "<br>" . mysqli_error($link);
}
}
mysqli_close($link);
?>