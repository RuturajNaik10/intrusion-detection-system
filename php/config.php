<?php
// Database connection parameters
$servername = "localhost";
$username = "NET";
$password = "root";
$database = "Network_Sys";

// Create connection
$link = mysqli_connect($servername, $username, $password, $database);

// Check connection
if (!$link) {
    die("Connection failed: " . mysqli_connect_error());
}
?>
