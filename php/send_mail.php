<?php
// Include PHPMailer autoload file
require 'vendor/autoload.php';
include 'config.php';
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

// Check if email is posted
if (isset($_POST['email'])) {
    // Create a new PHPMailer instance
    $mail = new PHPMailer(true); // Set to true for exception handling
    $conn = new mysqli($servername, $username, $password, $database);

    // Check connection
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }

    $email = $_POST['email'];

    $sql = "SELECT * FROM users WHERE emailid = '$email'";
    $result = $conn->query($sql);
    if ($result->num_rows > 0) {
        echo "Email exists!";
        try {
            $url = 'http://192.168.137.161:1200/api/otp';
            $response = file_get_contents($url);
            $data = json_decode($response, true);
            if ($data !== null) {
                if (isset($data['otp'])) {
                    echo "OTP: " . $data['otp'];
                    try{

                        $mail->isSMTP();
                        $mail->Host = 'smtp.gmail.com'; // Your SMTP server address
                        $mail->SMTPAuth = true;
                        $mail->Username = 'naikpratham88@gmail.com'; // Your email address
                        $mail->Password = 'dvggsssdufqbmfak'; // Your email password
                        $mail->SMTPSecure = 'tls'; // Enable TLS encryption, 'ssl' also accepted
                        $mail->Port = 587; // TCP port to connect to

                            // Email Content
                        $mail->setFrom('netwoksystems@gmail.com', 'Network systems');
                        $mail->addAddress($email); // Recipient email address
                        $mail->Subject = 'OTP for your Network System';
                        $mail->Body = 'OTP is ' . $data['otp'];

                        // Send Email
                        $mail->send();
                        $filePath = "otp.txt";
                        $fileHandle = fopen($filePath, "w");
                        fwrite($fileHandle, $data['otp']);
                        fclose($fileHandle);
                        header("Location: ../otp.html");
                        exit;
                        } 
                        catch (Exception $e)
                        {
                            echo 'Failed to send email. Error: ' . $mail->ErrorInfo;
                            exit;
                        }

                    }
                    else 
                    {
                        echo "OTP not found in response data.";
                    }
            } 
            else 
            {
                echo "Failed to decode JSON response.";
            }
        }
        catch (Exception $e){
            echo 'Failed to send email. Error: ';
        } 
    } 
    else 
    {
        echo "Email does not exist!";
    }
    $conn->close();
} else {
    echo "Email is not provided!";
}
?>
