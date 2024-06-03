function showError(message) {
    const errorMessage = document.getElementById('errorMessage');
    errorMessage.innerText = message;
    errorMessage.style.display = 'block';
    setTimeout(() => {
        errorMessage.style.display = 'none';
    }, 4000); // Hide after 4 seconds
}

function getPacketCounts() {
    fetch('http://192.168.137.161:5000/api/packet-counts', {
        mode: 'cors',
        method: 'GET',
        headers: {
            'Content-Type': 'application/json'
        }
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.json(); // Parse response body as JSON
    })
    .then(data => {
        // Update HTML content with the received data
        document.getElementById('Tclck').innerHTML = data.tcp_packets;
        document.getElementById('Uclck').innerHTML = data.udp_packets;
        document.getElementById('Iclck').innerHTML = data.icmp_packets;
        document.getElementById('HTclck').innerHTML = data.http_packets;
        document.getElementById('HTPclck').innerHTML = data.https_packets;
        document.getElementById('dnsclck').innerHTML = data.dns_packets;
        document.getElementById('smptclck').innerHTML = data.smtp_packets;
        document.getElementById('telnetclck').innerHTML = data.telnet_packets;
    })
    .catch(error => {
        console.error('Error fetching packet counts:', error);
        showError('Unable to connect. Please try again later.');
    });
}

// Call the function to fetch packet counts periodically
setInterval(getPacketCounts, 2000); // Fetch every 5 seconds
