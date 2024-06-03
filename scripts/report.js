function fetchData(argument) {
    console.log("hrllo");
    const date = document.getElementById('date').value;
    const time = document.getElementById('time').value;
    console.log(date);
    console.log(time);
    fetch(`http://192.168.137.161:9000/api/get_data?date=${date}&time=${time}`, {
            mode: 'cors',
            method: 'GET',
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(jsonData => {
            var x = JSON.stringify(jsonData, null, 4);
            //let srcPort = jsonData.data['SRC-PORT'];
            console.log(jsonData["DST-IP"]);
            //document.getElementById('json-data').textContent = JSON.stringify(jsonData, null, 4);
            document.getElementById('protocol').innerHTML = jsonData["PROTOCOL"];
            document.getElementById('sip').innerHTML = jsonData["SRC-IP"];
            document.getElementById('dip').innerHTML = jsonData["DST-IP"];
            document.getElementById('psize').innerHTML = jsonData["PAYLOAD SIZE"];
            document.getElementById('pcount').innerHTML = jsonData["PACKET-COUNT"];

        })
        .catch(error => {
            console.error('Error:', error);
            showError('Unable to fetch data. Please try again later.');
        });
function showError(message) {
        const errorMessage = document.getElementById('errorMessage');
        errorMessage.innerText = message;
        errorMessage.style.display = 'block';
        setTimeout(() => {
            errorMessage.style.display = 'none';
        }, 4000); // Hide after 4 seconds
    }
}
document.addEventListener("DOMContentLoaded", async function() {
    getPacketCounts(); // Fetch packet counts immediately when the page loads
    setInterval(getPacketCounts, 5000); // Fetch packet counts every 5 seconds
    // Function to fetch packet counts
    async function getPacketCounts() {
        fetch('http://192.168.137.161:8000/api/packet-report', {
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
                document.getElementById('cnts').innerHTML = data.total_packets;
                document.getElementById('pty').innerHTML = data.typ;
                document.getElementById('aip').innerHTML = data.src_ip;
                document.getElementById('vip').innerHTML = data.dst_ip;
            })
            .catch(error => {
                console.error('Error fetching packet counts:', error);
                showError('Unable to connect. Please try again later.');
            });
    }
    function showError(message) {
        const errorMessage = document.getElementById('errorMessage');
        errorMessage.innerText = message;
        errorMessage.style.display = 'block';
        setTimeout(() => {
            errorMessage.style.display = 'none';
        }, 4000); // Hide after 4 seconds
    }
});