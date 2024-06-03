// Function to fetch data from the API and render it in a table
async function fetchDataAndRender() {
    try {
        const response = await fetch('http://localhost:6767/data');
        const data = await response.json();
        renderTable(data);
    } catch (error) {
        console.error('Error fetching data:', error);
    }
}

// Function to render the table with fetched data
function renderTable(data) {
    const table = document.getElementById('csvTable');
    table.innerHTML = ''; // Clear existing table

    const thead = document.createElement('thead');
    const tr = document.createElement('tr');
    Object.keys(data).forEach(column => {
        const th = document.createElement('th');
        th.textContent = column;
        tr.appendChild(th);
    });
    thead.appendChild(tr);
    table.appendChild(thead);

    const tbody = document.createElement('tbody');
    const tr = document.createElement('tr');
    Object.values(data).forEach(value => {
        const td = document.createElement('td');
        td.textContent = value;
        tr.appendChild(td);
    });
    tbody.appendChild(tr);
    table.appendChild(tbody);

    // Scroll to the bottom of the table
    table.parentElement.scrollTop = table.parentElement.scrollHeight;
}

// Call the fetchDataAndRender function to fetch and render initial data
fetchDataAndRender();

// Fetch data from the API and update the table every 10 seconds
setInterval(fetchDataAndRender, 10000);
