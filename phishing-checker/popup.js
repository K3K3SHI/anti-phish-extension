document.addEventListener("DOMContentLoaded", function () {
    const urlTable = document.getElementById("urlTable").getElementsByTagName("tbody")[0];
    const clearButton = document.getElementById("clearData");

   
    function loadUrls() {
        chrome.runtime.sendMessage({ type: "get_urls" }, (urls) => {
            urlTable.innerHTML = ""; 
            
            urls.forEach((entry, index) => {
                let row = urlTable.insertRow();
                row.innerHTML = `
                    <td>${index + 1}</td>
                    <td>${entry.url}</td>
                    <td style="color: ${entry.status === 'phishing' ? 'red' : 'green'};">
                        ${entry.status.toUpperCase()}
                    </td>
                `;
            });
        });
    }

   
    clearButton.addEventListener("click", function () {
        chrome.storage.local.set({ visitedUrls: [] }, loadUrls);
    });

    
    loadUrls();
});
