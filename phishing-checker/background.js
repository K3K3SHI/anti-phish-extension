chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "save_url") {
        chrome.storage.local.get({ visitedUrls: [] }, (data) => {
            let urls = data.visitedUrls;
            let existingEntry = urls.find(entry => entry.url === message.url);
            
            if (!existingEntry) {
                urls.push({ url: message.url, status: message.status || "safe" });
                chrome.storage.local.set({ visitedUrls: urls });
            }
        });
    } else if (message.type === "report_phishing") {
        chrome.storage.local.get({ visitedUrls: [] }, (data) => {
            let urls = data.visitedUrls;
            let urlIndex = urls.findIndex(entry => entry.url === message.url);
            
            if (urlIndex !== -1) {
                urls[urlIndex].status = "phishing"; 
            } else {
                urls.push({ url: message.url, status: "phishing" });
            }

            chrome.storage.local.set({ visitedUrls: urls }, () => {
                chrome.notifications.create({
                    type: "basic",
                    iconUrl: "icon.png",
                    title: "Phishing Reported",
                    message: "This URL has been reported as phishing!"
                });
            });
        });
    } else if (message.type === "report_safe") {
        chrome.storage.local.get({ visitedUrls: [] }, (data) => {
            let urls = data.visitedUrls;
            let urlIndex = urls.findIndex(entry => entry.url === message.url);
            
            if (urlIndex !== -1) {
                urls[urlIndex].status = "safe"; 
            } else {
                urls.push({ url: message.url, status: "safe" });
            }

            chrome.storage.local.set({ visitedUrls: urls }, () => {
                chrome.notifications.create({
                    type: "basic",
                    iconUrl: "icon.png",
                    title: "safe webpage",
                    message: "This URL has been reported as safe!"
                });
            });
        });
    }else if (message.type === "get_urls") {
        chrome.storage.local.get({ visitedUrls: [] }, (data) => {
            sendResponse(data.visitedUrls);
        });
        return true; 
    }
});
