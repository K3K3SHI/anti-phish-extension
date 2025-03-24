let features = [ 
    1, 1, 1, 1, -1,  
    -1, -1, -1, -1, 1,  
    1, -1, -1, -1, 1,  
    -1, 1, -1, 0, 1, 
    1, 1, 1, -1, -1, 
    -1, -1, 1, 1, -1 
];

/*
function save_url() {
    chrome.storage.local.get({ visitedUrls: [] }, (data) => {
        let urls = data.visitedUrls;
        let existingEntry = urls.find(entry => entry.url === message.url);
        
        if (!existingEntry) {
            urls.push({ url: message.url, status: message.status || "safe" });
            chrome.storage.local.set({ visitedUrls: urls });
        }
    });
}

function report_phishing() {
   
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
}
*/

function isIP(url) {
    const ipRegex = /^(https?:\/\/)?(\d{1,3}\.){3}\d{1,3}(:\d+)?(\/.*)?$/;
    if( ipRegex.test(url)) {
        features[0] = -1 ;
    } else {
        features[0] = 1 ;
    }
}

function checkUrlLength(url) {
    if (url.length < 54) {
        features[1] = 1;
    } else if (url.length >=54 && url.length <=75) {
        features[1] = 0;
    } else {
        features[1] = -1;

    }
}

function checkTinyURL(url) {
    
    const shortenerDomains = [
        "bit.ly", "t.co", "tinyurl.com", "goo.gl", "is.gd",
        "buff.ly", "ow.ly", "shorte.st", "adf.ly", "cutt.ly",
        "rebrand.ly", "t2m.io", "rb.gy", "mcaf.ee", "soo.gd"
    ];

    try {
      
        const urlObj = new URL(url);
        const domain = urlObj.hostname.replace("www.", ""); 
        if( shortenerDomains.includes(domain)) {
            features[2] = 1;
        } else {
            features[2] = -1;
        }
    } catch (error) {
        features[2] = -1;
    }
}
function checkAtSymbol(url) {
    try {
       
        if (url.includes("@")) {
            features[3] = 1;
        }
        else {
            features[3] = -1;
        }
    } catch (error) {
        features[3] = -1;
    }
}


function checkDoubleSlashes(url) {
    try {
        const urlObj = new URL(url);
        const urlString = urlObj.href;

      
        const firstDoubleSlashIndex = urlString.indexOf("//");

      
        const secondDoubleSlashIndex = urlString.indexOf("//", firstDoubleSlashIndex + 1);

        if (secondDoubleSlashIndex !== -1) {
            features[4] = -1;
        } else {
            features[4] = 1;
        }

        return false;
    } catch (error) {
        features[4] = 1;
    }
}

function checkDashes(url) {
    try {
        const urlObj = new URL(url);
        const domain = urlObj.hostname;

        
        const dashCount = (domain.match(/-/g) || []).length;

    
        if (dashCount >= 2) {
            features[5] = -1;
        } else {
            features[5] = 1;
        }

    } catch (error) {
        features[5] = 1;
    }
}


function classifyDomainBySubdomains(url) {
    try {
        const urlObj = new URL(url);
        let hostname = urlObj.hostname;

  
        hostname = hostname.replace(/^www\./, "");

        
        const domainParts = hostname.split(".");

        
        const cctlds = ["uk", "us", "ca", "au", "in", "cn", "de", "fr", "jp", "br", "ru"];

       
        let baseDomainParts = domainParts;
        if (domainParts.length > 2 && cctlds.includes(domainParts[domainParts.length - 1])) {
            baseDomainParts = domainParts.slice(0, -2);
        } else {
            baseDomainParts = domainParts.slice(0, -1); 
        }

        const subdomainCount = baseDomainParts.length - 1; 

       
        if (subdomainCount === 0) {
            features[6] = -1; 
        } else if (subdomainCount === 1) {
            features[6] = 0; 
        } else {
            features[6] = 1; 
        }
    } catch (error) {
        features[6] = -1; 
    }
}


function checkHTTPs(url) {
    try {
        const urlObj = new URL(url);
        if( urlObj.protocol === "https:") {
            features[7] = -1; 
        } else {
            features[7] = 0; 
        }
    } catch (error) {
        features[7] = -1; 
    }
}

function checkFavicon() {
    const currentDomain = window.location.hostname.replace(/^www\./, ""); 
    const linkElements = document.querySelectorAll("link[rel*='icon']"); 

    for (let link of linkElements) {
        const faviconUrl = link.href;

        try {
            const faviconDomain = new URL(faviconUrl).hostname.replace(/^www\./, ""); 
            if (faviconDomain !== currentDomain) {
                features[9] = 1;
                return ;
            } else {
                features[9] = -1;
                return ;
            }
        } catch (error) {
            features[9] = -1;
            return ;
        }
    }

    features[9] = -1;
}

function checkNonStandardPort(url) {
    try {
        const parsedUrl = new URL(url);
        const port = parsedUrl.port;
        const standardPorts = {
            "http:": "80",
            "https:": "443",
            "ftp:": "21",
            "ssh:": "22"
        };

 
        if (port && port !== standardPorts[parsedUrl.protocol]) {
            features[10] = 1 ;
        }
    } catch (error) {
        features[10] = 0 ;
    }

    features[10] = 1 ;
}

function checkFakeHTTPS(url) {
    try {
        const parsedUrl = new URL(url);
        const domain = parsedUrl.hostname.toLowerCase(); 

        if (domain.includes("https") && !domain.startsWith("https://")) {
            features[11] = -1; 
        }
    } catch (error) {
        features[11] = 1; 
    }

    features[11] = 1;
}

function checkMetaScriptLinkTags() {
    const pageDomain = window.location.hostname; 
    const elements = document.querySelectorAll("meta, script, link"); 
    let totalLinks = elements.length;
    let externalLinks = 0;

    elements.forEach(element => {
        let src = element.src || element.href || element.content; 
        if (src && !src.includes(pageDomain) && src.startsWith("http")) {
            externalLinks++; 
        }
    });

    if (totalLinks === 0) return 1; 

    let externalPercentage = (externalLinks / totalLinks) * 100;

    if (externalPercentage < 17) {
        features[13] = 1;  
    } else if (externalPercentage >= 17 && externalPercentage <= 81) {
        features[13] = -1; 
    } else {
        features[13] = -1; 
    }
}

// index - 14
function checkSFH() {
    const currentDomain = window.location.hostname; 
    const forms = document.querySelectorAll("form"); 

    if (forms.length === 0) return 0; 

    for (let form of forms) {
        let action = form.action.trim(); 

        
        if (action === "" || action.toLowerCase() === "about:blank") {
            return -1;
        }

        try {
            let actionDomain = new URL(action).hostname;
            if (actionDomain && actionDomain !== currentDomain) {
                features[14] = 1;
            }
        } catch (error) {
            features[14] = -1;
        }
    }

    features[14] = 0; 
}

function checkPhishingMailUsage() {
    const forms = document.querySelectorAll("form");
    const scripts = document.querySelectorAll("script");

    
    for (let form of forms) {
        if (form.action.includes("mailto:")) {
            features[15] = -1; 
        }
    }

   
    for (let script of scripts) {
        if (script.textContent.includes("mail(")) {
            features[15] = -1; 
        }
    }

    features[15] = 1; 
}


function checkExcessiveRedirects() {
    if (performance && performance.navigation) {
        let redirectCount = performance.navigation.redirectCount; 

        if (redirectCount <= 1) {
            features[17] = 1;
        } else if (redirectCount <= 3) {
            features[17] = 0; 
        } else {
            features[17] = 0; 
        }
    } else {
        console.warn("Redirect detection not supported in this browser.");
        features[16] = 1; 
    }
}


function checkFakeStatusBarURL() {
    let suspicious = false;

   
    document.querySelectorAll("*").forEach(element => {
        if (element.hasAttribute("onmouseover")) {
            let scriptContent = element.getAttribute("onmouseover");

 
            if (/window\.status\s*=\s*/i.test(scriptContent) || /status\s*=\s*/i.test(scriptContent)) {
                suspicious = true;
            }
        }
    });

    if( suspicious ) {
        features[18] = 1;
    } else {
        features[18] = 1
    }
    return suspicious ? -1 : 1;
}


function checkRightClickBlocking() {
    let suspicious = false;

    
    if (document.oncontextmenu !== null) {
        suspicious = true;
    }

   
    document.querySelectorAll("*").forEach(element => {
        if (element.hasAttribute("onmousedown")) {
            let scriptContent = element.getAttribute("onmousedown");

          
            if (/event\.button\s*==\s*2/i.test(scriptContent)) {
                suspicious = true;
            }
        }
    });
    if(suspicious) {
        features[19] = 1; 
    } else {
        features[19] = -1;
    }
}


function checkPhishingPopups() {
    let popups = [];
    let phishingDetected = false;
    let suspiciousDetected = false;

 
    const originalOpen = window.open;
    window.open = function (...args) {
        let newWindow = originalOpen.apply(this, args);
        if (newWindow) {
            popups.push(newWindow);
        }
        return newWindow;
    };

   
    setTimeout(() => {
        popups.forEach(popup => {
            try {
                let forms = popup.document.querySelectorAll("form");
                forms.forEach(form => {
                    let inputs = form.querySelectorAll("input, textarea");
                    inputs.forEach(input => {
                        let fieldName = input.name.toLowerCase();
                       
                        if (fieldName.includes("password") || fieldName.includes("email") || 
                            fieldName.includes("credit") || fieldName.includes("card") || 
                            fieldName.includes("cvv") || fieldName.includes("security")) {
                            phishingDetected = true;
                        }
                    });
                });

                
                if (forms.length > 0 && !phishingDetected) {
                    suspiciousDetected = true;
                }
            } catch (error) {
                console.warn("Cannot access popup content due to CORS restrictions.");
            }
        });
    }, 3000); 

    if (phishingDetected) {
        features[20] = 1; 
    } else if (suspiciousDetected) {
        features[20] = -1; 
    } else {
        features[20] = -1; 
    }
}


function checkHiddenIframes() {
    let iframes = document.querySelectorAll("iframe");
    let phishingDetected = false;
    let suspiciousDetected = false;

    if (iframes.length === 0) {
        return 1;
    }

    iframes.forEach(iframe => {
        let width = iframe.width || iframe.style.width || iframe.getAttribute("width") || iframe.offsetWidth;
        let height = iframe.height || iframe.style.height || iframe.getAttribute("height") || iframe.offsetHeight;
        let border = iframe.frameBorder || iframe.getAttribute("frameBorder") || iframe.style.border;
        let opacity = window.getComputedStyle(iframe).opacity;

        width = parseInt(width) || 0;
        height = parseInt(height) || 0;
        opacity = parseFloat(opacity);

  
        if ((width === 0 || height === 0 || opacity === 0) && (!border || border === "0")) {
            phishingDetected = true;
        }
        
        else if (!border || border === "0") {
            suspiciousDetected = true;
        }
    });

    if (phishingDetected) {
        features[21] = 1 ;
    } else if (suspiciousDetected) {
        features[21] = 1 ; 
    } else {
        features[21] = -1 ; 
    }
}

async function checkDomainUsingWHOIS() {
    
    const domain = window.location.hostname.replace(/^www\./, ""); 
    const WHOIS_API = `https://api.whoisxmlapi.com/v1?apiKey=YOUR_API_KEY&domainName=${domain}`;

    try {
        let response = await fetch(WHOIS_API);
        if (!response.ok) throw new Error("WHOIS lookup failed");

        let data = await response.json();

    
        if (!data || !data.domain || !data.createDate) {
            console.warn("WHOIS Record Not Found! Likely a Phishing Website.");
            features[23] = -1; 
        }

        
        let creationDate = new Date(data.createDate);
        let currentDate = new Date();
        let sixMonthsAgo = new Date();
        sixMonthsAgo.setMonth(currentDate.getMonth() - 6);

        if (creationDate > sixMonthsAgo) {
            console.warn("Domain is less than 6 months old! Suspicious.");
            features[22] = 1; 
        }

        console.log("Domain is legitimate (older than 6 months).");
        features[22] = 1; 
    } catch (error) {
        console.error("Error fetching WHOIS data:", error);
        features[23] = -1; 
    }
}


async function checkWebsitePopularity() {

    const domain = window.location.hostname.replace(/^www\./, ""); 
    const ALEXA_API = `https://api.domainsdb.info/v1/alexa?domain=${domain}`;

    try {
        let response = await fetch(ALEXA_API);
        if (!response.ok) {
            features[24] = -1;
            return ;
        }

        let data = await response.json();

        
        if (!data || !data.rank) {
            console.warn("No Alexa ranking found! Likely a Phishing Website.");
            features[24] = 1; 
        }

        let rank = parseInt(data.rank, 10);

        if (rank > 0 && rank <= 100000) {
            console.log(`Alexa Rank: ${rank} (Legitimate Website)`);
            features[24] = -1; 
            return ; 
        } else {
            console.warn(`Alexa Rank: ${rank} (Suspicious Website)`);
            features[24] = 0;
        }
    } catch (error) {
        console.error("Error fetching Alexa data:", error);
        features[24] = 1; 
    }
}

 
async function checkPageRank() {
    const domain = window.location.hostname.replace(/^www\./, ""); 

    const PAGERANK_API = `https://openpagerank.com/api/v1.0/getPageRank?domains[]=${domain}`;

    try {
        let response = await fetch(PAGERANK_API, {
            method: "GET",
            headers: { "API-OPR": "your-api-key-here" } 
        });

        if (!response.ok) {
            features[25] = -1;
            return;
        }

        let data = await response.json();

        let pageRank = data.response[0]?.page_rank_decimal;

        if (pageRank === undefined || pageRank === null) {
            console.warn("No PageRank found! Likely a Phishing Website.");
            features[25] = -1; 
            return ;
        }

        if (pageRank > 0.2) {
            console.log(`PageRank: ${pageRank} (Legitimate Website)`);
            return ; 
        } else if (pageRank > 0 && pageRank <= 0.2) {
            console.warn(`PageRank: ${pageRank} (Suspicious Website)`);
            features[25] = -1; 
            return ;
        } else {
            console.warn(`PageRank: ${pageRank} (Phishing Website)`);
            features[25] = -1; 
            return ;
        }
    } catch (error) {
        console.error("Error fetching PageRank data:", error);
        features[25] = -1; 
        return ;
    }
}


// Main 

async function checkPhishing(features) {
    try {
        const currentUrl = window.location.href;

        
        let response = await fetch("https://phishing-detection-api-9cog.onrender.com/check", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ "features": features })
        });

        let data = await response.json();
        console.log("API Response:", data.result);

        if (data.result === "malicious") {
            alert( "WARNING: This site is flagged as phishing!");
            chrome.runtime.sendMessage({ type: "report_phishing", url: currentUrl });
        } else {
            alert("Great: This site is flagged as safe!");
            chrome.runtime.sendMessage({ type: "report_safe", url: currentUrl });

        }
    } catch (error) {
        console.error("Error calling phishing API:", error);
    }
}



async function runPhishingCheck() {
    // alert("document loaded");
    
    const currentUrl = window.location.href;
    //chrome.runtime.sendMessage({ type: "save_url", url: currentUrl });
    isIP(currentUrl);
    checkUrlLength(currentUrl);
    checkTinyURL(currentUrl);
    checkAtSymbol(currentUrl);
    checkDoubleSlashes(currentUrl) ;
    checkDashes(currentUrl);
    classifyDomainBySubdomains(currentUrl);
    checkHTTPs(currentUrl);
    checkFavicon(currentUrl);
    checkNonStandardPort(currentUrl);
    checkFakeHTTPS(currentUrl);
    checkMetaScriptLinkTags();
    checkSFH();
    checkPhishingMailUsage();
    checkExcessiveRedirects();
    checkRightClickBlocking();
    checkPhishingPopups() ;
    checkHiddenIframes();
    checkDomainUsingWHOIS() ;
    checkWebsitePopularity();
    checkPageRank();




    checkPhishing(features);
}

window.onload = function() {
    const currentUrl = window.location.href;
    const excludedDomains = ["google.com", "youtube.com","leetcode.com"];

    if (!excludedDomains.some(domain => currentUrl.includes(domain))) {
        console.log("Running phishing check...");
        runPhishingCheck();
    } else {
        console.log("Skipping phishing check for a trusted site.");
    }
};

