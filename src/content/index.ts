const currentUrl = window.location.href;

chrome.runtime.sendMessage({
  type: 'PAGE_URL',
  url: currentUrl,
});

console.log('SecureSense scanned:', currentUrl);