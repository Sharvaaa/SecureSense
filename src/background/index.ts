chrome.runtime.onMessage.addListener((message) => {
  if (message.type === 'PAGE_URL') {
    console.log('SecureSense received URL:', message.url);

    chrome.storage.local.set({
      currentUrl: message.url,
    });
  }
});

console.log('SecureSense background service worker started.');