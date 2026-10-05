import { analyzeUrl } from '../utils/urlAnalyzer';

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === 'PAGE_URL') {
    const url = message.url as string;

    console.log('SecureSense received URL:', url);

    const analysis = analyzeUrl(url);

    console.log('SecureSense URL analysis:', analysis);

    chrome.storage.local.set({
      currentUrl: url,
      urlAnalysis: analysis,
    });

    return;
  }

  if (message.type === 'GET_CURRENT_URL') {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tab = tabs[0];
      const url = tab?.url;

      if (!url) {
        sendResponse({
          success: false,
          error: 'Could not determine the current tab URL.',
        });
        return;
      }

      const analysis = analyzeUrl(url);

      chrome.storage.local.set({
        currentUrl: url,
        urlAnalysis: analysis,
      });

      sendResponse({
        success: true,
        analysis,
      });
    });

    return true;
  }
});

console.log('SecureSense background service worker started.');