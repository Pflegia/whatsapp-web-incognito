// This is the background page.
// it keeps track of prefrences/settings in localStorage

if (typeof chrome !== "undefined") {
  var browser = chrome;
}

// TODO: We need to remove this bad code dupliation
browser.runtime.onMessage.addListener(function (
  messageEvent,
  sender,
  callback
) {
  console.log("messageEvent", messageEvent);

  if (messageEvent.name == "sendDataToWebhook") {
    console.log("background dataToSend", messageEvent.data);
    const webhookUrl = process.env.WEBHOOK_URL;
    fetch(webhookUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(messageEvent.data),
    })
      .then((response) => {
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }

        // Check if the response body is empty
        if (response.bodyUsed) {
          console.log("Response body already used or empty");
          return null;
        }

        // Check if there is any body content in the response
        if (response.status === 202) {
          console.log("Request accepted, no response body.");
          return null;
        }

        // If it's JSON, parse it
        return response.text(); // Try to read as text first
      })
      .then((data) => {
        console.log("Webhook response:", data);
        callback({ success: true });
      })
      .catch((error) => {
        console.error("Error sending to webhook:", error);
        callback({ success: false, error });
      });
  }

  return true;
});

browser.action.onClicked.addListener(function (activeTab) {
  var newURL = "https://web.whatsapp.com";
  browser.tabs.create({ url: newURL });
});
