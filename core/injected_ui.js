// ---------------------
// UI Event handlers
// ---------------------

setTimeout(function () {
  if (!window.onerror) return;

  // WhatsApp hooks window.onerror.
  // This makes extension-related errors not printed out,
  // so make a hook-on-hook to print those first
  var originalOnError = window.onerror;
  window.onerror = function (message, source, lineno, colno, error) {
    console.error(error);
    originalOnError.call(window, message, source, lineno, colno, error);
  };
}, 1000);
