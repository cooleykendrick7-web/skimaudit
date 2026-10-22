// safe-script.js — legitimate FAQ accordion + newsletter validation (SAFE SAMPLE)
(function () {
  // Accordion: scoped to the FAQ container only
  var faq = document.querySelector('#faq');
  if (faq) {
    faq.addEventListener('click', function (e) {
      var btn = e.target.closest('.faq-q');
      if (btn) btn.nextElementSibling.classList.toggle('open');
    });
  }

  // Newsletter: validate the email field's FORMAT only, on submit
  var form = document.querySelector('#newsletter');
  if (form) {
    var onSubmit = function (e) {
      var email = form.querySelector('#newsletter-email');
      if (email && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email.value)) {
        e.preventDefault();
        email.focus();
      }
    };
    form.addEventListener('submit', onSubmit);
  }

  console.log('ui helpers loaded');
})();
